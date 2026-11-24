//! Drop workload for the simulation run.
//!
//! Sends go through the simulated I/O boundary to `peers` connections held in a connection
//! table, with sticking and failing drops turned on (`Sim.setDropFaults`). The workload acts
//! as the server loop's write deadline will: a connection with a send in flight for
//! `2 * deadline_ticks` is dropped, a drop that failed is tried again on the next tick, a
//! connection whose drop worked is released once its last send has come back and its entry
//! is handed to a new connection at once, and a connection whose drops are exhausted is
//! left alone, as the contract says. Now and then a connection just sent to is closed the
//! same way, one more send goes to a connection already dropped, or a connection already dropped
//! is dropped again. One accept is kept in flight throughout, and each arrival is released
//! at once.
//!
//! A model beside the simulator checks each completion on its own (the workload polls one
//! completion at a time, so it knows which one a drop ended):
//!   - each operation completes exactly once, with the kind it was submitted as;
//!   - once a send to a connection sticks, every later send to it sticks too, and a stuck
//!     send never completes before a drop of its connection works, then with PeerDown;
//!   - no send that didn't stick is still in flight `deadline_ticks` after its submission;
//!   - once a drop works, every send to that connection completes within the longest
//!     delay, every send submitted to it afterwards is ended by the drop with PeerDown, and
//!     of the sends pending at the drop, some are ended and some keep their own result;
//!   - a drop ends only sends to a connection whose drop worked: never one to a connection
//!     whose drops failed, nor one to the next connection on a reused entry;
//!   - a failed drop is counted on the entry, one per failure, through the table; the
//!     failure that reaches `constants.io_drop_attempts_max` returns DropsExhausted, and
//!     every later drop returns it too, drawing nothing and changing nothing;
//!   - dropping a connection again after a drop worked changes nothing and draws nothing;
//!   - an entry is handed out again under its next generation.
//! At the end, the only operations still in flight are the stuck sends of connections whose
//! drops ran out, and every other entry releases.
//!
//! Each completion and each drop folds into a trace hash, and the workload runs twice per
//! seed: both runs must match, count for count and completion for completion.

const std = @import("std");
const assert = std.debug.assert;
const cc = @import("coalition_connection");

const io = cc.io;
const constants = cc.constants;
const connections = cc.live.connections;
const Sim = io.sim.Sim;
const Table = connections.Table;

pub const Error = error{InvariantBroken};

/// Connections the workload sends to, and the table's size: one entry more, kept free for
/// the arrival the accept brings in.
const peers: u32 = 63;
const capacity: u32 = peers + 1;

const fault_percent: u8 = 10;
/// Chance, in percent, that a send sticks; and that a drop fails. A connection runs out of
/// drops after `io_drop_attempts_max` failures in a row: at 50% that's 1 in 16 of the
/// drops that start a close, about 30 of the 63 connections per run (measured: 16 at the
/// fewest over seeds 1 to 1000), so a seed that exhausts none is out of reach, and the rest
/// keep the run going.
const stick_percent: u8 = 5;
const drop_fail_percent: u8 = 50;

const sends_per_tick: u32 = 2;
/// Out of 32 per tick: how often a connection just sent to is closed.
const close_per_32: u8 = 2;
/// Out of 8 per tick: how often one more send goes to a connection already dropped, and
/// how often one is dropped again.
const after_drop_eighths: u8 = 2;
const redrop_eighths: u8 = 1;

/// Ticks of sending. A send sticks about every 10 ticks (5% of 2 sends a tick).
const workload_ticks: u32 = 4_000;

/// A send that doesn't stick completes within this many ticks of its submission. The write
/// deadline is twice that: a connection with a send in flight that long is dropped, so the
/// sends submitted behind a stuck one stick too before the drop.
const deadline_ticks: u32 = constants.sim_completion_delay_ticks_max;
/// The model's age buckets: one per tick a send may still complete in, plus the tick it was
/// submitted in.
const buckets: u32 = deadline_ticks + 1;

/// After sending stops, the run ends once every connection is settled: a stuck send is
/// past the write deadline within `2 * deadline_ticks + 1` ticks, its drop works or runs
/// out of attempts within `io_drop_attempts_max` ticks, and the dropped connection's sends
/// come back within `deadline_ticks`. Four times that is a margin no valid seed comes
/// near; a run that doesn't settle in it is a failure, not a hang.
const settle_ticks_max: u32 = 4 * (3 * deadline_ticks + constants.io_drop_attempts_max + 2);

/// Every send the run can submit: `sends_per_tick` plus one after a drop per tick.
const sends_max: u32 = workload_ticks * (sends_per_tick + 1);
/// Accepts take ids above every send's.
const accept_id_first: io.OperationId = sends_max;
/// Polls in one drain, one completion each: every operation in flight, then the empty one.
const polls_max: u32 = constants.io_operations_in_flight_max + 1;

/// The listener every accept names. The simulator opens nothing, so any descriptor will do.
const listener: io.Socket = 3;
/// The workload's own connections' sockets count up from here, below the simulator's
/// arrivals (`1 << 16` and up), so the two never share a number.
const socket_first: io.Socket = 16;

comptime {
    assert(fault_percent <= constants.sim_fault_percent_max);
    assert(stick_percent > 0 and stick_percent <= constants.sim_fault_percent_max);
    assert(drop_fail_percent > 0 and drop_fail_percent < 100);
    assert(capacity <= constants.http_connections_max);
    assert(close_per_32 < 32 and after_drop_eighths < 8 and redrop_eighths < 8);
    // The whole run fits in one simulated run, so no due tick is capped at its end.
    assert(workload_ticks + settle_ticks_max + deadline_ticks < constants.sim_ticks_max);
    // Every accept's id fits: at most one is submitted a tick.
    assert(@as(u64, sends_max) + workload_ticks + settle_ticks_max < std.math.maxInt(u32));
    // A new connection follows a working drop: of a healthy connection, at most one a
    // tick, or of a connection with a send stuck, at most one per send.
    assert(socket_first + peers + workload_ticks + settle_ticks_max + @as(u64, sends_max) < 1 << 16);
}

/// What a run did. Two runs with the same seed must match field for field.
pub const Counts = struct {
    sends: u32 = 0,
    /// Sends the share kept from accepts refused; rare, since few sends stay stuck.
    refused_share: u32 = 0,
    /// Sends that stuck by their own draw, and sends that stuck behind one stuck already.
    stuck_first: u32 = 0,
    stuck_behind: u32 = 0,
    /// Sends submitted to a connection after its drop worked, all ended with PeerDown.
    after_drop: u32 = 0,
    /// Sends pending when their connection's drop worked: ended by it, or kept their result.
    pending_ended: u32 = 0,
    pending_kept: u32 = 0,
    /// Drops the deadline started, drops of healthy connections, drops that worked, drops
    /// that failed, connections whose drops ran out, and drops of a connection dropped
    /// already.
    deadline_drops: u32 = 0,
    closes: u32 = 0,
    drops_worked: u32 = 0,
    drops_failed: u32 = 0,
    exhausted: u32 = 0,
    redrops: u32 = 0,
    /// Entries released after a drop and handed straight to a new connection.
    reconnects: u32 = 0,
    accepts: u32 = 0,
    peer_down: u32 = 0,
    /// FNV-style, one 64-bit word at a time, over every completion and every drop, in order.
    trace: u64 = fnv_offset,
};

const fnv_offset: u64 = 0xcbf29ce484222325;
const fnv_prime: u64 = 0x100000001b3;

const PeerState = enum {
    /// Sent to; dropped when a send passes the write deadline, or now and then to close it.
    open,
    /// A drop failed: tried again every tick until one works or they run out.
    dropping,
    /// A drop worked: released once its last send has come back.
    closing,
    /// Drops ran out: never sent to again, and released only if nothing is in flight.
    exhausted,
};

/// The model of one of the workload's connections, by table index.
const Peer = struct {
    id: io.PeerId,
    socket: io.Socket,
    state: PeerState,
    /// Sends in flight, as the table should count them, and how many of them stuck.
    sends: u32,
    stuck: u32,
    /// Sends in flight by the tick they were submitted in, modulo `buckets`; and sends in
    /// flight more than `deadline_ticks`, which only stuck ones may be.
    by_tick: [buckets]u32,
    overdue: u32,
    /// The tick a send to it was first in flight more than `deadline_ticks`, or null: the
    /// write deadline runs from there.
    overdue_since: ?u32,
    /// The tick the drop worked at; meaningful while `closing`.
    dropped_at: u32,
    /// Failed drops, as the table should count them.
    drops_failed: u32,
};

/// The model of one send, by id.
const SendRecord = struct {
    peer: io.PeerId,
    index: u32,
    tick: u32,
    /// The simulator counted it as stuck when it was submitted.
    stuck: bool,
    /// Submitted after a drop of its connection worked, so it ends with PeerDown.
    after_drop: bool,
    done: bool,
};

const Workload = struct {
    sim: Sim,
    table: *Table,
    random: std.Random,
    counts: Counts,
    peers: [capacity]?Peer,
    records: [sends_max]SendRecord,
    next_send: u32,
    next_accept: io.OperationId,
    accept_in_flight: bool,
    next_socket: io.Socket,
};

fn trace(w: *Workload, value: u64) void {
    w.counts.trace = (w.counts.trace ^ value) *% fnv_prime;
}

fn indexOf(peer: io.PeerId) u32 {
    const index: u32 = @as(connections.IdParts, @bitCast(peer)).index;
    assert(index < capacity);
    return index;
}

/// Opens a new connection on the entry the table hands out next.
fn open(w: *Workload) Error!u32 {
    assert(w.table.count() < capacity);
    const socket = w.next_socket;
    assert(socket >= socket_first and socket < 1 << 16); // Below the simulator's arrivals.
    const id = w.table.acquire(socket) catch |err| switch (err) {
        error.TableFull => return error.InvariantBroken, // The model left room.
    };
    w.next_socket += 1;
    const index = indexOf(id);
    if (w.peers[index] != null) return error.InvariantBroken; // Handed out twice.
    const entry = w.table.get(id);
    if (entry.sends_in_flight != 0 or entry.drops_failed != 0) return error.InvariantBroken;
    w.peers[index] = .{
        .id = id,
        .socket = socket,
        .state = .open,
        .sends = 0,
        .stuck = 0,
        .by_tick = @splat(0),
        .overdue = 0,
        .overdue_since = null,
        .dropped_at = 0,
        .drops_failed = 0,
    };
    return index;
}

/// The index of a random connection of the workload in `state`, probing from a random
/// entry, or null if none is.
fn pick(w: *Workload, state: PeerState) ?u32 {
    const start = w.random.uintLessThan(u32, capacity);
    var probe: u32 = 0;
    while (probe < capacity) : (probe += 1) {
        const index = (start + probe) % capacity;
        const peer = w.peers[index] orelse continue;
        if (peer.state == state) return index;
    }
    return null;
}

/// One send to the connection at `index`; the share kept from accepts may refuse it.
fn send(w: *Workload, index: u32) Error!void {
    const peer = &(w.peers[index].?);
    assert(peer.state == .open or peer.state == .closing);
    assert(w.next_send < sends_max);
    const id: io.OperationId = w.next_send;
    const submission: io.Submission = .{ .id = id, .operation = .{ .send = .{ .peer = peer.id, .bytes = "drop" } } };
    const stuck_before = w.sim.sends_stuck;
    w.sim.submit(submission) catch |err| switch (err) {
        // The share is full; with the accept in flight too, so is the ring.
        error.SlotsKeptForAccepts, error.QueueFull => {
            if (sendsInFlight(w) != constants.io_non_accepts_in_flight_max) return error.InvariantBroken;
            if (err == error.QueueFull and !w.accept_in_flight) return error.InvariantBroken;
            w.counts.refused_share += 1;
            return;
        },
        error.AcceptTooSoon => return error.InvariantBroken, // Only for an accept.
    };
    const stuck = w.sim.sends_stuck != stuck_before;
    if (w.sim.sends_stuck - stuck_before > 1) return error.InvariantBroken;
    if (peer.state == .closing) {
        // A send to a dropped connection is ended at once, never stuck.
        if (stuck) return error.InvariantBroken;
        w.counts.after_drop += 1;
    } else if (peer.stuck > 0) {
        // Behind a stuck send, every send sticks.
        if (!stuck) return error.InvariantBroken;
        w.counts.stuck_behind += 1;
    } else if (stuck) w.counts.stuck_first += 1;
    const tick = w.sim.ticks;
    w.records[w.next_send] = .{
        .peer = peer.id,
        .index = index,
        .tick = tick,
        .stuck = stuck,
        .after_drop = peer.state == .closing,
        .done = false,
    };
    w.next_send += 1;
    w.counts.sends += 1;
    peer.sends += 1;
    if (stuck) peer.stuck += 1;
    peer.by_tick[tick % buckets] += 1;
    if (w.table.get(peer.id).sends_in_flight != peer.sends) return error.InvariantBroken;
}

/// Sends in flight, as the model counts them.
fn sendsInFlight(w: *const Workload) u32 {
    var sends: u32 = 0;
    for (w.peers) |maybe| {
        const peer = maybe orelse continue;
        sends += peer.sends;
    }
    return sends;
}

/// Tries `peer`'s drop and checks what it did against the table.
fn dropPeer(w: *Workload, index: u32) Error!void {
    const peer = &(w.peers[index].?);
    assert(peer.state == .open or peer.state == .dropping);
    const table_failed_before = w.table.get(peer.id).drops_failed;
    const sim_failed_before = w.sim.drops_failed;
    const sim_dropped_before = w.sim.dropped;
    if (table_failed_before != peer.drops_failed) return error.InvariantBroken;
    const outcome: u64 = if (w.sim.drop(peer.id)) |_| outcome: {
        const table_failed = w.table.get(peer.id).drops_failed;
        if (w.sim.dropped != sim_dropped_before + 1) return error.InvariantBroken;
        if (table_failed == table_failed_before) {
            // It worked: nothing counted as failed.
            if (w.sim.drops_failed != sim_failed_before) return error.InvariantBroken;
            peer.state = .closing;
            peer.dropped_at = w.sim.ticks;
            w.counts.drops_worked += 1;
            break :outcome 1;
        }
        // It failed, and the table counted exactly that failure, short of the bound.
        if (table_failed != table_failed_before + 1) return error.InvariantBroken;
        if (table_failed >= constants.io_drop_attempts_max) return error.InvariantBroken;
        if (w.sim.drops_failed != sim_failed_before + 1) return error.InvariantBroken;
        peer.drops_failed += 1;
        peer.state = .dropping;
        w.counts.drops_failed += 1;
        break :outcome 2;
    } else |err| switch (err) {
        error.DropsExhausted => exhausted: {
            // The failure that reached the bound, tried and counted like the others.
            if (table_failed_before != constants.io_drop_attempts_max - 1) return error.InvariantBroken;
            if (w.table.get(peer.id).drops_failed != constants.io_drop_attempts_max) return error.InvariantBroken;
            if (w.sim.drops_failed != sim_failed_before + 1) return error.InvariantBroken;
            if (w.sim.dropped != sim_dropped_before + 1) return error.InvariantBroken;
            peer.drops_failed += 1;
            peer.state = .exhausted;
            w.counts.drops_failed += 1;
            w.counts.exhausted += 1;
            try dropAgain(w, index);
            break :exhausted 3;
        },
    };
    trace(w, outcome | (@as(u64, index) << 8) | (@as(u64, w.sim.ticks) << 16));
}

/// Drops a connection again: one whose drops ran out is refused, one whose drop worked
/// returns. Either way nothing is drawn and nothing changes but the count of drops tried,
/// which only the second one is.
fn dropAgain(w: *Workload, index: u32) Error!void {
    const peer = w.peers[index].?;
    assert(peer.state == .exhausted or peer.state == .closing);
    const failed_before = w.sim.drops_failed;
    const dropped_before = w.sim.dropped;
    const ended_before = w.sim.sends_dropped;
    const drop_source_before = w.sim.drop_source;
    const entry_before = w.table.get(peer.id).*;
    const exhausted = if (w.sim.drop(peer.id)) |_| false else |err| switch (err) {
        error.DropsExhausted => true,
    };
    if (exhausted != (peer.state == .exhausted)) return error.InvariantBroken;
    const tried: u64 = @intFromBool(!exhausted);
    if (w.sim.dropped != dropped_before + tried) return error.InvariantBroken;
    if (w.sim.drops_failed != failed_before or w.sim.sends_dropped != ended_before) return error.InvariantBroken;
    if (!std.meta.eql(drop_source_before, w.sim.drop_source)) return error.InvariantBroken;
    if (!std.meta.eql(entry_before, w.table.get(peer.id).*)) return error.InvariantBroken;
}

/// One send's completion, checked against the model and applied. `ended`: the poll that
/// returned it counted a send ended by a drop.
fn checkSend(w: *Workload, completion: io.Completion, ended: bool) Error!void {
    const tick = w.sim.ticks;
    if (completion.id >= w.next_send) return error.InvariantBroken;
    const record = &w.records[@intCast(completion.id)];
    if (record.done) return error.InvariantBroken; // Completed twice.
    record.done = true;
    const peer = &(w.peers[record.index] orelse return error.InvariantBroken);
    // The entry can't be released while the send is counted, so its id is still the one.
    if (peer.id != record.peer or peer.sends == 0) return error.InvariantBroken;
    const overdue = tick - record.tick > deadline_ticks;
    // Only a stuck send stays in flight past the longest delay.
    if (overdue and !record.stuck) return error.InvariantBroken;
    // A drop ends only sends to a connection whose drop worked, and ends every stuck send
    // and every send submitted after it; a pending one it may end or leave.
    if (ended and peer.state != .closing) return error.InvariantBroken;
    if ((record.stuck or record.after_drop) and !ended) return error.InvariantBroken;
    if (peer.state == .closing and !record.stuck and !record.after_drop) {
        if (ended) w.counts.pending_ended += 1 else w.counts.pending_kept += 1;
    }
    peer.sends -= 1;
    if (record.stuck) peer.stuck -= 1;
    if (overdue) {
        if (peer.overdue == 0) return error.InvariantBroken;
        peer.overdue -= 1;
    } else {
        const bucket = &peer.by_tick[record.tick % buckets];
        if (bucket.* == 0) return error.InvariantBroken;
        bucket.* -= 1;
    }
    var outcome: u64 = 1;
    if (completion.result.send) |bytes| {
        if (ended) return error.InvariantBroken; // A drop ends a send only with PeerDown.
        if (bytes == 0 or bytes > "drop".len) return error.InvariantBroken;
        outcome |= @as(u64, bytes) << 4;
    } else |err| switch (err) {
        error.PeerDown => {
            w.counts.peer_down += 1;
            outcome = 2;
        },
        error.Backpressure => {
            if (ended) return error.InvariantBroken;
            outcome = 3;
        },
    }
    trace(w, outcome | (completion.id << 8) | (@as(u64, tick) << 40));
}

/// An accept's completion: the arrival takes the free entry and leaves at once.
fn checkAccept(w: *Workload, completion: io.Completion) Error!void {
    if (completion.id + 1 != w.next_accept or !w.accept_in_flight) return error.InvariantBroken;
    w.accept_in_flight = false;
    const arrival = completion.result.accept catch |err| {
        switch (err) {
            error.PeerDown, error.Backpressure => {},
            // The model keeps an entry free for the one accept in flight.
            error.TableFull => return error.InvariantBroken,
        }
        trace(w, 4 | (completion.id << 8));
        return;
    };
    if (w.peers[indexOf(arrival)] != null) return error.InvariantBroken;
    _ = w.table.release(arrival) catch return error.InvariantBroken;
    w.counts.accepts += 1;
    trace(w, 5 | (completion.id << 8) | (arrival << 32));
}

/// Takes every completion that is due, one poll each, so a send a drop ended is known by
/// the poll that returned it.
fn drain(w: *Workload) Error!void {
    var completion: [1]io.Completion = undefined;
    var polls: u32 = 0;
    while (polls < polls_max) : (polls += 1) {
        const ended_before = w.sim.sends_dropped;
        if (w.sim.poll(&completion) == 0) break;
        const ended = w.sim.sends_dropped - ended_before;
        if (ended > 1) return error.InvariantBroken;
        switch (completion[0].result) {
            .send => try checkSend(w, completion[0], ended == 1),
            .accept => {
                if (completion[0].id < accept_id_first or ended != 0) return error.InvariantBroken;
                try checkAccept(w, completion[0]);
            },
            .execute => return error.InvariantBroken, // None submitted.
        }
    }
    // Each poll before the empty one took an operation in flight.
    if (polls == polls_max) return error.InvariantBroken;
}

/// After the drain at this tick: sends submitted `deadline_ticks` ago that are still in
/// flight are overdue. Each bucket ages once, just before the tick that reuses it.
fn age(w: *Workload) Error!void {
    const tick = w.sim.ticks;
    if (tick < deadline_ticks) return;
    const bucket = (tick - deadline_ticks) % buckets;
    for (&w.peers) |*maybe| {
        const peer = &(maybe.* orelse continue);
        peer.overdue += peer.by_tick[bucket];
        peer.by_tick[bucket] = 0;
        if (peer.overdue > 0 and peer.overdue_since == null) peer.overdue_since = tick;
        // Only stuck sends are still in flight past the longest delay.
        if (peer.overdue > peer.stuck) return error.InvariantBroken;
        // Once a drop has worked, every send to the connection completes within the
        // longest delay.
        if (peer.state == .closing and tick >= peer.dropped_at + deadline_ticks and peer.overdue > 0) {
            return error.InvariantBroken;
        }
    }
}

/// The table counts each connection's sends as the model does.
fn checkTable(w: *const Workload) Error!void {
    var sends: u64 = 0;
    for (w.peers) |maybe| {
        const peer = maybe orelse continue;
        const entry = w.table.get(peer.id);
        if (entry.sends_in_flight != peer.sends) return error.InvariantBroken;
        if (entry.drops_failed != peer.drops_failed) return error.InvariantBroken;
        var by_tick: u64 = peer.overdue;
        for (peer.by_tick) |count| by_tick += count;
        if (by_tick != peer.sends or peer.stuck > peer.sends) return error.InvariantBroken;
        sends += peer.sends;
    }
    if (sends != w.sim.sends_in_flight) return error.InvariantBroken;
    const accepts: u32 = @intFromBool(w.accept_in_flight);
    if (sends + accepts != w.sim.in_flight) return error.InvariantBroken;
}

/// Releases a dropped connection whose sends are all back, and opens a new one on its
/// entry.
fn reconnect(w: *Workload, index: u32) Error!void {
    const peer = w.peers[index].?;
    assert(peer.state == .closing and peer.sends == 0);
    const socket = w.table.release(peer.id) catch |err| switch (err) {
        error.SendsInFlight => return error.InvariantBroken,
    };
    if (socket != peer.socket) return error.InvariantBroken;
    w.peers[index] = null;
    // The free stack hands out the entry released last, under its next generation, so the
    // old id names nothing now.
    if (try open(w) != index) return error.InvariantBroken;
    const old_parts: connections.IdParts = @bitCast(peer.id);
    const new_parts: connections.IdParts = @bitCast(w.peers[index].?.id);
    if (new_parts.generation != old_parts.generation +% 1) return error.InvariantBroken;
    if (w.table.lookup(peer.id) != null) return error.InvariantBroken;
    w.counts.reconnects += 1;
    trace(w, 6 | (@as(u64, index) << 8));
}

/// The loop's part of a tick: deadlines, retries, releases and new connections, then now
/// and then a send after a drop, or a drop again.
fn tend(w: *Workload, sending: bool) Error!void {
    var index: u32 = 0;
    while (index < capacity) : (index += 1) {
        const peer = w.peers[index] orelse continue;
        switch (peer.state) {
            .open => if (peer.overdue_since) |since| {
                if (w.sim.ticks - since >= deadline_ticks) {
                    w.counts.deadline_drops += 1;
                    try dropPeer(w, index);
                }
            },
            .dropping => try dropPeer(w, index),
            .closing => if (peer.sends == 0) try reconnect(w, index),
            .exhausted => {},
        }
    }
    if (!sending) return;
    if (w.random.uintLessThan(u8, 8) < after_drop_eighths) {
        if (pick(w, .closing)) |closing| try send(w, closing);
    }
    if (w.random.uintLessThan(u8, 8) < redrop_eighths) {
        if (pick(w, .closing)) |closing| {
            w.counts.redrops += 1;
            try dropAgain(w, closing);
        }
    }
}

fn keepAccepting(w: *Workload) Error!void {
    if (w.accept_in_flight) return;
    const submission: io.Submission = .{ .id = w.next_accept, .operation = .{ .accept = .{ .listener = listener } } };
    w.sim.submit(submission) catch |err| switch (err) {
        error.AcceptTooSoon => return, // Tried again next tick.
        // An accept takes a slot kept for accepts, and only this one is ever in flight.
        error.QueueFull, error.SlotsKeptForAccepts => return error.InvariantBroken,
    };
    w.next_accept += 1;
    w.accept_in_flight = true;
}

fn step(w: *Workload, sending: bool) Error!void {
    try tend(w, sending);
    if (sending) {
        var sent: u32 = 0;
        var last: ?u32 = null;
        while (sent < sends_per_tick) : (sent += 1) {
            const index = w.random.uintLessThan(u32, capacity);
            const peer = w.peers[index] orelse continue;
            if (peer.state != .open) continue;
            try send(w, index);
            last = index;
        }
        // Closing a connection just sent to leaves sends pending at the drop, some due this
        // very tick, for the drop to end or leave.
        if (w.random.uintLessThan(u8, 32) < close_per_32) {
            if (last) |close| if (w.peers[close].?.state == .open) {
                w.counts.closes += 1;
                try dropPeer(w, close);
            };
        }
        try keepAccepting(w);
    }
    try checkTable(w);
    w.sim.tick();
    try drain(w);
    try age(w);
    try checkTable(w);
}

/// Whether every connection has settled: none waiting on a drop or a release, no send in
/// flight but the stuck sends of connections whose drops ran out, and no accept waiting.
fn settled(w: *const Workload) bool {
    if (w.accept_in_flight) return false;
    for (w.peers) |maybe| {
        const peer = maybe orelse continue;
        switch (peer.state) {
            .open => if (peer.sends > 0) return false,
            .dropping, .closing => return false,
            // Its sends that didn't stick still come back.
            .exhausted => if (peer.sends > peer.stuck) return false,
        }
    }
    return true;
}

/// After the run: only exhausted connections still hold sends, every other entry
/// releases, and every outcome came up.
fn checkEnd(w: *Workload) Error!void {
    var stuck: u64 = 0;
    var index: u32 = 0;
    while (index < capacity) : (index += 1) {
        const peer = w.peers[index] orelse continue;
        if (peer.state == .exhausted) {
            try dropAgain(w, index);
            stuck += peer.sends;
            // Whatever is left on it stuck, and only a drop that worked could end it.
            if (peer.stuck != peer.sends) return error.InvariantBroken;
        }
        const entry_before = w.table.get(peer.id).*;
        if (w.table.release(peer.id)) |socket| {
            if (peer.sends != 0 or socket != peer.socket) return error.InvariantBroken;
            w.peers[index] = null;
        } else |err| switch (err) {
            error.SendsInFlight => {
                if (peer.state != .exhausted or peer.sends == 0) return error.InvariantBroken;
                if (!std.meta.eql(entry_before, w.table.get(peer.id).*)) return error.InvariantBroken;
            },
        }
    }
    if (w.sim.in_flight != stuck or w.sim.sends_in_flight != stuck) return error.InvariantBroken;
    const c = w.counts;
    if (w.sim.drops_failed != c.drops_failed) return error.InvariantBroken;
    if (w.sim.dropped != @as(u64, c.drops_worked) + c.drops_failed + c.redrops) return error.InvariantBroken;
    if (c.deadline_drops + c.closes != c.drops_worked + c.exhausted) return error.InvariantBroken;
    if (w.sim.sends_stuck != c.stuck_first + c.stuck_behind) return error.InvariantBroken;
    if (w.sim.submitted != @as(u64, c.sends) + (w.next_accept - accept_id_first)) return error.InvariantBroken;
    if (c.stuck_first == 0 or c.stuck_behind == 0 or c.after_drop == 0) return error.InvariantBroken;
    if (c.pending_ended == 0 or c.pending_kept == 0) return error.InvariantBroken;
    if (c.deadline_drops == 0 or c.closes == 0 or c.redrops == 0) return error.InvariantBroken;
    if (c.drops_worked == 0 or c.drops_failed == 0 or c.exhausted == 0) return error.InvariantBroken;
    if (c.reconnects == 0 or c.accepts == 0) return error.InvariantBroken;
}

fn runOnce(seed: u64, w: *Workload) Error!Counts {
    const budget: u64 = @as(u64, capacity) * connections.entry_bytes;
    var startup = cc.StartupAllocator.init(std.heap.page_allocator, budget);
    const gpa = startup.allocator();
    var table = Table.init(gpa, capacity) catch return error.InvariantBroken;
    assert(startup.bytes_live == budget); // Exactly its own bytes: nothing hidden.
    startup.finishStartup();

    var prng: std.Random.DefaultPrng = .init(seed ^ 0xd409_5eed);
    w.* = .{
        .sim = .init(seed, fault_percent),
        .table = &table,
        .random = prng.random(),
        .counts = .{},
        .peers = @splat(null),
        .records = undefined,
        .next_send = 0,
        .next_accept = accept_id_first,
        .accept_in_flight = false,
        .next_socket = socket_first,
    };
    w.sim.setDropFaults(stick_percent, drop_fail_percent);
    w.sim.attachTable(&table);
    var opened: u32 = 0;
    while (opened < peers) : (opened += 1) _ = try open(w);
    errdefer std.debug.print("sim: drops failed at tick {d}\n", .{w.sim.ticks});

    var tick: u32 = 0;
    while (tick < workload_ticks) : (tick += 1) try step(w, true);
    tick = 0;
    while (!settled(w)) : (tick += 1) {
        if (tick == settle_ticks_max) return error.InvariantBroken;
        try step(w, false);
    }
    try checkEnd(w);

    // The stuck sends' entries stay in use; the table goes with the run.
    startup.beginShutdown();
    table.deinit(gpa);
    if (startup.bytes_live != 0) return error.InvariantBroken;
    w.table = undefined; // The table lived on this function's stack.
    return w.counts;
}

/// Runs the workload twice with the same seed and checks that both runs did the same
/// thing, completion for completion.
pub fn run(seed: u64) Error!Counts {
    // The workload holds a Sim and about 300 KiB of send records, so it lives in static
    // memory rather than on the stack. Each run starts it afresh.
    const static = struct {
        var workload: Workload = undefined;
    };
    const counts = try runOnce(seed, &static.workload);
    const again = try runOnce(seed, &static.workload);
    if (!std.meta.eql(counts, again)) return error.InvariantBroken;
    assert(counts.trace != fnv_offset); // The runs did something to compare.
    assert(counts.sends > 0);
    return counts;
}
