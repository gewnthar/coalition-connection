//! Accept workload for the simulation run (roadmap core 3a).
//!
//! Accepts go through the simulated I/O boundary into a full-size connection table
//! (http_connections_max entries). Each round keeps `accepts_in_flight` accepts waiting
//! until the table is full and `refusals_per_fill` arrivals were refused, then lets
//! connections leave until the table is empty. A model beside the table predicts every
//! answer: an arrival takes a free entry under a socket never seen before, a refusal comes
//! only when every entry is in use, and each accept completes exactly once.
//!
//! Each completion folds its id and result into a trace hash, and the workload runs twice
//! per seed: both runs must match, count for count and completion for completion.

const std = @import("std");
const assert = std.debug.assert;
const cc = @import("coalition_connection");

const io = cc.io;
const constants = cc.constants;
const connections = cc.live.connections;
const Sim = io.sim.Sim;
const Table = connections.Table;

pub const Error = error{InvariantBroken};

const capacity: u32 = constants.http_connections_max;
const fault_percent: u8 = 10;
const rounds: u32 = 2;
const refusals_per_fill: u32 = 8;

/// Accepts kept waiting while filling, as a listener with a backlog would be.
const accepts_in_flight: u32 = 128;
/// Connections that leave per tick while emptying.
const departures_per_tick: u32 = 64;

/// The listener every accept names. The simulator opens nothing, so any descriptor will do.
const listener: io.Socket = 3;

/// An accept waits 8 ticks on average, so about 15 complete per tick: a fill takes about
/// 300 ticks and an empty about 70. Ten times the fill is a margin no valid seed comes
/// near, and a phase that runs out of ticks is a failure, not a hang.
const phase_ticks_max: u32 = 3_000;

/// Ids in flight, tracked by id modulo the window. An id stays in flight for at most
/// `sim_completion_delay_ticks_max + 1` ticks, and at most `accepts_in_flight` ids are
/// handed out per tick, so two ids in flight never share an entry.
const outstanding_window: u32 = 4096;

const completions_batch: u32 = 64;

comptime {
    assert(fault_percent <= constants.sim_fault_percent_max);
    assert(accepts_in_flight <= constants.io_operations_in_flight_max);
    assert((constants.sim_completion_delay_ticks_max + 1) * accepts_in_flight < outstanding_window);
    // Every phase of every round fits in one simulated run.
    assert(@as(u64, rounds) * 2 * phase_ticks_max < constants.sim_ticks_max);
}

/// What a run did. Two runs with the same seed must match field for field.
pub const Counts = struct {
    submitted: u32 = 0,
    accepted: u32 = 0,
    refused: u32 = 0,
    peer_down: u32 = 0,
    backpressure: u32 = 0,
    departures: u32 = 0,
    peak: u32 = 0,
    /// FNV-1a over every completion's id and result, and every departure, in order.
    trace: u64 = fnv_offset,
};

const fnv_offset: u64 = 0xcbf29ce484222325;
const fnv_prime: u64 = 0x100000001b3;

const Workload = struct {
    sim: Sim,
    table: *Table,
    random: std.Random,
    counts: Counts,
    next_id: io.OperationId,
    outstanding: [outstanding_window]bool,
    /// The socket each entry in use holds, or -1.
    sockets: [capacity]io.Socket,
    in_use: u32,
    /// The largest socket an arrival got; the simulator never hands one out twice.
    socket_last: io.Socket,
};

fn windowIndex(id: io.OperationId) u32 {
    const index: u32 = @intCast(id % outstanding_window);
    assert(index < outstanding_window);
    assert(index == id % outstanding_window);
    return index;
}

/// Folds one value into the trace hash.
fn trace(counts: *Counts, value: u64) void {
    assert(counts.submitted > 0); // Only completions and departures write the trace.
    assert(value & 0xff != 0); // Every value carries what happened in its low byte.
    counts.trace = (counts.trace ^ value) *% fnv_prime;
}

/// Submits accepts until `accepts_in_flight` wait.
fn topUp(w: *Workload) Error!void {
    assert(w.sim.in_flight <= accepts_in_flight);
    const submitted_before = w.counts.submitted;
    while (w.sim.in_flight < accepts_in_flight) {
        const entry = &w.outstanding[windowIndex(w.next_id)];
        if (entry.*) return error.InvariantBroken; // The window is too small.
        const submission: io.Submission = .{ .id = w.next_id, .operation = .{ .accept = .{ .listener = listener } } };
        w.sim.submit(submission) catch |err| switch (err) {
            // Fewer than the ring's depth are ever in flight here.
            error.QueueFull => return error.InvariantBroken,
        };
        entry.* = true;
        w.next_id += 1;
        w.counts.submitted += 1;
    }
    assert(w.sim.in_flight == accepts_in_flight);
    assert(w.counts.submitted - submitted_before <= accepts_in_flight);
}

/// Checks one completion against the model and applies it.
fn check(w: *Workload, completion: io.Completion) Error!void {
    assert(w.in_use <= capacity);
    if (completion.id >= w.next_id) return error.InvariantBroken;
    const entry = &w.outstanding[windowIndex(completion.id)];
    if (!entry.*) return error.InvariantBroken; // Completed twice, or never submitted.
    entry.* = false;
    if (completion.result != .accept) return error.InvariantBroken;
    const peer = completion.result.accept catch |err| {
        const outcome: u64 = switch (err) {
            error.TableFull => refused: {
                if (w.in_use != capacity) return error.InvariantBroken; // Refused with room.
                w.counts.refused += 1;
                break :refused 1;
            },
            error.PeerDown => peer_down: {
                w.counts.peer_down += 1;
                break :peer_down 2;
            },
            error.Backpressure => backpressure: {
                w.counts.backpressure += 1;
                break :backpressure 3;
            },
        };
        trace(&w.counts, 1 | outcome << 8 | completion.id << 16);
        return;
    };
    if (peer >= capacity or w.sockets[peer] != -1) return error.InvariantBroken;
    const socket = w.table.get(peer).socket;
    if (socket <= w.socket_last) return error.InvariantBroken; // A socket handed out twice.
    w.socket_last = socket;
    w.sockets[peer] = socket;
    w.in_use += 1;
    w.counts.accepted += 1;
    w.counts.peak = @max(w.counts.peak, w.in_use);
    trace(&w.counts, 2 | @as(u64, peer) << 8 | completion.id << 32);
    // The simulator took the entries for a whole poll at once, in completion order, so the
    // model catches up with the table only at the end of the batch (`drain` checks it).
    assert(w.in_use <= w.table.count());
}

/// Takes every completion that is due.
fn drain(w: *Workload) Error!void {
    assert(w.counts.submitted >= w.sim.completed);
    assert(w.sim.in_flight <= accepts_in_flight);
    var completions: [completions_batch]io.Completion = undefined;
    const batches_max = constants.io_operations_in_flight_max / completions_batch + 1;
    var batches: u32 = 0;
    while (batches < batches_max) : (batches += 1) {
        const count = w.sim.poll(&completions);
        for (completions[0..count]) |completion| try check(w, completion);
        if (count < completions_batch) break;
    }
    if (batches == batches_max) return error.InvariantBroken;
    if (w.table.count() != w.in_use) return error.InvariantBroken;
}

/// Releases a random connection in use, found by probing from a random entry.
fn depart(w: *Workload) Error!void {
    assert(w.in_use > 0);
    var peer = w.random.uintLessThan(io.PeerId, capacity);
    var probes: u32 = 0;
    while (w.sockets[peer] == -1) : (probes += 1) {
        assert(probes < capacity); // At least one entry is in use.
        peer = (peer + 1) % capacity;
    }
    if (w.table.release(peer) != w.sockets[peer]) return error.InvariantBroken;
    w.sockets[peer] = -1;
    w.in_use -= 1;
    w.counts.departures += 1;
    trace(&w.counts, 3 | @as(u64, peer) << 8);
    assert(w.in_use == w.table.count());
}

/// Keeps accepts waiting until the table is full and `refusals_per_fill` more arrivals
/// were refused.
fn fill(w: *Workload) Error!void {
    const refused_before = w.counts.refused;
    var ticks: u32 = 0;
    while (w.counts.refused - refused_before < refusals_per_fill) : (ticks += 1) {
        if (ticks == phase_ticks_max) return error.InvariantBroken;
        try topUp(w);
        w.sim.tick();
        try drain(w);
    }
    assert(ticks <= phase_ticks_max);
    assert(w.in_use == capacity);
}

/// Stops accepting, lets the waiting accepts finish, and empties the table.
fn empty(w: *Workload) Error!void {
    var ticks: u32 = 0;
    while (w.in_use > 0 or w.sim.in_flight > 0) : (ticks += 1) {
        if (ticks == phase_ticks_max) return error.InvariantBroken;
        var departures: u32 = 0;
        while (departures < departures_per_tick and w.in_use > 0) : (departures += 1) try depart(w);
        w.sim.tick();
        try drain(w);
    }
    assert(ticks <= phase_ticks_max);
    assert(w.table.count() == 0);
}

/// After every round: each accept completed once, the table reached its limit and refused
/// past it, and every fault the simulator drew was seen.
fn checkEnd(w: *const Workload) Error!void {
    const counts = w.counts;
    assert(w.in_use == 0);
    assert(w.sim.in_flight == 0);
    for (w.outstanding) |entry| if (entry) return error.InvariantBroken;
    if (counts.peak != capacity) return error.InvariantBroken;
    if (counts.refused < rounds * refusals_per_fill) return error.InvariantBroken;
    if (counts.accepted != counts.departures) return error.InvariantBroken;
    const completed = counts.accepted + counts.refused + counts.peer_down + counts.backpressure;
    if (completed != counts.submitted or w.sim.completed != counts.submitted) return error.InvariantBroken;
    if (w.sim.accepted != counts.accepted or w.sim.refused != counts.refused) return error.InvariantBroken;
    if (counts.peer_down == 0 or counts.backpressure == 0) return error.InvariantBroken;
    if (w.sim.faults.accept_peer_down != counts.peer_down) return error.InvariantBroken;
}

fn runOnce(seed: u64, w: *Workload) Error!Counts {
    const budget: u64 = @as(u64, capacity) * connections.entry_bytes;
    var startup = cc.StartupAllocator.init(std.heap.page_allocator, budget);
    const gpa = startup.allocator();
    var table = Table.init(gpa, capacity) catch return error.InvariantBroken;
    assert(startup.bytes_live == budget); // Exactly its own bytes: nothing hidden.
    startup.finishStartup();

    var prng: std.Random.DefaultPrng = .init(seed ^ 0xacce_9700);
    w.* = .{
        .sim = .init(seed, fault_percent),
        .table = &table,
        .random = prng.random(),
        .counts = .{},
        .next_id = 0,
        .outstanding = @splat(false),
        .sockets = @splat(-1),
        .in_use = 0,
        .socket_last = -1,
    };
    w.sim.attachTable(&table);
    var round: u32 = 0;
    errdefer std.debug.print("sim: accepts failed in round {d} at tick {d}\n", .{ round, w.sim.ticks });
    while (round < rounds) : (round += 1) {
        try fill(w);
        try empty(w);
        table.assertInvariants();
    }
    assert(round == rounds);
    try checkEnd(w);

    startup.beginShutdown();
    table.deinit(gpa);
    if (startup.bytes_live != 0) return error.InvariantBroken;
    return w.counts;
}

/// Runs the workload twice with the same seed and checks that both runs did the same
/// thing, completion for completion.
pub fn run(seed: u64) Error!Counts {
    // The workload holds a Sim and a model of about 40 KiB, so it lives in static memory
    // rather than on the stack. Each run starts it afresh.
    const static = struct {
        var workload: Workload = undefined;
    };
    const counts = try runOnce(seed, &static.workload);
    const again = try runOnce(seed, &static.workload);
    if (!std.meta.eql(counts, again)) return error.InvariantBroken;
    assert(counts.peak == capacity);
    assert(counts.refused > 0);
    return counts;
}
