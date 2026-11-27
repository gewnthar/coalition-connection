//! Receive workload for the simulation run.
//!
//! Every connection's client sends the same three requests a byte at a time
//! (`Sim.setClientStream` with a chunk bound of 1): a GET kept alive, a POST with a body,
//! and a GET that asks to close. Connections come in through one accept kept in flight, and
//! the workload drives each one through the connection state machine
//! (`src/live/connection_state.zig`), as the server loop will: it turns every completion,
//! parse result and deadline into an event, carries out the transition's action, and moves
//! the entry only through `Table.setState`. A complete request is answered with a fixed
//! response; a client that closes or resets mid-request ends its connection; a client that
//! goes silent, or stops reading, meets its deadline and is dropped; a connection whose drops
//! run out is cancelled; and a connection with nothing left in flight is released, its entry
//! handed to the next arrival.
//!
//! Faults, short reads, silent clients, stuck sends and failing drops are all drawn by the
//! simulator. Checked as the run goes:
//!   - each operation completes exactly once, with the kind it was submitted as, to the
//!     connection that submitted it;
//!   - a connection is half-duplex: never a receive and a send in flight at once, and never
//!     two of either, with at most one cancel beside them, all as the table counts them;
//!   - every complete request holds exactly the bytes its client sent for it, in order, so
//!     no receive lost, repeated or misplaced a byte;
//!   - a new connection, a reused entry's included, starts with an empty head scan and an
//!     empty request buffer, its client's stream from the first byte;
//!   - a cancelled receive or send completes once, with Canceled, only after a cancel;
//!   - a connection leaves closing, and its entry is released, only with nothing in flight.
//! At the end every connection has closed, nothing is in flight, and the table is empty.
//!
//! Each completion folds into a trace hash, and the workload runs twice per seed: both runs
//! must match, count for count and completion for completion.

const std = @import("std");
const assert = std.debug.assert;
const cc = @import("coalition_connection");

const io = cc.io;
const constants = cc.constants;
const connections = cc.live.connections;
const machine = cc.live.connection_state;
const http_request = cc.live.http_request;
const Sim = io.sim.Sim;
const Table = connections.Table;

pub const Error = error{InvariantBroken};

/// The connection table's size.
const capacity: u32 = 64;

/// What every client sends, then it closes: two requests kept alive and one that closes.
const request_get = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
const request_post = "POST /f HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nok";
const request_close = "GET /c HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
const client_stream = request_get ++ request_post ++ request_close;
const client_requests: u32 = 3;

const response_kept = "HTTP/1.1 204 No Content\r\n\r\n";
const response_closed = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
const response_refused = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";

/// Faults per operation, and the chance a send or a receive sticks, in percent: low, since
/// a byte-at-a-time client makes about 120 receives, and most clients should get some way.
const fault_percent: u8 = 1;
const stick_percent: u8 = 1;
/// Half the drops fail, so some connections run out of drops and are cancelled.
const drop_fail_percent: u8 = 50;

/// Deadlines in ticks, scaled down from the server's seconds so a run sees each of them
/// many times: a byte takes at most `sim_completion_delay_ticks_max` ticks, so a request of
/// under 60 bytes arrives within the read deadline unless its client goes silent.
const idle_ticks: u32 = 1_000;
const read_ticks: u32 = 1_500;
const write_ticks: u32 = 100;

/// Ticks of accepting, then ticks to let every connection close.
const workload_ticks: u32 = 6_000;
const settle_ticks_max: u32 = 4 * (idle_ticks + read_ticks + constants.io_drop_attempts_max * write_ticks);

/// The listener the accept names; the simulator opens nothing.
const listener: io.Socket = 3;
/// An accept's id carries this index, past every entry.
const accept_index: u32 = 0xffff;
const completions_batch: u32 = 64;

comptime {
    assert(fault_percent <= constants.sim_fault_percent_max);
    assert(stick_percent > 0 and stick_percent <= constants.sim_fault_percent_max);
    assert(capacity <= constants.http_connections_max and capacity < accept_index);
    assert(client_stream.len <= io.sim.client_stream_bytes_max);
    assert(client_stream.len < constants.http_request_size_max);
    // A whole request arrives within the read deadline, byte by byte, at the longest delay.
    assert(request_post.len * (constants.sim_completion_delay_ticks_max + 1) < read_ticks);
    assert(workload_ticks + settle_ticks_max < constants.sim_ticks_max);
    assert(client_requests <= constants.http_requests_per_connection_max);
}

/// What a run did. Two runs with the same seed must match field for field.
pub const Counts = struct {
    accepts: u32 = 0,
    /// Connections whose entry had been released before, under an earlier id.
    reused: u32 = 0,
    receives: u32 = 0,
    bytes: u64 = 0,
    /// Requests answered, and clients that sent all three.
    requests: u32 = 0,
    complete_clients: u32 = 0,
    /// Receives that ended the connection: end of stream, PeerDown or a drop.
    receive_ended: u32 = 0,
    sends: u32 = 0,
    /// Submissions refused for now and resubmitted, and completions that said retry.
    refused: u32 = 0,
    retries: u32 = 0,
    /// Deadlines met while reading and while writing, and drops, failed or not.
    read_deadlines: u32 = 0,
    write_deadlines: u32 = 0,
    drops: u32 = 0,
    exhausted: u32 = 0,
    cancels: u32 = 0,
    canceled: u32 = 0,
    releases: u32 = 0,
    trace: u64 = fnv_offset,
};

const fnv_offset: u64 = 0xcbf29ce484222325;
const fnv_prime: u64 = 0x100000001b3;

/// The model of one connection, by table index.
const Conn = struct {
    peer: io.PeerId,
    /// Bytes in the request buffer; the head's length and the body's once the head parses.
    filled: u32 = 0,
    head_len: u32 = 0,
    content_length: u32 = 0,
    /// Requests answered, and where the request being read starts in the client stream.
    requests: u32 = 0,
    stream_at: u32 = 0,
    /// The tick the state's deadline passes, or null with none.
    deadline: ?u32 = null,
    /// The response going out, how much of it has gone, and whether it closes after.
    response: []const u8 = "",
    sent: u32 = 0,
    after: machine.After = .keep_open,
    /// The receive or send in flight, and the cancel in flight, by id.
    operation: ?io.OperationId = null,
    cancel: ?io.OperationId = null,
    /// A submission refused, or a completion that said retry, to submit next tick, and the
    /// tick it was set on.
    retry: ?io.Kind = null,
    retry_tick: u32 = 0,
    /// A drop returned DropsExhausted: the sweep hands the machine `drop_exhausted` next,
    /// outside the transition that dropped, so no transition runs inside another.
    exhausted: bool = false,
};

const Workload = struct {
    sim: Sim,
    table: *Table,
    buffers: []u8,
    counts: Counts,
    conns: [capacity]?Conn,
    /// Each entry's last generation seen, to tell a reused entry.
    seen: [capacity]bool,
    serial: u64,
    accept_in_flight: bool,
};

fn trace(w: *Workload, value: u64) void {
    w.counts.trace = (w.counts.trace ^ value) *% fnv_prime;
}

/// An id no operation in flight holds: a fresh serial in the high bits, the entry's index
/// (or `accept_index`) in the low 16, so a completion names its connection.
fn nextId(w: *Workload, index: u32) io.OperationId {
    assert(index < capacity or index == accept_index);
    w.serial += 1;
    const id: io.OperationId = (w.serial << 16) | index;
    assert(id & 0xffff == index);
    return id;
}

/// The connection on entry `index`; none there is a broken model.
fn connOf(w: *Workload, index: u32) Error!*Conn {
    assert(index < capacity);
    if (w.conns[index]) |*conn| return conn;
    return error.InvariantBroken;
}

/// Records a refused submission, or a completion that said retry, for the next tick.
fn retryLater(w: *Workload, conn: *Conn, kind: io.Kind) void {
    assert(kind == .send or kind == .receive or kind == .cancel);
    assert(conn.retry == null);
    conn.retry = kind;
    conn.retry_tick = w.sim.ticks;
}

fn bufferOf(w: *Workload, index: u32) []u8 {
    assert(index < capacity);
    const size = constants.http_request_size_max;
    assert(w.buffers.len == capacity * size);
    return w.buffers[index * size ..][0..size];
}

fn indexOf(peer: io.PeerId) u32 {
    const index: u32 = @as(connections.IdParts, @bitCast(peer)).index;
    assert(index < capacity);
    return index;
}

/// The deadline a transition sets, from now.
fn setDeadline(w: *Workload, conn: *Conn, deadline: machine.Deadline) void {
    const now = w.sim.ticks;
    assert(now < constants.sim_ticks_max);
    conn.deadline = switch (deadline) {
        .keep => conn.deadline,
        .clear => null,
        .idle => now + idle_ticks,
        .read => now + read_ticks,
        .write => now + write_ticks,
    };
    assert(deadline != .clear or conn.deadline == null);
}

/// Moves `index`'s connection by `event`: the entry's new state through the table, the
/// deadline, then the action.
fn apply(w: *Workload, index: u32, event: machine.Event) Error!void {
    assert(event != .accepted); // `onAccepted` takes an arrival.
    const conn = try connOf(w, index);
    const from = w.table.get(conn.peer).state;
    const result = machine.transition(from, event);
    trace(w, (@as(u64, @backingInt(from)) << 8) | @backingInt(result.to));
    // Only release frees an entry.
    if (result.to != from and result.to != .free) w.table.setState(conn.peer, result.to);
    setDeadline(w, conn, result.deadline);
    try act(w, index, result.action);
    assert(result.to == .free or w.table.get(conn.peer).state == result.to);
}

fn act(w: *Workload, index: u32, action: machine.Action) Error!void {
    const conn = try connOf(w, index);
    assert(w.table.lookup(conn.peer) != null);
    switch (action) {
        .none, .return_buffer => {},
        .receive => try submitReceive(w, index),
        .respond => |after| try startResponse(w, index, if (after == .close) response_closed else response_kept, after),
        .send_refusal => try startResponse(w, index, response_refused, .close),
        .send_rest => try submitSend(w, index),
        .resubmit => {}, // `conn.retry` already names it: it goes next tick.
        .next_request => {
            // The request buffer starts over; the parser left the scan empty.
            assert(w.table.get(conn.peer).scan.resume_at == 0);
            conn.filled = 0;
            conn.head_len = 0;
            conn.content_length = 0;
            try submitReceive(w, index);
        },
        .drop => try dropConn(w, index),
        .cancel => try submitCancel(w, index),
        .release => try release(w, index),
    }
}

fn startResponse(w: *Workload, index: u32, response: []const u8, after: machine.After) Error!void {
    const conn = try connOf(w, index);
    assert(response.len > 0);
    assert(conn.operation == null); // Half-duplex: the receive came back first.
    conn.response = response;
    conn.sent = 0;
    conn.after = after;
    try submitSend(w, index);
}

fn submitReceive(w: *Workload, index: u32) Error!void {
    const conn = try connOf(w, index);
    assert(conn.operation == null and conn.retry == null);
    assert(conn.filled < constants.http_request_size_max);
    const id = nextId(w, index);
    const into = bufferOf(w, index)[conn.filled..];
    const operation: io.Operation = .{ .receive = .{ .peer = conn.peer, .buffer = into } };
    if (try submitted(w, conn, .{ .id = id, .operation = operation })) w.counts.receives += 1;
}

fn submitSend(w: *Workload, index: u32) Error!void {
    const conn = try connOf(w, index);
    assert(conn.operation == null and conn.retry == null);
    assert(conn.sent < conn.response.len);
    const id = nextId(w, index);
    const operation: io.Operation = .{ .send = .{ .peer = conn.peer, .bytes = conn.response[conn.sent..] } };
    if (try submitted(w, conn, .{ .id = id, .operation = operation })) w.counts.sends += 1;
}

fn submitCancel(w: *Workload, index: u32) Error!void {
    const conn = try connOf(w, index);
    assert(conn.cancel == null and conn.retry == null);
    assert(w.table.get(conn.peer).state == .closing);
    const id = nextId(w, index);
    const operation: io.Operation = .{ .cancel = .{ .peer = conn.peer } };
    if (try submitted(w, conn, .{ .id = id, .operation = operation })) w.counts.cancels += 1;
}

/// Submits `submission` for `conn`, recording its id, or records a refusal to retry next
/// tick. Returns whether it went in.
fn submitted(w: *Workload, conn: *Conn, submission: io.Submission) Error!bool {
    const kind: io.Kind = submission.operation;
    assert(kind == .send or kind == .receive or kind == .cancel);
    w.sim.submit(submission) catch |err| switch (err) {
        error.QueueFull, error.SlotsKeptForAccepts, error.CancelsFull => {
            retryLater(w, conn, kind);
            w.counts.refused += 1;
            return false;
        },
        error.AcceptTooSoon => return error.InvariantBroken, // Only for an accept.
    };
    if (kind == .cancel) conn.cancel = submission.id else conn.operation = submission.id;
    assert(conn.retry == null);
    return true;
}

/// Drops the connection when something is in flight; otherwise drained follows at once.
fn dropConn(w: *Workload, index: u32) Error!void {
    const conn = try connOf(w, index);
    assert(w.table.get(conn.peer).state == .closing);
    // A refused submission waits no more: closing takes nothing new but a cancel.
    if (conn.retry != null and conn.retry.? != .cancel) conn.retry = null;
    if (!w.table.get(conn.peer).busy()) return;
    w.counts.drops += 1;
    w.sim.drop(conn.peer) catch |err| switch (err) {
        error.DropsExhausted => {
            w.counts.exhausted += 1;
            // A cancel already going or due covers it.
            if (conn.cancel == null and conn.retry == null) conn.exhausted = true;
        },
    };
    assert(!conn.exhausted or w.table.get(conn.peer).drops_failed == constants.io_drop_attempts_max);
}

fn release(w: *Workload, index: u32) Error!void {
    const conn = try connOf(w, index);
    if (conn.operation != null or conn.cancel != null) return error.InvariantBroken;
    const peer = conn.peer;
    assert(w.table.get(peer).state == .closing); // Only drained leads here.
    _ = w.table.release(peer) catch |err| switch (err) {
        error.OperationsInFlight => return error.InvariantBroken, // Drained means none.
    };
    w.counts.releases += 1;
    if (conn.requests == client_requests) w.counts.complete_clients += 1;
    w.conns[index] = null;
    assert(w.table.lookup(peer) == null);
}

/// Keeps one accept in flight while accepting.
fn keepAccepting(w: *Workload) Error!void {
    if (w.accept_in_flight) return;
    assert(w.sim.share.accepts_in_flight == 0);
    const id = nextId(w, accept_index);
    w.sim.submit(.{ .id = id, .operation = .{ .accept = .{ .listener = listener } } }) catch |err| switch (err) {
        error.QueueFull, error.AcceptTooSoon => return, // Tried again next tick.
        error.SlotsKeptForAccepts, error.CancelsFull => return error.InvariantBroken,
    };
    w.accept_in_flight = true;
    assert(w.sim.share.accepts_in_flight == 1);
}

fn onAccepted(w: *Workload, result: io.AcceptError!io.PeerId) Error!void {
    assert(w.accept_in_flight);
    w.accept_in_flight = false;
    const peer = result catch |err| switch (err) {
        error.PeerDown, error.Backpressure, error.TableFull => return,
    };
    const index = indexOf(peer);
    if (w.conns[index] != null) return error.InvariantBroken; // Handed out twice.
    const entry = w.table.get(peer);
    // A new connection starts empty, on a reused entry too.
    if (entry.scan.resume_at != 0 or entry.busy() or entry.canceled) return error.InvariantBroken;
    if (entry.state != .idle) return error.InvariantBroken;
    if (w.seen[index]) w.counts.reused += 1;
    w.seen[index] = true;
    w.counts.accepts += 1;
    w.conns[index] = .{ .peer = peer };
    // Acquire set idle already; the transition gives the action and the deadline.
    const result_transition = machine.transition(.free, .accepted);
    assert(result_transition.to == .idle);
    setDeadline(w, &w.conns[index].?, result_transition.deadline);
    try act(w, index, result_transition.action);
}

/// What the request buffer holds now, as the state machine names it.
fn classify(w: *Workload, index: u32) Error!machine.Received {
    const conn = try connOf(w, index);
    assert(conn.filled > 0 and conn.filled <= constants.http_request_size_max);
    assert(conn.stream_at < client_stream.len); // A client sends nothing past its stream.
    const buffer = bufferOf(w, index)[0..conn.filled];
    if (conn.head_len == 0) {
        // Every client sends valid requests, so a refusal means the bytes were wrong.
        const request = http_request.parse(buffer, w.table.headScan(conn.peer)) catch |err| switch (err) {
            error.Incomplete => return .head_short,
            else => return error.InvariantBroken,
        };
        conn.head_len = request.head_len;
        conn.content_length = request.content_length;
        const closes = if (request.header("Connection")) |value| std.ascii.eqlIgnoreCase(value, "close") else false;
        conn.after = if (closes or request.version == .http_1_0) .close else .keep_open;
    }
    const request_len = conn.head_len + conn.content_length;
    // A byte at a time never reads past a request's end.
    if (conn.filled > request_len) return error.InvariantBroken;
    if (conn.filled < request_len) return .body_short;
    // Every byte of the request is the client's, in order.
    const expected = client_stream[conn.stream_at..][0..request_len];
    if (!std.mem.eql(u8, buffer[0..request_len], expected)) return error.InvariantBroken;
    conn.stream_at += request_len;
    conn.requests += 1;
    w.counts.requests += 1;
    const last = conn.requests == constants.http_requests_per_connection_max;
    return .{ .complete = if (last) .close else conn.after };
}

fn onReceived(w: *Workload, index: u32, result: io.ReceiveError!u32) Error!void {
    const conn = try connOf(w, index);
    const state = w.table.get(conn.peer).state;
    // Taken back by `onCompletion`, and a receive goes only to a connection in use.
    assert(conn.operation == null and state != .free);
    assert(!w.table.get(conn.peer).receiving);
    const count = result catch |err| {
        if (err == error.Canceled) {
            w.counts.canceled += 1;
            if (!w.table.get(conn.peer).canceled) return error.InvariantBroken;
        }
        if (err == error.Backpressure and state != .closing) {
            retryLater(w, conn, .receive);
            w.counts.retries += 1;
            return apply(w, index, .retry);
        }
        if (state != .closing) w.counts.receive_ended += 1;
        return apply(w, index, .receive_ended);
    };
    if (count == 0) {
        if (state != .closing) w.counts.receive_ended += 1;
        return apply(w, index, .receive_ended);
    }
    if (state == .closing) return apply(w, index, .{ .received = .head_short });
    conn.filled += count;
    w.counts.bytes += count;
    if (conn.filled > constants.http_request_size_max) return error.InvariantBroken;
    // Everything in so far is the client's stream from this request's start, byte for byte,
    // so a lost, repeated or misplaced byte is caught at once, in a head or a body.
    if (conn.stream_at + conn.filled > client_stream.len) return error.InvariantBroken;
    const sent = client_stream[conn.stream_at..][0..conn.filled];
    if (!std.mem.eql(u8, bufferOf(w, index)[0..conn.filled], sent)) return error.InvariantBroken;
    const received = try classify(w, index);
    // Short of the request's end, the next receive goes on after what is in.
    return apply(w, index, .{ .received = received });
}

fn onSent(w: *Workload, index: u32, result: io.SendError!u32) Error!void {
    const conn = try connOf(w, index);
    const state = w.table.get(conn.peer).state;
    // Taken back by `onCompletion`; only a response is ever sent.
    assert(conn.operation == null);
    assert(conn.response.len > 0 and conn.sent < conn.response.len);
    const sent = result catch |err| switch (err) {
        error.Backpressure => if (state == .closing) return apply(w, index, .send_failed) else {
            retryLater(w, conn, .send);
            w.counts.retries += 1;
            return apply(w, index, .retry);
        },
        error.Canceled, error.PeerDown => {
            if (err == error.Canceled) w.counts.canceled += 1;
            if (err == error.Canceled and !w.table.get(conn.peer).canceled) return error.InvariantBroken;
            return apply(w, index, .send_failed);
        },
    };
    conn.sent += sent;
    if (conn.sent > conn.response.len) return error.InvariantBroken;
    if (conn.sent < conn.response.len) return apply(w, index, .sent_part);
    return apply(w, index, .{ .sent_all = conn.after });
}

/// Hands a completion to its connection, after checking it is the one in flight.
fn onCompletion(w: *Workload, completion: io.Completion) Error!void {
    // Every id this workload hands out carries a serial it has used.
    assert(completion.id >> 16 > 0 and completion.id >> 16 <= w.serial);
    assert(w.sim.completed <= w.sim.submitted);
    trace(w, completion.id);
    const index: u32 = @intCast(completion.id & 0xffff);
    if (index == accept_index) {
        if (completion.result != .accept) return error.InvariantBroken;
        return onAccepted(w, completion.result.accept);
    }
    if (index >= capacity) return error.InvariantBroken;
    const conn = try connOf(w, index);
    switch (completion.result) {
        .cancel => {
            if (conn.cancel != completion.id) return error.InvariantBroken;
            conn.cancel = null;
        },
        .receive => |result| {
            if (conn.operation != completion.id) return error.InvariantBroken;
            conn.operation = null;
            try onReceived(w, index, result);
        },
        .send => |result| {
            if (conn.operation != completion.id) return error.InvariantBroken;
            conn.operation = null;
            try onSent(w, index, result);
        },
        .accept, .execute => return error.InvariantBroken,
    }
}

/// Resubmits what was refused on an earlier tick, then, for each entry in one bounded pass
/// over the table, hands the machine what is due: drops that ran out, deadlines that
/// passed, and closing connections with nothing left in flight.
fn sweep(w: *Workload) Error!void {
    assert(w.table.count() <= capacity);
    var index: u32 = 0;
    while (index < capacity) : (index += 1) {
        if (w.conns[index] == null) continue;
        try resubmit(w, index);
        const conn = try connOf(w, index);
        if (conn.exhausted) {
            conn.exhausted = false;
            try apply(w, index, .drop_exhausted);
        }
        const state = w.table.get(conn.peer).state;
        if (conn.deadline) |deadline| if (w.sim.ticks >= deadline) {
            if (state == .writing) w.counts.write_deadlines += 1;
            if (state != .writing and state != .closing) w.counts.read_deadlines += 1;
            try apply(w, index, .deadline);
        };
        if (w.conns[index] == null) continue;
        const entry = w.table.get(conn.peer);
        const drained = !entry.busy() and conn.retry == null and !conn.exhausted;
        if (entry.state == .closing and drained) try apply(w, index, .drained);
    }
    assert(index == capacity);
}

/// Submits again what was refused, or said retry, on an earlier tick.
fn resubmit(w: *Workload, index: u32) Error!void {
    const conn = try connOf(w, index);
    const kind = conn.retry orelse return;
    assert(conn.retry_tick <= w.sim.ticks);
    if (conn.retry_tick == w.sim.ticks) return; // Next tick, as the machine says.
    conn.retry = null;
    switch (kind) {
        .receive => try submitReceive(w, index),
        .send => try submitSend(w, index),
        .cancel => try submitCancel(w, index),
        .accept, .execute => return error.InvariantBroken,
    }
    assert(conn.retry == null or conn.retry_tick == w.sim.ticks);
}

/// Every connection keeps the rules its state sets, as the table counts it.
fn checkConns(w: *const Workload) Error!void {
    assert(w.table.capacity() == capacity);
    var live: u32 = 0;
    for (w.conns, 0..) |maybe, index| {
        const conn = maybe orelse continue;
        live += 1;
        const entry = w.table.lookup(conn.peer) orelse return error.InvariantBroken;
        if (indexOf(conn.peer) != index) return error.InvariantBroken;
        const receiving = conn.operation != null and entry.receiving;
        if (entry.receiving and entry.sends_in_flight > 0) return error.InvariantBroken;
        if (entry.sends_in_flight > 1) return error.InvariantBroken;
        if ((conn.operation != null) != (entry.receiving or entry.sends_in_flight == 1)) return error.InvariantBroken;
        if ((conn.cancel != null) != entry.cancel_in_flight) return error.InvariantBroken;
        if (conn.requests > client_requests) return error.InvariantBroken;
        switch (entry.state) {
            .free => return error.InvariantBroken,
            .idle, .reading_head, .reading_body => {
                if (!receiving and conn.retry != .receive) return error.InvariantBroken;
                if (entry.canceled) return error.InvariantBroken;
            },
            .writing => if (entry.receiving or (entry.sends_in_flight == 0 and conn.retry != .send)) {
                return error.InvariantBroken;
            },
            .closing => if (conn.retry != null and conn.retry.? != .cancel) return error.InvariantBroken,
        }
    }
    if (live != w.table.count()) return error.InvariantBroken;
    assert(live <= capacity);
}

fn step(w: *Workload, accepting: bool) Error!void {
    assert(w.sim.ticks < constants.sim_ticks_max);
    const ticks_before = w.sim.ticks;
    if (accepting) try keepAccepting(w);
    w.sim.tick();
    var completions: [completions_batch]io.Completion = undefined;
    var batches: u32 = 0;
    while (batches < constants.io_operations_in_flight_max) : (batches += 1) {
        const count = w.sim.poll(&completions);
        for (completions[0..count]) |completion| try onCompletion(w, completion);
        if (count < completions_batch) break;
    }
    assert(batches < constants.io_operations_in_flight_max);
    try sweep(w);
    try checkConns(w);
    assert(w.sim.ticks == ticks_before + 1);
}

fn checkEnd(w: *const Workload) Error!void {
    const c = w.counts;
    // A complete client sent every request, each one answered once.
    assert(c.requests >= c.complete_clients * client_requests);
    assert(c.complete_clients <= c.accepts);
    if (w.table.count() != 0 or w.sim.in_flight != 0) return error.InvariantBroken;
    if (c.releases != c.accepts) return error.InvariantBroken;
    if (w.sim.bytes_received != c.bytes) return error.InvariantBroken;
    if (w.sim.canceled != c.canceled or w.sim.cancels != c.cancels) return error.InvariantBroken;
    // A seed that reaches none of these paths tests too little.
    if (c.complete_clients == 0 or c.reused == 0 or c.receive_ended == 0) return error.InvariantBroken;
    if (c.read_deadlines == 0 or c.exhausted == 0 or c.cancels == 0 or c.canceled == 0) return error.InvariantBroken;
}

fn runOnce(seed: u64, w: *Workload) Error!Counts {
    const buffers_bytes: u64 = @as(u64, capacity) * constants.http_request_size_max;
    const budget: u64 = @as(u64, capacity) * connections.entry_bytes + buffers_bytes;
    var startup = cc.StartupAllocator.init(std.heap.page_allocator, budget);
    const gpa = startup.allocator();
    var table = Table.init(gpa, capacity) catch return error.InvariantBroken;
    const buffers = gpa.alloc(u8, buffers_bytes) catch return error.InvariantBroken;
    assert(startup.bytes_live == budget); // Exactly its own bytes: nothing hidden.
    startup.finishStartup();
    w.* = .{
        .sim = .init(seed, fault_percent),
        .table = &table,
        .buffers = buffers,
        .counts = .{},
        .conns = @splat(null),
        .seen = @splat(false),
        .serial = 0,
        .accept_in_flight = false,
    };
    w.sim.setDropFaults(stick_percent, drop_fail_percent);
    w.sim.setClientStream(client_stream, 1);
    w.sim.attachTable(&table);
    errdefer std.debug.print("sim: receives failed at tick {d}\n", .{w.sim.ticks});

    var tick: u32 = 0;
    while (tick < workload_ticks) : (tick += 1) try step(w, true);
    tick = 0;
    while (w.table.count() > 0 or w.sim.in_flight > 0) : (tick += 1) {
        if (tick == settle_ticks_max) return error.InvariantBroken;
        try step(w, false);
    }
    try checkEnd(w);
    assert(w.sim.ticks <= constants.sim_ticks_max);
    startup.beginShutdown();
    gpa.free(buffers);
    table.deinit(gpa);
    if (startup.bytes_live != 0) return error.InvariantBroken;
    w.table = undefined; // The table lived on this function's stack.
    return w.counts;
}

/// Runs the workload twice with the same seed and checks that both runs did the same
/// thing, completion for completion.
pub fn run(seed: u64) Error!Counts {
    // The workload holds a Sim, so it lives in static memory rather than on the stack.
    const static = struct {
        var workload: Workload = undefined;
    };
    const counts = try runOnce(seed, &static.workload);
    const again = try runOnce(seed, &static.workload);
    if (!std.meta.eql(counts, again)) return error.InvariantBroken;
    assert(counts.trace != fnv_offset); // The runs did something to compare.
    assert(counts.accepts > 0);
    return counts;
}
