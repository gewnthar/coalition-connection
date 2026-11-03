//! Connection-table workload for the simulation run (roadmap core 4).
//!
//! Seeded arrivals and departures drive a full-size table (http_connections_max entries) to
//! its limit and past it, then empty it again, for `rounds` rounds. A model kept beside the
//! table predicts every answer: which id an arrival gets (the free stack hands out the id
//! released last), when an arrival is refused, which socket a departure hands back, and
//! each entry's state. A refused arrival must leave the whole table as it was. From the
//! second round on, the table can only hand out ids it took back earlier.
//!
//! Each step folds what it did (the id, socket and state) into a trace hash, and the
//! workload runs twice per seed: both runs must produce the same trace. Before the runs, a
//! startup with one byte too few must fail with OutOfMemory and leave nothing allocated.

const std = @import("std");
const assert = std.debug.assert;
const cc = @import("coalition_connection");

const constants = cc.constants;
const connections = cc.live.connections;
const Table = connections.Table;
const PeerId = connections.PeerId;
const Socket = connections.Socket;
const State = connections.State;

pub const Error = error{InvariantBroken};

const capacity: u32 = constants.http_connections_max;

/// Each round fills the table, keeps arriving until this many arrivals were refused, then
/// empties it.
const rounds: u32 = 4;
const refusals_per_fill: u32 = 8;

/// Out of 8: arrivals while filling, and while emptying. The rest are departures.
const fill_arrival_eighths: u8 = 6;
const empty_arrival_eighths: u8 = 2;

/// Out of 8: how often a step also moves a random connection between reading and writing.
const state_change_eighths: u8 = 4;

/// A phase drifts toward its goal by half a connection per step on average, so it needs
/// about 2 * capacity steps (standard deviation about 160); four times that leaves a margin
/// no valid seed comes near, and a phase that runs out of steps is a failure, not a hang.
const phase_steps_max: u32 = 8 * capacity;

/// The first fake socket. 0 is a valid descriptor, so the workload starts there.
const socket_first: Socket = 0;

comptime {
    assert(rounds >= 2); // Round 2 onward hands out only ids released before.
    assert(fill_arrival_eighths > 4 and empty_arrival_eighths < 4);
    assert(state_change_eighths < 8);
    // Every arrival gets a distinct socket, and the last one still fits a Socket.
    const steps_total: u64 = @as(u64, rounds) * 2 * phase_steps_max;
    assert(steps_total + socket_first <= std.math.maxInt(Socket));
}

/// What a run did. Two runs with the same seed must match field for field.
pub const Counts = struct {
    arrivals: u32 = 0,
    accepted: u32 = 0,
    refused: u32 = 0,
    departures: u32 = 0,
    /// Arrivals handed an id that was released before.
    reused: u32 = 0,
    state_changes: u32 = 0,
    peak: u32 = 0,
    steps: u32 = 0,
    /// FNV-1a over every step's operation, id, socket and state, in order.
    trace: u64 = fnv_offset,
};

const fnv_offset: u64 = 0xcbf29ce484222325;
const fnv_prime: u64 = 0x100000001b3;

/// Folds one value into the trace hash.
fn trace(counts: *Counts, value: u64) void {
    assert(counts.steps > 0); // Only steps write the trace.
    assert(value & 0xff != 0); // Every value carries its operation in the low byte.
    counts.trace = (counts.trace ^ value) *% fnv_prime;
}

/// The table as it should be.
const Model = struct {
    /// The socket each id in use was given, or -1.
    sockets: [capacity]Socket,
    states: [capacity]State,
    /// The free stack as it should be: `free_ids[0..free_count]`, top last.
    free_ids: [capacity]PeerId,
    free_count: u32,
    /// How many times each id was handed out.
    acquired: [capacity]u32,
    next_socket: Socket,

    fn init(model: *Model) void {
        model.sockets = @splat(-1);
        model.states = @splat(.free);
        model.acquired = @splat(0);
        model.free_count = capacity;
        model.next_socket = socket_first;
        // Table.init pushes the ids in reverse, so id 0 is on top.
        var position: u32 = 0;
        while (position < capacity) : (position += 1) {
            model.free_ids[position] = capacity - 1 - position;
        }
        assert(position == capacity);
        assert(model.free_ids[capacity - 1] == 0);
        assert(model.free_ids[0] == capacity - 1);
    }

    fn inUse(model: *const Model) u32 {
        assert(model.free_count <= capacity);
        const in_use = capacity - model.free_count;
        assert(in_use + model.free_count == capacity);
        return in_use;
    }
};

const Workload = struct {
    table: Table,
    model: *Model,
    random: std.Random,
    counts: Counts,
};

/// One arrival: the table must hand out the model's top free id, or refuse when full.
fn arrive(w: *Workload) Error!void {
    const model = w.model;
    assert(model.next_socket >= socket_first);
    const socket = model.next_socket;
    model.next_socket += 1;
    w.counts.arrivals += 1;
    const in_use = model.inUse();
    const id = w.table.acquire(socket) catch |err| switch (err) {
        error.TableFull => {
            if (in_use != capacity) return error.InvariantBroken;
            w.counts.refused += 1;
            trace(&w.counts, 1);
            // The whole table, not just its count, must be as it was.
            return checkTable(w);
        },
    };
    if (in_use == capacity) return error.InvariantBroken; // Accepted past the limit.
    model.free_count -= 1;
    if (id != model.free_ids[model.free_count]) return error.InvariantBroken;
    if (model.sockets[id] != -1) return error.InvariantBroken;
    model.sockets[id] = socket;
    model.states[id] = .reading;
    if (model.acquired[id] > 0) w.counts.reused += 1;
    model.acquired[id] += 1;
    w.counts.accepted += 1;
    w.counts.peak = @max(w.counts.peak, model.inUse());
    assert(w.counts.peak <= capacity);
    trace(&w.counts, 2 | @as(u64, id) << 8 | @as(u64, @intCast(socket)) << 32);
    const entry = w.table.get(id);
    if (entry.socket != socket or entry.state != .reading) return error.InvariantBroken;
}

/// A random connection in use, found by probing from a random id, or null when none is.
fn pickInUse(w: *Workload) ?PeerId {
    const model = w.model;
    if (model.inUse() == 0) return null;
    var id = w.random.uintLessThan(PeerId, capacity);
    var probes: u32 = 0;
    while (model.sockets[id] == -1) : (probes += 1) {
        assert(probes < capacity); // At least one id is in use.
        id = (id + 1) % capacity;
    }
    assert(model.states[id] != .free);
    return id;
}

/// One departure: the table must hand back the socket the model gave that id.
fn depart(w: *Workload) Error!void {
    const model = w.model;
    const id = pickInUse(w) orelse return;
    assert(model.free_count < capacity);
    const socket = w.table.release(id);
    if (socket != model.sockets[id]) return error.InvariantBroken;
    model.sockets[id] = -1;
    model.states[id] = .free;
    model.free_ids[model.free_count] = id;
    model.free_count += 1;
    w.counts.departures += 1;
    trace(&w.counts, 3 | @as(u64, id) << 8 | @as(u64, @intCast(socket)) << 32);
    assert(model.free_count <= capacity);
}

/// Moves a random connection to the state it isn't in.
fn changeState(w: *Workload) Error!void {
    const model = w.model;
    const id = pickInUse(w) orelse return;
    assert(model.sockets[id] >= socket_first);
    assert(model.states[id] != .free);
    const state: State = if (model.states[id] == .reading) .writing else .reading;
    w.table.setState(id, state);
    model.states[id] = state;
    w.counts.state_changes += 1;
    trace(&w.counts, 4 | @as(u64, id) << 8 | @as(u64, @backingInt(state)) << 32);
    const entry = w.table.get(id);
    if (entry.state != state or entry.socket != model.sockets[id]) return error.InvariantBroken;
}

fn step(w: *Workload, arrival_eighths: u8) Error!void {
    assert(arrival_eighths < 8);
    const steps_before = w.counts.steps;
    w.counts.steps += 1;
    if (w.random.uintLessThan(u8, 8) < arrival_eighths) try arrive(w) else try depart(w);
    if (w.random.uintLessThan(u8, 8) < state_change_eighths) try changeState(w);
    if (w.table.count() != w.model.inUse()) return error.InvariantBroken;
    if (w.table.free_count != w.model.free_count) return error.InvariantBroken;
    assert(w.counts.steps == steps_before + 1);
}

/// Fills the table, then keeps arriving until `refusals_per_fill` arrivals were refused.
fn fill(w: *Workload) Error!void {
    const refused_before = w.counts.refused;
    var steps: u32 = 0;
    while (w.counts.refused - refused_before < refusals_per_fill) : (steps += 1) {
        if (steps == phase_steps_max) return error.InvariantBroken;
        try step(w, fill_arrival_eighths);
    }
    assert(steps <= phase_steps_max);
    assert(w.counts.refused - refused_before == refusals_per_fill);
}

/// Empties the table.
fn empty(w: *Workload) Error!void {
    var steps: u32 = 0;
    while (w.model.inUse() > 0) : (steps += 1) {
        if (steps == phase_steps_max) return error.InvariantBroken;
        try step(w, empty_arrival_eighths);
    }
    assert(steps <= phase_steps_max);
    assert(w.table.count() == 0);
}

/// Walks the whole table against the model: every entry in use holds the model's socket and
/// state, and the free stack matches the model's, id for id.
fn checkTable(w: *const Workload) Error!void {
    const model = w.model;
    assert(model.free_count <= capacity);
    w.table.assertInvariants();
    assert(w.table.capacity() == capacity);
    if (w.table.free_count != model.free_count) return error.InvariantBroken;
    const stack = w.table.free_ids[0..w.table.free_count];
    if (!std.mem.eql(PeerId, stack, model.free_ids[0..model.free_count])) {
        return error.InvariantBroken;
    }
    var id: PeerId = 0;
    while (id < capacity) : (id += 1) {
        const socket = model.sockets[id];
        if (socket == -1) continue;
        const entry = w.table.get(id);
        if (entry.socket != socket or entry.state != model.states[id]) {
            return error.InvariantBroken;
        }
    }
    assert(id == capacity);
}

/// After every round: the table reached its limit and refused past it, and every id was
/// handed out at least `rounds` times in all, so each was handed out again after a release.
fn checkEnd(w: *const Workload) Error!void {
    const counts = w.counts;
    assert(w.table.count() == 0);
    assert(w.model.inUse() == 0);
    if (counts.peak != capacity) return error.InvariantBroken;
    // Each fill ends after exactly refusals_per_fill refusals; an empty phase starts with a
    // full table, so its first arrivals may be refused too.
    if (counts.refused < rounds * refusals_per_fill) return error.InvariantBroken;
    if (counts.accepted != counts.departures) return error.InvariantBroken;
    if (counts.arrivals != counts.accepted + counts.refused) return error.InvariantBroken;
    for (w.model.acquired) |acquired| {
        if (acquired < rounds) return error.InvariantBroken;
    }
    if (counts.state_changes == 0) return error.InvariantBroken;
    assert(counts.reused == counts.accepted - capacity); // Only first hand-outs aren't reuses.
}

/// One run: a full-size table, allocated at startup within exactly its own bytes, through
/// `rounds` fills and empties.
fn runOnce(seed: u64, model: *Model) Error!Counts {
    const budget: u64 = @as(u64, capacity) * connections.entry_bytes;
    var startup = cc.StartupAllocator.init(std.heap.page_allocator, budget);
    const gpa = startup.allocator();
    const table = Table.init(gpa, capacity) catch return error.InvariantBroken;
    assert(startup.bytes_live == budget); // Exactly its own bytes: nothing hidden.
    startup.finishStartup();
    model.init();

    var prng: std.Random.DefaultPrng = .init(seed);
    var w: Workload = .{ .table = table, .model = model, .random = prng.random(), .counts = .{} };
    try checkTable(&w);
    var round: u32 = 0;
    errdefer std.debug.print("sim: connections failed in round {d} at step {d}\n", .{ round, w.counts.steps });
    while (round < rounds) : (round += 1) {
        try fill(&w);
        if (w.table.count() != capacity) return error.InvariantBroken;
        try checkTable(&w);
        try empty(&w);
        try checkTable(&w);
    }
    assert(round == rounds);
    try checkEnd(&w);

    startup.beginShutdown();
    w.table.deinit(gpa);
    if (startup.bytes_live != 0) return error.InvariantBroken;
    assert(w.counts.arrivals == w.counts.accepted + w.counts.refused);
    return w.counts;
}

/// A startup one byte short of the table's bytes: the second allocation fails, and the
/// first must be given back.
fn checkInitOutOfMemory() Error!void {
    const budget: u64 = @as(u64, capacity) * connections.entry_bytes - 1;
    var startup = cc.StartupAllocator.init(std.heap.page_allocator, budget);
    const gpa = startup.allocator();
    if (Table.init(gpa, capacity)) |table| {
        var leaked = table;
        startup.finishStartup();
        startup.beginShutdown();
        leaked.deinit(gpa);
        return error.InvariantBroken;
    } else |err| switch (err) {
        error.OutOfMemory => {},
    }
    if (startup.bytes_live != 0) return error.InvariantBroken;
    assert(startup.allocationAllowed());
}

/// Checks a failed startup, then runs the workload twice with the same seed and checks
/// that both runs did the same thing, step for step.
pub fn run(seed: u64) Error!Counts {
    try checkInitOutOfMemory();
    // The model is about 64 KiB, so it lives in static memory rather than on the stack.
    // Each run starts it afresh.
    const static = struct {
        var model: Model = undefined;
    };
    const counts = try runOnce(seed, &static.model);
    const again = try runOnce(seed, &static.model);
    if (!std.meta.eql(counts, again)) return error.InvariantBroken;
    assert(counts.peak == capacity);
    assert(counts.refused > 0);
    return counts;
}
