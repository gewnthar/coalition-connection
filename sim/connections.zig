//! Connection-table workload for the simulation run (roadmap core 4).
//!
//! Seeded arrivals and departures drive a full-size table (http_connections_max entries) to
//! its limit and past it, then empty it again, for `rounds` rounds. A model kept beside the
//! table predicts every answer: which entry an arrival gets (the free stack hands out the
//! entry released last) and under which generation (one more than the entry's releases so
//! far), when an arrival is refused, which socket a departure hands back, and each entry's
//! state. A refused arrival must leave the whole table as it was, and when an entry is
//! handed out again, the id it was released under must find nothing. From the second round on, the table can only hand out entries it took
//! back earlier.
//!
//! Each step folds what it did (the entry, socket and state) into a trace hash, and the
//! workload runs twice per seed: both runs must produce the same trace. Before the runs, a
//! startup with one byte too few must fail with OutOfMemory and leave nothing allocated.

const std = @import("std");
const assert = std.debug.assert;
const cc = @import("coalition_connection");

const constants = cc.constants;
const connections = cc.live.connections;
const Table = connections.Table;
const PeerId = connections.PeerId;
const Index = connections.Index;
const IdParts = connections.IdParts;
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
    assert(rounds >= 2); // Round 2 onward hands out only entries released before.
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
    /// Arrivals handed an entry that was released before.
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
    /// The socket each entry in use was given, or -1.
    sockets: [capacity]Socket,
    states: [capacity]State,
    /// The id each entry was last handed out under: live while `sockets` isn't -1, stale
    /// after its release; meaningful once `acquired` is above zero.
    ids: [capacity]PeerId,
    /// The free stack as it should be: `free_indices[0..free_count]`, top last.
    free_indices: [capacity]Index,
    free_count: u32,
    /// How many times each entry was handed out. Every hand-out but the newest was
    /// released, so for an entry in use this is one more than its generation, wrapping.
    acquired: [capacity]u32,
    next_socket: Socket,

    fn init(model: *Model) void {
        model.sockets = @splat(-1);
        model.states = @splat(.free);
        model.ids = undefined;
        model.acquired = @splat(0);
        model.free_count = capacity;
        model.next_socket = socket_first;
        // Table.init pushes the indices in reverse, so entry 0 is on top.
        var position: u32 = 0;
        while (position < capacity) : (position += 1) {
            model.free_indices[position] = @intCast(capacity - 1 - position);
        }
        assert(position == capacity);
        assert(model.free_indices[capacity - 1] == 0);
        assert(model.free_indices[0] == capacity - 1);
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

/// One arrival: the table must hand out the model's top free entry under the generation
/// its releases predict, or refuse when full.
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
    const parts: IdParts = @bitCast(id);
    const index = parts.index;
    if (index != model.free_indices[model.free_count]) return error.InvariantBroken;
    if (model.sockets[index] != -1) return error.InvariantBroken;
    // Each earlier hand-out of this entry was released once, advancing its generation.
    const generation: connections.Generation = @truncate(model.acquired[index]);
    if (parts.generation != generation) return error.InvariantBroken;
    model.sockets[index] = socket;
    model.states[index] = .reading;
    // A reused entry: the id it was released under last names the old connection, so a
    // completion still carrying it must not find the new one.
    if (model.acquired[index] > 0) {
        if (w.table.lookup(model.ids[index]) != null) return error.InvariantBroken;
        w.counts.reused += 1;
    }
    model.ids[index] = id;
    model.acquired[index] += 1;
    w.counts.accepted += 1;
    w.counts.peak = @max(w.counts.peak, model.inUse());
    assert(w.counts.peak <= capacity);
    trace(&w.counts, 2 | (@as(u64, index) << 8) | (@as(u64, @intCast(socket)) << 32));
    const entry = w.table.get(id);
    if (entry.socket != socket or entry.state != .reading) return error.InvariantBroken;
}

/// A random entry in use, found by probing from a random index, or null when none is.
fn pickInUse(w: *Workload) ?u32 {
    const model = w.model;
    if (model.inUse() == 0) return null;
    var index = w.random.uintLessThan(u32, capacity);
    var probes: u32 = 0;
    while (model.sockets[index] == -1) : (probes += 1) {
        assert(probes < capacity); // At least one entry is in use.
        index = (index + 1) % capacity;
    }
    assert(model.states[index] != .free);
    return index;
}

/// One departure: the table must hand back the socket the model gave that entry.
fn depart(w: *Workload) Error!void {
    const model = w.model;
    const index = pickInUse(w) orelse return;
    assert(model.free_count < capacity);
    const id = model.ids[index];
    // The workload never sends, so the table must not refuse the release.
    const socket = w.table.release(id) catch |err| switch (err) {
        error.SendsInFlight => return error.InvariantBroken,
    };
    if (socket != model.sockets[index]) return error.InvariantBroken;
    model.sockets[index] = -1;
    model.states[index] = .free;
    model.free_indices[model.free_count] = @intCast(index);
    model.free_count += 1;
    w.counts.departures += 1;
    trace(&w.counts, 3 | (@as(u64, index) << 8) | (@as(u64, @intCast(socket)) << 32));
    assert(model.free_count <= capacity);
}

/// Moves a random connection to the state it isn't in.
fn changeState(w: *Workload) Error!void {
    const model = w.model;
    const index = pickInUse(w) orelse return;
    assert(model.sockets[index] >= socket_first);
    assert(model.states[index] != .free);
    const id = model.ids[index];
    const state: State = if (model.states[index] == .reading) .writing else .reading;
    w.table.setState(id, state);
    model.states[index] = state;
    w.counts.state_changes += 1;
    trace(&w.counts, 4 | (@as(u64, index) << 8) | (@as(u64, @backingInt(state)) << 32));
    const entry = w.table.get(id);
    if (entry.state != state or entry.socket != model.sockets[index]) return error.InvariantBroken;
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
/// state under the model's id, and the free stack matches the model's, entry for entry.
fn checkTable(w: *const Workload) Error!void {
    const model = w.model;
    assert(model.free_count <= capacity);
    w.table.assertInvariants();
    assert(w.table.capacity() == capacity);
    if (w.table.free_count != model.free_count) return error.InvariantBroken;
    const stack = w.table.free_indices[0..w.table.free_count];
    if (!std.mem.eql(Index, stack, model.free_indices[0..model.free_count])) {
        return error.InvariantBroken;
    }
    var index: u32 = 0;
    while (index < capacity) : (index += 1) {
        const socket = model.sockets[index];
        if (socket == -1) continue;
        const entry = w.table.get(model.ids[index]);
        if (entry.socket != socket or entry.state != model.states[index]) {
            return error.InvariantBroken;
        }
    }
    assert(index == capacity);
}

/// After every round: the table reached its limit and refused past it, and every entry was
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
