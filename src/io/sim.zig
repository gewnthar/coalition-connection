//! Deterministic simulator for the I/O boundary.
//!
//! Job: stand in for the network, the clock, the database and the random source, driven by
//! one seed. Time moves only when `tick` is called. Each submitted operation completes after a
//! seeded delay, so completions arrive out of submission order. Faults of every kind the
//! contract names, and short sends, are drawn from a seeded PRNG and counted. A failing seed
//! replays exactly.
//!
//! Three seeded streams keep each kind of draw independent of the others:
//!   outcomes   each operation's delay and result, drawn when it is submitted
//!   schedule   which free slot an operation takes and where each poll starts its scan
//!   random     the bytes `randomBytes` hands out
//! So how often a workload polls, or how many nonces it draws, never changes which
//! operations fail.
//!
//! Accepts: an accept's delay is the wait for a connection to arrive. When it completes, the
//! arrival takes an entry in the connection table attached with `attachTable`, under a fake
//! socket number never handed out before; a full table refuses it with `error.TableFull`,
//! as the real type does, and counts the refusal. Whether the connection fails before it
//! arrives is drawn at submit, like every other outcome, so the same seed refuses the same
//! arrivals in the same order.
//!
//! Inputs: a seed, a fault rate in percent (at most `constants.sim_fault_percent_max`) and,
//! for accepts, a connection table.
//! Outputs: the same contract as io/root.zig, plus counters a test can assert on.
//! Limits: at most `constants.sim_ticks_max` ticks per run, at most
//! `constants.io_operations_in_flight_max` operations in flight, and delays of at most
//! `constants.sim_completion_delay_ticks_max` ticks.
//!
//! Only tests and programs whose root file declares `pub const io_simulation = true;` may
//! use a `Sim`: `init`, `submit` and `randomBytes` each refuse to compile anywhere else, so
//! the seeded random source can't reach a production build.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const connections = @import("../live/connections.zig");
const io = @import("root.zig");

const slots_count = constants.io_operations_in_flight_max;

/// The first fake socket an arrival gets: above any descriptor a test or workload names as
/// its listener, so an arrival never shares a number with one, as with a real kernel.
const socket_first: io.Socket = 1 << 16;

/// Arrivals a run may have: every one gets a distinct fake socket that fits `io.Socket`.
const arrivals_max: u64 = std.math.maxInt(io.Socket) - socket_first;

/// Salts that separate the schedule and random streams from the outcome stream.
const schedule_salt: u64 = 0x9e37_79b9_7f4a_7c15;
const random_salt: u64 = 0xc2b2_ae3d_27d4_eb4f;

/// Faults injected so far, one counter per error the contract names.
pub const Faults = struct {
    peer_down: u32 = 0,
    backpressure: u32 = 0,
    unavailable: u32 = 0,
    timeout: u32 = 0,
    /// Accepts whose connection failed before it arrived, or that found the system short.
    accept_peer_down: u32 = 0,
    accept_backpressure: u32 = 0,

    pub fn total(self: Faults) u64 {
        const sends = @as(u64, self.peer_down) + self.backpressure;
        const executes = @as(u64, self.unavailable) + self.timeout;
        const accepts = @as(u64, self.accept_peer_down) + self.accept_backpressure;
        assert(sends >= self.peer_down and sends >= self.backpressure);
        assert(executes >= self.unavailable and executes >= self.timeout);
        return sends + executes + accepts;
    }
};

/// An accept's fault, drawn at submit. A full table is not drawn: it depends on the table
/// when the connection arrives.
const ArrivalError = error{ PeerDown, Backpressure };

/// What `submit` draws for an operation. A send's and a statement's result is final; an
/// accept draws only whether its connection fails, and takes its table entry on completion.
const Drawn = union(io.Kind) {
    send: io.SendError!u32,
    execute: io.DatabaseError!void,
    accept: ArrivalError!void,
};

const Slot = struct {
    submission: io.Submission,
    due_tick: u32,
    /// Drawn at submit, turned into the result at completion.
    drawn: Drawn,
    /// Hash of the operation's bytes at submit; they must be unchanged at completion.
    bytes_hash: u64,
};

pub const Sim = struct {
    outcomes: std.Random.DefaultPrng,
    schedule: std.Random.DefaultPrng,
    random_source: std.Random.DefaultPrng,
    fault_percent: u8,
    ticks: u32,
    now_ns: io.Instant,
    slots: [slots_count]?Slot,
    in_flight: u32,
    submitted: u64,
    completed: u64,
    bytes_sent: u64,
    short_sends: u32,
    statements: u32,
    random_bytes: u64,
    faults: Faults,
    /// Where arrivals take their entries; set once by `attachTable`, before any accept.
    table: ?*connections.Table,
    /// Arrivals that took a table entry, and arrivals a full table refused.
    accepted: u64,
    refused: u64,

    pub fn init(seed: u64, fault_percent: u8) Sim {
        comptime assertSimulationAllowed();
        assert(fault_percent <= constants.sim_fault_percent_max);
        const result: Sim = .{
            .outcomes = .init(seed),
            .schedule = .init(seed ^ schedule_salt),
            .random_source = .init(seed ^ random_salt),
            .fault_percent = fault_percent,
            .ticks = 0,
            .now_ns = 0,
            .slots = @splat(null),
            .in_flight = 0,
            .submitted = 0,
            .completed = 0,
            .bytes_sent = 0,
            .short_sends = 0,
            .statements = 0,
            .random_bytes = 0,
            .faults = .{},
            .table = null,
            .accepted = 0,
            .refused = 0,
        };
        assert(result.ticks == 0);
        assert(result.in_flight == 0);
        return result;
    }

    /// Gives arrivals a connection table to take their entries in. Call it once, before the
    /// first accept; the table is the caller's and must outlive every accept.
    pub fn attachTable(self: *Sim, table: *connections.Table) void {
        assert(self.table == null);
        assert(self.accepted + self.refused == 0);
        assert(table.capacity() > 0);
        self.table = table;
    }

    /// Advances simulated time by one tick.
    pub fn tick(self: *Sim) void {
        assert(self.ticks < constants.sim_ticks_max);
        self.ticks += 1;
        self.now_ns += constants.tick_ns;
        assert(self.now_ns == @as(u64, self.ticks) * constants.tick_ns);
    }

    pub fn now(self: *Sim) io.Instant {
        assert(self.ticks <= constants.sim_ticks_max);
        assert(self.now_ns == @as(u64, self.ticks) * constants.tick_ns);
        return self.now_ns;
    }

    /// Queues one operation to complete after a seeded delay of 0 to
    /// `sim_completion_delay_ticks_max` ticks, capped at the run's last tick, with its result
    /// drawn now. A full table returns `error.QueueFull` and leaves the state unchanged. An
    /// id already in flight breaks the contract and crashes, full table or not.
    pub fn submit(self: *Sim, submission: io.Submission) io.SubmitError!void {
        comptime assertSimulationAllowed();
        assert(self.in_flight <= slots_count);
        assertOperation(submission.operation);
        // An arrival needs a table to take its entry in.
        assert(submission.operation != .accept or self.table != null);
        self.assertIdNotInFlight(submission.id);
        if (self.in_flight == slots_count) return error.QueueFull;

        const index = self.freeSlot();
        const delay_max = constants.sim_completion_delay_ticks_max;
        const delay = self.outcomes.random().uintAtMost(u32, delay_max);
        // Never due after the run's last tick, so every accepted operation can complete.
        const due_tick = @min(self.ticks + delay, constants.sim_ticks_max);
        assert(due_tick >= self.ticks);
        self.slots[index] = .{
            .submission = submission,
            .due_tick = due_tick,
            .drawn = self.draw(submission.operation),
            .bytes_hash = hashOperation(submission.operation),
        };
        self.in_flight += 1;
        self.submitted += 1;
        assert(self.slots[index] != null);
        assert(self.completed + self.in_flight == self.submitted);
    }

    /// Moves operations that are due into `completions` and returns how many. The scan starts
    /// at a slot drawn from the schedule stream, so operations due on the same tick also come
    /// back in a seeded order. With nothing due it returns 0 and changes nothing else.
    pub fn poll(self: *Sim, completions: []io.Completion) u32 {
        assert(completions.len > 0);
        assert(completions.len <= slots_count);
        const in_flight_before = self.in_flight;
        const start = self.schedule.random().uintLessThan(u32, slots_count);

        var count: u32 = 0;
        var step: u32 = 0;
        while (step < slots_count and count < completions.len) : (step += 1) {
            const index = (start + step) % slots_count;
            const slot = self.slots[index] orelse continue;
            if (slot.due_tick > self.ticks) continue;
            self.slots[index] = null;
            completions[count] = self.complete(slot);
            count += 1;
        }
        assert(step <= slots_count);
        assert(count <= in_flight_before);
        self.in_flight -= count;
        assert(self.completed + self.in_flight == self.submitted);
        return count;
    }

    /// Fills `buffer` from the seeded random stream. Same seed, same bytes. Never fails, but
    /// keeps the contract's error so callers handle the production failure.
    pub fn randomBytes(self: *Sim, buffer: []u8) io.RandomError!void {
        comptime assertSimulationAllowed();
        assert(buffer.len > 0);
        assert(buffer.len <= constants.io_random_bytes_max);
        const drawn: u32 = @intCast(buffer.len);
        const before = self.random_bytes;
        self.random_source.random().bytes(buffer);
        self.random_bytes += drawn;
        assert(self.random_bytes == before + drawn);
    }

    /// The contract says ids in flight are distinct, so a caller that reuses one has a bug:
    /// its two completions would be indistinguishable. Scans every slot, at most
    /// `slots_count` steps, and crashes on a match. Changes no state.
    fn assertIdNotInFlight(self: *const Sim, id: io.OperationId) void {
        var occupied: u32 = 0;
        var index: u32 = 0;
        while (index < slots_count) : (index += 1) {
            const slot = self.slots[index] orelse continue;
            occupied += 1;
            assert(slot.submission.id != id);
        }
        // The count of occupied slots and `in_flight` are kept separately; they must agree.
        assert(occupied == self.in_flight);
    }

    /// Takes a free slot, scanning from a seeded offset.
    fn freeSlot(self: *Sim) u32 {
        assert(self.in_flight < slots_count);
        const start = self.schedule.random().uintLessThan(u32, slots_count);
        var step: u32 = 0;
        while (step < slots_count) : (step += 1) {
            if (self.slots[(start + step) % slots_count] == null) break;
        }
        // Fewer than slots_count operations are in flight, so the scan found a free slot.
        assert(step < slots_count);
        return (start + step) % slots_count;
    }

    fn draw(self: *Sim, operation: io.Operation) Drawn {
        assert(self.fault_percent <= constants.sim_fault_percent_max);
        const result: Drawn = switch (operation) {
            .send => |send| .{ .send = self.drawSend(send) },
            .execute => .{ .execute = self.drawExecute() },
            .accept => .{ .accept = self.drawArrival() },
        };
        assert(@as(io.Kind, result) == @as(io.Kind, operation));
        return result;
    }

    /// A send fails, completes short, or sends every byte.
    fn drawSend(self: *Sim, send: io.Send) io.SendError!u32 {
        assert(send.bytes.len > 0);
        assert(send.bytes.len <= constants.http_response_size_max);
        const length: u32 = @intCast(send.bytes.len);
        if (self.fault()) {
            if (self.outcomes.random().boolean()) return error.PeerDown;
            return error.Backpressure;
        }
        if (length > 1 and self.fault()) {
            return 1 + self.outcomes.random().uintLessThan(u32, length - 1);
        }
        return length;
    }

    fn drawExecute(self: *Sim) io.DatabaseError!void {
        assert(self.fault_percent <= constants.sim_fault_percent_max);
        assert(self.in_flight < slots_count);
        if (self.fault()) {
            if (self.outcomes.random().boolean()) return error.Unavailable;
            return error.Timeout;
        }
    }

    /// An accept's connection fails before it arrives, the system is short, or it arrives.
    fn drawArrival(self: *Sim) ArrivalError!void {
        assert(self.fault_percent <= constants.sim_fault_percent_max);
        assert(self.table != null);
        if (self.fault()) {
            if (self.outcomes.random().boolean()) return error.PeerDown;
            return error.Backpressure;
        }
    }

    fn fault(self: *Sim) bool {
        assert(self.fault_percent <= constants.sim_fault_percent_max);
        const roll = self.outcomes.random().uintLessThan(u8, 100);
        assert(roll < 100);
        return roll < self.fault_percent;
    }

    /// Turns a slot's drawn outcome into its result and counts it. Crashes if the caller
    /// changed the operation's bytes while it was in flight.
    fn complete(self: *Sim, slot: Slot) io.Completion {
        assert(self.completed < self.submitted);
        assert(hashOperation(slot.submission.operation) == slot.bytes_hash);
        const result: io.Result = switch (slot.drawn) {
            .send => |sent| sent: {
                self.countSend(sent, slot.submission.operation.send);
                break :sent .{ .send = sent };
            },
            .execute => |executed| executed: {
                self.countExecute(executed);
                break :executed .{ .execute = executed };
            },
            .accept => |arrival| .{ .accept = self.arrive(arrival) },
        };
        assert(@as(io.Kind, result) == @as(io.Kind, slot.submission.operation));
        self.completed += 1;
        return .{ .id = slot.submission.id, .result = result };
    }

    /// An arrival takes a table entry under a fresh fake socket; a full table refuses it and
    /// counts the refusal, and a drawn fault is counted and handed back.
    fn arrive(self: *Sim, arrival: ArrivalError!void) io.AcceptError!io.PeerId {
        assert(self.table != null); // `submit` checked it for every accept.
        const table = self.table.?;
        const faults_before = self.faults.total();
        arrival catch |err| {
            switch (err) {
                error.PeerDown => self.faults.accept_peer_down += 1,
                error.Backpressure => self.faults.accept_backpressure += 1,
            }
            assert(self.faults.total() == faults_before + 1);
            return err;
        };
        const arrivals = self.accepted + self.refused;
        assert(arrivals < arrivals_max);
        const socket: io.Socket = socket_first + @as(io.Socket, @intCast(arrivals));
        const peer = table.acquire(socket) catch |err| switch (err) {
            error.TableFull => {
                self.refused += 1;
                assert(self.accepted + self.refused == arrivals + 1);
                return error.TableFull;
            },
        };
        self.accepted += 1;
        assert(table.get(peer).socket == socket);
        assert(self.faults.total() == faults_before);
        return peer;
    }

    fn countSend(self: *Sim, sent: io.SendError!u32, send: io.Send) void {
        assert(send.bytes.len > 0);
        const faults_before = self.faults.total();
        const bytes = sent catch |err| {
            switch (err) {
                error.PeerDown => self.faults.peer_down += 1,
                error.Backpressure => self.faults.backpressure += 1,
            }
            assert(self.faults.total() == faults_before + 1);
            return;
        };
        assert(bytes > 0 and bytes <= send.bytes.len);
        if (bytes < send.bytes.len) self.short_sends += 1;
        self.bytes_sent += bytes;
    }

    fn countExecute(self: *Sim, executed: io.DatabaseError!void) void {
        const faults_before = self.faults.total();
        executed catch |err| {
            switch (err) {
                error.Unavailable => self.faults.unavailable += 1,
                error.Timeout => self.faults.timeout += 1,
            }
            assert(self.faults.total() == faults_before + 1);
            return;
        };
        self.statements += 1;
        assert(self.faults.total() == faults_before);
    }
};

/// Preconditions on an operation: a caller that breaks one has a bug, so these assert.
fn assertOperation(operation: io.Operation) void {
    switch (operation) {
        .send => |send| {
            const peer: connections.IdParts = @bitCast(send.peer);
            assert(peer.index < constants.http_connections_max);
            assert(send.bytes.len > 0);
            assert(send.bytes.len <= constants.http_response_size_max);
        },
        .execute => |execute| {
            assert(execute.statement.len > 0);
            assert(execute.statement.len <= constants.postgres_message_size_max);
        },
        .accept => |accept| assert(accept.listener >= 0),
    }
}

/// An accept names no caller bytes; its listener is hashed, so every kind is checked alike.
fn hashOperation(operation: io.Operation) u64 {
    const bytes: []const u8 = switch (operation) {
        .send => |send| send.bytes,
        .execute => |execute| execute.statement,
        .accept => |*accept| std.mem.asBytes(&accept.listener),
    };
    assert(bytes.len > 0);
    assert(bytes.len <= @max(constants.http_response_size_max, constants.postgres_message_size_max));
    return std.hash.Wyhash.hash(0, bytes);
}

/// Stops the build when a program that isn't a test or a declared simulation uses a `Sim`,
/// because its seeded random bytes would make every nonce predictable. A function body is
/// analyzed only when something calls it, so the check sits in each entry point.
fn assertSimulationAllowed() void {
    comptime {
        assert(@TypeOf(builtin.is_test) == bool);
        if (!builtin.is_test) {
            const root = @import("root");
            if (!@hasDecl(root, "io_simulation") or !root.io_simulation) {
                @compileError("io.sim.Sim is for tests and simulations only: declare " ++
                    "`pub const io_simulation = true;` in the simulation's root file");
            }
        }
        assert(builtin.is_test or @hasDecl(@import("root"), "io_simulation"));
    }
}

const testing = std.testing;

const recorded_max: u32 = 512;
const record_ticks_max: u32 = recorded_max + constants.sim_completion_delay_ticks_max + 1;

const Recording = struct {
    ids: [recorded_max]io.OperationId,
    /// The tick each operation was submitted and completed on, by id.
    submitted_tick: [recorded_max]u32,
    completed_tick: [recorded_max]u32,
    count: u32,
    sim: Sim,
};

/// Submits `recorded_max` operations, alternating sends and statements, at two per tick,
/// and records the order and the ticks their completions come back on.
fn record(seed: u64, fault_percent: u8) io.SubmitError!Recording {
    var recording: Recording = .{
        .ids = @splat(0),
        .submitted_tick = @splat(0),
        .completed_tick = @splat(0),
        .count = 0,
        .sim = .init(seed, fault_percent),
    };
    var next: io.OperationId = 0;
    var ticks: u32 = 0;
    while (ticks < record_ticks_max and recording.count < recorded_max) : (ticks += 1) {
        if (next < recorded_max) {
            // Two submissions per tick for at most 17 ticks stay far below the table's size.
            try recording.sim.submit(testSubmission(next));
            try recording.sim.submit(testSubmission(next + 1));
            recording.submitted_tick[@intCast(next)] = recording.sim.ticks;
            recording.submitted_tick[@intCast(next + 1)] = recording.sim.ticks;
            next += 2;
        }
        recording.sim.tick();
        drainInto(&recording);
    }
    assert(ticks <= record_ticks_max);
    assert(recording.count == recorded_max);
    assert(recording.sim.in_flight == 0);
    return recording;
}

fn drainInto(recording: *Recording) void {
    assert(recording.count <= recorded_max);
    var completions: [16]io.Completion = undefined;
    var batches: u32 = 0;
    while (batches < slots_count) : (batches += 1) {
        const count = recording.sim.poll(&completions);
        for (completions[0..count]) |completion| {
            recording.ids[recording.count] = completion.id;
            recording.completed_tick[@intCast(completion.id)] = recording.sim.ticks;
            recording.count += 1;
        }
        if (count == 0) break;
    }
    assert(batches < slots_count);
}

/// Even ids are sends, odd ids are statements.
fn testSubmission(id: io.OperationId) io.Submission {
    assert(id <= recorded_max + slots_count);
    const operation: io.Operation = if (id % 2 == 0)
        .{ .send = .{ .peer = @intCast(id % 8), .bytes = "ping" } }
    else
        .{ .execute = .{ .statement = "select 1" } };
    const expected: io.Kind = if (id % 2 == 0) .send else .execute;
    assert(@as(io.Kind, operation) == expected);
    return .{ .id = id, .operation = operation };
}

test "sim: same seed, same completion order and counts" {
    const a = try record(42, 20);
    const b = try record(42, 20);
    try testing.expectEqualSlices(io.OperationId, &a.ids, &b.ids);
    try testing.expectEqual(a.sim.faults, b.sim.faults);
    try testing.expectEqual(a.sim.bytes_sent, b.sim.bytes_sent);
    try testing.expectEqual(a.sim.statements, b.sim.statements);
    const c = try record(43, 20);
    try testing.expect(!std.mem.eql(io.OperationId, &a.ids, &c.ids));
}

test "sim: delays reorder completions within the bound, each operation once" {
    const run = try record(7, 0);
    var seen: [recorded_max]bool = @splat(false);
    var reordered = false;
    for (run.ids[0..run.count], 0..) |id, index| {
        try testing.expect(id < recorded_max);
        try testing.expect(!seen[@intCast(id)]);
        seen[@intCast(id)] = true;
        if (index > 0 and id < run.ids[index - 1]) reordered = true;
        // Never before the tick after submission, never later than the longest delay.
        const waited = run.completed_tick[@intCast(id)] - run.submitted_tick[@intCast(id)];
        try testing.expect(waited >= 1);
        try testing.expect(waited <= constants.sim_completion_delay_ticks_max);
    }
    try testing.expect(reordered);
    try testing.expectEqual(@as(u64, recorded_max), run.sim.completed);
    try testing.expectEqual(run.sim.submitted, run.sim.completed);
}

test "sim: a seeded run injects every fault kind and short sends" {
    const run = try record(1, constants.sim_fault_percent_max);
    try testing.expect(run.sim.faults.peer_down > 0);
    try testing.expect(run.sim.faults.backpressure > 0);
    try testing.expect(run.sim.faults.unavailable > 0);
    try testing.expect(run.sim.faults.timeout > 0);
    try testing.expect(run.sim.short_sends > 0);
    try testing.expect(run.sim.faults.total() <= run.sim.completed);
}

test "sim: time moves only on tick" {
    var sim = Sim.init(1, 0);
    try testing.expectEqual(@as(io.Instant, 0), sim.now());
    sim.tick();
    try testing.expectEqual(constants.tick_ns, sim.now());
}

test "sim: a poll with nothing due returns 0 and changes nothing" {
    var sim = Sim.init(5, 0);
    var completions: [4]io.Completion = undefined;
    try testing.expectEqual(@as(u32, 0), sim.poll(&completions));
    try sim.submit(testSubmission(0));
    var polls: u32 = 0;
    while (polls <= constants.sim_completion_delay_ticks_max) : (polls += 1) {
        // An operation is due only once its delay has passed; until then nothing changes.
        const count = sim.poll(&completions);
        if (count == 1) break;
        try testing.expectEqual(@as(u32, 0), count);
        try testing.expectEqual(@as(u32, 1), sim.in_flight);
        try testing.expectEqual(@as(u64, 0), sim.completed);
        sim.tick();
    }
    try testing.expect(polls <= constants.sim_completion_delay_ticks_max);
    try testing.expectEqual(@as(u32, 0), sim.in_flight);
    try testing.expectEqual(@as(u64, 1), sim.completed);
}

test "sim: a zero fault rate never fails and never sends short" {
    var sim = Sim.init(7, 0);
    try sim.submit(.{ .id = 1, .operation = .{ .send = .{ .peer = 0, .bytes = "hello" } } });
    try sim.submit(.{ .id = 2, .operation = .{ .execute = .{ .statement = "select 1" } } });
    var completions: [4]io.Completion = undefined;
    var count: u32 = 0;
    var ticks: u32 = 0;
    while (ticks <= constants.sim_completion_delay_ticks_max) : (ticks += 1) {
        sim.tick();
        count += sim.poll(completions[count..]);
    }
    try testing.expectEqual(@as(u32, 2), count);
    for (completions[0..count]) |completion| switch (completion.result) {
        .send => |sent| try testing.expectEqual(@as(u32, 5), try sent),
        .execute => |executed| try executed,
        .accept => return error.TestUnexpectedResult, // Nothing here submits an accept.
    };
    try testing.expectEqual(@as(u64, 0), sim.faults.total());
    try testing.expectEqual(@as(u64, 5), sim.bytes_sent);
    try testing.expectEqual(@as(u32, 0), sim.short_sends);
}

test "sim: a full table refuses a submission and changes nothing" {
    var sim = Sim.init(3, 0);
    var id: io.OperationId = 0;
    while (id < slots_count) : (id += 1) try sim.submit(testSubmission(id));
    try testing.expectError(error.QueueFull, sim.submit(testSubmission(id)));
    try testing.expectEqual(slots_count, sim.in_flight);
    try testing.expectEqual(@as(u64, slots_count), sim.submitted);

    var completions: [1]io.Completion = undefined;
    var ticks: u32 = 0;
    while (ticks <= constants.sim_completion_delay_ticks_max) : (ticks += 1) sim.tick();
    try testing.expectEqual(@as(u32, 1), sim.poll(&completions));
    try sim.submit(testSubmission(id));
    try testing.expectEqual(slots_count, sim.in_flight);
}

test "sim: an id may be reused once its operation has completed" {
    // Ids need be distinct only while in flight. With every other slot still full, the id
    // that just completed is accepted again, three times over.
    var sim = Sim.init(17, 0);
    var id: io.OperationId = 0;
    while (id < slots_count) : (id += 1) try sim.submit(testSubmission(id));
    var completions: [1]io.Completion = undefined;
    var ticks: u32 = 0;
    while (ticks <= constants.sim_completion_delay_ticks_max) : (ticks += 1) sim.tick();
    var round: u32 = 0;
    while (round < 3) : (round += 1) {
        try testing.expectEqual(@as(u32, 1), sim.poll(&completions));
        try testing.expectEqual(slots_count - 1, sim.in_flight);
        const reused = completions[0].id;
        try testing.expect(reused < slots_count);
        try sim.submit(testSubmission(reused));
        try testing.expectEqual(slots_count, sim.in_flight);
    }
    try testing.expectEqual(@as(u64, 3), sim.completed);
    try testing.expectEqual(@as(u64, slots_count + 3), sim.submitted);
}

test "sim: an operation submitted on the last tick still completes" {
    var sim = Sim.init(13, 0);
    var ticks: u32 = 0;
    while (ticks < constants.sim_ticks_max - 1) : (ticks += 1) sim.tick();
    try sim.submit(testSubmission(0));
    try sim.submit(testSubmission(1));
    sim.tick();
    try testing.expectEqual(constants.sim_ticks_max, sim.ticks);
    var completions: [2]io.Completion = undefined;
    try testing.expectEqual(@as(u32, 2), sim.poll(&completions));
    try testing.expectEqual(@as(u32, 0), sim.in_flight);
}

test "sim: same seed, same random bytes" {
    var a = Sim.init(9, 0);
    var b = Sim.init(9, 0);
    var c = Sim.init(10, 0);
    var bytes_a: [24]u8 = undefined;
    var bytes_b: [24]u8 = undefined;
    var bytes_c: [24]u8 = undefined;
    try a.randomBytes(&bytes_a);
    try b.randomBytes(&bytes_b);
    try c.randomBytes(&bytes_c);
    try testing.expectEqualSlices(u8, &bytes_a, &bytes_b);
    try testing.expect(!std.mem.eql(u8, &bytes_a, &bytes_c));
    try testing.expectEqual(@as(u64, 24), a.random_bytes);
}

test "sim: drawing random bytes and polling often leave outcomes unchanged" {
    const plain = try record(11, constants.sim_fault_percent_max);
    // Same seed and submissions, but this run draws a nonce and polls before every tick too.
    var busy = Sim.init(11, constants.sim_fault_percent_max);
    var completions: [16]io.Completion = undefined;
    var nonce: [24]u8 = undefined;
    var id: io.OperationId = 0;
    var ticks: u32 = 0;
    while (ticks < record_ticks_max) : (ticks += 1) {
        if (id < recorded_max) {
            try busy.submit(testSubmission(id));
            try busy.submit(testSubmission(id + 1));
            id += 2;
        }
        try busy.randomBytes(&nonce);
        _ = busy.poll(&completions);
        busy.tick();
        var batches: u32 = 0;
        while (batches < slots_count and busy.poll(&completions) > 0) : (batches += 1) {}
    }
    try testing.expectEqual(@as(u32, 0), busy.in_flight);
    try testing.expectEqual(plain.sim.completed, busy.completed);
    try testing.expectEqual(plain.sim.faults, busy.faults);
    try testing.expectEqual(plain.sim.short_sends, busy.short_sends);
    try testing.expectEqual(plain.sim.bytes_sent, busy.bytes_sent);
}

/// A small connection table for accept tests, set up in place because a `Sim` keeps a
/// pointer to it.
const TableFixture = struct {
    startup: StartupAllocator,
    gpa: std.mem.Allocator,
    table: connections.Table,

    fn setUp(self: *TableFixture, size: u32) !void {
        assert(size > 0);
        assert(size <= constants.http_connections_max);
        self.startup = .init(testing.allocator, @as(u64, size) * connections.entry_bytes);
        self.gpa = self.startup.allocator();
        self.table = try connections.Table.init(self.gpa, size);
        self.startup.finishStartup();
        assert(self.table.count() == 0);
    }

    fn tearDown(self: *TableFixture) void {
        assert(self.table.capacity() > 0);
        self.startup.beginShutdown();
        self.table.deinit(self.gpa);
        assert(self.startup.bytes_live == 0);
    }
};

const StartupAllocator = @import("../startup_allocator.zig").StartupAllocator;

fn acceptSubmission(id: io.OperationId) io.Submission {
    assert(id < slots_count); // The tests below keep at most a table's worth in flight.
    comptime assert(test_listener < socket_first);
    return .{ .id = id, .operation = .{ .accept = .{ .listener = test_listener } } };
}

const test_listener: io.Socket = 3;

/// Ticks until every operation in flight has completed, collecting at most
/// `completions.len` of them. Returns how many arrived.
fn drainAll(sim: *Sim, completions: []io.Completion) u32 {
    assert(completions.len > 0);
    assert(sim.in_flight <= completions.len);
    var count: u32 = 0;
    var ticks: u32 = 0;
    while (ticks <= constants.sim_completion_delay_ticks_max) : (ticks += 1) {
        sim.tick();
        if (count < completions.len) count += sim.poll(completions[count..]);
    }
    assert(sim.in_flight == 0);
    return count;
}

test "sim: accepts take table entries under fresh sockets until the table is full" {
    var fixture: TableFixture = undefined;
    try fixture.setUp(4);
    defer fixture.tearDown();
    var sim = Sim.init(21, 0);
    sim.attachTable(&fixture.table);
    var id: io.OperationId = 0;
    while (id < 6) : (id += 1) try sim.submit(acceptSubmission(id));
    var completions: [6]io.Completion = undefined;
    try testing.expectEqual(@as(u32, 6), drainAll(&sim, &completions));

    var sockets_seen: [6]io.Socket = @splat(-1);
    var accepted: u32 = 0;
    var refused: u32 = 0;
    // Arrivals take entries in completion order, so a refusal may come only once all four
    // entries were taken: a refusal with room left fails here, not only in the totals.
    for (completions) |completion| {
        if (completion.result.accept) |peer| {
            try testing.expectEqual(@as(u32, 0), refused);
            const socket = fixture.table.get(peer).socket;
            try testing.expect(socket >= socket_first);
            try testing.expect(std.mem.findScalar(io.Socket, &sockets_seen, socket) == null);
            sockets_seen[accepted] = socket;
            accepted += 1;
        } else |err| {
            try testing.expectEqual(error.TableFull, err);
            try testing.expectEqual(@as(u32, 4), accepted);
            refused += 1;
        }
    }
    try testing.expectEqual(@as(u32, 4), accepted);
    try testing.expectEqual(@as(u32, 2), refused);
    try testing.expectEqual(@as(u64, 4), sim.accepted);
    try testing.expectEqual(@as(u64, 2), sim.refused);
    try testing.expectEqual(@as(u32, 4), fixture.table.count());
    try testing.expectEqual(@as(u64, 0), sim.faults.total());
    for (completions) |completion| {
        if (completion.result.accept) |peer| _ = fixture.table.release(peer) else |_| {}
    }
}

/// Runs `ids.len` accepts at the largest fault rate into a table of `size`, records each
/// completion's id and outcome (the peer, or 1, 2 or 3 shifted past any peer for
/// TableFull, PeerDown and Backpressure) in completion order, and returns the simulator.
fn acceptRun(seed: u64, size: u32, ids: []io.OperationId, results: []u64) !Sim {
    assert(ids.len == results.len);
    assert(ids.len <= slots_count);
    var fixture: TableFixture = undefined;
    try fixture.setUp(size);
    defer fixture.tearDown();
    var sim = Sim.init(seed, constants.sim_fault_percent_max);
    sim.attachTable(&fixture.table);
    for (ids, 0..) |_, index| try sim.submit(acceptSubmission(index));
    var completions: [slots_count]io.Completion = undefined;
    const count = drainAll(&sim, completions[0..ids.len]);
    try testing.expectEqual(@as(u32, @intCast(ids.len)), count);
    for (completions[0..count], ids, results) |completion, *id, *result| {
        id.* = completion.id;
        result.* = if (completion.result.accept) |peer| peer else |err| switch (err) {
            error.TableFull => 1 << 32,
            error.PeerDown => 2 << 32,
            error.Backpressure => 3 << 32,
        };
    }
    try testing.expectEqual(fixture.table.count(), @as(u32, @intCast(sim.accepted)));
    // Release every entry, so the fixture's shutdown sees a table it can free.
    for (completions[0..count]) |completion| {
        if (completion.result.accept) |peer| _ = fixture.table.release(peer) else |_| {}
    }
    sim.table = null;
    return sim;
}

test "sim: same seed, same accepts, refusals and faults, in the same order" {
    const runs = 64;
    var ids_a: [runs]io.OperationId = undefined;
    var ids_b: [runs]io.OperationId = undefined;
    var ids_c: [runs]io.OperationId = undefined;
    var results_a: [runs]u64 = undefined;
    var results_b: [runs]u64 = undefined;
    var results_c: [runs]u64 = undefined;
    const a = try acceptRun(5, 16, &ids_a, &results_a);
    const b = try acceptRun(5, 16, &ids_b, &results_b);
    _ = try acceptRun(6, 16, &ids_c, &results_c);
    try testing.expectEqualSlices(io.OperationId, &ids_a, &ids_b);
    try testing.expectEqualSlices(u64, &results_a, &results_b);
    try testing.expect(!std.mem.eql(io.OperationId, &ids_a, &ids_c));
    try testing.expectEqual(a.faults, b.faults);
    try testing.expectEqual(a.refused, b.refused);
    // At a 50% fault rate, about 32 of 64 arrive, so 16 entries fill and the rest are
    // refused; both accept faults occur.
    try testing.expectEqual(@as(u64, 16), a.accepted);
    try testing.expect(a.refused > 0);
    try testing.expect(a.faults.accept_peer_down > 0);
    try testing.expect(a.faults.accept_backpressure > 0);
    try testing.expectEqual(@as(u64, runs), a.accepted + a.refused + a.faults.total());
}
