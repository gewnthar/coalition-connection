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
//! Inputs: a seed and a fault rate in percent (at most `constants.sim_fault_percent_max`).
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
const io = @import("root.zig");

const slots_count = constants.io_operations_in_flight_max;

/// Salts that separate the schedule and random streams from the outcome stream.
const schedule_salt: u64 = 0x9e37_79b9_7f4a_7c15;
const random_salt: u64 = 0xc2b2_ae3d_27d4_eb4f;

/// Faults injected so far, one counter per error the contract names.
pub const Faults = struct {
    peer_down: u32 = 0,
    backpressure: u32 = 0,
    unavailable: u32 = 0,
    timeout: u32 = 0,

    pub fn total(self: Faults) u64 {
        const sends = @as(u64, self.peer_down) + self.backpressure;
        const executes = @as(u64, self.unavailable) + self.timeout;
        assert(sends >= self.peer_down and sends >= self.backpressure);
        assert(executes >= self.unavailable and executes >= self.timeout);
        return sends + executes;
    }
};

const Slot = struct {
    submission: io.Submission,
    due_tick: u32,
    /// Drawn at submit, handed back at completion.
    result: io.Result,
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
        };
        assert(result.ticks == 0);
        assert(result.in_flight == 0);
        return result;
    }

    /// Advances simulated time by one tick.
    pub fn tick(self: *Sim) void {
        assert(self.ticks < constants.sim_ticks_max);
        self.ticks += 1;
        self.now_ns += constants.tick_ns;
        assert(self.now_ns == @as(u64, self.ticks) * constants.tick_ns);
    }

    pub fn now(self: *const Sim) io.Instant {
        assert(self.ticks <= constants.sim_ticks_max);
        assert(self.now_ns == @as(u64, self.ticks) * constants.tick_ns);
        return self.now_ns;
    }

    /// Queues one operation to complete after a seeded delay of 0 to
    /// `sim_completion_delay_ticks_max` ticks, capped at the run's last tick, with its result
    /// drawn now. A full table
    /// returns `error.QueueFull` and leaves the state unchanged.
    pub fn submit(self: *Sim, submission: io.Submission) io.SubmitError!void {
        comptime assertSimulationAllowed();
        assert(self.in_flight <= slots_count);
        assertOperation(submission.operation);
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
            .result = self.draw(submission.operation),
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

    fn draw(self: *Sim, operation: io.Operation) io.Result {
        assert(self.fault_percent <= constants.sim_fault_percent_max);
        const result: io.Result = switch (operation) {
            .send => |send| .{ .send = self.drawSend(send) },
            .execute => .{ .execute = self.drawExecute() },
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

    fn fault(self: *Sim) bool {
        assert(self.fault_percent <= constants.sim_fault_percent_max);
        const roll = self.outcomes.random().uintLessThan(u8, 100);
        assert(roll < 100);
        return roll < self.fault_percent;
    }

    /// Hands back a slot's result and counts it. Crashes if the caller changed the
    /// operation's bytes while it was in flight.
    fn complete(self: *Sim, slot: Slot) io.Completion {
        assert(self.completed < self.submitted);
        assert(hashOperation(slot.submission.operation) == slot.bytes_hash);
        switch (slot.result) {
            .send => |sent| self.countSend(sent, slot.submission.operation.send),
            .execute => |executed| self.countExecute(executed),
        }
        self.completed += 1;
        return .{ .id = slot.submission.id, .result = slot.result };
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
            assert(send.peer < constants.http_connections_max);
            assert(send.bytes.len > 0);
            assert(send.bytes.len <= constants.http_response_size_max);
        },
        .execute => |execute| {
            assert(execute.statement.len > 0);
            assert(execute.statement.len <= constants.postgres_message_size_max);
        },
    }
}

fn hashOperation(operation: io.Operation) u64 {
    const bytes: []const u8 = switch (operation) {
        .send => |send| send.bytes,
        .execute => |execute| execute.statement,
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
