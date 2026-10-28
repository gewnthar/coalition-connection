//! Deterministic simulator for the I/O boundary.
//!
//! Job: stand in for the network, the clock, the database and the random source, driven by
//! one seed. Time moves only when `tick` is called. Each submitted operation completes after a
//! seeded delay, so completions arrive out of submission order, and faults of every kind the
//! contract names are drawn from a seeded PRNG and counted. A failing seed replays exactly.
//!
//! Inputs: a seed and a fault rate in percent (at most `constants.sim_fault_percent_max`).
//! Outputs: the same contract as io/root.zig, plus counters a test can assert on.
//! Limits: at most `constants.sim_ticks_max` ticks per run, at most
//! `constants.io_operations_in_flight_max` operations in flight, and delays of at most
//! `constants.sim_completion_delay_ticks_max` ticks.
//!
//! Only tests and programs that declare `pub const io_simulation = true;` in their root file
//! may create a `Sim`, so the seeded random source can't reach a production build.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const io = @import("root.zig");

const slots_count = constants.io_operations_in_flight_max;

/// Seeds the random-bytes stream apart from the fault stream, so drawing a nonce never
/// shifts which operations fail.
const random_stream_salt: u64 = 0x9e37_79b9_7f4a_7c15;

/// Faults injected so far, one counter per error the contract names.
pub const Faults = struct {
    peer_down: u32 = 0,
    backpressure: u32 = 0,
    unavailable: u32 = 0,
    timeout: u32 = 0,

    pub fn total(self: Faults) u64 {
        const sends = @as(u64, self.peer_down) + self.backpressure;
        const executes = @as(u64, self.unavailable) + self.timeout;
        assert(sends >= self.peer_down);
        assert(executes >= self.timeout);
        return sends + executes;
    }
};

const Slot = struct {
    submission: io.Submission,
    due_tick: u32,
};

pub const Sim = struct {
    prng: std.Random.DefaultPrng,
    random_source: std.Random.DefaultPrng,
    fault_percent: u8,
    ticks: u32,
    now_ns: io.Instant,
    slots: [slots_count]?Slot,
    in_flight: u32,
    submitted: u64,
    completed: u64,
    bytes_sent: u64,
    statements: u32,
    random_bytes: u64,
    faults: Faults,

    pub fn init(seed: u64, fault_percent: u8) Sim {
        comptime assertSimulationAllowed();
        assert(fault_percent <= constants.sim_fault_percent_max);
        const result: Sim = .{
            .prng = .init(seed),
            .random_source = .init(seed ^ random_stream_salt),
            .fault_percent = fault_percent,
            .ticks = 0,
            .now_ns = 0,
            .slots = @splat(null),
            .in_flight = 0,
            .submitted = 0,
            .completed = 0,
            .bytes_sent = 0,
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
    /// `sim_completion_delay_ticks_max` ticks. A full table leaves the state unchanged.
    pub fn submit(self: *Sim, submission: io.Submission) io.SubmitError!void {
        assert(self.in_flight <= slots_count);
        assertOperation(submission.operation);
        if (self.in_flight == slots_count) return error.QueueFull;

        const index = self.freeSlot();
        const delay = self.prng.random().uintAtMost(u32, constants.sim_completion_delay_ticks_max);
        self.slots[index] = .{ .submission = submission, .due_tick = self.ticks + delay };
        self.in_flight += 1;
        self.submitted += 1;
        assert(self.slots[index] != null);
        assert(self.completed + self.in_flight == self.submitted);
    }

    /// Moves operations that are due into `completions` and returns how many. The scan starts
    /// at a seeded slot, so operations due on the same tick also come back in a seeded order.
    pub fn poll(self: *Sim, completions: []io.Completion) u32 {
        assert(completions.len > 0);
        assert(completions.len <= slots_count);
        const in_flight_before = self.in_flight;
        const start = self.prng.random().uintLessThan(u32, slots_count);

        var count: u32 = 0;
        var step: u32 = 0;
        while (step < slots_count and count < completions.len) : (step += 1) {
            const index = (start + step) % slots_count;
            const slot = self.slots[index] orelse continue;
            if (slot.due_tick > self.ticks) continue;
            self.slots[index] = null;
            completions[count] = self.complete(slot.submission);
            count += 1;
        }
        self.in_flight -= count;
        assert(self.in_flight == in_flight_before - count);
        assert(self.completed + self.in_flight == self.submitted);
        return count;
    }

    /// Fills `buffer` from the seeded random stream. Same seed, same bytes.
    pub fn randomBytes(self: *Sim, buffer: []u8) void {
        assert(buffer.len > 0);
        assert(buffer.len <= constants.io_random_bytes_max);
        const drawn: u32 = @intCast(buffer.len);
        const before = self.random_bytes;
        self.random_source.random().bytes(buffer);
        self.random_bytes += drawn;
        assert(self.random_bytes == before + drawn);
    }

    fn freeSlot(self: *const Sim) u32 {
        assert(self.in_flight < slots_count);
        var index: u32 = 0;
        while (index < slots_count) : (index += 1) {
            if (self.slots[index] == null) break;
        }
        // Fewer than slots_count operations are in flight, so the scan found a free slot.
        assert(index < slots_count);
        return index;
    }

    fn complete(self: *Sim, submission: io.Submission) io.Completion {
        assert(self.in_flight > 0);
        assert(self.completed < self.submitted);
        const result: io.Result = switch (submission.operation) {
            .send => |send| .{ .send = self.completeSend(send) },
            .execute => |execute| .{ .execute = self.completeExecute(execute) },
        };
        self.completed += 1;
        return .{ .id = submission.id, .result = result };
    }

    fn completeSend(self: *Sim, send: io.Send) io.SendError!u32 {
        assert(send.bytes.len > 0);
        assert(send.bytes.len <= constants.http_response_size_max);
        if (self.fault()) {
            if (self.prng.random().boolean()) {
                self.faults.peer_down += 1;
                return error.PeerDown;
            }
            self.faults.backpressure += 1;
            return error.Backpressure;
        }
        const sent: u32 = @intCast(send.bytes.len);
        self.bytes_sent += sent;
        return sent;
    }

    fn completeExecute(self: *Sim, execute: io.Execute) io.DatabaseError!void {
        assert(execute.statement.len > 0);
        assert(execute.statement.len <= constants.postgres_message_size_max);
        if (self.fault()) {
            if (self.prng.random().boolean()) {
                self.faults.unavailable += 1;
                return error.Unavailable;
            }
            self.faults.timeout += 1;
            return error.Timeout;
        }
        self.statements += 1;
    }

    fn fault(self: *Sim) bool {
        assert(self.fault_percent <= constants.sim_fault_percent_max);
        const roll = self.prng.random().uintLessThan(u8, 100);
        assert(roll < 100);
        return roll < self.fault_percent;
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

/// Stops the build when a program that isn't a test or a declared simulation creates a
/// `Sim`, because its seeded random bytes would make every nonce predictable.
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

const Recording = struct {
    ids: [recorded_max]io.OperationId,
    count: u32,
    sim: Sim,
};

/// Submits `recorded_max` operations, alternating sends and statements, at two per tick,
/// and records the order their completions come back in.
fn record(seed: u64, fault_percent: u8) io.SubmitError!Recording {
    var recording: Recording = .{ .ids = @splat(0), .count = 0, .sim = .init(seed, fault_percent) };
    var completions: [16]io.Completion = undefined;
    var next: io.OperationId = 0;
    var ticks: u32 = 0;
    const ticks_max = recorded_max + constants.sim_completion_delay_ticks_max + 1;
    while (ticks < ticks_max and recording.count < recorded_max) : (ticks += 1) {
        if (next < recorded_max) {
            // At most two submissions per tick for 17 ticks are in flight, far below the table.
            try recording.sim.submit(testSubmission(next));
            try recording.sim.submit(testSubmission(next + 1));
            next += 2;
        }
        recording.sim.tick();
        var drained: u32 = 0;
        while (drained < slots_count) : (drained += 1) {
            const count = recording.sim.poll(&completions);
            if (count == 0) break;
            for (completions[0..count]) |completion| {
                recording.ids[recording.count] = completion.id;
                recording.count += 1;
            }
        }
    }
    assert(recording.count == recorded_max);
    assert(recording.sim.in_flight == 0);
    return recording;
}

/// Even ids are sends, odd ids are statements.
fn testSubmission(id: io.OperationId) io.Submission {
    assert(id < std.math.maxInt(u32));
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

test "sim: delays reorder completions, and each operation completes once" {
    const run = try record(7, 0);
    var seen: [recorded_max]bool = @splat(false);
    var reordered = false;
    for (run.ids[0..run.count], 0..) |id, index| {
        try testing.expect(id < recorded_max);
        try testing.expect(!seen[@intCast(id)]);
        seen[@intCast(id)] = true;
        if (index > 0 and id < run.ids[index - 1]) reordered = true;
    }
    try testing.expect(reordered);
    try testing.expectEqual(@as(u64, recorded_max), run.sim.completed);
    try testing.expectEqual(run.sim.submitted, run.sim.completed);
}

test "sim: a seeded run injects every fault kind" {
    const run = try record(1, constants.sim_fault_percent_max);
    try testing.expect(run.sim.faults.peer_down > 0);
    try testing.expect(run.sim.faults.backpressure > 0);
    try testing.expect(run.sim.faults.unavailable > 0);
    try testing.expect(run.sim.faults.timeout > 0);
    try testing.expect(run.sim.faults.total() <= run.sim.completed);
}

test "sim: time moves only on tick" {
    var sim = Sim.init(1, 0);
    try testing.expectEqual(@as(io.Instant, 0), sim.now());
    sim.tick();
    try testing.expectEqual(constants.tick_ns, sim.now());
}

test "sim: a zero fault rate never fails" {
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

test "sim: same seed, same random bytes, and draws leave faults unchanged" {
    var a = Sim.init(9, 0);
    var b = Sim.init(9, 0);
    var c = Sim.init(10, 0);
    var bytes_a: [24]u8 = undefined;
    var bytes_b: [24]u8 = undefined;
    var bytes_c: [24]u8 = undefined;
    a.randomBytes(&bytes_a);
    b.randomBytes(&bytes_b);
    c.randomBytes(&bytes_c);
    try testing.expectEqualSlices(u8, &bytes_a, &bytes_b);
    try testing.expect(!std.mem.eql(u8, &bytes_a, &bytes_c));
    try testing.expectEqual(@as(u64, 24), a.random_bytes);

    // The fault stream is separate: a run that draws nonces fails the same operations.
    var plain = Sim.init(11, constants.sim_fault_percent_max);
    var drawing = Sim.init(11, constants.sim_fault_percent_max);
    var completions: [2]io.Completion = undefined;
    var id: io.OperationId = 0;
    while (id < 64) : (id += 1) {
        try plain.submit(testSubmission(id));
        try drawing.submit(testSubmission(id));
        drawing.randomBytes(&bytes_a);
        plain.tick();
        drawing.tick();
        _ = plain.poll(&completions);
        _ = drawing.poll(&completions);
    }
    try testing.expectEqual(plain.faults, drawing.faults);
}
