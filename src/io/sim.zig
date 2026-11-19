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
//! Sends: a send goes through the attached table with the same calls the real type makes.
//! Its peer is looked up at submit, before the queue is checked, so a free, stale or
//! out-of-range peer crashes as it does on the real type; the send is counted on its entry
//! (`Table.sendSubmitted`) until its completion uncounts it (`Table.sendCompleted`), so the
//! table refuses to release that entry with `error.SendsInFlight` meanwhile. Code that
//! releases early or sends on a stale id fails in simulation, not first on the real type.
//!
//! Inputs: a seed, a fault rate in percent (at most `constants.sim_fault_percent_max`) and,
//! for sends and accepts, a connection table.
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
/// Operations in flight that may be sends; the rest are kept for accepts, as on the real type.
const send_slots_max = constants.io_sends_in_flight_max;

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
    /// Operations in flight that are sends: never more than `send_slots_max`.
    sends_in_flight: u32,
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
            .sends_in_flight = 0,
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

    /// Gives sends the connection table their peers live in, and arrivals the table to take
    /// their entries in. Call it once, before the first send or accept; the table is the
    /// caller's and must outlive every send and accept.
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
    /// drawn now. A full table returns `error.QueueFull`, and a send with sends holding their
    /// whole share (`send_slots_max`) `error.SendSlotsFull`, as on the real type; either
    /// leaves the state unchanged. An id already in flight breaks the contract and crashes,
    /// full table or not.
    pub fn submit(self: *Sim, submission: io.Submission) io.SubmitError!void {
        comptime assertSimulationAllowed();
        assert(self.in_flight <= slots_count);
        assertOperation(submission.operation);
        // A send names its peer's entry, and an arrival takes one, so both need a table.
        assert(submission.operation == .execute or self.table != null);
        // Looked up before anything changes, as the real type does: a send naming a peer
        // that isn't live in the table (free, stale or past its end) is a caller's bug and
        // crashes, full queue or not.
        const sends_before = self.sendsCounted(submission.operation);
        self.assertIdNotInFlight(submission.id);
        assert(self.sends_in_flight <= send_slots_max);
        if (self.in_flight == slots_count) return error.QueueFull;
        // The operations past send_slots_max are kept for accepts.
        if (submission.operation == .send and self.sends_in_flight == send_slots_max) {
            return error.SendSlotsFull;
        }

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
        if (submission.operation == .send) self.sends_in_flight += 1;
        self.submitted += 1;
        // Counted on the peer's entry until it completes, through the same call the real
        // type makes, so the table refuses to release the entry meanwhile.
        if (submission.operation == .send) self.table.?.sendSubmitted(submission.operation.send.peer);
        const sends_added: connections.SendCount = if (submission.operation == .send) 1 else 0;
        assert(self.sendsCounted(submission.operation) == sends_before + sends_added);
        assert(self.slots[index] != null);
        assert(self.completed + self.in_flight == self.submitted);
    }

    /// Sends counted on a send's peer, read through `Table.get`, which crashes unless the
    /// peer is live; 0 for an accept or a statement, which name no peer.
    fn sendsCounted(self: *const Sim, operation: io.Operation) connections.SendCount {
        const count: connections.SendCount = switch (operation) {
            .send => |send| self.table.?.get(send.peer).sends_in_flight,
            .accept, .execute => 0,
        };
        // Only a send names a peer, so only a send can have a count.
        assert(operation == .send or count == 0);
        assert(count <= slots_count);
        return count;
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
        var sends: u32 = 0;
        var index: u32 = 0;
        while (index < slots_count) : (index += 1) {
            const slot = self.slots[index] orelse continue;
            occupied += 1;
            if (slot.submission.operation == .send) sends += 1;
            assert(slot.submission.id != id);
        }
        // The count of occupied slots, `in_flight` and `sends_in_flight` are kept
        // separately; they must agree.
        assert(occupied == self.in_flight);
        assert(sends == self.sends_in_flight);
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
                assert(self.sends_in_flight > 0); // Counted at submit.
                self.sends_in_flight -= 1;
                // The table refused to release the peer while this send was counted, so
                // the id is still live; `sendCompleted` crashes if it isn't.
                const send = slot.submission.operation.send;
                const table = self.table.?;
                const sends_before = table.get(send.peer).sends_in_flight;
                table.sendCompleted(send.peer);
                assert(table.get(send.peer).sends_in_flight == sends_before - 1);
                self.countSend(sent, send);
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
/// and records the order and the ticks their completions come back on. The sends go to
/// `fixture`'s peers, which must outlive the recording; every send is uncounted again
/// once its completion has come back.
fn record(fixture: *TableFixture, seed: u64, fault_percent: u8) !Recording {
    var recording: Recording = .{
        .ids = @splat(0),
        .submitted_tick = @splat(0),
        .completed_tick = @splat(0),
        .count = 0,
        .sim = .init(seed, fault_percent),
    };
    recording.sim.attachTable(&fixture.table);
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
    try fixture.expectNoSendsCounted();
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

/// Even ids are sends to peer `id % test_peers` (so to the even-numbered peers only), and
/// odd ids are statements.
fn testSubmission(id: io.OperationId) io.Submission {
    assert(id <= recorded_max + slots_count);
    const operation: io.Operation = if (id % 2 == 0)
        .{ .send = .{ .peer = @intCast(id % test_peers), .bytes = "ping" } }
    else
        .{ .execute = .{ .statement = "select 1" } };
    const expected: io.Kind = if (id % 2 == 0) .send else .execute;
    assert(@as(io.Kind, operation) == expected);
    return .{ .id = id, .operation = operation };
}

test "sim: same seed, same completion order and counts" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    const a = try record(&fixture, 42, 20);
    const b = try record(&fixture, 42, 20);
    try testing.expectEqualSlices(io.OperationId, &a.ids, &b.ids);
    try testing.expectEqual(a.sim.faults, b.sim.faults);
    try testing.expectEqual(a.sim.bytes_sent, b.sim.bytes_sent);
    try testing.expectEqual(a.sim.statements, b.sim.statements);
    const c = try record(&fixture, 43, 20);
    try testing.expect(!std.mem.eql(io.OperationId, &a.ids, &c.ids));
}

test "sim: delays reorder completions within the bound, each operation once" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    const run = try record(&fixture, 7, 0);
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
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    const run = try record(&fixture, 1, constants.sim_fault_percent_max);
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
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(5, 0);
    sim.attachTable(&fixture.table);
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
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(7, 0);
    sim.attachTable(&fixture.table);
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
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(3, 0);
    sim.attachTable(&fixture.table);
    var id: io.OperationId = 0;
    while (id < slots_count) : (id += 1) try sim.submit(testSubmission(id));
    // The refused submission is a send to peer 0, which holds every eighth id's send: it
    // must not be counted on the entry.
    const refused = testSubmission(id);
    try testing.expectEqual(io.Kind.send, @as(io.Kind, refused.operation));
    const entry_before = fixture.table.get(refused.operation.send.peer).*;
    try testing.expectEqual(@as(connections.SendCount, slots_count / test_peers), entry_before.sends_in_flight);
    try testing.expectError(error.QueueFull, sim.submit(refused));
    try testing.expectEqual(entry_before, fixture.table.get(refused.operation.send.peer).*);
    try testing.expectEqual(slots_count, sim.in_flight);
    try testing.expectEqual(@as(u64, slots_count), sim.submitted);

    var completions: [1]io.Completion = undefined;
    var ticks: u32 = 0;
    while (ticks <= constants.sim_completion_delay_ticks_max) : (ticks += 1) sim.tick();
    try testing.expectEqual(@as(u32, 1), sim.poll(&completions));
    try sim.submit(testSubmission(id));
    try testing.expectEqual(slots_count, sim.in_flight);
}

test "sim: a send past the sends' share is refused, and the last operation still goes in" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(5, 0);
    sim.attachTable(&fixture.table);
    var id: io.OperationId = 0;
    while (id < send_slots_max) : (id += 1) {
        try sim.submit(.{ .id = id, .operation = .{ .send = .{ .peer = 0, .bytes = "s" } } });
    }
    try testing.expectEqual(send_slots_max, sim.sends_in_flight);
    // The refused send must not be counted on its peer's entry either.
    const entry_before = fixture.table.get(0).*;
    try testing.expectEqual(@as(connections.SendCount, send_slots_max), entry_before.sends_in_flight);
    const slots_before = sim.slots;
    const send: io.Submission = .{ .id = id, .operation = .{ .send = .{ .peer = 0, .bytes = "s" } } };
    try testing.expectError(error.SendSlotsFull, sim.submit(send));
    try testing.expectEqual(entry_before, fixture.table.get(0).*);
    try testing.expectEqual(send_slots_max, sim.in_flight);
    try testing.expectEqual(@as(u64, send_slots_max), sim.submitted);
    try testing.expectEqualDeep(slots_before, sim.slots);

    // The operations kept back take anything but a send; then the table is full for all.
    const statement: io.Submission = .{ .id = id, .operation = .{ .execute = .{ .statement = "select 1" } } };
    try sim.submit(statement);
    try testing.expectEqual(slots_count, sim.in_flight);
    try testing.expectError(error.QueueFull, sim.submit(.{ .id = id + 1, .operation = statement.operation }));
    try testing.expectError(error.QueueFull, sim.submit(.{ .id = id + 1, .operation = send.operation }));

    // Every send completes and is uncounted.
    var completions: [slots_count]io.Completion = undefined;
    var ticks: u32 = 0;
    while (ticks <= constants.sim_completion_delay_ticks_max) : (ticks += 1) sim.tick();
    try testing.expectEqual(slots_count, sim.poll(&completions));
    try testing.expectEqual(@as(u32, 0), sim.sends_in_flight);
    try testing.expectEqual(@as(u32, 0), sim.in_flight);
    try fixture.expectNoSendsCounted();
}

test "sim: an id may be reused once its operation has completed" {
    // Ids need be distinct only while in flight. With every other slot still full, the id
    // that just completed is accepted again, three times over.
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(17, 0);
    sim.attachTable(&fixture.table);
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
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(13, 0);
    sim.attachTable(&fixture.table);
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
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    const plain = try record(&fixture, 11, constants.sim_fault_percent_max);
    // Same seed and submissions, but this run draws a nonce and polls before every tick too.
    var busy = Sim.init(11, constants.sim_fault_percent_max);
    busy.attachTable(&fixture.table);
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

    /// A table of `size` entries, every one in use, for sends. A fresh table hands out
    /// entry 0 first, each under generation 0, so peer `n` is entry `n`, as
    /// `testSubmission` names it.
    fn setUpPeers(self: *TableFixture, size: u32) !void {
        try self.setUp(size);
        var index: u32 = 0;
        while (index < size) : (index += 1) {
            const peer = try self.table.acquire(peerSocket(index));
            assert(peer == index);
        }
        assert(index == size);
        assert(self.table.count() == size);
    }

    /// Every entry in use has no send counted, as when every send has completed.
    fn expectNoSendsCounted(self: *const TableFixture) !void {
        var checked: u32 = 0;
        for (self.table.entries) |entry| {
            if (entry.state == .free) continue;
            try testing.expectEqual(@as(connections.SendCount, 0), entry.sends_in_flight);
            checked += 1;
        }
        try testing.expectEqual(self.table.count(), checked);
    }

    fn tearDown(self: *TableFixture) void {
        assert(self.table.capacity() > 0);
        self.startup.beginShutdown();
        self.table.deinit(self.gpa);
        assert(self.startup.bytes_live == 0);
    }
};

/// The peers the send tests name: `testSubmission` sends to peer `id % test_peers`.
const test_peers: u32 = 8;

/// The fake socket a send test's entry holds: below any arrival's, and distinct per entry.
fn peerSocket(index: u32) io.Socket {
    assert(index < constants.http_connections_max);
    comptime assert(test_listener + 1 + constants.http_connections_max < socket_first);
    return test_listener + 1 + @as(io.Socket, @intCast(index));
}

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
        if (completion.result.accept) |peer| _ = try fixture.table.release(peer) else |_| {}
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
        if (completion.result.accept) |peer| _ = try fixture.table.release(peer) else |_| {}
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

test "sim: a release with a send in flight is refused until the send completes" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(23, 0);
    sim.attachTable(&fixture.table);
    const peer: io.PeerId = 3;
    const send: io.Send = .{ .peer = peer, .bytes = "held" };
    try sim.submit(.{ .id = 1, .operation = .{ .send = send } });
    try sim.submit(.{ .id = 2, .operation = .{ .send = send } });
    try testing.expectEqual(@as(connections.SendCount, 2), fixture.table.get(peer).sends_in_flight);
    const entry_before = fixture.table.get(peer).*;
    try testing.expectError(error.SendsInFlight, fixture.table.release(peer));
    try testing.expectEqual(entry_before, fixture.table.get(peer).*);
    try testing.expectEqual(test_peers, fixture.table.count());

    // One completion at a time: with one send still in flight, the release is still refused.
    var completions: [1]io.Completion = undefined;
    var done: u32 = 0;
    var ticks: u32 = 0;
    while (ticks <= constants.sim_completion_delay_ticks_max and done < 2) : (ticks += 1) {
        sim.tick();
        var polls: u32 = 0;
        while (polls < 2 and sim.poll(&completions) == 1) : (polls += 1) {
            done += 1;
            try testing.expect(completions[0].id == 1 or completions[0].id == 2);
            try testing.expectEqual(@as(u32, send.bytes.len), try completions[0].result.send);
            const left: connections.SendCount = @intCast(2 - done);
            try testing.expectEqual(left, fixture.table.get(peer).sends_in_flight);
            if (left > 0) try testing.expectError(error.SendsInFlight, fixture.table.release(peer));
        }
    }
    try testing.expectEqual(@as(u32, 2), done);
    try testing.expectEqual(peerSocket(3), try fixture.table.release(peer));
    try testing.expect(fixture.table.lookup(peer) == null);
    try testing.expectEqual(test_peers - 1, fixture.table.count());
}

/// What `sendSoak` did, for the test to check that every path ran.
const SoakCounts = struct {
    sends: u32 = 0,
    completions: u32 = 0,
    releases_refused: u32 = 0,
    reconnects: u32 = 0,
    /// FNV-1a over every completion's id, in order, so a replay that completed the same
    /// totals in another order still differs.
    trace: u64 = 0xcbf29ce484222325,
};

const soak_steps: u32 = 4_000;
/// The last steps only tick, so every send in flight completes.
const soak_steps_total: u32 = soak_steps + constants.sim_completion_delay_ticks_max + 1;

/// A soak's simulator and its model: each entry's live id and its sends in flight, and the
/// entry each operation id's send went to (an id is its step number).
const Soak = struct {
    sim: Sim,
    table: *connections.Table,
    ids: [test_peers]io.PeerId,
    sends: [test_peers]u32,
    op_entry: [soak_steps]u8,
    counts: SoakCounts,

    /// A send to `entry`'s live id, unless every slot is in use.
    fn send(soak: *Soak, step_index: u32, entry: u32) !void {
        assert(step_index < soak_steps);
        assert(entry < test_peers);
        // A tick follows a send three times in eight, and nothing waits more than the
        // longest delay, so the soak holds a few dozen sends at most, never every slot;
        // the full-slot paths have tests of their own.
        assert(soak.sim.in_flight < slots_count);
        const operation: io.Send = .{ .peer = soak.ids[entry], .bytes = "soak" };
        try soak.sim.submit(.{ .id = step_index, .operation = .{ .send = operation } });
        soak.op_entry[step_index] = @intCast(entry);
        soak.sends[entry] += 1;
        soak.counts.sends += 1;
    }

    /// A release of `entry`: refused, changing nothing, exactly while the model counts a
    /// send on it; otherwise it succeeds, and the entry is taken again at once under its
    /// next generation, so the old id must find nothing.
    fn release(soak: *Soak, entry: u32) !void {
        assert(entry < test_peers);
        const table = soak.table;
        const before = table.get(soak.ids[entry]).*;
        const socket = table.release(soak.ids[entry]) catch |err| {
            try testing.expectEqual(error.SendsInFlight, err);
            try testing.expect(soak.sends[entry] > 0);
            try testing.expectEqual(before, table.get(soak.ids[entry]).*);
            soak.counts.releases_refused += 1;
            return;
        };
        try testing.expectEqual(@as(u32, 0), soak.sends[entry]);
        try testing.expectEqual(before.socket, socket);
        // The free stack hands back the entry just released, under a new generation.
        const again = try table.acquire(socket);
        const old: connections.IdParts = @bitCast(soak.ids[entry]);
        const new: connections.IdParts = @bitCast(again);
        try testing.expectEqual(old.index, new.index);
        try testing.expectEqual(old.generation + 1, new.generation);
        try testing.expect(table.lookup(soak.ids[entry]) == null);
        soak.ids[entry] = again;
        soak.counts.reconnects += 1;
    }

    /// One tick, then every completion due, each uncounted from the entry its send went to.
    fn tick(soak: *Soak) !void {
        const completed_before = soak.counts.completions;
        const in_flight_before = soak.sim.in_flight;
        soak.sim.tick();
        var completions: [16]io.Completion = undefined;
        var batches: u32 = 0;
        while (batches < slots_count) : (batches += 1) {
            const count = soak.sim.poll(&completions);
            for (completions[0..count]) |completion| {
                try testing.expect(completion.id < soak_steps);
                try testing.expectEqual(io.Kind.send, @as(io.Kind, completion.result));
                const done = soak.op_entry[@intCast(completion.id)];
                try testing.expect(soak.sends[done] > 0);
                soak.sends[done] -= 1;
                soak.counts.completions += 1;
                soak.counts.trace = (soak.counts.trace ^ completion.id) *% 0x100000001b3;
            }
            if (count < completions.len) break;
        }
        try testing.expect(batches < slots_count);
        // Every completion taken left the simulator: none lost, none taken twice.
        assert(soak.counts.completions - completed_before == in_flight_before - soak.sim.in_flight);
    }

    /// Each entry's count in the table equals the model's, and together they are every
    /// operation the simulator holds.
    fn check(soak: *const Soak) !void {
        var counted: u32 = 0;
        for (soak.ids, soak.sends) |id, expected| {
            try testing.expectEqual(expected, soak.table.get(id).sends_in_flight);
            counted += expected;
        }
        try testing.expectEqual(soak.sim.in_flight, counted);
        try testing.expectEqual(test_peers, soak.table.count());
    }
};

/// Seeded steps over `test_peers` live connections: half are sends to a random peer, one
/// in eight a release of a random peer, and the rest ticks that take every completion due.
/// After every step the table's counts match the model's (see `Soak`).
fn sendSoak(seed: u64) !SoakCounts {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var prng: std.Random.DefaultPrng = .init(seed ^ 0x5e9d_50a4);
    const random = prng.random();
    var soak: Soak = .{
        .sim = .init(seed, constants.sim_fault_percent_max),
        .table = &fixture.table,
        .ids = undefined,
        .sends = @splat(0),
        .op_entry = undefined,
        .counts = .{},
    };
    soak.sim.attachTable(&fixture.table);
    for (&soak.ids, 0..) |*id, index| id.* = @intCast(index);

    var step_index: u32 = 0;
    while (step_index < soak_steps_total) : (step_index += 1) {
        const action: u8 = if (step_index < soak_steps) random.uintLessThan(u8, 8) else 7;
        const entry = random.uintLessThan(u32, test_peers);
        switch (action) {
            0...3 => try soak.send(step_index, entry),
            4 => try soak.release(entry),
            else => try soak.tick(),
        }
        try soak.check();
    }
    assert(step_index == soak_steps_total);
    try testing.expectEqual(@as(u32, 0), soak.sim.in_flight);
    try testing.expectEqual(soak.counts.sends, soak.counts.completions);
    try fixture.expectNoSendsCounted();
    return soak.counts;
}

test "sim: seeded sends, releases and reconnects keep the table's counts with the model" {
    const seeds = [_]u64{ 1, 2, 0x5eed };
    for (seeds) |seed| {
        const counts = try sendSoak(seed);
        // Every path ran: sends completed, releases were refused with sends in flight and
        // allowed without, and entries were taken again under new generations.
        try testing.expect(counts.sends > soak_steps / 4);
        try testing.expect(counts.releases_refused > 0);
        try testing.expect(counts.reconnects > 0);
        try testing.expectEqual(counts, try sendSoak(seed));
    }
}
