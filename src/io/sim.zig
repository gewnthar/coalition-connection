//! Deterministic simulator for the I/O boundary.
//!
//! Job: stand in for the network, the clock and the database, driven by one seed. Time
//! moves only when `tick` is called, and faults (a peer down, a database timeout) are
//! drawn from a seeded PRNG, so a failing seed replays exactly.
//!
//! Inputs: a seed and a fault rate in percent (at most `constants.sim_fault_percent_max`).
//! Outputs: the same contract as io/root.zig, plus counters a test can assert on.
//! Limits: at most `constants.sim_ticks_max` ticks per run.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const io = @import("root.zig");

pub const Sim = struct {
    prng: std.Random.DefaultPrng,
    fault_percent: u8,
    ticks: u32,
    now_ns: io.Instant,
    bytes_sent: u64,
    statements: u32,
    faults: u32,

    pub fn init(seed: u64, fault_percent: u8) Sim {
        assert(fault_percent <= constants.sim_fault_percent_max);
        const result: Sim = .{
            .prng = .init(seed),
            .fault_percent = fault_percent,
            .ticks = 0,
            .now_ns = 0,
            .bytes_sent = 0,
            .statements = 0,
            .faults = 0,
        };
        assert(result.ticks == 0);
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

    pub fn send(self: *Sim, peer: io.PeerId, bytes: []const u8) io.SendError!void {
        assert(peer < constants.http_connections_max);
        assert(bytes.len > 0);
        assert(bytes.len <= constants.http_response_size_max);
        if (self.fault()) return error.PeerDown;
        self.bytes_sent += @as(u64, @intCast(bytes.len));
    }

    pub fn execute(self: *Sim, statement: []const u8) io.DatabaseError!void {
        assert(statement.len > 0);
        assert(statement.len <= constants.postgres_message_size_max);
        if (self.fault()) return error.Timeout;
        self.statements += 1;
    }

    fn fault(self: *Sim) bool {
        assert(self.fault_percent <= constants.sim_fault_percent_max);
        const roll = self.prng.random().uintLessThan(u8, 100);
        assert(roll < 100);
        const failed = roll < self.fault_percent;
        if (failed) self.faults += 1;
        return failed;
    }
};

const testing = std.testing;

fn runFixed(seed: u64) Sim {
    var sim = Sim.init(seed, 20);
    var i: u32 = 0;
    while (i < 1_000) : (i += 1) {
        sim.tick();
        // Faults are the point of this run; they are counted in `sim.faults`.
        sim.send(i % 8, "ping") catch |err| switch (err) {
            error.PeerDown, error.Backpressure => {},
        };
        sim.execute("select 1") catch |err| switch (err) {
            error.Unavailable, error.Timeout => {},
        };
    }
    return sim;
}

test "sim: same seed, same run" {
    const a = runFixed(42);
    const b = runFixed(42);
    try testing.expectEqual(a.faults, b.faults);
    try testing.expectEqual(a.bytes_sent, b.bytes_sent);
    try testing.expectEqual(a.statements, b.statements);
    try testing.expect(a.faults > 0);
}

test "sim: time moves only on tick" {
    var sim = Sim.init(1, 0);
    try testing.expectEqual(@as(io.Instant, 0), sim.now());
    sim.tick();
    try testing.expectEqual(constants.tick_ns, sim.now());
}

test "sim: a zero fault rate never fails" {
    var sim = Sim.init(7, 0);
    try sim.send(0, "hello");
    try sim.execute("select 1");
    try testing.expectEqual(@as(u32, 0), sim.faults);
    try testing.expectEqual(@as(u64, 5), sim.bytes_sent);
}
