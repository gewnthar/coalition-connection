//! Deterministic simulation run: `zig build sim -Dseed=<n>`.
//!
//! Placeholder: runs the simulated I/O boundary for a fixed number of ticks with faults
//! injected, and checks its counters. As components land, each one joins this loop as a
//! real workload (logins, ESI polling, live updates) with invariants checked every tick.
//! A failing seed replays exactly.

const std = @import("std");
const assert = std.debug.assert;
const cc = @import("coalition_connection");
const build_options = @import("build_options");

const fault_percent: u8 = 10;
const peers: u32 = 64;

const SimError = error{InvariantBroken};

fn workload(sim: *cc.io.sim.Sim) SimError!void {
    assert(sim.ticks <= cc.constants.sim_ticks_max);
    const before = sim.now();
    sim.tick();
    if (sim.now() <= before) return error.InvariantBroken;

    const peer: cc.io.PeerId = sim.ticks % peers;
    sim.send(peer, "event") catch |err| switch (err) {
        error.PeerDown, error.Backpressure => {}, // Counted in sim.faults.
    };
    sim.execute("select 1") catch |err| switch (err) {
        error.Unavailable, error.Timeout => {}, // Counted in sim.faults.
    };
    assert(sim.faults <= sim.ticks * 2);
}

pub fn main() SimError!void {
    const seed: u64 = build_options.seed;
    comptime assert(fault_percent <= cc.constants.sim_fault_percent_max);
    var sim = cc.io.sim.Sim.init(seed, fault_percent);

    var tick: u32 = 0;
    while (tick < cc.constants.sim_ticks_max) : (tick += 1) {
        workload(&sim) catch |err| {
            std.debug.print("sim: seed={d} failed at tick {d}\n", .{ seed, tick });
            return err;
        };
    }
    assert(sim.ticks == cc.constants.sim_ticks_max);
    if (sim.faults == 0) return error.InvariantBroken; // Faults must actually be injected.
    std.debug.print("sim: seed={d} ticks={d} faults={d} ok\n", .{ seed, sim.ticks, sim.faults });
}
