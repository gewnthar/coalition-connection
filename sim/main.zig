//! Deterministic simulation run: `zig build sim -Dseed=<n>`.
//!
//! Placeholder workload: each tick submits one send and one statement through the simulated
//! I/O boundary, advances time, and takes every completion that is due. Completions arrive
//! after seeded delays and out of order, with faults of every kind injected, and the run
//! checks its invariants every tick. As components land, each one joins this loop as a real
//! workload (logins, ESI polling, live updates). A failing seed replays exactly.

const std = @import("std");
const assert = std.debug.assert;
const cc = @import("coalition_connection");
const build_options = @import("build_options");

const io = cc.io;
const constants = cc.constants;
const Sim = io.sim.Sim;

/// Lets this program create `io.sim.Sim`; see src/io/sim.zig.
pub const io_simulation = true;

const fault_percent: u8 = 10;
const peers: u32 = 64;
const completions_batch: u32 = 64;

/// Ticks left at the end for every delayed completion to arrive.
const drain_ticks: u32 = constants.sim_completion_delay_ticks_max + 1;
const workload_ticks: u32 = constants.sim_ticks_max - drain_ticks;

const SimError = error{InvariantBroken};

const Run = struct {
    sim: Sim,
    next_id: io.OperationId,
    completed: u64,
    queue_full: u32,
};

/// Even ids are sends, odd ids are statements, so each completion's kind can be checked.
fn submitPair(run: *Run) void {
    assert(run.next_id % 2 == 0);
    const before = run.sim.submitted;
    const peer: io.PeerId = @intCast((run.next_id / 2) % peers);
    const pair = [2]io.Submission{
        .{ .id = run.next_id, .operation = .{ .send = .{ .peer = peer, .bytes = "event" } } },
        .{ .id = run.next_id + 1, .operation = .{ .execute = .{ .statement = "select 1" } } },
    };
    for (pair) |submission| {
        run.sim.submit(submission) catch |err| switch (err) {
            error.QueueFull => run.queue_full += 1, // Counted; the operation is dropped.
        };
    }
    run.next_id += 2;
    assert(run.sim.submitted <= before + 2);
}

fn checkCompletion(run: *const Run, completion: io.Completion) SimError!void {
    assert(run.next_id > 0);
    assert(run.completed <= run.sim.completed);
    if (completion.id >= run.next_id) return error.InvariantBroken;
    const expected: io.Kind = if (completion.id % 2 == 0) .send else .execute;
    if (@as(io.Kind, completion.result) != expected) return error.InvariantBroken;
    switch (completion.result) {
        .send => |sent| {
            const bytes = sent catch |err| switch (err) {
                error.PeerDown, error.Backpressure => return, // Counted in sim.faults.
            };
            if (bytes != "event".len) return error.InvariantBroken;
        },
        .execute => |executed| executed catch |err| switch (err) {
            error.Unavailable, error.Timeout => {}, // Counted in sim.faults.
        },
    }
}

/// Takes every completion that is due, checking each one.
fn drain(run: *Run) SimError!void {
    assert(run.completed == run.sim.completed);
    var completions: [completions_batch]io.Completion = undefined;
    var batches: u32 = 0;
    while (batches <= constants.io_operations_in_flight_max / completions_batch) : (batches += 1) {
        const count = run.sim.poll(&completions);
        for (completions[0..count]) |completion| try checkCompletion(run, completion);
        run.completed += count;
        if (count < completions_batch) break;
    }
    assert(batches <= constants.io_operations_in_flight_max / completions_batch);
    if (run.completed != run.sim.completed) return error.InvariantBroken;
    if (run.sim.completed + run.sim.in_flight != run.sim.submitted) return error.InvariantBroken;
}

fn step(run: *Run, submitting: bool) SimError!void {
    assert(run.sim.ticks < constants.sim_ticks_max);
    const before = run.sim.now();
    if (submitting) submitPair(run);
    run.sim.tick();
    if (run.sim.now() <= before) return error.InvariantBroken;
    try drain(run);
    assert(run.sim.faults.total() <= run.sim.completed);
}

pub fn main() SimError!void {
    const seed: u64 = build_options.seed;
    comptime assert(fault_percent <= constants.sim_fault_percent_max);
    comptime assert(drain_ticks < constants.sim_ticks_max);
    var run: Run = .{ .sim = .init(seed, fault_percent), .next_id = 0, .completed = 0, .queue_full = 0 };

    var tick: u32 = 0;
    while (tick < constants.sim_ticks_max) : (tick += 1) {
        step(&run, tick < workload_ticks) catch |err| {
            std.debug.print("sim: seed={d} failed at tick {d}\n", .{ seed, tick });
            return err;
        };
    }
    assert(run.sim.ticks == constants.sim_ticks_max);
    // Every delayed operation arrived, and every fault kind was injected.
    if (run.sim.in_flight != 0) return error.InvariantBroken;
    const faults = run.sim.faults;
    if (faults.peer_down == 0 or faults.backpressure == 0) return error.InvariantBroken;
    if (faults.unavailable == 0 or faults.timeout == 0) return error.InvariantBroken;
    std.debug.print("sim: seed={d} ticks={d} completed={d} queue_full={d}\n", .{ seed, run.sim.ticks, run.sim.completed, run.queue_full });
    std.debug.print("sim: faults={d} peer_down={d} backpressure={d} unavailable={d} timeout={d} ok\n", .{ faults.total(), faults.peer_down, faults.backpressure, faults.unavailable, faults.timeout });
}
