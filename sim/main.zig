//! Deterministic simulation run: `zig build sim -Dseed=<n>`.
//!
//! Placeholder workload: each tick submits one send and one statement through the simulated
//! I/O boundary, draws a nonce, advances time, and takes every completion that is due.
//! Completions arrive after seeded delays and out of order, with faults of every kind and
//! short sends injected, and the run checks its invariants every tick: each operation
//! completes exactly once, with the kind it was submitted as. As components land, each one
//! joins this loop as a real workload (logins, ESI polling, live updates). A failing seed
//! replays exactly.

const std = @import("std");
const assert = std.debug.assert;
const cc = @import("coalition_connection");
const build_options = @import("build_options");

const io = cc.io;
const constants = cc.constants;
const Sim = io.sim.Sim;

/// Lets this program use `io.sim.Sim`; see src/io/sim.zig.
pub const io_simulation = true;

const fault_percent: u8 = 10;
const peers: u32 = 64;
const completions_batch: u32 = 64;
const message = "event";

/// Ticks left at the end for every delayed completion to arrive.
const drain_ticks: u32 = constants.sim_completion_delay_ticks_max + 1;
const workload_ticks: u32 = constants.sim_ticks_max - drain_ticks;

/// Ids in flight, tracked by id modulo the window. Two ids per tick for at most
/// `drain_ticks` ticks are in flight at once, far fewer than the window, so two ids in flight
/// never share an entry.
const outstanding_window: u32 = 1024;

const SimError = error{InvariantBroken};

const Run = struct {
    sim: Sim,
    next_id: io.OperationId,
    completed: u64,
    queue_full: u32,
    outstanding: [outstanding_window]bool,
};

fn windowIndex(id: io.OperationId) u32 {
    const index: u32 = @intCast(id % outstanding_window);
    assert(index < outstanding_window);
    assert(index == id % outstanding_window);
    return index;
}

/// Even ids are sends, odd ids are statements, so each completion's kind can be checked.
fn submitPair(run: *Run) SimError!void {
    assert(run.next_id % 2 == 0);
    const before = run.sim.submitted;
    const peer: io.PeerId = @intCast((run.next_id / 2) % peers);
    const pair = [2]io.Submission{
        .{ .id = run.next_id, .operation = .{ .send = .{ .peer = peer, .bytes = message } } },
        .{ .id = run.next_id + 1, .operation = .{ .execute = .{ .statement = "select 1" } } },
    };
    for (pair) |submission| {
        const entry = &run.outstanding[windowIndex(submission.id)];
        if (entry.*) return error.InvariantBroken; // The window is too small.
        run.sim.submit(submission) catch |err| switch (err) {
            error.QueueFull => {
                run.queue_full += 1; // Counted; the operation never completes.
                continue;
            },
        };
        entry.* = true;
    }
    run.next_id += 2;
    assert(run.sim.submitted <= before + 2);
}

fn checkCompletion(run: *Run, completion: io.Completion) SimError!void {
    assert(run.next_id > 0);
    assert(run.completed <= run.sim.completed);
    if (completion.id >= run.next_id) return error.InvariantBroken;
    // Exactly once: the id must be in flight, and is in flight no longer.
    const entry = &run.outstanding[windowIndex(completion.id)];
    if (!entry.*) return error.InvariantBroken;
    entry.* = false;

    const expected: io.Kind = if (completion.id % 2 == 0) .send else .execute;
    if (@as(io.Kind, completion.result) != expected) return error.InvariantBroken;
    switch (completion.result) {
        .send => |sent| {
            const bytes = sent catch |err| switch (err) {
                error.PeerDown, error.Backpressure => return, // Counted in sim.faults.
            };
            // A short send is allowed; a real component would send the rest.
            if (bytes == 0 or bytes > message.len) return error.InvariantBroken;
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
    const batches_max = constants.io_operations_in_flight_max / completions_batch + 1;
    var batches: u32 = 0;
    while (batches < batches_max) : (batches += 1) {
        const count = run.sim.poll(&completions);
        for (completions[0..count]) |completion| try checkCompletion(run, completion);
        run.completed += count;
        if (count < completions_batch) break;
    }
    // Every in-flight operation fits in batches_max full batches, so the loop always breaks.
    if (batches == batches_max) return error.InvariantBroken;
    if (run.completed != run.sim.completed) return error.InvariantBroken;
    if (run.sim.completed + run.sim.in_flight != run.sim.submitted) return error.InvariantBroken;
}

fn step(run: *Run, submitting: bool) SimError!void {
    assert(run.sim.ticks < constants.sim_ticks_max);
    const before = run.sim.now();
    if (submitting) try submitPair(run);
    var nonce: [24]u8 = undefined;
    run.sim.randomBytes(&nonce) catch |err| switch (err) {
        error.RandomUnavailable => return error.InvariantBroken, // The simulator never fails.
    };
    run.sim.tick();
    if (run.sim.now() <= before) return error.InvariantBroken;
    try drain(run);
    assert(run.sim.faults.total() <= run.sim.completed);
}

/// After the run: everything arrived, and every fault kind and a short send happened.
fn checkEnd(run: *const Run) SimError!void {
    assert(run.sim.ticks == constants.sim_ticks_max);
    assert(run.completed == run.sim.completed);
    if (run.sim.in_flight != 0) return error.InvariantBroken;
    for (run.outstanding) |entry| if (entry) return error.InvariantBroken;
    const faults = run.sim.faults;
    if (faults.peer_down == 0 or faults.backpressure == 0) return error.InvariantBroken;
    if (faults.unavailable == 0 or faults.timeout == 0) return error.InvariantBroken;
    if (run.sim.short_sends == 0) return error.InvariantBroken;
}

pub fn main() SimError!void {
    const seed: u64 = build_options.seed;
    comptime assert(fault_percent <= constants.sim_fault_percent_max);
    comptime assert(2 * drain_ticks < outstanding_window);
    var run: Run = .{
        .sim = .init(seed, fault_percent),
        .next_id = 0,
        .completed = 0,
        .queue_full = 0,
        .outstanding = @splat(false),
    };

    var tick: u32 = 0;
    while (tick < constants.sim_ticks_max) : (tick += 1) {
        step(&run, tick < workload_ticks) catch |err| {
            std.debug.print("sim: seed={d} failed at tick {d}\n", .{ seed, tick });
            return err;
        };
    }
    checkEnd(&run) catch |err| {
        std.debug.print("sim: seed={d} failed after the last tick\n", .{seed});
        return err;
    };
    const sim = &run.sim;
    const faults = sim.faults;
    std.debug.print("sim: seed={d} ticks={d} completed={d}\n", .{ seed, sim.ticks, sim.completed });
    std.debug.print("sim: short_sends={d} queue_full={d}\n", .{ sim.short_sends, run.queue_full });
    std.debug.print("sim: peer_down={d} backpressure={d}\n", .{ faults.peer_down, faults.backpressure });
    std.debug.print("sim: unavailable={d} timeout={d} ok\n", .{ faults.unavailable, faults.timeout });
}
