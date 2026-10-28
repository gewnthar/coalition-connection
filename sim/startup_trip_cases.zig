//! The startup-trip cases: one list, read by build.zig (one build and one run per case)
//! and by sim/startup_trip.zig (what each case does), so the two can't drift apart.
//!
//! Each case puts a `StartupAllocator` in a phase, then makes one call. A case that
//! `trips` must stop the process on an assertion before the child allocator is touched;
//! a control case makes a call its phase allows and must finish normally.

const std = @import("std");
const assert = std.debug.assert;

/// The allocator's phase when the call is made. Mirrors `StartupAllocator.Phase`.
pub const Phase = enum(u8) { startup, running, shutdown };

pub const Call = enum(u8) {
    alloc,
    /// 16 bytes to 32.
    resize_grow,
    /// 16 bytes to 8: a shrink must not slip past the guard either.
    resize_shrink,
    /// 16 bytes to 0, which std.mem.Allocator may turn into a free; either way it must trip.
    resize_zero,
    remap_grow,
    remap_shrink,
    free,
    /// Frees 32 bytes when only 16 are live.
    free_oversize,
    /// Asks for the allocator interface again.
    get_allocator,
    finish_startup,
    begin_shutdown,
};

pub const Case = struct {
    name: []const u8,
    phase: Phase,
    call: Call,
    trips: bool,
};

pub const exit_finished: u8 = 0;
pub const exit_tripped: u8 = 42;

pub fn expectedExit(case: Case) u8 {
    assert(case.name.len > 0);
    assert(exit_finished != exit_tripped);
    return if (case.trips) exit_tripped else exit_finished;
}

pub const cases_max: u32 = 32;

pub const cases = [_]Case{
    // Every call the running phase forbids.
    .{ .name = "alloc_running", .phase = .running, .call = .alloc, .trips = true },
    .{ .name = "resize_grow_running", .phase = .running, .call = .resize_grow, .trips = true },
    .{ .name = "resize_shrink_running", .phase = .running, .call = .resize_shrink, .trips = true },
    .{ .name = "resize_zero_running", .phase = .running, .call = .resize_zero, .trips = true },
    .{ .name = "remap_grow_running", .phase = .running, .call = .remap_grow, .trips = true },
    .{ .name = "remap_shrink_running", .phase = .running, .call = .remap_shrink, .trips = true },
    .{ .name = "free_running", .phase = .running, .call = .free, .trips = true },
    .{ .name = "get_allocator_running", .phase = .running, .call = .get_allocator, .trips = true },
    .{ .name = "finish_startup_running", .phase = .running, .call = .finish_startup, .trips = true },
    // Shutdown allows frees only, and only of bytes that are live.
    .{ .name = "alloc_shutdown", .phase = .shutdown, .call = .alloc, .trips = true },
    .{ .name = "resize_grow_shutdown", .phase = .shutdown, .call = .resize_grow, .trips = true },
    .{ .name = "resize_shrink_shutdown", .phase = .shutdown, .call = .resize_shrink, .trips = true },
    .{ .name = "remap_grow_shutdown", .phase = .shutdown, .call = .remap_grow, .trips = true },
    .{ .name = "remap_shrink_shutdown", .phase = .shutdown, .call = .remap_shrink, .trips = true },
    .{ .name = "free_oversize_shutdown", .phase = .shutdown, .call = .free_oversize, .trips = true },
    .{ .name = "begin_shutdown_shutdown", .phase = .shutdown, .call = .begin_shutdown, .trips = true },
    .{ .name = "get_allocator_shutdown", .phase = .shutdown, .call = .get_allocator, .trips = true },
    .{ .name = "finish_startup_shutdown", .phase = .shutdown, .call = .finish_startup, .trips = true },
    // Startup allows frees too, but only of bytes that are live.
    .{ .name = "free_oversize_startup", .phase = .startup, .call = .free_oversize, .trips = true },
    // Phases move one step at a time: startup can't jump to shutdown.
    .{ .name = "begin_shutdown_startup", .phase = .startup, .call = .begin_shutdown, .trips = true },
    // Controls: the same calls where the phase allows them, so a harness bug on any call
    // path shows up as a failed control instead of a false trip.
    .{ .name = "alloc_startup", .phase = .startup, .call = .alloc, .trips = false },
    .{ .name = "resize_grow_startup", .phase = .startup, .call = .resize_grow, .trips = false },
    .{ .name = "resize_shrink_startup", .phase = .startup, .call = .resize_shrink, .trips = false },
    .{ .name = "remap_grow_startup", .phase = .startup, .call = .remap_grow, .trips = false },
    .{ .name = "remap_shrink_startup", .phase = .startup, .call = .remap_shrink, .trips = false },
    .{ .name = "free_startup", .phase = .startup, .call = .free, .trips = false },
    .{ .name = "free_shutdown", .phase = .shutdown, .call = .free, .trips = false },
    .{ .name = "resize_zero_shutdown", .phase = .shutdown, .call = .resize_zero, .trips = false },
};

comptime {
    assert(cases.len > 0);
    assert(cases.len <= cases_max);
    // Names become executable names, so each must be unique.
    @setEvalBranchQuota(100_000);
    for (cases, 0..) |a, i| {
        for (cases[i + 1 ..]) |b| {
            assert(!std.mem.eql(u8, a.name, b.name));
        }
    }
}
