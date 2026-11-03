//! The startup-trip cases: one list, read by build.zig (one run per case, naming the case
//! as its argument) and by sim/startup_trip.zig (what each case does), so the two can't
//! drift apart.
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
/// The arguments named no case. A bad argument must end the run with this code, never
/// pick a case or panic.
pub const exit_bad_argument: u8 = 7;

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

/// The index of the case with exactly this name, or null.
pub fn find(name: []const u8) ?u32 {
    assert(cases.len > 0);
    assert(cases.len <= cases_max);
    for (cases, 0..) |case, index| {
        if (std.mem.eql(u8, case.name, name)) return @intCast(index);
    }
    return null;
}

/// An argument list that names no case, and what the harness must say about it on stderr.
pub const BadArguments = struct {
    arguments: []const []const u8,
    stderr: []const u8,
};

/// What the harness prints for each bad argument list; it prints from these, so the
/// expected text and the printed text are one.
pub const say_none = "startup_trip: expected one argument, a case name; got none\n";
pub const say_more = "startup_trip: expected one argument, a case name; got more\n";
pub const say_unknown_head = "startup_trip: no case is named \"";
pub const say_unknown_tail = "\"\n";

fn sayUnknown(comptime name: []const u8) []const u8 {
    return say_unknown_head ++ name ++ say_unknown_tail;
}

/// build.zig runs the harness with each list and expects `exit_bad_argument` and the
/// message: no argument, an unknown name, an empty name, a real name's prefix, a real name
/// with a trailing byte, a real name in the wrong case, a real name twice, an unknown name
/// before a real one, and a real name before an empty one.
pub const bad_arguments = [_]BadArguments{
    .{ .arguments = &.{}, .stderr = say_none },
    .{ .arguments = &.{"no_such_case"}, .stderr = sayUnknown("no_such_case") },
    .{ .arguments = &.{""}, .stderr = sayUnknown("") },
    .{ .arguments = &.{"alloc"}, .stderr = sayUnknown("alloc") },
    .{ .arguments = &.{"alloc_running_"}, .stderr = sayUnknown("alloc_running_") },
    .{ .arguments = &.{"ALLOC_RUNNING"}, .stderr = sayUnknown("ALLOC_RUNNING") },
    .{ .arguments = &.{ "alloc_running", "alloc_running" }, .stderr = say_more },
    .{ .arguments = &.{ "no_such_case", "alloc_running" }, .stderr = say_more },
    .{ .arguments = &.{ "alloc_running", "" }, .stderr = say_more },
};

pub const bad_arguments_max: u32 = 10;

comptime {
    assert(bad_arguments.len > 0);
    assert(bad_arguments.len <= bad_arguments_max);
    // Each list really names no case: one argument that matches a case would make that
    // run pass for the wrong reason.
    for (bad_arguments) |bad| {
        assert(bad.arguments.len != 1 or find(bad.arguments[0]) == null);
        assert(bad.stderr.len > 0);
    }
}

comptime {
    assert(cases.len > 0);
    assert(cases.len <= cases_max);
    // A run picks its case by name, so each name must be unique.
    @setEvalBranchQuota(100_000);
    for (cases, 0..) |a, i| {
        for (cases[i + 1 ..]) |b| {
            assert(!std.mem.eql(u8, a.name, b.name));
        }
    }
}
