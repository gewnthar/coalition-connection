//! The startup-trip cases: one list, read by build.zig (one run per case, naming the case
//! as its argument) and by sim/startup_trip.zig (what each case does), so the two can't
//! drift apart.
//!
//! Each case names its target and makes one call on it. A `StartupAllocator` case puts the
//! allocator in a phase first; a connection-table case builds a small table with one free
//! entry and the rest in use, then ends startup. A case that `trips` must stop the process
//! on an assertion (before the child allocator is touched, for the allocator); a control
//! case makes a call its target allows and must finish normally.

const std = @import("std");
const assert = std.debug.assert;

/// The allocator's phase when the call is made. Mirrors `StartupAllocator.Phase`.
pub const Phase = enum(u8) { startup, running, shutdown };

pub const AllocatorCall = enum(u8) {
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

/// A call on the connection table the harness builds: `table_size` entries, `free_id`
/// released again, `writing_id` moved to writing, and the others in use and reading.
pub const TableCall = enum(u8) {
    // release, get and setState(.writing) on the free entry. Its socket field is -1, so
    // release and get may trip on their socket check as well as their state check.
    release_free,
    get_free,
    set_state_free,
    // The same, after the harness writes a valid-looking socket into the free entry, as a
    // stale field would. The state check alone must stop these.
    release_free_stale_socket,
    get_free_stale_socket,
    // setState(.free) on an entry in use: only release may free an entry.
    set_state_to_free,
    // An id one past the table's last entry, which must trip on the id check, not on an
    // out-of-bounds index.
    release_out_of_range,
    get_out_of_range,
    set_state_out_of_range,
    // Controls on the reading entry: release, get, and a move to writing.
    release_reading,
    get_reading,
    set_state_to_writing,
    // Controls on the writing entry, whose socket is 0, the lowest valid descriptor:
    // release, get, and a move back to reading.
    release_writing,
    get_writing,
    set_state_to_reading,
};

pub const table_size: u32 = 4;
/// The one free entry; the harness acquires every entry, then releases this one. Every
/// call is made with this one entry free, so the tests show each check at that fill level.
pub const free_id: u32 = 1;
/// An entry in use and reading, and one in use and writing. Each entry's socket is
/// `socket_base + id`, so the writing entry holds socket 0.
pub const reading_id: u32 = 2;
pub const writing_id: u32 = 0;
pub const socket_base: i32 = 0;

comptime {
    assert(free_id < table_size);
    assert(reading_id < table_size);
    assert(writing_id < table_size);
    assert(free_id != reading_id and free_id != writing_id and reading_id != writing_id);
    assert(socket_base + @as(i32, writing_id) == 0);
}

pub const Target = union(enum) {
    startup_allocator: struct { phase: Phase, call: AllocatorCall },
    connection_table: TableCall,
};

pub const Case = struct {
    name: []const u8,
    target: Target,
    trips: bool,
};

pub const Outcome = enum(u8) { trips, finishes };

fn onAllocator(name: []const u8, phase: Phase, call: AllocatorCall, outcome: Outcome) Case {
    assert(name.len > 0);
    // The running phase forbids every call, so a running case must trip.
    assert(phase != .running or outcome == .trips);
    return .{
        .name = name,
        .target = .{ .startup_allocator = .{ .phase = phase, .call = call } },
        .trips = outcome == .trips,
    };
}

fn onTable(name: []const u8, call: TableCall, outcome: Outcome) Case {
    assert(name.len > 0);
    // Table case names start with "table_", so the build log groups them.
    assert(std.mem.startsWith(u8, name, "table_"));
    return .{ .name = name, .target = .{ .connection_table = call }, .trips = outcome == .trips };
}

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

pub const cases_max: u32 = 48;

pub const cases = [_]Case{
    // Every call the running phase forbids.
    onAllocator("alloc_running", .running, .alloc, .trips),
    onAllocator("resize_grow_running", .running, .resize_grow, .trips),
    onAllocator("resize_shrink_running", .running, .resize_shrink, .trips),
    onAllocator("resize_zero_running", .running, .resize_zero, .trips),
    onAllocator("remap_grow_running", .running, .remap_grow, .trips),
    onAllocator("remap_shrink_running", .running, .remap_shrink, .trips),
    onAllocator("free_running", .running, .free, .trips),
    onAllocator("get_allocator_running", .running, .get_allocator, .trips),
    onAllocator("finish_startup_running", .running, .finish_startup, .trips),
    // Shutdown allows frees only, and only of bytes that are live.
    onAllocator("alloc_shutdown", .shutdown, .alloc, .trips),
    onAllocator("resize_grow_shutdown", .shutdown, .resize_grow, .trips),
    onAllocator("resize_shrink_shutdown", .shutdown, .resize_shrink, .trips),
    onAllocator("remap_grow_shutdown", .shutdown, .remap_grow, .trips),
    onAllocator("remap_shrink_shutdown", .shutdown, .remap_shrink, .trips),
    onAllocator("free_oversize_shutdown", .shutdown, .free_oversize, .trips),
    onAllocator("begin_shutdown_shutdown", .shutdown, .begin_shutdown, .trips),
    onAllocator("get_allocator_shutdown", .shutdown, .get_allocator, .trips),
    onAllocator("finish_startup_shutdown", .shutdown, .finish_startup, .trips),
    // Startup allows frees too, but only of bytes that are live.
    onAllocator("free_oversize_startup", .startup, .free_oversize, .trips),
    // Phases move one step at a time: startup can't jump to shutdown.
    onAllocator("begin_shutdown_startup", .startup, .begin_shutdown, .trips),
    // Controls: the same calls where the phase allows them, so a harness bug on any call
    // path shows up as a failed control instead of a false trip.
    onAllocator("alloc_startup", .startup, .alloc, .finishes),
    onAllocator("resize_grow_startup", .startup, .resize_grow, .finishes),
    onAllocator("resize_shrink_startup", .startup, .resize_shrink, .finishes),
    onAllocator("remap_grow_startup", .startup, .remap_grow, .finishes),
    onAllocator("remap_shrink_startup", .startup, .remap_shrink, .finishes),
    onAllocator("free_startup", .startup, .free, .finishes),
    onAllocator("free_shutdown", .shutdown, .free, .finishes),
    onAllocator("resize_zero_shutdown", .shutdown, .resize_zero, .finishes),
    // The connection table: an entry not in use can't be released, read or moved, and only
    // release frees an entry. The first two may trip on the socket check; the stale-socket
    // pair below pins the state check.
    onTable("table_release_free", .release_free, .trips),
    onTable("table_get_free", .get_free, .trips),
    onTable("table_set_state_free", .set_state_free, .trips),
    onTable("table_release_free_stale_socket", .release_free_stale_socket, .trips),
    onTable("table_get_free_stale_socket", .get_free_stale_socket, .trips),
    onTable("table_set_state_to_free", .set_state_to_free, .trips),
    onTable("table_release_out_of_range", .release_out_of_range, .trips),
    onTable("table_get_out_of_range", .get_out_of_range, .trips),
    onTable("table_set_state_out_of_range", .set_state_out_of_range, .trips),
    // Controls: the same calls on entries in use, reading and writing.
    onTable("table_release_reading", .release_reading, .finishes),
    onTable("table_get_reading", .get_reading, .finishes),
    onTable("table_set_state_to_writing", .set_state_to_writing, .finishes),
    onTable("table_release_writing", .release_writing, .finishes),
    onTable("table_get_writing", .get_writing, .finishes),
    onTable("table_set_state_to_reading", .set_state_to_reading, .finishes),
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
    // Every table call has exactly one case.
    for (std.enums.values(TableCall)) |call| {
        var found: u32 = 0;
        for (cases) |case| switch (case.target) {
            .connection_table => |case_call| found += @intFromBool(case_call == call),
            .startup_allocator => {},
        };
        assert(found == 1);
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
