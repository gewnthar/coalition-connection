//! Startup-trip harness: proves `StartupAllocator` stops the process when code calls it in
//! a phase that forbids the call, before the child allocator is touched.
//!
//! The guard is an assertion, and a tripped assertion panics, which ends the process. A
//! test block can't catch that, so `zig build test` builds this file once per case in
//! sim/startup_trip_cases.zig (the `case_index` build option) and runs each build as a
//! child process, checking its exit code. build.zig always builds it in ReleaseSafe, the
//! production mode, because the guard is compiled out where assertions are off.
//!
//! Exit codes (the first two are the passing ones, from the cases file):
//!   42  a trip case tripped: an assertion failed before the child allocator was reached
//!   0   a control case finished, and its call did what it should
//!   1   a panic before the call was made (a setup bug, not a result)
//!   2   a trip case's call returned without tripping: the guard is missing
//!   3   the call panicked, but not on an assertion
//!   4   setup failed
//!   5   the call reached the child allocator before tripping: the guard came too late
//!   6   a control case's call was refused, or left the accounting wrong
//!
//! What a pass proves: some assertion in `StartupAllocator` stopped the call before the
//! child allocator was reached. It can't tell which one: `fits` asserts the startup phase
//! too, so deleting only the phase check at the top of `alloc`, `resize` or `remap` still
//! trips, on the one in `fits`. Deleting both is caught.

const std = @import("std");
const assert = std.debug.assert;
const cc = @import("coalition_connection");
const build_options = @import("build_options");
const trip = @import("startup_trip_cases.zig");

const exit_early_panic: u8 = 1;
const exit_not_tripped: u8 = 2;
const exit_other_panic: u8 = 3;
const exit_setup_failed: u8 = 4;
const exit_child_reached: u8 = 5;
const exit_control_failed: u8 = 6;

comptime {
    const codes = [_]u8{
        trip.exit_finished,
        trip.exit_tripped,
        exit_early_panic,
        exit_not_tripped,
        exit_other_panic,
        exit_setup_failed,
        exit_child_reached,
        exit_control_failed,
    };
    for (codes, 0..) |a, i| {
        for (codes[i + 1 ..]) |b| assert(a != b);
    }
    assert(build_options.case_index < trip.cases.len);
}

const case: trip.Case = trip.cases[build_options.case_index];

/// Set just before the one call and cleared just after, so the panic handler can tell a
/// trip in that call from a panic anywhere else. Globals, because the panic handler takes
/// no context.
var armed: bool = false;
/// Calls that reached the child allocator, counted by `Tripwire`.
var child_calls: u32 = 0;
var child_calls_armed: u32 = 0;

pub const panic = std.debug.FullPanic(onPanic);

/// No runtime assertions here: a failed one would panic inside the panic handler. The
/// exit codes it chooses between are checked distinct at compile time above.
fn onPanic(message: []const u8, first_trace_address: ?usize) noreturn {
    _ = first_trace_address;
    if (!armed) {
        std.debug.print("startup_trip: {s} panicked before the call: {s}\n", .{ case.name, message });
        std.process.exit(exit_early_panic);
    }
    // std.debug.assert fails through `unreachable`, whose safety panic has this message.
    if (!std.mem.eql(u8, message, "reached unreachable code")) {
        std.debug.print("startup_trip: {s} panicked, but not on an assertion: {s}\n", .{ case.name, message });
        std.process.exit(exit_other_panic);
    }
    if (child_calls != child_calls_armed) {
        std.debug.print("startup_trip: {s} reached the child allocator before tripping\n", .{case.name});
        std.process.exit(exit_child_reached);
    }
    std.debug.print("startup_trip: {s} tripped\n", .{case.name});
    std.process.exit(trip.exit_tripped);
}

/// Forwards to a child allocator and counts every call that gets this far.
const Tripwire = struct {
    child: std.mem.Allocator,

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn allocator(self: *Tripwire) std.mem.Allocator {
        assert(child_calls == 0);
        assert(!armed);
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// Called first in every vtable function, before any assertion, so a panic that
    /// happens in here still counts as reaching the child.
    fn reached(context: *anyopaque) *Tripwire {
        child_calls += 1;
        assert(child_calls > 0);
        assert(child_calls <= 16); // The harness makes at most two child calls.
        return @ptrCast(@alignCast(context));
    }

    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self = reached(context);
        assert(len > 0);
        return self.child.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self = reached(context);
        assert(memory.len > 0);
        return self.child.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn remap(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self = reached(context);
        assert(memory.len > 0);
        return self.child.rawRemap(memory, alignment, new_len, ret_addr);
    }

    fn free(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self = reached(context);
        assert(memory.len > 0);
        self.child.rawFree(memory, alignment, ret_addr);
    }
};

const setup_len: u32 = 16;

pub fn main() void {
    // build.zig builds this file and src/root.zig in ReleaseSafe, so the guard's
    // assertions are compiled in. This checks the harness's own mode; the library's mode
    // rests on the `trip_root` module in build.zig.
    comptime assert(std.debug.runtime_safety);
    comptime assert(case.trips or case.phase != .running);

    // A fixed child keeps the run off the operating system's allocator.
    var backing: [256]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&backing);
    var tripwire: Tripwire = .{ .child = fixed.allocator() };
    var startup = cc.StartupAllocator.init(tripwire.allocator(), 128);
    const gpa = startup.allocator();
    const memory = gpa.alloc(u8, setup_len) catch |err| switch (err) {
        error.OutOfMemory => {
            std.debug.print("startup_trip: {s} setup could not allocate\n", .{case.name});
            std.process.exit(exit_setup_failed);
        },
    };
    assert(memory.len == setup_len);
    assert(startup.bytes_live == setup_len);
    assert(child_calls == 1);

    enterPhase(&startup);

    child_calls_armed = child_calls;
    armed = true;
    const result = callOnce(&startup, gpa, memory);
    armed = false;

    if (case.trips) {
        std.debug.print("startup_trip: {s} returned without tripping: the guard is missing\n", .{case.name});
        std.process.exit(exit_not_tripped);
    }
    if (!controlHeld(&startup, &fixed, result)) {
        std.debug.print("startup_trip: {s} control failed: granted={s} bytes_live={d} child calls={d}\n", .{
            case.name, if (result.ok) "yes" else "no", startup.bytes_live, child_calls - child_calls_armed,
        });
        std.process.exit(exit_control_failed);
    }
    std.debug.print("startup_trip: {s} finished\n", .{case.name});
    std.process.exit(trip.exit_finished);
}

fn enterPhase(startup: *cc.StartupAllocator) void {
    assert(startup.phase == .startup);
    assert(!armed);
    if (case.phase != .startup) startup.finishStartup();
    if (case.phase == .shutdown) startup.beginShutdown();
    assert(std.mem.eql(u8, @tagName(startup.phase), @tagName(case.phase)));
    assert(startup.allocationAllowed() == (case.phase == .startup));
}

const CallResult = struct {
    /// Whether the allocator granted the call.
    ok: bool,
};

/// Makes the case's one call; nothing else runs while `armed` is set. Every size differs
/// from the live 16 bytes, so std.mem.Allocator passes each call to the vtable.
fn callOnce(startup: *cc.StartupAllocator, gpa: std.mem.Allocator, memory: []u8) CallResult {
    assert(armed);
    assert(child_calls == child_calls_armed);
    assert(memory.len == setup_len);
    return switch (case.call) {
        .alloc => if (gpa.alloc(u8, 8)) |_| .{ .ok = true } else |err| switch (err) {
            error.OutOfMemory => .{ .ok = false },
        },
        .resize_grow => .{ .ok = gpa.resize(memory, 32) },
        .resize_shrink => .{ .ok = gpa.resize(memory, 8) },
        .resize_zero => .{ .ok = gpa.resize(memory, 0) },
        .remap_grow => .{ .ok = gpa.remap(memory, 32) != null },
        .remap_shrink => .{ .ok = gpa.remap(memory, 8) != null },
        .free => free: {
            gpa.free(memory);
            break :free .{ .ok = true };
        },
        .free_oversize => free: {
            gpa.free(memory.ptr[0..32]);
            break :free .{ .ok = true };
        },
        .get_allocator => get: {
            _ = startup.allocator();
            break :get .{ .ok = true };
        },
        .finish_startup => finish: {
            startup.finishStartup();
            break :finish .{ .ok = true };
        },
        .begin_shutdown => begin: {
            startup.beginShutdown();
            break :begin .{ .ok = true };
        },
    };
}

/// A control's call must be granted, reach the child exactly once, and leave bytes_live
/// at what the call implies.
fn controlHeld(startup: *const cc.StartupAllocator, fixed: *const std.heap.FixedBufferAllocator, result: CallResult) bool {
    assert(!case.trips);
    assert(!armed);
    const bytes_expected: u64 = switch (case.call) {
        .alloc => setup_len + 8,
        .resize_grow, .remap_grow => 32,
        .resize_shrink, .remap_shrink => 8,
        .free, .resize_zero => 0,
        else => @compileError("startup_trip: no control expectation for " ++ @tagName(case.call)),
    };
    if (!result.ok) return false;
    if (child_calls - child_calls_armed != 1) return false;
    if (startup.bytes_live != bytes_expected) return false;
    // A free of the child's last allocation hands its bytes back.
    if (bytes_expected == 0 and fixed.end_index != 0) return false;
    return true;
}
