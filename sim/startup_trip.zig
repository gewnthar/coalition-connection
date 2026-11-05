//! Startup-trip harness: proves `StartupAllocator` stops the process when code calls it in
//! a phase that forbids the call, before the child allocator is touched, and that the
//! connection table stops it when code releases, reads or moves an entry not in use.
//!
//! The guard is an assertion, and a tripped assertion panics, which ends the process. A
//! test block can't catch that, so `zig build test` builds this file once, in ReleaseSafe,
//! and runs it as a child process once per case in sim/startup_trip_cases.zig, with the
//! case's name as the one argument, checking each run's exit code. build.zig always builds
//! it in ReleaseSafe, the production mode, because the guard is compiled out where
//! assertions are off.
//!
//! Exit codes (42 and 0 pass for cases, 7 passes for bad argument lists; those three come
//! from the cases file):
//!   42  a trip case tripped: an assertion failed (for the allocator, before the child
//!       allocator was reached)
//!   0   a control case finished, and its call did what it should
//!   1   a panic before the call was made (a setup bug, not a result)
//!   2   a trip case's call returned without tripping: the check is missing
//!   3   the call panicked, but not on an assertion
//!   4   setup failed
//!   5   the call reached the child allocator before tripping: the guard came too late
//!   6   a control case's call was refused, or left the accounting or the table wrong
//!   7   the arguments name no case: not exactly one argument, or an unknown name
//!
//! A passing case prints nothing; only the failure codes say why on stderr. Zig's build
//! runner shows any stderr from a run step, even a passing one, under a "failed command"
//! line, so a passing case that printed would look like a failure in every test log.
//! build.zig checks every run's stderr, which captures it: empty for a case, the expected
//! message for a bad argument list.
//!
//! Linux only, like the server: the arguments are read with std.process.Args.Iterator.init,
//! which doesn't compile for Windows or WASI.
//!
//! What a pass proves: some assertion in `StartupAllocator` stopped the call before the
//! child allocator was reached. It can't tell which one: `fits` asserts the startup phase
//! too, so deleting only the phase check at the top of `alloc`, `resize` or `remap` still
//! trips, on the one in `fits`. Deleting both is caught.
//!
//! For the connection table, a pass proves an assertion stopped the call, not an index out
//! of bounds (exit 3). `release` and `get` also check the entry's socket, which a free entry
//! holds as -1, so a stale-socket case writes a valid-looking socket into the free entry
//! first: then only the state check can stop the call.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const cc = @import("coalition_connection");
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
        trip.exit_bad_argument,
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
    // Every case is checked here, not just the one a run picks: the running phase forbids
    // every call, so a running case that doesn't trip is a mistake in the list, and every
    // control's call needs an expectation in `bytesExpected`.
    for (trip.cases) |c| switch (c.target) {
        .startup_allocator => |on| {
            assert(c.trips or on.phase != .running);
            assert(c.trips or bytesExpected(on.call) != null);
        },
        .connection_table => |call| assert(c.trips != tableCallAllowed(call)),
    };
}

/// The case this run makes, by name, for the panic handler's messages. Set once the
/// argument has named a case; a global, because the panic handler takes no context.
var case_name: []const u8 = "(no case chosen yet)";
/// Set just before the one call and cleared just after, so the panic handler can tell a
/// trip in that call from a panic anywhere else.
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
        std.debug.print("startup_trip: {s} panicked before the call: {s}\n", .{ case_name, message });
        std.process.exit(exit_early_panic);
    }
    // std.debug.assert fails through `unreachable`, whose safety panic has this message.
    if (!std.mem.eql(u8, message, "reached unreachable code")) {
        std.debug.print("startup_trip: {s} panicked, but not on an assertion: {s}\n", .{ case_name, message });
        std.process.exit(exit_other_panic);
    }
    if (child_calls != child_calls_armed) {
        std.debug.print("startup_trip: {s} reached the child allocator before tripping\n", .{case_name});
        std.process.exit(exit_child_reached);
    }
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
/// The budget `main` gives the allocator; the table and the setup bytes each fit in it.
const budget_bytes: u64 = 128;
/// The fixed child allocator's backing. Each allocation may be padded to its alignment, so
/// the backing leaves room for the whole budget plus padding on each of the two
/// allocations the table makes.
const backing_len: u32 = 256;

comptime {
    assert(2 * setup_len <= budget_bytes);
    assert(trip.table_size * cc.live.connections.entry_bytes <= budget_bytes);
    assert(budget_bytes + 2 * @alignOf(cc.live.connections.Entry) <= backing_len);
    assert(@TypeOf(trip.socket_base) == cc.live.connections.Socket);
}

pub fn main(init: std.process.Init.Minimal) void {
    // build.zig builds this file and src/root.zig in ReleaseSafe, so the guard's
    // assertions are compiled in. This checks the harness's own module; the library's
    // mode rests on the `trip_root` module in build.zig.
    comptime assert(builtin.optimize.runtimeSafety());
    const case = caseFromArguments(init.args) orelse {
        std.process.exit(trip.exit_bad_argument);
    };
    case_name = case.name;
    assert(case.name.len > 0);

    // A fixed child keeps the run off the operating system's allocator.
    var backing: [backing_len]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&backing);
    var tripwire: Tripwire = .{ .child = fixed.allocator() };
    var startup = cc.StartupAllocator.init(tripwire.allocator(), budget_bytes);
    switch (case.target) {
        .startup_allocator => |on| runAllocatorCase(&startup, &fixed, on.phase, on.call, case),
        .connection_table => |call| runTableCase(&startup, call, case),
    }
}

fn runAllocatorCase(
    startup: *cc.StartupAllocator,
    fixed: *const std.heap.FixedBufferAllocator,
    phase: trip.Phase,
    call: trip.AllocatorCall,
    case: trip.Case,
) noreturn {
    assert(startup.bytes_live == 0);
    assert(startup.phase == .startup);
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

    enterPhase(startup, phase);

    child_calls_armed = child_calls;
    armed = true;
    const result = callOnce(startup, gpa, memory, call);
    armed = false;

    if (case.trips) {
        std.debug.print("startup_trip: {s} returned without tripping: the guard is missing\n", .{case.name});
        std.process.exit(exit_not_tripped);
    }
    if (!controlHeld(startup, fixed, result, call)) {
        std.debug.print("startup_trip: {s} control failed: granted={s} bytes_live={d} child calls={d}\n", .{
            case.name, if (result.ok) "yes" else "no", startup.bytes_live, child_calls - child_calls_armed,
        });
        std.process.exit(exit_control_failed);
    }
    std.process.exit(trip.exit_finished);
}

/// The case named by the one argument after the program's name, or null, after saying
/// why on stderr, when there isn't exactly one argument or it names no case.
fn caseFromArguments(arguments: std.process.Args) ?trip.Case {
    assert(!armed);
    assert(child_calls == 0);
    var iterator: std.process.Args.Iterator = .init(arguments);
    _ = iterator.skip(); // The program's own name.
    const name = iterator.next() orelse {
        std.debug.print("{s}", .{trip.say_none});
        return null;
    };
    if (iterator.next() != null) {
        std.debug.print("{s}", .{trip.say_more});
        return null;
    }
    const index = trip.find(name) orelse {
        std.debug.print("{s}{s}{s}", .{ trip.say_unknown_head, name, trip.say_unknown_tail });
        return null;
    };
    assert(index < trip.cases.len);
    assert(std.mem.eql(u8, trip.cases[index].name, name));
    return trip.cases[index];
}

fn enterPhase(startup: *cc.StartupAllocator, phase: trip.Phase) void {
    assert(startup.phase == .startup);
    assert(!armed);
    if (phase != .startup) startup.finishStartup();
    if (phase == .shutdown) startup.beginShutdown();
    assert(std.mem.eql(u8, @tagName(startup.phase), @tagName(phase)));
    assert(startup.allocationAllowed() == (phase == .startup));
}

const CallResult = struct {
    /// Whether the allocator granted the call.
    ok: bool,
};

/// Makes the case's one call; nothing else runs while `armed` is set. Every size differs
/// from the live 16 bytes, so std.mem.Allocator passes each call to the vtable.
fn callOnce(startup: *cc.StartupAllocator, gpa: std.mem.Allocator, memory: []u8, call: trip.AllocatorCall) CallResult {
    assert(armed);
    assert(child_calls == child_calls_armed);
    assert(memory.len == setup_len);
    return switch (call) {
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

/// The live bytes a control's call leaves, or null for a call no control makes. The
/// comptime block above checks every control case has one.
fn bytesExpected(call: trip.AllocatorCall) ?u64 {
    comptime assert(setup_len == 16);
    const bytes: ?u64 = switch (call) {
        .alloc => setup_len + 8,
        .resize_grow, .remap_grow => 32,
        .resize_shrink, .remap_shrink => 8,
        .free, .resize_zero => 0,
        .free_oversize, .get_allocator, .finish_startup, .begin_shutdown => null,
    };
    // Every expectation fits the 128-byte budget main gives the allocator.
    assert(bytes == null or bytes.? <= 2 * setup_len);
    return bytes;
}

/// A control's call must be granted, reach the child exactly once, and leave bytes_live
/// at what the call implies.
fn controlHeld(
    startup: *const cc.StartupAllocator,
    fixed: *const std.heap.FixedBufferAllocator,
    result: CallResult,
    call: trip.AllocatorCall,
) bool {
    assert(!armed);
    // The comptime block at the top proves every control's call has an expectation.
    const bytes_or_null = bytesExpected(call);
    assert(bytes_or_null != null);
    const bytes_expected = bytes_or_null.?;
    if (!result.ok) return false;
    if (child_calls - child_calls_armed != 1) return false;
    if (startup.bytes_live != bytes_expected) return false;
    // A free of the child's last allocation hands its bytes back.
    if (bytes_expected == 0 and fixed.end_index != 0) return false;
    return true;
}

const connections = cc.live.connections;
const Entry = connections.Entry;

/// Whether the table allows `call`: the controls, on an entry in use. The cases file says
/// the same through each case's outcome, and the comptime block at the top checks the two
/// agree.
fn tableCallAllowed(call: trip.TableCall) bool {
    const allowed = switch (call) {
        .release_reading,
        .get_reading,
        .set_state_to_writing,
        .release_writing,
        .get_writing,
        .set_state_to_reading,
        => true,
        .release_free,
        .get_free,
        .set_state_free,
        .release_free_stale_socket,
        .get_free_stale_socket,
        .set_state_to_free,
        .release_out_of_range,
        .get_out_of_range,
        .set_state_out_of_range,
        => false,
    };
    // Every allowed call names an entry in use; every forbidden one names the free entry,
    // a move to free, or an id out of range.
    assert(allowed == (tableCallId(call) != trip.free_id and call != .set_state_to_free and
        tableCallId(call) < trip.table_size));
    return allowed;
}

/// The id the call names.
fn tableCallId(call: trip.TableCall) u32 {
    const id: u32 = switch (call) {
        .release_free, .get_free, .set_state_free => trip.free_id,
        .release_free_stale_socket, .get_free_stale_socket => trip.free_id,
        .release_out_of_range, .get_out_of_range, .set_state_out_of_range => trip.table_size,
        .release_reading, .get_reading, .set_state_to_writing, .set_state_to_free => trip.reading_id,
        .release_writing, .get_writing, .set_state_to_reading => trip.writing_id,
    };
    assert(id <= trip.table_size);
    assert(id != trip.free_id or call != .set_state_to_free);
    return id;
}

fn socketOf(id: u32) connections.Socket {
    assert(id < trip.table_size);
    const socket = trip.socket_base + @as(connections.Socket, @intCast(id));
    assert(socket >= 0);
    return socket;
}

/// Builds a table of `table_size` entries during startup, acquires every entry, moves
/// `writing_id` to writing, releases `free_id`, ends startup, and makes the case's one call.
fn runTableCase(startup: *cc.StartupAllocator, call: trip.TableCall, case: trip.Case) noreturn {
    assert(startup.bytes_live == 0);
    assert(startup.phase == .startup);
    var table = connections.Table.init(startup.allocator(), trip.table_size) catch |err| switch (err) {
        error.OutOfMemory => {
            std.debug.print("startup_trip: {s} setup could not allocate the table\n", .{case.name});
            std.process.exit(exit_setup_failed);
        },
    };
    var id: u32 = 0;
    while (id < trip.table_size) : (id += 1) {
        const acquired = table.acquire(socketOf(id)) catch |err| switch (err) {
            error.TableFull => {
                std.debug.print("startup_trip: {s} setup found the table full\n", .{case.name});
                std.process.exit(exit_setup_failed);
            },
        };
        assert(acquired == id);
    }
    assert(id == trip.table_size);
    table.setState(trip.writing_id, .writing);
    assert(table.release(trip.free_id) == socketOf(trip.free_id));
    startup.finishStartup();
    table.assertInvariants();
    assert(table.count() == trip.table_size - 1);
    assert(table.entries[trip.free_id].state == .free);
    assert(table.entries[trip.reading_id].state == .reading);
    assert(table.entries[trip.writing_id].state == .writing);
    if (call == .release_free_stale_socket or call == .get_free_stale_socket) {
        // A valid-looking socket in a free entry, as a stale field would leave.
        table.entries[trip.free_id].socket = socketOf(trip.free_id);
    }
    var before: [trip.table_size]Entry = undefined;
    @memcpy(&before, table.entries);

    child_calls_armed = child_calls;
    armed = true;
    const socket = callTable(&table, call);
    armed = false;

    if (case.trips) {
        std.debug.print("startup_trip: {s} returned without tripping: the check is missing\n", .{case.name});
        std.process.exit(exit_not_tripped);
    }
    if (!tableControlHeld(&table, &before, call, socket)) {
        std.debug.print("startup_trip: {s} control failed: count={d} child calls={d}\n", .{
            case.name, table.count(), child_calls - child_calls_armed,
        });
        std.process.exit(exit_control_failed);
    }
    std.process.exit(trip.exit_finished);
}

/// Makes the case's one table call on the id it names; nothing else runs while `armed` is
/// set. Returns the socket the call handed back, or -1 for a call that returns none.
fn callTable(table: *connections.Table, call: trip.TableCall) connections.Socket {
    assert(armed);
    assert(child_calls == child_calls_armed);
    const id: connections.PeerId = tableCallId(call);
    return switch (call) {
        .release_free,
        .release_free_stale_socket,
        .release_out_of_range,
        .release_reading,
        .release_writing,
        => table.release(id),
        .get_free,
        .get_free_stale_socket,
        .get_out_of_range,
        .get_reading,
        .get_writing,
        => table.get(id).socket,
        .set_state_free, .set_state_out_of_range, .set_state_to_writing => state: {
            table.setState(id, .writing);
            break :state -1;
        },
        .set_state_to_free => state: {
            table.setState(id, .free);
            break :state -1;
        },
        .set_state_to_reading => state: {
            table.setState(id, .reading);
            break :state -1;
        },
    };
}

/// A control's call must touch no allocator, hand back the right socket, change only the
/// entry it names, and leave that entry as the call implies, with the free stack and the
/// entries agreeing.
fn tableControlHeld(
    table: *const connections.Table,
    before: *const [trip.table_size]Entry,
    call: trip.TableCall,
    socket: connections.Socket,
) bool {
    assert(!armed);
    const id = tableCallId(call);
    assert(id < trip.table_size and id != trip.free_id);
    if (child_calls != child_calls_armed) return false;
    var other: u32 = 0;
    while (other < trip.table_size) : (other += 1) {
        if (other == id) continue;
        if (!std.meta.eql(table.entries[other], before[other])) return false;
    }
    assert(other == trip.table_size);
    const entry = table.entries[id];
    const expected: Entry = switch (call) {
        .release_reading, .release_writing => .{ .socket = -1, .state = .free },
        .get_reading, .get_writing => before[id],
        .set_state_to_writing => .{ .socket = before[id].socket, .state = .writing },
        .set_state_to_reading => .{ .socket = before[id].socket, .state = .reading },
        else => unreachable, // tableCallAllowed: the comptime block admits only these.
    };
    if (!std.meta.eql(entry, expected)) return false;
    const released = call == .release_reading or call == .release_writing;
    const socket_expected: connections.Socket = if (call == .get_reading or call == .get_writing or released)
        socketOf(id)
    else
        -1;
    if (socket != socket_expected) return false;
    const count_expected: u32 = if (released) trip.table_size - 2 else trip.table_size - 1;
    if (table.count() != count_expected) return false;
    if (released and table.free_ids[table.free_count - 1] != id) return false;
    return tableAgrees(table);
}

/// Whether the free stack and the entries agree: every stacked id names a free entry and is
/// stacked once, and every free entry is stacked. The table's own `assertInvariants`
/// checks the same, but a failed assertion here would read as a panic outside the call.
fn tableAgrees(table: *const connections.Table) bool {
    assert(!armed);
    assert(table.entries.len == trip.table_size);
    if (table.capacity() != trip.table_size) return false;
    if (table.free_count > trip.table_size) return false;
    var stacked: [trip.table_size]bool = @splat(false);
    for (table.free_ids[0..table.free_count]) |id| {
        if (id >= trip.table_size) return false;
        if (stacked[id] or table.entries[id].state != .free) return false;
        stacked[id] = true;
    }
    for (table.entries, stacked) |entry, is_stacked| {
        if ((entry.state == .free) != is_stacked) return false;
    }
    return true;
}
