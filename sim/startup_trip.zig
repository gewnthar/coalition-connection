//! Startup-trip harness: proves `StartupAllocator` stops the process when code calls it in
//! a phase that forbids the call, before the child allocator is touched, that the
//! connection table stops it when code releases, reads or moves an entry not in use, and
//! that the real I/O type stops it when its clock steps back, when it is handed an execute,
//! when a send names a peer not in the table, and when it is set up after startup. It also
//! proves the response writer stops the process when the body, a header name or a header
//! value shares a byte with the buffer it writes into.
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
//!   1   a panic outside the call: in setup, or in a control's checks after it
//!   2   a trip case's call returned without tripping: the check is missing
//!   3   the call panicked, but not the way its case expects: not on an assertion, or for
//!       a submitted execute, not on the real type's placeholder panic
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
//!
//! For the real I/O type, the entry in use holds one end of a real socketpair, so the
//! controls' sends really go out and their completions really come back. A send to the
//! free entry is tried three ways: as it is, where its socket field of -1 can trip the
//! socket checks in `get` and `socketFor` as well as the state check; with the live
//! descriptor written back into it, where only the table's state check can stop the call
//! (without it, the call returns); and the same with every slot of the ring in use, where
//! the peer must be checked before the queue, or the call returns QueueFull instead of
//! tripping. Every real-I/O case but `real_init_running` sets up a ring first; where the
//! kernel refuses one, they fail with the setup code, never pass. `real_init_running` trips
//! before the ring is set up, so it runs either way.
//!
//! For the response writer, the buffer is cut from the middle of a larger array, so a field
//! can sit inside it, across one of its edges, right next to it, or in neither. `write`
//! checks the body and each header field before writing anything, and its copy checks
//! every source again, so a plain inside case passes as long as either check is there. The
//! `_head` case (whose body is never copied) and the `_refused` cases (which return an
//! error before the first copy) can only be stopped by the first check, so each pins one
//! assertion on its own. The copy's check has no case of its own: every source `write`
//! hands it was checked first, so through `write` it can't be the only check left.
//! As for every assertion case, a pass shows that some assertion fired during the call,
//! not which one; nothing else in `write` can fire on these inputs today.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const linux = std.os.linux;
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
        .real_io => |call| assert(c.trips != realCallAllowed(call)),
        .http_response => |call| assert(c.trips != responseCallAllowed(call)),
    };
}

/// The case this run makes, by name, for the panic handler's messages. Set once the
/// argument has named a case; a global, because the panic handler takes no context.
var case_name: []const u8 = "(no case chosen yet)";
/// How the chosen case must stop if it trips; set with `case_name`.
var panic_expected: trip.Panic = .assertion;
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
        std.debug.print("startup_trip: {s} panicked outside the call: {s}\n", .{ case_name, message });
        std.process.exit(exit_early_panic);
    }
    // std.debug.assert fails through `unreachable`, whose safety panic has this message;
    // the real type's execute panic begins with its own.
    const expected = switch (panic_expected) {
        .assertion => std.mem.eql(u8, message, trip.message_assertion),
        .execute_placeholder => std.mem.startsWith(u8, message, trip.message_execute_head),
    };
    if (!expected) {
        std.debug.print("startup_trip: {s} panicked, but not as expected ({t}): {s}\n", .{
            case_name, panic_expected, message,
        });
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
    assert(trip.real_table_size * cc.live.connections.entry_bytes <= budget_bytes);
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
    panic_expected = case.panic;
    assert(case.name.len > 0);

    // A fixed child keeps the run off the operating system's allocator.
    var backing: [backing_len]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&backing);
    var tripwire: Tripwire = .{ .child = fixed.allocator() };
    var startup = cc.StartupAllocator.init(tripwire.allocator(), budget_bytes);
    switch (case.target) {
        .startup_allocator => |on| runAllocatorCase(&startup, &fixed, on.phase, on.call, case),
        .connection_table => |call| runTableCase(&startup, call, case),
        .real_io => |call| runRealCase(&startup, call, case),
        .http_response => |call| runResponseCase(&startup, call, case),
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
        .lookup_out_of_range,
        .release_stale,
        .get_stale,
        .set_state_stale,
        => false,
    };
    // Every allowed call names an entry in use under its live generation; every forbidden
    // one names the free entry, a move to free, an id out of range, or a stale generation.
    const parts: connections.IdParts = @bitCast(tableCallId(call));
    const live = parts.index < trip.table_size and parts.index != trip.free_id and
        parts.generation == live_generation;
    assert(allowed == (live and call != .set_state_to_free));
    return allowed;
}

/// The generation of every entry the harness holds in use: none of them is ever released.
const live_generation: connections.Generation = 0;

/// The entry index the call names.
fn tableCallIndex(call: trip.TableCall) u32 {
    const index: u32 = switch (call) {
        .release_free, .get_free, .set_state_free => trip.free_id,
        .release_free_stale_socket, .get_free_stale_socket => trip.free_id,
        .release_out_of_range, .get_out_of_range, .set_state_out_of_range => trip.table_size,
        .lookup_out_of_range => trip.table_size,
        .release_reading, .get_reading, .set_state_to_writing, .set_state_to_free => trip.reading_id,
        .release_stale, .get_stale, .set_state_stale => trip.reading_id,
        .release_writing, .get_writing, .set_state_to_reading => trip.writing_id,
    };
    assert(index <= trip.table_size);
    assert(index != trip.free_id or call != .set_state_to_free);
    return index;
}

/// The generation of the free entry, released once during setup: the id the next acquire
/// would hand out carries it, so a call naming the free entry through that id passes the
/// generation check and only the state check can stop it.
const free_generation: connections.Generation = live_generation +% 1;

/// The id the call names: its entry's index under that entry's current generation, except
/// for the stale cases, which carry the generation before it (wrapping), one no live id
/// holds, so only the generation check can stop them.
fn tableCallId(call: trip.TableCall) connections.PeerId {
    const stale = call == .release_stale or call == .get_stale or call == .set_state_stale;
    const index = tableCallIndex(call);
    const generation: connections.Generation = if (stale)
        live_generation -% 1
    else if (index == trip.free_id)
        free_generation
    else
        live_generation;
    assert(!stale or index == trip.reading_id); // A stale id names an entry in use.
    assert(index < trip.table_size or generation == live_generation);
    return @bitCast(connections.IdParts{ .index = @intCast(index), .generation = generation });
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
    // The harness never counts a send, so nothing holds a release back.
    const freed = table.release(trip.free_id) catch |err| switch (err) {
        error.SendsInFlight => setupFailed(case, "found a send counted on the entry to free"),
    };
    assert(freed == socketOf(trip.free_id));
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
        .release_stale,
        // The harness never counts a send, so a refusal can only mean the table is wrong:
        // -2 matches no socket, and the control fails.
        => table.release(id) catch |err| switch (err) {
            error.SendsInFlight => -2,
        },
        .get_free,
        .get_free_stale_socket,
        .get_out_of_range,
        .get_stale,
        .get_reading,
        .get_writing,
        => table.get(id).socket,
        .set_state_free, .set_state_out_of_range, .set_state_stale, .set_state_to_writing => state: {
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
        .lookup_out_of_range => lookup: {
            _ = table.lookup(id);
            break :lookup -1;
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
    const index = tableCallIndex(call);
    assert(index < trip.table_size and index != trip.free_id);
    if (child_calls != child_calls_armed) return false;
    var other: u32 = 0;
    while (other < trip.table_size) : (other += 1) {
        if (other == index) continue;
        if (!std.meta.eql(table.entries[other], before[other])) return false;
    }
    assert(other == trip.table_size);
    const entry = table.entries[index];
    const expected: Entry = switch (call) {
        // A release advances the entry's generation, so the id it was called with is stale.
        .release_reading, .release_writing => .{
            .socket = -1,
            .state = .free,
            .generation = before[index].generation +% 1,
        },
        .get_reading, .get_writing => before[index],
        .set_state_to_writing => state: {
            var moved = before[index];
            moved.state = .writing;
            break :state moved;
        },
        .set_state_to_reading => state: {
            var moved = before[index];
            moved.state = .reading;
            break :state moved;
        },
        else => unreachable, // tableCallAllowed: the comptime block admits only these.
    };
    if (!std.meta.eql(entry, expected)) return false;
    const released = call == .release_reading or call == .release_writing;
    const socket_expected: connections.Socket = if (call == .get_reading or call == .get_writing or released)
        socketOf(index)
    else
        -1;
    if (socket != socket_expected) return false;
    const count_expected: u32 = if (released) trip.table_size - 2 else trip.table_size - 1;
    if (table.count() != count_expected) return false;
    if (released and table.free_indices[table.free_count - 1] != index) return false;
    if (released and table.lookup(tableCallId(call)) != null) return false;
    return tableAgrees(table);
}

/// Whether the free stack and the entries agree: every stacked index names a free entry and
/// is stacked once, every free entry is stacked, and no free entry holds a socket. The
/// table's own `assertInvariants` checks the same, but a failed assertion here would read
/// as a panic outside the call.
fn tableAgrees(table: *const connections.Table) bool {
    assert(!armed);
    assert(table.entries.len == trip.table_size);
    if (table.capacity() != trip.table_size) return false;
    if (table.free_count > trip.table_size) return false;
    var stacked: [trip.table_size]bool = @splat(false);
    for (table.free_indices[0..table.free_count]) |index| {
        if (index >= trip.table_size) return false;
        if (stacked[index] or table.entries[index].state != .free) return false;
        stacked[index] = true;
    }
    for (table.entries, stacked) |entry, is_stacked| {
        if ((entry.state == .free) != is_stacked) return false;
        if (entry.state == .free and entry.socket != -1) return false;
    }
    return true;
}

const Real = cc.io.real.Real;
/// The real type's ring depth: operations it holds in flight before QueueFull.
const slots_max: u32 = cc.constants.io_operations_in_flight_max;
/// Empty polls `drain` allows, 1 ms apart. Reason: a socketpair send completes during the
/// submitting system call; a second is ample even on a loaded CI machine.
const poll_attempts_max: u32 = 1_000;
/// The operation id the send control uses; the queue-full fill numbers its sends from 1,
/// so no fill send shares it.
const send_peer_id: cc.io.OperationId = slots_max + 1;
/// The byte each fill send carries.
const fill_byte: u8 = 'x';

/// Whether the real type allows `call`: the controls. The cases file says the same through
/// each case's outcome, and the comptime block at the top checks the two agree.
fn realCallAllowed(call: trip.RealCall) bool {
    const allowed = switch (call) {
        .now_fresh, .send_peer, .send_queue_full => true,
        .now_after_max,
        .submit_execute,
        .send_free,
        .send_free_stale_socket,
        .send_out_of_range,
        .send_free_queue_full,
        .init_running,
        => false,
    };
    // The controls are the clock read and the two sends to the entry in use; every case
    // that fills the ring is a send.
    assert(allowed == (call == .now_fresh or realCallPeer(call) == trip.real_peer_id));
    assert(!realCallFillsRing(call) or realCallPeer(call) != null);
    return allowed;
}

/// The peer a send case names, or null for a call that sends nothing. The free entry was
/// released once during setup, so it is named under its advanced generation: the id the
/// next acquire would hand out, which only the table's state check can refuse.
fn realCallPeer(call: trip.RealCall) ?cc.io.PeerId {
    const free_peer: cc.io.PeerId = @bitCast(connections.IdParts{
        .index = trip.real_free_id,
        .generation = free_generation,
    });
    const peer: ?cc.io.PeerId = switch (call) {
        .send_free, .send_free_stale_socket, .send_free_queue_full => free_peer,
        .send_out_of_range => trip.real_table_size,
        .send_peer, .send_queue_full => trip.real_peer_id,
        .now_after_max, .submit_execute, .init_running, .now_fresh => null,
    };
    // Only the two send controls name the entry in use; the forbidden sends name the free
    // entry or an id past the table.
    const index: ?connections.Index = if (peer) |id| @as(connections.IdParts, @bitCast(id)).index else null;
    assert(index == null or index.? <= trip.real_table_size);
    assert((peer == trip.real_peer_id) == (call == .send_peer or call == .send_queue_full));
    return peer;
}

/// Whether the case fills every slot of the ring before its call.
fn realCallFillsRing(call: trip.RealCall) bool {
    const fills = call == .send_free_queue_full or call == .send_queue_full;
    // One trip case and one control, which differ only in the peer they name.
    assert(!fills or (call == .send_queue_full) == (realCallPeer(call) == trip.real_peer_id));
    assert(!fills or realCallPeer(call) != null);
    return fills;
}

/// What a real-I/O call handed back, for the controls' checks.
const RealResult = struct {
    /// A clock call's reading; 0 for any other call.
    reading: cc.io.Instant = 0,
    /// The kernel's monotonic clock read just before and just after the call, so a reading
    /// can be checked against a clock the real type doesn't keep.
    clock_before: cc.io.Instant = 0,
    clock_after: cc.io.Instant = 0,
    /// Whether a submit returned QueueFull.
    queue_full: bool = false,
};

/// The state a real-I/O control's call must leave as it was, or change as it says.
const RealBefore = struct {
    entries: [trip.real_table_size]Entry,
    in_flight: u32,
    submitted: u64,
    completed: u64,
    last: cc.io.Instant,
    /// The submission queue's tail: a refused submission must not take an entry.
    sqe_tail: u32,
    free_count: u32,
};

fn setupFailed(case: trip.Case, comptime what: []const u8) noreturn {
    assert(!armed); // A failure inside the call is the case's result, not a setup failure.
    assert(what.len > 0);
    std.debug.print("startup_trip: {s} setup failed: " ++ what ++ "\n", .{case.name});
    std.process.exit(exit_setup_failed);
}

/// Builds a `real_table_size`-entry table during startup with `real_peer_id` holding one
/// end of a socketpair and `real_free_id` released again, sets up the real type on it
/// (unless the case does that itself, too late), ends startup, and makes the case's call.
fn runRealCase(startup: *cc.StartupAllocator, call: trip.RealCall, case: trip.Case) noreturn {
    assert(startup.bytes_live == 0);
    assert(startup.phase == .startup);
    const pair = socketPair(case);
    const local = pair[0];
    const remote = pair[1];
    var table = realTable(startup, case, local);

    var real: Real = undefined;
    if (call != .init_running) {
        real = Real.init(startup, &table) catch |err| {
            std.debug.print("startup_trip: {s} setup failed: no io_uring ring ({t})\n", .{ case.name, err });
            std.process.exit(exit_setup_failed);
        };
        assert(real.inFlight() == 0);
    }
    startup.finishStartup();
    table.assertInvariants();
    assert(table.count() == trip.real_table_size - 1);
    assert(table.entries[trip.real_free_id].state == .free);
    assert(table.entries[trip.real_free_id].socket == -1);
    assert(table.get(trip.real_peer_id).socket == local);

    switch (call) {
        .now_after_max => real.last = std.math.maxInt(cc.io.Instant),
        // The descriptor the entry held before it was released, as a stale field keeps it,
        // so only the state check can stop the send.
        .send_free_stale_socket, .send_free_queue_full => table.entries[trip.real_free_id].socket = local,
        else => {},
    }
    if (realCallFillsRing(call)) fillRing(&real, case);

    var before: RealBefore = undefined;
    @memcpy(&before.entries, table.entries);
    if (call != .init_running) {
        before.in_flight = real.inFlight();
        before.submitted = real.submitted;
        before.completed = real.completed;
        before.last = real.last;
        before.sqe_tail = real.ring.sq.sqe_tail;
        before.free_count = real.free_count;
    }

    child_calls_armed = child_calls;
    armed = true;
    const result = callReal(&real, startup, &table, call);
    armed = false;

    if (case.trips) {
        std.debug.print("startup_trip: {s} returned without tripping: the check is missing\n", .{case.name});
        std.process.exit(exit_not_tripped);
    }
    if (!realControlHeld(&real, &table, &before, call, result, local, remote)) {
        std.debug.print("startup_trip: {s} control failed: in flight={d} submitted={d} child calls={d}\n", .{
            case.name, real.inFlight(), real.submitted, child_calls - child_calls_armed,
        });
        std.process.exit(exit_control_failed);
    }
    std.process.exit(trip.exit_finished);
}

/// Both ends of a fresh stream socketpair: the first goes in the table, the second is the
/// far end the send control reads.
fn socketPair(case: trip.Case) [2]linux.fd_t {
    assert(!armed);
    var fds: [2]linux.fd_t = .{ -1, -1 };
    const flags = linux.SOCK.STREAM | linux.SOCK.CLOEXEC;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, flags, 0, &fds)) != .SUCCESS) {
        setupFailed(case, "no socketpair");
    }
    assert(fds[0] >= 0 and fds[1] >= 0);
    assert(fds[0] != fds[1]);
    return fds;
}

/// A `real_table_size`-entry table, built during startup, with `real_peer_id` holding
/// `local` and `real_free_id` released again.
fn realTable(startup: *cc.StartupAllocator, case: trip.Case, local: linux.fd_t) connections.Table {
    assert(startup.phase == .startup);
    assert(local >= 0);
    var table = connections.Table.init(startup.allocator(), trip.real_table_size) catch |err| switch (err) {
        error.OutOfMemory => setupFailed(case, "could not allocate the table"),
    };
    var id: u32 = 0;
    while (id < trip.real_table_size) : (id += 1) {
        // Every entry holds the local end; all but one are released again below.
        const acquired = table.acquire(local) catch |err| switch (err) {
            error.TableFull => setupFailed(case, "found the table full"),
        };
        assert(acquired == id);
    }
    assert(id == trip.real_table_size);
    // Nothing has been sent yet, so nothing holds the release back.
    const freed = table.release(trip.real_free_id) catch |err| switch (err) {
        error.SendsInFlight => setupFailed(case, "found a send counted on the entry to free"),
    };
    assert(freed == local);
    assert(table.count() == trip.real_table_size - 1);
    return table;
}

/// Puts a one-byte send to the entry in use in every slot of the ring, before the call.
fn fillRing(real: *Real, case: trip.Case) void {
    assert(!armed);
    assert(real.inFlight() == 0);
    var filled: u32 = 0;
    while (filled < slots_max) : (filled += 1) {
        const send: cc.io.Send = .{ .peer = trip.real_peer_id, .bytes = &.{fill_byte} };
        real.submit(.{ .id = filled + 1, .operation = .{ .send = send } }) catch |err| switch (err) {
            error.QueueFull => setupFailed(case, "the ring filled early"),
        };
    }
    assert(real.inFlight() == slots_max);
    assert(real.free_count == 0);
}

/// Makes the case's one call on the real type; nothing else runs while `armed` is set.
fn callReal(
    real: *Real,
    startup: *const cc.StartupAllocator,
    table: *connections.Table,
    call: trip.RealCall,
) RealResult {
    assert(armed);
    assert(child_calls == child_calls_armed);
    if (realCallPeer(call)) |peer| {
        const bytes = trip.real_send_bytes;
        const id: cc.io.OperationId = send_peer_id;
        real.submit(.{ .id = id, .operation = .{ .send = .{ .peer = peer, .bytes = bytes } } }) catch |err| {
            switch (err) {
                error.QueueFull => return .{ .queue_full = true },
            }
        };
        return .{};
    }
    switch (call) {
        .now_after_max, .now_fresh => {
            const clock_before = kernelClock();
            const reading = real.now();
            return .{ .reading = reading, .clock_before = clock_before, .clock_after = kernelClock() };
        },
        .submit_execute => {
            const execute: cc.io.Execute = .{ .statement = "select 1" };
            real.submit(.{ .id = send_peer_id, .operation = .{ .execute = execute } }) catch |err| switch (err) {
                error.QueueFull => return .{ .queue_full = true },
            };
            return .{};
        },
        .init_running => {
            // Whatever init returns, returning at all means the startup check is missing,
            // and the caller exits with that. A ring set up here is leaked; the process
            // ends straight after.
            var late = Real.init(startup, table) catch |err| switch (err) {
                error.RingUnavailable, error.RingResources, error.RingTooLarge => return .{},
            };
            late.deinit();
            return .{};
        },
        .send_free,
        .send_free_stale_socket,
        .send_out_of_range,
        .send_free_queue_full,
        .send_peer,
        .send_queue_full,
        => unreachable, // realCallPeer named a peer for each of these.
    }
}

/// A control's call must touch no allocator and leave the table as it was. The clock
/// control's reading is at or after the last and becomes the last. The send control's
/// completion comes back with its byte count and the far end reads the same bytes. The
/// queue-full control returns QueueFull with nothing changed, and every send already on
/// the ring still completes with its byte. Both send controls end with the ring empty and
/// closed, as `deinit` requires.
fn realControlHeld(
    real: *Real,
    table: *const connections.Table,
    before: *const RealBefore,
    call: trip.RealCall,
    result: RealResult,
    local: linux.fd_t,
    remote: linux.fd_t,
) bool {
    assert(!armed);
    assert(realCallAllowed(call));
    if (child_calls != child_calls_armed) return false;
    for (table.entries, before.entries, 0..) |entry, entry_before, index| {
        // A submitted send is counted on its peer's entry until its completion; nothing
        // else in any entry changes.
        var expected = entry_before;
        if (call == .send_peer and index == trip.real_peer_id) expected.sends_in_flight += 1;
        if (!std.meta.eql(entry, expected)) return false;
    }
    if (table.get(trip.real_peer_id).socket != local) return false;
    switch (call) {
        .now_fresh => {
            // Read between two kernel readings: a frozen or stale clock reads below the
            // first, a made-up one above the second.
            if (result.reading < result.clock_before or result.reading > result.clock_after) return false;
            if (result.clock_before <= before.last) return false;
            if (real.last != result.reading) return false;
            return real.inFlight() == 0 and real.submitted == 0;
        },
        .send_peer => if (!sendPeerHeld(real, before, result, remote)) return false,
        .send_queue_full => if (!queueFullHeld(real, before, result, remote)) return false,
        .now_after_max,
        .submit_execute,
        .send_free,
        .send_free_stale_socket,
        .send_out_of_range,
        .send_free_queue_full,
        .init_running,
        => unreachable, // Asserted allowed above.
    }
    if (real.inFlight() != 0 or real.completed != real.submitted) return false;
    real.deinit();
    return true;
}

/// The send control: one more submission, whose completion comes back under its id with
/// every byte sent, and the far end reads exactly those bytes.
fn sendPeerHeld(real: *Real, before: *const RealBefore, result: RealResult, remote: linux.fd_t) bool {
    assert(!armed);
    assert(before.in_flight == 0);
    if (result.queue_full) return false;
    if (real.submitted != before.submitted + 1) return false;
    if (real.last != before.last) return false;
    // `submit` hands the send to the kernel at once, unless the kernel refused for a moment.
    if (real.ring.sq_ready() != 0 and real.enters_deferred == 0) return false;
    var completions: [1]cc.io.Completion = undefined;
    if (drain(real, &completions) != 1) return false;
    if (completions[0].id != send_peer_id) return false;
    // The completion uncounted the send on its peer.
    if (real.table.get(trip.real_peer_id).sends_in_flight != 0) return false;
    const sent = switch (completions[0].result) {
        .send => |sent| sent catch return false,
        .execute, .accept => return false,
    };
    if (sent != trip.real_send_bytes.len) return false;
    // One byte of room past the message, so a send that wrote extra bytes reads longer.
    var received: [trip.real_send_bytes.len + 1]u8 = undefined;
    const rc = linux.recvfrom(remote, &received, received.len, linux.MSG.DONTWAIT, null, null);
    if (linux.errno(rc) != .SUCCESS) return false;
    return std.mem.eql(u8, received[0..rc], trip.real_send_bytes);
}

/// The queue-full control: QueueFull with the counts, the free slots, the submission queue
/// and the clock unchanged; then every send already on the ring completes once, under the
/// id it was given, with its one byte, and the far end reads exactly those bytes.
fn queueFullHeld(real: *Real, before: *const RealBefore, result: RealResult, remote: linux.fd_t) bool {
    assert(!armed);
    assert(before.in_flight == slots_max);
    if (!result.queue_full) return false;
    if (real.inFlight() != before.in_flight or real.free_count != before.free_count) return false;
    if (real.submitted != before.submitted or real.completed != before.completed) return false;
    if (real.ring.sq.sqe_tail != before.sqe_tail or real.last != before.last) return false;
    var completions: [slots_max]cc.io.Completion = undefined;
    if (drain(real, &completions) != slots_max) return false;
    var seen: [slots_max]bool = @splat(false);
    for (completions) |completion| {
        if (completion.id == 0 or completion.id > slots_max) return false;
        const index: u32 = @intCast(completion.id - 1);
        if (seen[index]) return false;
        seen[index] = true;
        const sent = switch (completion.result) {
            .send => |sent| sent catch return false,
            .execute, .accept => return false,
        };
        if (sent != 1) return false;
    }
    return farEndHolds(remote, slots_max);
}

/// Whether the far end holds exactly `count` fill bytes. One read of a buffer with room for
/// one more, so a send that wrote extra bytes reads longer; on a stream socketpair every
/// completed send's bytes are already there.
fn farEndHolds(remote: linux.fd_t, count: u32) bool {
    assert(!armed);
    assert(count > 0 and count <= slots_max);
    var received: [slots_max + 1]u8 = undefined;
    const rc = linux.recvfrom(remote, &received, received.len, linux.MSG.DONTWAIT, null, null);
    if (linux.errno(rc) != .SUCCESS) return false;
    if (rc != count) return false;
    return std.mem.allEqual(u8, received[0..count], fill_byte);
}

/// CLOCK_MONOTONIC read directly, in nanoseconds, for checking the real type's reading.
fn kernelClock() cc.io.Instant {
    var time: linux.timespec = undefined;
    const rc = linux.clock_gettime(.MONOTONIC, &time);
    // The real type reads this clock too; it stops the process when the read fails.
    assert(linux.errno(rc) == .SUCCESS);
    assert(time.sec >= 0 and time.nsec >= 0 and time.nsec < std.time.ns_per_s);
    return @as(u64, @intCast(time.sec)) * std.time.ns_per_s + @as(u64, @intCast(time.nsec));
}

/// Polls until `completions` is full or `poll_attempts_max` polls come back empty, and
/// returns how many arrived.
fn drain(real: *Real, completions: []cc.io.Completion) u32 {
    assert(!armed);
    assert(completions.len > 0 and completions.len <= slots_max);
    var count: u32 = 0;
    var empty: u32 = 0;
    var polls: u32 = 0;
    // Each poll either hands back at least one completion or counts as empty, so the loop
    // runs at most `completions.len + poll_attempts_max` times.
    while (count < completions.len and empty < poll_attempts_max) : (polls += 1) {
        assert(polls < slots_max + poll_attempts_max);
        const got = real.poll(completions[count..]);
        count += got;
        if (got > 0) continue;
        empty += 1;
        // An interrupted sleep only shortens the pause; the count of empty polls bounds
        // the loop either way.
        const pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
        _ = linux.nanosleep(&pause, null);
    }
    assert(count <= completions.len);
    assert(empty <= poll_attempts_max);
    return count;
}

const http_response = cc.live.http_response;

/// The buffer the writer writes into, and the bytes kept on each side of it in one array,
/// so a field can sit right next to the buffer without being in it.
const response_buffer_len: u32 = 96;
const response_margin: u32 = 16;
const response_storage_len: u32 = response_margin + response_buffer_len + response_margin;
/// Where in the buffer an inside field or body is placed: past the whole head a control
/// writes, so where a mutation leaves only the copy's check, the field is still intact
/// when its own copy comes and the copy's check, not a garbled field, stops the call.
const response_inside_at: u32 = 64;
/// What every byte of the array holds before a case places its fields.
const response_fill: u8 = '~';
/// The most header fields a case sends.
const response_headers_len: u32 = 3;
const response_name = "X-Case";
const response_value = "trip";
const response_body = "body";
/// What a control must write, spelled out by hand rather than built by the writer.
const response_expected = "HTTP/1.1 200 OK\r\nX-Case: trip\r\nContent-Length: 4\r\n\r\nbody";
const response_expected_empty = "HTTP/1.1 200 OK\r\nX-Case: trip\r\nContent-Length: 0\r\n\r\n";

comptime {
    assert(response_buffer_len <= cc.constants.http_response_size_max);
    // An inside field fits the buffer after the place it starts, and starts past the head.
    assert(response_inside_at >= response_expected_empty.len);
    assert(response_inside_at + response_name.len <= response_buffer_len);
    assert(response_inside_at + response_value.len <= response_buffer_len);
    assert(response_inside_at + response_body.len <= response_buffer_len);
    // The adjacent control's value and name fit before the buffer, and its body after it;
    // the straddling name has room past the buffer's end.
    assert(response_value.len + response_name.len <= response_margin);
    assert(response_body.len <= response_margin);
    assert(response_name.len - 1 <= response_margin);
    // Both controls' responses fit the buffer, with room to spare after them, so a write
    // past the response's end would show.
    assert(response_expected.len < response_buffer_len);
    assert(response_expected_empty.len < response_buffer_len);
    // The fill byte is in none of the bytes a case places, so a moved field would show.
    assert(std.mem.findScalar(u8, response_name ++ response_value ++ response_body, response_fill) == null);
}

/// Whether the writer allows `call`: the controls. The cases file says the same through
/// each case's outcome, and the comptime block at the top checks the two agree.
fn responseCallAllowed(call: trip.ResponseCall) bool {
    const allowed = switch (call) {
        .outside, .adjacent, .empty_body_inside => true,
        .body_inside,
        .body_inside_head,
        .body_straddles_start,
        .name_inside,
        .name_straddles_end,
        .value_inside,
        .name_inside_refused,
        .value_inside_refused,
        .value_inside_second_refused,
        => false,
    };
    // A control writes one plain GET response with one field: a refused field or an
    // omitted body would make its exact-output check test something other than placement.
    assert(!allowed or responseHeaderCount(call) == 1);
    assert(!allowed or call != .body_inside_head);
    return allowed;
}

/// The header fields a case sends: one, or for a `_refused` case the field (or fields) it
/// places and then the refused one.
fn responseHeaderCount(call: trip.ResponseCall) u32 {
    const count: u32 = switch (call) {
        .name_inside_refused, .value_inside_refused => 2,
        .value_inside_second_refused => 3,
        else => 1,
    };
    // A refused field ends the list, so it comes after a field the case placed.
    const refused = std.mem.endsWith(u8, @tagName(call), "_refused");
    assert(refused == (count > 1));
    assert(count <= response_headers_len);
    return count;
}

/// Places the case's body, name and value in `storage` (inside the buffer, across an edge,
/// next to it, or not at all) and returns the response that names them. `headers` holds
/// the fields.
fn responseFor(
    call: trip.ResponseCall,
    storage: *[response_storage_len]u8,
    headers: *[response_headers_len]http_response.Header,
) http_response.Response {
    assert(!armed);
    const buffer_end = response_margin + response_buffer_len;
    const inside: []u8 = storage[response_margin + response_inside_at .. buffer_end];
    const placed: u32 = if (call == .value_inside_second_refused) 1 else 0;
    headers.* = @splat(.{ .name = response_name, .value = response_value });
    const count = responseHeaderCount(call);
    // Refused: the writer sets Connection itself.
    if (count > 1) headers[count - 1] = .{ .name = "Connection", .value = "close" };
    var body: []const u8 = response_body;
    switch (call) {
        .body_inside, .body_inside_head => body = place(inside, response_body),
        // If the checks miss it, the head overwrites the body's bytes inside the buffer
        // before the body is copied; nothing checks a body's bytes, so the write returns.
        .body_straddles_start => body = place(storage[response_margin - 1 ..], response_body),
        .name_inside, .name_inside_refused => headers[0].name = place(inside, response_name),
        // On the buffer's last byte, far past the head, so the name is intact when its
        // copy comes: a straddle at the start would be garbled into a non-token by the
        // status line, and the token assertion, not an overlap check, would stop it.
        .name_straddles_end => headers[0].name = place(storage[buffer_end - 1 ..], response_name),
        .value_inside, .value_inside_refused, .value_inside_second_refused => {
            headers[placed].value = place(inside, response_value);
        },
        .outside => {},
        .adjacent => {
            const start = response_margin - response_name.len;
            headers[0].name = place(storage[start..], response_name);
            headers[0].value = place(storage[start - response_value.len ..], response_value);
            body = place(storage[buffer_end..], response_body);
        },
        .empty_body_inside => body = inside[0..0],
    }
    // Wherever they sit, the fields hold the same bytes, so only their place differs.
    assert(std.mem.eql(u8, headers[placed].name, response_name));
    assert(std.mem.eql(u8, headers[placed].value, response_value));
    assert(body.len == 0 or std.mem.eql(u8, body, response_body));
    return .{
        .status = .ok,
        .headers = headers[0..count],
        .body = body,
        .omit_body = call == .body_inside_head,
    };
}

/// Copies `bytes` to the start of `at` and returns the copy.
fn place(at: []u8, bytes: []const u8) []const u8 {
    assert(bytes.len > 0);
    assert(bytes.len <= at.len);
    @memcpy(at[0..bytes.len], bytes);
    return at[0..bytes.len];
}

/// Ends startup (the writer runs after it, and never allocates), places the case's fields,
/// and writes one response into the buffer in the middle of the array.
fn runResponseCase(startup: *cc.StartupAllocator, call: trip.ResponseCall, case: trip.Case) noreturn {
    assert(startup.bytes_live == 0);
    assert(startup.phase == .startup);
    startup.finishStartup();

    var storage: [response_storage_len]u8 = @splat(response_fill);
    var headers: [response_headers_len]http_response.Header = undefined;
    const response = responseFor(call, &storage, &headers);
    const buffer: []u8 = storage[response_margin..][0..response_buffer_len];
    const before: [response_storage_len]u8 = storage;

    child_calls_armed = child_calls;
    armed = true;
    const result = http_response.write(buffer, response);
    armed = false;

    if (case.trips) {
        std.debug.print("startup_trip: {s} returned without tripping: the check is missing\n", .{case.name});
        std.process.exit(exit_not_tripped);
    }
    if (!responseControlHeld(&storage, &before, call, result)) {
        std.debug.print("startup_trip: {s} control failed: result={any} child calls={d}\n", .{
            case.name, result, child_calls - child_calls_armed,
        });
        std.process.exit(exit_control_failed);
    }
    std.process.exit(trip.exit_finished);
}

/// A control's write must touch no allocator, return the exact response's length, put
/// exactly that response at the buffer's start, and leave every other byte of the array as
/// it was: nothing past the response's end, nothing outside the buffer, no field moved.
fn responseControlHeld(
    storage: *const [response_storage_len]u8,
    before: *const [response_storage_len]u8,
    call: trip.ResponseCall,
    result: http_response.Error!u32,
) bool {
    assert(!armed);
    assert(responseCallAllowed(call));
    if (child_calls != child_calls_armed) return false;
    const expected: []const u8 = switch (call) {
        .outside, .adjacent => response_expected,
        .empty_body_inside => response_expected_empty,
        else => unreachable, // responseCallAllowed: the comptime block admits only these.
    };
    const written = result catch return false;
    if (written != expected.len) return false;
    const end = response_margin + written;
    if (!std.mem.eql(u8, storage[response_margin..end], expected)) return false;
    if (!std.mem.eql(u8, storage[0..response_margin], before[0..response_margin])) return false;
    return std.mem.eql(u8, storage[end..], before[end..]);
}
