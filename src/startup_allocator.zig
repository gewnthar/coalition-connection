//! Startup-only allocator: enforces "no memory allocation after startup".
//!
//! Job: wrap the process allocator and allow allocation only while the program starts.
//! Once `finishStartup` is called, any allocate, resize or free trips an assertion, so a
//! hidden allocation on the hot path crashes in tests and ReleaseSafe builds instead of
//! slowly fragmenting memory. `beginShutdown` allows frees again so memory can be
//! released in order at exit.
//!
//! Inputs: a child allocator and a byte budget (at most `constants.memory_budget_bytes`).
//! Outputs: a `std.mem.Allocator` for startup code.
//! Limits: total live bytes never exceed the budget; allocation past it returns
//! `error.OutOfMemory`, which startup must handle by refusing to start.
//!
//! The vtable below is one of the few reviewed function-pointer sites: the standard
//! allocator interface requires it. Its `usize` parameters are also set by that interface.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

pub const StartupAllocator = struct {
    child: std.mem.Allocator,
    phase: Phase,
    bytes_budget: u64,
    bytes_live: u64,

    pub const Phase = enum(u8) { startup, running, shutdown };

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    pub fn init(child: std.mem.Allocator, bytes_budget: u64) StartupAllocator {
        assert(bytes_budget > 0);
        assert(bytes_budget <= constants.memory_budget_bytes);
        return .{ .child = child, .phase = .startup, .bytes_budget = bytes_budget, .bytes_live = 0 };
    }

    pub fn allocator(self: *StartupAllocator) std.mem.Allocator {
        assert(self.phase == .startup);
        assert(self.bytes_live <= self.bytes_budget);
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// Ends startup. From here on, every allocation or free is a bug.
    pub fn finishStartup(self: *StartupAllocator) void {
        assert(self.phase == .startup);
        assert(self.bytes_live <= self.bytes_budget);
        self.phase = .running;
    }

    /// Starts shutdown. Frees are allowed again; allocations are not.
    pub fn beginShutdown(self: *StartupAllocator) void {
        assert(self.phase == .running);
        assert(self.bytes_live <= self.bytes_budget);
        self.phase = .shutdown;
    }

    pub fn allocationAllowed(self: *const StartupAllocator) bool {
        assert(self.bytes_live <= self.bytes_budget);
        assert(self.bytes_budget > 0);
        return self.phase == .startup;
    }

    fn fromContext(context: *anyopaque) *StartupAllocator {
        const self: *StartupAllocator = @ptrCast(@alignCast(context));
        assert(self.bytes_live <= self.bytes_budget);
        assert(self.bytes_budget <= constants.memory_budget_bytes);
        return self;
    }

    fn fits(self: *const StartupAllocator, old_len: usize, new_len: usize) bool {
        assert(self.phase == .startup);
        assert(old_len <= self.bytes_live);
        const after = self.bytes_live - @as(u64, @intCast(old_len)) + @as(u64, @intCast(new_len));
        return after <= self.bytes_budget;
    }

    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self = fromContext(context);
        assert(self.phase == .startup); // Allocation after startup.
        if (!self.fits(0, len)) return null;
        const result = self.child.rawAlloc(len, alignment, ret_addr) orelse return null;
        self.bytes_live += @as(u64, @intCast(len));
        assert(self.bytes_live <= self.bytes_budget);
        return result;
    }

    fn resize(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self = fromContext(context);
        assert(self.phase == .startup); // Resize after startup.
        if (!self.fits(memory.len, new_len)) return false;
        if (!self.child.rawResize(memory, alignment, new_len, ret_addr)) return false;
        self.bytes_live = self.bytes_live - @as(u64, @intCast(memory.len)) + @as(u64, @intCast(new_len));
        assert(self.bytes_live <= self.bytes_budget);
        return true;
    }

    fn remap(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self = fromContext(context);
        assert(self.phase == .startup); // Remap after startup.
        if (!self.fits(memory.len, new_len)) return null;
        const result = self.child.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;
        self.bytes_live = self.bytes_live - @as(u64, @intCast(memory.len)) + @as(u64, @intCast(new_len));
        assert(self.bytes_live <= self.bytes_budget);
        return result;
    }

    fn free(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self = fromContext(context);
        assert(self.phase != .running); // Free while running.
        assert(memory.len <= self.bytes_live);
        self.child.rawFree(memory, alignment, ret_addr);
        self.bytes_live -= @as(u64, @intCast(memory.len));
    }
};

const testing = std.testing;

test "startup allocator: allocates at startup and frees at shutdown" {
    var startup = StartupAllocator.init(testing.allocator, 4096);
    const gpa = startup.allocator();
    const buffer = try gpa.alloc(u8, 100);
    try testing.expectEqual(@as(u64, 100), startup.bytes_live);
    try testing.expect(startup.allocationAllowed());

    startup.finishStartup();
    try testing.expect(!startup.allocationAllowed());
    try testing.expectEqual(StartupAllocator.Phase.running, startup.phase);

    startup.beginShutdown();
    gpa.free(buffer);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "startup allocator: refuses allocations past the budget" {
    var startup = StartupAllocator.init(testing.allocator, 64);
    const gpa = startup.allocator();
    try testing.expectError(error.OutOfMemory, gpa.alloc(u8, 65));
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);

    const exact = try gpa.alloc(u8, 64);
    try testing.expectError(error.OutOfMemory, gpa.alloc(u8, 1));
    gpa.free(exact);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "startup allocator: phases move forward only" {
    var startup = StartupAllocator.init(testing.allocator, 64);
    try testing.expectEqual(StartupAllocator.Phase.startup, startup.phase);
    startup.finishStartup();
    try testing.expectEqual(StartupAllocator.Phase.running, startup.phase);
    startup.beginShutdown();
    try testing.expectEqual(StartupAllocator.Phase.shutdown, startup.phase);
    try testing.expect(!startup.allocationAllowed());
}
