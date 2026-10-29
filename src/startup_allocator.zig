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

    /// Whether replacing `old_len` live bytes with `new_len` bytes stays within the budget.
    /// It compares `new_len` with the room left instead of adding it to `bytes_live`, so a
    /// huge request is refused instead of overflowing. Neither subtraction can wrap: the
    /// assertions give old_len <= bytes_live <= bytes_budget.
    fn fits(self: *const StartupAllocator, old_len: usize, new_len: usize) bool {
        assert(self.phase == .startup);
        assert(old_len <= self.bytes_live);
        assert(self.bytes_live <= self.bytes_budget);
        const bytes_kept: u64 = self.bytes_live - @as(u64, @intCast(old_len));
        const bytes_room: u64 = self.bytes_budget - bytes_kept;
        assert(bytes_kept + bytes_room == self.bytes_budget);
        const result = @as(u64, new_len) <= bytes_room;
        // Postcondition: a request that fits keeps the total within the budget. The sum
        // can't overflow here, because new_len <= bytes_room.
        if (result) assert(bytes_kept + @as(u64, new_len) <= self.bytes_budget);
        return result;
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

// The tests below use a FixedBufferAllocator as the child, because its resize and remap
// results are deterministic: growing works only for the last allocation, and shrinking
// always works. The backing buffer is larger than the budget, so a refusal in the
// past-the-budget tests can only come from the budget check.

test "startup allocator: resize grows and shrinks within the budget" {
    var backing: [256]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&backing);
    var startup = StartupAllocator.init(fixed.allocator(), 64);
    const gpa = startup.allocator();

    var memory = try gpa.alloc(u8, 16);
    try testing.expect(gpa.resize(memory, 48));
    memory = memory.ptr[0..48];
    try testing.expectEqual(@as(u64, 48), startup.bytes_live);

    // Growing to exactly the budget is allowed.
    try testing.expect(gpa.resize(memory, 64));
    memory = memory.ptr[0..64];
    try testing.expectEqual(@as(u64, 64), startup.bytes_live);

    try testing.expect(gpa.resize(memory, 8));
    memory = memory.ptr[0..8];
    try testing.expectEqual(@as(u64, 8), startup.bytes_live);

    gpa.free(memory);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "startup allocator: resize past the budget fails and leaves bytes_live unchanged" {
    var backing: [256]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&backing);
    var startup = StartupAllocator.init(fixed.allocator(), 64);
    const gpa = startup.allocator();

    const memory = try gpa.alloc(u8, 32);
    try testing.expect(!gpa.resize(memory, 65));
    try testing.expectEqual(@as(u64, 32), startup.bytes_live);

    // One byte past the budget, counting a second live allocation.
    const other = try gpa.alloc(u8, 32);
    try testing.expectEqual(@as(u64, 64), startup.bytes_live);
    try testing.expect(!gpa.resize(memory, 33));
    try testing.expectEqual(@as(u64, 64), startup.bytes_live);

    gpa.free(other);
    gpa.free(memory);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "startup allocator: resize the child refuses leaves bytes_live unchanged" {
    var backing: [256]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&backing);
    var startup = StartupAllocator.init(fixed.allocator(), 64);
    const gpa = startup.allocator();

    // The budget allows this growth, but the child can't grow a block that isn't its last.
    const first = try gpa.alloc(u8, 16);
    const second = try gpa.alloc(u8, 16);
    try testing.expect(!gpa.resize(first, 32));
    try testing.expectEqual(@as(u64, 32), startup.bytes_live);

    gpa.free(second);
    gpa.free(first);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "startup allocator: remap grows and shrinks within the budget" {
    var backing: [256]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&backing);
    var startup = StartupAllocator.init(fixed.allocator(), 64);
    const gpa = startup.allocator();

    var memory = try gpa.alloc(u8, 16);
    memory = gpa.remap(memory, 64) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 64), memory.len);
    try testing.expectEqual(@as(u64, 64), startup.bytes_live);

    memory = gpa.remap(memory, 8) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 8), memory.len);
    try testing.expectEqual(@as(u64, 8), startup.bytes_live);

    gpa.free(memory);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "startup allocator: remap past the budget fails and leaves bytes_live unchanged" {
    var backing: [256]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&backing);
    var startup = StartupAllocator.init(fixed.allocator(), 64);
    const gpa = startup.allocator();

    const memory = try gpa.alloc(u8, 32);
    try testing.expect(gpa.remap(memory, 65) == null);
    try testing.expectEqual(@as(u64, 32), startup.bytes_live);

    // The child refuses too: a block that isn't its last can't grow.
    const other = try gpa.alloc(u8, 16);
    try testing.expect(gpa.remap(memory, 48) == null);
    try testing.expectEqual(@as(u64, 48), startup.bytes_live);

    gpa.free(other);
    gpa.free(memory);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

// The three tests below ask for std.math.maxInt(usize) bytes. While other bytes are live,
// adding that to bytes_live overflows u64 on a 64-bit target, so each test checks that the
// budget check refuses the request with a normal failure instead of panicking. (On a
// 32-bit target the sum fits in u64, so there they only check the refusal.) The allocation
// test also asks once with nothing live, the zero edge case.

test "startup allocator: a huge allocation returns OutOfMemory and leaves bytes_live unchanged" {
    var startup = StartupAllocator.init(testing.allocator, 64);
    const gpa = startup.allocator();

    const live = try gpa.alloc(u8, 16);
    try testing.expectError(error.OutOfMemory, gpa.alloc(u8, std.math.maxInt(usize)));
    try testing.expectEqual(@as(u64, 16), startup.bytes_live);

    gpa.free(live);
    try testing.expectError(error.OutOfMemory, gpa.alloc(u8, std.math.maxInt(usize)));
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "startup allocator: a huge resize fails and leaves bytes_live unchanged" {
    var backing: [256]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&backing);
    var startup = StartupAllocator.init(fixed.allocator(), 64);
    const gpa = startup.allocator();

    // Two live blocks, so bytes_live is above the resized block's own length.
    const memory = try gpa.alloc(u8, 16);
    const other = try gpa.alloc(u8, 16);
    try testing.expect(!gpa.resize(memory, std.math.maxInt(usize)));
    try testing.expectEqual(@as(u64, 32), startup.bytes_live);
    try testing.expect(!gpa.resize(other, std.math.maxInt(usize)));
    try testing.expectEqual(@as(u64, 32), startup.bytes_live);

    gpa.free(other);
    gpa.free(memory);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "startup allocator: a huge remap fails and leaves bytes_live unchanged" {
    var backing: [256]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&backing);
    var startup = StartupAllocator.init(fixed.allocator(), 64);
    const gpa = startup.allocator();

    const memory = try gpa.alloc(u8, 16);
    const other = try gpa.alloc(u8, 16);
    try testing.expect(gpa.remap(memory, std.math.maxInt(usize)) == null);
    try testing.expectEqual(@as(u64, 32), startup.bytes_live);
    try testing.expect(gpa.remap(other, std.math.maxInt(usize)) == null);
    try testing.expectEqual(@as(u64, 32), startup.bytes_live);

    gpa.free(other);
    gpa.free(memory);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "startup allocator: growth to exactly the room left beside another live block" {
    var backing: [256]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&backing);
    var startup = StartupAllocator.init(fixed.allocator(), 64);
    const gpa = startup.allocator();

    // 16 bytes stay live, so the last block may grow to 48 and no further.
    const first = try gpa.alloc(u8, 16);
    var last = try gpa.alloc(u8, 16);
    try testing.expect(!gpa.resize(last, 49));
    try testing.expectEqual(@as(u64, 32), startup.bytes_live);
    try testing.expect(gpa.resize(last, 48));
    last = last.ptr[0..48];
    try testing.expectEqual(@as(u64, 64), startup.bytes_live);

    gpa.free(last);
    gpa.free(first);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}
