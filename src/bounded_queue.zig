//! Fixed-capacity FIFO ring buffer. Never allocates; every operation is O(1).

const std = @import("std");
const assert = std.debug.assert;

pub fn BoundedQueue(comptime T: type, comptime capacity: u32) type {
    comptime assert(capacity > 0);

    return struct {
        const Self = @This();

        items: [capacity]T = undefined,
        head: u32 = 0,
        len: u32 = 0,

        pub const Error = error{ Full, Empty };

        fn invariant(self: *const Self) void {
            assert(self.head < capacity);
            assert(self.len <= capacity);
        }

        pub fn push(self: *Self, item: T) Error!void {
            self.invariant();
            if (self.len == capacity) return error.Full;
            const tail = (self.head + self.len) % capacity;
            self.items[tail] = item;
            self.len += 1;
            self.invariant();
        }

        pub fn pop(self: *Self) Error!T {
            self.invariant();
            if (self.len == 0) return error.Empty;
            const item = self.items[self.head];
            self.head = (self.head + 1) % capacity;
            self.len -= 1;
            self.invariant();
            return item;
        }

        pub fn count(self: *const Self) u32 {
            self.invariant();
            return self.len;
        }
    };
}

test "fifo order and wraparound" {
    var q: BoundedQueue(u8, 3) = .{};
    try q.push(1);
    try q.push(2);
    try q.push(3);
    try std.testing.expectError(error.Full, q.push(4));
    try std.testing.expectEqual(@as(u8, 1), try q.pop());
    try q.push(4);
    try std.testing.expectEqual(@as(u32, 3), q.count());
    try std.testing.expectEqual(@as(u8, 2), try q.pop());
    try std.testing.expectEqual(@as(u8, 3), try q.pop());
    try std.testing.expectEqual(@as(u8, 4), try q.pop());
    try std.testing.expectError(error.Empty, q.pop());
}
