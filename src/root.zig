//! Coalition Connection core.
//! Rules: safety over speed; no dynamic allocation; all loops bounded;
//! small functions; assertions on preconditions/postconditions
//! (NASA Power of Ten, TigerBeetle Tiger Style).

pub const BoundedQueue = @import("bounded_queue.zig").BoundedQueue;

test {
    _ = @import("bounded_queue.zig");
}
