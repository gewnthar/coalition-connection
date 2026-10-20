//! Seeded fuzzer: `zig build fuzz -Dseed=<n>`.
//!
//! Placeholder with one target: drives BoundedQueue with random pushes and pops and checks
//! it against a trivial model after every step. Each component adds its own target as it
//! lands (parsers first). A failing seed replays exactly.

const std = @import("std");
const assert = std.debug.assert;
const cc = @import("coalition_connection");
const build_options = @import("build_options");

const capacity: u32 = 16;
const Queue = cc.BoundedQueue(u32, capacity);

/// The model: values are sequence numbers, so FIFO order means pops return them in order.
const Model = struct {
    next_push: u32 = 0,
    next_pop: u32 = 0,

    fn len(self: Model) u32 {
        assert(self.next_push >= self.next_pop);
        assert(self.next_push - self.next_pop <= capacity);
        return self.next_push - self.next_pop;
    }
};

const FuzzError = error{Mismatch};

fn step(random: std.Random, queue: *Queue, model: *Model) FuzzError!void {
    assert(queue.count() == model.len());
    assert(model.next_push >= model.next_pop);
    if (random.boolean()) {
        if (queue.push(model.next_push)) {
            model.next_push += 1;
        } else |err| switch (err) {
            error.Full => if (model.len() != capacity) return error.Mismatch,
            error.Empty => return error.Mismatch,
        }
    } else {
        if (queue.pop()) |value| {
            if (value != model.next_pop) return error.Mismatch;
            model.next_pop += 1;
        } else |err| switch (err) {
            error.Empty => if (model.len() != 0) return error.Mismatch,
            error.Full => return error.Mismatch,
        }
    }
    if (queue.count() != model.len()) return error.Mismatch;
}

pub fn main() FuzzError!void {
    const seed: u64 = build_options.seed;
    comptime assert(cc.constants.fuzz_iterations_max > 0);
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var queue: Queue = .{};
    var model: Model = .{};

    var iteration: u32 = 0;
    while (iteration < cc.constants.fuzz_iterations_max) : (iteration += 1) {
        step(random, &queue, &model) catch |err| {
            std.debug.print("fuzz bounded_queue: seed={d} failed at iteration {d}\n", .{ seed, iteration });
            return err;
        };
    }
    assert(iteration == cc.constants.fuzz_iterations_max);
    std.debug.print("fuzz bounded_queue: seed={d} iterations={d} ok\n", .{ seed, iteration });
}
