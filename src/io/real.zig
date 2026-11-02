//! The real I/O type, for Linux: the monotonic clock and the kernel's random source.
//!
//! Job: give production code a clock and random bytes from the operating system, with the
//! same method signatures the I/O contract (`root.zig`) asks for. It does not meet the whole
//! contract yet: `submit` and `poll` arrive with the io_uring ring, and until then
//! `assertContract` refuses this type (a test below checks that), so no component can take
//! it as its `IO`.
//!
//! Clock: `CLOCK_MONOTONIC`, read as u64 nanoseconds. The kernel promises it never goes
//! backwards. `now` asserts that each reading is at or after the reading taken in `init`;
//! the contract's `now` takes `*const`, so it has nowhere to keep the previous reading, and
//! checking each reading against the last one needs a contract change.
//!
//! Random bytes: `getrandom(2)` with no flags, so it blocks only until the kernel's pool is
//! first seeded at boot and never returns weaker bytes. An interrupted or short read is
//! retried, at most `constants.io_random_attempts_max` getrandom calls per draw. When the
//! kernel can't supply the bytes, the call returns `error.RandomUnavailable` and zeroes the
//! buffer, so a partly filled buffer can't be mistaken for a random one. There is no
//! fallback source.
//!
//! Inputs: buffers to fill. Outputs: time readings and random bytes.
//! Limits: 1 to `constants.io_random_bytes_max` random bytes per call; at most
//! `constants.io_random_attempts_max` getrandom calls per `randomBytes`.
//!
//! Linux only: each method refuses to compile for another operating system.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const linux = std.os.linux;
const constants = @import("../constants.zig");
const io = @import("root.zig");

const ns_per_s: u64 = std.time.ns_per_s;

/// Largest whole-second count whose every nanosecond still fits a u64 reading:
/// seconds * ns_per_s + (ns_per_s - 1) <= maxInt(u64). About 584 years of uptime.
const clock_seconds_max: u64 = (std.math.maxInt(u64) - (ns_per_s - 1)) / ns_per_s;

comptime {
    // Recomputed for the guard in `nanoseconds`: the largest reading fits, one more second
    // would not.
    assert(clock_seconds_max * ns_per_s + (ns_per_s - 1) <= std.math.maxInt(u64));
    assert(@as(u128, clock_seconds_max + 1) * ns_per_s + (ns_per_s - 1) > std.math.maxInt(u64));
}

pub const Real = struct {
    /// The clock reading taken at startup. Every later reading is at or after it.
    epoch: io.Instant,
    /// Random bytes handed out so far, for tests and metrics.
    random_bytes: u64,

    pub fn init() Real {
        comptime assertLinux();
        const result: Real = .{ .epoch = monotonicNow(), .random_bytes = 0 };
        // The monotonic clock counts from boot, so a running process never reads zero.
        assert(result.epoch > 0);
        assert(result.epoch <= monotonicNow());
        return result;
    }

    /// Nanoseconds on `CLOCK_MONOTONIC`.
    pub fn now(self: *const Real) io.Instant {
        comptime assertLinux();
        assert(self.epoch > 0);
        const reading = monotonicNow();
        // CLOCK_MONOTONIC never goes backwards; a reading before startup means the clock
        // or this type is broken, and no timeout computed from it can be trusted.
        assert(reading >= self.epoch);
        return reading;
    }

    /// Fills `buffer` from the kernel's CSPRNG, or returns `error.RandomUnavailable` with
    /// `buffer` zeroed.
    pub fn randomBytes(self: *Real, buffer: []u8) io.RandomError!void {
        comptime assertLinux();
        assert(buffer.len > 0);
        assert(buffer.len <= constants.io_random_bytes_max);
        const before = self.random_bytes;
        var kernel: Kernel = .{};
        try fill(Kernel, &kernel, buffer);
        self.random_bytes += buffer.len;
        assert(self.random_bytes == before + buffer.len);
    }
};

/// Reads `CLOCK_MONOTONIC` as nanoseconds.
fn monotonicNow() io.Instant {
    var time: linux.timespec = undefined;
    const rc = linux.clock_gettime(.MONOTONIC, &time);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        // CLOCK_MONOTONIC exists on every kernel this program supports and `time` is a
        // valid stack address, so a failure means the system is unusable. The contract's
        // `now` has no error, and running on without a clock would break every timeout, so
        // the process stops here with the reason, in every build mode.
        else => |err| std.debug.panic("clock_gettime(CLOCK_MONOTONIC) failed: {t}", .{err}),
    }
    assert(rc == 0);
    // Widened to i64: `timespec` holds isize on most targets and i64 on a few 32-bit ones.
    const result = nanoseconds(time.sec, time.nsec);
    assert(result > 0);
    return result;
}

/// Converts a kernel reading to nanoseconds. Asserts it is a valid monotonic reading.
fn nanoseconds(sec: i64, nsec: i64) io.Instant {
    assert(sec >= 0);
    assert(nsec >= 0 and nsec < ns_per_s);
    const seconds: u64 = @intCast(sec);
    assert(seconds <= clock_seconds_max);
    const result = seconds * ns_per_s + @as(u64, @intCast(nsec));
    assert(result / ns_per_s == seconds);
    return result;
}

/// What one getrandom call means for the loop in `fill`.
const Step = enum(u8) {
    /// Some bytes arrived; keep going.
    progress,
    /// Interrupted by a signal before any byte arrived; try again within the bound.
    retry,
    /// The kernel can't supply random bytes.
    unavailable,
};

/// Maps getrandom's errno to a step. Every errno has an explicit outcome.
fn classify(err: linux.E) Step {
    const step: Step = switch (err) {
        .SUCCESS => .progress,
        .INTR => .retry,
        // The caller's buffer is a valid slice and the flags are 0, so these mean a bug in
        // this file; the process stops with the reason, in every build mode.
        .FAULT, .INVAL => std.debug.panic("getrandom: bad arguments ({t})", .{err}),
        // ENOSYS (no getrandom), EPERM (blocked by a seccomp filter), EAGAIN (only possible
        // with GRND_NONBLOCK, which isn't passed, so something is wrong) and anything newer.
        else => .unavailable,
    };
    assert(step != .progress or err == .SUCCESS);
    assert(step != .retry or err == .INTR);
    return step;
}

/// The kernel's getrandom, as the source `randomBytes` passes to `fill`.
const Kernel = struct {
    pub fn getrandom(self: *Kernel, buf: [*]u8, count: usize, flags: u32) usize {
        _ = self;
        assert(count > 0);
        assert(flags == 0);
        return linux.getrandom(buf, count, flags);
    }
};

/// Fills `buffer` from `source.getrandom`, which returns what the getrandom syscall
/// returns. Production passes `Kernel`; tests pass stand-ins that fail or read short on
/// purpose. Zeroes `buffer` on failure. A success of 0 bytes uses up an attempt.
fn fill(comptime Source: type, source: *Source, buffer: []u8) io.RandomError!void {
    assert(buffer.len > 0);
    assert(buffer.len <= constants.io_random_bytes_max);
    var filled: u32 = 0;
    var attempts: u32 = 0;
    while (filled < buffer.len and attempts < constants.io_random_attempts_max) {
        attempts += 1;
        const remaining = buffer[filled..];
        const rc = source.getrandom(remaining.ptr, remaining.len, 0);
        switch (classify(linux.errno(rc))) {
            .progress => {
                // getrandom never reports more bytes than it was asked for, and the request
                // is at most io_random_bytes_max, so the count fits a u32.
                assert(rc <= remaining.len);
                filled += @intCast(rc);
            },
            .retry => {},
            .unavailable => break,
        }
    }
    assert(attempts <= constants.io_random_attempts_max);
    assert(filled <= buffer.len);
    if (filled < buffer.len) {
        std.crypto.secureZero(u8, buffer);
        return error.RandomUnavailable;
    }
}

/// Stops the build when the real I/O type is used for an operating system other than
/// Linux. A function body is analyzed only when something calls it, so the check sits in
/// each method.
fn assertLinux() void {
    comptime {
        if (builtin.target.os.tag != .linux) {
            @compileError("io.real.Real needs Linux (CLOCK_MONOTONIC, getrandom, io_uring)");
        }
        assert(builtin.target.os.tag == .linux);
    }
}

const testing = std.testing;

/// Readings taken by the clock test. Reason: enough to see many distinct readings, few
/// enough to finish in milliseconds even in a Debug build.
const clock_readings_max: u32 = 10_000;

test "real: a later clock reading is never below an earlier one" {
    const real = Real.init();
    var previous = real.now();
    try testing.expect(previous >= real.epoch);
    var count: u32 = 0;
    while (count < clock_readings_max) : (count += 1) {
        const reading = real.now();
        try testing.expect(reading >= previous);
        previous = reading;
    }
    try testing.expectEqual(clock_readings_max, count);
}

test "real: kernel readings convert to nanoseconds" {
    try testing.expectEqual(@as(u64, 0), nanoseconds(0, 0));
    try testing.expectEqual(@as(u64, 1_999_999_999), nanoseconds(1, 999_999_999));
    try testing.expectEqual(@as(u64, 3 * ns_per_s + 7), nanoseconds(3, 7));
    // The largest reading the guard admits: its last nanosecond still fits a u64.
    const largest: i64 = @intCast(clock_seconds_max);
    const expected = clock_seconds_max * ns_per_s + (ns_per_s - 1);
    try testing.expectEqual(expected, nanoseconds(largest, ns_per_s - 1));
}

test "real: randomBytes fills 1-byte and 64-byte buffers" {
    var real = Real.init();
    var one: [1]u8 = undefined;
    try real.randomBytes(&one);
    try testing.expectEqual(@as(u64, 1), real.random_bytes);

    // All zero after a fill has odds of 2^-512; it would mean nothing was written.
    var large: [constants.io_random_bytes_max]u8 = @splat(0);
    try real.randomBytes(&large);
    try testing.expect(!std.mem.allEqual(u8, &large, 0));
    try testing.expectEqual(@as(u64, 1 + constants.io_random_bytes_max), real.random_bytes);
}

test "real: two 32-byte draws differ" {
    var real = Real.init();
    var first: [32]u8 = undefined;
    var second: [32]u8 = undefined;
    try real.randomBytes(&first);
    try real.randomBytes(&second);
    // Equal draws have odds of 2^-256.
    try testing.expect(!std.mem.eql(u8, &first, &second));
    try testing.expectEqual(@as(u64, 64), real.random_bytes);
}

test "real: the type doesn't claim the contract before submit and poll exist" {
    const message = comptime io.contractError(Real);
    try testing.expect(message != null);
    try testing.expect(std.mem.indexOf(u8, message.?, "submit") != null);
}

/// Returns `-errno` the way a raw syscall does.
fn syscallError(err: linux.E) usize {
    assert(err != .SUCCESS);
    const result: usize = @bitCast(-@as(isize, @backingInt(err)));
    assert(linux.errno(result) == err);
    return result;
}

/// A scripted getrandom: each call takes the next entry of `script`. A positive entry
/// writes that many 0xAB bytes; an errno entry fails with it. Counts its calls.
const Scripted = struct {
    const Entry = union(enum) { bytes: u32, fails: linux.E };

    script: []const Entry,
    calls: u32 = 0,

    pub fn getrandom(self: *Scripted, buf: [*]u8, count: usize, flags: u32) usize {
        assert(count > 0);
        assert(flags == 0);
        assert(self.calls < self.script.len);
        const entry = self.script[self.calls];
        self.calls += 1;
        buf[0] = 0xFF; // Scribbles, so a test can see the buffer is zeroed after a failure.
        switch (entry) {
            .bytes => |bytes| {
                assert(bytes <= count);
                @memset(buf[0..bytes], 0xAB);
                return bytes;
            },
            .fails => |err| return syscallError(err),
        }
    }
};

test "real: short reads are resumed until the buffer is full" {
    var source: Scripted = .{ .script = &.{ .{ .bytes = 1 }, .{ .bytes = 2 }, .{ .bytes = 1 } } };
    var buffer: [4]u8 = @splat(0);
    try fill(Scripted, &source, &buffer);
    try testing.expectEqualSlices(u8, &.{ 0xAB, 0xAB, 0xAB, 0xAB }, &buffer);
    try testing.expectEqual(@as(u32, 3), source.calls);
}

test "real: an interrupted read is retried and then succeeds" {
    var source: Scripted = .{ .script = &.{ .{ .fails = .INTR }, .{ .bytes = 8 } } };
    var buffer: [8]u8 = @splat(0);
    try fill(Scripted, &source, &buffer);
    try testing.expect(std.mem.allEqual(u8, &buffer, 0xAB));
    try testing.expectEqual(@as(u32, 2), source.calls);
}

test "real: reads short past the attempt bound fail and zero the buffer" {
    const script: [constants.io_random_attempts_max]Scripted.Entry = @splat(.{ .bytes = 1 });
    var source: Scripted = .{ .script = &script };
    var buffer: [constants.io_random_attempts_max + 1]u8 = @splat(0x11);
    try testing.expectError(error.RandomUnavailable, fill(Scripted, &source, &buffer));
    try testing.expect(std.mem.allEqual(u8, &buffer, 0));
    try testing.expectEqual(constants.io_random_attempts_max, source.calls);
}

test "real: an always-interrupted source fails after exactly the bound" {
    const script: [constants.io_random_attempts_max]Scripted.Entry = @splat(.{ .fails = .INTR });
    var source: Scripted = .{ .script = &script };
    var buffer: [32]u8 = @splat(0x22);
    try testing.expectError(error.RandomUnavailable, fill(Scripted, &source, &buffer));
    try testing.expect(std.mem.allEqual(u8, &buffer, 0));
    try testing.expectEqual(constants.io_random_attempts_max, source.calls);
}

test "real: a source that fails partway leaves no partial bytes" {
    var source: Scripted = .{ .script = &.{ .{ .bytes = 16 }, .{ .fails = .NOSYS } } };
    var buffer: [32]u8 = @splat(0x33);
    try testing.expectError(error.RandomUnavailable, fill(Scripted, &source, &buffer));
    try testing.expect(std.mem.allEqual(u8, &buffer, 0));
    try testing.expectEqual(@as(u32, 2), source.calls);
}

test "real: every getrandom errno has an outcome" {
    try testing.expectEqual(Step.progress, classify(.SUCCESS));
    try testing.expectEqual(Step.retry, classify(.INTR));
    try testing.expectEqual(Step.unavailable, classify(.AGAIN));
    try testing.expectEqual(Step.unavailable, classify(.NOSYS));
    try testing.expectEqual(Step.unavailable, classify(.PERM));
    try testing.expectEqual(Step.unavailable, classify(.NOMEM));
}
