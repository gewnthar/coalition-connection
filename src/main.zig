//! The server program, installed by `zig build` as `zig-out/bin/coalition-connection`.
//!
//! Job: start the process in the order every later component follows: size memory through
//! the startup allocator, end startup, then run. For now there is nothing to run yet, so it
//! prints its name and version and exits 0; components join here as they land.
//!
//! Inputs: none yet. Outputs: one line on stdout, `coalition-connection <version>`.
//! Limits: no allocation after startup (the startup allocator enforces it); at most
//! `write_attempts_max` write calls for the version line.
//!
//! This root file must never declare `io_simulation`: the simulator (src/io/sim.zig)
//! compiles into any program whose root declares it, and its seeded random bytes would make
//! every token predictable. The comptime block below refuses such a build.
//!
//! Linux only: the event loop is io_uring.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const linux = std.os.linux;
const cc = @import("coalition_connection");
const build_options = @import("build_options");

const version_line = "coalition-connection " ++ build_options.version ++ "\n";

/// Longest version line. Reason: a semantic version with a short pre-release tag fits in
/// well under 64 bytes, and one bounded line keeps the write to a single call in practice.
const version_line_max: u32 = 64;

/// write calls one line may take. Reason: a write to a pipe or terminal is normally whole
/// in one call; a signal or a short write costs a retry, and the bound stops a full,
/// non-blocking stdout from spinning (there is no waiting here, only retries).
const write_attempts_max: u32 = 8;

comptime {
    // `@hasDecl` sees only `pub` declarations, and the simulator checks with `@hasDecl`
    // too, so this catches every declaration that would let it in.
    if (@hasDecl(@This(), "io_simulation")) {
        @compileError("the server's root file must not declare io_simulation: " ++
            "io.sim.Sim would compile into production");
    }
    if (builtin.target.os.tag != .linux) {
        @compileError("the server runs on Linux only (io_uring, CLOCK_MONOTONIC, getrandom)");
    }
    assert(version_line.len > "coalition-connection \n".len);
    assert(version_line.len <= version_line_max);
}

pub const MainError = error{StdoutUnavailable};

pub fn main() MainError!void {
    var startup: cc.StartupAllocator = .init(std.heap.page_allocator, cc.constants.memory_budget_bytes);
    assert(startup.allocationAllowed());
    // Components size their buffers here, from constants.zig, before startup ends.
    startup.finishStartup();
    assert(!startup.allocationAllowed());

    const written = writeAll(linux.STDOUT_FILENO, version_line);

    // Shutdown runs on the error path too, so every later component releases in order.
    startup.beginShutdown();
    assert(startup.bytes_live == 0);
    return written;
}

/// Writes all of `bytes` to `fd`, or returns `error.StdoutUnavailable` when the descriptor
/// is closed, broken or stays full.
fn writeAll(fd: linux.fd_t, bytes: []const u8) MainError!void {
    assert(fd >= 0);
    assert(bytes.len > 0 and bytes.len <= version_line_max);
    var written: u32 = 0;
    var attempts: u32 = 0;
    while (written < bytes.len and attempts < write_attempts_max) {
        attempts += 1;
        const rest = bytes[written..];
        const rc = linux.write(fd, rest.ptr, rest.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                // write never reports more bytes than it was given.
                assert(rc <= rest.len);
                written += @intCast(rc);
            },
            // A signal arrived, or the descriptor is non-blocking and full: retry within
            // the bound.
            .INTR, .AGAIN => {},
            // EBADF (closed), EIO, ENOSPC and the rest: there is nowhere to report the
            // version, so the program fails. EPIPE lands here only when SIGPIPE is ignored;
            // by default the kernel ends the process with SIGPIPE when the reader is gone.
            else => return error.StdoutUnavailable,
        }
    }
    assert(attempts <= write_attempts_max);
    assert(written <= bytes.len);
    if (written < bytes.len) return error.StdoutUnavailable;
}

const testing = std.testing;

test "main: writeAll delivers the whole line through a pipe" {
    var fds: [2]linux.fd_t = undefined;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })));
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);

    try writeAll(fds[1], version_line);
    var buffer: [version_line_max]u8 = undefined;
    const rc = linux.read(fds[0], &buffer, buffer.len);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    try testing.expectEqualStrings(version_line, buffer[0..rc]);
}

test "main: writeAll to a closed descriptor fails with StdoutUnavailable" {
    var fds: [2]linux.fd_t = undefined;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })));
    _ = linux.close(fds[0]);
    // Closed: the write end's number is no longer a valid descriptor.
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.close(fds[1])));
    try testing.expectError(error.StdoutUnavailable, writeAll(fds[1], version_line));
}

test "main: the version line names the program and ends in a newline" {
    try testing.expect(std.mem.startsWith(u8, version_line, "coalition-connection "));
    try testing.expect(std.mem.endsWith(u8, version_line, "\n"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, version_line, "\n"));
}
