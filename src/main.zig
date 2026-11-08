//! The server program, installed by `zig build` as `zig-out/bin/coalition-connection`.
//!
//! Job: start the process in the order every later component follows: read the config,
//! size memory through the startup allocator, end startup, then run. For now there is
//! nothing to run yet, so once the config checks out it prints its name and version and
//! exits 0; components join here as they land.
//!
//! Inputs: one command-line argument, the path of the config file, which src/config.zig
//! reads and checks: `coalition-connection <config file>`. The server takes no options yet,
//! so an argument starting with `-` is refused rather than read as a path.
//!
//! Outputs: one line on stdout, `coalition-connection <version>`, and exit status 0. A bad
//! command line logs the usage on stderr and exits 2. A config the server refuses, or a
//! version line it can't write, logs why on stderr and exits 1, with nothing on stdout.
//!
//! Limits: no allocation after startup (the startup allocator enforces it); a config path
//! of at most `config_file_path_max` bytes; at most `write_attempts_max` write calls for the
//! version line.
//!
//! The server's I/O type is `io.real.Real`, the io_uring ring, checked against the I/O
//! contract at compile time. It isn't started yet: the listener and the event loop arrive
//! with roadmap core 3.
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

/// The I/O type every component in the server is built with: the real one. The comptime
/// block below checks it meets the I/O contract. Once components take `IO` (roadmap core
/// 3), this is the one place that picks it.
pub const IO = cc.io.real.Real;

/// Longest version line. Reason: a semantic version with a short pre-release tag fits in
/// well under 64 bytes, and one bounded line keeps the write to a single call in practice.
const version_line_max: u32 = 64;

/// write calls one line may take. Reason: a write to a pipe or terminal is normally whole
/// in one call; a signal or a short write costs a retry, and the bound stops a full,
/// non-blocking stdout from spinning (there is no waiting here, only retries).
const write_attempts_max: u32 = 8;

/// Exit status of a start that got through startup and printed the version line.
const exit_success: u8 = 0;

/// Exit status when the config is refused or the version line can't be written. Reason:
/// one status for "the server would not start", apart from a bad command line.
const exit_failure: u8 = 1;

/// Exit status for a command line the server doesn't accept. Reason: 2 is the usual status
/// for a usage error, so a supervisor or a script can tell it from a refused config.
const exit_usage: u8 = 2;

const config_path_max = cc.constants.config_file_path_max;

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
    cc.io.assertContract(IO);
    assert(version_line.len > "coalition-connection \n".len);
    assert(version_line.len <= version_line_max);
    assert(config_path_max > 0);
    assert(exit_success != exit_failure and exit_failure != exit_usage);
}

pub const UsageError = error{
    /// Not exactly one argument after the program's name.
    ArgumentCount,
    /// The argument is the empty string.
    PathEmpty,
    /// The argument starts with `-`: the server takes no options yet.
    PathIsOption,
    /// The argument is longer than `config_file_path_max` bytes.
    PathTooLong,
};

pub const MainError = error{StdoutUnavailable};

/// Everything that stops a start after the command line: a config the server refuses, or
/// a version line it can't write.
pub const RunError = cc.config.LoadError || MainError;

pub fn main(init: std.process.Init.Minimal) u8 {
    const config_path = configPath(init.args) catch |err| {
        std.log.err("usage: coalition-connection <config file> ({t})", .{err});
        return exit_usage;
    };
    assert(config_path.len > 0);
    assert(config_path.len <= config_path_max);
    // run logs each error where it happens, with what it was doing.
    run(config_path) catch return exit_failure;
    return exit_success;
}

/// The config file's path: the one argument after the program's name. The scan for the
/// argument's end reads at most `config_file_path_max + 1` bytes, all inside the argument,
/// since it stops at the first NUL.
fn configPath(arguments: std.process.Args) UsageError![:0]const u8 {
    const vector = arguments.vector;
    if (vector.len != 2) return error.ArgumentCount;
    const argument = vector[1];
    var len: u32 = 0;
    while (len <= config_path_max and argument[len] != 0) : (len += 1) {}
    assert(len <= config_path_max + 1);
    if (len > config_path_max) return error.PathTooLong;
    if (len == 0) return error.PathEmpty;
    if (argument[0] == '-') return error.PathIsOption;
    const path = argument[0..len :0];
    assert(path.len == len);
    assert(path[0] != '-');
    return path;
}

/// Reads and checks the config at `config_path`, then runs startup in order. For now that
/// ends with the version line.
fn run(config_path: [:0]const u8) RunError!void {
    assert(config_path.len > 0);
    var startup: cc.StartupAllocator = .init(std.heap.page_allocator, cc.constants.memory_budget_bytes);
    assert(startup.allocationAllowed());
    // load frees its file buffer and parse scratch before it returns, so startup keeps only
    // the config value itself.
    const config = cc.config.load(startup.allocator(), config_path) catch |err| {
        // load logs a syntax error itself, by line and column, never the file's text.
        if (err != error.ConfigSyntax) std.log.err("config {s}: {t}", .{ config_path, err });
        assert(startup.bytes_live == 0);
        return err;
    };
    assert(startup.bytes_live == 0);
    assert(config.connections_max > 0);
    assert(config.connections_max <= cc.constants.http_connections_max);
    // Components size their buffers here, from constants.zig and the config, before
    // startup ends.
    startup.finishStartup();
    assert(!startup.allocationAllowed());

    const written = writeAll(linux.STDOUT_FILENO, version_line);
    written catch |err| std.log.err("version line: {t}", .{err});

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

const program = "coalition-connection";

test "main: the config path is the one argument after the program's name" {
    const absolute = [_][*:0]const u8{ program, "/etc/coalition-connection/config.zon" };
    const path = try configPath(.{ .vector = &absolute });
    try testing.expectEqualStrings("/etc/coalition-connection/config.zon", path);
    try testing.expectEqual(@as(u8, 0), path[path.len]);
    // A relative path resolves against the working directory, which is the caller's choice.
    const relative = [_][*:0]const u8{ program, "config.zon" };
    try testing.expectEqualStrings("config.zon", try configPath(.{ .vector = &relative }));
    // A dash anywhere but first is part of the path.
    const dashed = [_][*:0]const u8{ program, "/etc/coalition-connection/-config.zon" };
    const dashed_path = try configPath(.{ .vector = &dashed });
    try testing.expectEqualStrings("/etc/coalition-connection/-config.zon", dashed_path);
}

test "main: no argument, or more than one, is ArgumentCount" {
    const empty_vector = [_][*:0]const u8{};
    try testing.expectError(error.ArgumentCount, configPath(.{ .vector = &empty_vector }));
    const name_only = [_][*:0]const u8{program};
    try testing.expectError(error.ArgumentCount, configPath(.{ .vector = &name_only }));
    const two = [_][*:0]const u8{ program, "/a.zon", "/b.zon" };
    try testing.expectError(error.ArgumentCount, configPath(.{ .vector = &two }));
    const empty_second = [_][*:0]const u8{ program, "/a.zon", "" };
    try testing.expectError(error.ArgumentCount, configPath(.{ .vector = &empty_second }));
}

test "main: an empty argument is PathEmpty, and one starting with - is PathIsOption" {
    const empty = [_][*:0]const u8{ program, "" };
    try testing.expectError(error.PathEmpty, configPath(.{ .vector = &empty }));
    const options = [_][*:0]const u8{ "-", "-h", "--help", "--version", "--", "-/etc/config.zon" };
    for (options) |option| {
        const vector = [_][*:0]const u8{ program, option };
        try testing.expectError(error.PathIsOption, configPath(.{ .vector = &vector }));
    }
}

test "main: a path of config_file_path_max bytes is accepted; one byte more is PathTooLong" {
    var buffer: [config_path_max + 2]u8 = @splat('a');
    buffer[0] = '/';
    buffer[config_path_max] = 0;
    const longest = [_][*:0]const u8{ program, buffer[0..config_path_max :0] };
    const path = try configPath(.{ .vector = &longest });
    try testing.expectEqual(@as(usize, config_path_max), path.len);
    // The path is the argument itself, not a copy.
    try testing.expectEqual(@intFromPtr(&buffer), @intFromPtr(path.ptr));

    // One byte more, and the scan stops at the bound, one byte before the argument's NUL.
    buffer[config_path_max] = 'a';
    buffer[config_path_max + 1] = 0;
    const over = [_][*:0]const u8{ program, buffer[0 .. config_path_max + 1 :0] };
    try testing.expectError(error.PathTooLong, configPath(.{ .vector = &over }));
}

test "main: the version line names the program and ends in a newline" {
    try testing.expect(std.mem.startsWith(u8, version_line, "coalition-connection "));
    try testing.expect(std.mem.endsWith(u8, version_line, "\n"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, version_line, "\n"));
}
