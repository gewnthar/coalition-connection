//! The server program, installed by `zig build` as `zig-out/bin/coalition-connection`.
//!
//! Job: start the process in the order every later component follows: close inherited
//! descriptors, read the config, make sure the open-file limit covers every connection it
//! allows, size memory through the startup allocator, end startup, then run. For now there
//! is nothing to run yet, so once the config checks out it prints its name and version and
//! exits 0; components join here as they land.
//!
//! Inputs: one command-line argument, the path of the config file, which src/config.zig
//! reads and checks: `coalition-connection <config file>`. The server takes no options yet,
//! so an argument starting with `-` is refused rather than read as a path.
//!
//! Outputs: one line on stdout, `coalition-connection <version>`, and exit status 0. A bad
//! command line logs the usage on stderr and exits 2. A config the server refuses, an
//! open-file limit that can't cover every connection, or a version line it can't write,
//! logs why on stderr and exits 1, with nothing on stdout.
//!
//! Open files: every connection holds a socket, so the soft open-file limit (RLIMIT_NOFILE)
//! must cover the config's `connections_max` plus `descriptors_besides_connections`
//! (src/constants.zig), or accepts would fail for want of a descriptor while the
//! connection table still had room. At the common soft limit of 1,024 that would happen
//! after about 1,020 connections. The limit caps descriptor numbers, not how many are open,
//! so startup first closes every descriptor above standard error that the process
//! inherited: each would take a connection's number. Then, when the soft limit is short
//! and the hard limit allows it, startup raises the soft limit to exactly the need,
//! silently; otherwise it refuses to start, logging the limits it read and the need.
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

/// Exit status when the config or the open-file limit is refused, or the version line can't
/// be written. Reason:
/// one status for "the server would not start", apart from a bad command line.
const exit_failure: u8 = 1;

/// Exit status for a command line the server doesn't accept. Reason: 2 is the usual status
/// for a usage error, so a supervisor or a script can tell it from a refused config.
const exit_usage: u8 = 2;

const config_path_max = cc.constants.config_file_path_max;
const descriptors_needed_max = cc.constants.descriptors_needed_max;
const descriptors_besides_connections = cc.constants.descriptors_besides_connections;

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

pub const FileLimitError = error{
    /// close_range failed, so descriptors the process inherited may still take numbers
    /// the connections need.
    InheritedFilesUnclosed,
    /// getrlimit failed, so the server can't tell whether every connection gets a socket.
    FileLimitUnavailable,
    /// The hard open-file limit is below the need, so the soft limit can't be raised to it.
    FileLimitTooLow,
    /// setrlimit refused to raise the soft limit to the need.
    FileLimitRaiseFailed,
    /// The soft limit read back after a successful raise is below the need again: another
    /// process changed it in between (prlimit).
    FileLimitChanged,
};

/// Everything that stops a start after the command line: a config the server refuses, an
/// open-file limit that can't cover every connection, or a version line it can't write.
pub const RunError = FileLimitError || cc.config.LoadError || MainError;

/// What startup does about the open-file limit, decided by `fileLimitAction`.
pub const FileLimitAction = union(enum) {
    /// The soft limit already covers the need: leave both limits as they are.
    keep,
    /// The soft limit is short and the hard limit covers the need: set the soft limit to
    /// this value, the need, and leave the hard limit as it is.
    raise: u64,
    /// The hard limit is short too, so no unprivileged raise can meet the need.
    refuse,
};

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
    // First, so nothing the server opens lands among the inherited descriptors. It and
    // ensureFileLimit log their own errors.
    try closeInheritedFiles();
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
    // After the config, so a bad config is reported as one, and before any component
    // opens a descriptor or startup ends. Raising the limit allocates nothing.
    try ensureFileLimit(descriptorsNeeded(config.connections_max));
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

/// Closes every descriptor above standard error, all of them inherited, since the server
/// has opened none yet. Each would take a number the open-file limit keeps for a
/// connection. Logs and returns `InheritedFilesUnclosed` when the kernel refuses.
fn closeInheritedFiles() FileLimitError!void {
    const first: linux.fd_t = linux.STDERR_FILENO + 1;
    const last: linux.fd_t = std.math.maxInt(linux.fd_t);
    assert(first == 3);
    assert(first < last);
    const close_errno = linux.errno(linux.close_range(first, last, .{ .CLOEXEC = false, .UNSHARE = false }));
    if (close_errno != .SUCCESS) {
        const err = error.InheritedFilesUnclosed;
        std.log.err("inherited descriptors: close_range failed, errno {d}: {t}", .{ @backingInt(close_errno), err });
        return err;
    }
}

/// The open-file limit a config allowing `connections_max` connections needs.
fn descriptorsNeeded(connections_max: u32) u64 {
    assert(connections_max > 0);
    assert(connections_max <= cc.constants.http_connections_max);
    const need = @as(u64, connections_max) + descriptors_besides_connections;
    assert(need <= descriptors_needed_max);
    return need;
}

/// Decides what startup does about the open-file limit, from the soft and hard limits and
/// the descriptors the server needs. Pure, so every case is tested without touching the
/// process's limits. A raise goes to the need itself, never to the hard limit, so the
/// process keeps no more headroom than the descriptors it counts.
fn fileLimitAction(soft: u64, hard: u64, need: u64) FileLimitAction {
    assert(need > 0);
    // The kernel never reports a soft limit above the hard one (readFileLimit checks).
    assert(soft <= hard);
    if (soft >= need) return .keep;
    if (hard < need) return .refuse;
    return .{ .raise = need };
}

/// Makes sure the soft open-file limit is at least `need`: keeps it, raises it, or refuses
/// with a named error after logging what it read and the need.
fn ensureFileLimit(need: u64) FileLimitError!void {
    // Every caller's need covers the descriptors the server holds besides connections.
    assert(need > descriptors_besides_connections);
    const before = try readFileLimit(need);
    switch (fileLimitAction(before.cur, before.max, need)) {
        .keep => return,
        .refuse => {
            const err = error.FileLimitTooLow;
            std.log.err("open-file limit: soft {d}, hard {d}, need {d}: {t}: raise the hard limit " ++
                "(ulimit -Hn, or LimitNOFILE= under systemd) or lower connections_max", .{ before.cur, before.max, need, err });
            return err;
        },
        .raise => |soft| {
            // The raise this function acts on is the one its reading called for.
            assert(before.cur < soft and soft == need);
            const raised: linux.rlimit = .{ .cur = soft, .max = before.max };
            const raise_errno = linux.errno(linux.setrlimit(.NOFILE, &raised));
            if (raise_errno != .SUCCESS) {
                const err = error.FileLimitRaiseFailed;
                std.log.err("open-file limit: raising soft {d} to {d} (hard {d}) failed, errno {d}: {t}", .{
                    before.cur, soft, before.max, @backingInt(raise_errno), err,
                });
                return err;
            }
        },
    }
    // The limits are the kernel's, read back: a soft limit short again is a named error,
    // not an assertion, since another process can change them through prlimit at any time.
    const after = try readFileLimit(need);
    if (after.cur < need) {
        const err = error.FileLimitChanged;
        std.log.err("open-file limit: soft {d} after raising, hard {d}, need {d}: {t}", .{ after.cur, after.max, need, err });
        return err;
    }
}

/// Reads RLIMIT_NOFILE. `need` goes into the log line when the read fails.
fn readFileLimit(need: u64) FileLimitError!linux.rlimit {
    assert(need > descriptors_besides_connections);
    // Soft above hard, so a read that leaves it untouched can't pass the check below.
    var limit: linux.rlimit = .{ .cur = std.math.maxInt(u64), .max = 0 };
    const read_errno = linux.errno(linux.getrlimit(.NOFILE, &limit));
    if (read_errno != .SUCCESS) {
        const err = error.FileLimitUnavailable;
        std.log.err("open-file limit: getrlimit failed, errno {d} (need {d}): {t}", .{ @backingInt(read_errno), need, err });
        return err;
    }
    // Linux refuses any setrlimit with the soft limit above the hard one.
    assert(limit.cur <= limit.max);
    return limit;
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

test "main: descriptorsNeeded is the config's connections plus the descriptors besides them" {
    try testing.expectEqual(@as(u64, 1) + descriptors_besides_connections, descriptorsNeeded(1));
    try testing.expectEqual(@as(u64, 1024) + descriptors_besides_connections, descriptorsNeeded(1024));
    try testing.expectEqual(descriptors_needed_max, descriptorsNeeded(cc.constants.http_connections_max));
}

test "main: fileLimitAction keeps, raises or refuses at need - 1, need and need + 1" {
    const need: u64 = descriptors_needed_max;
    // A soft limit well short of the need, derived from it so the cases hold for any limit.
    const short: u64 = need / 2;
    const unlimited = std.math.maxInt(u64);
    // Soft limit at need - 1, need and need + 1, with the hard limit at its largest.
    try testing.expectEqual(FileLimitAction{ .raise = need }, fileLimitAction(need - 1, unlimited, need));
    try testing.expectEqual(FileLimitAction.keep, fileLimitAction(need, unlimited, need));
    try testing.expectEqual(FileLimitAction.keep, fileLimitAction(need + 1, unlimited, need));
    // Hard limit at need - 1, need and need + 1, with the soft limit short.
    try testing.expectEqual(FileLimitAction.refuse, fileLimitAction(short, need - 1, need));
    try testing.expectEqual(FileLimitAction{ .raise = need }, fileLimitAction(short, need, need));
    try testing.expectEqual(FileLimitAction{ .raise = need }, fileLimitAction(short, need + 1, need));
    // Both limits at need - 1, need and need + 1.
    try testing.expectEqual(FileLimitAction.refuse, fileLimitAction(need - 1, need - 1, need));
    try testing.expectEqual(FileLimitAction.keep, fileLimitAction(need, need, need));
    try testing.expectEqual(FileLimitAction.keep, fileLimitAction(need + 1, need + 1, need));
}

test "main: fileLimitAction raises to the need, never to the hard limit, and never lowers" {
    const need: u64 = descriptors_needed_max;
    const unlimited = std.math.maxInt(u64);
    // A raise asks for exactly the need, however much room the hard limit leaves.
    try testing.expectEqual(FileLimitAction{ .raise = need }, fileLimitAction(0, unlimited, need));
    // A soft limit of 0 with a hard limit of 0 can't be raised.
    try testing.expectEqual(FileLimitAction.refuse, fileLimitAction(0, 0, need));
    // A soft limit already far above the need is kept, not lowered to it.
    try testing.expectEqual(FileLimitAction.keep, fileLimitAction(need * 4, unlimited, need));
}

/// Exit statuses of the forked children in the tests below. 0 means the child saw what the
/// test expects; the others say which step went wrong, so a failure names its cause.
const child_ok: u8 = 0;
const child_setup_failed: u8 = 10;
const child_wrong_result: u8 = 11;
const child_limit_wrong: u8 = 12;
const child_hard_too_low: u8 = 13;
const child_inherited_open: u8 = 14;

/// Polls for a child's exit, `wait_poll_ns` apart. Reason: a child here does a few
/// syscalls, so 2,000 polls of 5 ms (10 s) is ample; past it the child is killed and the
/// test fails instead of hanging.
const wait_polls_max: u32 = 2_000;
const wait_poll_ns: u32 = 5 * std.time.ns_per_ms;

/// Bytes of a child's stderr kept, and read calls taken to drain it. Reason: a child logs
/// at most a few lines, and the pipe is drained only after the child has exited.
const child_stderr_max: u32 = 4096;
const child_stderr_reads_max: u32 = 64;

/// The short soft open-file limit the children start from: enough for the standard streams
/// and a few test descriptors, and far below any need.
const child_soft_limit: u64 = 64;

comptime {
    // The children's short soft limit is below the smallest need they ask for: 1,024
    // connections (the config in the start test) or the machine's hard limit, minus one.
    assert(child_soft_limit + 1 < descriptorsNeeded(1024));
    assert(child_stderr_max > 0 and child_stderr_reads_max > 0);
}

/// What a forked child left: its exit status and what it wrote to stderr.
const ChildResult = struct {
    status: u8,
    stderr_len: u32,
    stderr: [child_stderr_max]u8,
};

/// Runs `body` in a forked child, so changing limits or closing descriptors there can't
/// touch the test runner, and returns its exit status and its stderr, read from a pipe.
fn runInChild(comptime body: fn () u8) !ChildResult {
    var pipe: [2]linux.fd_t = undefined;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.pipe2(&pipe, .{ .CLOEXEC = true })));
    defer _ = linux.close(pipe[0]);
    const pid_rc = linux.fork();
    if (linux.errno(pid_rc) != .SUCCESS) {
        _ = linux.close(pipe[1]);
        return error.TestUnexpectedResult;
    }
    if (pid_rc == 0) {
        // The child: stderr becomes the pipe's write end, and stdout goes nowhere.
        if (linux.errno(linux.dup2(pipe[1], linux.STDERR_FILENO)) != .SUCCESS) linux.exit_group(child_setup_failed);
        const null_rc = linux.open("/dev/null", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
        if (linux.errno(null_rc) != .SUCCESS) linux.exit_group(child_setup_failed);
        if (linux.errno(linux.dup2(@intCast(null_rc), linux.STDOUT_FILENO)) != .SUCCESS) linux.exit_group(child_setup_failed);
        linux.exit_group(body());
    }
    _ = linux.close(pipe[1]);
    const pid: linux.pid_t = @intCast(pid_rc);
    assert(pid > 0);
    const status = try waitChild(pid);
    var result: ChildResult = .{ .status = status, .stderr_len = 0, .stderr = undefined };
    result.stderr_len = drainPipe(pipe[0], &result.stderr);
    assert(result.stderr_len <= child_stderr_max);
    if (result.status != child_ok) {
        std.debug.print("child exited {d}; stderr:\n{s}\n", .{ result.status, result.stderr[0..result.stderr_len] });
    }
    return result;
}

/// Waits for `pid` to exit within `wait_polls_max` polls, killing and reaping it past that.
/// A child that ends on a signal (an assertion's panic, say) fails the test.
fn waitChild(pid: linux.pid_t) !u8 {
    assert(pid > 0);
    var polls: u32 = 0;
    while (polls < wait_polls_max) : (polls += 1) {
        var raw: i32 = 0;
        const rc = linux.waitpid(pid, &raw, linux.W.NOHANG);
        const errno = linux.errno(rc);
        if (errno == .INTR) continue;
        try testing.expectEqual(linux.E.SUCCESS, errno);
        if (rc == 0) {
            const pause: linux.timespec = .{ .sec = 0, .nsec = wait_poll_ns };
            _ = linux.nanosleep(&pause, null);
            continue;
        }
        // waitpid reports on the one child it was asked about.
        assert(rc == @as(usize, @intCast(pid)));
        const status: u32 = @bitCast(raw);
        if (!linux.W.IFEXITED(status)) {
            std.debug.print("child ended on signal {d}\n", .{@backingInt(linux.W.TERMSIG(status))});
            return error.TestUnexpectedResult;
        }
        return linux.W.EXITSTATUS(status);
    }
    _ = linux.kill(pid, .KILL);
    var raw: i32 = 0;
    _ = linux.waitpid(pid, &raw, 0);
    std.debug.print("child still running after {d} polls; killed\n", .{wait_polls_max});
    return error.TestUnexpectedResult;
}

/// Reads what is left in a pipe whose write ends are all closed, up to the buffer's size.
fn drainPipe(fd: linux.fd_t, buffer: *[child_stderr_max]u8) u32 {
    assert(fd >= 0);
    var len: u32 = 0;
    var reads: u32 = 0;
    while (len < buffer.len and reads < child_stderr_reads_max) : (reads += 1) {
        const rc = linux.read(fd, buffer[len..].ptr, buffer.len - len);
        const errno = linux.errno(rc);
        if (errno == .INTR) continue;
        if (errno != .SUCCESS or rc == 0) break;
        assert(rc <= buffer.len - len);
        len += @intCast(rc);
    }
    assert(len <= buffer.len);
    return len;
}

/// The child's open-file limits, or exit with `child_setup_failed`.
fn childFileLimit() linux.rlimit {
    var limit: linux.rlimit = .{ .cur = 0, .max = 0 };
    if (linux.errno(linux.getrlimit(.NOFILE, &limit)) != .SUCCESS) linux.exit_group(child_setup_failed);
    // Linux refuses any setrlimit with the soft limit above the hard one.
    assert(limit.cur <= limit.max);
    // Even a test runner's child keeps its standard streams under the limit.
    assert(limit.cur >= 3);
    return limit;
}

/// Sets both open-file limits, or exits the child with `child_setup_failed`.
fn childSetFileLimit(soft: u64, hard: u64) void {
    assert(soft <= hard);
    // Every child starts with a short soft limit, so the server has to act.
    assert(soft == child_soft_limit);
    const limit: linux.rlimit = .{ .cur = soft, .max = hard };
    if (linux.errno(linux.setrlimit(.NOFILE, &limit)) != .SUCCESS) linux.exit_group(child_setup_failed);
}

/// Child: the hard limit drops to one below the need, so ensureFileLimit must refuse with
/// FileLimitTooLow and leave the soft limit alone. The need is the largest one, or the
/// machine's own hard limit if that is lower, so the test runs on any machine.
fn childRefusesShortHardLimit() u8 {
    const hard = @min(childFileLimit().max, descriptors_needed_max) - 1;
    if (hard <= child_soft_limit) return child_hard_too_low;
    childSetFileLimit(child_soft_limit, hard);
    const result = ensureFileLimit(hard + 1);
    const left = childFileLimit();
    if (left.cur != child_soft_limit or left.max != hard) return child_limit_wrong;
    result catch |err| return if (err == error.FileLimitTooLow) child_ok else child_wrong_result;
    return child_wrong_result;
}

/// Child: the soft limit drops to `child_soft_limit` with the hard limit kept, so
/// ensureFileLimit must raise the soft limit to exactly the need and keep the hard limit.
fn childRaisesShortSoftLimit() u8 {
    const hard = childFileLimit().max;
    const need = @min(hard, descriptors_needed_max);
    if (need <= child_soft_limit + 1) return child_hard_too_low;
    childSetFileLimit(child_soft_limit, hard);
    ensureFileLimit(need) catch return child_wrong_result;
    const after = childFileLimit();
    if (after.cur != need or after.max != hard) return child_limit_wrong;
    return child_ok;
}

/// The config the start test hands run: the example config's two fields.
const child_config = ".{ .socket_path = \"/run/coalition-connection/app.sock\", .connections_max = 1024 }\n";

/// Child: a whole start, through run, with a short soft limit and an extra descriptor
/// inherited. The config comes from a memory file on standard input, the one descriptor
/// above which startup closes everything. After run, the soft limit is the config's need
/// and the extra descriptor is closed.
fn childStartRaisesLimitAndClosesInherited() u8 {
    const hard = childFileLimit().max;
    const need = descriptorsNeeded(1024);
    if (hard < need) return child_hard_too_low;
    const memory_rc = linux.memfd_create("config", linux.MFD.CLOEXEC);
    if (linux.errno(memory_rc) != .SUCCESS) return child_setup_failed;
    const written = linux.write(@intCast(memory_rc), child_config, child_config.len);
    if (linux.errno(written) != .SUCCESS or written != child_config.len) return child_setup_failed;
    if (linux.errno(linux.dup2(@intCast(memory_rc), linux.STDIN_FILENO)) != .SUCCESS) return child_setup_failed;
    // memory_rc itself stays open: one more inherited descriptor startup must close.
    const inherited: linux.fd_t = @intCast(memory_rc);
    assert(inherited > linux.STDERR_FILENO);
    childSetFileLimit(child_soft_limit, hard);
    run("/proc/self/fd/0") catch return child_wrong_result;
    const after = childFileLimit();
    if (after.cur != need or after.max != hard) return child_limit_wrong;
    const flags = linux.fcntl(inherited, linux.F.GETFD, 0);
    if (linux.errno(flags) != .BADF) return child_inherited_open;
    return child_ok;
}

test "main: a hard open-file limit below the need refuses with FileLimitTooLow and logs it" {
    const result = try runInChild(childRefusesShortHardLimit);
    try testing.expectEqual(child_ok, result.status);
    const logged = result.stderr[0..result.stderr_len];
    try testing.expect(std.mem.find(u8, logged, "open-file limit: soft 64, hard ") != null);
    try testing.expect(std.mem.find(u8, logged, ": FileLimitTooLow: raise the hard limit") != null);
}

test "main: a short soft open-file limit is raised to exactly the need, silently" {
    const result = try runInChild(childRaisesShortSoftLimit);
    try testing.expectEqual(child_ok, result.status);
    try testing.expectEqual(@as(u32, 0), result.stderr_len);
}

test "main: a start raises the soft limit to the config's need and closes inherited files" {
    const result = try runInChild(childStartRaisesLimitAndClosesInherited);
    try testing.expectEqual(child_ok, result.status);
    // A clean start logs nothing; the version line went to /dev/null.
    try testing.expectEqual(@as(u32, 0), result.stderr_len);
}
