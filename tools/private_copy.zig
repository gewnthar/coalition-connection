//! Build helper: copies one small file to a new path, readable and writable by its owner
//! alone (mode 0600).
//!
//! `zig build test` starts the server with docs/config.example.zon, and the server refuses a
//! config file its group or others may write. Git writes a checked-out file with the mode
//! the umask leaves, so under umask 002 (the usual default where each user has a group of
//! their own) the example is 0664 and would be refused. The build hands the server this
//! copy instead, so the start test checks the example's contents whatever the checkout's
//! umask was.
//!
//! Usage: private_copy <source> <destination>. Exits 0 on success, 1 on any failure, with
//! the reason on stderr. Linux only, like the server.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;

/// The largest file copied. Reason: the config file's own limit (4 KiB), with room to
/// spare; a larger source is refused rather than cut short.
const size_max: u32 = 16 * 1024;

/// Longest argument. Reason: a path in the build's cache, well inside PATH_MAX.
const argument_max: u32 = 4096;

/// Read or write calls per file. Reason: a regular file of `size_max` bytes reads and
/// writes whole in one call; the bound leaves room for interrupted calls.
const calls_max: u32 = 16;

pub fn main(init: std.process.Init.Minimal) u8 {
    const vector = init.args.vector;
    if (vector.len != 3) {
        std.debug.print("usage: private_copy <source> <destination>\n", .{});
        return 1;
    }
    const source = argument(vector[1]) orelse {
        std.debug.print("private_copy: source path empty or too long\n", .{});
        return 1;
    };
    const destination = argument(vector[2]) orelse {
        std.debug.print("private_copy: destination path empty or too long\n", .{});
        return 1;
    };
    // argument's bound: both paths fit any buffer the kernel takes.
    assert(source.len <= argument_max and destination.len <= argument_max);
    var buffer: [size_max + 1]u8 = undefined;
    const len = readSource(source, &buffer) catch |err| {
        std.debug.print("private_copy: {s}: {t}\n", .{ source, err });
        return 1;
    };
    // readSource's bound, which the slice below relies on.
    assert(len <= size_max);
    writeDestination(destination, buffer[0..len]) catch |err| {
        std.debug.print("private_copy: {s}: {t}\n", .{ destination, err });
        return 1;
    };
    return 0;
}

/// The argument as a NUL-terminated slice, scanning at most `argument_max + 1` bytes, or
/// null when it is empty or longer than that.
fn argument(pointer: [*:0]const u8) ?[:0]const u8 {
    var len: u32 = 0;
    while (len <= argument_max and pointer[len] != 0) : (len += 1) {}
    assert(len <= argument_max + 1);
    if (len == 0 or len > argument_max) return null;
    // The scan stopped at the argument's NUL, not inside it.
    assert(pointer[len] == 0 and pointer[len - 1] != 0);
    return pointer[0..len :0];
}

const CopyError = error{ SourceUnreadable, SourceNotRegular, SourceTooLarge, DestinationUnwritable };

/// Reads the whole regular file at `path` into `buffer`, one byte past `size_max` so an
/// oversized file is seen, and returns its length.
fn readSource(path: [:0]const u8, buffer: *[size_max + 1]u8) CopyError!u32 {
    assert(path.len > 0);
    const opened = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOCTTY = true, .NONBLOCK = true }, 0);
    if (linux.errno(opened) != .SUCCESS) return error.SourceUnreadable;
    const fd: linux.fd_t = @intCast(opened);
    defer _ = linux.close(fd);
    // A FIFO or device could read as empty or never end.
    var status: linux.Statx = undefined;
    const statted = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &status);
    if (linux.errno(statted) != .SUCCESS or !status.mask.TYPE) return error.SourceUnreadable;
    if (!linux.S.ISREG(status.mode)) return error.SourceNotRegular;
    var len: u32 = 0;
    var calls: u32 = 0;
    while (len < buffer.len) : (calls += 1) {
        if (calls == calls_max) return error.SourceUnreadable;
        const rest = buffer[len..];
        const rc = linux.read(fd, rest.ptr, rest.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) break;
                assert(rc <= rest.len); // read never reports more than it was given.
                len += @intCast(rc);
            },
            .INTR => {},
            else => return error.SourceUnreadable,
        }
    }
    assert(calls <= calls_max);
    if (len > size_max) return error.SourceTooLarge;
    return len;
}

/// Creates `path` (never following a symlink there), sets its mode to exactly 0600 and
/// writes `bytes` to it whole. A close that fails (an I/O error a network file system
/// reports late) fails the copy too.
fn writeDestination(path: [:0]const u8, bytes: []const u8) CopyError!void {
    assert(path.len > 0);
    assert(bytes.len <= size_max);
    const flags: linux.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true, .NOFOLLOW = true };
    const opened = linux.open(path, flags, 0o600);
    if (linux.errno(opened) != .SUCCESS) return error.DestinationUnwritable;
    const fd: linux.fd_t = @intCast(opened);
    var open_now = true;
    errdefer if (open_now) {
        _ = linux.close(fd);
    };
    // An existing file keeps its old mode through O_TRUNC, so the mode is set explicitly,
    // before any byte is written.
    if (linux.errno(linux.fchmod(fd, 0o600)) != .SUCCESS) return error.DestinationUnwritable;
    var written: u32 = 0;
    var calls: u32 = 0;
    while (written < bytes.len) : (calls += 1) {
        if (calls == calls_max) return error.DestinationUnwritable;
        const rest = bytes[written..];
        const rc = linux.write(fd, rest.ptr, rest.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                assert(rc <= rest.len); // write never reports more than it was given.
                written += @intCast(rc);
            },
            .INTR => {},
            else => return error.DestinationUnwritable,
        }
    }
    assert(calls <= calls_max);
    // Linux releases the descriptor even when close fails, so it is never closed twice.
    open_now = false;
    if (linux.errno(linux.close(fd)) != .SUCCESS) return error.DestinationUnwritable;
}
