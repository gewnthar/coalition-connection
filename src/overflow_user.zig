//! The overflow user check (roadmap core 8): the server refuses to run as the kernel's
//! overflow user.
//!
//! Job:
//!   In a user namespace, every file whose owner the namespace doesn't map shows as owned by
//!   the overflow user (`/proc/sys/kernel/overflowuid`, 65534 by default). A server running
//!   as that user would take such a file, a config or a socket directory owned by any
//!   unmapped user outside the namespace, for its own. So before the config is read,
//!   startup reads the overflow user ID and refuses to start when the server's effective
//!   user ID equals it. It fails closed: when the file can't be opened, read or parsed,
//!   startup refuses too, rather than guessing the default.
//!
//! Inputs:
//!   The path of the overflow user ID file (`overflow_uid_path` in the server; tests pass
//!   others) and the server's effective user ID.
//!
//! Outputs:
//!   Nothing, or a named error: `OverflowUser`, `OverflowUidUnavailable` or
//!   `OverflowUidMalformed`. The caller logs it.
//!
//! Limits (src/constants.zig):
//!   overflow_uid_file_size_max: the longest file accepted.
//!   overflow_uid_read_attempts_max: read calls for the file.
//!
//! No allocation: the file is read into a small buffer on the stack.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const constants = @import("constants.zig");

/// Where the kernel publishes the overflow user ID.
pub const overflow_uid_path: [:0]const u8 = "/proc/sys/kernel/overflowuid";

const file_size_max = constants.overflow_uid_file_size_max;
const read_attempts_max = constants.overflow_uid_read_attempts_max;

/// The kernel's "no user" value (-1 as a uid_t), which no process runs as.
const uid_none: linux.uid_t = std.math.maxInt(linux.uid_t);

/// Digits in the largest user ID.
const uid_digits_max: u32 = std.fmt.count("{d}", .{std.math.maxInt(linux.uid_t)});

comptime {
    // The file holds at most the largest user ID and its newline, and nothing longer.
    assert(file_size_max == uid_digits_max + 1);
    assert(read_attempts_max >= 2);
    // The read-bound test needs the bound to run out before the room fills.
    assert(read_attempts_max < file_size_max + 1);
}

pub const ParseError = error{
    /// The file's bytes aren't one user ID in decimal followed by one newline: empty,
    /// too long, a byte that isn't a digit, a leading zero, a missing newline, or a value
    /// past the largest user ID.
    OverflowUidMalformed,
};

pub const ReadError = error{
    /// The file can't be opened or read whole.
    OverflowUidUnavailable,
} || ParseError;

pub const CheckError = error{
    /// The server's effective user is the overflow user.
    OverflowUser,
} || ReadError;

/// What the server's user and the overflow user allow. Pure, so every case is tested
/// without changing who the test runs as.
pub const Verdict = enum { run, refuse };

/// `server_uid` is the server's effective user ID, `overflow_uid` the kernel's overflow user.
pub fn verdict(server_uid: linux.uid_t, overflow_uid: linux.uid_t) Verdict {
    // No process runs as the "no user" value, and a parsed overflow ID is never it.
    assert(server_uid != uid_none);
    assert(overflow_uid != uid_none);
    return if (server_uid == overflow_uid) .refuse else .run;
}

/// Parses the file's bytes: a user ID in decimal, without a leading zero unless it is 0,
/// and exactly one newline after it. Reads at most `overflow_uid_file_size_max` bytes.
pub fn parse(bytes: []const u8) ParseError!linux.uid_t {
    if (bytes.len < 2 or bytes.len > file_size_max) return error.OverflowUidMalformed;
    if (bytes[bytes.len - 1] != '\n') return error.OverflowUidMalformed;
    const digits = bytes[0 .. bytes.len - 1];
    if (digits[0] == '0' and digits.len > 1) return error.OverflowUidMalformed;
    // The loop's bound: at most 10 digits, so the value fits in a u64 before it is checked
    // against a uid_t.
    assert(digits.len <= uid_digits_max);
    var value: u64 = 0;
    for (digits) |byte| {
        if (byte < '0' or byte > '9') return error.OverflowUidMalformed;
        value = value * 10 + (byte - '0');
    }
    // uid_none is the "no user" value, never an overflow user.
    if (value >= uid_none) return error.OverflowUidMalformed;
    const uid: linux.uid_t = @intCast(value);
    // Only the canonical form is accepted: the ID written back takes exactly its digits.
    assert(std.fmt.count("{d}", .{uid}) == digits.len);
    return uid;
}

/// Reads and parses the overflow user ID at `path`, which must name a regular file (the
/// kernel's sysctl files are). Logs the kernel's errno when the file can't be opened, checked
/// or read, at info level: the caller logs the refusal itself.
pub fn read(path: [:0]const u8) ReadError!linux.uid_t {
    assert(path.len > 0);
    // Every caller passes an absolute path, so the working directory can't change the file.
    assert(path[0] == '/');
    // Non-blocking, so a FIFO at the path can't stall startup in open.
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOCTTY = true, .NONBLOCK = true };
    const open_rc = linux.open(path, flags, 0);
    const fd: linux.fd_t = switch (linux.errno(open_rc)) {
        .SUCCESS => @intCast(open_rc),
        else => |errno| {
            std.log.info("overflow user: {s}: open failed, errno {d}", .{ path, @backingInt(errno) });
            return error.OverflowUidUnavailable;
        },
    };
    defer _ = linux.close(fd);
    try checkRegular(fd, path);
    // One byte past the longest valid file, so a longer one is seen, not cut short.
    var room: [file_size_max + 1]u8 = undefined;
    const len = readAll(fd, &room) catch |err| {
        std.log.info("overflow user: {s}: {t}", .{ path, err });
        return err;
    };
    return parse(room[0..len]);
}

/// Refuses anything at `fd` but a regular file: a FIFO, socket, device or directory could
/// hand over bytes no kernel wrote, or none.
fn checkRegular(fd: linux.fd_t, path: [:0]const u8) error{OverflowUidUnavailable}!void {
    assert(fd >= 0);
    assert(path.len > 0);
    var status: linux.Statx = undefined;
    const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &status);
    const errno = linux.errno(rc);
    if (errno != .SUCCESS) {
        std.log.info("overflow user: {s}: statx failed, errno {d}", .{ path, @backingInt(errno) });
        return error.OverflowUidUnavailable;
    }
    if (!status.mask.TYPE or !linux.S.ISREG(status.mode)) {
        std.log.info("overflow user: {s}: not a regular file (mode {o})", .{ path, status.mode });
        return error.OverflowUidUnavailable;
    }
}

/// Reads from `fd` until end of file or until `room` is full, and returns the bytes read.
fn readAll(fd: linux.fd_t, room: *[file_size_max + 1]u8) error{OverflowUidUnavailable}!u32 {
    assert(fd >= 0);
    var len: u32 = 0;
    var attempts: u32 = 0;
    while (len < room.len) : (attempts += 1) {
        if (attempts == read_attempts_max) {
            std.log.info("overflow user: not read whole in {d} read calls", .{read_attempts_max});
            return error.OverflowUidUnavailable;
        }
        const rest = room[len..];
        const rc = linux.read(fd, rest.ptr, rest.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) break; // End of file.
                assert(rc <= rest.len); // read never reports more than it was given.
                len += @intCast(rc);
            },
            .INTR => {},
            // EIO and the rest: no whole value to read.
            else => |errno| {
                std.log.info("overflow user: read failed, errno {d}", .{@backingInt(errno)});
                return error.OverflowUidUnavailable;
            },
        }
    }
    assert(attempts <= read_attempts_max);
    assert(len <= room.len);
    return len;
}

/// Refuses with `OverflowUser` when `server_uid` is the overflow user read from `path`, and
/// with the read's own error when the file can't be read or parsed.
pub fn check(path: [:0]const u8, server_uid: linux.uid_t) CheckError!void {
    assert(path.len > 0);
    assert(server_uid != uid_none);
    const overflow_uid = try read(path);
    switch (verdict(server_uid, overflow_uid)) {
        .run => {},
        .refuse => return error.OverflowUser,
    }
}

const testing = std.testing;

test "overflow_user: verdict refuses exactly the overflow user" {
    const cases = [_]struct { server: linux.uid_t, overflow: linux.uid_t, verdict: Verdict }{
        .{ .server = 65534, .overflow = 65534, .verdict = .refuse },
        .{ .server = 0, .overflow = 0, .verdict = .refuse },
        .{ .server = 1000, .overflow = 1000, .verdict = .refuse },
        .{ .server = 1000, .overflow = 65534, .verdict = .run },
        .{ .server = 0, .overflow = 65534, .verdict = .run },
        // Next to the overflow user, on either side.
        .{ .server = 65533, .overflow = 65534, .verdict = .run },
        .{ .server = 65535, .overflow = 65534, .verdict = .run },
        // The largest user IDs a process or the parser can hold.
        .{ .server = uid_none - 1, .overflow = uid_none - 1, .verdict = .refuse },
        .{ .server = uid_none - 1, .overflow = 65534, .verdict = .run },
    };
    for (cases) |case| try testing.expectEqual(case.verdict, verdict(case.server, case.overflow));
}

test "overflow_user: parse reads one decimal user ID and its newline" {
    try testing.expectEqual(@as(linux.uid_t, 65534), try parse("65534\n"));
    try testing.expectEqual(@as(linux.uid_t, 0), try parse("0\n"));
    try testing.expectEqual(@as(linux.uid_t, 7), try parse("7\n"));
    // The longest file accepted: the largest user ID below the "no user" value.
    try testing.expectEqual(uid_none - 1, try parse("4294967294\n"));
}

test "overflow_user: parse refuses empty, too long and malformed input" {
    const malformed = [_][]const u8{
        "", // Empty.
        "\n", // No digits.
        "65534", // No newline.
        "65534\n\n", // Two newlines.
        "65534 \n", // A space.
        " 65534\n",
        "+65534\n", // A sign.
        "-1\n",
        "6553a\n", // A byte that isn't a digit.
        "0x10\n",
        "065534\n", // A leading zero.
        "00\n",
        "65534\r\n", // A carriage return.
        "4294967295\n", // The "no user" value.
        "4294967296\n", // Past the largest user ID.
        "9999999999\n", // The largest 10 digits.
        "42949672950\n", // One byte too long.
        "12345678901234567890\n",
    };
    for (malformed) |bytes| try testing.expectError(error.OverflowUidMalformed, parse(bytes));
}

/// A memory file holding `bytes`, named by a path under /proc/self/fd.
const TestFile = struct {
    fd: linux.fd_t,
    path_bytes: [31:0]u8,

    fn init(bytes: []const u8) !TestFile {
        const rc = linux.memfd_create("overflowuid", linux.MFD.CLOEXEC);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
        const fd: linux.fd_t = @intCast(rc);
        if (bytes.len > 0) {
            const written = linux.write(fd, bytes.ptr, bytes.len);
            try testing.expectEqual(linux.E.SUCCESS, linux.errno(written));
            try testing.expectEqual(bytes.len, written);
        }
        var file: TestFile = .{ .fd = fd, .path_bytes = @splat(0) };
        const name = try std.fmt.bufPrint(&file.path_bytes, "/proc/self/fd/{d}", .{fd});
        assert(name.len < file.path_bytes.len);
        assert(file.path_bytes[name.len] == 0);
        return file;
    }

    fn path(file: *const TestFile) [:0]const u8 {
        assert(file.fd >= 0);
        const name = std.mem.sliceTo(&file.path_bytes, 0);
        assert(name.len > "/proc/self/fd/".len);
        return name;
    }

    fn deinit(file: *TestFile) void {
        assert(file.fd >= 0);
        assert(linux.errno(linux.close(file.fd)) == .SUCCESS);
        file.fd = -1;
    }
};

test "overflow_user: read parses the file, and refuses one too long" {
    var default = try TestFile.init("65534\n");
    defer default.deinit();
    try testing.expectEqual(@as(linux.uid_t, 65534), try read(default.path()));
    var long = try TestFile.init("655340000000\n");
    defer long.deinit();
    try testing.expectError(error.OverflowUidMalformed, read(long.path()));
    // One byte past the longest valid file, whose first 11 bytes would parse: the byte
    // past them must be seen.
    var one_more = try TestFile.init("1234567890\n\n");
    defer one_more.deinit();
    try testing.expectError(error.OverflowUidMalformed, read(one_more.path()));
    var empty = try TestFile.init("");
    defer empty.deinit();
    try testing.expectError(error.OverflowUidMalformed, read(empty.path()));
    var root = try TestFile.init("0\n");
    defer root.deinit();
    try testing.expectEqual(@as(linux.uid_t, 0), try read(root.path()));
}

test "overflow_user: a path that can't be opened or read is OverflowUidUnavailable" {
    try testing.expectError(error.OverflowUidUnavailable, read("/nonexistent/overflowuid"));
    // A directory opens, but reading it fails with EISDIR.
    try testing.expectError(error.OverflowUidUnavailable, read("/proc/sys/kernel"));
    // The kernel calls /proc/self/mem a regular file, but reading address 0 fails with EIO.
    try testing.expectError(error.OverflowUidUnavailable, read("/proc/self/mem"));
}

test "overflow_user: a FIFO holding a valid line is refused, with or without a writer" {
    var fds: [2]linux.fd_t = undefined;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })));
    defer _ = linux.close(fds[0]);
    try testing.expectEqual(@as(usize, 6), linux.write(fds[1], "65534\n", 6));
    var path_bytes: [31:0]u8 = @splat(0);
    const path = try std.fmt.bufPrintSentinel(&path_bytes, "/proc/self/fd/{d}", .{fds[0]}, 0);
    try testing.expectError(error.OverflowUidUnavailable, read(path));
    _ = linux.close(fds[1]);
    try testing.expectError(error.OverflowUidUnavailable, read(path));
}

test "overflow_user: a source that needs more read calls than the bound is OverflowUidUnavailable" {
    // Each read of a packet socket returns one packet, here one byte, so the bound runs out
    // before the room does. A packet waits for every byte of the room, so a looser bound
    // fills the room and returns instead of blocking.
    var room: [file_size_max + 1]u8 = undefined;
    var fds: [2]linux.fd_t = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0, &fds);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);
    var packet: u32 = 0;
    while (packet < room.len) : (packet += 1) {
        try testing.expectEqual(@as(usize, 1), linux.write(fds[1], "1", 1));
    }
    try testing.expectError(error.OverflowUidUnavailable, readAll(fds[0], &room));
}

test "overflow_user: check refuses the overflow user and lets any other run" {
    var file = try TestFile.init("65534\n");
    defer file.deinit();
    try testing.expectError(error.OverflowUser, check(file.path(), 65534));
    try check(file.path(), 1000);
    try check(file.path(), 0);
    // An unreadable file refuses every user, the overflow user's default included.
    try testing.expectError(error.OverflowUidUnavailable, check("/nonexistent/overflowuid", 1000));
    try testing.expectError(error.OverflowUidUnavailable, check("/nonexistent/overflowuid", 65534));
}

test "overflow_user: the kernel's own file parses" {
    // Every Linux kernel since 2.4 publishes it, and the kernel keeps it at most 65535.
    const uid = try read(overflow_uid_path);
    try testing.expect(uid <= 65535);
}
