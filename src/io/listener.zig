//! Local listener (roadmap core 51): the one socket the server accepts connections on.
//!
//! Job:
//!   Open a Unix stream socket at the config's socket path, the local socket nginx reaches
//!   inside the pod, and refuse to start with a named error rather than listen anywhere
//!   else. The server never opens a TCP or UDP listener, so no port of its own is ever
//!   published: a client outside the pod can't reach it, whatever the firewall says.
//!
//! Inputs:
//!   The socket path from `config.Config.socketPath`: absolute, 1 to
//!   `config_socket_path_max` bytes, no NUL. The config refuses anything else, network
//!   addresses such as `0.0.0.0:8080` included, so a path is the only address this file
//!   is ever handed.
//!
//! Outputs:
//!   A `Listener`: the listening socket, which the I/O type's accepts take (`io.Accept`),
//!   and the path, which `close` removes again. Or a named error for each way the path or
//!   the socket can fail.
//!
//! Limits (src/constants.zig):
//!   listener_backlog: connections the kernel queues before the server accepts them.
//!   listener_bind_attempts_max: bind calls one open may take.
//!   listener_socket_mode: who may connect to the socket file.
//!
//! One server per path. Before it touches the socket path, `open` takes an exclusive
//! `flock` on a lock file beside it, `<path>.lock`, and holds it until `close`. A second
//! server on the same path finds the lock taken and refuses with `SocketPathInUse`. The
//! kernel drops the lock when its holder exits, however it exits, so a socket file found
//! at the path while the lock is held was most likely left by a server that stopped
//! without `close` (a crash, a kill). The lock alone doesn't prove it, since a program that
//! never takes this lock may be serving a socket at that very path. So before removing a
//! socket at the path, `open` connects to it without blocking. Only a refused connect
//! (ECONNREFUSED: no socket there is listening and accepting right now) makes it stale: it
//! is removed and bound again, or a restart would fail until someone deleted it by hand. A
//! connect that gets through, or finds the backlog full, reached a live server, and opening
//! refuses with `SocketPathInUse`, leaving that server's socket alone. A file, a directory,
//! a symlink or a live datagram socket at the path is never removed: opening refuses with
//! `SocketPathOccupied`. (A dead socket file's type can't be learned: the kernel refuses a
//! connect to it before it compares types, so it is stale like any other.) A socket another
//! user owns, live or stale, is neither probed nor removed: `SocketPathOccupied`. The lock file itself
//! stays after `close`; removing it would let two starting servers lock two different
//! files.
//!
//! None of that proves anything in a directory another user may change, since that user
//! could put a socket, a symlink or a lock file of their own at either path. So before it
//! takes the lock, `open` checks the socket's directory: owned by the server's user or root
//! (`SocketDirectoryOwnerWrong`), writable by neither group nor others, so not a sticky
//! directory such as /tmp either (`SocketDirectoryWritable`), and with no POSIX access ACL
//! (`SocketDirectoryAclPresent`). Then the lock file it opened must be a regular file the
//! server's user owns, with one link and no permission bits for group or others
//! (`SocketLockUnsafe`), or it is refused before it is locked.
//!
//! The socket file is created with `listener_socket_mode` and no other: the umask is set
//! for the one bind call so bind makes the file with exactly those bits, then put back.
//! Nothing changes the mode by path afterwards, so a symlink swapped in at the path can't
//! redirect a chmod onto another file. Connecting to a Unix socket needs write permission
//! on the file itself, so the mode decides who may connect, unless the file carries a POSIX
//! access ACL. A default ACL on the socket's directory gives every new file one, and then
//! the mode's group bits are only the ACL's mask: named entries (for example
//! `u:nobody:rwx`) can let other users connect, or an empty owning-group entry can shut the
//! group out, while the mode still reads exactly right. So before listen the socket file is
//! first checked for an access ACL, and any POSIX ACL refuses with `SocketAclPresent`; then
//! its mode is read back, and anything else (a default ACL with no named entries can narrow
//! it) refuses with `SocketModeWrong`. Permission models outside POSIX ACLs (NFSv4 ACLs,
//! CIFS, FUSE without default_permissions) aren't checked, so the socket's directory is on
//! a local file system. The umask is the process's, so `open` runs at startup, before any
//! other thread exists.
//!
//! `check` is the postcondition every listener meets before an accept is submitted on it:
//! a Unix socket, a stream socket, bound to a path in the file system, and listening.
//! `open` ends with it, and a caller can run it on any listener it is handed, so a TCP
//! socket can't become the listener by mistake, nor can a Unix socket on an abstract or
//! unnamed address, which no file mode guards, or on a relative path.
//!
//! Errnos are logged as numbers (`{d}` of `@backingInt`), never by name, since `linux.E`
//! has no name for some values the kernel can return.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const constants = @import("../constants.zig");
const io = @import("root.zig");

const path_max = constants.config_socket_path_max;
const backlog = constants.listener_backlog;
const bind_attempts_max = constants.listener_bind_attempts_max;
const socket_mode = constants.listener_socket_mode;

const lock_suffix = ".lock";

comptime {
    // The path and its NUL fit in `sun_path`, so the kernel sees every byte of it.
    assert(path_max + 1 <= @typeInfo(@FieldType(linux.sockaddr.un, "path")).array.len);
    // The path's length is kept in a u8.
    assert(path_max <= std.math.maxInt(u8));
    assert(backlog > 0 and backlog <= std.math.maxInt(i32));
    // One bind, and one more after a stale socket is removed.
    assert(bind_attempts_max == 2);
    // Permission bits only: no set-id or sticky bits on a socket file.
    assert(socket_mode & ~@as(u32, 0o777) == 0);
}

pub const CheckError = error{
    /// The descriptor isn't a socket at all.
    ListenerNotSocket,
    /// A socket, but not a Unix one: a TCP or UDP socket would listen on a network
    /// address, which the server never does.
    ListenerNotLocal,
    /// A Unix socket, but not a stream socket, so it has no connections to accept.
    ListenerNotStream,
    /// A Unix stream socket on an abstract or unnamed address, which any process in the
    /// network namespace could connect to whatever a file's mode says, or on a relative
    /// path, which the server never binds.
    ListenerNotOnPath,
    /// A Unix stream socket that isn't listening.
    ListenerNotListening,
    /// The kernel refused to say what the descriptor is (a closed descriptor, or an answer
    /// of the wrong size).
    ListenerUnreadable,
};

pub const OpenError = CheckError || error{
    /// The process or system is out of descriptors or kernel memory, or a security policy
    /// refuses Unix sockets.
    ListenerUnavailable,
    /// The path's directory is missing, isn't a directory, or the process may not create a
    /// file there (permissions, a read-only file system, a symlink loop), or another
    /// directory was put at its path while it was checked.
    SocketDirectoryUnusable,
    /// The path's directory is owned by a user other than the server's or root. Its owner
    /// could rename, remove or replace the socket file and the lock file, so neither would
    /// be the server's.
    SocketDirectoryOwnerWrong,
    /// Group or others may write in the path's directory (a sticky directory such as /tmp
    /// included), so another user could put files at the socket's and the lock's paths.
    SocketDirectoryWritable,
    /// The path's directory carries a POSIX access ACL, so its mode alone no longer says
    /// who may change it.
    SocketDirectoryAclPresent,
    /// The lock file at `<path>.lock` isn't a regular file owned by the server's user, with
    /// one link and no permission bits for group or others, so another user may have made
    /// it, or may share it through a hard link.
    SocketLockUnsafe,
    /// Another server holds the path's lock; or a live server, which took no lock, answers
    /// on a socket of the server's user at the path; or a socket there can't be probed (no permission to
    /// connect), so it can't be shown stale; or a process that doesn't take the lock bound
    /// the path, or replaced the socket there, while the stale socket was being replaced;
    /// or such a process removed or replaced the socket file between bind and listen. A
    /// live socket, and any file this call didn't bind, is never removed.
    SocketPathInUse,
    /// A file, a directory, a symlink, a live datagram socket, or a socket of any kind, live
    /// or stale, owned by a user other than the server's, is at the path. It is never
    /// removed, and another user's socket is never probed.
    SocketPathOccupied,
    /// The socket file bind made carries a POSIX access ACL (a default ACL on its directory
    /// gives it one), so its mode no longer says who may connect: the ACL's entries may let
    /// users the mode leaves out connect, or shut out the group the mode names.
    SocketAclPresent,
    /// The kernel wouldn't say whether the socket file carries an access ACL; the errno is
    /// logged.
    SocketAclUnreadable,
    /// The kernel wouldn't say whether the socket's directory carries an access ACL; the
    /// errno is logged.
    SocketDirectoryAclUnreadable,
    /// The socket file bind made doesn't have exactly `listener_socket_mode` (a default ACL
    /// with no named entries on the directory can narrow it), so the clients the mode names
    /// might not connect.
    SocketModeWrong,
    /// A system call failed for a reason none of the above names; the errno is logged.
    ListenFailed,
};

/// Where the socket file came from: the file system and inode bind made. `close`, and `open`
/// on failure, remove the path only while it still names this file, never one someone put
/// there since. The pair names one file only while the listener's socket is open, since the
/// socket holds the inode; so each removal runs before that socket is closed.
const FileId = struct {
    dev_major: u32,
    dev_minor: u32,
    ino: u64,
};

pub const Listener = struct {
    socket: io.Socket,
    /// The lock file, locked exclusively for as long as the listener is open.
    lock: linux.fd_t,
    file: FileId,
    /// The path and its NUL, as bind was given it.
    address: linux.sockaddr.un,
    path_len: u8,

    /// The socket file's path, NUL-terminated.
    pub fn path(self: *const Listener) [:0]const u8 {
        assert(self.path_len > 0 and self.path_len <= path_max);
        assert(self.address.path[self.path_len] == 0);
        return self.address.path[0..self.path_len :0];
    }

    /// Removes the socket file, if the path still names the file bind made, then closes the
    /// socket and last the lock, so no other server binds the path before it is clear.
    /// Failures are logged, not returned: by then the server is stopping, and a file left
    /// behind is replaced by the next `open`.
    pub fn close(self: *Listener) void {
        assert(self.socket >= 0);
        assert(self.lock >= 0 and self.lock != self.socket);
        unlinkIfSame(self.path(), self.file, self.socket);
        closeLogged(self.socket, "socket");
        closeLogged(self.lock, "lock file");
        self.socket = -1;
        self.lock = -1;
    }
};

/// Opens a Unix stream socket listening at `socket_path`, replacing a stale socket a
/// stopped server left there: one a probe connect shows nothing accepts on. It sets the
/// process umask for its one bind call, so it runs before any other thread exists. On
/// failure the socket and lock are closed, and a socket file this call bound is removed
/// while the path still names it; a file put at the path since, by a process that doesn't
/// take the lock, is never removed. Left behind: the lock file, and the socket file itself
/// when its identity couldn't be read right after bind (statx failed), since then nothing
/// tells it from a replacement. The next `open` replaces such a file as stale.
pub fn open(socket_path: []const u8) OpenError!Listener {
    const user = linux.geteuid();
    return openPaused(socket_path, pauseNone, .{ .directory = user, .lock = user, .socket = user });
}

/// Who the directory, the lock file and a stale socket must belong to. `open` names the
/// server's user, the effective user id, for all three; a test names another user for one
/// of them, so each owner check can be seen to refuse without root or a second account.
const Owners = struct {
    directory: linux.uid_t,
    lock: linux.uid_t,
    socket: linux.uid_t,
};

/// Called by `openPaused` between reading the bound file's identity and checking it, with
/// the socket path. `open` passes `pauseNone`; a test passes one that replaces the file at
/// the path, as a process that doesn't take the lock could at that moment. A comptime
/// parameter, so no function pointer exists at run time; with `Owners`, one of this file's
/// two test seams.
const Pause = fn (file_path: [:0]const u8) void;

/// Does nothing, so it has no assertions: there is no state of its own to check, and
/// `openPaused` has already asserted everything about the path.
fn pauseNone(file_path: [:0]const u8) void {
    _ = file_path;
}

/// `open`, with `pause` run once after bind, at the point where a replaced file is most
/// easily mistaken for this call's own, and the files' owners checked against `owners`.
/// `pause` is comptime, so `open` calls `pauseNone` directly, which compiles to nothing.
fn openPaused(socket_path: []const u8, comptime pause: Pause, owners: Owners) OpenError!Listener {
    assert(socket_path.len > 0 and socket_path.len <= path_max);
    assert(socket_path[0] == '/');
    assert(std.mem.findScalar(u8, socket_path, 0) == null);

    var listener: Listener = .{
        .socket = -1,
        .lock = -1,
        .file = undefined,
        .address = .{ .path = @splat(0) },
        .path_len = @intCast(socket_path.len),
    };
    @memcpy(listener.address.path[0..socket_path.len], socket_path);
    const file_path = listener.path();

    // First the directory both files live in: a user who may write there could put a file
    // of their own at either path, so nothing below would prove anything. The lock file is
    // opened through the checked directory's descriptor, so it is in that very directory.
    const dir = try directoryCheck(file_path, owners.directory);
    const locked = takeLock(dir, file_path, owners.lock);
    closeLogged(dir, "socket directory");
    listener.lock = try locked;
    errdefer closeLogged(listener.lock, "lock file");
    listener.socket = try unixSocket(.blocking);
    errdefer closeLogged(listener.socket, "socket");
    try bindReplacingStale(listener.socket, &listener.address, file_path, owners.socket);
    // The lock is held, so the socket at the path is the one bind just made, unless a
    // process that doesn't take the lock replaced it in between; boundFile refuses a path
    // that names no socket. A socket swapped in before boundFile's statx would be taken
    // for this one: Linux has no call that gives a bound socket's file by descriptor, so
    // that window, like the one in removeStale, isn't closed. Until the identity is known
    // nothing is removed on failure.
    listener.file = try boundFile(file_path);
    // Removed on failure only while the path still names that file: a file put there since
    // is someone else's, which is exactly what boundCheck refuses as SocketPathInUse.
    errdefer unlinkIfSame(file_path, listener.file, listener.socket);
    pause(file_path);
    try boundCheck(file_path, listener.file);

    const listened = linux.errno(linux.listen(listener.socket, backlog));
    if (listened != .SUCCESS) {
        std.log.err("listener {s}: listen failed, errno {d}", .{ file_path, @backingInt(listened) });
        return error.ListenFailed;
    }
    try check(listener.socket);
    assert(listener.socket >= 0 and listener.lock >= 0);
    assert(listener.socket != listener.lock);
    return listener;
}

/// Checks that `socket` is a listening Unix stream socket bound to a path: the only kind the
/// server accepts connections on.
pub fn check(socket: io.Socket) CheckError!void {
    assert(socket >= 0);
    const domain = try socketOption(socket, linux.SO.DOMAIN);
    if (domain != linux.AF.UNIX) return error.ListenerNotLocal;
    const kind = try socketOption(socket, linux.SO.TYPE);
    if (kind != linux.SOCK.STREAM) return error.ListenerNotStream;
    var address: linux.sockaddr.un = undefined;
    var address_len: linux.socklen_t = @sizeOf(linux.sockaddr.un);
    switch (linux.errno(linux.getsockname(socket, @ptrCast(&address), &address_len))) {
        .SUCCESS => {},
        else => return error.ListenerUnreadable,
    }
    // An answer longer than the buffer (a 108-byte path with no NUL, bound by some other
    // program) or shorter than the family can't be read as a path: refused.
    if (address_len > @sizeOf(linux.sockaddr.un) or address_len < family_len) return error.ListenerUnreadable;
    // Postcondition of the domain check: getsockname, a second answer about the same
    // descriptor, names the same family. Unlike the answers above, nothing outside this
    // process can make the two disagree: only a bug here (the wrong option read) or a
    // descriptor closed and reused under this call by another part of the server can.
    assert(address.family == linux.AF.UNIX);
    // An unnamed socket's address is the family alone; an abstract one's path starts with
    // a NUL. Neither has a file whose mode decides who may connect. A relative path isn't
    // one the server binds.
    if (address_len == family_len or address.path[0] != '/') return error.ListenerNotOnPath;
    const listening = try socketOption(socket, linux.SO.ACCEPTCONN);
    // SO_ACCEPTCONN is a flag: the kernel answers 0 or 1, and anything else is a kernel
    // this file doesn't know.
    if (listening > 1) return error.ListenerUnreadable;
    if (listening != 1) return error.ListenerNotListening;
}

/// Reads one integer socket option at the socket level.
fn socketOption(socket: io.Socket, name: u32) CheckError!u32 {
    assert(socket >= 0);
    assert(name == linux.SO.DOMAIN or name == linux.SO.TYPE or name == linux.SO.ACCEPTCONN);
    var value: i32 = -1;
    var len: linux.socklen_t = @sizeOf(i32);
    const rc = linux.getsockopt(socket, linux.SOL.SOCKET, name, @ptrCast(&value), &len);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .NOTSOCK => return error.ListenerNotSocket,
        else => return error.ListenerUnreadable,
    }
    // The kernel's answer is checked, not trusted: an answer of another size or a negative
    // value means this file's model of the kernel is wrong.
    if (len != @sizeOf(i32) or value < 0) return error.ListenerUnreadable;
    return @intCast(value);
}

/// Bytes of a Unix socket address before its path: the family alone, as the kernel reports
/// an unnamed socket's address.
const family_len: linux.socklen_t = @offsetOf(linux.sockaddr.un, "path");

/// Opens `<socket_path>.lock` in `dir`, the socket's directory as `directoryCheck` opened
/// it, checks that it belongs to `owner` alone, and locks it exclusively without waiting. A
/// lock held by another process is `SocketPathInUse`.
fn takeLock(dir: linux.fd_t, socket_path: [:0]const u8, owner: linux.uid_t) OpenError!linux.fd_t {
    assert(dir >= 0);
    assert(socket_path.len > 0 and socket_path.len <= path_max);
    assert(socket_path[0] == '/');
    // The full path, for the log lines.
    var bytes: [path_max + lock_suffix.len + 1]u8 = undefined;
    // The buffer holds the longest path, the suffix and the NUL, so this can't overflow.
    const lock_path = std.fmt.bufPrintSentinel(&bytes, "{s}" ++ lock_suffix, .{socket_path}, 0) catch unreachable;
    assert(lock_path.len == socket_path.len + lock_suffix.len);
    // The name inside `dir`: everything after the socket path's last slash, and the suffix.
    // The path starts with a slash, as asserted above, so there is a last one.
    const slash = std.mem.findScalarLast(u8, lock_path, '/') orelse unreachable;
    const lock_name = lock_path[slash + 1 ..];
    assert(lock_name.len >= lock_suffix.len and std.mem.findScalar(u8, lock_name, '/') == null);
    // No symlink is followed, and a FIFO can't stall startup in open.
    const flags: linux.O = .{ .ACCMODE = .RDWR, .CREAT = true, .CLOEXEC = true, .NOFOLLOW = true, .NOCTTY = true, .NONBLOCK = true };
    const opened = linux.openat(dir, lock_name, flags, 0o600);
    const lock: linux.fd_t = switch (pathErrno(linux.errno(opened))) {
        .success => @intCast(opened),
        .directory_unusable => return error.SocketDirectoryUnusable,
        .resources => return error.ListenerUnavailable,
        .failed => {
            std.log.err("listener {s}: open failed, errno {d}", .{ lock_path, @backingInt(linux.errno(opened)) });
            return error.ListenFailed;
        },
    };
    errdefer closeLogged(lock, "lock file");
    // Checked before it is locked, so a file another user made is never held.
    try lockCheck(lock, lock_path, owner);
    const locked = linux.errno(linux.flock(lock, std.posix.LOCK.EX | std.posix.LOCK.NB));
    switch (locked) {
        .SUCCESS => {},
        .AGAIN => return error.SocketPathInUse,
        .NOLCK => return error.ListenerUnavailable,
        else => {
            std.log.err("listener {s}: flock failed, errno {d}", .{ lock_path, @backingInt(locked) });
            return error.ListenFailed;
        },
    }
    assert(lock >= 0);
    return lock;
}

/// Permission bits the socket's directory may not have: write for group or others.
const directory_write_others: u32 = 0o022;

/// Permission bits a lock file may have: the owner's alone.
const lock_mode_allowed: u32 = 0o700;

/// The directory `socket_path` names its file in, written into `bytes`: every byte before
/// the last slash, or the root directory's own slash when that is the only one.
fn directoryOf(socket_path: [:0]const u8, bytes: *[path_max + 1]u8) [:0]const u8 {
    assert(socket_path.len > 0 and socket_path.len <= path_max);
    assert(socket_path[0] == '/');
    // The assertion above proves a slash exists.
    const slash = std.mem.findScalarLast(u8, socket_path, '/') orelse unreachable;
    const len: usize = if (slash == 0) 1 else slash;
    // The directory ends where the file's name begins: at a slash, unless it is the root.
    assert(len == 1 or socket_path[len] == '/');
    @memcpy(bytes[0..len], socket_path[0..len]);
    bytes[len] = 0;
    return bytes[0..len :0];
}

/// What the socket directory's owner and mode allow. Pure, so tests can check owners a test
/// can't make (another user; root, when the test isn't root).
const DirectoryVerdict = enum { ok, owner_wrong, writable };

/// `mode` is the directory's type and mode, `uid` its owner and `user` the server's. Root
/// may own it, as root owns /run: root can already change anything the server has.
fn directoryVerdict(mode: u16, uid: linux.uid_t, user: linux.uid_t) DirectoryVerdict {
    assert(linux.S.ISDIR(mode));
    const owner_ok = uid == user or uid == 0;
    const verdict: DirectoryVerdict = if (!owner_ok)
        .owner_wrong
    else if (mode & directory_write_others != 0)
        .writable
    else
        .ok;
    // The owner is judged first: another user's directory is refused for its owner, never
    // for its mode, so the log names the problem that matters.
    assert(verdict != .writable or owner_ok);
    return verdict;
}

/// Refuses the directory `socket_path` names its file in unless only `owner`, the server's
/// user, or root may change it: owned by one of them, writable by neither group nor others,
/// and carrying no POSIX access ACL. Returns the directory, opened with O_PATH (which needs
/// no permission on it), for the lock file to be opened in; the caller closes it. Its owner
/// and mode are read through that descriptor. Its ACL is read by path, since fgetxattr
/// refuses an O_PATH descriptor and /proc may not be mounted, so afterwards the path must
/// still name the directory opened, or `SocketDirectoryUnusable`. Only the socket's own
/// directory is checked: a user who may write in one above it could swap the whole
/// directory at any time, and nothing here can stop that, since bind takes only a path.
fn directoryCheck(socket_path: [:0]const u8, owner: linux.uid_t) OpenError!linux.fd_t {
    assert(socket_path.len > 0 and socket_path.len <= path_max);
    assert(socket_path[0] == '/');
    var bytes: [path_max + 1]u8 = undefined;
    const dir_path = directoryOf(socket_path, &bytes);
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .PATH = true, .DIRECTORY = true, .CLOEXEC = true };
    const opened = linux.open(dir_path, flags, 0);
    const dir: linux.fd_t = switch (pathErrno(linux.errno(opened))) {
        .success => @intCast(opened),
        .directory_unusable => return error.SocketDirectoryUnusable,
        .resources => return error.ListenerUnavailable,
        .failed => {
            std.log.err("listener {s}: open of the directory failed, errno {d}", .{ dir_path, @backingInt(linux.errno(opened)) });
            return error.ListenFailed;
        },
    };
    errdefer closeLogged(dir, "socket directory");
    const status = try directoryStatus(dir, dir_path);
    switch (directoryVerdict(status.mode, status.uid, owner)) {
        .ok => {},
        .owner_wrong => {
            std.log.info("listener {s}: the directory's owner is user {d}, not the server's user or root", .{ dir_path, status.uid });
            return error.SocketDirectoryOwnerWrong;
        },
        .writable => {
            std.log.info("listener {s}: group or others may write in the directory, mode {o}", .{ dir_path, status.mode & 0o7777 });
            return error.SocketDirectoryWritable;
        },
    }
    try directoryAclCheck(dir_path);
    if (!try sameDirectory(dir_path, status)) {
        std.log.info("listener {s}: another directory was put at the path while it was checked", .{dir_path});
        return error.SocketDirectoryUnusable;
    }
    assert(dir >= 0);
    return dir;
}

/// The type, mode, owner and identity of the directory `dir`, opened at `dir_path`.
fn directoryStatus(dir: linux.fd_t, dir_path: [:0]const u8) OpenError!linux.Statx {
    assert(dir >= 0);
    assert(dir_path.len > 0);
    var status: linux.Statx = undefined;
    const mask: linux.STATX = .{ .TYPE = true, .MODE = true, .UID = true, .INO = true };
    const err = linux.errno(linux.statx(dir, "", linux.AT.EMPTY_PATH, mask, &status));
    try statusErrno(err, dir_path, "the directory");
    if (!status.mask.TYPE or !status.mask.MODE or !status.mask.UID or !status.mask.INO) {
        std.log.err("listener {s}: can't read back the directory", .{dir_path});
        return error.ListenFailed;
    }
    // O_DIRECTORY opened it, so only a kernel that broke that promise reports another type.
    assert(linux.S.ISDIR(status.mode));
    return status;
}

/// Maps a failed statx of `what` at `file_path`: out of memory is `ListenerUnavailable`,
/// anything else `ListenFailed`, with the errno logged. A descriptor's own statx can't be
/// refused for the path, so no errno means the directory is unusable.
fn statusErrno(err: linux.E, file_path: [:0]const u8, what: []const u8) OpenError!void {
    assert(file_path.len > 0);
    assert(what.len > 0);
    switch (pathErrno(err)) {
        .success => {},
        .resources => return error.ListenerUnavailable,
        .directory_unusable, .failed => {
            std.log.err("listener {s}: statx of {s} failed, errno {d}", .{ file_path, what, @backingInt(err) });
            return error.ListenFailed;
        },
    }
}

/// Refuses a directory at `dir_path` that carries a POSIX access ACL. getxattr follows a
/// symlink, as the open of the directory did, so both read the same directory. Like the
/// socket file's query, it passes a size of 0 and copies nothing. A default ACL isn't
/// refused here: it changes who may use the files made in the directory, not the directory,
/// and the socket file it would give an access ACL is refused before listen.
fn directoryAclCheck(dir_path: [:0]const u8) OpenError!void {
    assert(dir_path.len > 0);
    assert(dir_path[0] == '/');
    var unused: [1]u8 = undefined;
    const rc = linux.getxattr(dir_path, acl_access_name, &unused, 0);
    const err = linux.errno(rc);
    // On success rc is the size; a size past u32 is past xattr_size_max, so it saturates.
    const len: u32 = if (err == .SUCCESS) std.math.lossyCast(u32, rc) else 0;
    switch (aclOutcome(err, len)) {
        .none => {},
        .present => return error.SocketDirectoryAclPresent,
        .gone => return error.SocketDirectoryUnusable,
        .unreadable => {
            std.log.err("listener {s}: can't read the directory's ACL, errno {d}, size {d}", .{ dir_path, @backingInt(err), len });
            return error.SocketDirectoryAclUnreadable;
        },
    }
}

/// Whether `dir_path`, following symlinks as the open did, still names the directory whose
/// status `opened` is. A path that names nothing now is false; a statx that fails for any
/// other reason is an error, with its errno logged.
fn sameDirectory(dir_path: [:0]const u8, opened: linux.Statx) OpenError!bool {
    assert(dir_path.len > 0);
    assert(opened.mask.INO and linux.S.ISDIR(opened.mode));
    var status: linux.Statx = undefined;
    const err = linux.errno(linux.statx(linux.AT.FDCWD, dir_path, 0, .{ .TYPE = true, .INO = true }, &status));
    if (err == .NOENT or err == .NOTDIR) return false;
    try statusErrno(err, dir_path, "the directory");
    if (!status.mask.TYPE or !status.mask.INO) {
        std.log.err("listener {s}: can't read back the directory", .{dir_path});
        return error.ListenFailed;
    }
    return linux.S.ISDIR(status.mode) and status.ino == opened.ino and
        status.dev_major == opened.dev_major and status.dev_minor == opened.dev_minor;
}

/// What a lock file's status shows. Pure, so tests can check owners and link counts a test
/// can't make.
const LockVerdict = enum { ok, not_regular, owner_wrong, linked, mode_wide };

/// `mode` is the lock file's type and mode, `uid` its owner, `links` its link count and
/// `user` the server's. Unlike the directory, root's lock file isn't the server's: the
/// server makes its own, and a file it can't have made is someone else's.
fn lockVerdict(mode: u16, uid: linux.uid_t, links: u32, user: linux.uid_t) LockVerdict {
    // statx reported the type, so a mode with no type bits is a bug in the caller.
    assert(mode & linux.S.IFMT != 0);
    const verdict: LockVerdict = if (!linux.S.ISREG(mode))
        .not_regular
    else if (uid != user)
        .owner_wrong
    else if (links != 1)
        .linked
    else if (mode & 0o7777 & ~lock_mode_allowed != 0)
        .mode_wide
    else
        .ok;
    // The kind and the owner are judged before the links and the mode: a file that isn't
    // the server's is refused for that, whatever its mode says.
    assert(verdict != .linked or (linux.S.ISREG(mode) and uid == user));
    assert(verdict != .mode_wide or (uid == user and links == 1));
    return verdict;
}

/// Refuses the lock file `lock`, just opened at `lock_path`, unless it is a regular file
/// `owner` owns, with one link and no permission bits for group or others. Read through the
/// descriptor, so it is the file open returned, whatever is at the path now.
fn lockCheck(lock: linux.fd_t, lock_path: [:0]const u8, owner: linux.uid_t) OpenError!void {
    assert(lock >= 0);
    assert(std.mem.endsWith(u8, lock_path, lock_suffix));
    var status: linux.Statx = undefined;
    const mask: linux.STATX = .{ .TYPE = true, .MODE = true, .NLINK = true, .UID = true };
    const err = linux.errno(linux.statx(lock, "", linux.AT.EMPTY_PATH, mask, &status));
    try statusErrno(err, lock_path, "the lock file");
    if (!status.mask.TYPE or !status.mask.MODE or !status.mask.NLINK or !status.mask.UID) {
        std.log.err("listener {s}: can't read back the lock file", .{lock_path});
        return error.ListenFailed;
    }
    const verdict = lockVerdict(status.mode, status.uid, status.nlink, owner);
    if (verdict == .ok) return;
    std.log.info("listener {s}: lock file refused ({t}): mode {o}, owner {d}, links {d}", .{
        lock_path, verdict, status.mode & 0o7777, status.uid, status.nlink,
    });
    return error.SocketLockUnsafe;
}

const Blocking = enum { blocking, nonblocking };

/// A new Unix stream socket, closed on exec. A nonblocking one is for the probe, whose
/// connect must never wait on a server that doesn't accept.
fn unixSocket(blocking: Blocking) OpenError!io.Socket {
    const nonblocking: u32 = if (blocking == .nonblocking) linux.SOCK.NONBLOCK else 0;
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC | nonblocking, 0);
    const err = linux.errno(rc);
    switch (err) {
        .SUCCESS => {},
        .MFILE, .NFILE, .NOBUFS, .NOMEM, .ACCES => return error.ListenerUnavailable,
        else => {
            std.log.err("listener: socket failed, errno {d}", .{@backingInt(err)});
            return error.ListenFailed;
        },
    }
    assert(rc <= std.math.maxInt(i32));
    const socket: io.Socket = @intCast(rc);
    assert(socket >= 0);
    return socket;
}

/// What a failed call on a path means. Pure, so tests can check every arm.
const PathOutcome = enum { success, directory_unusable, resources, failed };

fn pathErrno(err: linux.E) PathOutcome {
    assert(@backingInt(err) < 4096);
    const outcome: PathOutcome = switch (err) {
        .SUCCESS => .success,
        // A missing or non-directory component, no search or write permission, a
        // read-only file system, a symlink loop or a symlink where none is followed.
        .NOENT, .NOTDIR, .ACCES, .PERM, .ROFS, .LOOP, .NAMETOOLONG => .directory_unusable,
        // Out of descriptors, kernel memory or space for the inode.
        .MFILE, .NFILE, .NOMEM, .NOBUFS, .NOSPC, .DQUOT => .resources,
        // A bad descriptor or address (a bug), an I/O error, or an errno the call isn't
        // documented to return: startup refuses, with the number logged.
        else => .failed,
    };
    assert((outcome == .success) == (err == .SUCCESS));
    return outcome;
}

/// Binds `socket` to `address`. A stale socket at the path is removed and the path bound
/// once more; anything else at the path refuses.
fn bindReplacingStale(socket: io.Socket, address: *const linux.sockaddr.un, file_path: [:0]const u8, owner: linux.uid_t) OpenError!void {
    assert(socket >= 0);
    assert(file_path.len > 0 and address.path[file_path.len] == 0);
    // The family, the path and its NUL, as unix(7) counts an address's length.
    const address_len: linux.socklen_t = @intCast(@offsetOf(linux.sockaddr.un, "path") + file_path.len + 1);
    var attempts: u32 = 0;
    while (attempts < bind_attempts_max) {
        attempts += 1;
        const err = bindMasked(socket, address, address_len);
        if (err == .ADDRINUSE) {
            // Taken a second time, after the stale socket went: a process that doesn't take
            // the lock is binding the path.
            if (attempts == bind_attempts_max) break;
            try removeStale(address, address_len, file_path, owner);
            continue;
        }
        switch (pathErrno(err)) {
            .success => return,
            .directory_unusable => return error.SocketDirectoryUnusable,
            .resources => return error.ListenerUnavailable,
            .failed => {
                std.log.err("listener {s}: bind failed, errno {d}", .{ file_path, @backingInt(err) });
                return error.ListenFailed;
            },
        }
    }
    assert(attempts <= bind_attempts_max);
    return error.SocketPathInUse;
}

/// The umask bind runs under: every permission bit `listener_socket_mode` leaves out.
const bind_umask: u32 = 0o777 & ~socket_mode;

/// Binds `socket` with the umask set to `bind_umask`, so the kernel creates the socket file
/// with exactly `listener_socket_mode`, then puts the process's umask back. Returns bind's
/// errno; umask itself can't fail.
fn bindMasked(socket: io.Socket, address: *const linux.sockaddr.un, address_len: linux.socklen_t) linux.E {
    assert(socket >= 0);
    assert(address.path[0] == '/');
    const previous = linux.syscall1(.umask, bind_umask);
    const err = linux.errno(linux.bind(socket, @ptrCast(address), address_len));
    const replaced = linux.syscall1(.umask, previous);
    // Nothing else set the umask while bind ran: no other thread runs during startup.
    assert(replaced == bind_umask);
    return err;
}

/// What a probe's connect to the socket at the path found. Pure, so tests can check every
/// arm, including those a test can't provoke (a test running as root may always connect).
const ProbeOutcome = enum {
    /// Refused (ECONNREFUSED): no socket there is listening and accepting, so it is stale.
    /// That includes a socket some program has bound but not yet put in listen, or one
    /// whose listener has shut its receive side; the lock is what keeps this server's own
    /// starting copies apart.
    stale,
    /// The path is empty now: bind again.
    gone,
    /// Connected, or the backlog is full (EAGAIN): a live server listens there.
    live,
    /// A live datagram or seqpacket socket (EPROTOTYPE): never the server's, never removed.
    not_stream,
    /// No write permission on the file: it can't be shown stale, so it isn't ours to remove.
    forbidden,
    /// Out of kernel memory or buffers.
    resources,
    /// An errno connect isn't documented to return here: startup refuses, the number logged.
    failed,
};

fn probeOutcome(err: linux.E) ProbeOutcome {
    assert(@backingInt(err) < 4096);
    const outcome: ProbeOutcome = switch (err) {
        .CONNREFUSED => .stale,
        .NOENT => .gone,
        .SUCCESS, .AGAIN => .live,
        .PROTOTYPE => .not_stream,
        .ACCES, .PERM => .forbidden,
        .NOMEM, .NOBUFS => .resources,
        else => .failed,
    };
    // Only a refused connect ever lets the socket be removed.
    assert((outcome == .stale) == (err == .CONNREFUSED));
    return outcome;
}

/// Connects to the socket at `address` without blocking, to learn whether a server answers
/// there, whatever lock it took or didn't. Returns `stale` or `gone`; every other outcome
/// refuses with a named error. The probe's connection, if it gets through, is closed at once.
fn probe(address: *const linux.sockaddr.un, address_len: linux.socklen_t, file_path: [:0]const u8) OpenError!ProbeOutcome {
    assert(address.path[0] == '/');
    assert(address_len == family_len + file_path.len + 1);
    const client = try unixSocket(.nonblocking);
    defer closeLogged(client, "probe socket");
    // A blocking probe would wait forever on a full backlog no server drains.
    const status_flags = linux.fcntl(client, linux.F.GETFL, 0);
    assert(linux.errno(status_flags) == .SUCCESS and status_flags & linux.SOCK.NONBLOCK != 0);
    const err = linux.errno(linux.connect(client, address, address_len));
    const outcome = probeOutcome(err);
    switch (outcome) {
        .stale, .gone => return outcome,
        .live => {
            std.log.info("listener {s}: a live server that holds no lock listens at the path", .{file_path});
            return error.SocketPathInUse;
        },
        .not_stream => return error.SocketPathOccupied,
        .forbidden => {
            std.log.info("listener {s}: may not connect to the socket at the path to test it", .{file_path});
            return error.SocketPathInUse;
        },
        .resources => return error.ListenerUnavailable,
        .failed => {
            std.log.err("listener {s}: probe connect failed, errno {d}", .{ file_path, @backingInt(err) });
            return error.ListenFailed;
        },
    }
}

/// Removes a stale socket at `file_path`: one `owner`, the server's user, owns and nothing
/// listens on, as a probe connect shows. Refuses for a live socket, another user's socket
/// and a file of any other kind.
fn removeStale(address: *const linux.sockaddr.un, address_len: linux.socklen_t, file_path: [:0]const u8, owner: linux.uid_t) OpenError!void {
    assert(file_path.len > 0);
    assert(file_path[0] == '/');
    var status: linux.Statx = undefined;
    const mask: linux.STATX = .{ .TYPE = true, .INO = true, .UID = true };
    const rc = linux.statx(linux.AT.FDCWD, file_path, linux.AT.SYMLINK_NOFOLLOW, mask, &status);
    const err = linux.errno(rc);
    // Gone since bind saw it: bind again.
    if (err == .NOENT) return;
    switch (pathErrno(err)) {
        .success => {},
        .directory_unusable => return error.SocketDirectoryUnusable,
        .resources => return error.ListenerUnavailable,
        .failed => {
            std.log.err("listener {s}: statx failed, errno {d}", .{ file_path, @backingInt(err) });
            return error.ListenFailed;
        },
    }
    // A symlink is reported as one, not followed, so a link to a socket elsewhere is
    // never removed or taken.
    if (!status.mask.TYPE or !linux.S.ISSOCK(status.mode)) return error.SocketPathOccupied;
    if (!status.mask.INO or !status.mask.UID) return error.ListenFailed;
    // Read in the same statx as the type, so the owner is the socket's that was checked:
    // a socket another user left is never this server's to remove, stale or not, and is
    // judged before the probe, so it is never connected to either.
    if (status.uid != owner) {
        std.log.info("listener {s}: the socket at the path is user {d}'s, not the server's", .{ file_path, status.uid });
        return error.SocketPathOccupied;
    }
    const probed: FileId = .{ .dev_major = status.dev_major, .dev_minor = status.dev_minor, .ino = status.ino };
    // Only now, with a socket and not a symlink at the path, is the probe's connect aimed
    // at it; connect follows symlinks, so the path must still name the same socket file
    // afterwards, or what was probed isn't what would be removed. A server that starts
    // listening between the probe and the unlink below still loses its path: only a
    // program that skips the lock can, and nothing closes that window.
    if (try probe(address, address_len, file_path) == .gone) return;
    if (!sameFile(file_path, probed)) {
        std.log.info("listener {s}: the socket file changed while it was probed", .{file_path});
        return error.SocketPathInUse;
    }

    const unlinked = linux.errno(linux.unlink(file_path));
    if (unlinked == .NOENT) return;
    switch (pathErrno(unlinked)) {
        .success => std.log.info("listener {s}: removed a stale socket", .{file_path}),
        .directory_unusable => return error.SocketDirectoryUnusable,
        .resources => return error.ListenerUnavailable,
        .failed => {
            std.log.err("listener {s}: unlink failed, errno {d}", .{ file_path, @backingInt(unlinked) });
            return error.ListenFailed;
        },
    }
}

/// The file system and inode of the socket file bind just made at `file_path`, read once,
/// right after bind, so that every later check and the cleanup on failure can tell this
/// file from one put at the path since. A path that no longer names a socket (removed, or
/// replaced by another kind of file, since bind) is `SocketPathInUse`: no socket there is
/// this call's.
fn boundFile(file_path: [:0]const u8) OpenError!FileId {
    assert(file_path.len > 0);
    assert(file_path[0] == '/');
    var status: linux.Statx = undefined;
    const mask: linux.STATX = .{ .TYPE = true, .INO = true };
    const err = linux.errno(linux.statx(linux.AT.FDCWD, file_path, linux.AT.SYMLINK_NOFOLLOW, mask, &status));
    if (err == .NOENT) return error.SocketPathInUse;
    if (err != .SUCCESS) {
        std.log.err("listener {s}: statx of the socket file failed, errno {d}", .{ file_path, @backingInt(err) });
        return error.ListenFailed;
    }
    if (!status.mask.TYPE or !status.mask.INO) {
        std.log.err("listener {s}: can't read back the socket file", .{file_path});
        return error.ListenFailed;
    }
    if (!linux.S.ISSOCK(status.mode)) return error.SocketPathInUse;
    return .{ .dev_major = status.dev_major, .dev_minor = status.dev_minor, .ino = status.ino };
}

/// Checks the socket file `file` at `file_path` before listen: first that it carries no
/// POSIX access ACL, then that it has exactly `listener_socket_mode`, in that order: with an
/// access ACL the mode's group bits are only the ACL's mask, so a mode read back from such a
/// file proves nothing. The kernel applies the umask itself, but a default ACL on the
/// directory can add an access ACL or narrow the mode, and a file system may rewrite it;
/// each refuses here, before any client could connect. The ACL is queried by path, so the
/// mode is read by a statx that also shows the path still names `file`: otherwise the ACL
/// checked may not be its, and the path is `SocketPathInUse`.
fn boundCheck(file_path: [:0]const u8, file: FileId) OpenError!void {
    assert(file_path.len > 0);
    assert(file_path[0] == '/');
    aclCheck(file_path) catch |err_acl| {
        // A query that failed on a file put at the path since (or on an empty path) says
        // nothing about this one: the path is someone else's.
        if (!sameFile(file_path, file)) return error.SocketPathInUse;
        return err_acl;
    };
    var status: linux.Statx = undefined;
    const mask: linux.STATX = .{ .TYPE = true, .MODE = true, .INO = true };
    const err = linux.errno(linux.statx(linux.AT.FDCWD, file_path, linux.AT.SYMLINK_NOFOLLOW, mask, &status));
    if (err == .NOENT) return error.SocketPathInUse;
    if (err != .SUCCESS) {
        std.log.err("listener {s}: statx of the socket file failed, errno {d}", .{ file_path, @backingInt(err) });
        return error.ListenFailed;
    }
    if (!status.mask.TYPE or !status.mask.MODE or !status.mask.INO) {
        std.log.err("listener {s}: can't read back the socket file", .{file_path});
        return error.ListenFailed;
    }
    const same = linux.S.ISSOCK(status.mode) and status.ino == file.ino and
        status.dev_major == file.dev_major and status.dev_minor == file.dev_minor;
    if (!same) {
        std.log.info("listener {s}: the socket file was replaced before listen", .{file_path});
        return error.SocketPathInUse;
    }
    const mode: u32 = @as(u32, status.mode) & 0o7777;
    modeCheck(mode) catch |err_mode| {
        std.log.err("listener {s}: socket file mode is {o}, not {o}", .{ file_path, mode, socket_mode });
        return err_mode;
    };
    assert(mode == socket_mode);
}

/// Refuses a socket file mode other than exactly `listener_socket_mode`. Pure, so tests can
/// check modes a test can't make bind produce.
fn modeCheck(mode: u32) error{SocketModeWrong}!void {
    assert(mode & ~@as(u32, 0o7777) == 0);
    if (mode != socket_mode) return error.SocketModeWrong;
    assert(mode & bind_umask == 0);
}

/// The extended attribute a file's POSIX access ACL is stored in, as acl(5) names it.
const acl_access_name = "system.posix_acl_access";

/// Bytes of the smallest POSIX ACL in its extended-attribute form: a 4-byte version and the
/// three entries every ACL has (owner, owning group, others), 8 bytes each.
const acl_size_min: u32 = 4 + 3 * 8;

/// Bytes of the largest extended-attribute value Linux reads or writes (XATTR_SIZE_MAX).
const xattr_size_max: u32 = 65536;

/// What a query for a file's POSIX access ACL found. Pure, so tests can check every arm,
/// including those a test can't provoke (a file system without POSIX ACLs, a malformed size).
const AclOutcome = enum {
    /// No POSIX access ACL (ENODATA), or a file system without POSIX ACLs (EOPNOTSUPP, which
    /// Linux also spells ENOTSUP). Other ACL models aren't seen here (see the file's doc).
    none,
    /// The query succeeded with a size an ACL can have, so an access ACL exists. Whatever its
    /// entries say, it is refused: the kernel stores one whenever it isn't the three-entry
    /// form the mode alone expresses.
    present,
    /// The path names nothing (ENOENT): the socket file bind made was removed since, by a
    /// process that doesn't take the lock, so the path is someone else's.
    gone,
    /// Any other errno (a security policy refusing the read, an errno the call isn't
    /// documented to return), or a size no ACL has: startup refuses, logged.
    unreadable,
};

/// `len` is the attribute's size when the query succeeded, and 0 when it failed.
fn aclOutcome(err: linux.E, len: u32) AclOutcome {
    assert(@backingInt(err) < 4096);
    assert(err == .SUCCESS or len == 0);
    // The size comes from the file system, so it is checked, not trusted: an ACL is the
    // version and at least three 8-byte entries, and no attribute is larger than Linux allows.
    const well_formed = len >= acl_size_min and len <= xattr_size_max and (len - 4) % 8 == 0;
    return switch (err) {
        .SUCCESS => if (well_formed) .present else .unreadable,
        .NODATA, .OPNOTSUPP => .none,
        .NOENT => .gone,
        else => .unreadable,
    };
}

/// Refuses a socket file at `file_path` that carries a POSIX access ACL. The query passes a
/// size of 0, so the kernel only reports whether the attribute exists and how long it is,
/// and copies nothing: no buffer is needed, whatever the ACL holds. lgetxattr reads the file
/// at the path itself, never one a symlink there points to.
fn aclCheck(file_path: [:0]const u8) error{ SocketAclPresent, SocketAclUnreadable, SocketPathInUse }!void {
    assert(file_path.len > 0);
    assert(file_path[0] == '/');
    var unused: [1]u8 = undefined;
    const rc = linux.lgetxattr(file_path, acl_access_name, &unused, 0);
    const err = linux.errno(rc);
    // On success rc is the size; a size past u32 is past xattr_size_max, so it saturates.
    const len: u32 = if (err == .SUCCESS) std.math.lossyCast(u32, rc) else 0;
    switch (aclOutcome(err, len)) {
        .none => {},
        // Returned without a log line, like the other refusals with no number to report
        // (SocketPathOccupied, SocketDirectoryUnusable): the error's name says what to fix.
        .present => return error.SocketAclPresent,
        .gone => return error.SocketPathInUse,
        .unreadable => {
            std.log.err("listener {s}: can't read the socket file's ACL, errno {d}, size {d}", .{ file_path, @backingInt(err), len });
            return error.SocketAclUnreadable;
        },
    }
}

/// The file system and inode at `file_path`, without following a symlink, or null when
/// the kernel can't say or the file isn't a socket.
fn fileId(file_path: [:0]const u8) ?FileId {
    assert(file_path.len > 0);
    assert(file_path[0] == '/');
    var status: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, file_path, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true, .INO = true }, &status);
    if (linux.errno(rc) != .SUCCESS) return null;
    if (!status.mask.TYPE or !status.mask.INO) return null;
    if (!linux.S.ISSOCK(status.mode)) return null;
    return .{ .dev_major = status.dev_major, .dev_minor = status.dev_minor, .ino = status.ino };
}

/// Whether `file_path` still names the socket file `file`.
fn sameFile(file_path: [:0]const u8, file: FileId) bool {
    assert(file_path.len > 0);
    assert(file_path[0] == '/');
    const now = fileId(file_path) orelse return false;
    return now.ino == file.ino and now.dev_major == file.dev_major and now.dev_minor == file.dev_minor;
}

/// Removes `file_path` while it still names the socket file `file`, and leaves anything else
/// there: a file put at the path by a process that doesn't take the lock is never this
/// server's to remove. Such a process could still swap the file between the check and the
/// unlink; Linux has no unlink by inode, and the lock is what keeps this server's own
/// copies apart. `socket`, the one bound to `file`, must still be open: it holds the file's
/// inode, so no file put at the path since can have been given the same number. Once it
/// is closed, a file system such as ext4 hands the freed number to the next file at once.
fn unlinkIfSame(file_path: [:0]const u8, file: FileId, socket: io.Socket) void {
    assert(file_path.len > 0 and file_path[0] == '/');
    assert(socket >= 0);
    assert(linux.errno(linux.fcntl(socket, linux.F.GETFD, 0)) == .SUCCESS);
    if (sameFile(file_path, file)) {
        unlinkLogged(file_path);
    } else if (linux.errno(linux.access(file_path, linux.F_OK)) == .NOENT) {
        std.log.info("listener {s}: the socket file was already removed", .{file_path});
    } else {
        std.log.info("listener {s}: left a file someone else put at the path", .{file_path});
    }
}

/// Removes `file_path`, logging any failure but a file already gone.
fn unlinkLogged(file_path: [:0]const u8) void {
    assert(file_path.len > 0);
    assert(file_path[0] == '/');
    const err = linux.errno(linux.unlink(file_path));
    switch (err) {
        .SUCCESS, .NOENT => {},
        else => std.log.warn("listener {s}: unlink failed, errno {d}", .{ file_path, @backingInt(err) }),
    }
}

/// Closes `fd`, logging a failure. Linux releases the descriptor even when close reports
/// an error, so there is nothing to retry.
fn closeLogged(fd: linux.fd_t, what: []const u8) void {
    assert(fd >= 0);
    assert(what.len > 0);
    const err = linux.errno(linux.close(fd));
    if (err != .SUCCESS) std.log.warn("listener: close of the {s} failed, errno {d}", .{ what, @backingInt(err) });
}

const testing = std.testing;

/// Longest test directory path. Reason: "/tmp/cc-listener-", 16 hex digits of random
/// bytes, "-" and a tag of at most 8 bytes, well inside `config_socket_path_max` so a file
/// name still fits.
const test_dir_max: u32 = 48;

/// Entries one test directory may hold when it is removed. Reason: the busiest test makes
/// four files and their locks; one getdents64 call reads them all.
const test_dir_entries_max: u32 = 16;

/// A fresh directory under /tmp for one test, mode 0700, named by random bytes and a tag,
/// so runs sharing /tmp (parallel CI jobs, containers with equal pids) never share a path.
const TestDir = struct {
    bytes: [test_dir_max + 1]u8,
    len: u8,

    fn create(self: *TestDir, tag: []const u8) !void {
        assert(tag.len > 0 and tag.len <= 8);
        var random: [8]u8 = undefined;
        const drawn = linux.getrandom(&random, random.len, 0);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(drawn));
        try testing.expectEqual(random.len, drawn);
        const dir = try std.fmt.bufPrintSentinel(&self.bytes, "/tmp/cc-listener-{x}-{s}", .{
            std.mem.readInt(u64, &random, .little), tag,
        }, 0);
        self.len = @intCast(dir.len);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mkdir(dir, 0o700)));
        assert(self.bytes[self.len] == 0);
    }

    fn path(self: *const TestDir) [:0]const u8 {
        assert(self.len > 0);
        assert(self.bytes[self.len] == 0);
        return self.bytes[0..self.len :0];
    }

    /// `name` inside the directory, written into the caller's `buffer`.
    fn file(self: *const TestDir, buffer: *[path_max + 1]u8, name: []const u8) [:0]const u8 {
        assert(name.len > 0);
        assert(self.len + 1 + name.len <= path_max);
        // The assertion above proves the path and its NUL fit the buffer.
        return std.fmt.bufPrintSentinel(buffer, "{s}/{s}", .{ self.path(), name }, 0) catch unreachable;
    }

    /// Removes everything in the directory, then the directory, so a failed test leaves
    /// nothing behind either. Failures are logged rather than asserted, so they never hide
    /// the failure that left the files there.
    fn remove(self: *const TestDir) void {
        assert(self.len > 0);
        const opened = linux.open(self.path(), .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        if (linux.errno(opened) != .SUCCESS) return std.log.warn("test dir {s}: open failed", .{self.path()});
        const dir: linux.fd_t = @intCast(opened);
        defer closeLogged(dir, "test directory");
        var buffer: [4096]u8 align(@alignOf(linux.dirent64)) = undefined;
        const read = linux.getdents64(dir, &buffer, buffer.len);
        if (linux.errno(read) != .SUCCESS) return std.log.warn("test dir {s}: getdents64 failed", .{self.path()});
        var offset: usize = 0;
        var entries: u32 = 0;
        while (offset < read and entries < test_dir_entries_max + 2) : (entries += 1) {
            const entry: *const linux.dirent64 = @ptrCast(@alignCast(&buffer[offset]));
            offset += entry.reclen;
            const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&entry.name)), 0);
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
            const flags: u32 = if (entry.type == linux.DT.DIR) linux.AT.REMOVEDIR else 0;
            const removed = linux.errno(linux.unlinkat(dir, @ptrCast(&entry.name), flags));
            if (removed != .SUCCESS) std.log.warn("test dir {s}: unlinkat {s} failed", .{ self.path(), name });
        }
        assert(entries <= test_dir_entries_max + 2);
        if (linux.errno(linux.rmdir(self.path())) != .SUCCESS) std.log.warn("test dir {s}: rmdir failed", .{self.path()});
    }
};

/// Whether something of any kind is at `file_path`, a dangling symlink included.
fn exists(file_path: [:0]const u8) !bool {
    assert(file_path.len > 0);
    assert(file_path[0] == '/');
    var status: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, file_path, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &status);
    const err = linux.errno(rc);
    if (err != .SUCCESS and err != .NOENT) return error.TestUnexpectedResult;
    return err == .SUCCESS;
}

/// Connects a new blocking client to the Unix socket at `file_path` and returns the
/// connect's errno, closing the client again.
fn connectTo(file_path: [:0]const u8) !linux.E {
    assert(file_path.len > 0 and file_path.len <= path_max);
    var address: linux.sockaddr.un = .{ .path = @splat(0) };
    @memcpy(address.path[0..file_path.len], file_path);
    const client = try unixSocket(.blocking);
    defer closeLogged(client, "test client");
    const len: linux.socklen_t = @intCast(@offsetOf(linux.sockaddr.un, "path") + file_path.len + 1);
    assert(address.path[file_path.len] == 0);
    return linux.errno(linux.connect(client, &address, len));
}

/// Expects `open` to refuse `file_path` with `expected`. A listener opened by mistake is
/// closed again, so a failing test leaks no descriptor and holds no lock.
fn expectOpenError(expected: OpenError, file_path: [:0]const u8) !void {
    assert(file_path.len > 0);
    assert(file_path[0] == '/');
    if (open(file_path)) |opened| {
        var listener = opened;
        listener.close();
        return error.TestUnexpectedResult;
    } else |err| try testing.expectEqual(expected, err);
}

/// Leaves a stale socket at `file_path`: bound and listened on, then dropped without
/// `close`, as a server that crashed leaves it. Its lock goes with it, as the kernel drops
/// a dead process's locks.
fn leaveStaleSocket(file_path: [:0]const u8) !void {
    assert(file_path.len > 0);
    const stale = try open(file_path);
    assert(stale.socket >= 0 and stale.lock >= 0);
    closeLogged(stale.socket, "socket");
    closeLogged(stale.lock, "lock file");
    try testing.expect(try exists(file_path));
}

test "listener: open listens on a Unix stream socket at the path, and close removes it" {
    var dir: TestDir = undefined;
    try dir.create("open");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");

    var listener = try open(file_path);
    var open_now = true;
    defer if (open_now) listener.close();
    try testing.expectEqualStrings(file_path, listener.path());
    try check(listener.socket);
    try testing.expect(sameFile(file_path, listener.file));
    // Both descriptors are closed on exec, so a child process never inherits them.
    for ([_]linux.fd_t{ listener.socket, listener.lock }) |fd| {
        const descriptor_flags = linux.fcntl(fd, linux.F.GETFD, 0);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(descriptor_flags));
        try testing.expect(descriptor_flags & linux.FD_CLOEXEC != 0);
    }
    // The socket file has exactly the configured mode, whatever the umask.
    var status: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, file_path, linux.AT.SYMLINK_NOFOLLOW, .{ .MODE = true }, &status);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    try testing.expectEqual(@as(u32, socket_mode), @as(u32, status.mode) & 0o7777);
    // A client connects through the path.
    try testing.expectEqual(linux.E.SUCCESS, try connectTo(file_path));

    open_now = false;
    listener.close();
    try testing.expectEqual(@as(io.Socket, -1), listener.socket);
    try testing.expect(!try exists(file_path));
    try testing.expectEqual(linux.E.NOENT, try connectTo(file_path));
}

test "listener: a path of config_socket_path_max bytes opens" {
    var dir: TestDir = undefined;
    try dir.create("long");
    defer dir.remove();
    const name_len = path_max - dir.len - 1;
    const name: [path_max]u8 = @splat('s');
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, name[0..name_len]);
    try testing.expectEqual(@as(usize, path_max), file_path.len);

    var listener = try open(file_path);
    defer listener.close();
    try testing.expectEqual(@as(usize, path_max), listener.path().len);
    try testing.expectEqual(linux.E.SUCCESS, try connectTo(file_path));
}

test "listener: a stale socket a stopped server left is replaced" {
    var dir: TestDir = undefined;
    try dir.create("stale");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");
    try leaveStaleSocket(file_path);
    try testing.expectEqual(linux.E.CONNREFUSED, try connectTo(file_path));

    var listener = try open(file_path);
    defer listener.close();
    try testing.expectEqual(linux.E.SUCCESS, try connectTo(file_path));
}

/// A socket of `kind` bound at `file_path` by a program that never takes the lock, as some
/// unrelated program serving that path would. Listening when `listening`.
fn bindUnlocked(file_path: [:0]const u8, kind: u32, listening: bool) !io.Socket {
    assert(file_path.len > 0 and file_path.len <= path_max);
    assert(kind == linux.SOCK.STREAM or kind == linux.SOCK.DGRAM);
    var address: linux.sockaddr.un = .{ .path = @splat(0) };
    @memcpy(address.path[0..file_path.len], file_path);
    const rc = linux.socket(linux.AF.UNIX, kind | linux.SOCK.CLOEXEC, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    const socket: io.Socket = @intCast(rc);
    errdefer closeLogged(socket, "test socket");
    const len: linux.socklen_t = @intCast(family_len + file_path.len + 1);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.bind(socket, @ptrCast(&address), len)));
    if (listening) try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.listen(socket, 4)));
    return socket;
}

test "listener: a live socket another service holds, with no lock, is SocketPathInUse and kept" {
    var dir: TestDir = undefined;
    try dir.create("live");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");
    const other = try bindUnlocked(file_path, linux.SOCK.STREAM, true);
    defer closeLogged(other, "test socket");
    const before = fileId(file_path) orelse return error.TestUnexpectedResult;

    try expectOpenError(error.SocketPathInUse, file_path);
    // The other service's socket is the same file and still takes connections.
    try testing.expect(sameFile(file_path, before));
    try testing.expectEqual(linux.E.SUCCESS, try connectTo(file_path));
}

test "listener: a live socket with a full backlog is SocketPathInUse and kept" {
    var dir: TestDir = undefined;
    try dir.create("backlog");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");
    var address: linux.sockaddr.un = .{ .path = @splat(0) };
    @memcpy(address.path[0..file_path.len], file_path);
    const len: linux.socklen_t = @intCast(family_len + file_path.len + 1);
    const other = try bindUnlocked(file_path, linux.SOCK.STREAM, false);
    defer closeLogged(other, "test socket");
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.listen(other, 0)));
    // Fill the backlog with connects nobody accepts, until a nonblocking one would wait.
    var clients: [4]io.Socket = @splat(-1);
    defer for (clients) |client| if (client >= 0) closeLogged(client, "test client");
    var full = false;
    for (&clients) |*client| {
        client.* = try unixSocket(.nonblocking);
        const err = linux.errno(linux.connect(client.*, &address, len));
        if (err == .AGAIN) {
            full = true;
            break;
        }
        try testing.expectEqual(linux.E.SUCCESS, err);
    }
    try testing.expect(full);
    const before = fileId(file_path) orelse return error.TestUnexpectedResult;

    try expectOpenError(error.SocketPathInUse, file_path);
    try testing.expect(sameFile(file_path, before));
}

test "listener: a socket bound but not listening, with no lock, is stale and replaced" {
    var dir: TestDir = undefined;
    try dir.create("unlisten");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");
    const other = try bindUnlocked(file_path, linux.SOCK.STREAM, false);
    defer closeLogged(other, "test socket");
    const before = fileId(file_path) orelse return error.TestUnexpectedResult;

    var listener = try open(file_path);
    defer listener.close();
    try testing.expect(!sameFile(file_path, before));
    try testing.expectEqual(linux.E.SUCCESS, try connectTo(file_path));
}

test "listener: a datagram socket at the path is SocketPathOccupied and kept" {
    var dir: TestDir = undefined;
    try dir.create("dgram");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");
    const other = try bindUnlocked(file_path, linux.SOCK.DGRAM, false);
    defer closeLogged(other, "test socket");
    const before = fileId(file_path) orelse return error.TestUnexpectedResult;

    try expectOpenError(error.SocketPathOccupied, file_path);
    try testing.expect(sameFile(file_path, before));
}

/// Sets the process's umask and returns the one it replaces.
fn setUmask(mask: u32) u32 {
    assert(mask & ~@as(u32, 0o777) == 0);
    const previous = linux.syscall1(.umask, mask);
    assert(previous <= 0o777);
    return @intCast(previous);
}

test "listener: the socket file has exactly the configured mode under any umask, which is put back" {
    var dir: TestDir = undefined;
    try dir.create("umask");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");
    const original = setUmask(0);
    defer _ = setUmask(original);

    // 0 would leave the file 0777; 077 would lock the group, and so nginx, out; 0777
    // would leave nobody able to connect. 0 comes first because the lock file, made by the
    // first open, keeps the mode that open's umask gives it: under 0777 it would be 000,
    // and every later open by a user other than root would fail.
    for ([_]u32{ 0, 0o022, 0o077, 0o777 }) |mask| {
        _ = setUmask(mask);
        var listener = try open(file_path);
        defer listener.close();
        try testing.expectEqual(mask, setUmask(mask));
        var status: linux.Statx = undefined;
        const rc = linux.statx(linux.AT.FDCWD, file_path, linux.AT.SYMLINK_NOFOLLOW, .{ .MODE = true }, &status);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
        try testing.expectEqual(socket_mode, @as(u32, status.mode) & 0o7777);
    }
    // A bind that fails puts the umask back too: a dangling symlink at the path makes bind
    // return EADDRINUSE, after the lock is taken.
    const dangling = dir.file(&buffer, "dangling.sock");
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.symlink("/nonexistent/cc.sock", dangling)));
    _ = setUmask(0o022);
    try expectOpenError(error.SocketPathOccupied, dangling);
    try testing.expectEqual(@as(u32, 0o022), setUmask(0o022));
}

test "listener: a socket file mode other than exactly the configured one is refused" {
    try modeCheck(socket_mode);
    for ([_]u32{ 0o600, 0o640, 0o666, 0o670, 0o760, 0o000, 0o4660, 0o1660 }) |mode| {
        try testing.expectError(error.SocketModeWrong, modeCheck(mode));
    }
}

const AclTag = enum(u16) {
    user_obj = 0x01,
    user = 0x02,
    group_obj = 0x04,
    group = 0x08,
    mask = 0x10,
    other = 0x20,
};

/// One entry of a test ACL: a tag, rwx bits and, for a named user or group, its id.
const AclEntry = struct { tag: AclTag, perm: u16, id: u32 = std.math.maxInt(u32) };

/// Entries a test ACL may hold. Reason: the largest test ACL, owner, one named user,
/// owning group, mask and others, has five.
const test_acl_entries_max: u32 = 5;

/// Bytes of the largest test ACL in the kernel's extended-attribute form.
const test_acl_size_max: u32 = 4 + 8 * test_acl_entries_max;

/// Writes `entries` into `buffer` in the extended-attribute form setxattr takes: a 4-byte
/// version, then per entry a u16 tag, a u16 permission set and a u32 id, all little-endian.
/// The entries must already be in the order the kernel accepts: by tag, then by id, with a
/// mask whenever a named user or group is present (acl(5)), or setxattr refuses them.
fn testAclBytes(entries: []const AclEntry, buffer: *[test_acl_size_max]u8) []const u8 {
    assert(entries.len >= 3 and entries.len <= test_acl_entries_max);
    var named: u32 = 0;
    var masks: u32 = 0;
    std.mem.writeInt(u32, buffer[0..4], 2, .little); // POSIX_ACL_XATTR_VERSION
    for (entries, 0..) |entry, index| {
        assert(entry.perm <= 7);
        if (index > 0) {
            const before = entries[index - 1];
            const tag = @backingInt(entry.tag);
            const tag_before = @backingInt(before.tag);
            assert(tag > tag_before or (tag == tag_before and entry.id > before.id));
        }
        if (entry.tag == .user or entry.tag == .group) named += 1;
        if (entry.tag == .mask) masks += 1;
        const at = 4 + 8 * index;
        assert(at + 8 <= buffer.len);
        std.mem.writeInt(u16, buffer[at..][0..2], @backingInt(entry.tag), .little);
        std.mem.writeInt(u16, buffer[at + 2 ..][0..2], entry.perm, .little);
        std.mem.writeInt(u32, buffer[at + 4 ..][0..4], entry.id, .little);
    }
    assert(masks <= 1 and (named == 0 or masks == 1));
    return buffer[0 .. 4 + 8 * entries.len];
}

/// A default ACL like `setfacl -d -m u:nobody:rwx,g::---` leaves: the owner, user 65534
/// (nobody) and the mask rwx, the owning group and others nothing. A socket made under it
/// reads mode 0660, yet nobody may connect and the owning group may not.
const acl_nobody_in_group_out = [_]AclEntry{
    .{ .tag = .user_obj, .perm = 7 },
    .{ .tag = .user, .perm = 7, .id = 65534 },
    .{ .tag = .group_obj, .perm = 0 },
    .{ .tag = .mask, .perm = 7 },
    .{ .tag = .other, .perm = 0 },
};

/// The same with a read-only mask: a socket made under it reads mode 0640, which the mode
/// check would refuse too, so it pins that the ACL check runs first.
const acl_nobody_mask_read = [_]AclEntry{
    .{ .tag = .user_obj, .perm = 7 },
    .{ .tag = .user, .perm = 7, .id = 65534 },
    .{ .tag = .group_obj, .perm = 7 },
    .{ .tag = .mask, .perm = 4 },
    .{ .tag = .other, .perm = 0 },
};

/// Gives the directory at `dir_path` a default ACL of `entries`. The test needs /tmp on a
/// file system with POSIX ACLs (ext4, xfs, btrfs and tmpfs have them): one that refuses
/// fails the test with the errno, never skips it.
fn setDefaultAcl(dir_path: [:0]const u8, entries: []const AclEntry) !void {
    assert(dir_path.len > 0);
    assert(dir_path[0] == '/');
    var buffer: [test_acl_size_max]u8 = undefined;
    const acl = testAclBytes(entries, &buffer);
    const err = linux.errno(linux.setxattr(dir_path, "system.posix_acl_default", acl.ptr, acl.len, 0));
    if (err != .SUCCESS) std.log.warn("test dir {s}: setxattr of a default ACL failed, errno {d}", .{ dir_path, @backingInt(err) });
    try testing.expectEqual(linux.E.SUCCESS, err);
}

/// Whether the access ACL at `file_path` (read without following a symlink) holds a
/// named-user entry for `id`.
fn aclNamesUser(file_path: [:0]const u8, id: u32) !bool {
    assert(file_path.len > 0);
    assert(file_path[0] == '/');
    var buffer: [test_acl_size_max]u8 = undefined;
    const rc = linux.lgetxattr(file_path, acl_access_name, &buffer, buffer.len);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    try testing.expect(rc >= acl_size_min and rc <= buffer.len and (rc - 4) % 8 == 0);
    var at: usize = 4;
    var entries: u32 = 0;
    while (at + 8 <= rc and entries < test_acl_entries_max) : (entries += 1) {
        const tag = std.mem.readInt(u16, buffer[at..][0..2], .little);
        const entry_id = std.mem.readInt(u32, buffer[at + 4 ..][0..4], .little);
        if (tag == @backingInt(AclTag.user) and entry_id == id) return true;
        at += 8;
    }
    assert(entries <= test_acl_entries_max);
    return false;
}

test "listener: a default ACL on the directory leaves the mode right but adds an access ACL" {
    // The gap the ACL check closes: under the umask open uses, a socket bound in a directory
    // with a default ACL naming another user reads exactly listener_socket_mode, so the mode
    // check alone passes it, yet its access ACL names that user.
    var dir: TestDir = undefined;
    try dir.create("aclmode");
    defer dir.remove();
    try setDefaultAcl(dir.path(), &acl_nobody_in_group_out);
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "other.sock");
    const original = setUmask(bind_umask);
    const socket = bindUnlocked(file_path, linux.SOCK.STREAM, false);
    _ = setUmask(original);
    closeLogged(try socket, "test socket");
    var status: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, file_path, linux.AT.SYMLINK_NOFOLLOW, .{ .MODE = true }, &status);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    try modeCheck(@as(u32, status.mode) & 0o7777);
    try testing.expect(try aclNamesUser(file_path, 65534));
    try testing.expectError(error.SocketAclPresent, aclCheck(file_path));
    // A symlink to that socket is read as the link, which carries no ACL, never the socket.
    const link = dir.file(&buffer, "link.sock");
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.symlink("other.sock", link)));
    try aclCheck(link);
}

test "listener: a socket that a directory's default ACL gives an access ACL is refused, and nothing is left" {
    var dir: TestDir = undefined;
    try dir.create("acl");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");

    // The fresh directory carries no default ACL (none inherited from /tmp), so it opens.
    var none: [1]u8 = undefined;
    const inherited = linux.lgetxattr(dir.path(), "system.posix_acl_default", &none, 0);
    try testing.expectEqual(linux.E.NODATA, linux.errno(inherited));
    {
        var plain = try open(file_path);
        defer plain.close();
    }

    try setDefaultAcl(dir.path(), &acl_nobody_in_group_out);
    try expectOpenError(error.SocketAclPresent, file_path);
    // The refused open removed the socket file it bound and released the lock.
    try testing.expect(!try exists(file_path));

    // A mask that also narrows the mode to 0640 is still SocketAclPresent: the ACL is
    // checked before the mode, which an access ACL makes meaningless.
    try setDefaultAcl(dir.path(), &acl_nobody_mask_read);
    try expectOpenError(error.SocketAclPresent, file_path);
    try testing.expect(!try exists(file_path));

    // With the default ACL gone, the same path opens again, so the lock was released.
    const removed = linux.errno(linux.removexattr(dir.path(), "system.posix_acl_default"));
    try testing.expectEqual(linux.E.SUCCESS, removed);
    var again = try open(file_path);
    defer again.close();
    try check(again.socket);
}

test "listener: every ACL query outcome, and only a well-formed successful query is an ACL" {
    try testing.expectEqual(AclOutcome.present, aclOutcome(.SUCCESS, acl_size_min));
    try testing.expectEqual(AclOutcome.present, aclOutcome(.SUCCESS, 44));
    try testing.expectEqual(AclOutcome.present, aclOutcome(.SUCCESS, xattr_size_max - 4));
    // Sizes no ACL has: empty, short, between entries, and past the largest attribute.
    for ([_]u32{ 0, 4, acl_size_min - 8, acl_size_min - 1, 45, xattr_size_max + 4, std.math.maxInt(u32) }) |len| {
        try testing.expectEqual(AclOutcome.unreadable, aclOutcome(.SUCCESS, len));
    }
    try testing.expectEqual(AclOutcome.none, aclOutcome(.NODATA, 0));
    try testing.expectEqual(AclOutcome.none, aclOutcome(.OPNOTSUPP, 0));
    try testing.expectEqual(AclOutcome.gone, aclOutcome(.NOENT, 0));
    const unreadable = [_]linux.E{ .ACCES, .PERM, .RANGE, .@"2BIG", .NOMEM, .IO, .FAULT, .NOTDIR, .LOOP };
    for (unreadable) |err| try testing.expectEqual(AclOutcome.unreadable, aclOutcome(err, 0));
    // A number std has no name for.
    try testing.expectEqual(AclOutcome.unreadable, aclOutcome(@fromBackingInt(@intCast(4000)), 0));
}

test "listener: every probe errno has an outcome, and only a refused connect is stale" {
    try testing.expectEqual(ProbeOutcome.stale, probeOutcome(.CONNREFUSED));
    try testing.expectEqual(ProbeOutcome.gone, probeOutcome(.NOENT));
    try testing.expectEqual(ProbeOutcome.live, probeOutcome(.SUCCESS));
    try testing.expectEqual(ProbeOutcome.live, probeOutcome(.AGAIN));
    try testing.expectEqual(ProbeOutcome.not_stream, probeOutcome(.PROTOTYPE));
    try testing.expectEqual(ProbeOutcome.forbidden, probeOutcome(.ACCES));
    try testing.expectEqual(ProbeOutcome.forbidden, probeOutcome(.PERM));
    try testing.expectEqual(ProbeOutcome.resources, probeOutcome(.NOMEM));
    try testing.expectEqual(ProbeOutcome.resources, probeOutcome(.NOBUFS));
    const failed = [_]linux.E{ .BADF, .INVAL, .NOTSOCK, .FAULT, .ISCONN, .TIMEDOUT, .CONNRESET, .LOOP };
    for (failed) |err| try testing.expectEqual(ProbeOutcome.failed, probeOutcome(err));
    try testing.expectEqual(ProbeOutcome.failed, probeOutcome(@fromBackingInt(@intCast(4000))));
}

test "listener: a second server on the same path is SocketPathInUse; the first keeps it" {
    var dir: TestDir = undefined;
    try dir.create("inuse");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");
    var first = try open(file_path);
    defer first.close();

    try expectOpenError(error.SocketPathInUse, file_path);
    // The first server's socket is untouched: same file, still taking connections.
    try testing.expect(sameFile(file_path, first.file));
    try testing.expectEqual(linux.E.SUCCESS, try connectTo(file_path));
}

/// Binds a socket at `file_path` and drops it, taking no lock.
fn leaveStaleSocketUnlocked(file_path: [:0]const u8) !void {
    assert(file_path.len > 0);
    var address: linux.sockaddr.un = .{ .path = @splat(0) };
    @memcpy(address.path[0..file_path.len], file_path);
    const socket = try unixSocket(.blocking);
    defer closeLogged(socket, "socket");
    const len: linux.socklen_t = @intCast(@offsetOf(linux.sockaddr.un, "path") + file_path.len + 1);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.bind(socket, @ptrCast(&address), len)));
    assert(socket >= 0);
}

test "listener: a file, a directory or a symlink at the path is SocketPathOccupied and kept" {
    var dir: TestDir = undefined;
    try dir.create("occupied");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;

    const regular = dir.file(&buffer, "file");
    const flags: linux.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true };
    const created = linux.open(regular, flags, 0o600);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(created));
    closeLogged(@intCast(created), "test file");
    try expectOpenError(error.SocketPathOccupied, regular);
    try testing.expect(try exists(regular));

    const directory = dir.file(&buffer, "dir");
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mkdir(directory, 0o700)));
    try expectOpenError(error.SocketPathOccupied, directory);
    try testing.expect(try exists(directory));

    // A symlink to a stale socket: the link is neither followed nor removed, and the
    // socket it points to stays too.
    var target_buffer: [path_max + 1]u8 = undefined;
    const target = dir.file(&target_buffer, "target.sock");
    try leaveStaleSocket(target);
    const link = dir.file(&buffer, "link.sock");
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.symlink(target, link)));
    try expectOpenError(error.SocketPathOccupied, link);
    try testing.expect(try exists(link));
    try testing.expect(try exists(target));

    // A dangling symlink: bind refuses it as taken, and it stays.
    const dangling = dir.file(&buffer, "dangling.sock");
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.symlink("/nonexistent/cc.sock", dangling)));
    try expectOpenError(error.SocketPathOccupied, dangling);
    try testing.expect(try exists(dangling));
}

test "listener: a missing directory is SocketDirectoryUnusable" {
    var dir: TestDir = undefined;
    try dir.create("missing");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    try expectOpenError(error.SocketDirectoryUnusable, dir.file(&buffer, "absent/app.sock"));
    try testing.expect(!try exists(dir.file(&buffer, "absent")));

    // A regular file where the directory should be.
    const regular = dir.file(&buffer, "file");
    const flags: linux.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true };
    const created = linux.open(regular, flags, 0o600);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(created));
    closeLogged(@intCast(created), "test file");
    try expectOpenError(error.SocketDirectoryUnusable, dir.file(&buffer, "file/app.sock"));
}

/// Sets the mode of `file_path` (following a symlink) and fails the test if it can't.
fn setMode(file_path: [:0]const u8, mode: u32) !void {
    assert(file_path.len > 0 and file_path[0] == '/');
    assert(mode & ~@as(u32, 0o7777) == 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.chmod(file_path, mode)));
}

test "listener: a directory group or others may write in is refused before anything is made there" {
    var dir: TestDir = undefined;
    try dir.create("dirmode");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");
    var lock_buffer: [path_max + 1]u8 = undefined;
    const lock_path = dir.file(&lock_buffer, "app.sock.lock");
    // Put back before dir.remove runs, whatever fails in between; a failure is logged and
    // fails the test through that log line.
    defer setMode(dir.path(), 0o700) catch std.log.err("test dir {s}: mode not put back", .{dir.path()});

    // World-writable, group-writable, writable by others alone, and sticky like /tmp.
    for ([_]u32{ 0o777, 0o770, 0o730, 0o702, 0o1777, 0o1733 }) |mode| {
        try setMode(dir.path(), mode);
        try expectOpenError(error.SocketDirectoryWritable, file_path);
        // Refused before the lock: neither the lock file nor the socket was made.
        try testing.expect(!try exists(lock_path));
        try testing.expect(!try exists(file_path));
    }
    // Readable and searchable by others is fine: only writing lets them put files there.
    for ([_]u32{ 0o700, 0o750, 0o755, 0o711 }) |mode| {
        try setMode(dir.path(), mode);
        var listener = try open(file_path);
        defer listener.close();
        try check(listener.socket);
    }
}

test "listener: a directory that carries an access ACL is refused, even one that grants no write" {
    var dir: TestDir = undefined;
    try dir.create("diracl");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");

    // Nobody gets r-x through a r-x mask, so the mode reads 0750 and the writable check
    // alone would pass the directory: only the ACL check refuses it.
    const entries = [_]AclEntry{
        .{ .tag = .user_obj, .perm = 7 },
        .{ .tag = .user, .perm = 5, .id = 65534 },
        .{ .tag = .group_obj, .perm = 5 },
        .{ .tag = .mask, .perm = 5 },
        .{ .tag = .other, .perm = 0 },
    };
    var acl_buffer: [test_acl_size_max]u8 = undefined;
    const acl = testAclBytes(&entries, &acl_buffer);
    const set = linux.errno(linux.setxattr(dir.path(), acl_access_name, acl.ptr, acl.len, 0));
    if (set != .SUCCESS) std.log.warn("test dir {s}: setxattr of an access ACL failed, errno {d}", .{ dir.path(), @backingInt(set) });
    try testing.expectEqual(linux.E.SUCCESS, set);
    var status: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, dir.path(), 0, .{ .MODE = true }, &status);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    try testing.expectEqual(@as(u32, 0o750), @as(u32, status.mode) & 0o7777);

    try expectOpenError(error.SocketDirectoryAclPresent, file_path);
    try testing.expect(!try exists(file_path));

    // With the ACL gone, the same directory opens.
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.removexattr(dir.path(), acl_access_name)));
    var listener = try open(file_path);
    defer listener.close();
    try check(listener.socket);
}

test "listener: every directory owner and mode has a verdict, and only the server's or root's private one passes" {
    const user: linux.uid_t = 1000;
    const other: linux.uid_t = 1001;
    const Case = struct { uid: linux.uid_t, mode: u16, user: linux.uid_t, expected: DirectoryVerdict };
    const cases = [_]Case{
        .{ .uid = user, .mode = 0o700, .user = user, .expected = .ok },
        .{ .uid = user, .mode = 0o755, .user = user, .expected = .ok },
        .{ .uid = 0, .mode = 0o755, .user = user, .expected = .ok },
        .{ .uid = 0, .mode = 0o700, .user = 0, .expected = .ok },
        .{ .uid = other, .mode = 0o700, .user = user, .expected = .owner_wrong },
        // The owner is checked first: a writable directory of another user's is that user's.
        .{ .uid = other, .mode = 0o777, .user = user, .expected = .owner_wrong },
        // Running as root, another user's directory is still theirs.
        .{ .uid = user, .mode = 0o700, .user = 0, .expected = .owner_wrong },
        .{ .uid = user, .mode = 0o720, .user = user, .expected = .writable },
        .{ .uid = user, .mode = 0o702, .user = user, .expected = .writable },
        .{ .uid = 0, .mode = 0o1777, .user = user, .expected = .writable },
        .{ .uid = 0, .mode = 0o775, .user = 0, .expected = .writable },
    };
    for (cases) |case| {
        const mode: u16 = @intCast(linux.S.IFDIR | case.mode);
        try testing.expectEqual(case.expected, directoryVerdict(mode, case.uid, case.user));
    }
}

test "listener: the socket's directory is every byte before the last slash, or the root" {
    var bytes: [path_max + 1]u8 = undefined;
    try testing.expectEqualStrings("/run/coalition-connection", directoryOf("/run/coalition-connection/app.sock", &bytes));
    try testing.expectEqualStrings("/", directoryOf("/app.sock", &bytes));
    try testing.expectEqualStrings("/", directoryOf("/", &bytes));
    try testing.expectEqualStrings("/run/", directoryOf("/run//app.sock", &bytes));
    try testing.expectEqualStrings("/run/cc", directoryOf("/run/cc/", &bytes));
    var at_max: [path_max:0]u8 = @splat('d');
    at_max[0] = '/';
    at_max[path_max - 2] = '/';
    try testing.expectEqual(@as(usize, path_max - 2), directoryOf(&at_max, &bytes).len);
}

test "listener: a directory swapped in at the path after it was opened is not the same directory" {
    var dir: TestDir = undefined;
    try dir.create("dirswap");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const inner = dir.file(&buffer, "run");
    var moved_buffer: [path_max + 1]u8 = undefined;
    const moved = dir.file(&moved_buffer, "moved");
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mkdir(inner, 0o700)));
    const opened = linux.open(inner, .{ .ACCMODE = .RDONLY, .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(opened));
    const fd: linux.fd_t = @intCast(opened);
    defer closeLogged(fd, "test directory");
    const status = try directoryStatus(fd, inner);
    try testing.expect(try sameDirectory(inner, status));

    // Moved away and a new directory made at the path: the path names another one now.
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.rename(inner, moved)));
    try testing.expect(!try sameDirectory(inner, status));
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mkdir(inner, 0o700)));
    try testing.expect(!try sameDirectory(inner, status));
    try testing.expect(try sameDirectory(moved, status));
}

/// Makes a regular file at `file_path` with exactly `mode`, whatever the umask.
fn makeFile(file_path: [:0]const u8, mode: u32) !void {
    assert(file_path.len > 0 and file_path[0] == '/');
    assert(mode & ~@as(u32, 0o777) == 0);
    const flags: linux.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true };
    const created = linux.open(file_path, flags, 0o600);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(created));
    const fd: linux.fd_t = @intCast(created);
    defer closeLogged(fd, "test file");
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.fchmod(fd, mode)));
}

/// Expects `open` to refuse `file_path` with `SocketLockUnsafe` while `lock_path` holds a
/// lock file made beforehand, leaving that file, and making no socket file.
fn expectLockRefused(file_path: [:0]const u8, lock_path: [:0]const u8) !void {
    assert(file_path.len > 0);
    assert(lock_path.len > file_path.len);
    try expectOpenError(error.SocketLockUnsafe, file_path);
    try testing.expect(try exists(lock_path));
    try testing.expect(!try exists(file_path));
}

test "listener: a lock file made beforehand that isn't the server's private one is refused and kept" {
    var dir: TestDir = undefined;
    try dir.create("lockfile");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");
    var lock_buffer: [path_max + 1]u8 = undefined;
    const lock_path = dir.file(&lock_buffer, "app.sock.lock");

    // Open to group or others: someone else may have made it, or may use it.
    for ([_]u32{ 0o666, 0o640, 0o604 }) |mode| {
        try makeFile(lock_path, mode);
        try expectLockRefused(file_path, lock_path);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.unlink(lock_path)));
    }
    // A FIFO, which the nonblocking open gets through without waiting.
    const fifo = linux.mknod(lock_path, linux.S.IFIFO | 0o600, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(fifo));
    try expectLockRefused(file_path, lock_path);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.unlink(lock_path)));

    // A hard link to another file: whoever holds the other name shares the lock's file.
    var other_buffer: [path_max + 1]u8 = undefined;
    const other = dir.file(&other_buffer, "other");
    try makeFile(other, 0o600);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.link(other, lock_path)));
    try expectLockRefused(file_path, lock_path);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.unlink(other)));

    // With the other name gone it is a private lock file again, and the path opens.
    var listener = try open(file_path);
    defer listener.close();
    try check(listener.socket);
}

test "listener: every lock file status has a verdict, and only the server's private regular file passes" {
    const user: linux.uid_t = 1000;
    const reg = linux.S.IFREG;
    const Case = struct { mode: u32, uid: linux.uid_t, links: u32, expected: LockVerdict };
    // Owned by another user and linked twice: refused for the owner, which is judged first.
    const cases = [_]Case{
        .{ .mode = reg | 0o600, .uid = user, .links = 1, .expected = .ok },
        .{ .mode = reg | 0o700, .uid = user, .links = 1, .expected = .ok },
        // Made under a umask of 0777.
        .{ .mode = reg | 0o000, .uid = user, .links = 1, .expected = .ok },
        .{ .mode = linux.S.IFIFO | 0o600, .uid = user, .links = 1, .expected = .not_regular },
        .{ .mode = linux.S.IFDIR | 0o700, .uid = user, .links = 1, .expected = .not_regular },
        .{ .mode = linux.S.IFSOCK | 0o600, .uid = user, .links = 1, .expected = .not_regular },
        .{ .mode = linux.S.IFCHR | 0o600, .uid = user, .links = 1, .expected = .not_regular },
        // Root's file isn't a server's that runs as another user.
        .{ .mode = reg | 0o600, .uid = 0, .links = 1, .expected = .owner_wrong },
        .{ .mode = reg | 0o600, .uid = 1001, .links = 1, .expected = .owner_wrong },
        .{ .mode = reg | 0o600, .uid = user, .links = 2, .expected = .linked },
        .{ .mode = reg | 0o600, .uid = user, .links = 0, .expected = .linked },
        .{ .mode = reg | 0o640, .uid = user, .links = 1, .expected = .mode_wide },
        .{ .mode = reg | 0o601, .uid = user, .links = 1, .expected = .mode_wide },
        .{ .mode = reg | 0o4600, .uid = user, .links = 1, .expected = .mode_wide },
        .{ .mode = reg | 0o1600, .uid = user, .links = 1, .expected = .mode_wide },
        .{ .mode = reg | 0o666, .uid = 1001, .links = 2, .expected = .owner_wrong },
        .{ .mode = reg | 0o666, .uid = user, .links = 2, .expected = .linked },
        .{ .mode = linux.S.IFIFO | 0o666, .uid = 1001, .links = 2, .expected = .not_regular },
    };
    for (cases) |case| {
        const mode: u16 = @intCast(case.mode);
        try testing.expectEqual(case.expected, lockVerdict(mode, case.uid, case.links, user));
    }
}

test "listener: the lock file stays after close, and the path opens again" {
    var dir: TestDir = undefined;
    try dir.create("reopen");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");
    var lock_buffer: [path_max + 1]u8 = undefined;
    const lock_path = dir.file(&lock_buffer, "app.sock.lock");

    var first = try open(file_path);
    first.close();
    try testing.expect(try exists(lock_path));
    var second = try open(file_path);
    defer second.close();
    try testing.expectEqual(linux.E.SUCCESS, try connectTo(file_path));
}

test "listener: close leaves a socket someone else put at the path" {
    var dir: TestDir = undefined;
    try dir.create("replaced");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");
    var first = try open(file_path);
    // Someone removes the server's file and binds the path again, ignoring the lock.
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.unlink(file_path)));
    try leaveStaleSocketUnlocked(file_path);
    try testing.expect(!sameFile(file_path, first.file));

    first.close();
    try testing.expect(try exists(file_path));
}

/// What a process that doesn't take the lock leaves at the path while `open` runs, after
/// bind: a socket of its own, the same under a default ACL on the directory, a file of
/// another kind, or nothing. Each replacement has exactly `listener_socket_mode`, so only
/// the identity check can tell it from the file bind made.
const Replacement = enum { socket, socket_acl, file, nothing };

/// The pause the replacement tests pass to `openPaused`: removes the socket file `open`
/// just bound and puts `replacement` in its place. The pause can't return an error, so a
/// failed step sets `failed`, which the test checks first; a socket it binds stays open in
/// `socket` until the test closes it. Set by `expectReplacedRefused` before each call.
const ReplaceDuringOpen = struct {
    var replacement: Replacement = .nothing;
    var socket: io.Socket = -1;
    var failed: bool = false;

    fn pause(file_path: [:0]const u8) void {
        assert(file_path.len > 0 and file_path[0] == '/');
        assert(socket == -1 and !failed);
        failed = !replace(file_path);
    }

    fn replace(file_path: [:0]const u8) bool {
        assert(file_path.len > 0);
        assert(socket == -1);
        if (linux.errno(linux.unlink(file_path)) != .SUCCESS) return false;
        switch (replacement) {
            .socket, .socket_acl => {
                if (replacement == .socket_acl) {
                    var dir_buffer: [path_max + 1]u8 = undefined;
                    const slash = std.mem.findScalarLast(u8, file_path, '/') orelse return false;
                    @memcpy(dir_buffer[0..slash], file_path[0..slash]);
                    dir_buffer[slash] = 0;
                    setDefaultAcl(dir_buffer[0..slash :0], &acl_nobody_in_group_out) catch return false;
                }
                const previous = linux.syscall1(.umask, bind_umask);
                defer _ = linux.syscall1(.umask, previous);
                socket = bindUnlocked(file_path, linux.SOCK.STREAM, true) catch return false;
            },
            .file => {
                const flags: linux.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true };
                const created = linux.open(file_path, flags, 0o600);
                if (linux.errno(created) != .SUCCESS) return false;
                const fd: linux.fd_t = @intCast(created);
                defer closeLogged(fd, "test file");
                if (linux.errno(linux.fchmod(fd, socket_mode)) != .SUCCESS) return false;
            },
            .nothing => {},
        }
        return true;
    }
};

/// Expects `openPaused` with `replacement` put at the path during open to refuse
/// `file_path` as `SocketPathInUse`.
fn expectReplacedRefused(replacement: Replacement, file_path: [:0]const u8) !void {
    assert(file_path.len > 0);
    assert(ReplaceDuringOpen.socket == -1);
    ReplaceDuringOpen.replacement = replacement;
    ReplaceDuringOpen.failed = false;
    const result = openPaused(file_path, ReplaceDuringOpen.pause, serverOwners());
    try testing.expect(!ReplaceDuringOpen.failed);
    if (result) |opened| {
        var listener = opened;
        listener.close();
        return error.TestUnexpectedResult;
    } else |err| try testing.expectEqual(error.SocketPathInUse, err);
}

/// Closes the replacement socket a test left open, if any.
fn closeReplacement() void {
    assert(ReplaceDuringOpen.socket >= -1);
    if (ReplaceDuringOpen.socket >= 0) closeLogged(ReplaceDuringOpen.socket, "test socket");
    ReplaceDuringOpen.socket = -1;
    assert(ReplaceDuringOpen.socket == -1);
}

test "listener: a socket put at the path during open is SocketPathInUse, kept and still reachable" {
    var dir: TestDir = undefined;
    try dir.create("swapsock");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");
    defer closeReplacement();

    try expectReplacedRefused(.socket, file_path);
    // The refused open's cleanup left the other program's socket where it was, though its
    // mode is exactly the one this server sets.
    try testing.expect(ReplaceDuringOpen.socket >= 0);
    try testing.expect(try exists(file_path));
    try testing.expectEqual(linux.E.SUCCESS, try connectTo(file_path));

    // The lock was released: with the other socket gone, the path opens again.
    closeReplacement();
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.unlink(file_path)));
    var again = try open(file_path);
    defer again.close();
    try check(again.socket);
}

test "listener: a replacement that carries an ACL is SocketPathInUse, not SocketAclPresent, and kept" {
    var dir: TestDir = undefined;
    try dir.create("swapacl");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");
    defer closeReplacement();

    // The pause sets a default ACL on the directory before it binds, so only the
    // replacement carries an access ACL: the identity is checked before the ACL's error.
    try expectReplacedRefused(.socket_acl, file_path);
    try testing.expect(try aclNamesUser(file_path, 65534));
    try testing.expectEqual(linux.E.SUCCESS, try connectTo(file_path));
}

test "listener: a file put at the path, or the path emptied, during open is SocketPathInUse" {
    var dir: TestDir = undefined;
    try dir.create("swapfile");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;

    const file_path = dir.file(&buffer, "app.sock");
    try expectReplacedRefused(.file, file_path);
    // A regular file is never mistaken for the socket bind made, so it stays.
    try testing.expect(try exists(file_path));
    try testing.expect(fileId(file_path) == null);

    const emptied = dir.file(&buffer, "gone.sock");
    try expectReplacedRefused(.nothing, emptied);
    try testing.expect(!try exists(emptied));
}

test "listener: unlinkIfSame removes only the socket file it names, while both are bound" {
    var dir: TestDir = undefined;
    try dir.create("ifsame");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");

    // Both sockets stay open, as open's and close's own socket does when they clean up: an
    // open socket holds its file's inode, so the second file can't be given the first's
    // number. (Once both are closed, ext4 hands a freed number to the next file at once.)
    const first = try bindUnlocked(file_path, linux.SOCK.STREAM, true);
    defer closeLogged(first, "test socket");
    const first_file = fileId(file_path) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.unlink(file_path)));
    const second = try bindUnlocked(file_path, linux.SOCK.STREAM, true);
    defer closeLogged(second, "test socket");
    const second_file = fileId(file_path) orelse return error.TestUnexpectedResult;
    try testing.expect(first_file.ino != second_file.ino);

    unlinkIfSame(file_path, first_file, first);
    try testing.expect(try exists(file_path));
    try testing.expect(sameFile(file_path, second_file));
    unlinkIfSame(file_path, second_file, second);
    try testing.expect(!try exists(file_path));
}

/// A TCP socket on 127.0.0.1 at a port the kernel picks, listening: what a server that
/// listened on a network address would hold.
fn tcpListener() !io.Socket {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    const socket: io.Socket = @intCast(rc);
    errdefer closeLogged(socket, "test socket");
    const address: linux.sockaddr.in = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f00_0001) };
    const bound = linux.bind(socket, @ptrCast(&address), @sizeOf(linux.sockaddr.in));
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(bound));
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.listen(socket, 4)));
    assert(socket >= 0);
    return socket;
}

test "listener: check refuses a network listener, and any socket that can't take connections" {
    // Listening, but on a network address: never the server's listener.
    const tcp = try tcpListener();
    defer closeLogged(tcp, "test socket");
    try testing.expectError(error.ListenerNotLocal, check(tcp));

    const datagram_rc = linux.socket(linux.AF.UNIX, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(datagram_rc));
    const datagram: io.Socket = @intCast(datagram_rc);
    defer closeLogged(datagram, "test socket");
    try testing.expectError(error.ListenerNotStream, check(datagram));

    const unlistened = try unixSocket(.blocking);
    defer closeLogged(unlistened, "test socket");
    try testing.expectError(error.ListenerNotOnPath, check(unlistened));

    // A bind given the family alone autobinds an abstract address, which no file mode
    // guards.
    const abstract = try unixSocket(.blocking);
    defer closeLogged(abstract, "test socket");
    const unnamed: linux.sockaddr.un = .{ .path = @splat(0) };
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.bind(abstract, @ptrCast(&unnamed), family_len)));
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.listen(abstract, 4)));
    try testing.expectError(error.ListenerNotOnPath, check(abstract));

    // Bound to a path, but not listening.
    var dir: TestDir = undefined;
    try dir.create("check");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const bound = try bindUnlocked(dir.file(&buffer, "app.sock"), linux.SOCK.STREAM, false);
    defer closeLogged(bound, "test socket");
    try testing.expectError(error.ListenerNotListening, check(bound));

    var fds: [2]linux.fd_t = undefined;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })));
    defer closeLogged(fds[0], "test pipe");
    defer closeLogged(fds[1], "test pipe");
    try testing.expectError(error.ListenerNotSocket, check(fds[0]));

    // A number past any descriptor this process can hold: EBADF.
    try testing.expectError(error.ListenerUnreadable, check(std.math.maxInt(i32)));
}

test "listener: every path errno has an outcome" {
    try testing.expectEqual(PathOutcome.success, pathErrno(.SUCCESS));
    const unusable = [_]linux.E{ .NOENT, .NOTDIR, .ACCES, .PERM, .ROFS, .LOOP, .NAMETOOLONG };
    for (unusable) |err| try testing.expectEqual(PathOutcome.directory_unusable, pathErrno(err));
    const resources = [_]linux.E{ .MFILE, .NFILE, .NOMEM, .NOBUFS, .NOSPC, .DQUOT };
    for (resources) |err| try testing.expectEqual(PathOutcome.resources, pathErrno(err));
    const failed = [_]linux.E{ .IO, .BADF, .INVAL, .NOTSOCK, .FAULT, .ADDRNOTAVAIL, .ISDIR, .BUSY };
    for (failed) |err| try testing.expectEqual(PathOutcome.failed, pathErrno(err));
    // An errno no call here documents, and a number std has no name for.
    try testing.expectEqual(PathOutcome.failed, pathErrno(.CONNRESET));
    try testing.expectEqual(PathOutcome.failed, pathErrno(@fromBackingInt(@intCast(4000))));
}

/// The owners `open` itself checks against: the server's user for all three.
fn serverOwners() Owners {
    const user = linux.geteuid();
    const owners: Owners = .{ .directory = user, .lock = user, .socket = user };
    assert(owners.directory == owners.lock and owners.lock == owners.socket);
    return owners;
}

/// A user id that isn't this process's, nor root's: the "other user" of the owner tests.
fn foreignUser() linux.uid_t {
    const user = linux.geteuid();
    const foreign: linux.uid_t = if (user == 65534) 65533 else 65534;
    assert(foreign != user and foreign != 0);
    return foreign;
}

/// Expects `openPaused` with `owners` to refuse `file_path` with `expected`, closing a
/// listener opened by mistake.
fn expectOwnersRefused(expected: OpenError, file_path: [:0]const u8, owners: Owners) !void {
    assert(file_path.len > 0);
    assert(file_path[0] == '/');
    if (openPaused(file_path, pauseNone, owners)) |opened| {
        var listener = opened;
        listener.close();
        return error.TestUnexpectedResult;
    } else |err| try testing.expectEqual(expected, err);
}

test "listener: a directory another user owns is refused, before the lock file is made" {
    var dir: TestDir = undefined;
    try dir.create("dirowner");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");
    var lock_buffer: [path_max + 1]u8 = undefined;
    const lock_path = dir.file(&lock_buffer, "app.sock.lock");
    const foreign = foreignUser();
    var owners = serverOwners();
    if (linux.geteuid() == 0) {
        // Root's directories always pass, so as root the directory is given to the other
        // user instead, and given back before dir.remove runs.
        const chowned = linux.chown(dir.path(), foreign, foreign);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(chowned));
    } else {
        owners.directory = foreign;
    }
    defer if (linux.geteuid() == 0) {
        _ = linux.chown(dir.path(), 0, 0);
    };
    try expectOwnersRefused(error.SocketDirectoryOwnerWrong, file_path, owners);
    try testing.expect(!try exists(lock_path));
    try testing.expect(!try exists(file_path));
}

test "listener: a lock file another user owns is refused, even while someone holds its lock" {
    var dir: TestDir = undefined;
    try dir.create("lockown");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    const file_path = dir.file(&buffer, "app.sock");
    var lock_buffer: [path_max + 1]u8 = undefined;
    const lock_path = dir.file(&lock_buffer, "app.sock.lock");
    var owners = serverOwners();
    owners.lock = foreignUser();
    // The lock file this test's user made is another user's as far as the server can tell.
    try expectOwnersRefused(error.SocketLockUnsafe, file_path, owners);
    try testing.expect(try exists(lock_path));
    try testing.expect(!try exists(file_path));

    // A 0666 lock file someone holds the lock on: the file is judged before the lock is
    // tried, so it is SocketLockUnsafe, not SocketPathInUse.
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.unlink(lock_path)));
    try makeFile(lock_path, 0o666);
    const held = linux.open(lock_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(held));
    const holder: linux.fd_t = @intCast(held);
    defer closeLogged(holder, "test lock holder");
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.flock(holder, std.posix.LOCK.EX | std.posix.LOCK.NB)));
    try expectLockRefused(file_path, lock_path);
}

test "listener: another user's socket at the path, stale or live, is SocketPathOccupied and kept" {
    var dir: TestDir = undefined;
    try dir.create("sockown");
    defer dir.remove();
    var buffer: [path_max + 1]u8 = undefined;
    var owners = serverOwners();
    owners.socket = foreignUser();

    const stale = dir.file(&buffer, "stale.sock");
    try leaveStaleSocket(stale);
    const stale_file = fileId(stale) orelse return error.TestUnexpectedResult;
    try expectOwnersRefused(error.SocketPathOccupied, stale, owners);
    try testing.expect(sameFile(stale, stale_file));
    // The server's own stale socket is still replaced.
    {
        var listener = try open(stale);
        defer listener.close();
        // A new socket, though it may get the freed inode's number: this one takes
        // connections.
        try testing.expectEqual(linux.E.SUCCESS, try connectTo(stale));
    }

    // A live one is refused before the probe connects to it: SocketPathOccupied, not the
    // SocketPathInUse a probe would give.
    var live_buffer: [path_max + 1]u8 = undefined;
    const live = dir.file(&live_buffer, "live.sock");
    const other = try bindUnlocked(live, linux.SOCK.STREAM, true);
    defer closeLogged(other, "test socket");
    try expectOwnersRefused(error.SocketPathOccupied, live, owners);
    try testing.expectEqual(linux.E.SUCCESS, try connectTo(live));
    try expectOpenError(error.SocketPathInUse, live);
}
