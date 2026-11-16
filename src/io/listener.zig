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
//! connect to it before it compares types, so it is stale like any other.) The lock file
//! itself stays after `close`; removing it would let two starting servers lock two
//! different files.
//!
//! The socket file is created with `listener_socket_mode` and no other: the umask is set
//! for the one bind call so bind makes the file with exactly those bits, then put back.
//! Nothing changes the mode by path afterwards, so a symlink swapped in at the path can't
//! redirect a chmod onto another file. The mode is read back before listen, and anything
//! else (a default ACL on the directory can narrow it) refuses with `SocketModeWrong`.
//! Connecting to a Unix socket needs write permission on the file itself, so the mode
//! decides who may connect; an access ACL the directory's default ACL adds can widen that,
//! so the socket's directory carries none. The umask is the process's, so `open` runs at
//! startup, before any other thread exists.
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
    /// file there (permissions, a read-only file system, a symlink loop).
    SocketDirectoryUnusable,
    /// Another server holds the path's lock; or a live server, which took no lock, answers
    /// on the socket at the path; or a socket there can't be probed (no permission to
    /// connect), so it can't be shown stale; or a process that doesn't take the lock bound
    /// the path, or replaced the socket there, while the stale socket was being replaced.
    /// A live socket is never removed.
    SocketPathInUse,
    /// A file, a directory, a symlink or a live datagram socket is at the path. It is never
    /// removed.
    SocketPathOccupied,
    /// The socket file bind made doesn't have exactly `listener_socket_mode` (a default ACL
    /// on the directory can narrow it), so the clients the mode names might not connect.
    SocketModeWrong,
    /// A system call failed for a reason none of the above names; the errno is logged.
    ListenFailed,
};

/// Where the socket file came from: the file system and inode bind made. `close` removes the
/// path only while it still names this file, never one someone put there since.
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
        const file_path = self.path();
        if (sameFile(file_path, self.file)) unlinkLogged(file_path);
        closeLogged(self.socket, "socket");
        closeLogged(self.lock, "lock file");
        self.socket = -1;
        self.lock = -1;
    }
};

/// Opens a Unix stream socket listening at `socket_path`, replacing a stale socket a
/// stopped server left there: one a probe connect shows nothing accepts on. It sets the
/// process umask for its one bind call, so it runs before any other thread exists. Nothing is left behind on failure but the lock file: the
/// socket and lock are closed, and a socket file this call bound is removed.
pub fn open(socket_path: []const u8) OpenError!Listener {
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

    listener.lock = try takeLock(file_path);
    errdefer closeLogged(listener.lock, "lock file");
    listener.socket = try unixSocket(.blocking);
    errdefer closeLogged(listener.socket, "socket");
    try bindReplacingStale(listener.socket, &listener.address, file_path);
    // The lock is held, so the file at the path is the one bind just made.
    errdefer unlinkLogged(file_path);
    listener.file = try boundFile(file_path);

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

/// Opens `<socket_path>.lock` and locks it exclusively without waiting. A lock held by
/// another process is `SocketPathInUse`.
fn takeLock(socket_path: [:0]const u8) OpenError!linux.fd_t {
    assert(socket_path.len > 0 and socket_path.len <= path_max);
    var bytes: [path_max + lock_suffix.len + 1]u8 = undefined;
    const lock_path = std.fmt.bufPrintSentinel(&bytes, "{s}" ++ lock_suffix, .{socket_path}, 0) catch unreachable;
    assert(lock_path.len == socket_path.len + lock_suffix.len);
    // No symlink is followed, and a FIFO can't stall startup in open.
    const flags: linux.O = .{ .ACCMODE = .RDWR, .CREAT = true, .CLOEXEC = true, .NOFOLLOW = true, .NOCTTY = true, .NONBLOCK = true };
    const opened = linux.open(lock_path, flags, 0o600);
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
fn bindReplacingStale(socket: io.Socket, address: *const linux.sockaddr.un, file_path: [:0]const u8) OpenError!void {
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
            try removeStale(address, address_len, file_path);
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

/// Removes a stale socket at `file_path`: one nothing listens on, as a probe connect shows.
/// Refuses for a live socket and for a file of any other kind.
fn removeStale(address: *const linux.sockaddr.un, address_len: linux.socklen_t, file_path: [:0]const u8) OpenError!void {
    assert(file_path.len > 0);
    assert(file_path[0] == '/');
    var status: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, file_path, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true, .INO = true }, &status);
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
    if (!status.mask.INO) return error.ListenFailed;
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

/// The socket file bind just made at `file_path`, read back before listen: its file system
/// and inode, once its mode is shown to be exactly `listener_socket_mode`. The kernel
/// applies the umask itself, but a default ACL on the directory can narrow the mode, and a
/// file system may rewrite it; either refuses here, before any client could connect.
fn boundFile(file_path: [:0]const u8) OpenError!FileId {
    assert(file_path.len > 0);
    assert(file_path[0] == '/');
    var status: linux.Statx = undefined;
    const mask: linux.STATX = .{ .TYPE = true, .MODE = true, .INO = true };
    const err = linux.errno(linux.statx(linux.AT.FDCWD, file_path, linux.AT.SYMLINK_NOFOLLOW, mask, &status));
    if (err != .SUCCESS) {
        std.log.err("listener {s}: statx of the socket file failed, errno {d}", .{ file_path, @backingInt(err) });
        return error.ListenFailed;
    }
    if (!status.mask.TYPE or !status.mask.MODE or !status.mask.INO or !linux.S.ISSOCK(status.mode)) {
        std.log.err("listener {s}: can't read back the socket file", .{file_path});
        return error.ListenFailed;
    }
    const mode: u32 = @as(u32, status.mode) & 0o7777;
    modeCheck(mode) catch |err_mode| {
        std.log.err("listener {s}: socket file mode is {o}, not {o}", .{ file_path, mode, socket_mode });
        return err_mode;
    };
    return .{ .dev_major = status.dev_major, .dev_minor = status.dev_minor, .ino = status.ino };
}

/// Refuses a socket file mode other than exactly `listener_socket_mode`. Pure, so tests can
/// check modes a test can't make bind produce.
fn modeCheck(mode: u32) error{SocketModeWrong}!void {
    assert(mode & ~@as(u32, 0o7777) == 0);
    if (mode != socket_mode) return error.SocketModeWrong;
    assert(mode & bind_umask == 0);
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
