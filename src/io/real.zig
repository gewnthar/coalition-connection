//! The real I/O type, for Linux: an io_uring ring, the monotonic clock and the kernel's
//! random source.
//!
//! Job: give production code the I/O contract (`root.zig`) on the real system. `submit`
//! queues an operation on the ring without a system call; `poll` hands every queued
//! operation to the kernel in one `io_uring_enter` and copies out the finished ones, so a
//! burst of sends costs one system call, not one each. Neither ever waits.
//!
//! Ring: `constants.io_operations_in_flight_max` submission entries, set up once in `init`
//! and never resized. The kernel makes the completion queue twice that size, so it can't
//! overflow while at most that many operations are in flight. Each operation in flight
//! holds one slot of a fixed table; the slot's index is the ring's `user_data`, so a
//! completion finds its operation without a search. A submission with no free slot returns
//! `error.QueueFull` and changes nothing.
//!
//! Sends: `IORING_OP_SEND` on the peer's socket from the connection table, with
//! `MSG_NOSIGNAL`, so a peer that has gone away fails the send with `EPIPE` instead of
//! ending the process with `SIGPIPE`. Each errno send(2) documents maps to `PeerDown` or
//! `Backpressure`, or stops the process when it can only mean a bug in this file or its
//! caller (`sendErrno`). An errno send(2) doesn't document is a fact about the kernel this
//! file didn't know, not a bug a client caused, so it fails only that connection: it maps
//! to `PeerDown` and is counted in `send_errno_undocumented_count`, with the latest one
//! kept in `send_errno_undocumented_last`.
//!
//! Accepts: `IORING_OP_ACCEPT` on the caller's listening socket, with `SOCK_CLOEXEC` on the
//! new socket. The completion takes an entry in the connection table for the new socket and
//! hands back its `PeerId`. When the table is full, the new socket is closed at once, so the
//! client sees the connection end instead of waiting, and the accept completes with
//! `error.TableFull`; `refused` counts these. Every errno maps to `PeerDown`,
//! `Backpressure` or a stop with its reason (`acceptError`).
//!
//! `execute` is a simulator placeholder until Postgres is framed over sockets (roadmap
//! core 11); submitting one here stops the process with that reason.
//!
//! Clock: `CLOCK_MONOTONIC`, read as u64 nanoseconds. The kernel promises it never goes
//! backwards, and `now` asserts it: each reading is at or after the previous one.
//!
//! Random bytes: `getrandom(2)` with no flags, so it blocks only until the kernel's pool is
//! first seeded at boot and never returns weaker bytes. An interrupted or short read is
//! retried, at most `constants.io_random_attempts_max` getrandom calls per draw. When the
//! kernel can't supply the bytes, the call returns `error.RandomUnavailable` and zeroes the
//! buffer, so a partly filled buffer can't be mistaken for a random one. There is no
//! fallback source.
//!
//! Inputs: the connection table, submissions, listening sockets, buffers to fill.
//! Outputs: completions, time readings and random bytes.
//! Limits: `constants.io_operations_in_flight_max` operations in flight; sends of at most
//! `constants.http_response_size_max` bytes; 1 to `constants.io_random_bytes_max` random
//! bytes per call, with at most `constants.io_random_attempts_max` getrandom calls.
//!
//! Linux only: each method refuses to compile for another operating system.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const linux = std.os.linux;
const constants = @import("../constants.zig");
const connections = @import("../live/connections.zig");
const StartupAllocator = @import("../startup_allocator.zig").StartupAllocator;
const io = @import("root.zig");

const ns_per_s: u64 = std.time.ns_per_s;

/// Largest whole-second count whose every nanosecond still fits a u64 reading:
/// seconds * ns_per_s + (ns_per_s - 1) <= maxInt(u64). About 584 years of uptime.
const clock_seconds_max: u64 = (std.math.maxInt(u64) - (ns_per_s - 1)) / ns_per_s;

/// Operations in flight, and the ring's submission queue depth.
const slots_count: u32 = constants.io_operations_in_flight_max;

/// One operation in flight: what its completion needs to be checked and handed back.
const Slot = struct {
    id: io.OperationId,
    /// A send or an accept: `submit` refuses every other kind.
    kind: io.Kind,
    /// Bytes a send was given; the kernel never reports more. 0 for an accept.
    length: u32,
    in_use: bool,
};

/// Largest page the target may use; the kernel maps the ring in whole pages.
const page_bytes_max: u64 = std.heap.page_size_max;

/// Bytes the kernel's ring header (heads, tails, masks, flags) may take before the
/// completion entries. Reason: under 128 bytes on current kernels; a page leaves room for
/// fields a later kernel adds.
const ring_header_bytes_max: u64 = 4096;

/// What the ring and this type may take, worst case: the ring mapping (header, completion
/// entries at twice the queue depth, the submission index) and the submission entries, each
/// rounded up to whole pages, plus `Real` itself with its slot table.
pub const ring_bytes_estimate: u64 =
    std.mem.alignForward(u64, ring_header_bytes_max +
        2 * slots_count * @sizeOf(linux.io_uring_cqe) + slots_count * @sizeOf(u32), page_bytes_max) +
    std.mem.alignForward(u64, slots_count * @sizeOf(linux.io_uring_sqe), page_bytes_max) +
    @sizeOf(Real);

comptime {
    // Recomputed for the guard in `nanoseconds`: the largest reading fits, one more second
    // would not.
    assert(clock_seconds_max * ns_per_s + (ns_per_s - 1) <= std.math.maxInt(u64));
    assert(@as(u128, clock_seconds_max + 1) * ns_per_s + (ns_per_s - 1) > std.math.maxInt(u64));
    // io_uring_setup takes a power of two of at most 32,768 entries, as a u16.
    assert(std.math.isPowerOfTwo(slots_count));
    assert(slots_count <= 32_768 and slots_count <= std.math.maxInt(u16));
    // The memory table's row covers the worst case; `ringInit` checks the kernel's actual
    // mapping against the same row at startup.
    assert(ring_bytes_estimate <= constants.io_ring_size_max);
}

/// Setting up the ring failed. `RingUnavailable`: the kernel has no io_uring, or it is
/// switched off (the `kernel.io_uring_disabled` sysctl, or a seccomp filter in a
/// container). `RingResources`: out of file descriptors, locked memory or kernel memory.
/// `RingTooLarge`: the kernel mapped more than the memory table allows
/// (`constants.io_ring_size_max`).
pub const InitError = error{ RingUnavailable, RingResources, RingTooLarge };

pub const Real = struct {
    /// The clock reading taken at startup. Every later reading is at or after it.
    epoch: io.Instant,
    /// The latest clock reading; the next is at or after it.
    last: io.Instant,
    /// Random bytes handed out so far, for tests and metrics.
    random_bytes: u64,
    ring: linux.IoUring,
    /// Maps a send's `PeerId` to its socket, and takes an entry for each accepted
    /// connection. Owned by the caller; outlives this.
    table: *connections.Table,
    slots: [slots_count]Slot,
    /// Free slot indices, a stack: `free_slots[0..free_count]` are not in use.
    free_slots: [slots_count]u32,
    free_count: u32,
    submitted: u64,
    completed: u64,
    /// Times the kernel refused submissions for a moment (short of memory, or a signal);
    /// they stay queued and go in at the next `submit` or `poll`. For metrics.
    enters_deferred: u64,
    /// Connections accepted and closed at once because the table was full. For metrics.
    refused: u64,
    /// Sends that failed with an errno send(2) doesn't document; each completed as
    /// `PeerDown`. For metrics: any count above zero means `sendErrno` is missing a case.
    send_errno_undocumented_count: u64,
    /// The latest of those errnos, or `.SUCCESS` if there has been none, so the missing
    /// case can be named. It may be a value std has no name for, so print it with
    /// `@backingInt`, never `{t}` or `@tagName`.
    send_errno_undocumented_last: linux.E,

    /// Sets up the ring. `startup` proves the call happens during startup; nothing is
    /// mapped or allocated afterwards.
    pub fn init(startup: *const StartupAllocator, table: *connections.Table) InitError!Real {
        comptime assertLinux();
        assert(startup.allocationAllowed());
        assert(table.capacity() > 0);
        const ring = try ringInit();
        var result: Real = .{
            .epoch = monotonicNow(),
            .last = 0,
            .random_bytes = 0,
            .ring = ring,
            .table = table,
            .slots = @splat(.{ .id = 0, .kind = .send, .length = 0, .in_use = false }),
            .free_slots = undefined,
            .free_count = slots_count,
            .submitted = 0,
            .completed = 0,
            .enters_deferred = 0,
            .refused = 0,
            .send_errno_undocumented_count = 0,
            .send_errno_undocumented_last = .SUCCESS,
        };
        // Push the indices in reverse, so the first submission takes slot 0.
        var position: u32 = 0;
        while (position < slots_count) : (position += 1) {
            assert(position < result.free_slots.len);
            result.free_slots[position] = slots_count - 1 - position;
        }
        assert(position == slots_count);
        result.last = result.epoch;
        // The monotonic clock counts from boot, so a running process never reads zero.
        assert(result.epoch > 0);
        assert(result.ring.sq.sqes.len == slots_count);
        return result;
    }

    /// Closes the ring. Call it during shutdown only, once every operation has completed:
    /// the kernel tears a ring down in the background, so a send still in flight could
    /// read its bytes after this returns. An accept completes only when a connection
    /// arrives, and the contract has no cancel until core 3b, so until then a caller
    /// stops submitting accepts and waits for the last one before shutting down.
    pub fn deinit(self: *Real) void {
        comptime assertLinux();
        assert(self.ring.fd >= 0);
        assert(self.inFlight() == 0);
        assert(self.completed == self.submitted);
        self.ring.deinit();
        self.* = undefined;
    }

    /// Operations submitted and not yet handed back by `poll`.
    pub fn inFlight(self: *const Real) u32 {
        assert(self.free_count <= slots_count);
        const result = slots_count - self.free_count;
        assert(result <= slots_count);
        return result;
    }

    /// Nanoseconds on `CLOCK_MONOTONIC`, never before the previous reading.
    pub fn now(self: *Real) io.Instant {
        comptime assertLinux();
        assert(self.epoch > 0);
        assert(self.last >= self.epoch);
        const reading = monotonicNow();
        // CLOCK_MONOTONIC never goes backwards; a reading before the last one means the
        // clock or this type is broken, and no timeout computed from it can be trusted.
        assert(reading >= self.last);
        self.last = reading;
        return reading;
    }

    /// Puts one operation on the ring and hands it to the kernel at once, so the kernel
    /// takes hold of the peer's socket now, not at some later poll: a connection closed and
    /// its descriptor number reused before then could otherwise receive another peer's
    /// bytes. With every slot in use, returns `error.QueueFull` and changes nothing.
    pub fn submit(self: *Real, submission: io.Submission) io.SubmitError!void {
        comptime assertLinux();
        const in_flight_before = self.inFlight();
        // Looked up before anything changes: a peer not in the table is a caller's bug.
        const socket = self.socketFor(submission.operation);
        if (self.free_count == 0) return error.QueueFull;

        // Each queued entry belongs to an operation in flight, and fewer than slots_count
        // are in flight, so the submission queue has room.
        assert(self.ring.sq_ready() < slots_count);
        const sqe = self.ring.get_sqe() catch unreachable;
        const index = self.free_slots[self.free_count - 1];
        assert(!self.slots[index].in_use);
        self.slots[index] = prepare(sqe, submission, socket);
        sqe.user_data = index;
        self.free_count -= 1;
        self.submitted += 1;
        if (!enter(&self.ring)) self.enters_deferred += 1;
        assert(self.inFlight() == in_flight_before + 1);
        assert(self.completed + self.inFlight() == self.submitted);
    }

    /// Hands over any operation the kernel refused for a moment, then moves finished ones
    /// into `completions` and returns how many. Never waits: with nothing finished it
    /// returns 0.
    pub fn poll(self: *Real, completions: []io.Completion) u32 {
        comptime assertLinux();
        assert(completions.len > 0);
        assert(completions.len <= slots_count);
        const in_flight_before = self.inFlight();
        if (in_flight_before == 0) return 0;

        if (self.ring.sq_ready() > 0 and !enter(&self.ring)) self.enters_deferred += 1;
        var cqes: [slots_count]linux.io_uring_cqe = undefined;
        const count = copyReady(&self.ring, cqes[0..completions.len]);
        assert(count <= in_flight_before);
        for (cqes[0..count], completions[0..count]) |cqe, *completion| {
            completion.* = self.complete(cqe);
        }
        assert(self.inFlight() == in_flight_before - count);
        assert(self.completed + self.inFlight() == self.submitted);
        return count;
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

    /// The socket an operation acts on, checked before anything changes: a send's peer from
    /// the table (`get` asserts it is in use), an accept's listener as given. `execute`
    /// stops the process: it is a simulator placeholder.
    fn socketFor(self: *const Real, operation: io.Operation) io.Socket {
        const socket: io.Socket = switch (operation) {
            .send => |send| send: {
                assert(send.bytes.len > 0);
                assert(send.bytes.len <= constants.http_response_size_max);
                break :send self.table.get(send.peer).socket;
            },
            .accept => |accept| accept.listener,
            .execute => std.debug.panic("io.real: execute is a simulator placeholder; " ++
                "the real type has no database traffic until Postgres is framed over sockets", .{}),
        };
        assert(socket >= 0);
        assert(self.free_count <= slots_count);
        return socket;
    }

    /// Frees the slot a completion names and builds its `io.Completion`.
    fn complete(self: *Real, cqe: linux.io_uring_cqe) io.Completion {
        // user_data is always a slot index this type wrote, and a send or an accept posts
        // one completion.
        assert(cqe.user_data < slots_count);
        assert(cqe.flags & linux.IORING_CQE_F_MORE == 0);
        const index: u32 = @intCast(cqe.user_data);
        const slot = self.slots[index];
        assert(slot.in_use); // A completion for a slot with nothing in flight.
        self.slots[index].in_use = false;
        self.free_slots[self.free_count] = index;
        self.free_count += 1;
        self.completed += 1;
        assert(self.free_count <= slots_count);
        assert(slot.kind != .execute); // `prepare` never writes one.
        const result: io.Result = switch (slot.kind) {
            .send => .{ .send = self.sendResult(cqe.res, slot.length) },
            .accept => .{ .accept = self.acceptResult(cqe.res) },
            .execute => unreachable, // Asserted above.

        };
        return .{ .id = slot.id, .result = result };
    }

    /// A send's result from its completion: the bytes sent, or the error its errno means.
    /// An undocumented errno completes as `PeerDown` and is counted.
    fn sendResult(self: *Real, res: i32, length: u32) io.SendError!u32 {
        assert(length > 0);
        assert(length <= constants.http_response_size_max);
        if (res > 0) {
            const sent: u32 = @intCast(res);
            assert(sent <= length); // The kernel never reports more bytes than it was given.
            return sent;
        }
        // A stream send of at least one byte that sent none made no progress; the caller
        // tries again later.
        if (res == 0) return error.Backpressure;
        assert(res > -4096);
        const err: linux.E = @fromBackingInt(@intCast(-res));
        // The count and the latest errno change together, so neither is set without the other.
        assert((self.send_errno_undocumented_count == 0) == (self.send_errno_undocumented_last == .SUCCESS));
        switch (sendErrno(err)) {
            .peer_down => return error.PeerDown,
            .backpressure => return error.Backpressure,
            // A bad descriptor (a socket closed while its send was in flight), address, flag
            // or length, a Fast Open or a cancel this type never asks for: each means a bug in
            // this file or its caller, so the process stops with the reason.
            .bug => std.debug.panic("io_uring send: errno {d}", .{@backingInt(err)}),
            .peer_down_undocumented => {
                self.send_errno_undocumented_count += 1;
                self.send_errno_undocumented_last = err;
                return error.PeerDown;
            },
        }
    }

    /// An accept's result from its completion: the new connection's entry, or the error its
    /// errno means. A full table closes the new socket and counts the refusal.
    fn acceptResult(self: *Real, res: i32) io.AcceptError!io.PeerId {
        assert(res > -4096);
        if (res < 0) {
            const err: linux.E = @fromBackingInt(@intCast(-res));
            return acceptError(err);
        }
        const socket: io.Socket = res;
        const count_before = self.table.count();
        const peer = self.table.acquire(socket) catch |err| switch (err) {
            error.TableFull => {
                assert(count_before == self.table.capacity());
                // Linux releases the descriptor even when close is interrupted or reports
                // an I/O error, so neither is retried: a retry could close a descriptor
                // handed out since. The kernel handed this one over a moment ago and
                // nothing else holds it, so any other errno is a bug in this file.
                const closed = linux.errno(linux.close(socket));
                switch (closed) {
                    .SUCCESS, .INTR, .IO => {},
                    else => std.debug.panic("close of a refused connection: {t}", .{closed}),
                }
                self.refused += 1;
                return error.TableFull;
            },
        };
        assert(self.table.count() == count_before + 1);
        assert(self.table.get(peer).socket == socket);
        return peer;
    }
};

/// Fills a submission entry for a send or an accept, and returns the slot that tracks it.
fn prepare(sqe: *linux.io_uring_sqe, submission: io.Submission, socket: io.Socket) Slot {
    assert(socket >= 0);
    const slot: Slot = switch (submission.operation) {
        .send => |send| send: {
            sqe.prep_send(socket, send.bytes, linux.MSG.NOSIGNAL);
            break :send .{ .id = submission.id, .kind = .send, .length = @intCast(send.bytes.len), .in_use = true };
        },
        .accept => accept: {
            // No peer address is asked for: the app listens only where nginx reaches it.
            sqe.prep_accept(socket, null, null, linux.SOCK.CLOEXEC);
            break :accept .{ .id = submission.id, .kind = .accept, .length = 0, .in_use = true };
        },
        // `socketFor` stopped the process already.
        .execute => unreachable,
    };
    assert(slot.kind == @as(io.Kind, submission.operation));
    assert(slot.kind != .execute);
    assert(sqe.fd == socket);
    return slot;
}

/// Maps a failed accept's errno. Every errno has an explicit outcome.
fn acceptError(err: linux.E) io.AcceptError {
    assert(err != .SUCCESS);
    const result: io.AcceptError = switch (err) {
        // The connection failed before it was taken: it aborted, a firewall refused it, or
        // Linux passed on a network error already pending on it (accept(2), "Error
        // handling", and the other errors its ERRORS section says some kernels return).
        // The listener is fine; the caller accepts again.
        .CONNABORTED, .PERM, .PROTO, .NOPROTOOPT, .NONET => error.PeerDown,
        .HOSTDOWN, .HOSTUNREACH, .NETDOWN, .NETUNREACH, .TIMEDOUT => error.PeerDown,
        .NOSR, .SOCKTNOSUPPORT, .PROTONOSUPPORT => error.PeerDown,
        // Out of descriptors, buffers or memory, or interrupted: try again later.
        .MFILE, .NFILE, .NOBUFS, .NOMEM, .INTR, .AGAIN => error.Backpressure,
        // A bad or non-listening socket, a bad address or flag, or a cancel this type never
        // asks for: each means a bug in this file or its caller. EOPNOTSUPP is on the
        // pending-error list too, but it also means a listener that isn't a stream socket,
        // and every listener here is one, so it is treated as that bug.
        .BADF, .NOTSOCK, .INVAL, .FAULT, .OPNOTSUPP, .CANCELED => {
            std.debug.panic("io_uring accept: {t}", .{err});
        },
        else => std.debug.panic("io_uring accept: undocumented errno {t}", .{err}),
    };
    // Only a full table, never an errno, means TableFull.
    assert(result == error.PeerDown or result == error.Backpressure);
    return result;
}

/// Sets up a ring of `slots_count` entries, mapping each failure to `InitError`.
fn ringInit() InitError!linux.IoUring {
    assert(slots_count > 0);
    var ring = linux.IoUring.init(slots_count, 0) catch |err| return switch (err) {
        // io_uring is missing or switched off, or a security module refused the mapping.
        error.PermissionDenied,
        error.SystemOutdated,
        error.AccessDenied,
        error.MemoryMappingNotSupported,
        error.Unexpected,
        => error.RingUnavailable,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.SystemResources,
        error.LockedMemoryLimitExceeded,
        error.OutOfMemory,
        => error.RingResources,
        // The entry count is a constant power of two, the flags are 0, the parameters live
        // on the standard library's stack and no fixed mapping is asked for, so these mean
        // a bug, not a system state.
        error.EntriesZero,
        error.EntriesNotPowerOfTwo,
        error.ArgumentsInvalid,
        error.ParamsOutsideAccessibleAddressSpace,
        error.MappingAlreadyExists,
        => std.debug.panic("io_uring_setup: bad arguments ({t})", .{err}),
    };
    errdefer ring.deinit();
    // The kernel sizes the queues from the entry count; anything else breaks the slot
    // table's promise that the completion queue can't overflow.
    if (ring.sq.sqes.len != slots_count or ring.cq.cqes.len < 2 * slots_count) {
        return error.RingUnavailable;
    }
    // The mapping's size comes from the kernel, so it is checked, not assumed.
    const mapped: u64 = @as(u64, ring.sq.mmap.len) + ring.sq.mmap_sqes.len + @sizeOf(Real);
    if (mapped > constants.io_ring_size_max) return error.RingTooLarge;
    assert(ring.fd >= 0);
    return ring;
}

/// Hands every queued submission to the kernel without waiting. Returns false when the
/// kernel refused for a moment, leaving them queued for the next call; any other failure is
/// a bug in this file.
fn enter(ring: *linux.IoUring) bool {
    assert(ring.fd >= 0);
    const queued = ring.sq_ready();
    assert(queued > 0 and queued <= slots_count);
    _ = ring.submit() catch |err| switch (err) {
        // The kernel is short of memory, has too many completions pending, or a signal
        // arrived: what wasn't taken stays queued, and the next call tries again.
        error.SystemResources, error.CompletionQueueOvercommitted, error.SignalInterrupt => return false,
        // A bad descriptor or entry, a ring in the wrong state, or an opcode this kernel
        // lacks: every one is set up by this file, so the process stops with the reason.
        error.FileDescriptorInvalid,
        error.FileDescriptorInBadState,
        error.SubmissionQueueEntryInvalid,
        error.BufferInvalid,
        error.RingShuttingDown,
        error.OpcodeNotSupported,
        error.InvalidThread,
        error.Unexpected,
        => std.debug.panic("io_uring_enter: {t}", .{err}),
    };
    return true;
}

/// Copies the finished completions that fit in `cqes`, without waiting.
fn copyReady(ring: *linux.IoUring, cqes: []linux.io_uring_cqe) u32 {
    assert(cqes.len > 0);
    assert(cqes.len <= slots_count);
    // With wait_nr 0, copy_cqes enters the kernel only to flush an overflowed completion
    // queue, which the slot table rules out; its errors are handled as in `enter`.
    const count = ring.copy_cqes(cqes, 0) catch |err| switch (err) {
        error.SystemResources, error.CompletionQueueOvercommitted, error.SignalInterrupt => 0,
        error.FileDescriptorInvalid,
        error.FileDescriptorInBadState,
        error.SubmissionQueueEntryInvalid,
        error.BufferInvalid,
        error.RingShuttingDown,
        error.OpcodeNotSupported,
        error.InvalidThread,
        error.Unexpected,
        => std.debug.panic("io_uring_enter (completions): {t}", .{err}),
    };
    assert(count <= cqes.len);
    return count;
}

/// What a failed send's errno means. `peer_down_undocumented` is an errno send(2) isn't
/// documented to return; `Real.sendResult` treats it as `PeerDown` and counts it. `bug`
/// can only mean a bug in this file or its caller; `Real.sendResult` stops the process.
const SendOutcome = enum { peer_down, backpressure, peer_down_undocumented, bug };

/// Maps a failed send's errno to its outcome. Pure, so tests can check every arm,
/// including the ones that stop the process.
fn sendErrno(err: linux.E) SendOutcome {
    // Preconditions for any caller, tests included: a failure, in the kernel's errno
    // range of 1 to 4095.
    assert(err != .SUCCESS);
    assert(@backingInt(err) < 4096);
    return switch (err) {
        // The connection is gone or unusable: the caller closes it. EACCES and EPERM come
        // from a security module or a firewall refusing this connection, which a retry
        // won't change; EIO and EPROTO from a failed transport under the socket.
        .PIPE, .CONNRESET, .CONNABORTED, .NOTCONN, .SHUTDOWN, .TIMEDOUT => .peer_down,
        .HOSTUNREACH, .NETUNREACH, .NETDOWN, .HOSTDOWN, .NETRESET, .CONNREFUSED => .peer_down,
        .ACCES, .PERM, .IO, .PROTO => .peer_down,
        // The kernel is short of buffers or the call was interrupted: try again later.
        .AGAIN, .NOBUFS, .NOMEM, .INTR => .backpressure,
        // Only a bug causes these; `Real.sendResult` says which and stops. EALREADY is a
        // second Fast Open in progress, and no send here sets MSG_FASTOPEN.
        .BADF, .NOTSOCK, .FAULT, .INVAL, .OPNOTSUPP, .MSGSIZE, .DESTADDRREQ, .ISCONN => .bug,
        .CANCELED, .ALREADY => .bug,
        // An errno send(2) isn't documented to return, named in std or not. It says this
        // file's model of the kernel is incomplete, not that this process is broken, and a
        // client might be able to provoke it, so stopping would take the server down for
        // everyone. Only this connection fails, and the caller counts it.
        else => .peer_down_undocumented,
    };
}

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

/// A connection table holding one end of a socketpair, and a ring that sends on it. Set up
/// in place, because `Real` keeps a pointer to the table.
const Fixture = struct {
    startup: StartupAllocator,
    /// Taken during startup; frees the table at shutdown.
    gpa: std.mem.Allocator,
    table: connections.Table,
    real: Real,
    /// Registered in the table as `peer`.
    local: linux.fd_t,
    /// The far end; tests read from it or close it.
    remote: linux.fd_t,
    peer: io.PeerId,

    fn setUp(self: *Fixture) !void {
        var fds: [2]linux.fd_t = undefined;
        const flags = linux.SOCK.STREAM | linux.SOCK.CLOEXEC;
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.socketpair(linux.AF.UNIX, flags, 0, &fds)));
        self.local = fds[0];
        self.remote = fds[1];
        errdefer _ = linux.close(fds[0]);
        errdefer _ = linux.close(fds[1]);
        self.startup = .init(testing.allocator, 4 * connections.entry_bytes);
        self.gpa = self.startup.allocator();
        self.table = try connections.Table.init(self.gpa, 4);
        errdefer self.table.deinit(self.gpa);
        self.peer = try self.table.acquire(self.local);
        self.real = try Real.init(&self.startup, &self.table);
        self.startup.finishStartup();
        assert(self.real.inFlight() == 0);
        assert(self.table.count() == 1);
    }

    /// Closes the ring first, so nothing in flight still names a socket.
    fn tearDown(self: *Fixture) void {
        assert(self.table.count() == 1);
        self.real.deinit();
        assert(self.table.release(self.peer) == self.local);
        self.startup.beginShutdown();
        self.table.deinit(self.gpa);
        assert(self.startup.bytes_live == 0);
        _ = linux.close(self.local);
        if (self.remote >= 0) _ = linux.close(self.remote);
    }

    fn send(self: *Fixture, id: io.OperationId, bytes: []const u8) io.SubmitError!void {
        assert(bytes.len > 0);
        assert(bytes.len <= constants.http_response_size_max);
        return self.real.submit(.{ .id = id, .operation = .{ .send = .{ .peer = self.peer, .bytes = bytes } } });
    }
};

/// Empty polls `pollUntil` allows, 1 ms apart. Reason: a socketpair send normally completes
/// during the submitting system call; a second is ample even on a loaded CI machine.
const poll_attempts_max: u32 = 1_000;

/// Polls until `want` completions have arrived in `completions`, or fails the test. After
/// each empty poll it drains whatever `remote` has received, so sends parked on a full
/// socket buffer can finish; pass -1 to leave the far end alone.
fn pollUntil(real: *Real, completions: []io.Completion, want: u32, remote: linux.fd_t) !void {
    assert(want > 0);
    assert(want <= completions.len);
    var count: u32 = 0;
    var attempts: u32 = 0;
    while (count < want and attempts < poll_attempts_max) : (attempts += 1) {
        const got = real.poll(completions[count..want]);
        count += got;
        if (got > 0) continue;
        if (remote >= 0) {
            var scratch: [4096]u8 = undefined;
            _ = linux.recvfrom(remote, &scratch, scratch.len, linux.MSG.DONTWAIT, null, null);
        }
        const pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
        _ = linux.nanosleep(&pause, null);
    }
    assert(attempts <= poll_attempts_max);
    try testing.expectEqual(want, count);
}

/// Readings taken by the clock test. Reason: enough to see many distinct readings, few
/// enough to finish in milliseconds even in a Debug build.
const clock_readings_max: u32 = 10_000;

test "real: a later clock reading is never below an earlier one" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    const real = &fixture.real;
    var previous = real.now();
    try testing.expect(previous >= real.epoch);
    var count: u32 = 0;
    while (count < clock_readings_max) : (count += 1) {
        const reading = real.now();
        try testing.expect(reading >= previous);
        try testing.expectEqual(reading, real.last);
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
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    const real = &fixture.real;
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
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    const real = &fixture.real;
    var first: [32]u8 = undefined;
    var second: [32]u8 = undefined;
    try real.randomBytes(&first);
    try real.randomBytes(&second);
    // Equal draws have odds of 2^-256.
    try testing.expect(!std.mem.eql(u8, &first, &second));
    try testing.expectEqual(@as(u64, 64), real.random_bytes);
}

test "real: the type meets the I/O contract" {
    io.assertContract(Real);
    try testing.expect(comptime io.contractError(Real) == null);
}

test "real: a send over a socketpair completes with its byte count" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    try fixture.send(41, "hello");
    try testing.expectEqual(@as(u32, 1), fixture.real.inFlight());

    var completions: [4]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, 1, -1);
    try testing.expectEqual(@as(io.OperationId, 41), completions[0].id);
    try testing.expectEqual(@as(u32, 5), try completions[0].result.send);
    try testing.expectEqual(@as(u32, 0), fixture.real.inFlight());
    try testing.expectEqual(@as(u64, 1), fixture.real.completed);

    var received: [8]u8 = undefined;
    const rc = linux.read(fixture.remote, &received, received.len);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    try testing.expectEqualStrings("hello", received[0..rc]);
    // Nothing in flight: a poll returns 0 at once.
    try testing.expectEqual(@as(u32, 0), fixture.real.poll(&completions));
}

test "real: a send to a closed peer completes with PeerDown" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.close(fixture.remote)));
    fixture.remote = -1;
    // Without MSG_NOSIGNAL this send would end the test process with SIGPIPE.
    try fixture.send(7, "x");
    var completions: [1]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, 1, -1);
    try testing.expectEqual(@as(io.OperationId, 7), completions[0].id);
    try testing.expectError(error.PeerDown, completions[0].result.send);
    try testing.expectEqual(@as(u32, 0), fixture.real.inFlight());
}

test "real: one submission past the ring's depth returns QueueFull and changes nothing" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    var id: io.OperationId = 0;
    while (id < slots_count) : (id += 1) try fixture.send(id, "y");
    try testing.expectEqual(slots_count, fixture.real.inFlight());

    const sqe_tail_before = fixture.real.ring.sq.sqe_tail;
    const slots_before = fixture.real.slots;
    try testing.expectError(error.QueueFull, fixture.send(id, "z"));
    try testing.expectEqual(slots_count, fixture.real.inFlight());
    try testing.expectEqual(@as(u64, slots_count), fixture.real.submitted);
    try testing.expectEqual(sqe_tail_before, fixture.real.ring.sq.sqe_tail);
    try testing.expectEqualSlices(Slot, &slots_before, &fixture.real.slots);

    // Every send completes exactly once, with its own id, and the slots come back free.
    var completions: [slots_count]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, slots_count, fixture.remote);
    var seen: [slots_count]bool = @splat(false);
    for (completions) |completion| {
        try testing.expect(completion.id < slots_count);
        try testing.expect(!seen[@intCast(completion.id)]);
        seen[@intCast(completion.id)] = true;
        try testing.expectEqual(@as(u32, 1), try completion.result.send);
    }
    try testing.expectEqual(@as(u32, 0), fixture.real.inFlight());
    try fixture.send(id, "z");
    try pollUntil(&fixture.real, completions[0..1], 1, fixture.remote);
    try testing.expectEqual(id, completions[0].id);
}

/// A `Real` with only the fields `sendResult` reads and writes set, so the errno tests
/// need no ring and run where io_uring is switched off.
fn sendResultOnly() Real {
    var real: Real = undefined;
    real.send_errno_undocumented_count = 0;
    real.send_errno_undocumented_last = .SUCCESS;
    return real;
}

/// Raw completion result for a failed send.
fn sendFailed(err: linux.E) i32 {
    return -@as(i32, @backingInt(err));
}

const send_errnos_peer_down = [_]linux.E{
    .PIPE,        .CONNRESET,  .CONNABORTED, .NOTCONN,  .SHUTDOWN, .TIMEDOUT,
    .HOSTUNREACH, .NETUNREACH, .NETDOWN,     .HOSTDOWN, .NETRESET, .CONNREFUSED,
    .ACCES,       .PERM,       .IO,          .PROTO,
};
const send_errnos_backpressure = [_]linux.E{ .AGAIN, .NOBUFS, .NOMEM, .INTR };
const send_errnos_bug = [_]linux.E{
    .BADF,    .NOTSOCK,     .FAULT,  .INVAL,    .OPNOTSUPP,
    .MSGSIZE, .DESTADDRREQ, .ISCONN, .CANCELED, .ALREADY,
};

/// Errnos send(2) doesn't document: some std names, the top of the kernel's range, and a
/// value std has no name for.
const send_errnos_undocumented = [_]linux.E{
    .NOENT,    .EXIST,                .SRCH,                 .NOSPC, .ROFS, .NOSYS,
    .HWPOISON, @fromBackingInt(4095), @fromBackingInt(1000),
};

test "real: every documented send errno has an outcome, counted nowhere" {
    var real = sendResultOnly();
    for (send_errnos_peer_down) |err| {
        try testing.expectEqual(SendOutcome.peer_down, sendErrno(err));
        try testing.expectError(error.PeerDown, real.sendResult(sendFailed(err), 5));
    }
    for (send_errnos_backpressure) |err| {
        try testing.expectEqual(SendOutcome.backpressure, sendErrno(err));
        try testing.expectError(error.Backpressure, real.sendResult(sendFailed(err), 5));
    }
    try testing.expectEqual(@as(u64, 0), real.send_errno_undocumented_count);
    try testing.expectEqual(linux.E.SUCCESS, real.send_errno_undocumented_last);
}

test "real: a send errno only a bug causes is a bug, not a dropped connection" {
    // `sendResult` stops the process on these, so only the mapping is checked here.
    for (send_errnos_bug) |err| {
        try testing.expectEqual(SendOutcome.bug, sendErrno(err));
    }
}

test "real: an undocumented send errno is PeerDown and is counted" {
    var real = sendResultOnly();
    for (send_errnos_undocumented, 1..) |err, count| {
        try testing.expectEqual(SendOutcome.peer_down_undocumented, sendErrno(err));
        try testing.expectError(error.PeerDown, real.sendResult(sendFailed(err), 5));
        try testing.expectEqual(@as(u64, count), real.send_errno_undocumented_count);
        try testing.expectEqual(err, real.send_errno_undocumented_last);
    }
    // Documented errnos, bytes and no progress leave the count and the latest errno alone.
    const counted = real.send_errno_undocumented_count;
    try testing.expectError(error.PeerDown, real.sendResult(sendFailed(.PIPE), 5));
    try testing.expectError(error.Backpressure, real.sendResult(sendFailed(.AGAIN), 5));
    try testing.expectError(error.Backpressure, real.sendResult(0, 5));
    try testing.expectEqual(@as(u32, 5), try real.sendResult(5, 5));
    try testing.expectEqual(counted, real.send_errno_undocumented_count);
    const latest = send_errnos_undocumented[send_errnos_undocumented.len - 1];
    try testing.expectEqual(latest, real.send_errno_undocumented_last);
}

test "real: a completion's result maps bytes and no progress" {
    var real = sendResultOnly();
    try testing.expectEqual(@as(u32, 5), try real.sendResult(5, 5));
    try testing.expectEqual(@as(u32, 2), try real.sendResult(2, 5)); // A short send.
    try testing.expectError(error.Backpressure, real.sendResult(0, 5));
    try testing.expectEqual(@as(u64, 0), real.send_errno_undocumented_count);
}

test "real: a poll takes no more completions than its buffer holds; the rest wait" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    try fixture.send(1, "a");
    try fixture.send(2, "b");
    try fixture.send(3, "c");
    var seen: [4]bool = @splat(false);
    var round: u32 = 0;
    while (round < 3) : (round += 1) {
        var one: [1]io.Completion = undefined;
        try pollUntil(&fixture.real, &one, 1, -1);
        try testing.expect(one[0].id >= 1 and one[0].id <= 3);
        try testing.expect(!seen[@intCast(one[0].id)]);
        seen[@intCast(one[0].id)] = true;
        try testing.expectEqual(3 - (round + 1), fixture.real.inFlight());
    }
    var none: [1]io.Completion = undefined;
    try testing.expectEqual(@as(u32, 0), fixture.real.poll(&none));
}

test "real: the memory table covers the ring the kernel maps" {
    var found: ?constants.MemoryRow = null;
    for (constants.memory_table) |row| {
        if (std.mem.eql(u8, row.name, ring_row_name)) found = row;
    }
    const row = found orelse return error.TestExpectedRow;
    try testing.expect(row.count * row.size >= ring_bytes_estimate);
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    const ring = &fixture.real.ring;
    const mapped = @as(u64, ring.sq.mmap.len) + ring.sq.mmap_sqes.len + @sizeOf(Real);
    try testing.expect(mapped <= ring_bytes_estimate);
}

const ring_row_name = "io_uring ring and in-flight table of the real I/O type";

/// A TCP listener on 127.0.0.1, at a port the kernel picks, and a client socket for it.
const Loopback = struct {
    listener: linux.fd_t,
    client: linux.fd_t,
    address: linux.sockaddr.in,

    fn open(self: *Loopback) !void {
        const flags = linux.SOCK.STREAM | linux.SOCK.CLOEXEC;
        self.listener = try socketOpen(linux.AF.INET, flags);
        errdefer _ = linux.close(self.listener);
        self.address = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f00_0001) };
        var length: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.bind(self.listener, @ptrCast(&self.address), length)));
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.listen(self.listener, 4)));
        // Port 0 asked the kernel to pick one; read back which.
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.getsockname(self.listener, @ptrCast(&self.address), &length)));
        try testing.expect(self.address.port != 0);
        self.client = try socketOpen(linux.AF.INET, flags);
        assert(self.listener != self.client);
        assert(self.address.family == linux.AF.INET);
    }

    /// Connects the client. On loopback the kernel completes the handshake from the
    /// listener's backlog, before anything accepts it.
    fn connect(self: *Loopback) !void {
        assert(self.client >= 0);
        assert(self.address.port != 0);
        const rc = linux.connect(self.client, @ptrCast(&self.address), @sizeOf(linux.sockaddr.in));
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    }

    fn close(self: *Loopback) void {
        assert(self.listener >= 0);
        assert(self.client >= 0);
        _ = linux.close(self.client);
        _ = linux.close(self.listener);
    }
};

fn socketOpen(domain: u32, flags: u32) !linux.fd_t {
    assert(flags & linux.SOCK.CLOEXEC != 0);
    const rc = linux.socket(domain, flags, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    const socket: linux.fd_t = @intCast(rc);
    assert(socket >= 0);
    return socket;
}

test "real: an accept over a loopback listener takes a table entry for the connection" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    var loopback: Loopback = undefined;
    try loopback.open();
    defer loopback.close();

    try fixture.real.submit(.{ .id = 9, .operation = .{ .accept = .{ .listener = loopback.listener } } });
    try testing.expectEqual(@as(u32, 1), fixture.real.inFlight());
    try loopback.connect();
    var completions: [2]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, 1, -1);
    try testing.expectEqual(@as(io.OperationId, 9), completions[0].id);
    const peer = try completions[0].result.accept;
    // Released first on any failure below, so the fixture's teardown reports nothing false.
    const socket = fixture.table.get(peer).socket;
    defer _ = linux.close(fixture.table.release(peer));
    try testing.expectEqual(@as(u32, 2), fixture.table.count());
    try testing.expectEqual(connections.State.reading, fixture.table.get(peer).state);
    try testing.expectEqual(@as(u64, 0), fixture.real.refused);

    // The accepted socket is closed on exec, so a child process never inherits it.
    const descriptor_flags = linux.fcntl(socket, linux.F.GETFD, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(descriptor_flags));
    try testing.expect(descriptor_flags & linux.FD_CLOEXEC != 0);

    // The entry's socket is the accepted end: bytes from the client arrive on it.
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.write(loopback.client, "hi", 2)));
    var received: [4]u8 = undefined;
    const rc = linux.read(socket, &received, received.len);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    try testing.expectEqualStrings("hi", received[0..rc]);
}

test "real: an accept into a full table closes the connection and completes with TableFull" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    var loopback: Loopback = undefined;
    try loopback.open();
    defer loopback.close();
    // Fill the rest of the table with descriptor numbers no test opens; the table never
    // touches them.
    var fillers: [3]io.PeerId = undefined;
    for (&fillers, 0..) |*filler, index| filler.* = try fixture.table.acquire(@intCast(1_000_000 + index));
    defer for (fillers) |filler| {
        _ = fixture.table.release(filler);
    };
    try testing.expectEqual(fixture.table.capacity(), fixture.table.count());

    try fixture.real.submit(.{ .id = 4, .operation = .{ .accept = .{ .listener = loopback.listener } } });
    try loopback.connect();
    var completions: [1]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, 1, -1);
    try testing.expectEqual(@as(io.OperationId, 4), completions[0].id);
    try testing.expectError(error.TableFull, completions[0].result.accept);
    try testing.expectEqual(@as(u64, 1), fixture.real.refused);
    try testing.expectEqual(fixture.table.capacity(), fixture.table.count());

    // The refused connection was closed before the completion was handed back, so the
    // client reads end of stream. Reads never wait, and are retried a bounded number of
    // times, 1 ms apart, in case the close reaches the client late: a connection left open
    // fails the test instead of hanging it.
    var received: [1]u8 = undefined;
    var rc: usize = 0;
    var attempts: u32 = 0;
    while (attempts < poll_attempts_max) : (attempts += 1) {
        rc = linux.recvfrom(loopback.client, &received, received.len, linux.MSG.DONTWAIT, null, null);
        if (linux.errno(rc) != .AGAIN) break;
        const pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
        _ = linux.nanosleep(&pause, null);
    }
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    try testing.expectEqual(@as(usize, 0), rc);
}

test "real: every accept errno has an outcome" {
    try testing.expectEqual(error.PeerDown, acceptError(.CONNABORTED));
    try testing.expectEqual(error.PeerDown, acceptError(.PERM));
    try testing.expectEqual(error.PeerDown, acceptError(.PROTO));
    try testing.expectEqual(error.PeerDown, acceptError(.NOPROTOOPT));
    try testing.expectEqual(error.PeerDown, acceptError(.NONET));
    try testing.expectEqual(error.PeerDown, acceptError(.HOSTDOWN));
    try testing.expectEqual(error.PeerDown, acceptError(.HOSTUNREACH));
    try testing.expectEqual(error.PeerDown, acceptError(.NETDOWN));
    try testing.expectEqual(error.PeerDown, acceptError(.NETUNREACH));
    try testing.expectEqual(error.PeerDown, acceptError(.TIMEDOUT));
    try testing.expectEqual(error.PeerDown, acceptError(.NOSR));
    try testing.expectEqual(error.PeerDown, acceptError(.SOCKTNOSUPPORT));
    try testing.expectEqual(error.PeerDown, acceptError(.PROTONOSUPPORT));
    try testing.expectEqual(error.Backpressure, acceptError(.MFILE));
    try testing.expectEqual(error.Backpressure, acceptError(.NFILE));
    try testing.expectEqual(error.Backpressure, acceptError(.NOBUFS));
    try testing.expectEqual(error.Backpressure, acceptError(.NOMEM));
    try testing.expectEqual(error.Backpressure, acceptError(.INTR));
    try testing.expectEqual(error.Backpressure, acceptError(.AGAIN));
}

test "real: a failed accept changes no table entry" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    const aborted = -@as(i32, @backingInt(linux.E.CONNABORTED));
    const short = -@as(i32, @backingInt(linux.E.MFILE));
    try testing.expectError(error.PeerDown, fixture.real.acceptResult(aborted));
    try testing.expectError(error.Backpressure, fixture.real.acceptResult(short));
    try testing.expectEqual(@as(u32, 1), fixture.table.count());
    try testing.expectEqual(@as(u64, 0), fixture.real.refused);
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

/// Far ends in the send soak. Reason: enough that closes and live peers mix in one run, few
/// enough that each gets thousands of bytes.
const soak_peers_count: u32 = 4;
/// Rounds per seed. Each round tops the ring up and then polls part of it back.
const soak_rounds_max: u32 = 32;
/// Every `soak_fill_every`-th round fills the ring to its depth, so every slot is taken.
const soak_fill_every: u32 = 8;
/// A round closes a far end with odds of one in this many. Reason: about four closes in a
/// run of 32 rounds, so most seeds close all three closable far ends partway through.
const soak_close_odds: u32 = 8;
/// Largest send. Reason: small enough that a peer's socket buffer rarely fills; when it
/// does, the send waits in the kernel until `pollDown` drains that far end.
const soak_send_bytes_max: u32 = 512;
/// Operation ids a run can use: each round submits at most a full ring.
const soak_operations_max: u32 = soak_rounds_max * slots_count;
/// The buffer one read of a far end fills.
const soak_scratch_bytes: u32 = 4096;
/// Reads per drain of one far end. Reason: a full ring of the largest sends to one peer is
/// 128 KiB, 32 reads; the rest is margin.
const soak_reads_max: u32 = 1_024;
/// Empty polls in a row before the soak gives up on the kernel, 1 ms apart.
const soak_empty_polls_max: u32 = poll_attempts_max;
/// Seeds the soak replays. A failed check prints its seed. Each seed's schedule (targets,
/// peers, lengths, closes, how many to poll back) comes from one stream, and poll buffer
/// sizes from a second, so kernel timing can't change what a seed submits.
const soak_seeds = [_]u64{ 0x5eed, 1, 2, 3, 4, 5, 0xdead_beef, 0x0123_4567_89ab_cdef };

comptime {
    assert(soak_peers_count >= 2); // Peer 0 is never closed; at least one other is closable.
    assert(soak_peers_count <= std.math.maxInt(u8)); // SoakOperation.peer is a u8.
    assert(soak_rounds_max >= 2 * soak_fill_every); // At least two full rounds: slots reused.
    assert(soak_send_bytes_max <= constants.http_response_size_max);
    // One drain can read a full ring's bytes to one peer, so the final drain empties it.
    assert(@as(u64, slots_count) * soak_send_bytes_max <= @as(u64, soak_reads_max - 1) * soak_scratch_bytes);
}

/// What the soak knows about one operation it submitted.
const SoakOperation = struct {
    peer: u8,
    length: u32,
    /// The far end was closed before this send was submitted, so it must end in PeerDown.
    after_close: bool,
    completions: u8,
};

/// A seeded run of many sends over several socketpairs, with far ends closed partway.
/// Set up in place, because `Real` keeps a pointer to the table.
const Soak = struct {
    seed: u64,
    /// The schedule: targets, peers, lengths, closes and how many to poll back.
    schedule: std.Random.DefaultPrng,
    /// Poll buffer sizes only; how many are drawn depends on kernel timing.
    poll_sizes: std.Random.DefaultPrng,
    startup: StartupAllocator,
    gpa: std.mem.Allocator,
    table: connections.Table,
    real: Real,
    locals: [soak_peers_count]linux.fd_t,
    /// -1 once the soak has closed it.
    remotes: [soak_peers_count]linux.fd_t,
    peers: [soak_peers_count]io.PeerId,
    operations: [soak_operations_max]SoakOperation,
    /// Operation ids handed out so far; the next id is this.
    submitted: u32,
    completed: u32,
    /// Times each slot was taken by a submission.
    slot_uses: [slots_count]u32,
    /// Bytes successful completions report sent, and bytes the far end has read, per peer.
    sent: [soak_peers_count]u64,
    received: [soak_peers_count]u64,
    sends_after_close: u32,
    peer_down: u32,
    closes: u32,
    /// Every send points into this; it never changes, so no send's bytes move in flight.
    bytes: [soak_send_bytes_max]u8,

    fn setUp(self: *Soak, seed: u64) !void {
        self.seed = seed;
        self.schedule = .init(seed);
        self.poll_sizes = .init(seed ^ 0x9e37_79b9_7f4a_7c15);
        self.locals = @splat(-1);
        self.remotes = @splat(-1);
        errdefer for (self.locals, self.remotes) |local, remote| {
            if (local >= 0) _ = linux.close(local);
            if (remote >= 0) _ = linux.close(remote);
        };
        self.startup = .init(testing.allocator, soak_peers_count * connections.entry_bytes);
        self.gpa = self.startup.allocator();
        self.table = try connections.Table.init(self.gpa, soak_peers_count);
        errdefer self.table.deinit(self.gpa);
        for (&self.locals, &self.remotes, &self.peers) |*local, *remote, *peer| {
            var fds: [2]linux.fd_t = undefined;
            const flags = linux.SOCK.STREAM | linux.SOCK.CLOEXEC;
            try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.socketpair(linux.AF.UNIX, flags, 0, &fds)));
            local.* = fds[0];
            remote.* = fds[1];
            peer.* = try self.table.acquire(fds[0]);
        }
        self.real = try Real.init(&self.startup, &self.table);
        self.startup.finishStartup();
        self.submitted = 0;
        self.completed = 0;
        self.slot_uses = @splat(0);
        self.sent = @splat(0);
        self.received = @splat(0);
        self.sends_after_close = 0;
        self.peer_down = 0;
        self.closes = 0;
        var position: u32 = 0;
        while (position < soak_send_bytes_max) : (position += 1) self.bytes[position] = @truncate(position);
        assert(self.real.inFlight() == 0);
        assert(self.table.count() == soak_peers_count);
    }

    /// Closes the ring first, so nothing in flight still names a socket. After a failed
    /// check, operations may still be in flight: they are polled back and dropped. If some
    /// never come back, the ring is left open and false is returned, so the caller leaks
    /// this rather than free bytes the kernel may still read; the check's failure shows
    /// instead of `deinit`'s assertion.
    fn tearDown(self: *Soak) bool {
        assert(self.table.count() == soak_peers_count);
        assert(self.startup.phase == .running);
        var completions: [slots_count]io.Completion = undefined;
        var polls: u32 = 0;
        while (self.real.inFlight() > 0 and polls < soak_empty_polls_max) : (polls += 1) {
            if (self.real.poll(&completions) > 0) continue;
            _ = self.drain();
            const pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
            _ = linux.nanosleep(&pause, null);
        }
        const settled = self.real.inFlight() == 0;
        if (settled) self.real.deinit();
        for (self.peers, self.locals) |peer, local| assert(self.table.release(peer) == local);
        self.startup.beginShutdown();
        self.table.deinit(self.gpa);
        assert(self.startup.bytes_live == 0);
        for (self.locals, self.remotes) |local, remote| {
            _ = linux.close(local);
            if (remote >= 0) _ = linux.close(remote);
        }
        return settled;
    }

    /// Submits one send of random length to a random peer, and checks the slot it took.
    fn submitOne(self: *Soak) !void {
        assert(self.real.inFlight() < slots_count);
        assert(self.submitted < soak_operations_max);
        const random = self.schedule.random();
        const peer = random.uintLessThan(u8, soak_peers_count);
        const length = random.intRangeAtMost(u32, 1, soak_send_bytes_max);
        const id = self.submitted;
        const after_close = self.remotes[peer] < 0;
        self.operations[id] = .{ .peer = peer, .length = length, .after_close = after_close, .completions = 0 };
        try self.real.submit(.{
            .id = id,
            .operation = .{ .send = .{ .peer = self.peers[peer], .bytes = self.bytes[0..length] } },
        });
        self.submitted += 1;
        if (after_close) self.sends_after_close += 1;
        // Exactly one slot in use holds the new id; found by search, so the test doesn't
        // depend on how the free list orders slots.
        var found: ?u32 = null;
        for (self.real.slots, 0..) |slot, index| {
            if (!slot.in_use or slot.id != id) continue;
            try testing.expect(found == null);
            found = @intCast(index);
        }
        const index = found orelse return error.TestExpectedSlot;
        self.slot_uses[index] += 1;
        try testing.expectEqual(self.submitted - self.completed, self.real.inFlight());
    }

    /// Checks one completion against what was submitted, and counts it.
    fn record(self: *Soak, completion: io.Completion) !void {
        try testing.expect(self.completed < self.submitted);
        try testing.expect(completion.id < self.submitted);
        const operation = &self.operations[@intCast(completion.id)];
        try testing.expectEqual(@as(u8, 0), operation.completions); // Exactly once.
        operation.completions = 1;
        self.completed += 1;
        if (completion.result.send) |sent| {
            try testing.expect(!operation.after_close);
            try testing.expect(sent > 0 and sent <= operation.length);
            self.sent[operation.peer] += sent;
        } else |err| switch (err) {
            // Only a closed far end makes a send fail. A send in flight when its far end
            // closed may still have gone through, but one submitted after can't.
            error.PeerDown => {
                try testing.expect(self.remotes[operation.peer] < 0);
                self.peer_down += 1;
            },
            // A send on a blocking socketpair waits in the kernel instead of failing with
            // EAGAIN; only a machine out of buffers (ENOBUFS, ENOMEM) could report this.
            error.Backpressure => return error.TestUnexpectedBackpressure,
        }
        assert(self.completed <= self.submitted);
    }

    /// Reads whatever the open far ends have received, without waiting. Returns whether
    /// every open far end was read until it had nothing more.
    fn drain(self: *Soak) bool {
        assert(self.closes < soak_peers_count);
        assert(self.remotes[0] >= 0);
        var empty: bool = true;
        for (self.remotes, &self.received) |remote, *received| {
            if (remote < 0) continue;
            var scratch: [soak_scratch_bytes]u8 = undefined;
            var reads: u32 = 0;
            while (reads < soak_reads_max) : (reads += 1) {
                const rc = linux.recvfrom(remote, &scratch, scratch.len, linux.MSG.DONTWAIT, null, null);
                if (linux.errno(rc) != .SUCCESS or rc == 0) break;
                assert(rc <= scratch.len);
                received.* += @as(u32, @intCast(rc));
            }
            if (reads == soak_reads_max) empty = false;
        }
        return empty;
    }

    /// Polls until exactly `leftover` operations are in flight, never asking for more
    /// completions than that leaves. Fails the test if the kernel stops completing.
    fn pollDown(self: *Soak, leftover: u32) !void {
        assert(leftover <= self.real.inFlight());
        assert(leftover < slots_count);
        var completions: [slots_count]io.Completion = undefined;
        var empty_polls: u32 = 0;
        var polls: u32 = 0;
        // Each non-empty poll takes at least one completion, so at most slots_count of them,
        // each after at most soak_empty_polls_max empty ones.
        const polls_max: u32 = slots_count * (soak_empty_polls_max + 1);
        while (self.real.inFlight() > leftover and empty_polls < soak_empty_polls_max) : (polls += 1) {
            assert(polls < polls_max);
            const wanted = self.real.inFlight() - leftover;
            const size = self.poll_sizes.random().intRangeAtMost(u32, 1, wanted);
            const got = self.real.poll(completions[0..size]);
            for (completions[0..got]) |completion| try self.record(completion);
            _ = self.drain();
            if (got > 0) {
                empty_polls = 0;
                continue;
            }
            empty_polls += 1;
            const pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
            _ = linux.nanosleep(&pause, null);
        }
        try testing.expectEqual(leftover, self.real.inFlight());
        try testing.expectEqual(self.submitted - self.completed, self.real.inFlight());
    }

    /// Closes one random far end other than peer 0, if any is still open. Our own end stays
    /// open, as the contract requires while its sends are in flight.
    fn closeOne(self: *Soak) !void {
        assert(self.remotes[0] >= 0);
        const closes_before = self.closes;
        const start = self.schedule.random().intRangeAtMost(u32, 1, soak_peers_count - 1);
        var probes: u32 = 0;
        while (probes < soak_peers_count - 1) : (probes += 1) {
            const peer = 1 + (start - 1 + probes) % (soak_peers_count - 1);
            if (self.remotes[peer] < 0) continue;
            try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.close(self.remotes[peer])));
            self.remotes[peer] = -1;
            self.closes += 1;
            break;
        }
        assert(self.closes <= closes_before + 1);
        assert(self.closes < soak_peers_count);
    }

    /// A full ring refuses one more submission and changes nothing.
    fn expectFullRefusal(self: *Soak) !void {
        assert(self.real.inFlight() == slots_count);
        assert(self.real.free_count == 0);
        const submitted_before = self.real.submitted;
        const sqe_tail_before = self.real.ring.sq.sqe_tail;
        const slots_before = self.real.slots;
        const refused: io.Submission = .{
            .id = self.submitted,
            .operation = .{ .send = .{ .peer = self.peers[0], .bytes = self.bytes[0..1] } },
        };
        try testing.expectError(error.QueueFull, self.real.submit(refused));
        try testing.expectEqual(submitted_before, self.real.submitted);
        try testing.expectEqual(sqe_tail_before, self.real.ring.sq.sqe_tail);
        try testing.expectEqualSlices(Slot, &slots_before, &self.real.slots);
        try testing.expectEqual(slots_count, self.real.inFlight());
    }

    /// One round: top the ring up to a target, maybe close a far end, poll part of it back.
    fn round(self: *Soak, number: u32) !void {
        assert(number < soak_rounds_max);
        assert(self.real.inFlight() < slots_count);
        const random = self.schedule.random();
        // At least one send a round, so there is always something to poll back.
        const target = if (number % soak_fill_every == 0)
            slots_count
        else
            random.intRangeAtMost(u32, self.real.inFlight() + 1, slots_count);
        var submissions: u32 = 0;
        while (self.real.inFlight() < target) : (submissions += 1) {
            assert(submissions < slots_count);
            try self.submitOne();
        }
        if (target == slots_count) try self.expectFullRefusal();
        // Random closes, plus one before the second full round if none came yet, so every
        // seed sends to a closed far end.
        const forced = number == soak_fill_every - 1 and self.closes == 0;
        if (forced or random.uintLessThan(u32, soak_close_odds) == 0) try self.closeOne();
        try self.pollDown(random.uintLessThan(u32, self.real.inFlight()));
    }

    /// Runs every round, then lets everything finish and checks the totals.
    fn run(self: *Soak) !void {
        assert(self.submitted == 0);
        assert(self.real.inFlight() == 0);
        errdefer std.debug.print("real: send soak failed with seed 0x{x}\n", .{self.seed});
        var number: u32 = 0;
        while (number < soak_rounds_max) : (number += 1) try self.round(number);
        try self.pollDown(0);
        try self.checkTotals();
    }

    /// After the run: every operation completed once, every slot was reused, and each far
    /// end never closed read exactly the bytes its sends reported.
    fn checkTotals(self: *Soak) !void {
        assert(self.real.inFlight() == 0);
        assert(self.submitted <= soak_operations_max);
        try testing.expectEqual(self.submitted, self.completed);
        try testing.expectEqual(@as(u64, self.submitted), self.real.submitted);
        try testing.expectEqual(self.real.submitted, self.real.completed);
        for (self.operations[0..self.submitted]) |operation| {
            try testing.expectEqual(@as(u8, 1), operation.completions);
        }
        for (self.slot_uses) |uses| try testing.expect(uses >= 2);
        // Every send has completed, so every byte reported sent is already in a far end's
        // buffer: one drain reads all of it.
        try testing.expect(self.drain());
        for (self.remotes, self.sent, self.received) |remote, sent, received| {
            if (remote >= 0) try testing.expectEqual(sent, received);
        }
        try testing.expect(self.sent[0] > 0);
        // The run did what it is for: sends after a close, each of which failed.
        try testing.expect(self.sends_after_close >= 1);
    }
};

test "real: a seeded send soak over socketpairs completes every send once and frees every slot" {
    for (soak_seeds) |seed| {
        const soak = try testing.allocator.create(Soak);
        soak.setUp(seed) catch |err| {
            testing.allocator.destroy(soak);
            return err;
        };
        // A soak whose ring never settled is leaked on purpose; see `tearDown`.
        defer if (soak.tearDown()) testing.allocator.destroy(soak);
        try soak.run();
    }
}
