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
//! Slots kept for accepts and cancels: sends and receives share at most
//! `constants.io_shared_in_flight_max` slots, counted in `share` (`io.SlotShare`, shared
//! with the simulator), and one past that returns `error.SlotsKeptForAccepts` and changes
//! nothing, even with a slot free. Cancels have `constants.io_cancels_in_flight_max` slots
//! of their own, and one past those returns `error.CancelsFull`. The rest,
//! `constants.accepts_in_flight_max`, stay for accepts, so clients that stop reading, each
//! with a send stuck on a full socket buffer, can't take the whole ring and stop the server
//! accepting anyone else, or cancelling a connection whose drops ran out. Accepts are counted in `share` too: one past
//! `constants.accepts_in_flight_max` is a caller's bug, since each holds a descriptor when it
//! completes, so `submit` stops the process on it before checking the ring.
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
//! A send's socket number is read from the table at submit, but the kernel may take the
//! send only at a later `submit` or `poll` (`enter` can be refused for a moment), and acts
//! on it until its completion. So `submit` counts each send on its connection's entry
//! (`Table.sendSubmitted`) and its completion uncounts it (`Table.sendCompleted`); the table
//! refuses to release an entry while any are counted, so the socket can't be closed and
//! its number handed to the next accepted connection while a send still names it.
//!
//! Dropping a connection: a send to a client that stops reading waits in the kernel for
//! room in the socket buffer, with no end, and holds its slot and its entry meanwhile.
//! `drop` shuts the connection's socket down both ways (`shutdown(2)`, `SHUT_RDWR`), so the
//! kernel fails every send still pending on it (`EPIPE`, so `PeerDown`) and the client
//! reads end of stream; the caller then releases the entry once its last send has
//! completed, and closes the socket. Each errno shutdown(2) documents is handled as for
//! sends (`shutdownErrno`): a connection already gone is dropped already, a bad descriptor
//! stops the process, and an undocumented errno is counted in
//! `drop_errno_undocumented_count`, with the latest one in `drop_errno_undocumented_last`.
//! An undocumented errno also leaves the connection's sends pending, so it counts as a
//! failed drop on the connection's entry (`Table.dropFailed`). Each drop first asks the
//! entry (`Table.dropAdmit`), so once `constants.io_drop_attempts_max` have failed, drop
//! returns `error.DropsExhausted` without calling shutdown again, and the caller cancels the
//! connection's operations instead. The simulator makes the same two calls.
//!
//! Receives: `IORING_OP_RECV` on the peer's socket into the caller's buffer, counted on the
//! peer's entry (`Table.receiveSubmitted`, at most one per connection) until its completion
//! (`Table.receiveCompleted`), as sends are. It completes with the bytes read, or 0 when the
//! peer closed its side, or when the connection was dropped: a shutdown ends a pending
//! receive as end of stream. Each errno recv(2) documents maps as for sends
//! (`receiveErrno`); an undocumented one is `PeerDown`, counted in
//! `receive_errno_undocumented_count` with the latest in `receive_errno_undocumented_last`.
//!
//! Cancels: `IORING_OP_ASYNC_CANCEL` with `IORING_ASYNC_CANCEL_FD` and
//! `IORING_ASYNC_CANCEL_ALL` on the peer's socket (Linux 5.19 or later), so every send and
//! receive in flight on that socket completes with `ECANCELED`, which this type hands back
//! as `error.Canceled`, after checking the entry was canceled (`Table.assertCanceled`). One
//! the kernel was already running in a worker thread is interrupted instead (`EINTR`, which
//! would be Backpressure); on a canceled entry that is handed back as `error.Canceled` too,
//! since the caller is closing it either way. The cancel itself is counted on the entry
//! (`Table.cancelSubmitted`) and completes with the number of operations it reached, which
//! the kernel counts per worker on its slow path, so treat it as a hint. A kernel that refuses the flags returns `EINVAL`, which
//! stops the process with the reason; an errno the cancel isn't documented to return is
//! counted in `cancel_errno_undocumented_count`, with the latest in
//! `cancel_errno_undocumented_last`, and completes as 0 reached, so the caller's next
//! deadline tries again.
//!
//! Accepts: `IORING_OP_ACCEPT` on the caller's listening socket, with `SOCK_CLOEXEC` on the
//! new socket. The completion takes an entry in the connection table for the new socket and
//! hands back its `PeerId`. When the table is full, the new socket is closed at once, so the
//! client sees the connection end instead of waiting, and the accept completes with
//! `error.TableFull`; `refused` counts these. Each errno accept(2) documents maps to
//! `PeerDown` or `Backpressure`, or stops the process when it can only mean a bug in this
//! file or its caller (`acceptErrno`). An errno accept(2) doesn't document is a fact about
//! the kernel this file didn't know, not a reason to stop serving everyone: it maps to
//! `Backpressure`, so the caller accepts again later rather than at once (a listener that
//! keeps failing the same way can't spin the loop), and is counted in
//! `accept_errno_undocumented_count`, with the latest one kept in
//! `accept_errno_undocumented_last`.
//!
//! Waiting after Backpressure: when an accept completes with `error.Backpressure`, `poll`
//! reads the clock and starts `accept_wait` (`io.AcceptWait`, shared with the simulator)
//! from that reading. Until the clock is `constants.io_accept_backpressure_wait_ns` past it,
//! `submit` refuses every accept with `error.AcceptTooSoon`, takes no slot and counts the
//! refusal; the first accept submitted after that clears the wait. Each Backpressure starts
//! the wait again. Sends are never held back, and a full ring is reported first, as
//! `error.QueueFull`, when both hold.
//!
//! Errnos are printed as numbers (`{d}` of `@backingInt`), never by name: `linux.E` is
//! non-exhaustive, and printing a value std has no name for stops the process with "invalid
//! enum value" instead of the message meant.
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
//! `constants.http_response_size_max` bytes; receives into at most
//! `constants.http_request_size_max` bytes; 1 to `constants.io_random_bytes_max` random
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
const listener = @import("listener.zig");

const ns_per_s: u64 = std.time.ns_per_s;

/// Largest whole-second count whose every nanosecond still fits a u64 reading:
/// seconds * ns_per_s + (ns_per_s - 1) <= maxInt(u64). About 584 years of uptime.
const clock_seconds_max: u64 = (std.math.maxInt(u64) - (ns_per_s - 1)) / ns_per_s;

/// Operations in flight, and the ring's submission queue depth.
const slots_count: u32 = constants.io_operations_in_flight_max;

/// Slots sends and receives may hold at once; the rest are kept for accepts and cancels.
const shared_slots_max: u32 = constants.io_shared_in_flight_max;

/// One operation in flight: what its completion needs to be checked and handed back.
const Slot = struct {
    id: io.OperationId,
    /// A send, a receive, an accept or a cancel: `submit` refuses a statement.
    kind: io.Kind,
    /// Bytes a send was given, or a receive's buffer holds; the kernel never reports more.
    /// 0 for an accept or a cancel.
    length: u32,
    /// The connection a send, receive or cancel was counted on, uncounted at its
    /// completion. 0 for an accept.
    peer: io.PeerId,
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
    /// Slots in use that hold a send: never more than `shared_slots_max`.
    sends_in_flight: u32,
    /// Slots in use that hold anything but an accept, counted against the share kept from
    /// accepts through the same calls as in the simulator.
    share: io.SlotShare,
    submitted: u64,
    completed: u64,
    /// Shutdowns `drop` has called, failed or not; a drop refused before calling one is
    /// not counted. For metrics.
    dropped: u64,
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
    /// Accepts that failed with an errno accept(2) doesn't document; each completed as
    /// `Backpressure`. For metrics: any count above zero means `acceptErrno` is missing a
    /// case.
    accept_errno_undocumented_count: u64,
    /// The latest of those errnos, or `.SUCCESS` if there has been none. Print it with
    /// `@backingInt`, as for sends.
    accept_errno_undocumented_last: linux.E,
    /// The wait after an accept completed with `Backpressure`, and the accepts it refused.
    accept_wait: io.AcceptWait,
    /// Drops whose shutdown failed with an errno shutdown(2) doesn't document. For metrics:
    /// any count above zero means `shutdownErrno` is missing a case, and those connections'
    /// sends may still be pending.
    drop_errno_undocumented_count: u64,
    /// The latest of those errnos, or `.SUCCESS` if there has been none. Print it with
    /// `@backingInt`, as for sends.
    drop_errno_undocumented_last: linux.E,
    /// Receives that failed with an errno recv(2) doesn't document; each completed as
    /// `PeerDown`. For metrics: any count above zero means `receiveErrno` is missing a case.
    receive_errno_undocumented_count: u64,
    /// The latest of those errnos, or `.SUCCESS` if there has been none. Print it with
    /// `@backingInt`, as for sends.
    receive_errno_undocumented_last: linux.E,
    /// Cancels that failed with an errno the cancel isn't documented to return; each
    /// completed as 0 reached. For metrics: any count above zero means `cancelErrno` is
    /// missing a case, and those connections' operations may still be pending.
    cancel_errno_undocumented_count: u64,
    /// The latest of those errnos, or `.SUCCESS` if there has been none. Print it with
    /// `@backingInt`, as for sends.
    cancel_errno_undocumented_last: linux.E,
    /// Connections `release` has freed and closed. For metrics and tests.
    released: u64,
    /// Closes, of released connections and of those refused for a full table, that failed
    /// with an errno close(2) isn't documented to return for a socket; on Linux the
    /// descriptor is freed either way. For metrics: any count above zero
    /// means `closeErrno` is missing a case.
    close_errno_undocumented_count: u64,
    /// The latest of those errnos, or `.SUCCESS` if there has been none. Print it with
    /// `@backingInt`, as for sends.
    close_errno_undocumented_last: linux.E,

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
            .slots = @splat(.{ .id = 0, .kind = .send, .length = 0, .peer = 0, .in_use = false }),
            .free_slots = undefined,
            .free_count = slots_count,
            .sends_in_flight = 0,
            .share = .{},
            .submitted = 0,
            .completed = 0,
            .dropped = 0,
            .enters_deferred = 0,
            .refused = 0,
            .send_errno_undocumented_count = 0,
            .send_errno_undocumented_last = .SUCCESS,
            .accept_errno_undocumented_count = 0,
            .accept_errno_undocumented_last = .SUCCESS,
            .accept_wait = .{},
            .drop_errno_undocumented_count = 0,
            .drop_errno_undocumented_last = .SUCCESS,
            .receive_errno_undocumented_count = 0,
            .receive_errno_undocumented_last = .SUCCESS,
            .cancel_errno_undocumented_count = 0,
            .cancel_errno_undocumented_last = .SUCCESS,
            .released = 0,
            .close_errno_undocumented_count = 0,
            .close_errno_undocumented_last = .SUCCESS,
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
    /// arrives, and a cancel names a connection, never the listener, so a caller stops
    /// submitting accepts and waits for the last one before shutting down.
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

    /// Puts one operation on the ring and tries to hand it to the kernel at once. If the
    /// kernel refuses for a moment, the operation stays queued and goes in at the next
    /// `submit` or `poll`, still naming the socket number read now. A send is therefore
    /// counted on its connection's entry until its completion, and the table refuses to
    /// release that entry meanwhile, so the number can't be closed and reused under it.
    /// With every slot in use, returns `error.QueueFull`; for a send or a receive when
    /// those hold every slot they may (`shared_slots_max`), `error.SlotsKeptForAccepts`;
    /// for a cancel when cancels hold all of theirs, `error.CancelsFull`; and for an accept
    /// while the wait after a Backpressure runs, `error.AcceptTooSoon`. The first three
    /// change nothing, the last only the wait's refusal count and the clock's latest
    /// reading, and a full ring wins when it and another hold. An id already in flight
    /// breaks the contract and stops the process, full ring or not, and so do an accept past
    /// `constants.accepts_in_flight_max` and an operation its peer's entry has no room for
    /// (`Table.assertRoomFor`).
    pub fn submit(self: *Real, submission: io.Submission) io.SubmitError!void {
        comptime assertLinux();
        const submitted_before = self.submitted;
        try self.queue(submission);
        if (!enter(&self.ring)) self.enters_deferred += 1;
        assert(self.submitted == submitted_before + 1);
        assert(self.completed + self.inFlight() == self.submitted);
    }

    /// Everything `submit` does except handing the ring to the kernel: takes a slot, fills a
    /// submission entry and counts the operation on its peer. The entry waits on the ring
    /// until the next `enter`, as after a refused one; tests call this directly to hold it
    /// there.
    fn queue(self: *Real, submission: io.Submission) io.SubmitError!void {
        const in_flight_before = self.inFlight();
        // Looked up before anything changes: a peer not in the table, or one whose entry
        // has no room for the operation, is a caller's bug.
        const socket = self.socketFor(submission.operation);
        self.assertIdNotInFlight(submission.id);
        // A second accept past `constants.accepts_in_flight_max` is a caller's bug, checked
        // before the queue, as above.
        self.share.assertAcceptRoom(submission.operation);
        assert(self.sends_in_flight <= shared_slots_max);
        if (self.free_count == 0) return error.QueueFull;
        // The slots past shared_slots_max are kept for accepts and cancels.
        try self.share.admit(submission.operation, self.free_count);
        // Checked last, so a refusal above leaves the wait and the clock as they were. The
        // clock is read only while a wait runs.
        if (submission.operation == .accept and self.accept_wait.resume_at != null) {
            try self.accept_wait.admit(self.now());
        }
        const counted_before = self.countedOnPeer(submission.operation);

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
        self.share.taken(submission.operation);
        // Counted before the kernel can see it, so no completion arrives uncounted.
        self.table.operationSubmitted(submission.operation);
        if (submission.operation == .send) self.sends_in_flight += 1;
        const added: u32 = @intFromBool(io.operationPeer(submission.operation) != null);
        assert(self.countedOnPeer(submission.operation) == counted_before + added);
        assert(self.inFlight() == in_flight_before + 1);
    }

    /// What the peer's entry counts of an operation's kind: its sends, whether a receive is
    /// in flight, or whether a cancel is; 0 for an accept, which names no peer.
    fn countedOnPeer(self: *const Real, operation: io.Operation) u32 {
        assert(operation != .execute); // `socketFor` stopped the process already.
        const count = self.table.operationCount(operation);
        assert(count <= slots_count);
        return count;
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

    /// Shuts `peer`'s connection down both ways, for a caller that is closing it: every send
    /// still pending on its socket, such as one stuck on a client that stopped reading,
    /// completes at a later `poll` with `PeerDown`, and the client reads end of stream.
    /// Dropping a connection again changes nothing more. Takes no slot and completes nothing
    /// itself. The entry stays in use, and its socket open, until the caller releases it,
    /// which the table refuses while a send is still counted; the caller closes the socket
    /// release hands back. `peer` must be live. Never waits. A shutdown that fails with an
    /// errno shutdown(2) doesn't document counts against the connection's
    /// `constants.io_drop_attempts_max`; the drop that reaches it, and every later one,
    /// returns `error.DropsExhausted`, the later ones without calling shutdown.
    pub fn drop(self: *Real, peer: io.PeerId) io.DropError!void {
        comptime assertLinux();
        assert(self.ring.fd >= 0); // Not after deinit.
        assert(self.table.lookup(peer) != null); // A live connection only.
        var kernel: ShutdownKernel = .{};
        return self.dropThrough(ShutdownKernel, &kernel, peer);
    }

    /// Frees `peer`'s entry in the connection table and closes its socket, once nothing is in
    /// flight on it: the end of a connection's life, as an accept was its start. While a
    /// send, a receive or a cancel is still in flight, returns `error.OperationsInFlight`
    /// and changes nothing, so the socket stays open for the kernel to finish with. `peer`
    /// must be live. Never waits: a stream socket's close returns at once.
    pub fn release(self: *Real, peer: io.PeerId) io.ReleaseError!void {
        comptime assertLinux();
        assert(self.ring.fd >= 0); // Not after deinit.
        assert(self.table.lookup(peer) != null); // A live connection only.
        const count_before = self.table.count();
        const socket = try self.table.release(peer);
        assert(socket >= 0);
        assert(socket != self.ring.fd);
        self.closeResult(linux.errno(linux.close(socket)));
        self.released += 1;
        assert(self.table.count() == count_before - 1);
        // The entry's generation moved on, so the id is stale.
        assert(self.table.lookup(peer) == null);
    }

    /// Handles a released socket's close errno: nothing when it closed, a stop for a bug,
    /// a count for an errno close(2) isn't documented to return for a socket.
    fn closeResult(self: *Real, err: linux.E) void {
        if (err == .SUCCESS) return;
        const undocumented_before = self.close_errno_undocumented_count;
        // The count and the latest errno change together, so neither is set without the other.
        assert((undocumented_before == 0) == (self.close_errno_undocumented_last == .SUCCESS));
        const outcome = closeErrno(err);
        switch (outcome) {
            .closed => {},
            .bug => std.debug.panic("close of a released connection's socket: errno {d}", .{@backingInt(err)}),
            .undocumented => {
                self.close_errno_undocumented_count += 1;
                self.close_errno_undocumented_last = err;
            },
        }
        // Only an undocumented errno is counted, once each.
        const counted: u64 = @intFromBool(outcome == .undocumented);
        assert(self.close_errno_undocumented_count == undocumented_before + counted);
    }

    /// Everything `drop` does, with shutdown(2) taken from `shutdown`, so tests can inject
    /// the errnos a real socket never returns on cue. Production passes `ShutdownKernel`.
    fn dropThrough(self: *Real, comptime Shutdown: type, shutdown: *Shutdown, peer: io.PeerId) io.DropError!void {
        const entry = self.table.get(peer);
        // Every send counted on the entry holds one of this type's send slots, and every
        // send slot is in flight.
        assert(entry.sends_in_flight <= self.sends_in_flight);
        assert(self.sends_in_flight <= self.inFlight());
        // Asked before shutdown, so an exhausted connection costs no system call.
        try self.table.dropAdmit(peer);
        const failed = self.shutdownResult(shutdown.shutdown(entry.socket));
        self.dropped += 1;
        if (failed) try self.table.dropFailed(peer);
    }

    /// Handles a drop's shutdown errno: nothing for a connection shut down or gone already,
    /// a stop for a bug, a count for an errno shutdown(2) doesn't document. Returns whether
    /// the drop failed, which only an undocumented errno means: that connection may still
    /// have sends pending, so the caller drops it again later (the server loop's write
    /// deadline), and the count says it happened.
    fn shutdownResult(self: *Real, err: linux.E) bool {
        if (err == .SUCCESS) return false;
        const undocumented_before = self.drop_errno_undocumented_count;
        // The count and the latest errno change together, so neither is set without the other.
        assert((undocumented_before == 0) == (self.drop_errno_undocumented_last == .SUCCESS));
        const outcome = shutdownErrno(err);
        switch (outcome) {
            .dropped => {},
            .bug => std.debug.panic("shutdown of a connection's socket: errno {d}", .{@backingInt(err)}),
            .undocumented => {
                self.drop_errno_undocumented_count += 1;
                self.drop_errno_undocumented_last = err;
            },
        }
        // Only an undocumented errno is counted, once each.
        const counted: u64 = @intFromBool(outcome == .undocumented);
        assert(self.drop_errno_undocumented_count == undocumented_before + counted);
        return outcome == .undocumented;
    }

    /// The contract says ids in flight are distinct; a caller that reuses one has a bug, as
    /// its two completions couldn't be told apart. Scans every slot, at most `slots_count`
    /// steps, and stops the process on a match. Changes no state.
    fn assertIdNotInFlight(self: *const Real, id: io.OperationId) void {
        var occupied: u32 = 0;
        var sends: u32 = 0;
        var accepts: u32 = 0;
        var cancels: u32 = 0;
        var index: u32 = 0;
        while (index < slots_count) : (index += 1) {
            const slot = &self.slots[index];
            if (!slot.in_use) continue;
            occupied += 1;
            if (slot.kind == .send) sends += 1;
            if (slot.kind == .accept) accepts += 1;
            if (slot.kind == .cancel) cancels += 1;
            assert(slot.id != id); // An id already in flight.
        }
        // The slots in use, the free stack, the send count and the shares kept for accepts
        // and cancels are kept separately; they must agree.
        assert(occupied == self.inFlight());
        assert(sends == self.sends_in_flight);
        assert(occupied - accepts - cancels == self.share.others_in_flight);
        assert(accepts == self.share.accepts_in_flight);
        assert(cancels == self.share.cancels_in_flight);
    }

    /// The socket an operation acts on, checked before anything changes: a send's,
    /// receive's or cancel's peer from the table (`get` asserts it is in use, and
    /// `assertRoomFor` that its entry takes the operation), an accept's listener as given.
    /// `execute` stops the process: it is a simulator placeholder.
    fn socketFor(self: *const Real, operation: io.Operation) io.Socket {
        if (operation == .execute) std.debug.panic("io.real: execute is a simulator placeholder; " ++
            "the real type has no database traffic until Postgres is framed over sockets", .{});
        assertOperationBytes(operation);
        const socket: io.Socket = if (io.operationPeer(operation)) |peer| peer: {
            self.table.assertRoomFor(peer, operation);
            break :peer self.table.get(peer).socket;
        } else operation.accept.listener;
        assert(socket >= 0);
        assert(self.free_count <= slots_count);
        return socket;
    }

    /// Frees the slot a completion names and builds its `io.Completion`.
    fn complete(self: *Real, cqe: linux.io_uring_cqe) io.Completion {
        // user_data is always a slot index this type wrote, and each kind posts one
        // completion.
        assert(cqe.user_data < slots_count);
        assert(cqe.flags & linux.IORING_CQE_F_MORE == 0);
        const index: u32 = @intCast(cqe.user_data);
        const slot = self.slots[index];
        assert(slot.in_use); // A completion for a slot with nothing in flight.
        self.slots[index].in_use = false;
        self.free_slots[self.free_count] = index;
        self.free_count += 1;
        self.completed += 1;
        self.share.released(slot.kind);
        assert(self.free_count <= slots_count);
        assert(slot.kind != .execute); // `prepare` never writes one.
        if (slot.kind != .accept) self.uncount(slot);
        const result: io.Result = switch (slot.kind) {
            .send => send: {
                var sent = self.sendResult(cqe.res, slot.length);
                if (sent == error.Backpressure and self.table.get(slot.peer).canceled) sent = error.Canceled;
                // Only a cancel of the send's connection ends it so.
                if (sent == error.Canceled) self.table.assertCanceled(slot.peer);
                break :send .{ .send = sent };
            },
            .receive => receive: {
                var received = self.receiveResult(cqe.res, slot.length);
                if (received == error.Backpressure and self.table.get(slot.peer).canceled) received = error.Canceled;
                if (received == error.Canceled) self.table.assertCanceled(slot.peer);
                break :receive .{ .receive = received };
            },
            .cancel => .{ .cancel = self.cancelResult(cqe.res) },
            .accept => .{ .accept = self.acceptResult(cqe.res) },
            .execute => unreachable, // Asserted above.
        };
        return .{ .id = slot.id, .result = result };
    }

    /// Uncounts a finished send, receive or cancel on its peer's entry. The table refused
    /// to release the peer while the operation was counted, so the id is still live and
    /// names the socket it was submitted on.
    fn uncount(self: *Real, slot: Slot) void {
        const operation = slotOperation(slot);
        const counted_before = self.table.operationCount(operation);
        assert(counted_before > 0); // Counted at submit.
        self.table.operationCompleted(operation);
        assert(self.table.operationCount(operation) == counted_before - 1);
        if (slot.kind == .send) {
            assert(self.sends_in_flight > 0); // Counted at submit, like the peer's.
            self.sends_in_flight -= 1;
        }
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
            .canceled => return error.Canceled,
            // A bad descriptor (a socket closed while its send was in flight), address, flag
            // or length, or a Fast Open this type never asks for: each means a bug in this
            // file or its caller, so the process stops with the reason.
            .bug => std.debug.panic("io_uring send: errno {d}", .{@backingInt(err)}),
            .peer_down_undocumented => {
                self.send_errno_undocumented_count += 1;
                self.send_errno_undocumented_last = err;
                return error.PeerDown;
            },
        }
    }

    /// A receive's result from its completion: the bytes read (0 for end of stream), or the
    /// error its errno means. An undocumented errno completes as `PeerDown` and is counted.
    fn receiveResult(self: *Real, res: i32, length: u32) io.ReceiveError!u32 {
        assert(length > 0);
        assert(length <= constants.http_request_size_max);
        if (res >= 0) {
            const received: u32 = @intCast(res);
            assert(received <= length); // The kernel never reads more than the buffer holds.
            return received;
        }
        assert(res > -4096);
        const err: linux.E = @fromBackingInt(@intCast(-res));
        // The count and the latest errno change together, so neither is set without the other.
        assert((self.receive_errno_undocumented_count == 0) == (self.receive_errno_undocumented_last == .SUCCESS));
        switch (receiveErrno(err)) {
            .peer_down => return error.PeerDown,
            .backpressure => return error.Backpressure,
            .canceled => return error.Canceled,
            .bug => std.debug.panic("io_uring receive: errno {d}", .{@backingInt(err)}),
            .peer_down_undocumented => {
                self.receive_errno_undocumented_count += 1;
                self.receive_errno_undocumented_last = err;
                return error.PeerDown;
            },
        }
    }

    /// A cancel's result from its completion: the operations it reached. An errno the cancel
    /// isn't documented to return is counted and completes as 0 reached.
    fn cancelResult(self: *Real, res: i32) u32 {
        assert(res > -4096);
        if (res >= 0) {
            const reached: u32 = @intCast(res);
            // Only operations in flight can be reached, and the cancel holds a slot itself.
            assert(reached < slots_count);
            return reached;
        }
        const err: linux.E = @fromBackingInt(@intCast(-res));
        // The count and the latest errno change together, so neither is set without the other.
        assert((self.cancel_errno_undocumented_count == 0) == (self.cancel_errno_undocumented_last == .SUCCESS));
        switch (cancelErrno(err)) {
            .none_found => return 0,
            .bug => std.debug.panic("io_uring cancel: errno {d} (cancelling by descriptor " ++
                "needs Linux 5.19 or later)", .{@backingInt(err)}),
            .undocumented => {
                self.cancel_errno_undocumented_count += 1;
                self.cancel_errno_undocumented_last = err;
                return 0;
            },
        }
    }

    /// An accept's result from its completion: the new connection's entry, or the error its
    /// errno means. A full table closes the new socket and counts the refusal; Backpressure
    /// starts the wait before the next accept.
    fn acceptResult(self: *Real, res: i32) io.AcceptError!io.PeerId {
        assert(res > -4096);
        if (res < 0) {
            const err: linux.E = @fromBackingInt(@intCast(-res));
            const resume_before = self.accept_wait.resume_at;
            const failed = self.acceptFailed(err);
            if (failed == error.Backpressure) self.accept_wait.begin(self.now());
            // Only Backpressure touches the wait: a connection that failed says nothing of
            // the system's descriptors or memory.
            assert(failed == error.Backpressure or std.meta.eql(self.accept_wait.resume_at, resume_before));
            return failed;
        }
        const socket: io.Socket = res;
        const count_before = self.table.count();
        const peer = self.table.acquire(socket) catch |err| switch (err) {
            error.TableFull => {
                assert(count_before == self.table.capacity());
                // The same rule as a released connection's close (`closeErrno`): never
                // retried, since a retry could close a descriptor handed out since.
                self.closeResult(linux.errno(linux.close(socket)));
                self.refused += 1;
                return error.TableFull;
            },
        };
        assert(self.table.count() == count_before + 1);
        assert(self.table.get(peer).socket == socket);
        return peer;
    }

    /// The error a failed accept's errno means. An undocumented errno completes as
    /// `Backpressure` and is counted.
    fn acceptFailed(self: *Real, err: linux.E) io.AcceptError {
        assert(err != .SUCCESS);
        // The count and the latest errno change together, so neither is set without the other.
        assert((self.accept_errno_undocumented_count == 0) == (self.accept_errno_undocumented_last == .SUCCESS));
        const result: io.AcceptError = switch (acceptErrno(err)) {
            .peer_down => error.PeerDown,
            .backpressure => error.Backpressure,
            .bug => std.debug.panic("io_uring accept: errno {d}", .{@backingInt(err)}),
            .backpressure_undocumented => undocumented: {
                self.accept_errno_undocumented_count += 1;
                self.accept_errno_undocumented_last = err;
                break :undocumented error.Backpressure;
            },
        };
        // Only a full table, never an errno, means TableFull.
        assert(result == error.PeerDown or result == error.Backpressure);
        return result;
    }
};

/// Fills a submission entry for a send, a receive, an accept or a cancel, and returns the
/// slot that tracks it.
fn prepare(sqe: *linux.io_uring_sqe, submission: io.Submission, socket: io.Socket) Slot {
    assert(socket >= 0);
    var slot: Slot = .{ .id = submission.id, .kind = submission.operation, .length = 0, .peer = 0, .in_use = true };
    switch (submission.operation) {
        .send => |send| {
            sqe.prep_send(socket, send.bytes, linux.MSG.NOSIGNAL);
            slot.length = @intCast(send.bytes.len);
            slot.peer = send.peer;
        },
        .receive => |receive| {
            sqe.prep_recv(socket, receive.buffer, 0);
            slot.length = @intCast(receive.buffer.len);
            slot.peer = receive.peer;
        },
        .cancel => |cancel| {
            // Every request on the socket, not only the first one found.
            sqe.prep_cancel_fd(socket, linux.IORING_ASYNC_CANCEL_ALL);
            slot.peer = cancel.peer;
        },
        // No peer address is asked for: the app listens only where nginx reaches it.
        .accept => sqe.prep_accept(socket, null, null, linux.SOCK.CLOEXEC),
        // `socketFor` stopped the process already.
        .execute => unreachable,
    }
    assert(slot.kind != .execute);
    assert(sqe.fd == socket);
    return slot;
}

/// The operation a slot's completion uncounts on its peer, rebuilt from what the slot
/// kept: only the kind and the peer matter to the table, so the bytes are left empty.
fn slotOperation(slot: Slot) io.Operation {
    assert(slot.in_use);
    assert(slot.kind == .send or slot.kind == .receive or slot.kind == .cancel);
    const operation: io.Operation = switch (slot.kind) {
        .send => .{ .send = .{ .peer = slot.peer, .bytes = "" } },
        .receive => .{ .receive = .{ .peer = slot.peer, .buffer = &.{} } },
        .cancel => .{ .cancel = .{ .peer = slot.peer } },
        .accept, .execute => unreachable, // Asserted above.
    };
    assert(io.operationPeer(operation).? == slot.peer);
    return operation;
}

/// Preconditions on the bytes a send or a receive names: a caller that breaks one has a
/// bug, so these assert.
fn assertOperationBytes(operation: io.Operation) void {
    switch (operation) {
        .send => |send| {
            assert(send.bytes.len > 0);
            assert(send.bytes.len <= constants.http_response_size_max);
        },
        .receive => |receive| {
            assert(receive.buffer.len > 0);
            assert(receive.buffer.len <= constants.http_request_size_max);
        },
        .accept, .cancel, .execute => {},
    }
}

/// What a failed accept's errno means. `backpressure_undocumented` is an errno accept(2)
/// isn't documented to return; `Real.acceptFailed` treats it as `Backpressure` and counts
/// it. `bug` can only mean a bug in this file or its caller; `Real.acceptFailed` stops the
/// process.
const AcceptOutcome = enum { peer_down, backpressure, backpressure_undocumented, bug };

/// Maps a failed accept's errno to its outcome. Pure, so tests can check every arm,
/// including the ones that stop the process.
fn acceptErrno(err: linux.E) AcceptOutcome {
    // Preconditions for any caller, tests included: a failure, in the kernel's errno
    // range of 1 to 4095.
    assert(err != .SUCCESS);
    assert(@backingInt(err) < 4096);
    return switch (err) {
        // The connection failed before it was taken: it aborted, a firewall refused it, or
        // Linux passed on a network error already pending on it (accept(2), "Error
        // handling", and the other errors its ERRORS section says some kernels return).
        // The listener is fine; the caller accepts again.
        .CONNABORTED, .PERM, .PROTO, .NOPROTOOPT, .NONET => .peer_down,
        .HOSTDOWN, .HOSTUNREACH, .NETDOWN, .NETUNREACH, .TIMEDOUT => .peer_down,
        .NOSR, .SOCKTNOSUPPORT, .PROTONOSUPPORT => .peer_down,
        // Out of descriptors, buffers or memory, or interrupted: try again later.
        .MFILE, .NFILE, .NOBUFS, .NOMEM, .INTR, .AGAIN => .backpressure,
        // A bad or non-listening socket, a bad address or flag, or a cancel this type never
        // asks for: each means a bug in this file or its caller. EOPNOTSUPP is on the
        // pending-error list too, but it also means a listener that isn't a stream socket,
        // and every listener here is one, so it is treated as that bug.
        .BADF, .NOTSOCK, .INVAL, .FAULT, .OPNOTSUPP, .CANCELED => .bug,
        // An errno accept(2) isn't documented to return, named in std or not. It says this
        // file's model of the kernel is incomplete, not that this process is broken, and a
        // client might be able to provoke it, so stopping would take the server down for
        // everyone. The caller accepts again later, and `Real.acceptFailed` counts it.
        else => .backpressure_undocumented,
    };
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

/// What a failed send's or receive's errno means. `canceled`: a cancel of its connection
/// reached it. `peer_down_undocumented` is an errno send(2) or recv(2) isn't documented to
/// return; `Real.sendResult` and `Real.receiveResult` treat it as `PeerDown` and count it.
/// `bug` can only mean a bug in this file or its caller; they stop the process.
const SendOutcome = enum { peer_down, backpressure, canceled, peer_down_undocumented, bug };

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
        // A cancel of the connection reached the send; `Real.complete` checks it was asked.
        .CANCELED => .canceled,
        // Only a bug causes these; `Real.sendResult` says which and stops. EALREADY is a
        // second Fast Open in progress, and no send here sets MSG_FASTOPEN.
        .BADF, .NOTSOCK, .FAULT, .INVAL, .OPNOTSUPP, .MSGSIZE, .DESTADDRREQ, .ISCONN => .bug,
        .ALREADY => .bug,
        // An errno send(2) isn't documented to return, named in std or not. It says this
        // file's model of the kernel is incomplete, not that this process is broken, and a
        // client might be able to provoke it, so stopping would take the server down for
        // everyone. Only this connection fails, and the caller counts it.
        else => .peer_down_undocumented,
    };
}

/// Maps a failed receive's errno to its outcome, as `sendErrno` does for sends. Pure, so
/// tests can check every arm, including the ones that stop the process.
fn receiveErrno(err: linux.E) SendOutcome {
    // Preconditions for any caller, tests included: a failure, in the kernel's errno
    // range of 1 to 4095.
    assert(err != .SUCCESS);
    assert(@backingInt(err) < 4096);
    return switch (err) {
        // The connection is gone or unusable, as for sends: the caller closes it.
        .CONNRESET, .CONNREFUSED, .CONNABORTED, .NOTCONN, .TIMEDOUT, .PIPE => .peer_down,
        .HOSTUNREACH, .NETUNREACH, .NETDOWN, .HOSTDOWN, .NETRESET => .peer_down,
        .ACCES, .PERM, .IO, .PROTO => .peer_down,
        // The kernel is short of buffers or the call was interrupted: try again later.
        .AGAIN, .NOBUFS, .NOMEM, .INTR => .backpressure,
        // A cancel of the connection reached the receive; `Real.complete` checks it was asked.
        .CANCELED => .canceled,
        // A descriptor that isn't an open socket, a bad buffer, or a flag this type never
        // sets: each means a bug here or in the caller.
        .BADF, .NOTSOCK, .FAULT, .INVAL, .OPNOTSUPP => .bug,
        // Counted, not fatal, as for sends: only this connection fails.
        else => .peer_down_undocumented,
    };
}

/// What a failed cancel's errno means for `Real.cancelResult`. `none_found`: nothing on the
/// socket was in flight. `bug`: a bad descriptor, or flags the kernel doesn't know (before
/// Linux 5.19). `undocumented`: an errno a cancel isn't documented to return.
const CancelOutcome = enum { none_found, bug, undocumented };

/// Maps a cancel's errno to its outcome. Pure, so tests can check every arm, including the
/// one that stops the process.
fn cancelErrno(err: linux.E) CancelOutcome {
    // Preconditions for any caller, tests included: a failure, in the kernel's errno range
    // of 1 to 4095.
    assert(err != .SUCCESS);
    assert(@backingInt(err) < 4096);
    return switch (err) {
        // ENOENT: no request matched. With IORING_ASYNC_CANCEL_ALL the kernel reports that
        // as 0 reached, but an older path may still return it.
        .NOENT => .none_found,
        // The descriptor is held open by the entry, and the flags are this file's, so
        // these mean a bug or a kernel too old for cancelling by descriptor.
        .BADF, .INVAL => .bug,
        // Counted, not fatal: the caller's next deadline cancels again.
        else => .undocumented,
    };
}

/// What a failed close's errno means for `Real.release`. `closed`: the descriptor is freed
/// all the same. `bug`: only a bug in this file or its caller causes it. `undocumented`: an
/// errno close(2) isn't documented to return for a socket.
const CloseOutcome = enum { closed, bug, undocumented };

/// Maps a close's errno to its outcome. Pure, so tests can check every arm, including the
/// one that stops the process.
fn closeErrno(err: linux.E) CloseOutcome {
    // Preconditions for any caller, tests included: a failure, in the kernel's errno range
    // of 1 to 4095.
    assert(err != .SUCCESS);
    assert(@backingInt(err) < 4096);
    return switch (err) {
        // EINTR and EIO: Linux frees the descriptor even when close is interrupted or
        // reports an I/O error, so retrying could close a number handed out since.
        .INTR, .IO => .closed,
        // A number that isn't open: the table handed back a socket closed already, or one
        // never opened, which only a bug causes.
        .BADF => .bug,
        // ENOSPC and EDQUOT come from files with data to flush, never from a socket;
        // counted, not fatal, since the descriptor is freed either way.
        else => .undocumented,
    };
}

/// What a failed shutdown's errno means for `Real.drop`. `dropped`: the connection was gone
/// already, so no send can stay pending on it. `bug`: only a bug in this file
/// or its caller causes it. `undocumented`: an errno shutdown(2) isn't documented to return.
const DropOutcome = enum { dropped, bug, undocumented };

/// Maps a shutdown's errno to its outcome. Pure, so tests can check every arm, including
/// the one that stops the process.
fn shutdownErrno(err: linux.E) DropOutcome {
    // Preconditions for any caller, tests included: a failure, in the kernel's errno range
    // of 1 to 4095.
    assert(err != .SUCCESS);
    assert(@backingInt(err) < 4096);
    return switch (err) {
        // ENOTCONN: the client is gone already (a stream socket reset or closed under it),
        // so no send waits for it to read.
        .NOTCONN => .dropped,
        // A descriptor that isn't an open socket (a closed or reused number) or a bad `how`:
        // each means a bug here or in the caller.
        .BADF, .NOTSOCK, .INVAL => .bug,
        // Counted, not fatal, as for sends: the kernel's behaviour is a fact this file
        // didn't know, and stopping would take the server down for everyone.
        else => .undocumented,
    };
}

/// The kernel's shutdown(2), both ways, as the source `drop` passes to `dropThrough`.
const ShutdownKernel = struct {
    pub fn shutdown(self: *ShutdownKernel, socket: io.Socket) linux.E {
        _ = self;
        assert(socket >= 0);
        const rc = linux.shutdown(socket, linux.SHUT.RDWR);
        const err = linux.errno(rc);
        // shutdown(2) returns 0 or a failure, never a count.
        assert((rc == 0) == (err == .SUCCESS));
        return err;
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
        else => |err| std.debug.panic("clock_gettime(CLOCK_MONOTONIC) failed: errno {d}", .{@backingInt(err)}),
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
        self.startup = .init(testing.allocator, fixture_table_size * connections.entry_bytes);
        self.gpa = self.startup.allocator();
        self.table = try connections.Table.init(self.gpa, fixture_table_size);
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
        // deinit asserted nothing is in flight, so no send is counted on the peer.
        assert(!self.table.get(self.peer).busy());
        const released = self.table.release(self.peer) catch |err| switch (err) {
            error.OperationsInFlight => unreachable,
        };
        assert(released == self.local);
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

    /// Fills the slots kept for cancels: takes `cancel_entries` more entries, each on the far
    /// end, which nothing on the ring uses, so each cancel reaches nothing, and submits a
    /// cancel of each, ids from `first`. Returns the entries for `releaseCancelled`.
    fn fillCancels(self: *Fixture, first: io.OperationId) ![cancel_entries]io.PeerId {
        assert(self.remote >= 0);
        assert(self.real.share.cancels_in_flight == 0);
        var peers: [cancel_entries]io.PeerId = undefined;
        for (&peers, 0..) |*peer, index| {
            peer.* = try self.table.acquire(self.remote);
            try self.real.submit(.{ .id = first + index, .operation = .{ .cancel = .{ .peer = peer.* } } });
        }
        try testing.expectEqual(cancel_entries, self.real.share.cancels_in_flight);
        return peers;
    }

    /// Takes the cancels `fillCancels` submitted, each reaching nothing, and releases their
    /// entries. Nothing else may complete meanwhile.
    fn releaseCancelled(self: *Fixture, peers: [cancel_entries]io.PeerId, first: io.OperationId) !void {
        var completions: [cancel_entries]io.Completion = undefined;
        try pollUntil(&self.real, &completions, cancel_entries, -1);
        for (completions) |completion| {
            try testing.expect(completion.id >= first and completion.id < first + cancel_entries);
            try testing.expectEqual(@as(u32, 0), completion.result.cancel);
        }
        for (peers) |peer| try testing.expectEqual(self.remote, try self.table.release(peer));
        try testing.expectEqual(@as(u32, 0), self.real.share.cancels_in_flight);
        try testing.expectEqual(@as(u32, 1), self.table.count());
    }
};

/// Entries `Fixture.fillCancels` takes: one for each cancel the ring keeps slots for.
const cancel_entries: u32 = constants.io_cancels_in_flight_max;

/// The fixture's table: the peer, three spare entries, and the cancels' entries.
const fixture_table_size: u32 = 4 + cancel_entries;

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

test "real: a peer with a send in flight is refused release until its completion" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    try fixture.send(5, "held");
    // Counted at submit: whether or not the kernel has taken the send yet, the entry can't be
    // released, so its socket can't be closed and its number reused under the send.
    try testing.expectEqual(@as(connections.SendCount, 1), fixture.table.get(fixture.peer).sends_in_flight);
    const entry_before = fixture.table.get(fixture.peer).*;
    try testing.expectError(error.OperationsInFlight, fixture.table.release(fixture.peer));
    try testing.expectEqual(entry_before, fixture.table.get(fixture.peer).*);
    try testing.expectEqual(@as(u32, 1), fixture.table.count());

    var completions: [1]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, 1, -1);
    try testing.expectEqual(@as(io.OperationId, 5), completions[0].id);
    try testing.expectEqual(@as(u32, 4), try completions[0].result.send);
    // The completion uncounted it: the peer could be released now (the fixture does).
    try testing.expectEqual(@as(connections.SendCount, 0), fixture.table.get(fixture.peer).sends_in_flight);
}

test "real: a send left on the ring before enter holds its peer until its completion" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    // As if the kernel refused the enter: the entry waits on the ring, naming the socket.
    const send: io.Send = .{ .peer = fixture.peer, .bytes = "late" };
    try fixture.real.queue(.{ .id = 6, .operation = .{ .send = send } });
    try testing.expectEqual(@as(u32, 1), fixture.real.ring.sq_ready());
    const entry_before = fixture.table.get(fixture.peer).*;
    try testing.expectEqual(@as(connections.SendCount, 1), entry_before.sends_in_flight);
    try testing.expectError(error.OperationsInFlight, fixture.table.release(fixture.peer));
    try testing.expectEqual(entry_before, fixture.table.get(fixture.peer).*);

    // The next poll hands it to the kernel; it goes out on the socket it was queued with.
    var completions: [1]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, 1, -1);
    try testing.expectEqual(@as(io.OperationId, 6), completions[0].id);
    try testing.expectEqual(@as(u32, 4), try completions[0].result.send);
    try testing.expectEqual(@as(u32, 0), fixture.real.ring.sq_ready());
    try testing.expectEqual(@as(connections.SendCount, 0), fixture.table.get(fixture.peer).sends_in_flight);
    var received: [8]u8 = undefined;
    const rc = linux.read(fixture.remote, &received, received.len);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    try testing.expectEqualStrings("late", received[0..rc]);
}

test "real: a refused submission counts no send on its peer" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    var id: io.OperationId = 0;
    while (id < shared_slots_max) : (id += 1) try fixture.send(id, "q");
    try testing.expectEqual(@as(connections.SendCount, shared_slots_max), fixture.table.get(fixture.peer).sends_in_flight);
    try testing.expectError(error.SlotsKeptForAccepts, fixture.send(id, "r"));
    try testing.expectEqual(@as(connections.SendCount, shared_slots_max), fixture.table.get(fixture.peer).sends_in_flight);

    var completions: [shared_slots_max]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, shared_slots_max, fixture.remote);
    try testing.expectEqual(@as(connections.SendCount, 0), fixture.table.get(fixture.peer).sends_in_flight);
}

test "real: an accept counts no send on any peer" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    var loopback: Loopback = undefined;
    try loopback.open();
    defer loopback.close();
    try fixture.real.submit(.{ .id = 3, .operation = .{ .accept = .{ .listener = loopback.listener } } });
    try testing.expectEqual(@as(connections.SendCount, 0), fixture.table.get(fixture.peer).sends_in_flight);
    try loopback.connect();
    var completions: [1]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, 1, -1);
    const peer = try completions[0].result.accept;
    try testing.expectEqual(@as(connections.SendCount, 0), fixture.table.get(peer).sends_in_flight);
    _ = linux.close(try fixture.table.release(peer));
    try testing.expectEqual(@as(connections.SendCount, 0), fixture.table.get(fixture.peer).sends_in_flight);
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

test "real: one send past the sends' share of the ring returns SlotsKeptForAccepts and changes nothing" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    var id: io.OperationId = 0;
    while (id < shared_slots_max) : (id += 1) try fixture.send(id, "y");
    try testing.expectEqual(shared_slots_max, fixture.real.inFlight());
    try testing.expectEqual(shared_slots_max, fixture.real.sends_in_flight);
    // The slots kept for accepts are still free.
    try testing.expectEqual(slots_count - shared_slots_max, fixture.real.free_count);

    const sqe_tail_before = fixture.real.ring.sq.sqe_tail;
    const slots_before = fixture.real.slots;
    try testing.expectError(error.SlotsKeptForAccepts, fixture.send(id, "z"));
    try testing.expectEqual(shared_slots_max, fixture.real.inFlight());
    try testing.expectEqual(shared_slots_max, fixture.real.sends_in_flight);
    try testing.expectEqual(@as(u64, shared_slots_max), fixture.real.submitted);
    try testing.expectEqual(sqe_tail_before, fixture.real.ring.sq.sqe_tail);
    try testing.expectEqualSlices(Slot, &slots_before, &fixture.real.slots);

    // Every send completes exactly once, with its own id, and the slots come back free.
    var completions: [shared_slots_max]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, shared_slots_max, fixture.remote);
    var seen: [shared_slots_max]bool = @splat(false);
    for (completions) |completion| {
        try testing.expect(completion.id < shared_slots_max);
        try testing.expect(!seen[@intCast(completion.id)]);
        seen[@intCast(completion.id)] = true;
        try testing.expectEqual(@as(u32, 1), try completion.result.send);
    }
    try testing.expectEqual(@as(u32, 0), fixture.real.inFlight());
    try testing.expectEqual(@as(u32, 0), fixture.real.sends_in_flight);
    try fixture.send(id, "z");
    try pollUntil(&fixture.real, completions[0..1], 1, fixture.remote);
    try testing.expectEqual(id, completions[0].id);
}

/// Writes into `socket` without waiting until its send buffer is full, and returns the bytes
/// written. Nothing reads the far end, so a send submitted afterwards waits in the kernel.
/// Fails the test if the buffer never fills within `fill_writes_max` writes.
fn fillSendBuffer(socket: linux.fd_t) !u64 {
    assert(socket >= 0);
    const chunk: [fill_chunk_bytes]u8 = @splat('f');
    var written: u64 = 0;
    var writes: u32 = 0;
    while (writes < fill_writes_max) : (writes += 1) {
        const flags = linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL;
        const rc = linux.sendto(socket, &chunk, chunk.len, flags, null, 0);
        const err = linux.errno(rc);
        if (err == .AGAIN) break;
        try testing.expectEqual(linux.E.SUCCESS, err);
        assert(rc > 0 and rc <= chunk.len);
        written += @as(u32, @intCast(rc));
    }
    try testing.expect(writes < fill_writes_max);
    try testing.expect(written > 0);
    return written;
}

/// Bytes each write of `fillSendBuffer` offers.
const fill_chunk_bytes: u32 = 4096;
/// Writes `fillSendBuffer` allows. Reason: a socketpair's buffer is a few hundred KiB by
/// default (net.core.wmem_default); 4,096 writes of 4 KiB are 16 MiB, far past it.
const fill_writes_max: u32 = 4096;
/// Polls, 1 ms apart, a stuck send must stay pending for. Reason: a send that could go out
/// completes during its submitting system call; 20 ms shows it is waiting, not slow.
const stuck_polls: u32 = 20;

/// Polls `stuck_polls` times, 1 ms apart, and fails the test if anything completes.
fn expectStuck(real: *Real) !void {
    assert(real.inFlight() > 0);
    const in_flight = real.inFlight();
    var completions: [1]io.Completion = undefined;
    var polls: u32 = 0;
    while (polls < stuck_polls) : (polls += 1) {
        try testing.expectEqual(@as(u32, 0), real.poll(&completions));
        const pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
        _ = linux.nanosleep(&pause, null);
    }
    assert(polls == stuck_polls);
    try testing.expectEqual(in_flight, real.inFlight());
}

/// Reads `remote` until end of stream, 1 ms apart when it has nothing yet, and returns the
/// bytes read. Fails the test if the stream doesn't end within the bound.
fn readToEnd(remote: linux.fd_t) !u64 {
    assert(remote >= 0);
    var scratch: [fill_chunk_bytes]u8 = undefined;
    var total: u64 = 0;
    var reads: u32 = 0;
    while (reads < fill_writes_max + poll_attempts_max) : (reads += 1) {
        const rc = linux.recvfrom(remote, &scratch, scratch.len, linux.MSG.DONTWAIT, null, null);
        const err = linux.errno(rc);
        if (err == .AGAIN) {
            const pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
            _ = linux.nanosleep(&pause, null);
            continue;
        }
        try testing.expectEqual(linux.E.SUCCESS, err);
        if (rc == 0) return total;
        assert(rc <= scratch.len);
        total += @as(u32, @intCast(rc));
    }
    assert(reads == fill_writes_max + poll_attempts_max);
    return error.TestStreamNeverEnded;
}

test "real: drop fails a send stuck on a client that stopped reading, and the entry can be released" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    const filled = try fillSendBuffer(fixture.local);
    const stuck: [fill_chunk_bytes]u8 = @splat('s');
    try fixture.send(21, &stuck);
    try expectStuck(&fixture.real);
    // The stuck send holds the entry, and nothing would ever release it.
    try testing.expectError(error.OperationsInFlight, fixture.table.release(fixture.peer));

    try fixture.real.drop(fixture.peer);
    try testing.expectEqual(@as(u64, 1), fixture.real.dropped);
    // A second drop of the same connection is harmless.
    try fixture.real.drop(fixture.peer);
    try testing.expectEqual(@as(u64, 2), fixture.real.dropped);
    try testing.expectEqual(@as(u64, 0), fixture.real.drop_errno_undocumented_count);
    // drop completes nothing itself; the send comes back through poll, having sent nothing.
    try testing.expectEqual(@as(u32, 1), fixture.real.inFlight());
    var completions: [1]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, 1, -1);
    try testing.expectEqual(@as(io.OperationId, 21), completions[0].id);
    try testing.expectError(error.PeerDown, completions[0].result.send);
    // A send after the drop can't wait either.
    try fixture.send(22, "late");
    try pollUntil(&fixture.real, &completions, 1, -1);
    try testing.expectEqual(@as(io.OperationId, 22), completions[0].id);
    try testing.expectError(error.PeerDown, completions[0].result.send);

    // Nothing is counted on the entry any more, so it is released; the fixture takes the
    // socket again for its own tearDown.
    try testing.expectEqual(@as(connections.SendCount, 0), fixture.table.get(fixture.peer).sends_in_flight);
    try testing.expectEqual(fixture.local, try fixture.table.release(fixture.peer));
    fixture.peer = try fixture.table.acquire(fixture.local);
    // The client reads what fitted before the drop, none of the stuck send, then the end.
    try testing.expectEqual(filled, try readToEnd(fixture.remote));
}

test "real: dropping one connection leaves another connection's stuck send pending" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    var fds: [2]linux.fd_t = undefined;
    const flags = linux.SOCK.STREAM | linux.SOCK.CLOEXEC;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.socketpair(linux.AF.UNIX, flags, 0, &fds)));
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);
    const other = try fixture.table.acquire(fds[0]);
    _ = try fillSendBuffer(fixture.local);
    _ = try fillSendBuffer(fds[0]);
    const send_other: io.Send = .{ .peer = other, .bytes = "o" };
    try fixture.send(31, "m");
    try fixture.real.submit(.{ .id = 32, .operation = .{ .send = send_other } });
    try expectStuck(&fixture.real);

    try fixture.real.drop(fixture.peer);
    var completions: [2]io.Completion = undefined;
    try pollUntil(&fixture.real, completions[0..1], 1, -1);
    try testing.expectEqual(@as(io.OperationId, 31), completions[0].id);
    try testing.expectError(error.PeerDown, completions[0].result.send);
    // The other connection's send still waits, still counted on its entry.
    try expectStuck(&fixture.real);
    try testing.expectEqual(@as(connections.SendCount, 1), fixture.table.get(other).sends_in_flight);
    try testing.expectError(error.OperationsInFlight, fixture.table.release(other));

    // Reading its far end lets it finish with its byte; then it is released.
    const filled = try readSome(fds[1]);
    try testing.expect(filled > 0);
    try pollUntil(&fixture.real, completions[0..1], 1, fds[1]);
    try testing.expectEqual(@as(io.OperationId, 32), completions[0].id);
    try testing.expectEqual(@as(u32, 1), try completions[0].result.send);
    try testing.expectEqual(fds[0], try fixture.table.release(other));
}

/// Reads what `remote` holds without waiting, at most `fill_writes_max` reads, and returns
/// the bytes read.
fn readSome(remote: linux.fd_t) !u64 {
    assert(remote >= 0);
    var scratch: [fill_chunk_bytes]u8 = undefined;
    var total: u64 = 0;
    var reads: u32 = 0;
    while (reads < fill_writes_max) : (reads += 1) {
        const rc = linux.recvfrom(remote, &scratch, scratch.len, linux.MSG.DONTWAIT, null, null);
        if (linux.errno(rc) == .AGAIN) break;
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
        assert(rc > 0 and rc <= scratch.len);
        total += @as(u32, @intCast(rc));
    }
    try testing.expect(reads < fill_writes_max);
    return total;
}

/// The first operation id past those of the sends that go in, in the tests that fill the
/// sends' share, for the operations those tests submit beside them; a refused send may
/// reuse it, since a refusal holds no id.
const ids_past_share: io.OperationId = shared_slots_max;

test "real: with every send slot held by a stuck send, an accept still goes in and completes" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    var loopback: Loopback = undefined;
    try loopback.open();
    defer loopback.close();
    _ = try fillSendBuffer(fixture.local);
    var id: io.OperationId = 0;
    while (id < shared_slots_max) : (id += 1) try fixture.send(id, "w");
    try expectStuck(&fixture.real);
    try testing.expectError(error.SlotsKeptForAccepts, fixture.send(id, "w"));
    try testing.expectEqual(shared_slots_max, fixture.real.inFlight());

    // The slot kept for accepts takes the accept, and the slots kept for cancels a cancel
    // each; then the ring is full for everything.
    const accept: io.Operation = .{ .accept = .{ .listener = loopback.listener } };
    try fixture.real.submit(.{ .id = ids_past_share, .operation = accept });
    const cancels_first = ids_past_share + 2;
    const cancelled = try fixture.fillCancels(cancels_first);
    try testing.expectEqual(slots_count, fixture.real.inFlight());
    try testing.expectEqual(@as(u32, 0), fixture.real.free_count);
    try testing.expectEqual(constants.accepts_in_flight_max, fixture.real.share.accepts_in_flight);
    const slots_before = fixture.real.slots;
    const submitted_before = fixture.real.submitted;
    const sqe_tail_before = fixture.real.ring.sq.sqe_tail;
    const entry_before = fixture.table.get(fixture.peer).*;
    const share_before = fixture.real.share;
    // A send meets both limits now; the full ring is the one it reports, as on the simulator,
    // and the refusal changes nothing. A second accept would pass
    // `constants.accepts_in_flight_max`, a caller's bug that stops the process before the ring
    // is checked (the startup-trip harness covers it).
    try testing.expectError(error.QueueFull, fixture.send(ids_past_share + 1, "w"));
    // So does a cancel, its own share full too, and the refusal marks no entry cancelled.
    const cancel: io.Operation = .{ .cancel = .{ .peer = fixture.peer } };
    try testing.expectError(error.QueueFull, fixture.real.submit(.{ .id = ids_past_share + 1, .operation = cancel }));
    try testing.expectEqualSlices(Slot, &slots_before, &fixture.real.slots);
    try testing.expectEqual(submitted_before, fixture.real.submitted);
    try testing.expectEqual(sqe_tail_before, fixture.real.ring.sq.sqe_tail);
    try testing.expectEqual(entry_before, fixture.table.get(fixture.peer).*);
    try testing.expectEqual(share_before, fixture.real.share);
    try testing.expectEqual(@as(u32, 0), fixture.real.free_count);
    try testing.expectEqual(slots_count, fixture.real.inFlight());
    try fixture.releaseCancelled(cancelled, cancels_first);
    try loopback.connect();
    var completions: [slots_count]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, 1, -1);
    try testing.expectEqual(ids_past_share, completions[0].id);
    const accepted = try completions[0].result.accept;

    // Dropping the stuck connection hands every send slot back.
    try fixture.real.drop(fixture.peer);
    try pollUntil(&fixture.real, completions[0..shared_slots_max], shared_slots_max, -1);
    var seen: [shared_slots_max]bool = @splat(false);
    for (completions[0..shared_slots_max]) |completion| {
        try testing.expect(completion.id < shared_slots_max);
        try testing.expect(!seen[@intCast(completion.id)]); // Each send completes once.
        seen[@intCast(completion.id)] = true;
        try testing.expectError(error.PeerDown, completion.result.send);
    }
    try testing.expectEqual(@as(u32, 0), fixture.real.inFlight());
    try testing.expectEqual(@as(u32, 0), fixture.real.sends_in_flight);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.close(try fixture.table.release(accepted))));
    try testing.expectEqual(fixture.local, try fixture.table.release(fixture.peer));
    fixture.peer = try fixture.table.acquire(fixture.local);
}

test "real: an accept counts against no share, so a send takes the share's last place, and the accept's freed slot stays kept" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    var loopback: Loopback = undefined;
    try loopback.open();
    defer loopback.close();
    _ = try fillSendBuffer(fixture.local);
    // The accept goes in first, then one send fewer than the share, all stuck.
    const accept: io.Operation = .{ .accept = .{ .listener = loopback.listener } };
    try fixture.real.submit(.{ .id = ids_past_share, .operation = accept });
    var id: io.OperationId = 0;
    while (id < shared_slots_max - 1) : (id += 1) try fixture.send(id, "w");
    try expectStuck(&fixture.real);
    try testing.expectEqual(1 + cancel_entries, fixture.real.free_count);
    try testing.expectEqual(shared_slots_max - 1, fixture.real.share.others_in_flight);
    // The share's last place is not the accept's: it counts operations, not free slots.
    try fixture.send(id, "w");
    id += 1;
    try expectStuck(&fixture.real);
    try testing.expectEqual(slots_count - cancel_entries, fixture.real.inFlight());
    try testing.expectEqual(shared_slots_max, fixture.real.share.others_in_flight);

    // The accept completes; its slot is free again but kept, so a send is refused and
    // changes nothing, and another accept takes it.
    try loopback.connect();
    var completions: [slots_count]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, 1, -1);
    try testing.expectEqual(ids_past_share, completions[0].id);
    const accepted = try completions[0].result.accept;
    const slots_before = fixture.real.slots;
    const sends_before = fixture.table.get(fixture.peer).sends_in_flight;
    try testing.expectError(error.SlotsKeptForAccepts, fixture.send(id, "w"));
    try testing.expectEqualSlices(Slot, &slots_before, &fixture.real.slots);
    try testing.expectEqual(sends_before, fixture.table.get(fixture.peer).sends_in_flight);
    try testing.expectEqual(shared_slots_max, fixture.real.share.others_in_flight);
    // A second listener, since the first one's client is connected already.
    var other: Loopback = undefined;
    try other.open();
    defer other.close();
    try fixture.real.submit(.{ .id = ids_past_share + 1, .operation = .{ .accept = .{ .listener = other.listener } } });
    try testing.expectEqual(slots_count - cancel_entries, fixture.real.inFlight());

    // Dropping the stuck connection hands every send slot back; the second accept stays.
    try fixture.real.drop(fixture.peer);
    try pollUntil(&fixture.real, completions[0..shared_slots_max], shared_slots_max, -1);
    for (completions[0..shared_slots_max]) |completion| {
        try testing.expect(completion.id < shared_slots_max);
        try testing.expectError(error.PeerDown, completion.result.send);
    }
    try testing.expectEqual(@as(u32, 1), fixture.real.inFlight());
    try testing.expectEqual(@as(u32, 0), fixture.real.share.others_in_flight);
    try other.connect();
    try pollUntil(&fixture.real, completions[0..1], 1, -1);
    try testing.expectEqual(ids_past_share + 1, completions[0].id);
    const second = try completions[0].result.accept;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.close(try fixture.table.release(second))));
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.close(try fixture.table.release(accepted))));
    try testing.expectEqual(fixture.local, try fixture.table.release(fixture.peer));
    fixture.peer = try fixture.table.acquire(fixture.local);
}

/// A shutdown that finds the connection gone already (ENOTCONN), as a stand-in for
/// `ShutdownKernel`: a drop, not a failure.
const GoneShutdown = struct {
    calls: u32 = 0,

    pub fn shutdown(self: *GoneShutdown, socket: io.Socket) linux.E {
        assert(socket >= 0);
        assert(self.calls < std.math.maxInt(u32));
        self.calls += 1;
        return .NOTCONN;
    }
};

test "real: a shutdown that finds the connection gone counts no failed drop, however often" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    var gone: GoneShutdown = .{};
    var attempt: u32 = 0;
    // Past the bound: a drop that works is never refused.
    while (attempt < 2 * constants.io_drop_attempts_max) : (attempt += 1) {
        try fixture.real.dropThrough(GoneShutdown, &gone, fixture.peer);
    }
    try testing.expectEqual(2 * constants.io_drop_attempts_max, gone.calls);
    try testing.expectEqual(@as(connections.DropCount, 0), fixture.table.get(fixture.peer).drops_failed);
    try testing.expectEqual(@as(u64, 0), fixture.real.drop_errno_undocumented_count);
    try testing.expectEqual(@as(u64, 2 * constants.io_drop_attempts_max), fixture.real.dropped);
}

/// A shutdown that always fails with an errno shutdown(2) doesn't document, as a stand-in
/// for `ShutdownKernel`, counting its calls.
const FailingShutdown = struct {
    calls: u32 = 0,

    pub fn shutdown(self: *FailingShutdown, socket: io.Socket) linux.E {
        assert(socket >= 0);
        // dropThrough asks the entry first, so it never calls past the bound.
        assert(self.calls < constants.io_drop_attempts_max);
        self.calls += 1;
        return .IO;
    }
};

test "real: an undocumented shutdown errno counts against the bound, and past it drop calls no shutdown" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    _ = try fillSendBuffer(fixture.local);
    try fixture.send(41, "stuck");
    try expectStuck(&fixture.real);
    const bound = constants.io_drop_attempts_max;
    var failing: FailingShutdown = .{};
    var attempt: u32 = 0;
    while (attempt < bound - 1) : (attempt += 1) {
        try fixture.real.dropThrough(FailingShutdown, &failing, fixture.peer);
        const failed: connections.DropCount = @intCast(attempt + 1);
        try testing.expectEqual(failed, fixture.table.get(fixture.peer).drops_failed);
    }
    // The failure that reaches the bound says so at once.
    try testing.expectError(error.DropsExhausted, fixture.real.dropThrough(FailingShutdown, &failing, fixture.peer));
    try testing.expectEqual(bound, failing.calls);
    try testing.expectEqual(@as(connections.DropCount, bound), fixture.table.get(fixture.peer).drops_failed);
    try testing.expectEqual(@as(u64, bound), fixture.real.drop_errno_undocumented_count);
    try testing.expectEqual(linux.E.IO, fixture.real.drop_errno_undocumented_last);
    try testing.expectEqual(@as(u64, bound), fixture.real.dropped);
    // From then on the real drop is refused too, before any shutdown: the socket is still
    // open both ways, and the send still waits.
    try testing.expectError(error.DropsExhausted, fixture.real.drop(fixture.peer));
    try testing.expectEqual(@as(u64, bound), fixture.real.dropped);
    try expectStuck(&fixture.real);

    // The cancel frees it: the stuck send completes with Canceled, the cancel says it
    // reached one, and the entry, its counts back to zero, is released.
    try testing.expectError(error.OperationsInFlight, fixture.table.release(fixture.peer));
    try fixture.real.submit(.{ .id = 42, .operation = .{ .cancel = .{ .peer = fixture.peer } } });
    var completions: [2]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, 2, -1);
    var canceled_send = false;
    var reached: ?u32 = null;
    for (completions) |completion| switch (completion.id) {
        41 => canceled_send = completion.result.send == error.Canceled,
        42 => reached = completion.result.cancel,
        else => return error.TestUnexpectedResult,
    };
    try testing.expect(canceled_send);
    try testing.expectEqual(@as(?u32, 1), reached);
    try testing.expectEqual(@as(u32, 0), fixture.real.inFlight());
    try testing.expect(!fixture.table.get(fixture.peer).busy());
    try testing.expectEqual(fixture.local, try fixture.table.release(fixture.peer));
    fixture.peer = try fixture.table.acquire(fixture.local);
    try testing.expectEqual(@as(connections.DropCount, 0), fixture.table.get(fixture.peer).drops_failed);
}

test "real: every shutdown errno has an outcome, and only an undocumented one is counted" {
    try testing.expectEqual(DropOutcome.dropped, shutdownErrno(.NOTCONN));
    for ([_]linux.E{ .BADF, .NOTSOCK, .INVAL }) |err| {
        try testing.expectEqual(DropOutcome.bug, shutdownErrno(err));
    }
    // Named in std but not documented for shutdown(2), and a value std has no name for.
    const undocumented = [_]linux.E{ .IO, .NOMEM, .PIPE, @fromBackingInt(4000) };
    for (undocumented) |err| try testing.expectEqual(DropOutcome.undocumented, shutdownErrno(err));

    var real = errnoCountersOnly();
    try testing.expect(!real.shutdownResult(.SUCCESS));
    try testing.expect(!real.shutdownResult(.NOTCONN));
    try testing.expectEqual(@as(u64, 0), real.drop_errno_undocumented_count);
    try testing.expectEqual(linux.E.SUCCESS, real.drop_errno_undocumented_last);
    var count: u64 = 0;
    for (undocumented) |err| {
        try testing.expect(real.shutdownResult(err));
        count += 1;
        try testing.expectEqual(count, real.drop_errno_undocumented_count);
        try testing.expectEqual(err, real.drop_errno_undocumented_last);
    }
    try testing.expectEqual(@as(u64, undocumented.len), count);
}

/// A `Real` with only the fields `sendResult` and `acceptFailed` read and write set, so
/// the errno tests need no ring and run where io_uring is switched off.
fn errnoCountersOnly() Real {
    var real: Real = undefined;
    real.send_errno_undocumented_count = 0;
    real.send_errno_undocumented_last = .SUCCESS;
    real.accept_errno_undocumented_count = 0;
    real.accept_errno_undocumented_last = .SUCCESS;
    real.drop_errno_undocumented_count = 0;
    real.drop_errno_undocumented_last = .SUCCESS;
    real.receive_errno_undocumented_count = 0;
    real.receive_errno_undocumented_last = .SUCCESS;
    real.cancel_errno_undocumented_count = 0;
    real.cancel_errno_undocumented_last = .SUCCESS;
    real.close_errno_undocumented_count = 0;
    real.close_errno_undocumented_last = .SUCCESS;
    return real;
}

test "real: every close errno has an outcome, and only an undocumented one is counted" {
    try testing.expectEqual(CloseOutcome.closed, closeErrno(.INTR));
    try testing.expectEqual(CloseOutcome.closed, closeErrno(.IO));
    try testing.expectEqual(CloseOutcome.bug, closeErrno(.BADF));
    // Named in std but not documented for a socket's close(2), and a value std has no name for.
    const undocumented = [_]linux.E{ .NOSPC, .DQUOT, .PIPE, @fromBackingInt(4000) };
    for (undocumented) |err| try testing.expectEqual(CloseOutcome.undocumented, closeErrno(err));

    var real = errnoCountersOnly();
    real.closeResult(.SUCCESS);
    real.closeResult(.INTR);
    real.closeResult(.IO);
    try testing.expectEqual(@as(u64, 0), real.close_errno_undocumented_count);
    try testing.expectEqual(linux.E.SUCCESS, real.close_errno_undocumented_last);
    var count: u64 = 0;
    for (undocumented) |err| {
        real.closeResult(err);
        count += 1;
        try testing.expectEqual(count, real.close_errno_undocumented_count);
        try testing.expectEqual(err, real.close_errno_undocumented_last);
    }
    try testing.expectEqual(@as(u64, undocumented.len), count);
}

test "real: release refuses while a send is in flight, then frees the entry and closes its socket" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    var fds: [2]linux.fd_t = undefined;
    const flags = linux.SOCK.STREAM | linux.SOCK.CLOEXEC;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.socketpair(linux.AF.UNIX, flags, 0, &fds)));
    defer _ = linux.close(fds[1]);
    const other = try fixture.table.acquire(fds[0]);
    try fixture.real.submit(.{ .id = 1, .operation = .{ .send = .{ .peer = other, .bytes = "x" } } });
    // In flight: refused, and nothing changed, the socket still open.
    try testing.expectError(error.OperationsInFlight, fixture.real.release(other));
    try testing.expect(fixture.table.lookup(other) != null);
    try testing.expectEqual(@as(u64, 0), fixture.real.released);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.fcntl(fds[0], linux.F.GETFD, 0)));
    var completions: [1]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, 1, -1);
    try testing.expectEqual(@as(u32, 1), try completions[0].result.send);
    try fixture.real.release(other);
    // The entry is free, its id stale, and the socket closed: the far end reads end of stream.
    try testing.expectEqual(@as(?*const connections.Entry, null), fixture.table.lookup(other));
    try testing.expectEqual(@as(u64, 1), fixture.real.released);
    try testing.expectEqual(linux.E.BADF, linux.errno(linux.fcntl(fds[0], linux.F.GETFD, 0)));
    var byte: [2]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), linux.read(fds[1], &byte, byte.len));
    try testing.expectEqual(@as(usize, 0), linux.read(fds[1], &byte, byte.len));
    try testing.expectEqual(@as(u64, 0), fixture.real.close_errno_undocumented_count);
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
    .BADF,    .NOTSOCK,     .FAULT,  .INVAL,   .OPNOTSUPP,
    .MSGSIZE, .DESTADDRREQ, .ISCONN, .ALREADY,
};

/// Errnos send(2) doesn't document: some std names, the top of the kernel's range, and a
/// value std has no name for.
const send_errnos_undocumented = [_]linux.E{
    .NOENT,    .EXIST,                .SRCH,                 .NOSPC, .ROFS, .NOSYS,
    .HWPOISON, @fromBackingInt(4095), @fromBackingInt(1000),
};

test "real: every documented send errno has an outcome, counted nowhere" {
    var real = errnoCountersOnly();
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
    var real = errnoCountersOnly();
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
    var real = errnoCountersOnly();
    try testing.expectEqual(@as(u32, 5), try real.sendResult(5, 5));
    try testing.expectEqual(@as(u32, 2), try real.sendResult(2, 5)); // A short send.
    try testing.expectError(error.Backpressure, real.sendResult(0, 5));
    try testing.expectEqual(@as(u64, 0), real.send_errno_undocumented_count);
}
test "real: ECANCELED on a send is Canceled, counted nowhere" {
    var real = errnoCountersOnly();
    try testing.expectEqual(SendOutcome.canceled, sendErrno(.CANCELED));
    try testing.expectError(error.Canceled, real.sendResult(sendFailed(.CANCELED), 5));
    try testing.expectEqual(@as(u64, 0), real.send_errno_undocumented_count);
}

const receive_errnos_peer_down = [_]linux.E{
    .CONNRESET,   .CONNREFUSED, .CONNABORTED, .NOTCONN,  .TIMEDOUT, .PIPE,
    .HOSTUNREACH, .NETUNREACH,  .NETDOWN,     .HOSTDOWN, .NETRESET, .ACCES,
    .PERM,        .IO,          .PROTO,
};
const receive_errnos_backpressure = [_]linux.E{ .AGAIN, .NOBUFS, .NOMEM, .INTR };
const receive_errnos_bug = [_]linux.E{ .BADF, .NOTSOCK, .FAULT, .INVAL, .OPNOTSUPP };
/// Errnos recv(2) doesn't document: some only send(2) has, others std names, the top of the
/// kernel's range, and a value std has no name for.
const receive_errnos_undocumented = [_]linux.E{
    .MSGSIZE, .ISCONN, .SHUTDOWN, .NOENT, .NOSPC, @fromBackingInt(4095), @fromBackingInt(1000),
};

test "real: every documented receive errno has an outcome, counted nowhere" {
    var real = errnoCountersOnly();
    for (receive_errnos_peer_down) |err| {
        try testing.expectEqual(SendOutcome.peer_down, receiveErrno(err));
        try testing.expectError(error.PeerDown, real.receiveResult(sendFailed(err), 5));
    }
    for (receive_errnos_backpressure) |err| {
        try testing.expectEqual(SendOutcome.backpressure, receiveErrno(err));
        try testing.expectError(error.Backpressure, real.receiveResult(sendFailed(err), 5));
    }
    try testing.expectEqual(SendOutcome.canceled, receiveErrno(.CANCELED));
    try testing.expectError(error.Canceled, real.receiveResult(sendFailed(.CANCELED), 5));
    // `receiveResult` stops the process on these, so only the mapping is checked here.
    for (receive_errnos_bug) |err| try testing.expectEqual(SendOutcome.bug, receiveErrno(err));
    try testing.expectEqual(@as(u64, 0), real.receive_errno_undocumented_count);
    try testing.expectEqual(linux.E.SUCCESS, real.receive_errno_undocumented_last);
}

test "real: an undocumented receive errno is PeerDown and is counted; bytes and end of stream are not" {
    var real = errnoCountersOnly();
    for (receive_errnos_undocumented, 1..) |err, count| {
        try testing.expectEqual(SendOutcome.peer_down_undocumented, receiveErrno(err));
        try testing.expectError(error.PeerDown, real.receiveResult(sendFailed(err), 5));
        try testing.expectEqual(@as(u64, count), real.receive_errno_undocumented_count);
        try testing.expectEqual(err, real.receive_errno_undocumented_last);
    }
    const counted = real.receive_errno_undocumented_count;
    try testing.expectEqual(@as(u32, 5), try real.receiveResult(5, 5));
    try testing.expectEqual(@as(u32, 2), try real.receiveResult(2, 5)); // A short read.
    try testing.expectEqual(@as(u32, 0), try real.receiveResult(0, 5)); // End of stream.
    try testing.expectError(error.PeerDown, real.receiveResult(sendFailed(.CONNRESET), 5));
    try testing.expectEqual(counted, real.receive_errno_undocumented_count);
    // Sends keep their own count.
    try testing.expectEqual(@as(u64, 0), real.send_errno_undocumented_count);
}

const cancel_errnos_undocumented = [_]linux.E{ .ALREADY, .AGAIN, .NOMEM, .PERM, @fromBackingInt(4095) };

test "real: a cancel's result is what it reached; ENOENT is none, an undocumented errno counts as none" {
    var real = errnoCountersOnly();
    try testing.expectEqual(@as(u32, 0), real.cancelResult(0));
    try testing.expectEqual(@as(u32, 3), real.cancelResult(3));
    try testing.expectEqual(CancelOutcome.none_found, cancelErrno(.NOENT));
    try testing.expectEqual(@as(u32, 0), real.cancelResult(sendFailed(.NOENT)));
    try testing.expectEqual(@as(u64, 0), real.cancel_errno_undocumented_count);
    // `cancelResult` stops the process on these, so only the mapping is checked here.
    try testing.expectEqual(CancelOutcome.bug, cancelErrno(.BADF));
    try testing.expectEqual(CancelOutcome.bug, cancelErrno(.INVAL));
    for (cancel_errnos_undocumented, 1..) |err, count| {
        try testing.expectEqual(CancelOutcome.undocumented, cancelErrno(err));
        try testing.expectEqual(@as(u32, 0), real.cancelResult(sendFailed(err)));
        try testing.expectEqual(@as(u64, count), real.cancel_errno_undocumented_count);
        try testing.expectEqual(err, real.cancel_errno_undocumented_last);
    }
}

/// Writes all of `bytes` to `socket`, which must take them at once.
fn writeAll(socket: linux.fd_t, bytes: []const u8) !void {
    const rc = linux.sendto(socket, bytes.ptr, bytes.len, linux.MSG.NOSIGNAL, null, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    try testing.expectEqual(bytes.len, rc);
}

test "real: a receive reads what the far end wrote, short of its buffer, then end of stream" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    try writeAll(fixture.remote, "GET / HTTP/1.1\r\n");
    var buffer: [64]u8 = @splat(0);
    const receive: io.Operation = .{ .receive = .{ .peer = fixture.peer, .buffer = &buffer } };
    try fixture.real.submit(.{ .id = 51, .operation = receive });
    try testing.expect(fixture.table.get(fixture.peer).receiving);
    // The receive holds the entry until it completes.
    try testing.expectError(error.OperationsInFlight, fixture.table.release(fixture.peer));
    var completions: [1]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, 1, -1);
    try testing.expectEqual(@as(io.OperationId, 51), completions[0].id);
    const received = try completions[0].result.receive;
    try testing.expectEqualStrings("GET / HTTP/1.1\r\n", buffer[0..received]);
    // Nothing past what was read was written.
    try testing.expect(std.mem.allEqual(u8, buffer[received..], 0));
    try testing.expect(!fixture.table.get(fixture.peer).receiving);

    // The far end closes: the next receive reads end of stream.
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.close(fixture.remote)));
    fixture.remote = -1;
    try fixture.real.submit(.{ .id = 52, .operation = receive });
    try pollUntil(&fixture.real, &completions, 1, -1);
    try testing.expectEqual(@as(u32, 0), try completions[0].result.receive);
    try testing.expectEqual(@as(u64, 0), fixture.real.receive_errno_undocumented_count);
}

test "real: a drop ends a pending receive as end of stream, and its entry can be released" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    var buffer: [16]u8 = undefined;
    const receive: io.Operation = .{ .receive = .{ .peer = fixture.peer, .buffer = &buffer } };
    try fixture.real.submit(.{ .id = 61, .operation = receive });
    // Nothing was written, so the receive waits.
    var completions: [1]io.Completion = undefined;
    try testing.expectEqual(@as(u32, 0), fixture.real.poll(&completions));
    try fixture.real.drop(fixture.peer);
    try pollUntil(&fixture.real, &completions, 1, -1);
    try testing.expectEqual(@as(io.OperationId, 61), completions[0].id);
    // The contract allows end of stream or PeerDown; Linux gives end of stream.
    const ended = completions[0].result.receive catch |err| switch (err) {
        error.PeerDown => 0,
        error.Backpressure, error.Canceled => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(@as(u32, 0), ended);
    try testing.expectEqual(fixture.local, try fixture.table.release(fixture.peer));
    fixture.peer = try fixture.table.acquire(fixture.local);
}

test "real: a cancel ends a pending receive with Canceled, reaching one, and a second reaches none" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    var buffer: [16]u8 = undefined;
    const receive: io.Operation = .{ .receive = .{ .peer = fixture.peer, .buffer = &buffer } };
    try fixture.real.submit(.{ .id = 71, .operation = receive });
    try fixture.real.submit(.{ .id = 72, .operation = .{ .cancel = .{ .peer = fixture.peer } } });
    try testing.expect(fixture.table.get(fixture.peer).canceled);
    try testing.expectEqual(@as(u32, 1), fixture.real.share.cancels_in_flight);
    var completions: [2]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, 2, -1);
    var canceled_receive = false;
    var reached: ?u32 = null;
    for (completions) |completion| switch (completion.id) {
        71 => canceled_receive = completion.result.receive == error.Canceled,
        72 => reached = completion.result.cancel,
        else => return error.TestUnexpectedResult,
    };
    try testing.expect(canceled_receive);
    try testing.expectEqual(@as(?u32, 1), reached);
    try testing.expectEqual(@as(u32, 0), fixture.real.share.cancels_in_flight);
    // A second cancel, with nothing left in flight, reaches nothing.
    try fixture.real.submit(.{ .id = 73, .operation = .{ .cancel = .{ .peer = fixture.peer } } });
    try pollUntil(&fixture.real, completions[0..1], 1, -1);
    try testing.expectEqual(@as(u32, 0), completions[0].result.cancel);
    try testing.expectEqual(fixture.local, try fixture.table.release(fixture.peer));
    fixture.peer = try fixture.table.acquire(fixture.local);
    try testing.expect(!fixture.table.get(fixture.peer).canceled);
}

test "real: past the cancels' share a cancel is refused with CancelsFull and changes nothing" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    const first: io.OperationId = 100;
    const cancelled = try fixture.fillCancels(first);
    const slots_before = fixture.real.slots;
    const submitted_before = fixture.real.submitted;
    const share_before = fixture.real.share;
    const entry_before = fixture.table.get(fixture.peer).*;
    const cancel: io.Submission = .{ .id = first + cancel_entries, .operation = .{ .cancel = .{ .peer = fixture.peer } } };
    try testing.expectError(error.CancelsFull, fixture.real.submit(cancel));
    try testing.expectEqualSlices(Slot, &slots_before, &fixture.real.slots);
    try testing.expectEqual(submitted_before, fixture.real.submitted);
    try testing.expectEqual(share_before, fixture.real.share);
    // The refused cancel marks nothing: the entry still takes a send.
    try testing.expectEqual(entry_before, fixture.table.get(fixture.peer).*);
    try fixture.releaseCancelled(cancelled, first);
    try fixture.send(first + cancel_entries + 1, "x");
    var completions: [1]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, 1, fixture.remote);
    try testing.expectEqual(@as(u32, 1), try completions[0].result.send);
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
    // No send is submitted on the new connection, so nothing holds its release back.
    assert(!fixture.table.get(peer).busy());
    defer _ = linux.close(fixture.table.release(peer) catch |err| switch (err) {
        error.OperationsInFlight => unreachable,
    });
    try testing.expectEqual(@as(u32, 2), fixture.table.count());
    try testing.expectEqual(connections.State.idle, fixture.table.get(peer).state);
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

test "real: an accept on the local listener takes the client connecting through its path" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    // A fresh 0700 directory under a random name, so runs sharing /tmp never meet.
    var random: [8]u8 = undefined;
    try testing.expectEqual(random.len, linux.getrandom(&random, random.len, 0));
    var dir_bytes: [64]u8 = undefined;
    const dir = try std.fmt.bufPrintSentinel(&dir_bytes, "/tmp/cc-real-{x}", .{std.mem.readInt(u64, &random, .little)}, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mkdir(dir, 0o700)));
    defer _ = linux.rmdir(dir);
    var path_bytes: [constants.config_socket_path_max + 1]u8 = undefined;
    const socket_path = try std.fmt.bufPrintSentinel(&path_bytes, "{s}/app.sock", .{dir}, 0);
    var lock_bytes: [constants.config_socket_path_max + 8]u8 = undefined;
    const lock_path = try std.fmt.bufPrintSentinel(&lock_bytes, "{s}.lock", .{socket_path}, 0);
    // Runs after close below: the lock file is all close leaves.
    defer _ = linux.unlink(lock_path);
    var local = try listener.open(socket_path);
    defer local.close();

    try fixture.real.submit(.{ .id = 11, .operation = .{ .accept = .{ .listener = local.socket } } });
    const client = try socketOpen(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC);
    defer _ = linux.close(client);
    const address_len: linux.socklen_t = @intCast(@offsetOf(linux.sockaddr.un, "path") + socket_path.len + 1);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.connect(client, &local.address, address_len)));
    var completions: [2]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, 1, -1);
    try testing.expectEqual(@as(io.OperationId, 11), completions[0].id);
    const peer = try completions[0].result.accept;
    const socket = fixture.table.get(peer).socket;
    assert(!fixture.table.get(peer).busy());
    defer _ = linux.close(fixture.table.release(peer) catch |err| switch (err) {
        error.OperationsInFlight => unreachable,
    });
    try testing.expectEqual(@as(u32, 2), fixture.table.count());

    // The entry's socket is the accepted end of the client's connection.
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.write(client, "hi", 2)));
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
    var fillers: [fixture_table_size - 1]io.PeerId = undefined;
    for (&fillers, 0..) |*filler, index| filler.* = try fixture.table.acquire(@intCast(1_000_000 + index));
    defer for (fillers) |filler| {
        // The fillers never send, so nothing holds their release back.
        assert(!fixture.table.get(filler).busy());
        _ = fixture.table.release(filler) catch |err| switch (err) {
            error.OperationsInFlight => unreachable,
        };
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

const accept_errnos_peer_down = [_]linux.E{
    .CONNABORTED, .PERM,           .PROTO,          .NOPROTOOPT, .NONET,
    .HOSTDOWN,    .HOSTUNREACH,    .NETDOWN,        .NETUNREACH, .TIMEDOUT,
    .NOSR,        .SOCKTNOSUPPORT, .PROTONOSUPPORT,
};
const accept_errnos_backpressure = [_]linux.E{ .MFILE, .NFILE, .NOBUFS, .NOMEM, .INTR, .AGAIN };
const accept_errnos_bug = [_]linux.E{ .BADF, .NOTSOCK, .INVAL, .FAULT, .OPNOTSUPP, .CANCELED };

/// Errnos accept(2) doesn't document: some std names, the top of the kernel's range, and a
/// value std has no name for.
const accept_errnos_undocumented = [_]linux.E{
    .NOENT,    .EXIST,                .SRCH,                 .NOSPC, .ROFS, .PIPE,
    .HWPOISON, @fromBackingInt(4095), @fromBackingInt(1000),
};

test "real: every documented accept errno has an outcome, counted nowhere" {
    var real = errnoCountersOnly();
    for (accept_errnos_peer_down) |err| {
        try testing.expectEqual(AcceptOutcome.peer_down, acceptErrno(err));
        try testing.expectEqual(error.PeerDown, real.acceptFailed(err));
    }
    for (accept_errnos_backpressure) |err| {
        try testing.expectEqual(AcceptOutcome.backpressure, acceptErrno(err));
        try testing.expectEqual(error.Backpressure, real.acceptFailed(err));
    }
    try testing.expectEqual(@as(u64, 0), real.accept_errno_undocumented_count);
    try testing.expectEqual(linux.E.SUCCESS, real.accept_errno_undocumented_last);
}

test "real: an accept errno only a bug causes is a bug, not a dropped connection" {
    // `acceptFailed` stops the process on these, so only the mapping is checked here.
    for (accept_errnos_bug) |err| {
        try testing.expectEqual(AcceptOutcome.bug, acceptErrno(err));
    }
}

test "real: an undocumented accept errno is Backpressure and is counted" {
    var real = errnoCountersOnly();
    for (accept_errnos_undocumented, 1..) |err, count| {
        try testing.expectEqual(AcceptOutcome.backpressure_undocumented, acceptErrno(err));
        try testing.expectEqual(error.Backpressure, real.acceptFailed(err));
        try testing.expectEqual(@as(u64, count), real.accept_errno_undocumented_count);
        try testing.expectEqual(err, real.accept_errno_undocumented_last);
    }
    // Documented errnos leave the count and the latest errno alone, and sends' counts stay
    // separate.
    const counted = real.accept_errno_undocumented_count;
    try testing.expectEqual(error.PeerDown, real.acceptFailed(.CONNABORTED));
    try testing.expectEqual(error.Backpressure, real.acceptFailed(.MFILE));
    try testing.expectEqual(counted, real.accept_errno_undocumented_count);
    const latest = accept_errnos_undocumented[accept_errnos_undocumented.len - 1];
    try testing.expectEqual(latest, real.accept_errno_undocumented_last);
    try testing.expectEqual(@as(u64, 0), real.send_errno_undocumented_count);
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

/// The completion result an accept gets when the system is short of descriptors.
const accept_short: i32 = -@as(i32, @backingInt(linux.E.MFILE));

/// Sleeps 1 ms at a time until the real type's clock reaches `instant`, at most
/// `poll_attempts_max` times, or fails the test.
fn sleepUntil(real: *Real, instant: io.Instant) !void {
    assert(instant > real.epoch);
    var attempts: u32 = 0;
    while (real.now() < instant and attempts < poll_attempts_max) : (attempts += 1) {
        const pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
        _ = linux.nanosleep(&pause, null);
    }
    assert(attempts <= poll_attempts_max);
    try testing.expect(real.now() >= instant);
}

test "real: after Backpressure an accept is refused until the wait is over, sends are not" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    var loopback: Loopback = undefined;
    try loopback.open();
    defer loopback.close();

    // A connection that failed starts no wait.
    const aborted = -@as(i32, @backingInt(linux.E.CONNABORTED));
    try testing.expectError(error.PeerDown, fixture.real.acceptResult(aborted));
    try testing.expectEqual(@as(?io.Instant, null), fixture.real.accept_wait.resume_at);
    const before_short = fixture.real.now();
    try testing.expectError(error.Backpressure, fixture.real.acceptResult(accept_short));
    const resume_at = fixture.real.accept_wait.resume_at orelse return error.TestExpectedWait;
    // Started from a reading taken at the completion, no earlier than the one before it.
    try testing.expect(resume_at >= before_short + constants.io_accept_backpressure_wait_ns);
    try testing.expect(resume_at <= fixture.real.now() + constants.io_accept_backpressure_wait_ns);

    // Refused, taking no slot and no submission entry; only the refusal count changes.
    const accept: io.Submission = .{ .id = 21, .operation = .{ .accept = .{ .listener = loopback.listener } } };
    const submitted_before = fixture.real.submitted;
    const sqe_tail_before = fixture.real.ring.sq.sqe_tail;
    const slots_before = fixture.real.slots;
    try testing.expectError(error.AcceptTooSoon, fixture.real.submit(accept));
    try testing.expectEqual(submitted_before, fixture.real.submitted);
    try testing.expectEqual(sqe_tail_before, fixture.real.ring.sq.sqe_tail);
    try testing.expectEqualSlices(Slot, &slots_before, &fixture.real.slots);
    try testing.expectEqual(@as(u64, 1), fixture.real.accept_wait.refused);
    try testing.expectEqual(@as(?io.Instant, resume_at), fixture.real.accept_wait.resume_at);

    // A send isn't held back by the wait.
    try fixture.send(22, "hi");
    var completions: [2]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, 1, fixture.remote);
    try testing.expectEqual(@as(u32, 2), try completions[0].result.send);

    // Once the clock reaches the end of the wait, the accept goes in and clears it.
    try sleepUntil(&fixture.real, resume_at);
    try fixture.real.submit(accept);
    try testing.expectEqual(@as(?io.Instant, null), fixture.real.accept_wait.resume_at);
    try testing.expectEqual(@as(u64, 1), fixture.real.accept_wait.refused);
    try loopback.connect();
    try pollUntil(&fixture.real, &completions, 1, -1);
    try testing.expectEqual(@as(io.OperationId, 21), completions[0].id);
    const peer = try completions[0].result.accept;
    assert(!fixture.table.get(peer).busy());
    _ = linux.close(fixture.table.release(peer) catch |err| switch (err) {
        error.OperationsInFlight => unreachable,
    });
}

test "real: a second Backpressure starts the wait again" {
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    var loopback: Loopback = undefined;
    try loopback.open();
    defer loopback.close();
    try testing.expectError(error.Backpressure, fixture.real.acceptResult(accept_short));
    const first = fixture.real.accept_wait.resume_at.?;
    // A tenth of the wait passes, then another accept finds the system short.
    try sleepUntil(&fixture.real, first - constants.io_accept_backpressure_wait_ns / 10 * 9);
    try testing.expectError(error.Backpressure, fixture.real.acceptResult(accept_short));
    const second = fixture.real.accept_wait.resume_at.?;
    try testing.expect(second >= first + constants.io_accept_backpressure_wait_ns / 10);
    // Past the first wait's end, the second still runs: about 90 ms of it is left, far
    // longer than the 1 ms sleeps overshoot.
    try sleepUntil(&fixture.real, first);
    const accept: io.Submission = .{ .id = 23, .operation = .{ .accept = .{ .listener = loopback.listener } } };
    try testing.expectError(error.AcceptTooSoon, fixture.real.submit(accept));
    try testing.expectEqual(@as(?io.Instant, second), fixture.real.accept_wait.resume_at);
}

test "real: with the share full, the slot kept for accepts still waits out a Backpressure" {
    // A full ring and a running wait can't both meet an accept: a full ring already holds
    // `constants.accepts_in_flight_max` accepts, so another would be a caller's bug (the
    // startup-trip harness covers it). The nearest case is every send slot in use and the
    // kept slot free: the accept is refused by the wait, not by the share.
    comptime assert(slots_count - shared_slots_max == constants.accepts_in_flight_max + constants.io_cancels_in_flight_max);
    var fixture: Fixture = undefined;
    try fixture.setUp();
    defer fixture.tearDown();
    var loopback: Loopback = undefined;
    try loopback.open();
    defer loopback.close();

    var id: io.OperationId = 1;
    while (id <= shared_slots_max) : (id += 1) try fixture.send(id, "x");
    try testing.expectEqual(slots_count - shared_slots_max, fixture.real.free_count);
    try testing.expectError(error.Backpressure, fixture.real.acceptResult(accept_short));
    const resume_at = fixture.real.accept_wait.resume_at orelse return error.TestExpectedWait;
    const late: io.Submission = .{ .id = id, .operation = .{ .accept = .{ .listener = loopback.listener } } };
    try testing.expectError(error.AcceptTooSoon, fixture.real.submit(late));
    try testing.expectEqual(@as(u64, 1), fixture.real.accept_wait.refused);
    try testing.expectEqual(@as(u32, 0), fixture.real.share.accepts_in_flight);

    // Once the wait is over, the accept takes the kept slot, leaving only the cancels'
    // free; it takes the connection once the sends are back.
    try sleepUntil(&fixture.real, resume_at);
    try fixture.real.submit(late);
    try testing.expectEqual(cancel_entries, fixture.real.free_count);
    try testing.expectEqual(constants.accepts_in_flight_max, fixture.real.share.accepts_in_flight);
    var completions: [slots_count]io.Completion = undefined;
    try pollUntil(&fixture.real, &completions, shared_slots_max, fixture.remote);
    for (completions[0..shared_slots_max]) |completion| try testing.expectEqual(@as(u32, 1), try completion.result.send);
    try loopback.connect();
    try pollUntil(&fixture.real, &completions, 1, -1);
    try testing.expectEqual(late.id, completions[0].id);
    const peer = try completions[0].result.accept;
    // No send is submitted on the new connection, so nothing holds its release back.
    assert(!fixture.table.get(peer).busy());
    _ = linux.close(fixture.table.release(peer) catch |err| switch (err) {
        error.OperationsInFlight => unreachable,
    });
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
/// Sends the soak keeps in flight at most. Reason: a fixed count, not the sends' share, so
/// the number of submissions doesn't grow with the ring: 256 sends mix peers, closes and
/// partial polls as well as thousands would. Each submission still scans the whole slot
/// table (the type's distinct-id check and the soak's own search), so that part of its cost
/// does grow with the ring. The tests that fill the whole share do so once each, with no
/// soak around them.
const soak_in_flight_max: u32 = 256;
/// Every `soak_fill_every`-th round tops the ring up to `soak_in_flight_max`.
const soak_fill_every: u32 = 8;
/// A round closes a far end with odds of one in this many. Reason: about four closes in a
/// run of 32 rounds, so most seeds close all three closable far ends partway through.
const soak_close_odds: u32 = 8;
/// Largest send. Reason: small enough that a peer's socket buffer rarely fills; when it
/// does, the send waits in the kernel until `pollDown` drains that far end.
const soak_send_bytes_max: u32 = 512;
/// Operation ids a run can use: each round submits at most `soak_in_flight_max`.
const soak_operations_max: u32 = soak_rounds_max * soak_in_flight_max;
/// The buffer one read of a far end fills.
const soak_scratch_bytes: u32 = 4096;
/// Reads per drain of one far end. Reason: the most sends in flight, all of the largest
/// size and to one peer, are 128 KiB, 32 reads; the rest is margin.
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
    // One drain can read every byte in flight to one peer, so the final drain empties it.
    assert(@as(u64, soak_in_flight_max) * soak_send_bytes_max <= @as(u64, soak_reads_max - 1) * soak_scratch_bytes);
    // The soak never reaches the sends' share, so no submission of it is refused.
    assert(soak_in_flight_max < shared_slots_max);
}

/// What the soak knows about one operation it submitted.
const SoakOperation = struct {
    peer: u8,
    /// The id the send was submitted under; it must still be live at the completion.
    id: io.PeerId,
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
    /// Sends submitted and not yet recorded, per peer: what each entry's count must say.
    peer_in_flight: [soak_peers_count]u32,
    /// Releases the table refused because the peer had sends in flight.
    busy_refusals: u32,
    /// Idle peers released and taken again on the same socket, under a new id.
    reuses: u32,
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
        self.peer_in_flight = @splat(0);
        self.busy_refusals = 0;
        self.reuses = 0;
        var position: u32 = 0;
        while (position < soak_send_bytes_max) : (position += 1) self.bytes[position] = @truncate(position);
        assert(self.real.inFlight() == 0);
        assert(self.table.count() == soak_peers_count);
    }

    /// Closes the ring first, so nothing in flight still names a socket. After a failed
    /// check, operations may still be in flight: they are polled back and dropped. If some
    /// never come back, the ring, the table and the sockets are left open and false is
    /// returned, so the caller leaks this rather than free bytes the kernel may still read;
    /// the check's failure shows instead of `deinit`'s assertion.
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
        // Sends still in flight hold their peers' entries and sockets: the whole soak is
        // left as it is, and the failed check shows instead.
        if (!settled) return false;
        self.real.deinit();
        for (self.peers, self.locals) |peer, local| {
            assert(!self.table.get(peer).busy());
            const released = self.table.release(peer) catch |err| switch (err) {
                error.OperationsInFlight => unreachable, // Nothing is in flight.
            };
            assert(released == local);
        }
        self.startup.beginShutdown();
        self.table.deinit(self.gpa);
        assert(self.startup.bytes_live == 0);
        for (self.locals, self.remotes) |local, remote| {
            _ = linux.close(local);
            if (remote >= 0) _ = linux.close(remote);
        }
        return true;
    }

    /// Submits one send of random length to a random peer, and checks the slot it took.
    fn submitOne(self: *Soak) !void {
        assert(self.real.inFlight() < soak_in_flight_max);
        assert(self.submitted < soak_operations_max);
        const random = self.schedule.random();
        const peer = random.uintLessThan(u8, soak_peers_count);
        const length = random.intRangeAtMost(u32, 1, soak_send_bytes_max);
        const id = self.submitted;
        const after_close = self.remotes[peer] < 0;
        self.operations[id] = .{
            .peer = peer,
            .id = self.peers[peer],
            .length = length,
            .after_close = after_close,
            .completions = 0,
        };
        try self.real.submit(.{
            .id = id,
            .operation = .{ .send = .{ .peer = self.peers[peer], .bytes = self.bytes[0..length] } },
        });
        self.submitted += 1;
        self.peer_in_flight[peer] += 1;
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
        // The peer is still live and still holds the socket the send was submitted on.
        try testing.expect(self.peer_in_flight[operation.peer] > 0);
        self.peer_in_flight[operation.peer] -= 1;
        // Idle peers are released and taken again each round, so a send that outlived its
        // peer's release would find its id stale here.
        const entry = self.table.lookup(operation.id) orelse return error.TestPeerReleased;
        try testing.expectEqual(self.peers[operation.peer], operation.id);
        try testing.expectEqual(self.locals[operation.peer], entry.socket);
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
            // Nothing in the soak cancels.
            error.Canceled => return error.TestUnexpectedCanceled,
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
            // A poll uncounts every send it hands back, so after the batch each entry's
            // count is the sends still in flight on it.
            for (self.peers, self.peer_in_flight) |peer, in_flight| {
                try testing.expectEqual(in_flight, self.table.get(peer).sends_in_flight);
            }
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

    /// Every peer with sends in flight is refused release, and its entry stays as it was.
    /// Every idle peer is released and taken again on the same socket, under a new id.
    fn expectBusyRefusals(self: *Soak) !void {
        assert(self.table.count() == soak_peers_count);
        var in_flight_total: u32 = 0;
        for (&self.peers, self.peer_in_flight, self.locals) |*peer, in_flight, local| {
            const entry_before = self.table.get(peer.*).*;
            try testing.expectEqual(in_flight, entry_before.sends_in_flight);
            in_flight_total += in_flight;
            if (in_flight > 0) {
                try testing.expectError(error.OperationsInFlight, self.table.release(peer.*));
                try testing.expectEqual(entry_before, self.table.get(peer.*).*);
                self.busy_refusals += 1;
                continue;
            }
            try testing.expectEqual(local, try self.table.release(peer.*));
            const again = try self.table.acquire(local);
            try testing.expect(again != peer.*);
            peer.* = again;
            self.reuses += 1;
        }
        try testing.expectEqual(soak_peers_count, self.table.count());
        // The model's per-peer counts add up to what the ring has in flight.
        assert(in_flight_total == self.real.inFlight());
    }

    /// One round: top the ring up to a target, maybe close a far end, poll part of it back.
    fn round(self: *Soak, number: u32) !void {
        assert(number < soak_rounds_max);
        assert(self.real.inFlight() < soak_in_flight_max);
        const random = self.schedule.random();
        // At least one send a round, so there is always something to poll back.
        const target = if (number % soak_fill_every == 0)
            soak_in_flight_max
        else
            random.intRangeAtMost(u32, self.real.inFlight() + 1, soak_in_flight_max);
        var submissions: u32 = 0;
        while (self.real.inFlight() < target) : (submissions += 1) {
            assert(submissions < soak_in_flight_max);
            try self.submitOne();
        }
        // Random closes, plus one before the second full round if none came yet, so every
        // seed sends to a closed far end.
        const forced = number == soak_fill_every - 1 and self.closes == 0;
        if (forced or random.uintLessThan(u32, soak_close_odds) == 0) try self.closeOne();
        try self.expectBusyRefusals();
        try self.pollDown(random.uintLessThan(u32, self.real.inFlight()));
        // Some peers may be idle now: they are released and taken again while the others'
        // sends are still in flight.
        try self.expectBusyRefusals();
    }

    /// Runs every round, then lets everything finish and checks the totals.
    fn run(self: *Soak) !void {
        assert(self.submitted == 0);
        assert(self.real.inFlight() == 0);
        errdefer std.debug.print("real: send soak failed with seed 0x{x}\n", .{self.seed});
        var number: u32 = 0;
        while (number < soak_rounds_max) : (number += 1) try self.round(number);
        try self.pollDown(0);
        // Nothing is in flight, so every peer is released and taken again.
        try self.expectBusyRefusals();
        try self.checkTotals();
    }

    /// After the run: every operation completed once, `soak_in_flight_max` slots were each
    /// reused and the rest never taken, and each far end never closed read exactly the
    /// bytes its sends reported.
    fn checkTotals(self: *Soak) !void {
        assert(self.real.inFlight() == 0);
        assert(self.submitted <= soak_operations_max);
        try testing.expectEqual(self.submitted, self.completed);
        try testing.expectEqual(@as(u64, self.submitted), self.real.submitted);
        try testing.expectEqual(self.real.submitted, self.real.completed);
        for (self.operations[0..self.submitted]) |operation| {
            try testing.expectEqual(@as(u8, 1), operation.completions);
        }
        // Sends hold at most soak_in_flight_max slots at once, and the free stack hands back
        // the slot freed last, so the slots below that depth are never reached and the same
        // soak_in_flight_max slots carry every send. A change to the free list's order would
        // change this count.
        var reused: u32 = 0;
        var unused: u32 = 0;
        for (self.slot_uses) |uses| {
            if (uses >= 2) reused += 1;
            if (uses == 0) unused += 1;
        }
        try testing.expectEqual(soak_in_flight_max, reused);
        try testing.expectEqual(slots_count - soak_in_flight_max, unused);
        for (self.peers, self.peer_in_flight) |peer, in_flight| {
            try testing.expectEqual(@as(u32, 0), in_flight);
            try testing.expectEqual(@as(connections.SendCount, 0), self.table.get(peer).sends_in_flight);
        }
        try testing.expect(self.busy_refusals > 0);
        try testing.expect(self.reuses > 0);
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

/// Entries in the accept soak's table that accepts take. Reason: small, so a batch of
/// connections often finds it full and each entry is taken and released many times in one
/// run. The table has one more, `accept_soak_filler_index`, for the connection whose stuck
/// sends hold slots through each period.
const accept_soak_table_size: u32 = 4;
/// The entry the filler takes: the first acquire hands out entry 0, before any accept.
const accept_soak_filler_index: connections.Index = 0;
/// Rounds per seed. Each round connects a batch of clients, accepts them one at a time and
/// releases some of the connections held.
const accept_soak_rounds_max: u32 = 24;
/// Every `accept_soak_period`-th round starts a period: one accept goes in, then
/// `accept_soak_filler_sends` stuck sends to the filler. The period's last round reads the
/// filler's far end until every send is back, takes one last client and releases every
/// connection held, so the next period starts from nothing.
const accept_soak_period: u32 = 8;
/// Stuck sends to the filler in each period. Reason: a fixed count, not the rest of the
/// ring, so the number of submissions doesn't grow with the ring; with the accept they take
/// the same 256 slots in every period, and the accepts complete and go in again while those
/// sends never finish. The ring is never full here: the tests that fill the whole sends'
/// share and the whole ring do so once each, with no soak around them.
const accept_soak_filler_sends: u32 = 255;
/// Clients connected before their accepts are polled back, one accept at a time. Reason:
/// four times the table, so a batch often finds the table full partway; far below the
/// listener's backlog, so a connect never waits.
const accept_soak_batch_max: u32 = 16;
/// Operation ids a run can use: a period's fill takes the filler's sends and an accept, and
/// each round's batch at most `accept_soak_batch_max` accepts more.
const accept_soak_ids_max: u32 = accept_soak_rounds_max * (accept_soak_filler_sends + 1 + accept_soak_batch_max);
/// Reads one check of a client or an accepted socket may take, 1 ms apart, before the soak
/// gives up on the kernel. Reason: a close or a write on a Unix socket reaches the other end
/// within the system call; a second is ample even on a loaded CI machine.
const accept_soak_reads_max: u32 = poll_attempts_max;
/// Directory names tried before setup gives up: one already there (left by a run that
/// stopped mid-way, or another run in a separate pid namespace) is skipped, never touched.
const accept_soak_dir_attempts_max: u32 = 16;
/// The directory's name: the prefix, then the pid (a u32 in decimal), the seed (a u64 in
/// hex) and the attempt (below 100), each after a dash.
const accept_soak_dir_prefix = "/tmp/cc-accept-soak";
const accept_soak_dir_bytes: u32 = accept_soak_dir_prefix.len + 1 + 10 + 1 + 16 + 1 + 2 + 1;
const accept_soak_socket_name = "/app.sock";
/// Seeds the accept soak replays. A failed check prints its seed. Every choice of how many
/// accepts to submit, how many clients to connect and which connections to release comes
/// from one stream seeded here and depends only on counts the kernel can't change. Which
/// accept (and so which ring slot) the kernel gives each client can differ between replays;
/// the counts and the table's ids don't. Poll buffer sizes come from a second stream, whose
/// draws depend on timing, so they can't shift the schedule.
const accept_soak_seeds = [_]u64{ 0x5eed, 1, 2, 3, 4, 5, 0xdead_beef, 0x0123_4567_89ab_cdef };

comptime {
    assert(accept_soak_table_size >= 2);
    assert(accept_soak_table_size <= constants.http_connections_max);
    // A batch can overfill the table, so TableFull comes up in every period's first batch.
    assert(accept_soak_batch_max > accept_soak_table_size);
    // A batch's connections all fit the backlog, so no connect waits for an accept.
    assert(accept_soak_batch_max <= constants.listener_backlog);
    // One accept in flight at a time, as the server keeps, and the filler's sends stay
    // inside the sends' share, so no fill is refused.
    assert(constants.accepts_in_flight_max == 1);
    assert(accept_soak_filler_sends > 0 and accept_soak_filler_sends < shared_slots_max);
    // At least two whole periods, so every slot a fill holds and every entry is taken twice
    // from empty.
    assert(accept_soak_rounds_max % accept_soak_period == 0);
    assert(accept_soak_rounds_max / accept_soak_period >= 2);
    assert(accept_soak_period >= 3); // A fill round, a round between, and a drain round.
    assert(accept_soak_dir_attempts_max < 100); // The attempt prints in two digits.
    // The socket path fits what the listener takes.
    assert(accept_soak_dir_bytes - 1 + accept_soak_socket_name.len <= constants.config_socket_path_max);
    assert(slots_count <= std.math.maxInt(u16)); // A slot index fits `id_slots`.
    // The filler's entry is part of the table, beside those accepts take.
    assert(accept_soak_filler_index < accept_soak_table_size + 1);
}

/// Entries in the accept soak's table: those accepts take, and the filler's.
const accept_soak_capacity: u32 = accept_soak_table_size + 1;

/// A connection the soak's table holds: its id, the client's end and the accepted end.
const AcceptSoakHeld = struct {
    peer: io.PeerId,
    client: linux.fd_t,
    accepted: linux.fd_t,
};

/// A seeded run of many accepts over the local listener into a small table, one accept in
/// flight at a time, with every connection held for a while and then released. A filler
/// connection, a socketpair whose send buffer is full, takes `accept_soak_filler_sends`
/// stuck sends in each period, so the accepts go in and come back past slots held by sends
/// that never finish. Set up in place, because `Real` keeps a pointer to the table.
const AcceptSoak = struct {
    seed: u64,
    schedule: std.Random.DefaultPrng,
    poll_sizes: std.Random.DefaultPrng,
    startup: StartupAllocator,
    gpa: std.mem.Allocator,
    table: connections.Table,
    real: Real,
    /// A 0700 directory named for the process and the seed, holding the socket and its lock,
    /// so runs sharing /tmp never meet and no unseeded random source names it.
    dir_bytes: [accept_soak_dir_bytes]u8,
    dir_len: u8,
    path_bytes: [constants.config_socket_path_max + 1]u8,
    path_len: u8,
    lock_bytes: [constants.config_socket_path_max + 8]u8,
    lock_len: u8,
    local: listener.Listener,
    /// The filler's end in the table, its id, and its far end, which nothing reads until a
    /// period's last round, so sends to the filler stay stuck until then.
    filler_local: linux.fd_t,
    filler_remote: linux.fd_t,
    filler: io.PeerId,
    /// Sends to the filler in flight.
    filler_sends: u32,
    /// Operations submitted so far, accepts and sends; the next one's id is this.
    submitted: u64,
    completed: u64,
    /// The ids submitted and not yet completed, and the ring slot each id took.
    in_flight_ids: std.bit_set.Static(accept_soak_ids_max),
    id_slots: [accept_soak_ids_max]u16,
    /// Clients connected so far; each writes its number, a u32, as its first bytes.
    clients_connected: u32,
    held: [accept_soak_table_size]AcceptSoakHeld,
    held_count: u32,
    /// Times each ring slot was taken by an accept or a send, and each table entry by an
    /// accepted connection.
    slot_uses: [slots_count]u32,
    entry_uses: [accept_soak_capacity]u32,
    /// The id each entry was last released under, if any: it must never resolve again, and
    /// the entry's next id must differ from it.
    stale: [accept_soak_capacity]?io.PeerId,
    /// Accepts that completed with TableFull; `Real.refused` must say the same.
    refused: u64,

    fn setUp(self: *AcceptSoak, seed: u64) !void {
        self.seed = seed;
        self.schedule = .init(seed);
        self.poll_sizes = .init(seed ^ 0x9e37_79b9_7f4a_7c15);
        try self.makeDir();
        const dir = self.dirPath();
        errdefer _ = linux.rmdir(dir);
        const socket_path = try std.fmt.bufPrintSentinel(&self.path_bytes, "{s}" ++ accept_soak_socket_name, .{dir}, 0);
        self.path_len = @intCast(socket_path.len);
        const lock_path = try std.fmt.bufPrintSentinel(&self.lock_bytes, "{s}.lock", .{socket_path}, 0);
        self.lock_len = @intCast(lock_path.len);
        errdefer _ = linux.unlink(lock_path);
        self.local = try listener.open(socket_path);
        errdefer self.local.close();
        self.startup = .init(testing.allocator, accept_soak_capacity * connections.entry_bytes);
        self.gpa = self.startup.allocator();
        self.table = try connections.Table.init(self.gpa, accept_soak_capacity);
        errdefer self.table.deinit(self.gpa);
        try self.setUpFiller();
        errdefer self.closeFiller();
        self.real = try Real.init(&self.startup, &self.table);
        self.startup.finishStartup();
        self.filler_sends = 0;
        self.submitted = 0;
        self.completed = 0;
        self.in_flight_ids = .empty;
        self.id_slots = undefined;
        self.clients_connected = 0;
        self.held = undefined;
        self.held_count = 0;
        self.slot_uses = @splat(0);
        self.entry_uses = @splat(0);
        self.stale = @splat(null);
        self.refused = 0;
        assert(self.real.inFlight() == 0);
        assert(self.table.count() == 1);
    }

    /// Opens the filler's socketpair and puts its end in the table, at
    /// `accept_soak_filler_index`; each period's fill round fills its send buffer.
    fn setUpFiller(self: *AcceptSoak) !void {
        assert(self.table.count() == 0);
        var fds: [2]linux.fd_t = .{ -1, -1 };
        const flags = linux.SOCK.STREAM | linux.SOCK.CLOEXEC;
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.socketpair(linux.AF.UNIX, flags, 0, &fds)));
        self.filler_local = fds[0];
        self.filler_remote = fds[1];
        errdefer self.closeFiller();
        self.filler = try self.table.acquire(self.filler_local);
        const parts: connections.IdParts = @bitCast(self.filler);
        try testing.expectEqual(accept_soak_filler_index, parts.index);
        assert(self.table.count() == 1);
    }

    /// Closes both ends of the filler's socketpair; its entry, if still held, is released
    /// first by the caller.
    fn closeFiller(self: *AcceptSoak) void {
        assert(self.filler_local >= 0);
        assert(self.filler_remote >= 0);
        _ = linux.close(self.filler_remote);
        _ = linux.close(self.filler_local);
        self.filler_remote = -1;
        self.filler_local = -1;
    }

    /// Connections the table holds for accepts: all but the filler.
    fn acceptedCount(self: *const AcceptSoak) u32 {
        const count = self.table.count();
        assert(count >= 1); // The filler is held for the whole run.
        assert(count <= accept_soak_capacity);
        return count - 1;
    }

    /// Makes a fresh 0700 directory, skipping any name already taken.
    fn makeDir(self: *AcceptSoak) !void {
        const pid: u32 = @bitCast(linux.getpid());
        var attempt: u32 = 0;
        while (attempt < accept_soak_dir_attempts_max) : (attempt += 1) {
            const dir = try std.fmt.bufPrintSentinel(
                &self.dir_bytes,
                accept_soak_dir_prefix ++ "-{d}-{x}-{d}",
                .{ pid, self.seed, attempt },
                0,
            );
            const made = linux.errno(linux.mkdir(dir, 0o700));
            if (made == .EXIST) continue;
            try testing.expectEqual(linux.E.SUCCESS, made);
            self.dir_len = @intCast(dir.len);
            break;
        } else return error.TestNoFreshDirectory;
        assert(attempt < accept_soak_dir_attempts_max);
        assert(self.dir_len > accept_soak_dir_prefix.len);
    }

    fn dirPath(self: *const AcceptSoak) [:0]const u8 {
        assert(self.dir_len > accept_soak_dir_prefix.len);
        assert(self.dir_len < accept_soak_dir_bytes);
        return self.dir_bytes[0..self.dir_len :0];
    }

    fn lockPath(self: *const AcceptSoak) [:0]const u8 {
        assert(self.lock_len > self.path_len);
        assert(self.lock_len < self.lock_bytes.len);
        return self.lock_bytes[0..self.lock_len :0];
    }

    /// Settles what a failed check left behind, then frees everything. Accepts still in
    /// flight complete only when a client connects, so at most one non-blocking client is
    /// connected for each, then the ring is polled a bounded number of times. Every entry
    /// still in use is released and its socket closed, held or not. The listener and its
    /// directory go before the ring, so a later assertion can't leave them behind. If some
    /// accepts never complete, the ring and the table are left open and false is returned,
    /// so the caller leaks this rather than free memory the kernel may still use.
    fn tearDown(self: *AcceptSoak) bool {
        assert(self.startup.phase == .running);
        assert(self.held_count <= accept_soak_table_size);
        for (self.held[0..self.held_count]) |connection| {
            if (connection.client >= 0) _ = linux.close(connection.client);
        }
        self.held_count = 0;
        // Closing the filler's far end fails every send still stuck on it.
        _ = linux.close(self.filler_remote);
        self.filler_remote = -1;
        // A client for the accept in flight, if any; the filler's sends need none.
        const wanted = self.real.share.accepts_in_flight;
        var connected: u32 = 0;
        while (connected < wanted) : (connected += 1) {
            const client = self.connectNonBlocking() orelse break;
            _ = linux.close(client);
        }
        assert(connected <= wanted);
        var completions: [slots_count]io.Completion = undefined;
        var polls: u32 = 0;
        while (self.real.inFlight() > 0 and polls < poll_attempts_max) : (polls += 1) {
            if (self.real.poll(&completions) > 0) continue;
            const pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
            _ = linux.nanosleep(&pause, null);
        }
        assert(polls <= poll_attempts_max);
        self.releaseLive();
        _ = linux.close(self.filler_local);
        self.filler_local = -1;
        self.local.close();
        _ = linux.unlink(self.lockPath());
        _ = linux.rmdir(self.dirPath());
        if (self.real.inFlight() > 0) return false;
        self.real.deinit();
        self.startup.beginShutdown();
        self.table.deinit(self.gpa);
        assert(self.startup.bytes_live == 0);
        return true;
    }

    /// Releases every entry in use and closes its socket, during teardown only: a failed
    /// check may leave entries the soak never recorded. The filler's socket is closed by
    /// the caller; an entry whose sends never came back is left, as the ring is.
    fn releaseLive(self: *AcceptSoak) void {
        assert(self.held_count == 0);
        var left: u32 = 0;
        for (self.table.entries, 0..) |entry, index| {
            if (entry.state == .free) continue;
            const peer: io.PeerId = @bitCast(connections.IdParts{
                .index = @intCast(index),
                .generation = entry.generation,
            });
            const socket = self.table.release(peer) catch |err| switch (err) {
                error.OperationsInFlight => {
                    // Only the filler sends; accepted connections never do.
                    assert(index == accept_soak_filler_index);
                    left += 1;
                    continue;
                },
            };
            if (index != accept_soak_filler_index) _ = linux.close(socket);
        }
        // Only the filler sends.
        assert(left <= 1);
        assert(self.table.count() == left);
    }

    /// The listener's address and its length, for connect.
    fn addressLen(self: *const AcceptSoak) linux.socklen_t {
        assert(self.path_len > 0);
        assert(self.local.address.path[self.path_len] == 0);
        return @intCast(@offsetOf(linux.sockaddr.un, "path") + self.path_len + 1);
    }

    /// Opens a client and connects it to the listener's path. The connection waits in the
    /// listener's backlog until an accept in flight takes it; a batch never connects more
    /// clients than the backlog holds, so this never waits.
    fn connectClient(self: *AcceptSoak) !linux.fd_t {
        assert(self.real.inFlight() > 0);
        const client = try socketOpen(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC);
        errdefer _ = linux.close(client);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.connect(client, &self.local.address, self.addressLen())));
        assert(client >= 0);
        return client;
    }

    /// As `connectClient`, but never waits and never fails the test: null when the socket
    /// can't be opened or the backlog is full. For teardown.
    fn connectNonBlocking(self: *AcceptSoak) ?linux.fd_t {
        assert(self.local.socket >= 0);
        const flags = linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK;
        const rc = linux.socket(linux.AF.UNIX, flags, 0);
        if (linux.errno(rc) != .SUCCESS) return null;
        const client: linux.fd_t = @intCast(rc);
        assert(client >= 0);
        if (linux.errno(linux.connect(client, &self.local.address, self.addressLen())) != .SUCCESS) {
            _ = linux.close(client);
            return null;
        }
        return client;
    }

    /// Submits one accept on the listener and records the slot it took.
    fn submitAccept(self: *AcceptSoak) !void {
        assert(self.real.share.accepts_in_flight == 0);
        try self.submitOne(.{ .accept = .{ .listener = self.local.socket } });
        assert(self.real.share.accepts_in_flight == 1);
    }

    /// Submits one one-byte send to the filler, which sticks, and records the slot it took.
    fn submitFillerSend(self: *AcceptSoak) !void {
        const in_flight_before = self.filler_sends;
        try self.submitOne(.{ .send = .{ .peer = self.filler, .bytes = "x" } });
        self.filler_sends += 1;
        assert(self.filler_sends > in_flight_before);
        assert(self.real.sends_in_flight == self.filler_sends); // Only the filler sends.
        assert(self.table.get(self.filler).sends_in_flight == self.filler_sends);
    }

    /// Submits one operation under the next id and records the slot it took.
    fn submitOne(self: *AcceptSoak, operation: io.Operation) !void {
        assert(self.real.inFlight() < slots_count);
        assert(self.submitted < accept_soak_ids_max);
        const id = self.submitted;
        try self.real.submit(.{ .id = id, .operation = operation });
        self.submitted += 1;
        // Exactly one slot in use holds the new id; found by search, so the test doesn't
        // depend on how the free list orders slots.
        var found: ?u16 = null;
        for (self.real.slots, 0..) |slot, index| {
            if (!slot.in_use or slot.id != id) continue;
            try testing.expect(found == null);
            try testing.expectEqual(@as(io.Kind, operation), slot.kind);
            found = @intCast(index);
        }
        const index = found orelse return error.TestExpectedSlot;
        self.slot_uses[index] += 1;
        self.in_flight_ids.set(@intCast(id));
        self.id_slots[@intCast(id)] = index;
        try testing.expectEqual(self.submitted - self.completed, @as(u64, self.real.inFlight()));
        assert(self.in_flight_ids.count() == self.real.inFlight());
    }

    /// Reads from `socket` without waiting, retrying 1 ms apart, until it has something to
    /// say: bytes, end of stream or an error. Returns the read's result; fails the test if
    /// the socket stays silent past the bound.
    fn readSoon(socket: linux.fd_t, buffer: []u8) !usize {
        assert(socket >= 0);
        assert(buffer.len > 0);
        var attempts: u32 = 0;
        while (attempts < accept_soak_reads_max) : (attempts += 1) {
            const rc = linux.recvfrom(socket, buffer.ptr, buffer.len, linux.MSG.DONTWAIT, null, null);
            if (linux.errno(rc) != .AGAIN) return rc;
            const pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
            _ = linux.nanosleep(&pause, null);
        }
        assert(attempts == accept_soak_reads_max);
        return error.TestSocketSilent;
    }

    /// The far end of `client` was closed: the client reads end of stream, or a reset when
    /// the far end was closed with bytes the client wrote still unread (a refused
    /// connection's number). A far end still open fails `readSoon` instead.
    fn expectClosed(client: linux.fd_t) !void {
        assert(client >= 0);
        var received: [1]u8 = undefined;
        const rc = try readSoon(client, &received);
        const err = linux.errno(rc);
        if (err == .CONNRESET) return;
        try testing.expectEqual(linux.E.SUCCESS, err);
        try testing.expectEqual(@as(usize, 0), rc);
    }

    /// The far end of `client` is still open and has sent nothing.
    fn expectOpen(client: linux.fd_t) !void {
        assert(client >= 0);
        var received: [1]u8 = undefined;
        const rc = linux.recvfrom(client, &received, received.len, linux.MSG.DONTWAIT, null, null);
        try testing.expectEqual(linux.E.AGAIN, linux.errno(rc));
    }

    /// Connects one client per element of `clients`, each writing its number. Returns the
    /// first client's number.
    fn connectBatch(self: *AcceptSoak, clients: []linux.fd_t) !u32 {
        assert(clients.len > 0 and clients.len <= accept_soak_batch_max);
        assert(self.real.share.accepts_in_flight == 1); // Something will take each one.
        const first_number = self.clients_connected;
        for (clients) |*client| {
            assert(client.* == -1);
            client.* = try self.connectClient();
            const number = self.clients_connected;
            self.clients_connected += 1;
            var tag: [4]u8 = undefined;
            std.mem.writeInt(u32, &tag, number, .little);
            const written = linux.write(client.*, &tag, tag.len);
            try testing.expectEqual(linux.E.SUCCESS, linux.errno(written));
            try testing.expectEqual(tag.len, written);
        }
        return first_number;
    }

    /// Polls until the one accept in flight completes and returns its completion, each poll
    /// with a buffer of a random size, so a poll has more places than the ring has ready.
    /// (With one accept in flight, polls shorter than the ready count are left to the send
    /// soak.) The filler's sends stay stuck meanwhile, so nothing else may complete. Fails
    /// the test if the kernel stops completing.
    fn pollAccept(self: *AcceptSoak) !io.Completion {
        assert(self.real.share.accepts_in_flight == 1);
        assert(self.real.inFlight() == self.filler_sends + 1);
        var completions: [accept_soak_batch_max]io.Completion = undefined;
        var empty_polls: u32 = 0;
        while (empty_polls < poll_attempts_max) : (empty_polls += 1) {
            const size = self.poll_sizes.random().intRangeAtMost(u32, 1, accept_soak_batch_max);
            const got = self.real.poll(completions[0..size]);
            if (got > 0) {
                try testing.expectEqual(@as(u32, 1), got);
                try testing.expect(completions[0].result == .accept);
                return completions[0];
            }
            const pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
            _ = linux.nanosleep(&pause, null);
        }
        // Nothing came back: the accept still holds its slot.
        assert(self.real.share.accepts_in_flight == 1);
        return error.TestAcceptNeverCompleted;
    }

    /// Reads the filler's far end until every send stuck on it has come back with its one
    /// byte. The accept in flight has no client, so it keeps waiting. Fails the test if
    /// the sends stop coming back.
    fn drainFiller(self: *AcceptSoak) !void {
        assert(self.filler_sends > 0);
        assert(self.real.share.accepts_in_flight == 1);
        var completions: [slots_count]io.Completion = undefined;
        var empty_polls: u32 = 0;
        var polls: u32 = 0;
        // Each non-empty poll takes at least one send, so at most a ring of them, each
        // after at most poll_attempts_max empty ones.
        const polls_max: u32 = slots_count * (poll_attempts_max + 1);
        while (self.filler_sends > 0 and empty_polls < poll_attempts_max) : (polls += 1) {
            assert(polls < polls_max);
            _ = try readSome(self.filler_remote);
            const got = self.real.poll(completions[0..self.filler_sends]);
            for (completions[0..got]) |completion| {
                try testing.expect(completion.result == .send);
                try testing.expectEqual(@as(u32, 1), try completion.result.send);
                try self.recordCompletion(completion);
                self.filler_sends -= 1;
            }
            if (got > 0) {
                empty_polls = 0;
                continue;
            }
            empty_polls += 1;
            const pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
            _ = linux.nanosleep(&pause, null);
        }
        try testing.expectEqual(@as(u32, 0), self.filler_sends);
        try testing.expectEqual(@as(connections.SendCount, 0), self.table.get(self.filler).sends_in_flight);
        try testing.expectEqual(@as(u32, 1), self.real.inFlight());
    }

    /// Checks one completion's id: one in flight, completed once, whose slot is free again.
    fn recordCompletion(self: *AcceptSoak, completion: io.Completion) !void {
        assert(self.completed < self.submitted);
        try testing.expect(completion.id < self.submitted);
        const id: u32 = @intCast(completion.id);
        try testing.expect(self.in_flight_ids.isSet(id));
        self.in_flight_ids.unset(id);
        self.completed += 1;
        // Nothing is submitted while a batch is polled, so the slot this id took is free.
        try testing.expect(!self.real.slots[self.id_slots[id]].in_use);
        assert(self.completed <= self.submitted);
    }

    /// Connects `count` clients, each writing its number, then accepts them one at a time:
    /// each completion is followed by the next accept, so one stays in flight, unless
    /// `last` and it was the batch's last client. The table takes exactly as many as it has
    /// room for; the rest complete with TableFull and their connections are closed. Each
    /// connection taken is matched to its client by the number it wrote, so the entry's
    /// socket is shown to be its accepted end.
    fn batch(self: *AcceptSoak, count: u32, last: bool) !void {
        assert(count > 0 and count <= accept_soak_batch_max);
        assert(self.held_count == self.acceptedCount());
        const room = accept_soak_table_size - self.held_count;
        var clients: [accept_soak_batch_max]linux.fd_t = @splat(-1);
        defer for (clients) |client| {
            if (client >= 0) _ = linux.close(client);
        };
        const first_number = try self.connectBatch(clients[0..count]);
        var taken: u32 = 0;
        var refused_here: u32 = 0;
        var matched: [accept_soak_batch_max]bool = @splat(false);
        var index: u32 = 0;
        while (index < count) : (index += 1) {
            const completion = try self.pollAccept();
            try self.recordCompletion(completion);
            if (!last or index + 1 < count) try self.submitAccept();
            if (completion.result.accept) |peer| {
                // The table had room at this completion, so no TableFull came before it in
                // the batch: nothing was released in between.
                try testing.expectEqual(@as(u32, 0), refused_here);
                taken += 1;
                try self.recordTaken(peer, &clients, &matched, first_number);
            } else |err| switch (err) {
                error.TableFull => {
                    try testing.expectEqual(accept_soak_table_size, self.acceptedCount());
                    refused_here += 1;
                },
                // A local listener's connection can't fail on the network, and the soak
                // stays far below the descriptor limit.
                error.PeerDown, error.Backpressure => return error.TestUnexpectedAcceptError,
            }
        }
        try testing.expectEqual(@min(count, room), taken);
        try testing.expectEqual(count - taken, refused_here);
        self.refused += refused_here;
        try testing.expectEqual(self.refused, self.real.refused);
        try testing.expectEqual(self.held_count, self.acceptedCount());
        try testing.expectEqual(self.filler_sends + @intFromBool(!last), self.real.inFlight());
        // Every refused connection was closed before its completion was handed back, so its
        // client reads end of stream.
        for (clients[0..count], matched[0..count]) |client, was_taken| {
            assert(was_taken == (client < 0)); // A taken client is held now.
            if (!was_taken) try expectClosed(client);
        }
        self.table.assertInvariants();
    }

    /// Checks one connection the table took and holds it: its entry is live under a new
    /// id, and its socket reads the number one of this batch's clients wrote, which no other
    /// entry read, while that client's end is still open.
    fn recordTaken(
        self: *AcceptSoak,
        peer: io.PeerId,
        clients: *[accept_soak_batch_max]linux.fd_t,
        matched: *[accept_soak_batch_max]bool,
        first_number: u32,
    ) !void {
        assert(self.held_count < accept_soak_table_size);
        assert(first_number < self.clients_connected);
        const entry = self.table.lookup(peer) orelse return error.TestPeerNotLive;
        try testing.expectEqual(connections.State.idle, entry.state);
        try testing.expectEqual(@as(connections.SendCount, 0), entry.sends_in_flight);
        for (self.held[0..self.held_count]) |other| {
            try testing.expect(other.peer != peer);
            try testing.expect(other.accepted != entry.socket);
        }
        const parts: connections.IdParts = @bitCast(peer);
        try testing.expect(parts.index < accept_soak_capacity);
        try testing.expect(parts.index != accept_soak_filler_index);
        // The entry's last id went stale at its release: the new one differs, and the old
        // one no longer reaches the entry now that it is in use again.
        if (self.stale[parts.index]) |stale| {
            try testing.expect(stale != peer);
            try testing.expect(self.table.lookup(stale) == null);
        }
        var tag: [4]u8 = undefined;
        const rc = try readSoon(entry.socket, &tag);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
        try testing.expectEqual(tag.len, rc);
        const number = std.mem.readInt(u32, &tag, .little);
        try testing.expect(number >= first_number);
        const position = number - first_number;
        try testing.expect(position < accept_soak_batch_max);
        try testing.expect(clients[position] >= 0);
        try testing.expect(!matched[position]);
        matched[position] = true;
        // Held from here, so teardown closes the client and `batch` doesn't.
        self.held[self.held_count] = .{ .peer = peer, .client = clients[position], .accepted = entry.socket };
        self.held_count += 1;
        clients[position] = -1;
        self.entry_uses[parts.index] += 1;
        try expectOpen(self.held[self.held_count - 1].client);
    }

    /// Releases the held connection at `position`: the table hands back its accepted end,
    /// its id goes stale, and once the soak closes that end its client reads end of stream.
    fn releaseAt(self: *AcceptSoak, position: u32) !void {
        assert(position < self.held_count);
        assert(self.held_count == self.acceptedCount());
        const connection = self.held[position];
        const count_before = self.table.count();
        const socket = try self.table.release(connection.peer);
        const closed = linux.errno(linux.close(socket));
        // Removed from `held` before any check can fail, so teardown never closes it twice.
        self.held[position] = self.held[self.held_count - 1];
        self.held_count -= 1;
        defer _ = linux.close(connection.client);
        try testing.expectEqual(connection.accepted, socket);
        try testing.expectEqual(linux.E.SUCCESS, closed);
        try testing.expectEqual(count_before - 1, self.table.count());
        try testing.expect(self.table.lookup(connection.peer) == null);
        const parts: connections.IdParts = @bitCast(connection.peer);
        self.stale[parts.index] = connection.peer;
        try expectClosed(connection.client);
    }

    /// Releases some held connections, picked by the schedule.
    fn releaseSome(self: *AcceptSoak) !void {
        assert(self.held_count == self.acceptedCount());
        const random = self.schedule.random();
        const releases = random.uintAtMost(u32, self.held_count);
        var done: u32 = 0;
        while (done < releases) : (done += 1) {
            assert(self.held_count > 0);
            try self.releaseAt(random.uintLessThan(u32, self.held_count));
        }
        assert(self.held_count == self.acceptedCount());
    }

    /// Releases every held connection.
    fn releaseAll(self: *AcceptSoak) !void {
        const held_before = self.held_count;
        var releases: u32 = 0;
        while (self.held_count > 0) : (releases += 1) {
            assert(releases < held_before);
            try self.releaseAt(self.held_count - 1);
        }
        assert(releases == held_before);
        assert(self.acceptedCount() == 0);
    }

    /// The first round of a period: one accept goes in, `accept_soak_filler_sends` stuck
    /// sends to the filler follow it, and a batch larger than the table runs, so TableFull
    /// comes up in every period.
    fn fillRound(self: *AcceptSoak) !void {
        // The previous period ended with nothing in flight, so every slot the fill holds is
        // taken anew.
        try testing.expectEqual(@as(u32, 0), self.real.inFlight());
        try testing.expectEqual(@as(u32, 0), self.acceptedCount());
        _ = try fillSendBuffer(self.filler_local);
        try self.submitAccept();
        var sends: u32 = 0;
        while (sends < accept_soak_filler_sends) : (sends += 1) try self.submitFillerSend();
        assert(sends == accept_soak_filler_sends);
        try expectStuck(&self.real);
        try testing.expectEqual(accept_soak_filler_sends + 1, self.real.inFlight());
        try self.batch(accept_soak_batch_max, false);
        try self.releaseSome();
    }

    /// One round. The first of a period puts the filler's sends in; the last brings the filler's sends
    /// back, takes one last batch with no accept after it, and releases everything; the
    /// others run one batch and release some.
    fn round(self: *AcceptSoak, number: u32) !void {
        assert(number < accept_soak_rounds_max);
        const phase = number % accept_soak_period;
        if (phase == 0) return self.fillRound();
        // The fill round left one accept in flight, and each batch since put one back.
        assert(self.real.share.accepts_in_flight == 1);
        const random = self.schedule.random();
        const size = random.intRangeAtMost(u32, 1, accept_soak_batch_max);
        if (phase == accept_soak_period - 1) {
            try self.drainFiller();
            try self.batch(size, true);
            return self.releaseAll();
        }
        try self.batch(size, false);
        try self.releaseSome();
    }

    /// Runs every round, then checks the totals.
    fn run(self: *AcceptSoak) !void {
        assert(self.submitted == 0);
        assert(self.real.inFlight() == 0);
        errdefer std.debug.print("real: accept soak failed with seed 0x{x}\n", .{self.seed});
        var number: u32 = 0;
        while (number < accept_soak_rounds_max) : (number += 1) try self.round(number);
        assert(number == accept_soak_rounds_max);
        try self.checkTotals();
    }

    /// After the run: every accept completed, nothing is in flight or held, and the counters
    /// the real type keeps agree with the soak's.
    fn checkTotals(self: *AcceptSoak) !void {
        assert(self.held_count == 0);
        assert(self.submitted <= accept_soak_ids_max);
        try testing.expectEqual(@as(u32, 0), self.real.inFlight());
        try testing.expectEqual(@as(usize, 0), self.in_flight_ids.count());
        try testing.expectEqual(self.submitted, self.completed);
        try testing.expectEqual(self.submitted, self.real.submitted);
        try testing.expectEqual(self.real.submitted, self.real.completed);
        try testing.expectEqual(self.refused, self.real.refused);
        try testing.expectEqual(@as(u32, 0), self.acceptedCount());
        try testing.expectEqual(@as(u32, 0), self.filler_sends);
        try testing.expectEqual(@as(u32, 0), self.real.share.accepts_in_flight);
        try testing.expectEqual(@as(u64, 0), self.real.accept_errno_undocumented_count);
        // The soak's own coverage, not the code's: these fail if a change to the constants
        // or the schedule stops it taking every slot a fill holds, and every entry, in every
        // period. The free stack hands back the slot freed last and a fill never holds more
        // than its sends and the accept, so the slots below that depth are never taken.
        const periods = accept_soak_rounds_max / accept_soak_period;
        var taken: u32 = 0;
        for (self.slot_uses) |uses| {
            if (uses == 0) continue;
            try testing.expect(uses >= periods);
            taken += 1;
        }
        try testing.expectEqual(accept_soak_filler_sends + 1, taken);
        for (self.entry_uses, 0..) |uses, index| {
            if (index == accept_soak_filler_index) continue;
            try testing.expect(uses >= periods);
        }
        self.table.assertInvariants();
    }
};

test "real: a seeded accept soak on the local listener reuses every slot a fill holds and every entry, and closes every refusal" {
    for (accept_soak_seeds) |seed| {
        const soak = try testing.allocator.create(AcceptSoak);
        soak.setUp(seed) catch |err| {
            testing.allocator.destroy(soak);
            return err;
        };
        // A soak whose ring never settled is leaked on purpose; see `tearDown`.
        defer if (soak.tearDown()) testing.allocator.destroy(soak);
        try soak.run();
    }
}
