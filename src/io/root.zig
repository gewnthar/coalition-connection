//! I/O boundary: the only way any component reaches the network, the clock, the database or
//! random bytes.
//!
//! Job: define the contract an I/O type must meet, so the same component code runs against
//! the real system in production and against the deterministic simulator (`sim.zig`) in
//! tests. Components take the I/O type as a `comptime IO: type` parameter, which keeps
//! dispatch static: no function pointers and no hidden allocation.
//!
//! The contract has the shape of io_uring (roadmap core 1): a component submits an
//! operation and gets its result later, as a completion. Nothing blocks, and completions may
//! arrive in any order, so components are written for the event loop from the start.
//!
//! Contract (every method is `pub`, so `@hasDecl` sees it; `assertContract` checks each type):
//!   now(self: *IO) Instant                              monotonic clock, nanoseconds; each
//!                                                       reading at or after the previous one
//!   submit(self: *IO, Submission) SubmitError!void      queue one operation
//!   poll(self: *IO, []Completion) u32                   take finished operations
//!   randomBytes(self: *IO, []u8) RandomError!void       fill a buffer with random bytes
//!   drop(self: *IO, PeerId) DropError!void              shut a connection down both ways
//!
//! Operation lifetime: the bytes an operation names belong to the caller and must stay valid
//! and unchanged until its completion arrives, as with io_uring; the simulator checks this.
//! Each accepted operation completes exactly once, carrying the `id` the caller gave it, and
//! ids in flight must be distinct; the simulator and the real type both check this. A
//! submission refused with any `SubmitError` never completes.
//! Every operation but an accept or a cancel (a send, a receive or a statement) shares at
//! most `constants.io_shared_in_flight_max` operations; the rest are kept for accepts and
//! cancels, so clients that stop reading, or any other kind piling up, can't keep the
//! server from accepting, or from cancelling a connection whose drops ran out. Any of
//! those kinds past that share is refused with `error.SlotsKeptForAccepts`, even with
//! operations free. Cancels have a share of their own, `constants.io_cancels_in_flight_max`,
//! and one past it is refused with `error.CancelsFull`; an accept may take any free
//! operation. The simulator and the real type both check this through `SlotShare`. At most
//! `constants.accepts_in_flight_max` accepts may be in flight, since each completes holding
//! a descriptor; another is a caller's bug and stops the process, however full the queue
//! is, checked through `SlotShare` on both types too. `poll` takes a buffer of 1 to
//! `constants.io_operations_in_flight_max` completions. A send may complete short,
//! reporting fewer bytes than it was given; the caller sends the rest. A send's, a
//! receive's or a cancel's peer stays in the connection table, with its socket open, until
//! that operation's completion arrives. Both types enforce this: they count each such
//! operation on its peer's entry, and the table refuses to release an entry with any
//! counted (`error.OperationsInFlight`).
//!
//! Receives (roadmap core 3b): a receive reads what has arrived on a connection into the
//! caller's buffer, which belongs to the I/O type until the completion arrives (the
//! simulator checks the caller leaves it alone), and completes with the bytes it read: at
//! least one and at most the buffer's length, or 0 when the peer has closed its side (end
//! of stream). It may complete short of the buffer at any point, so a request head can
//! arrive a byte at a time. At most one receive may be in flight on a connection, since
//! two would split its bytes between their buffers in no set order; a second is a
//! caller's bug and stops the process (`Table.receiveSubmitted`).
//!
//! Cancels (roadmap core 3b): a cancel names a connection, and every send and receive in
//! flight on it that hasn't finished yet completes with `error.Canceled`, at a later
//! `poll`; one that had already finished keeps its own result. The cancel completes too,
//! with the number of operations it reached, which may be 0. It is how the caller frees a
//! connection whose drops ran out (`error.DropsExhausted`). Once a cancel is submitted on
//! a connection, nothing but another cancel or a drop may be submitted on it until it is
//! released, and at most one cancel may be in flight on it; either is a caller's bug and
//! stops the process (`Table.cancelSubmitted`). Accepts are never cancelled: a cancel names
//! a connection, and an accept waits on the listener.
//!
//! Accepts (roadmap core 3a): an accept waits on a listening socket until a connection
//! arrives, then completes with the new connection's `PeerId`: the I/O type itself takes
//! an entry in the connection table for it, so the caller never holds a raw socket. When
//! the table is full, the connection is closed at once and the accept completes with
//! `error.TableFull`; the caller decides when to accept again. Each accept takes one
//! connection: to keep accepting, submit another. After an accept completes with
//! `error.Backpressure`, every accept submitted within
//! `constants.io_accept_backpressure_wait_ns` is refused with `error.AcceptTooSoon` and
//! never completes. The wait is measured from a clock reading taken inside the `poll` that
//! handed back the Backpressure, so a caller's deadline of `now()` after that poll plus the
//! wait is never early. A refusal changes nothing the caller holds, so submitting again on
//! any later tick is safe. Each Backpressure starts the wait again. Sends are not held
//! back. The simulator and the real type both check this through `AcceptWait`, each
//! against its own clock.
//!
//! Dropping a connection: a send to a client that stops reading can stay pending for ever,
//! holding its slot and its connection's entry. `drop` shuts the connection down, so every
//! send still pending on it completes at a later `poll`, as `error.PeerDown` or, for one
//! that had already finished, with its own result; a send submitted to it afterwards
//! completes as `error.PeerDown`. It takes no operation slot and completes nothing itself.
//! The caller then releases the entry once its last send has come back. A drop can fail (an
//! errno shutdown(2) doesn't document, on the real type), leaving the sends pending; each
//! failure is counted on the connection's entry, for its whole life, and once
//! `constants.io_drop_attempts_max` have failed, that drop and every later one of the
//! connection returns `error.DropsExhausted` without trying again; the caller then cancels
//! the connection's operations instead. A drop also ends a receive pending on the
//! connection, as end of stream (0 bytes) or `error.PeerDown`, and a receive submitted to
//! it afterwards completes the same way. Once a drop has worked, dropping again changes
//! nothing and never fails. The simulator and the real type both count through the same
//! table calls (`Table.dropAdmit`, `Table.dropFailed`).
//!
//! Placeholders: `execute` stands in for database traffic until roadmap core 11 frames
//! Postgres over sockets. Components should not build on `execute`.
//!
//! Random bytes: the operating system's CSPRNG in production, the seeded PRNG in the
//! simulator, so token nonces never break replay. The simulator refuses to compile into a
//! program that doesn't declare itself a simulation (see `sim.zig`).
//!
//! Inputs: submissions from components; buffers to fill.
//! Outputs: time readings, completions with explicit errors, random bytes.
//! Limits: at most `constants.io_operations_in_flight_max` operations in flight; messages of
//! at most `constants.http_response_size_max` bytes; receives into at most
//! `constants.http_request_size_max` bytes; statements of at most
//! `constants.postgres_message_size_max` bytes; at most `constants.io_random_bytes_max`
//! random bytes per call.
//!
//! `now` takes `*IO`, not `*const IO`, so an I/O type can keep its last reading and check
//! every new one against it.
//!
//! Status: the contract, the simulator, and the real type for Linux (`real.zig`), which
//! meets the contract with an io_uring ring for sends, receives, accepts and cancels. `listener.zig` opens
//! the one socket accepts are taken on: a Unix socket at the config's path, never a network
//! address. The contract grows (connect, timers) slice by slice.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const sim = @import("sim.zig");
pub const real = @import("real.zig");
pub const listener = @import("listener.zig");

/// Nanoseconds on a monotonic clock. Never wall-clock time.
pub const Instant = u64;

/// A connection in the startup-sized connection table: the entry's index in the low 16 bits
/// and the entry's generation in the high 48, so an id goes stale once its connection is
/// released, and one entry's generation takes years to wrap (`src/live/connections.zig`).
pub const PeerId = u64;

/// A Linux file descriptor. The event loop is io_uring, so the boundary is Linux-only, and
/// the type is spelled out instead of taken from a portable layer whose size varies by
/// target.
pub const Socket = i32;

/// Chosen by the caller and handed back with the completion, like io_uring's user_data.
pub const OperationId = u64;

/// `QueueFull`: every operation the I/O type holds is in flight. `SlotsKeptForAccepts`:
/// anything but an accept or a cancel, with those kinds already holding their whole share
/// (`constants.io_shared_in_flight_max`); the operations left are kept for accepts and
/// cancels. `CancelsFull`: a cancel, with `constants.io_cancels_in_flight_max` cancels in
/// flight already. Each way, submit again after a completion.
/// `AcceptTooSoon`: an accept, less than `constants.io_accept_backpressure_wait_ns` after
/// the latest accept that completed with `error.Backpressure`; submit it again once that
/// time has passed. A full queue never meets an accept: the share keeps exactly
/// `constants.accepts_in_flight_max` operations back, so a full queue already holds every
/// accept allowed, and another accept stops the process before the queue is checked.
pub const SubmitError = error{ QueueFull, SlotsKeptForAccepts, CancelsFull, AcceptTooSoon };

/// `Canceled`: a cancel of the send's connection reached it before it finished.
pub const SendError = error{ PeerDown, Backpressure, Canceled };

/// Why a receive read nothing. `PeerDown`: the connection failed (reset, or dropped).
/// `Backpressure`: the system was short of memory, or the call was interrupted; receive
/// again later. `Canceled`: a cancel of the connection reached it before it finished. End
/// of stream is no error: the receive completes with 0 bytes.
pub const ReceiveError = error{ PeerDown, Backpressure, Canceled };
pub const DatabaseError = error{ Unavailable, Timeout };

/// `DropsExhausted`: dropping this connection has failed `constants.io_drop_attempts_max`
/// times, so the I/O type no longer tries; its sends may still be pending.
pub const DropError = error{DropsExhausted};

/// Why an accept handed back no connection. `TableFull`: a connection arrived, but every
/// entry of the connection table is in use, so it was closed. `PeerDown`: the connection
/// failed before it could be accepted. `Backpressure`: the system is short of descriptors
/// or memory, or the call was interrupted; the I/O type refuses the next accept with
/// `error.AcceptTooSoon` until `constants.io_accept_backpressure_wait_ns` has passed, so a
/// retry that would fail the same way can't spin the loop.
pub const AcceptError = error{ TableFull, PeerDown, Backpressure };

/// The wait after an accept completes with `error.Backpressure`, kept by every I/O type
/// that meets the contract, so the real type and the simulator make the same checks through
/// the same calls, each with a reading of its own clock. Each Backpressure starts the wait
/// again from the reading given; `admit` refuses an accept with `error.AcceptTooSoon` until
/// a reading reaches `resume_at`, and clears the wait at the first one that does.
pub const AcceptWait = struct {
    /// The reading the running wait started from; meaningful only while `resume_at` is set.
    started_at: Instant = 0,
    /// When an accept may be submitted again, or null when no wait runs.
    resume_at: ?Instant = null,
    /// Accepts refused with `AcceptTooSoon`. For metrics and tests.
    refused: u64 = 0,

    /// Starts the wait, or starts it again, from `reading`, taken as the Backpressure
    /// completion is handed back.
    pub fn begin(self: *AcceptWait, reading: Instant) void {
        const wait = constants.io_accept_backpressure_wait_ns;
        // A clock reading has centuries of room below the top of a u64.
        assert(reading <= std.math.maxInt(Instant) - wait);
        // Readings come from one monotonic clock, so a restart never starts earlier.
        assert(self.resume_at == null or self.started_at <= reading);
        self.started_at = reading;
        self.resume_at = reading + wait;
    }

    /// Lets an accept go ahead at `reading`, clearing a wait that is over, or refuses it
    /// with `error.AcceptTooSoon` and counts the refusal; changes nothing else.
    pub fn admit(self: *AcceptWait, reading: Instant) error{AcceptTooSoon}!void {
        const resume_at = self.resume_at orelse return;
        // The wait ends exactly one wait after it started, and it started at a reading no
        // later than this one.
        assert(resume_at - self.started_at == constants.io_accept_backpressure_wait_ns);
        assert(self.started_at <= reading);
        if (reading < resume_at) {
            self.refused += 1;
            return error.AcceptTooSoon;
        }
        self.resume_at = null;
    }
};

/// The operations kept for accepts and cancels, counted by every I/O type that meets the
/// contract through the same calls, as with `AcceptWait`, so a check only one side makes
/// can't let a bug pass every simulation. Every operation but an accept or a cancel counts
/// against one share of `constants.io_shared_in_flight_max`; a cancel counts against its
/// own share of `constants.io_cancels_in_flight_max`; an accept counts against no share
/// and may take any free operation. The I/O type checks its own full queue first.
///
/// Accepts are counted too, against `constants.accepts_in_flight_max`: each one in flight
/// completes holding a new socket, a descriptor the open-file check at startup counts in
/// `constants.descriptors_besides_connections`, so a caller that keeps more in flight could
/// run the process out of descriptors the check promised were there. A caller's bug, so
/// `assertAcceptRoom` stops the process on it, before the I/O type checks anything that
/// can refuse a submission.
pub const SlotShare = struct {
    /// Operations in flight that are neither accepts nor cancels: never more than
    /// `others_max`.
    others_in_flight: u32 = 0,
    /// Cancels in flight: never more than `cancels_max`.
    cancels_in_flight: u32 = 0,
    /// Accepts in flight: never more than `accepts_max`.
    accepts_in_flight: u32 = 0,

    pub const others_max: u32 = constants.io_shared_in_flight_max;
    pub const cancels_max: u32 = constants.io_cancels_in_flight_max;
    pub const accepts_max: u32 = constants.accepts_in_flight_max;

    comptime {
        // The three shares are the whole queue, so a full queue has every share full.
        assert(others_max + cancels_max + accepts_max == constants.io_operations_in_flight_max);
    }

    /// Operations counted here, of every kind.
    pub fn total(self: *const SlotShare) u32 {
        assert(self.others_in_flight <= others_max);
        assert(self.cancels_in_flight <= cancels_max and self.accepts_in_flight <= accepts_max);
        return self.others_in_flight + self.cancels_in_flight + self.accepts_in_flight;
    }

    /// Stops the process when `kind` is an accept and `accepts_max` accepts are in flight
    /// already. Changes nothing. The I/O type calls it before its full-queue check, so a
    /// caller's bug stops the process however full the queue is.
    pub fn assertAcceptRoom(self: *const SlotShare, kind: Kind) void {
        assert(self.accepts_in_flight <= accepts_max);
        // Every operation counted here holds one of the I/O type's.
        assert(self.total() <= constants.io_operations_in_flight_max);
        // A caller keeps at most `accepts_max` accepts in flight (src/constants.zig).
        if (kind == .accept) assert(self.accepts_in_flight < accepts_max);
    }

    /// Refuses `kind` when its share is held whole: a cancel with `error.CancelsFull`, any
    /// kind but an accept or a cancel with `error.SlotsKeptForAccepts`. Changes nothing.
    /// `free` is the operations the I/O type has free, after its own full-queue check, so
    /// never 0.
    pub fn admit(self: *const SlotShare, kind: Kind, free: u32) error{ SlotsKeptForAccepts, CancelsFull }!void {
        // The full queue is checked first, as the contract orders the refusals.
        assert(free > 0);
        // Every operation is counted here or free, on both types.
        assert(self.total() + free == constants.io_operations_in_flight_max);
        switch (kind) {
            .accept => {},
            .cancel => if (self.cancels_in_flight == cancels_max) return error.CancelsFull,
            .send, .receive, .execute => if (self.others_in_flight == others_max) {
                return error.SlotsKeptForAccepts;
            },
        }
    }

    /// Counts an operation of `kind` that `admit` let in and that now holds a slot.
    pub fn taken(self: *SlotShare, kind: Kind) void {
        const total_before = self.total();
        // `assertAcceptRoom` stopped the process, or `admit` refused it, otherwise.
        switch (kind) {
            .accept => {
                assert(self.accepts_in_flight < accepts_max);
                self.accepts_in_flight += 1;
            },
            .cancel => {
                assert(self.cancels_in_flight < cancels_max);
                self.cancels_in_flight += 1;
            },
            .send, .receive, .execute => {
                assert(self.others_in_flight < others_max);
                self.others_in_flight += 1;
            },
        }
        assert(self.total() == total_before + 1);
    }

    /// Uncounts an operation of `kind` that has completed and given its slot back.
    pub fn released(self: *SlotShare, kind: Kind) void {
        const total_before = self.total();
        // Each was counted by `taken` at submit.
        switch (kind) {
            .accept => {
                assert(self.accepts_in_flight > 0);
                self.accepts_in_flight -= 1;
            },
            .cancel => {
                assert(self.cancels_in_flight > 0);
                self.cancels_in_flight -= 1;
            },
            .send, .receive, .execute => {
                assert(self.others_in_flight > 0);
                self.others_in_flight -= 1;
            },
        }
        assert(self.total() == total_before - 1);
    }
};

/// The operating system could not supply random bytes. Production callers refuse the
/// operation that needed them; they never fall back to a weaker source.
pub const RandomError = error{RandomUnavailable};

pub const Kind = enum(u8) { send, execute, accept, receive, cancel };

/// One outgoing message to a peer.
pub const Send = struct {
    peer: PeerId,
    bytes: []const u8,
};

/// One database statement.
pub const Execute = struct {
    statement: []const u8,
};

/// Take one connection from a listening socket.
pub const Accept = struct {
    listener: Socket,
};

/// Read what has arrived from a peer into `buffer`, which the I/O type owns until the
/// receive completes.
pub const Receive = struct {
    peer: PeerId,
    buffer: []u8,
};

/// End every send and receive in flight on a peer's connection.
pub const Cancel = struct {
    peer: PeerId,
};

pub const Operation = union(Kind) {
    send: Send,
    execute: Execute,
    accept: Accept,
    receive: Receive,
    cancel: Cancel,
};

pub const Submission = struct {
    id: OperationId,
    operation: Operation,
};

/// The outcome of one operation. A send reports the bytes it sent; an accept, the new
/// connection's entry in the connection table; a receive, the bytes it read (0 for end of
/// stream); a cancel, the operations it reached.
pub const Result = union(Kind) {
    send: SendError!u32,
    execute: DatabaseError!void,
    accept: AcceptError!PeerId,
    receive: ReceiveError!u32,
    cancel: u32,
};

pub const Completion = struct {
    id: OperationId,
    result: Result,
};

/// The low bits of a `PeerId` that hold its entry's index (`connections.IdParts`).
const peer_index_mask: PeerId = std.math.maxInt(u16);

/// The peer an operation acts on, or null for an accept or a statement, which name none.
pub fn operationPeer(operation: Operation) ?PeerId {
    const peer: ?PeerId = switch (operation) {
        .send => |send| send.peer,
        .receive => |receive| receive.peer,
        .cancel => |cancel| cancel.peer,
        .accept, .execute => null,
    };
    // Exactly the kinds a connection's entry counts name a peer.
    const counted = operation == .send or operation == .receive or operation == .cancel;
    assert((peer != null) == counted);
    // A peer's index, its id's low 16 bits (`connections.IdParts`), names an entry of the
    // largest table.
    assert(peer == null or (peer.? & peer_index_mask) < constants.http_connections_max);
    return peer;
}

/// Fails compilation when `IO` does not meet the contract above.
pub fn assertContract(comptime IO: type) void {
    comptime {
        if (contractError(IO)) |message| @compileError(message);
        assert(contractError(IO) == null);
    }
}

/// Describes the first way `IO` breaks the contract, or returns null when it meets it. A
/// stand-in with a missing method or a wrong signature is caught here, at compile time, not
/// at some distant call site.
pub fn contractError(comptime IO: type) ?[]const u8 {
    assert(@typeInfo(IO) == .@"struct");
    // The array's element type keeps each result optional; a chain of `orelse` evaluated at
    // compile time would hand back the bare payload type.
    const messages = [_]?[]const u8{
        methodError(IO, "now", fn (*IO) Instant),
        methodError(IO, "submit", fn (*IO, Submission) SubmitError!void),
        methodError(IO, "poll", fn (*IO, []Completion) u32),
        methodError(IO, "randomBytes", fn (*IO, []u8) RandomError!void),
        methodError(IO, "drop", fn (*IO, PeerId) DropError!void),
    };
    var first: ?[]const u8 = null;
    for (messages) |message| {
        if (first == null) first = message;
    }
    assert(first == null or first.?.len > 0);
    return first;
}

/// Checks one method. `@hasDecl` comes first because naming a missing declaration is itself
/// a compile error; both branches are decided at compile time.
fn methodError(comptime IO: type, comptime name: []const u8, comptime Expected: type) ?[]const u8 {
    assert(name.len > 0);
    assert(@typeInfo(Expected) == .@"fn");
    if (!@hasDecl(IO, name)) {
        return "I/O contract: " ++ @typeName(IO) ++ " has no pub method " ++ name;
    } else if (@TypeOf(@field(IO, name)) != Expected) {
        return "I/O contract: " ++ @typeName(IO) ++ "." ++ name ++ " should be " ++
            @typeName(Expected);
    } else {
        return null;
    }
}

const testing = std.testing;

test "io: the simulator meets the contract" {
    assertContract(sim.Sim);
    try testing.expect(comptime contractError(sim.Sim) == null);
}

/// Stand-in with every method but `randomBytes`.
const MissingRandom = struct {
    pub fn now(self: *MissingRandom) Instant {
        _ = self;
        return 0;
    }
    pub fn submit(self: *MissingRandom, submission: Submission) SubmitError!void {
        _ = self;
        _ = submission;
    }
    pub fn poll(self: *MissingRandom, completions: []Completion) u32 {
        _ = self;
        _ = completions;
        return 0;
    }
};

/// Stand-in whose `poll` returns `usize` instead of `u32`.
const WrongPoll = struct {
    pub fn now(self: *WrongPoll) Instant {
        _ = self;
        return 0;
    }
    pub fn submit(self: *WrongPoll, submission: Submission) SubmitError!void {
        _ = self;
        _ = submission;
    }
    pub fn poll(self: *WrongPoll, completions: []Completion) usize {
        _ = self;
        return completions.len;
    }
    pub fn randomBytes(self: *WrongPoll, buffer: []u8) RandomError!void {
        _ = self;
        @memset(buffer, 0);
    }
};

test "io: a stand-in with a missing method is refused" {
    const message = comptime contractError(MissingRandom);
    try testing.expect(message != null);
    try testing.expect(std.mem.find(u8, message.?, "randomBytes") != null);
}

test "io: a stand-in with a wrong signature is refused" {
    const message = comptime contractError(WrongPoll);
    try testing.expect(message != null);
    try testing.expect(std.mem.find(u8, message.?, "poll") != null);
    try testing.expect(comptime contractError(struct {}) != null);
}

/// The contract's methods, so a test can name which one a stand-in gets wrong.
const Method = enum { now, submit, poll, random_bytes, drop };
const methods_count: u32 = 5;

/// The name each method has in the contract.
fn methodName(comptime method: Method) []const u8 {
    const name = switch (method) {
        .now => "now",
        .submit => "submit",
        .poll => "poll",
        .random_bytes => "randomBytes",
        .drop => "drop",
    };
    assert(name.len > 0);
    assert(name.len <= "randomBytes".len);
    return name;
}

/// The signature the contract asks of `IO` for `method`, written out again here rather than
/// read from `contractError`, so a change to the contract's table shows up as a failing test.
fn Signature(comptime IO: type, comptime method: Method) type {
    const result = switch (method) {
        .now => fn (*IO) Instant,
        .submit => fn (*IO, Submission) SubmitError!void,
        .poll => fn (*IO, []Completion) u32,
        .random_bytes => fn (*IO, []u8) RandomError!void,
        .drop => fn (*IO, PeerId) DropError!void,
    };
    assert(@typeInfo(result) == .@"fn");
    assert(@typeInfo(result).@"fn".param_types.len >= 1);
    return result;
}

const message_prefix = "I/O contract: ";

/// The exact message `contractError` gives when `IO.method` has the wrong signature.
fn messageWrong(comptime IO: type, comptime method: Method) []const u8 {
    const result = message_prefix ++ @typeName(IO) ++ "." ++ comptime methodName(method) ++
        " should be " ++ @typeName(Signature(IO, method));
    assert(std.mem.startsWith(u8, result, message_prefix));
    assert(result.len > message_prefix.len);
    return result;
}

/// The exact message `contractError` gives when `IO` has no `pub` declaration `method`.
fn messageMissing(comptime IO: type, comptime method: Method) []const u8 {
    const result = message_prefix ++ @typeName(IO) ++ " has no pub method " ++
        comptime methodName(method);
    assert(std.mem.startsWith(u8, result, message_prefix));
    assert(result.len > message_prefix.len);
    return result;
}

/// Correct method bodies for a stand-in type `Self`, so each stand-in below spells out only
/// the method it gets wrong, hides or leaves out.
fn StandInMethods(comptime Self: type) type {
    assert(@typeInfo(Self) == .@"struct");
    assert(@sizeOf(Self) == 0);
    return struct {
        pub fn now(self: *Self) Instant {
            _ = self;
            return 0;
        }
        pub fn submit(self: *Self, submission: Submission) SubmitError!void {
            _ = self;
            _ = submission;
        }
        pub fn poll(self: *Self, completions: []Completion) u32 {
            _ = self;
            _ = completions;
            return 0;
        }
        pub fn randomBytes(self: *Self, buffer: []u8) RandomError!void {
            _ = self;
            @memset(buffer, 0);
        }
        pub fn drop(self: *Self, peer: PeerId) DropError!void {
            _ = self;
            _ = peer;
        }
    };
}

/// Checks that `contractError(IO)` gives exactly `expected`. When the check wrongly accepts
/// `IO`, this fails as a test rather than stopping the build at an unwrap of null.
fn expectMessage(comptime IO: type, comptime expected: []const u8) !void {
    comptime assert(std.mem.startsWith(u8, expected, message_prefix));
    const message = comptime contractError(IO);
    const actual = message orelse return error.TestExpectedMessage;
    try testing.expectEqualStrings(expected, actual);
}

/// Meets the contract: the control for every test below. Without it, a `contractError` that
/// refused every type would pass them all.
const Correct = struct {
    pub const now = StandInMethods(Correct).now;
    pub const submit = StandInMethods(Correct).submit;
    pub const poll = StandInMethods(Correct).poll;
    pub const randomBytes = StandInMethods(Correct).randomBytes;
    pub const drop = StandInMethods(Correct).drop;
};

/// `now` takes `*const Self` where the contract takes `*Self`, so it couldn't keep its last
/// reading.
const WrongNow = struct {
    pub fn now(self: *const WrongNow) Instant {
        _ = self;
        return 0;
    }
    pub const submit = StandInMethods(WrongNow).submit;
    pub const poll = StandInMethods(WrongNow).poll;
    pub const randomBytes = StandInMethods(WrongNow).randomBytes;
    pub const drop = StandInMethods(WrongNow).drop;
};

/// `submit` widens its error set to `anyerror`, so callers lose an exhaustive switch.
const WrongSubmit = struct {
    pub const now = StandInMethods(WrongSubmit).now;
    pub fn submit(self: *WrongSubmit, submission: Submission) anyerror!void {
        _ = self;
        _ = submission;
    }
    pub const poll = StandInMethods(WrongSubmit).poll;
    pub const randomBytes = StandInMethods(WrongSubmit).randomBytes;
    pub const drop = StandInMethods(WrongSubmit).drop;
};

/// `randomBytes` returns a count the contract doesn't have.
const WrongRandom = struct {
    pub const now = StandInMethods(WrongRandom).now;
    pub const submit = StandInMethods(WrongRandom).submit;
    pub const poll = StandInMethods(WrongRandom).poll;
    pub fn randomBytes(self: *WrongRandom, buffer: []u8) RandomError!u32 {
        _ = self;
        @memset(buffer, 0);
        return @intCast(buffer.len);
    }
    pub const drop = StandInMethods(WrongRandom).drop;
};

/// `drop` returns nothing, so a caller couldn't learn that a connection's drops are
/// exhausted and its sends still pending.
const WrongDrop = struct {
    pub const now = StandInMethods(WrongDrop).now;
    pub const submit = StandInMethods(WrongDrop).submit;
    pub const poll = StandInMethods(WrongDrop).poll;
    pub const randomBytes = StandInMethods(WrongDrop).randomBytes;
    pub fn drop(self: *WrongDrop, peer: PeerId) void {
        _ = self;
        _ = peer;
    }
};

test "io: a stand-in that meets the contract passes" {
    assertContract(Correct);
    try testing.expect(comptime contractError(Correct) == null);
}

test "io: each method's signature is checked" {
    // WrongPoll, above, takes the poll case.
    try expectMessage(WrongNow, messageWrong(WrongNow, .now));
    try expectMessage(WrongSubmit, messageWrong(WrongSubmit, .submit));
    try expectMessage(WrongPoll, messageWrong(WrongPoll, .poll));
    try expectMessage(WrongRandom, messageWrong(WrongRandom, .random_bytes));
    try expectMessage(WrongDrop, messageWrong(WrongDrop, .drop));
}

test "io: a private method counts as missing, for each method" {
    // In Zig 0.17 `@hasDecl` sees only `pub` declarations, so a private method is missing,
    // as it would be at a call site in another file.
    const PrivateNow = struct {
        const Self = @This();
        fn now(self: *Self) Instant {
            _ = self;
            return 0;
        }
        pub const submit = StandInMethods(Self).submit;
        pub const poll = StandInMethods(Self).poll;
        pub const randomBytes = StandInMethods(Self).randomBytes;
        pub const drop = StandInMethods(Self).drop;
    };
    const PrivateSubmit = struct {
        const Self = @This();
        pub const now = StandInMethods(Self).now;
        fn submit(self: *Self, submission: Submission) SubmitError!void {
            _ = self;
            _ = submission;
        }
        pub const poll = StandInMethods(Self).poll;
        pub const randomBytes = StandInMethods(Self).randomBytes;
        pub const drop = StandInMethods(Self).drop;
    };
    const PrivatePoll = struct {
        const Self = @This();
        pub const now = StandInMethods(Self).now;
        pub const submit = StandInMethods(Self).submit;
        fn poll(self: *Self, completions: []Completion) u32 {
            _ = self;
            _ = completions;
            return 0;
        }
        pub const randomBytes = StandInMethods(Self).randomBytes;
        pub const drop = StandInMethods(Self).drop;
    };
    const PrivateRandom = struct {
        const Self = @This();
        pub const now = StandInMethods(Self).now;
        pub const submit = StandInMethods(Self).submit;
        pub const poll = StandInMethods(Self).poll;
        fn randomBytes(self: *Self, buffer: []u8) RandomError!void {
            _ = self;
            @memset(buffer, 0);
        }
        pub const drop = StandInMethods(Self).drop;
    };
    const PrivateDrop = struct {
        const Self = @This();
        pub const now = StandInMethods(Self).now;
        pub const submit = StandInMethods(Self).submit;
        pub const poll = StandInMethods(Self).poll;
        pub const randomBytes = StandInMethods(Self).randomBytes;
        fn drop(self: *Self, peer: PeerId) DropError!void {
            _ = self;
            _ = peer;
        }
    };
    try expectMessage(PrivateNow, messageMissing(PrivateNow, .now));
    try expectMessage(PrivateSubmit, messageMissing(PrivateSubmit, .submit));
    try expectMessage(PrivatePoll, messageMissing(PrivatePoll, .poll));
    try expectMessage(PrivateRandom, messageMissing(PrivateRandom, .random_bytes));
    try expectMessage(PrivateDrop, messageMissing(PrivateDrop, .drop));
}

test "io: a type with several problems is blamed for the first, in contract order" {
    // Each stand-in gets one method wrong and leaves out every method after it. Any change
    // to the table's order swaps some adjacent pair, and so does checking every method for
    // presence before any signature, so one of these then blames the later method.
    const NowWrongRestMissing = struct {
        pub fn now(self: *const @This()) Instant {
            _ = self;
            return 0;
        }
    };
    const SubmitWrongRestMissing = struct {
        const Self = @This();
        pub const now = StandInMethods(Self).now;
        pub fn submit(self: *Self, submission: Submission) anyerror!void {
            _ = self;
            _ = submission;
        }
    };
    const PollWrongRandomMissing = struct {
        const Self = @This();
        pub const now = StandInMethods(Self).now;
        pub const submit = StandInMethods(Self).submit;
        pub fn poll(self: *Self, completions: []Completion) usize {
            _ = self;
            return completions.len;
        }
    };
    const RandomWrongDropMissing = struct {
        const Self = @This();
        pub const now = StandInMethods(Self).now;
        pub const submit = StandInMethods(Self).submit;
        pub const poll = StandInMethods(Self).poll;
        pub fn randomBytes(self: *Self, buffer: []u8) RandomError!u32 {
            _ = self;
            @memset(buffer, 0);
            return @intCast(buffer.len);
        }
    };
    const Empty = struct {};
    comptime assert(std.enums.values(Method).len == methods_count);
    try expectMessage(Empty, messageMissing(Empty, .now));
    try expectMessage(NowWrongRestMissing, messageWrong(NowWrongRestMissing, .now));
    try expectMessage(SubmitWrongRestMissing, messageWrong(SubmitWrongRestMissing, .submit));
    try expectMessage(PollWrongRandomMissing, messageWrong(PollWrongRandomMissing, .poll));
    try expectMessage(RandomWrongDropMissing, messageWrong(RandomWrongDropMissing, .random_bytes));
}

test {
    _ = sim;
    // The real type is Linux only; on another target its tests aren't analyzed at all.
    if (builtin.target.os.tag == .linux) {
        _ = real;
        _ = listener;
    }
}

test "AcceptWait: refuses until one wait past the latest Backpressure, then clears" {
    const wait = constants.io_accept_backpressure_wait_ns;
    var accept_wait: AcceptWait = .{};
    // No wait runs: every reading is admitted, and nothing is counted.
    try accept_wait.admit(5);
    accept_wait.begin(1_000);
    try testing.expectError(error.AcceptTooSoon, accept_wait.admit(1_000));
    try testing.expectError(error.AcceptTooSoon, accept_wait.admit(1_000 + wait - 1));
    // A second Backpressure starts the wait again from its own reading.
    accept_wait.begin(1_500);
    try testing.expectError(error.AcceptTooSoon, accept_wait.admit(1_000 + wait));
    try testing.expectEqual(@as(?Instant, 1_500 + wait), accept_wait.resume_at);
    try accept_wait.admit(1_500 + wait);
    try testing.expectEqual(@as(?Instant, null), accept_wait.resume_at);
    try accept_wait.admit(1_500 + wait);
    try testing.expectEqual(@as(u64, 3), accept_wait.refused);
}

test "SlotShare: accepts are counted to their limit, apart from the share" {
    comptime assert(SlotShare.accepts_max == constants.accepts_in_flight_max);
    var share: SlotShare = .{};
    // Below the limit, an accept has room, and other kinds never touch the accepts' count.
    share.assertAcceptRoom(.accept);
    share.taken(.send);
    share.taken(.execute);
    try testing.expectEqual(@as(u32, 0), share.accepts_in_flight);
    var taken: u32 = 0;
    while (taken < SlotShare.accepts_max) : (taken += 1) {
        share.assertAcceptRoom(.accept);
        share.taken(.accept);
    }
    try testing.expectEqual(SlotShare.accepts_max, share.accepts_in_flight);
    try testing.expectEqual(@as(u32, 2), share.others_in_flight);
    // At the limit, other kinds still pass the check; another accept would stop the
    // process (the startup-trip harness covers that).
    share.assertAcceptRoom(.send);
    share.assertAcceptRoom(.execute);
    // A finished accept gives its place back, and a finished send leaves accepts alone.
    share.released(.send);
    try testing.expectEqual(SlotShare.accepts_max, share.accepts_in_flight);
    share.released(.accept);
    try testing.expectEqual(SlotShare.accepts_max - 1, share.accepts_in_flight);
    share.assertAcceptRoom(.accept);
}

test "SlotShare: anything but an accept is refused once the share is held, and an accept never is" {
    const others_max = SlotShare.others_max;
    const total = constants.io_operations_in_flight_max;
    // The constants keep at least one operation out of the share.
    comptime assert(others_max < total);
    var share: SlotShare = .{};
    var held: u32 = 0;
    while (held < others_max) : (held += 1) {
        const kind: Kind = if (held % 2 == 0) .send else .execute;
        try share.admit(kind, total - held);
        share.taken(kind);
    }
    try testing.expectEqual(others_max, share.others_in_flight);
    try testing.expectError(error.SlotsKeptForAccepts, share.admit(.send, total - held));
    try testing.expectError(error.SlotsKeptForAccepts, share.admit(.execute, total - held));
    // An accept is let in and taken without touching the count.
    try share.admit(.accept, total - held);
    share.taken(.accept);
    try testing.expectEqual(others_max, share.others_in_flight);
    // A finished accept frees nothing in the share; a finished send frees one place.
    share.released(.accept);
    try testing.expectError(error.SlotsKeptForAccepts, share.admit(.execute, total - held));
    share.released(.send);
    try testing.expectEqual(others_max - 1, share.others_in_flight);
    try share.admit(.execute, total - held + 1);
}

test "SlotShare: cancels have a share of their own, refused past it, and touch no other count" {
    const cancels_max = SlotShare.cancels_max;
    var share: SlotShare = .{};
    var held: u32 = 0;
    while (held < cancels_max) : (held += 1) {
        try share.admit(.cancel, constants.io_operations_in_flight_max - held);
        share.taken(.cancel);
    }
    try testing.expectEqual(cancels_max, share.cancels_in_flight);
    try testing.expectEqual(@as(u32, 0), share.others_in_flight);
    const free = constants.io_operations_in_flight_max - held;
    try testing.expectError(error.CancelsFull, share.admit(.cancel, free));
    // The other kinds are let in beside a full cancels' share.
    try share.admit(.send, free);
    try share.admit(.receive, free);
    try share.admit(.accept, free);
    // A full share of the others refuses them, but not a cancel while its own has room.
    share.released(.cancel);
    const others: SlotShare = .{ .others_in_flight = SlotShare.others_max };
    const others_free = constants.io_operations_in_flight_max - SlotShare.others_max;
    try testing.expectError(error.SlotsKeptForAccepts, others.admit(.receive, others_free));
    try testing.expectError(error.SlotsKeptForAccepts, others.admit(.send, others_free));
    try others.admit(.cancel, others_free);
    try testing.expectEqual(cancels_max - 1, share.cancels_in_flight);
    try testing.expectEqual(cancels_max - 1, share.total());
}

test "io: operationPeer names the peer of exactly the kinds a connection counts" {
    const buffer: []u8 = &.{};
    try testing.expectEqual(@as(?PeerId, 7), operationPeer(.{ .send = .{ .peer = 7, .bytes = "x" } }));
    try testing.expectEqual(@as(?PeerId, 8), operationPeer(.{ .receive = .{ .peer = 8, .buffer = buffer } }));
    try testing.expectEqual(@as(?PeerId, 9), operationPeer(.{ .cancel = .{ .peer = 9 } }));
    try testing.expectEqual(@as(?PeerId, null), operationPeer(.{ .accept = .{ .listener = 3 } }));
    try testing.expectEqual(@as(?PeerId, null), operationPeer(.{ .execute = .{ .statement = "select 1" } }));
}
