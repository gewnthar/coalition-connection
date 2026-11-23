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
//!
//! Operation lifetime: the bytes an operation names belong to the caller and must stay valid
//! and unchanged until its completion arrives, as with io_uring; the simulator checks this.
//! Each accepted operation completes exactly once, carrying the `id` the caller gave it, and
//! ids in flight must be distinct; the simulator and the real type both check this. A
//! submission refused with any `SubmitError` never completes.
//! Every operation but an accept (a send or a statement today) shares at most
//! `constants.io_non_accepts_in_flight_max` operations; the rest are kept for accepts, so
//! clients that stop reading, or any other kind piling up, can't keep the server from
//! accepting. Anything but an accept past that share is refused with
//! `error.SlotsKeptForAccepts`, even with operations free, and an accept may still take
//! any free operation; the simulator and the real type both check this through
//! `SlotShare`. `poll` takes a buffer of 1 to
//! `constants.io_operations_in_flight_max` completions. A send may complete short,
//! reporting fewer bytes than it was given; the caller sends the rest. A send's peer stays
//! in the connection table, with its socket open, until the send's completion arrives. The
//! real type enforces this: it counts each send on its peer's entry, and the table refuses
//! to release an entry with sends counted (`error.SendsInFlight`).
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
//! Placeholders: `execute` stands in for database traffic until roadmap core 11 frames
//! Postgres over sockets, and the contract has no cancel yet; core 3b adds socket reads and
//! cancellation. Components should not build on `execute`.
//!
//! Random bytes: the operating system's CSPRNG in production, the seeded PRNG in the
//! simulator, so token nonces never break replay. The simulator refuses to compile into a
//! program that doesn't declare itself a simulation (see `sim.zig`).
//!
//! Inputs: submissions from components; buffers to fill.
//! Outputs: time readings, completions with explicit errors, random bytes.
//! Limits: at most `constants.io_operations_in_flight_max` operations in flight; messages of
//! at most `constants.http_response_size_max` bytes; statements of at most
//! `constants.postgres_message_size_max` bytes; at most `constants.io_random_bytes_max`
//! random bytes per call.
//!
//! `now` takes `*IO`, not `*const IO`, so an I/O type can keep its last reading and check
//! every new one against it.
//!
//! Status: the contract, the simulator, and the real type for Linux (`real.zig`), which
//! meets the contract with an io_uring ring for sends and accepts. `listener.zig` opens
//! the one socket accepts are taken on: a Unix socket at the config's path, never a network
//! address. The contract grows (receive, cancel, connect, timers) slice by slice.

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
/// anything but an accept, with operations other than accepts already holding their whole
/// share (`constants.io_non_accepts_in_flight_max`); the operations left are kept for
/// accepts. Either way, submit again after a completion.
/// `AcceptTooSoon`: an accept, less than `constants.io_accept_backpressure_wait_ns` after
/// the latest accept that completed with `error.Backpressure`; submit it again once that
/// time has passed. A full queue wins when it and `AcceptTooSoon` both hold.
pub const SubmitError = error{ QueueFull, SlotsKeptForAccepts, AcceptTooSoon };
pub const SendError = error{ PeerDown, Backpressure };
pub const DatabaseError = error{ Unavailable, Timeout };

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

/// The operations kept for accepts, counted by every I/O type that meets the contract
/// through the same calls, as with `AcceptWait`, so a check only one side makes can't let a
/// bug pass every simulation. Every operation but an accept counts against one share of
/// `constants.io_non_accepts_in_flight_max`; an accept counts against nothing here and may
/// take any free operation. The I/O type checks its own full queue first.
pub const SlotShare = struct {
    /// Operations in flight that aren't accepts: never more than `others_max`.
    others_in_flight: u32 = 0,

    pub const others_max: u32 = constants.io_non_accepts_in_flight_max;

    /// Refuses `kind` with `error.SlotsKeptForAccepts` when it isn't an accept and the
    /// others already hold their whole share. Changes nothing. `free` is the operations the
    /// I/O type has free, after its own full-queue check, so never 0.
    pub fn admit(self: *const SlotShare, kind: Kind, free: u32) error{SlotsKeptForAccepts}!void {
        // The full queue is checked first, as the contract orders the refusals.
        assert(free > 0);
        // Every operation counted here holds one that isn't free.
        assert(self.others_in_flight + free <= constants.io_operations_in_flight_max);
        if (kind == .accept) return;
        if (self.others_in_flight == others_max) return error.SlotsKeptForAccepts;
    }

    /// Counts an operation of `kind` that `admit` let in and that now holds a slot.
    pub fn taken(self: *SlotShare, kind: Kind) void {
        assert(self.others_in_flight <= others_max);
        if (kind == .accept) return;
        // `admit` refused it otherwise.
        assert(self.others_in_flight < others_max);
        self.others_in_flight += 1;
    }

    /// Uncounts an operation of `kind` that has completed and given its slot back.
    pub fn released(self: *SlotShare, kind: Kind) void {
        assert(self.others_in_flight <= others_max);
        if (kind == .accept) return;
        // Counted by `taken` at submit.
        assert(self.others_in_flight > 0);
        self.others_in_flight -= 1;
    }
};

/// The operating system could not supply random bytes. Production callers refuse the
/// operation that needed them; they never fall back to a weaker source.
pub const RandomError = error{RandomUnavailable};

pub const Kind = enum(u8) { send, execute, accept };

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

pub const Operation = union(Kind) {
    send: Send,
    execute: Execute,
    accept: Accept,
};

pub const Submission = struct {
    id: OperationId,
    operation: Operation,
};

/// The outcome of one operation. A send reports the bytes it sent; an accept, the new
/// connection's entry in the connection table.
pub const Result = union(Kind) {
    send: SendError!u32,
    execute: DatabaseError!void,
    accept: AcceptError!PeerId,
};

pub const Completion = struct {
    id: OperationId,
    result: Result,
};

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
const Method = enum { now, submit, poll, random_bytes };
const methods_count: u32 = 4;

/// The name each method has in the contract.
fn methodName(comptime method: Method) []const u8 {
    const name = switch (method) {
        .now => "now",
        .submit => "submit",
        .poll => "poll",
        .random_bytes => "randomBytes",
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
    };
    try expectMessage(PrivateNow, messageMissing(PrivateNow, .now));
    try expectMessage(PrivateSubmit, messageMissing(PrivateSubmit, .submit));
    try expectMessage(PrivatePoll, messageMissing(PrivatePoll, .poll));
    try expectMessage(PrivateRandom, messageMissing(PrivateRandom, .random_bytes));
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
    const Empty = struct {};
    comptime assert(std.enums.values(Method).len == methods_count);
    try expectMessage(Empty, messageMissing(Empty, .now));
    try expectMessage(NowWrongRestMissing, messageWrong(NowWrongRestMissing, .now));
    try expectMessage(SubmitWrongRestMissing, messageWrong(SubmitWrongRestMissing, .submit));
    try expectMessage(PollWrongRandomMissing, messageWrong(PollWrongRandomMissing, .poll));
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
