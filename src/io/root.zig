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
//!   now(self: *const IO) Instant                        monotonic clock, nanoseconds
//!   submit(self: *IO, Submission) SubmitError!void      queue one operation
//!   poll(self: *IO, []Completion) u32                   take finished operations
//!   randomBytes(self: *IO, []u8) RandomError!void       fill a buffer with random bytes
//!
//! Operation lifetime: the bytes an operation names belong to the caller and must stay valid
//! and unchanged until its completion arrives, as with io_uring; the simulator checks this.
//! Each accepted operation completes exactly once, carrying the `id` the caller gave it, and
//! ids in flight must be distinct. A submission refused with `error.QueueFull` never
//! completes. `poll` takes a buffer of 1 to `constants.io_operations_in_flight_max`
//! completions. A send may complete short, reporting fewer bytes than it was given; the
//! caller sends the rest.
//!
//! Placeholders: `execute` stands in for database traffic until roadmap core 11 frames
//! Postgres over sockets, and the contract has no cancel yet; core 3 adds socket reads and
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
//! Status: contract and simulator only. The io_uring implementation arrives with roadmap
//! core 2 and core 3, and the contract grows (accept, receive, connect, timers) slice by
//! slice.

const std = @import("std");
const assert = std.debug.assert;

pub const sim = @import("sim.zig");

/// Nanoseconds on a monotonic clock. Never wall-clock time.
pub const Instant = u64;

/// Index of a connection in the startup-sized connection table.
pub const PeerId = u32;

/// Chosen by the caller and handed back with the completion, like io_uring's user_data.
pub const OperationId = u64;

pub const SubmitError = error{QueueFull};
pub const SendError = error{ PeerDown, Backpressure };
pub const DatabaseError = error{ Unavailable, Timeout };

/// The operating system could not supply random bytes. Production callers refuse the
/// operation that needed them; they never fall back to a weaker source.
pub const RandomError = error{RandomUnavailable};

pub const Kind = enum(u8) { send, execute };

/// One outgoing message to a peer.
pub const Send = struct {
    peer: PeerId,
    bytes: []const u8,
};

/// One database statement.
pub const Execute = struct {
    statement: []const u8,
};

pub const Operation = union(Kind) {
    send: Send,
    execute: Execute,
};

pub const Submission = struct {
    id: OperationId,
    operation: Operation,
};

/// The outcome of one operation. A send reports the bytes it sent.
pub const Result = union(Kind) {
    send: SendError!u32,
    execute: DatabaseError!void,
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
        methodError(IO, "now", fn (*const IO) Instant),
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
    pub fn now(self: *const MissingRandom) Instant {
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
    pub fn now(self: *const WrongPoll) Instant {
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
    try testing.expect(std.mem.indexOf(u8, message.?, "randomBytes") != null);
}

test "io: a stand-in with a wrong signature is refused" {
    const message = comptime contractError(WrongPoll);
    try testing.expect(message != null);
    try testing.expect(std.mem.indexOf(u8, message.?, "poll") != null);
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
        .now => fn (*const IO) Instant,
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
        pub fn now(self: *const Self) Instant {
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

/// `now` takes `*Self` where the contract takes `*const Self`.
const WrongNow = struct {
    pub fn now(self: *WrongNow) Instant {
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
        fn now(self: *const Self) Instant {
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
        pub fn now(self: *@This()) Instant {
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
}
