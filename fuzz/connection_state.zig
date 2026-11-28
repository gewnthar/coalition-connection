//! Fuzz target for the connection state machine (`cc.live.connection_state`).
//!
//! Each run walks many connections, one after another, from free back to free. Every step
//! the generator picks an event the machine documents for that point (see `Event`), drawn
//! from a small model of the books a server loop keeps for the connection: which receive
//! or send is in flight (at most one: a connection is half-duplex), whether a cancel is in
//! flight beside it (a cancel completes on its own, with no event for the machine), which
//! submission was refused for now, whether a response buffer is held, how many responses
//! went out, how many drops landed, and which deadline is running. It checks the machine
//! three ways:
//!
//!   - `step` and `transition` give exactly the transition `expect` predicts. `expect` is a
//!     second copy of the file header's table, written by event rather than by state;
//!   - the action, applied to the model's books, keeps them sound: a receive or send is only
//!     submitted with nothing in flight, a buffer is only taken when none is held and only
//!     returned when one is, next_request only follows a response that keeps the connection
//!     open, a resubmit always has a refused submission to send again, a cancel always has
//!     something to cancel, and release finds nothing in flight, nothing refused and no
//!     buffer held. These checks read only the machine's answer, never `expect`'s, so a
//!     mistake shared by the two copies of the table still has to keep the books balanced;
//!   - the machine's own rules: free is left only for idle, closing only for free and only
//!     by drained, every deadline drops into closing, every receive that ended closes, a
//!     refused request is answered with its refusal, a connection kept open only ever closes
//!     at `http_requests_per_connection_max` responses, and the deadline running after each
//!     step is the one the new state runs under.
//!
//! Before the walks, every state is paired with every sample event and every refusal
//! status: `step` must give null exactly where `expect` does, and `moves` must say yes
//! exactly for the pairs of states some listed event joins.
//!
//! What the books assume a loop does, beyond the machine: a refused receive or send is
//! abandoned when its connection is dropped into closing, and a buffer held for a refused
//! send is returned then; a refusal's response always closes; a drop counts towards running
//! out only while something is in flight; drop_exhausted comes only with something in
//! flight and no cancel going or due; a refused cancel is given up once its operation comes
//! back. These are the model's, so the request-limit and buffer-on-drop checks test the
//! model and the machine together, not the machine alone.
//!
//! The run fails with `error.LimitMissed` unless every listed pair of state and sample
//! event, every state, every action and every deadline came up, as did a connection served
//! to the request limit, a refusal answered and closed, a refused submission sent again, a
//! refused cancel, a cancel completing after its operation, and a buffer returned on a
//! drop. Every loop is bounded; a failing seed replays exactly.

const std = @import("std");
const assert = std.debug.assert;
const cc = @import("coalition_connection");

const machine = cc.live.connection_state;
const State = machine.State;
const Event = machine.Event;
const Received = machine.Received;
const Action = machine.Action;
const ActionTag = std.meta.Tag(Action);
const Deadline = machine.Deadline;
const Transition = machine.Transition;
const After = machine.After;
const Status = cc.live.http_response.Status;

pub const Error = error{ Mismatch, LimitMissed };

const requests_max: u32 = cc.constants.http_requests_per_connection_max;
const drops_max: u32 = cc.constants.io_drop_attempts_max;
/// Steps over the whole run, across every connection.
const steps_total_max: u32 = 2 * cc.constants.fuzz_iterations_max;
/// Steps one connection may take: enough for a long connection to reach the request
/// limit (about five steps a request) and then close.
const steps_per_connection_max: u32 = 8 * requests_max + 64;
/// Every this many connections, one runs with no failures or refusals until the limit.
const long_every: u32 = 64;
/// One submission in this many is refused for now.
const refused_one_in: u32 = 8;

const state_count: u32 = machine.states_all.len;
const sample_count: u32 = machine.events_sample.len;
const action_count: u32 = @typeInfo(ActionTag).@"enum".field_names.len;
const deadline_count: u32 = @typeInfo(Deadline).@"enum".field_names.len;

/// Every status the parser answers a refused request with.
const refusals = [_]Status{
    .bad_request,
    .content_too_large,
    .request_header_fields_too_large,
    .not_implemented,
    .http_version_not_supported,
};
const refusal_count: u32 = refusals.len;

/// A receive or send the loop has submitted, or a cancel.
const Op = enum(u8) { none, receive, send, cancel };

/// The loop's books for one connection.
const Conn = struct {
    state: State = .free,
    /// The receive or send in flight; half-duplex, so at most one.
    in_flight: Op = .none,
    /// A cancel is in flight; it completes on its own step.
    cancel_in_flight: bool = false,
    /// A submission refused for now; a retry sends it again.
    refused: Op = .none,
    buffer_held: bool = false,
    /// What the loop chose for the response going out: a refusal always closes.
    response_after: After = .close,
    /// The response going out answers a refused request.
    refusing: bool = false,
    responses: u32 = 0,
    /// Drops that landed while something was in flight, up to `drops_max`.
    drops: u32 = 0,
    /// The deadline running: clear, idle, read or write (never keep).
    running: Deadline = .clear,
    /// Runs with no failures or refusals until the request limit.
    long: bool,
};

const Counts = struct {
    /// `pairs[state][sample]`: steps that met this pair.
    pairs: [state_count][sample_count]u32 = @splat(@splat(0)),
    states: [state_count]u32 = @splat(0),
    actions: [action_count]u32 = @splat(0),
    deadlines: [deadline_count]u32 = @splat(0),
    steps: u32 = 0,
    connections: u32 = 0,
    released: u32 = 0,
    at_limit: u32 = 0,
    refusals_closed: u32 = 0,
    refused: u32 = 0,
    refused_cancels: u32 = 0,
    cancels_completed: u32 = 0,
    buffers_on_drop: u32 = 0,
    unlisted_checked: u32 = 0,
};

// One-line helpers, too small for assertions of their own.
fn t(to: State, action: Action, deadline: Deadline) Transition {
    return .{ .to = to, .action = action, .deadline = deadline };
}

fn reading(state: State) bool {
    return state == .idle or state == .reading_head or state == .reading_body;
}

fn sameTransition(a: ?Transition, b: ?Transition) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.meta.eql(a.?, b.?);
}

/// The model's transition for `event` in `from`, or null for a pair the machine doesn't
/// list. A second copy of the file header's table, organised by event.
fn expect(from: State, event: Event) ?Transition {
    const closing = from == .closing;
    const writing = from == .writing;
    const result: ?Transition = switch (event) {
        .accepted => if (from == .free) t(.idle, .receive, .idle) else null,
        .received => |received| if (reading(from)) expectReceived(from, received) else if (closing) t(.closing, .none, .keep) else null,
        .receive_ended => if (reading(from)) t(.closing, .none, .write) else if (closing) t(.closing, .none, .keep) else null,
        .sent_part => if (writing) t(.writing, .send_rest, .keep) else if (closing) t(.closing, .return_buffer, .keep) else null,
        .sent_all => |after| if (writing) switch (after) {
            .keep_open => t(.idle, .next_request, .idle),
            .close => t(.closing, .return_buffer, .write),
        } else if (closing) t(.closing, .return_buffer, .keep) else null,
        .send_failed => if (writing) t(.closing, .return_buffer, .write) else if (closing) t(.closing, .return_buffer, .keep) else null,
        .retry => if (from == .free) null else t(from, .resubmit, .keep),
        .deadline => if (from == .free) null else t(.closing, .drop, .write),
        .drop_exhausted => if (closing) t(.closing, .cancel, .keep) else null,
        .drained => if (closing) t(.free, .release, .clear) else null,
    };
    // Only an accept leaves free, and only drained reaches it.
    assert(result == null or (from == .free) == (event == .accepted));
    assert(result == null or (result.?.to == .free) == (event == .drained));
    return result;
}

fn expectReceived(from: State, received: Received) ?Transition {
    assert(reading(from));
    // The first bytes start the read deadline; later ones keep it.
    const deadline: Deadline = if (from == .idle) .read else .keep;
    const body = from == .reading_body;
    const result: ?Transition = switch (received) {
        .head_short => if (body) null else t(.reading_head, .receive, deadline),
        .body_short => t(.reading_body, .receive, deadline),
        .complete => |after| t(.writing, .{ .respond = after }, .write),
        .invalid => |status| if (body) null else t(.writing, .{ .send_refusal = status }, .write),
    };
    // A body is never refused and never goes back to a short head.
    assert(!body or result == null or result.?.to != .reading_head);
    assert(!body or result == null or result.?.action != .send_refusal);
    return result;
}

/// The deadline a state runs under.
fn deadlineFor(state: State) Deadline {
    const result: Deadline = switch (state) {
        .free => .clear,
        .idle => .idle,
        .reading_head, .reading_body => .read,
        .writing, .closing => .write,
    };
    assert(result != .keep);
    assert((result == .read) == (state == .reading_head or state == .reading_body));
    return result;
}

/// Whether two events have the same tag and payload shape, a refusal's status aside.
fn sameShape(a: Event, b: Event) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    const result = switch (a) {
        .received => |received| switch (received) {
            .head_short => b.received == .head_short,
            .body_short => b.received == .body_short,
            .complete => |after| b.received == .complete and b.received.complete == after,
            .invalid => b.received == .invalid,
        },
        .sent_all => |after| after == b.sent_all,
        .accepted, .receive_ended, .sent_part, .send_failed, .retry, .deadline, .drop_exhausted, .drained => true,
    };
    // Shapes differ only through a payload.
    assert(result or a == .received or a == .sent_all);
    return result;
}

/// The index in `events_sample` of the sample shaped like `event`.
fn sampleIndex(event: Event) u32 {
    var found: ?u32 = null;
    var index: u32 = 0;
    while (index < sample_count) : (index += 1) {
        if (sameShape(machine.events_sample[index], event)) {
            assert(found == null); // Two samples of one shape.
            found = index;
        }
    }
    assert(found != null); // Every shape has a sample.
    return found.?;
}

/// `step` must agree with `expect` on one pair, listed or not.
fn checkPair(from: State, event: Event, counts: *Counts) Error!void {
    const unlisted_before = counts.unlisted_checked;
    const got = machine.step(from, event);
    const want = expect(from, event);
    if (!sameTransition(got, want)) {
        std.debug.print("fuzz connection_state: {t} with {any}: step gave {any}, model {any}\n", .{ from, event, got, want });
        return error.Mismatch;
    }
    if (want == null) counts.unlisted_checked += 1;
    assert(got == null or got.?.to == from or got.?.to != .free or from == .closing);
    assert(counts.unlisted_checked - unlisted_before == @intFromBool(got == null));
}

/// Every state with every sample event and every refusal status; and `moves` against the
/// pairs of states the listed events join.
fn checkAllPairs(counts: *Counts) Error!void {
    var joined: [state_count][state_count]bool = @splat(@splat(false));
    for (machine.states_all) |from| {
        for (machine.events_sample) |event| {
            try checkPair(from, event, counts);
            if (expect(from, event)) |listed| joined[@backingInt(from)][@backingInt(listed.to)] = true;
        }
        var index: u32 = 0;
        while (index < refusal_count) : (index += 1) {
            try checkPair(from, .{ .received = .{ .invalid = refusals[index] } }, counts);
        }
    }
    var moves_checked: u32 = 0;
    for (machine.states_all) |from| {
        for (machine.states_all) |to| {
            if (machine.moves(from, to) != joined[@backingInt(from)][@backingInt(to)]) {
                std.debug.print("fuzz connection_state: moves({t}, {t}) disagrees with the listed pairs\n", .{ from, to });
                return error.Mismatch;
            }
            moves_checked += 1;
        }
    }
    assert(moves_checked == state_count * state_count);
    assert(counts.unlisted_checked > 0);
}

/// The After the loop chooses for a complete request: close at the request limit, keep
/// open on a long connection, otherwise as the request asks.
fn chooseAfter(random: std.Random, conn: *const Conn) After {
    assert(conn.responses < requests_max);
    assert(conn.state != .free and conn.state != .writing and conn.state != .closing);
    if (conn.responses + 1 == requests_max or (!conn.long and random.uintLessThan(u32, 4) == 0)) return .close;
    return .keep_open;
}

const candidates_max: u32 = 16;

const Candidates = struct {
    events: [candidates_max]Event = undefined,
    len: u32 = 0,

    fn add(self: *Candidates, event: Event, weight: u32) void {
        assert(weight > 0);
        assert(self.len + weight <= candidates_max);
        var added: u32 = 0;
        while (added < weight) : (added += 1) {
            self.events[self.len] = event;
            self.len += 1;
        }
    }
};

fn anyRefusal(random: std.Random) Status {
    return refusals[random.uintLessThan(u32, refusal_count)];
}

/// A random received payload of any shape, for a receive coming back in closing.
fn anyReceived(random: std.Random) Received {
    return switch (random.uintLessThan(u32, 5)) {
        0 => .head_short,
        1 => .body_short,
        2 => .{ .complete = .keep_open },
        3 => .{ .complete = .close },
        else => .{ .invalid = anyRefusal(random) },
    };
}

/// Events for a reading state: the receive in flight comes back, or the refused one goes again.
fn readingCandidates(random: std.Random, conn: *const Conn, list: *Candidates) void {
    assert(reading(conn.state));
    assert(conn.in_flight == .receive or conn.refused == .receive);
    if (!conn.long) list.add(.deadline, 1);
    if (conn.refused == .receive) return list.add(.retry, 3);
    if (conn.state != .reading_body) list.add(.{ .received = .head_short }, 2);
    list.add(.{ .received = .body_short }, 2);
    list.add(.{ .received = .{ .complete = chooseAfter(random, conn) } }, 2);
    if (conn.long) return;
    if (conn.state != .reading_body) list.add(.{ .received = .{ .invalid = anyRefusal(random) } }, 1);
    list.add(.receive_ended, 1);
}

/// Events for writing: the send in flight comes back, or the refused one goes again.
fn writingCandidates(conn: *const Conn, list: *Candidates) void {
    assert(conn.state == .writing);
    assert(conn.buffer_held and (conn.in_flight == .send or conn.refused == .send));
    if (!conn.long) list.add(.deadline, 1);
    if (conn.refused == .send) return list.add(.retry, 3);
    list.add(.sent_part, 1);
    list.add(.{ .sent_all = conn.response_after }, 2);
    if (!conn.long) list.add(.send_failed, 1);
}

/// Events for closing: what is in flight comes back, drops pace on, a refused cancel goes
/// again, drops run out, or nothing is left and the connection drains.
fn closingCandidates(random: std.Random, conn: *const Conn, list: *Candidates) void {
    assert(conn.state == .closing);
    assert(conn.refused == .none or conn.refused == .cancel);
    // Deadlines weigh more while something is in flight, so drops run out often enough.
    list.add(.deadline, if (conn.in_flight == .none) 1 else 3);
    switch (conn.in_flight) {
        .receive => {
            list.add(.{ .received = anyReceived(random) }, 1);
            list.add(.receive_ended, 1);
        },
        .send => {
            list.add(.sent_part, 1);
            list.add(.{ .sent_all = if (random.boolean()) .keep_open else .close }, 1);
            list.add(.send_failed, 1);
        },
        .none, .cancel => {},
    }
    const outstanding = conn.in_flight != .none or conn.cancel_in_flight or conn.refused != .none;
    if (conn.in_flight != .none and !conn.cancel_in_flight and conn.refused == .none and conn.drops == drops_max) {
        list.add(.drop_exhausted, 2);
    }
    if (conn.refused == .cancel) list.add(.retry, 2);
    if (!outstanding) list.add(.drained, 4);
}

/// An event the machine documents for now, for this connection's books.
fn pickEvent(random: std.Random, conn: *const Conn) Event {
    var list: Candidates = .{};
    switch (conn.state) {
        .free => list.add(.accepted, 1),
        .idle, .reading_head, .reading_body => readingCandidates(random, conn, &list),
        .writing => writingCandidates(conn, &list),
        .closing => closingCandidates(random, conn, &list),
    }
    assert(list.len > 0 and list.len <= candidates_max);
    const event = list.events[random.uintLessThan(u32, list.len)];
    // Each state's candidates are only ever events the model lists for it.
    assert(expect(conn.state, event) != null);
    return event;
}

fn mismatch(conn: *const Conn, event: Event, got: Transition, what: []const u8) Error {
    std.debug.print("fuzz connection_state: {t} with {any} gave {any}: {s}\n", .{ conn.state, event, got, what });
    return error.Mismatch;
}

/// A completion takes its receive or send off the books; a cancel refused for it is given
/// up, while a cancel already in flight still has its own completion to come.
fn applyEvent(conn: *Conn, event: Event) void {
    switch (event) {
        .received, .receive_ended => assert(conn.in_flight == .receive),
        .sent_part, .sent_all, .send_failed => assert(conn.in_flight == .send),
        .accepted => assert(conn.in_flight == .none and !conn.buffer_held and conn.responses == 0),
        .retry, .deadline, .drop_exhausted, .drained => return,
    }
    if (event == .accepted) return;
    conn.in_flight = .none;
    if (conn.refused == .cancel) conn.refused = .none;
    assert(conn.refused == .none);
}

/// The loop submits `op`; one in `refused_one_in` is refused for now.
fn submit(random: std.Random, conn: *Conn, op: Op, counts: *Counts) void {
    assert(op != .none);
    assert(conn.refused == .none);
    // Half-duplex: a receive or send goes only with nothing else in flight.
    assert(op == .cancel or conn.in_flight == .none);
    if (!conn.long and random.uintLessThan(u32, refused_one_in) == 0) {
        conn.refused = op;
        counts.refused += 1;
        if (op == .cancel) counts.refused_cancels += 1;
        return;
    }
    if (op == .cancel) conn.cancel_in_flight = true else conn.in_flight = op;
}

/// Takes a response buffer and submits its first send.
fn takeBuffer(random: std.Random, conn: *Conn, event: Event, got: Transition, after: After, counts: *Counts) Error!void {
    assert(got.action == .respond or got.action == .send_refusal);
    assert(after == .close or got.action == .respond);
    if (got.to != .writing) return mismatch(conn, event, got, "a response outside writing");
    if (conn.buffer_held) return mismatch(conn, event, got, "a buffer taken while one is held");
    if (conn.in_flight != .none or conn.refused != .none) return mismatch(conn, event, got, "a send beside another operation");
    conn.buffer_held = true;
    conn.response_after = after;
    conn.refusing = got.action == .send_refusal;
    submit(random, conn, .send, counts);
}

/// Applies a respond: one response more, and the last allowed one closes.
fn applyRespond(random: std.Random, conn: *Conn, event: Event, got: Transition, after: After, counts: *Counts) Error!void {
    assert(got.action == .respond);
    const responses_before = conn.responses;
    if (conn.responses >= requests_max) return mismatch(conn, event, got, "a response past the request limit");
    conn.responses += 1;
    if (conn.responses == requests_max) {
        if (after != .close) return mismatch(conn, event, got, "the last allowed response keeps the connection open");
        counts.at_limit += 1;
    }
    try takeBuffer(random, conn, event, got, after, counts);
    assert(conn.responses == responses_before + 1);
}

/// Sends the refused submission again; in closing only a cancel is ever refused.
fn applyResubmit(random: std.Random, conn: *Conn, event: Event, got: Transition, counts: *Counts) Error!void {
    assert(got.action == .resubmit);
    assert(conn.refused == .none or conn.in_flight == .none or conn.refused == .cancel);
    const op = conn.refused;
    if (op == .none) return mismatch(conn, event, got, "a resubmit with nothing refused");
    if ((op == .cancel) != (got.to == .closing)) return mismatch(conn, event, got, "a resubmit of the wrong kind");
    conn.refused = .none;
    submit(random, conn, op, counts);
}

/// A drop: counted while something is in flight; a refused receive or send is abandoned,
/// and a buffer held for a refused send is returned.
fn applyDrop(conn: *Conn, event: Event, got: Transition, counts: *Counts) Error!void {
    assert(got.action == .drop);
    assert(conn.drops <= drops_max);
    if (got.to != .closing) return mismatch(conn, event, got, "a drop outside closing");
    if (conn.refused == .receive or conn.refused == .send) {
        if (conn.refused == .send) {
            if (!conn.buffer_held) return mismatch(conn, event, got, "a refused send with no buffer");
            conn.buffer_held = false;
            counts.buffers_on_drop += 1;
        }
        conn.refused = .none;
    }
    if (conn.in_flight != .none and conn.drops < drops_max) conn.drops += 1;
}

/// Release: nothing in flight, nothing refused, no buffer held; a connection that was
/// kept open throughout closes only at the request limit.
fn applyRelease(conn: *Conn, event: Event, got: Transition, counts: *Counts) Error!void {
    assert(got.action == .release);
    assert(conn.responses <= requests_max);
    if (conn.in_flight != .none or conn.cancel_in_flight) return mismatch(conn, event, got, "a release with an operation in flight");
    if (conn.refused != .none) return mismatch(conn, event, got, "a release with a submission refused");
    if (conn.buffer_held) return mismatch(conn, event, got, "a release with a response buffer held");
    if (conn.long and conn.responses != requests_max) return mismatch(conn, event, got, "a connection kept open closed before the request limit");
    counts.released += 1;
    conn.* = .{ .state = .free, .long = conn.long };
}

/// Applies the machine's action to the loop's books, checking each is sound.
fn applyAction(random: std.Random, conn: *Conn, event: Event, got: Transition, counts: *Counts) Error!void {
    // Only a refused cancel sits beside an operation in flight.
    assert(conn.refused == .none or conn.refused == .cancel or conn.in_flight == .none);
    switch (got.action) {
        .none => {},
        .receive => {
            if (conn.in_flight != .none or conn.refused != .none) return mismatch(conn, event, got, "a receive beside another operation");
            submit(random, conn, .receive, counts);
        },
        .respond => |after| try applyRespond(random, conn, event, got, after, counts),
        .send_refusal => try takeBuffer(random, conn, event, got, .close, counts),
        .resubmit => try applyResubmit(random, conn, event, got, counts),
        .send_rest => {
            if (!conn.buffer_held or conn.in_flight != .none or conn.refused != .none) return mismatch(conn, event, got, "the rest sent without its buffer, or beside another operation");
            submit(random, conn, .send, counts);
        },
        .next_request => {
            if (!conn.buffer_held or conn.response_after != .keep_open or conn.in_flight != .none or conn.refused != .none) return mismatch(conn, event, got, "a next request after a closing response");
            conn.buffer_held = false;
            submit(random, conn, .receive, counts);
        },
        .return_buffer => {
            if (!conn.buffer_held) return mismatch(conn, event, got, "a buffer returned with none held");
            if (conn.refusing and event == .sent_all and conn.state == .writing) counts.refusals_closed += 1;
            conn.buffer_held = false;
        },
        .drop => try applyDrop(conn, event, got, counts),
        .cancel => {
            if (conn.in_flight == .none or conn.cancel_in_flight) return mismatch(conn, event, got, "a cancel with nothing to cancel");
            submit(random, conn, .cancel, counts);
        },
        .release => try applyRelease(conn, event, got, counts),
    }
    assert(conn.in_flight != .cancel);
}

/// The machine's own rules, apart from its table: how free and closing are left and
/// entered, and what a deadline, an ended receive and a refused request lead to.
fn checkRules(conn: *const Conn, event: Event, got: Transition) Error!void {
    const from = conn.state;
    assert(from != .free or event == .accepted);
    assert(from != got.to or got.to != .free);
    if (from == .free and got.to != .idle) return mismatch(conn, event, got, "free left for anything but idle");
    if (from == .closing and got.to != .closing and got.to != .free) return mismatch(conn, event, got, "closing left for a live state");
    if ((got.to == .free) != (event == .drained)) return mismatch(conn, event, got, "free reached without drained");
    if (event == .deadline and (got.to != .closing or got.action != .drop)) return mismatch(conn, event, got, "a deadline that doesn't drop into closing");
    if (event == .receive_ended and got.to != .closing) return mismatch(conn, event, got, "an ended receive that stays open");
    const refused_request = event == .received and event.received == .invalid;
    if (refused_request and from != .closing and got.action != .send_refusal) return mismatch(conn, event, got, "a refused request not answered with its refusal");
}

/// The deadline running after the step must be the one the new state runs under; a kept
/// deadline must already be that one.
fn applyDeadline(conn: *Conn, event: Event, got: Transition) Error!void {
    assert(conn.running != .keep);
    assert(conn.running == deadlineFor(conn.state));
    const wanted = deadlineFor(got.to);
    const running = if (got.deadline == .keep) conn.running else got.deadline;
    if (running != wanted) return mismatch(conn, event, got, "the running deadline isn't the new state's");
    conn.running = running;
}

fn count(counts: *Counts, from: State, event: Event, got: Transition) void {
    assert(counts.steps < steps_total_max);
    const pair = &counts.pairs[@backingInt(from)][sampleIndex(event)];
    const before = pair.*;
    pair.* += 1;
    counts.states[@backingInt(got.to)] += 1;
    counts.actions[@backingInt(std.meta.activeTag(got.action))] += 1;
    counts.deadlines[@backingInt(got.deadline)] += 1;
    counts.steps += 1;
    assert(pair.* == before + 1);
}

/// One step: a cancel in flight may complete first; then pick an event, check the
/// machine's answer three ways, and apply it.
fn walkStep(random: std.Random, conn: *Conn, counts: *Counts) Error!void {
    const steps_before = counts.steps;
    assert(conn.state != .free or conn.in_flight == .none);
    if (conn.cancel_in_flight and conn.in_flight == .none and random.boolean()) {
        conn.cancel_in_flight = false;
        counts.cancels_completed += 1;
    }
    const event = pickEvent(random, conn);
    const from = conn.state;
    const want = expect(from, event);
    const got = machine.step(from, event) orelse return mismatch(conn, event, want.?, "step refused a pair the model lists");
    if (!sameTransition(got, want)) return mismatch(conn, event, got, "not the model's transition");
    if (!sameTransition(machine.transition(from, event), got)) return mismatch(conn, event, got, "transition and step disagree");
    try checkRules(conn, event, got);
    applyEvent(conn, event);
    try applyAction(random, conn, event, got, counts);
    try applyDeadline(conn, event, got);
    conn.state = got.to;
    count(counts, from, event, got);
    assert(counts.steps == steps_before + 1);
}

/// One connection, from free until it is free again or its steps run out.
fn walkConnection(random: std.Random, long: bool, counts: *Counts) Error!void {
    assert(counts.steps < steps_total_max);
    const steps_before = counts.steps;
    var conn: Conn = .{ .long = long };
    var steps: u32 = 0;
    while (steps < steps_per_connection_max and counts.steps < steps_total_max) : (steps += 1) {
        try walkStep(random, &conn, counts);
        if (conn.state == .free) break;
    }
    assert(steps <= steps_per_connection_max);
    assert(counts.steps > steps_before);
}

fn reachedAll(counts: *const Counts) bool {
    assert(counts.steps == steps_total_max);
    assert(counts.released <= counts.connections);
    for (machine.states_all, counts.pairs) |from, row| {
        for (machine.events_sample, row) |event, met| {
            if (expect(from, event) != null and met == 0) return false;
        }
    }
    for (counts.states) |met| if (met == 0) return false;
    for (counts.actions) |met| if (met == 0) return false;
    for (counts.deadlines) |met| if (met == 0) return false;
    return counts.at_limit > 0 and counts.refusals_closed > 0 and counts.refused > 0 and
        counts.refused_cancels > 0 and counts.cancels_completed > 0 and counts.buffers_on_drop > 0 and
        counts.released > 0;
}

fn report(counts: *const Counts, seed: u64) void {
    assert(counts.connections > 0);
    assert(counts.steps == steps_total_max);
    var pairs_min: u32 = std.math.maxInt(u32);
    for (machine.states_all, counts.pairs) |from, row| {
        for (machine.events_sample, row) |event, met| {
            if (expect(from, event) != null) pairs_min = @min(pairs_min, met);
        }
    }
    std.debug.print("fuzz connection_state: seed={d} steps={d} connections={d} released={d} at_limit={d} refusals_closed={d}\n", .{
        seed, counts.steps, counts.connections, counts.released, counts.at_limit, counts.refusals_closed,
    });
    std.debug.print("  states={any}\n  actions={any}\n  deadlines={any}\n", .{ counts.states, counts.actions, counts.deadlines });
    std.debug.print("  refused={d} refused_cancels={d} cancels_completed={d} buffers_on_drop={d} unlisted={d} fewest steps for one listed pair={d}\n", .{
        counts.refused, counts.refused_cancels, counts.cancels_completed, counts.buffers_on_drop, counts.unlisted_checked, pairs_min,
    });
}

pub fn run(seed: u64) Error!void {
    comptime assert(steps_per_connection_max > 5 * requests_max);
    comptime assert(drops_max > 0);
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var counts: Counts = .{};
    try checkAllPairs(&counts);
    // Every connection takes at least one step, so the steps bound the connections.
    while (counts.steps < steps_total_max) {
        const long = counts.connections % long_every == 0;
        walkConnection(random, long, &counts) catch |err| {
            std.debug.print("fuzz connection_state: seed={d} failed at connection {d}, step {d}\n", .{ seed, counts.connections, counts.steps });
            return err;
        };
        counts.connections += 1;
        assert(counts.connections <= counts.steps);
    }
    report(&counts, seed);
    if (!reachedAll(&counts)) {
        std.debug.print("fuzz connection_state: seed={d} missed a pair, state, action, deadline or limit\n", .{seed});
        return error.LimitMissed;
    }
    std.debug.print("fuzz connection_state: seed={d} steps={d} ok\n", .{ seed, counts.steps });
}
