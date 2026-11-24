//! Connection state machine (roadmap core 3 and core 4).
//!
//! Job:
//!   Say, for one connection, which state an event moves it to, what the server loop must
//!   do about it, and which deadline the new state runs under. Pure: no I/O, no clock, no
//!   allocation and no state of its own, so every transition is a table entry a test can
//!   check, and the server loop and the simulator follow exactly the same rules.
//!
//! Inputs:
//!   The connection's current `State` and one `Event`: a completion, a parse result or a
//!   deadline, as the server loop turns them into events.
//!
//! Outputs:
//!   A `Transition`: the next `State`, the `Action` the loop carries out, and the
//!   `Deadline` it sets (or keeps) for the new state.
//!
//! Limits: none of its own. The loop owns the timeouts and the per-connection counters,
//! among them whether the response going out closes the connection: it passes that back
//! as the `After` of `sent_all`, the same as it chose for `respond` or `send_refusal`
//! (always `close` after a refusal), since the machine keeps no state to check it.
//!
//! A connection is half-duplex: it never has a receive and a send in flight at once, and
//! never two of either. HTTP/1.1 without pipelining needs no more.
//!
//!   free          the entry is unused; its index is on the table's free stack
//!   idle          waiting for a request's first byte (new or kept alive): one receive
//!   reading_head  bytes have arrived, but the head isn't complete: one receive
//!   reading_body  the head is parsed, the body isn't all in: one receive
//!   writing       the response is going out: one send
//!   closing       ending: dropped if anything was in flight, waiting for it to come back
//!
//! Transitions (state, event: next state, action, deadline):
//!
//!   free, accepted: idle, receive, idle
//!   idle, received head_short: reading_head, receive, read
//!   reading_head, received head_short: reading_head, receive, kept
//!   idle, received body_short: reading_body, receive, read
//!   reading_head or reading_body, received body_short: reading_body, receive, kept
//!   any reading state, received complete: writing, respond, write
//!   idle or reading_head, received invalid: writing, send the refusal, write
//!   any reading state, receive_ended: closing, none (drained follows), write
//!   any reading state or writing, retry: unchanged, resubmit, kept
//!   any reading state or writing, deadline: closing, drop, write
//!   writing, sent_part: writing, send the rest, kept
//!   writing, sent_all keep_open: idle, next request, idle
//!   writing, sent_all close or send_failed: closing, return the buffer, write
//!   closing, a receive's completion: closing, none (its bytes are ignored), kept
//!   closing, a send's completion: closing, return the buffer, kept
//!   closing, retry (a refused cancel): closing, resubmit, kept
//!   closing, deadline: closing, drop again, write
//!   closing, drop_exhausted: closing, cancel, kept
//!   closing, drained: free, release, cleared
//!
//! Every pair of state and event this file doesn't list is a bug in the caller, and
//! `transition` stops the process on it. `step` answers the same question with null
//! instead, for tests and for compile-time tables such as `moves`.

const std = @import("std");
const assert = std.debug.assert;
const http_response = @import("http_response.zig");

/// Where a connection is in its life. The table keeps one per entry.
pub const State = enum(u8) {
    free,
    idle,
    reading_head,
    reading_body,
    writing,
    closing,
};

/// Whether the connection stays open once the response is sent.
pub const After = enum(u8) {
    keep_open,
    close,
};

/// What the request buffer holds after a receive's bytes were appended to it.
pub const Received = union(enum) {
    /// No end of head yet, and the buffer isn't full.
    head_short,
    /// The head is parsed, and the body is still short.
    body_short,
    /// The whole request is in. `close` when the request asks for it (HTTP/1.0 or
    /// Connection: close), when bytes follow its end (no pipelining), or when it is the
    /// connection's last allowed request.
    complete: After,
    /// The parser refused the request; the status to answer it with.
    invalid: http_response.Status,
};

/// One thing that happened to a connection.
pub const Event = union(enum) {
    /// An accept's completion took this entry.
    accepted,
    /// A receive brought bytes.
    received: Received,
    /// A receive came back with 0 bytes (the peer closed) or PeerDown.
    receive_ended,
    /// A short send; the rest is still to go.
    sent_part,
    /// The response's last byte is sent.
    sent_all: After,
    /// A send came back PeerDown.
    send_failed,
    /// A receive, send or cancel was refused for now (Backpressure, QueueFull or
    /// SlotsKeptForAccepts).
    retry,
    /// The state's deadline passed.
    deadline,
    /// A drop returned DropsExhausted.
    drop_exhausted,
    /// In closing, nothing is in flight any more.
    drained,
};

/// What the server loop does after a transition.
pub const Action = union(enum) {
    /// Nothing to submit.
    none,
    /// Submit a receive into the request buffer.
    receive,
    /// Take a response buffer, route the request, write the response and send it; close
    /// after it when asked.
    respond: After,
    /// Send this status's static response, then close.
    send_refusal: http_response.Status,
    /// Submit the refused receive, send or cancel again on the next tick.
    resubmit,
    /// Send the rest of a response a short send left.
    send_rest,
    /// Return the response buffer, reset the request (bytes received, the request's end and
    /// the HeadScan to empty; requests served up by one), and receive the next request.
    next_request,
    /// Return the response buffer to the pool.
    return_buffer,
    /// Drop the connection, so its receive or send comes back.
    drop,
    /// Cancel every operation in flight on the connection.
    cancel,
    /// Release the entry and close the socket.
    release,
};

/// The deadline the loop sets when a transition lands.
pub const Deadline = enum(u8) {
    /// Leave the deadline as it is.
    keep,
    /// No deadline: the entry is free.
    clear,
    /// The idle timeout, from now.
    idle,
    /// The read timeout, from now; it carries on through the body.
    read,
    /// The write timeout, from now; also paces drop retries while closing.
    write,
};

pub const Transition = struct {
    to: State,
    action: Action,
    deadline: Deadline,
};

/// The next state, action and deadline for `event` in `from`. A pair this machine doesn't
/// list is a bug in the caller, so it stops the process.
pub fn transition(from: State, event: Event) Transition {
    const result = step(from, event) orelse std.debug.panic(
        "connection state {t}: event {t} not allowed",
        .{ from, std.meta.activeTag(event) },
    );
    // Only an accept takes a free entry, and only release gives one back.
    assert((from == .free) == (event == .accepted));
    assert((result.to == .free) == (event == .drained));
    return result;
}

/// The same as `transition`, but null for a pair the machine doesn't list.
pub fn step(from: State, event: Event) ?Transition {
    assert(eventValid(event));
    const result: ?Transition = switch (from) {
        .free => fromFree(from, event),
        .idle, .reading_head, .reading_body => fromReading(from, event),
        .writing => fromWriting(from, event),
        .closing => fromClosing(from, event),
    };
    if (result) |listed| {
        assert(fits(listed));
        assert(consistent(from, listed));
    }
    return result;
}

/// Whether some event moves a connection from `from` to `to`. For callers that set a state
/// directly, such as the connection table's `setState`.
pub fn moves(from: State, to: State) bool {
    const row = move_table[@backingInt(from)];
    const allowed = row[@backingInt(to)];
    // Every state but free can leave through closing, so no row is empty but free's
    // way into idle.
    assert(row[@backingInt(State.closing)] or from == .free);
    assert(!allowed or to != .free or from == .closing);
    return allowed;
}

fn fromFree(from: State, event: Event) ?Transition {
    assert(from == .free);
    assert(eventValid(event));
    return switch (event) {
        .accepted => .{ .to = .idle, .action = .receive, .deadline = .idle },
        .received,
        .receive_ended,
        .sent_part,
        .sent_all,
        .send_failed,
        .retry,
        .deadline,
        .drop_exhausted,
        .drained,
        => null,
    };
}

/// The three reading states share their exits: a receive is in flight in each.
fn fromReading(from: State, event: Event) ?Transition {
    assert(from == .idle or from == .reading_head or from == .reading_body);
    assert(eventValid(event));
    return switch (event) {
        .received => |received| fromReceived(from, received),
        .receive_ended => .{ .to = .closing, .action = .none, .deadline = .write },
        .retry => .{ .to = from, .action = .resubmit, .deadline = .keep },
        .deadline => .{ .to = .closing, .action = .drop, .deadline = .write },
        .accepted, .sent_part, .sent_all, .send_failed, .drop_exhausted, .drained => null,
    };
}

fn fromReceived(from: State, received: Received) ?Transition {
    assert(from == .idle or from == .reading_head or from == .reading_body);
    assert(eventValid(.{ .received = received }));
    const reading_body = from == .reading_body;
    return switch (received) {
        // A parsed head never comes back to a short head.
        .head_short => if (reading_body) null else .{
            .to = .reading_head,
            .action = .receive,
            // The first bytes start the read deadline.
            .deadline = if (from == .idle) .read else .keep,
        },
        .body_short => .{
            .to = .reading_body,
            .action = .receive,
            // A whole head in the first receive starts the read deadline here.
            .deadline = if (from == .idle) .read else .keep,
        },
        .complete => |after| .{ .to = .writing, .action = .{ .respond = after }, .deadline = .write },
        // The body's framing is settled with the head, so only a head can be refused.
        .invalid => |status| if (reading_body) null else .{
            .to = .writing,
            .action = .{ .send_refusal = status },
            .deadline = .write,
        },
    };
}

fn fromWriting(from: State, event: Event) ?Transition {
    assert(from == .writing);
    assert(eventValid(event));
    return switch (event) {
        .sent_part => .{ .to = .writing, .action = .send_rest, .deadline = .keep },
        .sent_all => |after| switch (after) {
            .keep_open => .{ .to = .idle, .action = .next_request, .deadline = .idle },
            .close => .{ .to = .closing, .action = .return_buffer, .deadline = .write },
        },
        .send_failed => .{ .to = .closing, .action = .return_buffer, .deadline = .write },
        .retry => .{ .to = .writing, .action = .resubmit, .deadline = .keep },
        .deadline => .{ .to = .closing, .action = .drop, .deadline = .write },
        .accepted, .received, .receive_ended, .drop_exhausted, .drained => null,
    };
}

/// In closing nothing new goes in but a drop or a cancel, and every completion that comes
/// back only brings the count in flight down.
fn fromClosing(from: State, event: Event) ?Transition {
    assert(from == .closing);
    assert(eventValid(event));
    return switch (event) {
        // A receive's bytes are ignored; a send's buffer goes back to the pool.
        .received, .receive_ended => .{ .to = .closing, .action = .none, .deadline = .keep },
        .sent_part, .sent_all, .send_failed => .{ .to = .closing, .action = .return_buffer, .deadline = .keep },
        // Only a cancel is submitted while closing, so a refusal here is the cancel's,
        // which goes again on the next tick.
        .retry => .{ .to = .closing, .action = .resubmit, .deadline = .keep },
        .deadline => .{ .to = .closing, .action = .drop, .deadline = .write },
        .drop_exhausted => .{ .to = .closing, .action = .cancel, .deadline = .keep },
        .drained => .{ .to = .free, .action = .release, .deadline = .clear },
        .accepted => null,
    };
}

/// Whether a transition's action and deadline fit the state it lands in: a receive only
/// into a reading state, a send only into writing, a drop or cancel only into closing, a
/// release only into free, and a fresh deadline only where the state table sets one.
fn fits(result: Transition) bool {
    const to = result.to;
    const reading = to == .idle or to == .reading_head or to == .reading_body;
    const action_fits = switch (result.action) {
        .receive => reading,
        .next_request => to == .idle,
        .respond, .send_refusal, .send_rest => to == .writing,
        .drop, .cancel, .return_buffer => to == .closing,
        .release => to == .free,
        .none, .resubmit => to != .free,
    };
    const deadline_fits = switch (result.deadline) {
        .keep => to != .free,
        .clear => to == .free,
        .idle => to == .idle,
        .read => to == .reading_head or to == .reading_body,
        .write => to == .writing or to == .closing,
    };
    const result_fits = action_fits and deadline_fits;
    // A fitting transition frees an entry exactly when it releases it and clears its
    // deadline: only one arm of each switch admits free.
    assert(!result_fits or ((to == .free) == (result.action == .release)));
    assert(!result_fits or ((to == .free) == (result.deadline == .clear)));
    return result_fits;
}

/// Whether a transition agrees with where it came from: a retry or a short send stays put
/// and keeps its deadline, a state is left for closing only with the write deadline set
/// for its drop, closing leaves only for free, and a kept deadline means the same state or
/// a head turning into a body.
fn consistent(from: State, result: Transition) bool {
    assert(from != .free or result.to == .idle);
    assert(fits(result));
    const stays = result.to == from;
    const keeps_ok = result.deadline != .keep or stays or
        (from == .reading_head and result.to == .reading_body);
    const resubmit_ok = result.action != .resubmit or stays;
    const into_closing_ok = result.to != .closing or from == .closing or result.deadline == .write;
    const out_of_closing_ok = from != .closing or result.to == .closing or result.to == .free;
    return keeps_ok and resubmit_ok and into_closing_ok and out_of_closing_ok;
}

/// Whether an event's payload is one the loop can produce: a refusal carries an error
/// status the parser gives (`http_response.statusForParseError`), never a success.
fn eventValid(event: Event) bool {
    const valid = switch (event) {
        .received => |received| switch (received) {
            .invalid => |status| refusal(status),
            .head_short, .body_short, .complete => true,
        },
        .accepted, .receive_ended, .sent_part, .sent_all, .send_failed => true,
        .retry, .deadline, .drop_exhausted, .drained => true,
    };
    // Only a refusal's status can make an event invalid.
    assert(valid or event == .received);
    assert(valid or event.received == .invalid);
    return valid;
}

/// Whether `status` is one the parser answers a refused request with.
fn refusal(status: http_response.Status) bool {
    const code: u16 = @backingInt(status);
    assert(code >= 200 and code <= 599);
    const result = switch (status) {
        .bad_request,
        .content_too_large,
        .request_header_fields_too_large,
        .not_implemented,
        .http_version_not_supported,
        => true,
        .ok, .not_found, .method_not_allowed => false,
    };
    // A refusal is never a success.
    assert(!result or code >= 400);
    return result;
}

/// One event of each kind and payload shape, so a loop over them reaches every listed pair.
pub const events_sample = [_]Event{
    .accepted,
    .{ .received = .head_short },
    .{ .received = .body_short },
    .{ .received = .{ .complete = .keep_open } },
    .{ .received = .{ .complete = .close } },
    .{ .received = .{ .invalid = .bad_request } },
    .receive_ended,
    .sent_part,
    .{ .sent_all = .keep_open },
    .{ .sent_all = .close },
    .send_failed,
    .retry,
    .deadline,
    .drop_exhausted,
    .drained,
};

const state_count = @typeInfo(State).@"enum".field_names.len;

/// Every state, in backing-value order.
pub const states_all = [_]State{ .free, .idle, .reading_head, .reading_body, .writing, .closing };

/// `move_table[from][to]`: whether some event in `events_sample` moves `from` to `to`.
/// Built at compile time from `step`, so it can't drift from the transitions. Every
/// payload of an event kind leads to the same state, so one sample per payload shape that
/// changes the target is enough.
const move_table: [state_count][state_count]bool = table: {
    @setEvalBranchQuota(20_000);
    var result: [state_count][state_count]bool = @splat(@splat(false));
    for (states_all) |from| {
        for (events_sample) |event| {
            if (step(from, event)) |listed| result[@backingInt(from)][@backingInt(listed.to)] = true;
        }
    }
    break :table result;
};

comptime {
    @setEvalBranchQuota(20_000);
    // Backing values run 0 to state_count - 1, so they index the move table, and
    // states_all lists each state once, in that order.
    assert(states_all.len == state_count);
    for (@typeInfo(State).@"enum".field_names, 0..) |name, index| {
        assert(@backingInt(@field(State, name)) == index);
        assert(states_all[index] == @field(State, name));
    }
    // Every event kind and every kind of received has a sample, so the move table and the
    // tests see every listed pair.
    for (@typeInfo(Event).@"union".field_names) |name| {
        var found = false;
        for (events_sample) |event| found = found or std.mem.eql(u8, @tagName(event), name);
        assert(found);
    }
    for (@typeInfo(Received).@"union".field_names) |name| {
        var found = false;
        for (events_sample) |event| {
            if (event == .received) found = found or std.mem.eql(u8, @tagName(event.received), name);
        }
        assert(found);
    }
}

const testing = std.testing;

/// One listed pair: the state, the event, and the transition the file header names for it.
const Case = struct {
    from: State,
    event: Event,
    to: State,
    action: Action,
    deadline: Deadline,
};

/// Every listed pair of state and event, written out from the file header's table.
/// Any other pair must give null.
const listed_cases = [_]Case{
    .{ .from = .free, .event = .accepted, .to = .idle, .action = .receive, .deadline = .idle },
    // idle
    .{ .from = .idle, .event = .{ .received = .head_short }, .to = .reading_head, .action = .receive, .deadline = .read },
    .{ .from = .idle, .event = .{ .received = .body_short }, .to = .reading_body, .action = .receive, .deadline = .read },
    .{ .from = .idle, .event = .{ .received = .{ .complete = .keep_open } }, .to = .writing, .action = .{ .respond = .keep_open }, .deadline = .write },
    .{ .from = .idle, .event = .{ .received = .{ .complete = .close } }, .to = .writing, .action = .{ .respond = .close }, .deadline = .write },
    .{ .from = .idle, .event = .{ .received = .{ .invalid = .bad_request } }, .to = .writing, .action = .{ .send_refusal = .bad_request }, .deadline = .write },
    .{ .from = .idle, .event = .receive_ended, .to = .closing, .action = .none, .deadline = .write },
    .{ .from = .idle, .event = .retry, .to = .idle, .action = .resubmit, .deadline = .keep },
    .{ .from = .idle, .event = .deadline, .to = .closing, .action = .drop, .deadline = .write },
    // reading_head
    .{ .from = .reading_head, .event = .{ .received = .head_short }, .to = .reading_head, .action = .receive, .deadline = .keep },
    .{ .from = .reading_head, .event = .{ .received = .body_short }, .to = .reading_body, .action = .receive, .deadline = .keep },
    .{ .from = .reading_head, .event = .{ .received = .{ .complete = .keep_open } }, .to = .writing, .action = .{ .respond = .keep_open }, .deadline = .write },
    .{ .from = .reading_head, .event = .{ .received = .{ .complete = .close } }, .to = .writing, .action = .{ .respond = .close }, .deadline = .write },
    .{ .from = .reading_head, .event = .{ .received = .{ .invalid = .bad_request } }, .to = .writing, .action = .{ .send_refusal = .bad_request }, .deadline = .write },
    .{ .from = .reading_head, .event = .receive_ended, .to = .closing, .action = .none, .deadline = .write },
    .{ .from = .reading_head, .event = .retry, .to = .reading_head, .action = .resubmit, .deadline = .keep },
    .{ .from = .reading_head, .event = .deadline, .to = .closing, .action = .drop, .deadline = .write },
    // reading_body
    .{ .from = .reading_body, .event = .{ .received = .body_short }, .to = .reading_body, .action = .receive, .deadline = .keep },
    .{ .from = .reading_body, .event = .{ .received = .{ .complete = .keep_open } }, .to = .writing, .action = .{ .respond = .keep_open }, .deadline = .write },
    .{ .from = .reading_body, .event = .{ .received = .{ .complete = .close } }, .to = .writing, .action = .{ .respond = .close }, .deadline = .write },
    .{ .from = .reading_body, .event = .receive_ended, .to = .closing, .action = .none, .deadline = .write },
    .{ .from = .reading_body, .event = .retry, .to = .reading_body, .action = .resubmit, .deadline = .keep },
    .{ .from = .reading_body, .event = .deadline, .to = .closing, .action = .drop, .deadline = .write },
    // writing
    .{ .from = .writing, .event = .sent_part, .to = .writing, .action = .send_rest, .deadline = .keep },
    .{ .from = .writing, .event = .{ .sent_all = .keep_open }, .to = .idle, .action = .next_request, .deadline = .idle },
    .{ .from = .writing, .event = .{ .sent_all = .close }, .to = .closing, .action = .return_buffer, .deadline = .write },
    .{ .from = .writing, .event = .send_failed, .to = .closing, .action = .return_buffer, .deadline = .write },
    .{ .from = .writing, .event = .retry, .to = .writing, .action = .resubmit, .deadline = .keep },
    .{ .from = .writing, .event = .deadline, .to = .closing, .action = .drop, .deadline = .write },
    // closing
    .{ .from = .closing, .event = .{ .received = .head_short }, .to = .closing, .action = .none, .deadline = .keep },
    .{ .from = .closing, .event = .{ .received = .body_short }, .to = .closing, .action = .none, .deadline = .keep },
    .{ .from = .closing, .event = .{ .received = .{ .complete = .keep_open } }, .to = .closing, .action = .none, .deadline = .keep },
    .{ .from = .closing, .event = .{ .received = .{ .complete = .close } }, .to = .closing, .action = .none, .deadline = .keep },
    .{ .from = .closing, .event = .{ .received = .{ .invalid = .bad_request } }, .to = .closing, .action = .none, .deadline = .keep },
    .{ .from = .closing, .event = .receive_ended, .to = .closing, .action = .none, .deadline = .keep },
    .{ .from = .closing, .event = .sent_part, .to = .closing, .action = .return_buffer, .deadline = .keep },
    .{ .from = .closing, .event = .{ .sent_all = .keep_open }, .to = .closing, .action = .return_buffer, .deadline = .keep },
    .{ .from = .closing, .event = .{ .sent_all = .close }, .to = .closing, .action = .return_buffer, .deadline = .keep },
    .{ .from = .closing, .event = .send_failed, .to = .closing, .action = .return_buffer, .deadline = .keep },
    .{ .from = .closing, .event = .retry, .to = .closing, .action = .resubmit, .deadline = .keep },
    .{ .from = .closing, .event = .deadline, .to = .closing, .action = .drop, .deadline = .write },
    .{ .from = .closing, .event = .drop_exhausted, .to = .closing, .action = .cancel, .deadline = .keep },
    .{ .from = .closing, .event = .drained, .to = .free, .action = .release, .deadline = .clear },
};

fn listedCase(from: State, event: Event) ?Case {
    var found: ?Case = null;
    for (listed_cases) |case| {
        if (case.from == from and std.meta.eql(case.event, event)) {
            assert(found == null); // A pair listed twice.
            found = case;
        }
    }
    return found;
}

test "connection_state: every listed pair gives its transition, every other pair null" {
    var listed: u32 = 0;
    var unlisted: u32 = 0;
    for (states_all) |from| {
        for (events_sample) |event| {
            const got = step(from, event);
            if (listedCase(from, event)) |case| {
                listed += 1;
                const want: Transition = .{ .to = case.to, .action = case.action, .deadline = case.deadline };
                try testing.expectEqualDeep(@as(?Transition, want), got);
                try testing.expectEqualDeep(want, transition(from, event));
            } else {
                unlisted += 1;
                try testing.expectEqual(@as(?Transition, null), got);
            }
        }
    }
    // Every case met a sample event, so none of them was skipped.
    try testing.expectEqual(@as(u32, listed_cases.len), listed);
    try testing.expectEqual(@as(u32, state_count * events_sample.len), listed + unlisted);
}

test "connection_state: a refusal keeps its status, for every status the parser gives" {
    const statuses = [_]http_response.Status{
        .bad_request,
        .content_too_large,
        .request_header_fields_too_large,
        .not_implemented,
        .http_version_not_supported,
    };
    for (statuses) |status| {
        try testing.expect(refusal(status));
        for ([_]State{ .idle, .reading_head }) |from| {
            const got = transition(from, .{ .received = .{ .invalid = status } });
            try testing.expectEqual(State.writing, got.to);
            try testing.expectEqualDeep(Action{ .send_refusal = status }, got.action);
            try testing.expectEqual(Deadline.write, got.deadline);
        }
        // A body can't be refused: its framing was settled with the head.
        try testing.expectEqual(@as(?Transition, null), step(.reading_body, .{ .received = .{ .invalid = status } }));
    }
    // Every parser error but Incomplete maps to a status this machine accepts.
    const ParseError = @import("http_request.zig").Error;
    inline for (@typeInfo(ParseError).error_set.error_names.?) |name| {
        const err: ParseError = @field(ParseError, name);
        if (http_response.statusForParseError(err)) |status| try testing.expect(refusal(status));
    }
    try testing.expect(!refusal(.ok));
    try testing.expect(!refusal(.not_found));
    try testing.expect(!refusal(.method_not_allowed));
}

test "connection_state: the move table matches the listed pairs" {
    var expected: [state_count][state_count]bool = @splat(@splat(false));
    for (listed_cases) |case| expected[@backingInt(case.from)][@backingInt(case.to)] = true;
    for (states_all) |from| {
        for (states_all) |to| {
            try testing.expectEqual(expected[@backingInt(from)][@backingInt(to)], moves(from, to));
        }
    }
    // Spot checks: no shortcuts past closing, no way back to free.
    try testing.expect(!moves(.writing, .free));
    try testing.expect(!moves(.idle, .free));
    try testing.expect(!moves(.free, .writing));
    try testing.expect(!moves(.reading_body, .reading_head));
    try testing.expect(!moves(.closing, .idle));
    try testing.expect(moves(.writing, .idle));
    try testing.expect(moves(.closing, .free));
}

/// Applies `events` in order from `start`, checking each step's state, and returns the last
/// transition. Every walk is at most `walk_events_max` events long.
fn walk(start: State, events: []const Event, states: []const State) !Transition {
    assert(events.len == states.len);
    assert(events.len > 0 and events.len <= walk_events_max);
    var state = start;
    var last: Transition = undefined;
    for (events, states) |event, expected| {
        last = transition(state, event);
        try testing.expectEqual(expected, last.to);
        state = last.to;
    }
    return last;
}

const walk_events_max: u32 = 16;

/// Requests a walk serves on one connection kept alive: the server's limit. The loop
/// counts them, and the machine only sees the last one as `close`.
const keep_alive_requests: u32 = @import("../constants.zig").http_requests_per_connection_max;

test "connection_state: a connection kept alive serves requests until the last one closes it" {
    var state = transition(.free, .accepted).to;
    try testing.expectEqual(State.idle, state);
    var served: u32 = 0;
    while (served < keep_alive_requests) : (served += 1) {
        const last = served + 1 == keep_alive_requests;
        const after: After = if (last) .close else .keep_open;
        state = transition(state, .{ .received = .head_short }).to;
        try testing.expectEqual(State.reading_head, state);
        state = transition(state, .{ .received = .body_short }).to;
        const done = transition(state, .{ .received = .{ .complete = after } });
        try testing.expectEqualDeep(Action{ .respond = after }, done.action);
        state = transition(done.to, .sent_part).to;
        const sent = transition(state, .{ .sent_all = after });
        if (last) {
            try testing.expectEqual(State.closing, sent.to);
            try testing.expectEqual(Action.return_buffer, sent.action);
        } else {
            try testing.expectEqual(State.idle, sent.to);
            try testing.expectEqual(Action.next_request, sent.action);
            try testing.expectEqual(Deadline.idle, sent.deadline);
        }
        state = sent.to;
    }
    try testing.expectEqual(keep_alive_requests, served);
    const freed = transition(state, .drained);
    try testing.expectEqual(State.free, freed.to);
    try testing.expectEqual(Action.release, freed.action);
}

test "connection_state: a parse error is answered, then the connection closes" {
    const last = try walk(.free, &.{
        .accepted,
        .{ .received = .head_short },
        .{ .received = .{ .invalid = .request_header_fields_too_large } },
        .{ .sent_all = .close },
        .drained,
    }, &.{ .idle, .reading_head, .writing, .closing, .free });
    try testing.expectEqual(Action.release, last.action);
    const refused = transition(.reading_head, .{ .received = .{ .invalid = .request_header_fields_too_large } });
    try testing.expectEqualDeep(Action{ .send_refusal = .request_header_fields_too_large }, refused.action);
}

test "connection_state: a deadline in each state drops, then closes" {
    for ([_]State{ .idle, .reading_head, .reading_body, .writing, .closing }) |from| {
        const got = transition(from, .deadline);
        try testing.expectEqual(State.closing, got.to);
        try testing.expectEqual(Action.drop, got.action);
        // The write deadline paces the next drop attempt.
        try testing.expectEqual(Deadline.write, got.deadline);
    }
    try testing.expectEqual(@as(?Transition, null), step(.free, .deadline));
    // A reading connection's receive comes back after the drop, then nothing is in flight.
    _ = try walk(.reading_body, &.{ .deadline, .receive_ended, .drained }, &.{ .closing, .closing, .free });
    // A writing connection's send comes back PeerDown after the drop, and its buffer returns.
    const dropped = transition(.writing, .deadline);
    try testing.expectEqual(Action.drop, dropped.action);
    const back = transition(dropped.to, .send_failed);
    try testing.expectEqual(State.closing, back.to);
    try testing.expectEqual(Action.return_buffer, back.action);
    try testing.expectEqual(Deadline.keep, back.deadline);
    const freed = transition(back.to, .drained);
    try testing.expectEqual(State.free, freed.to);
}

test "connection_state: drops run out, then cancel, drained and free" {
    const events = [_]Event{
        .accepted,
        .{ .received = .{ .complete = .keep_open } },
        .deadline, // The send is stuck: drop it.
        .deadline, // The drop failed: drop again.
        .deadline,
        .drop_exhausted,
        .retry, // The cancel was refused for now.
        .send_failed, // The cancelled send comes back.
        .drained,
    };
    const states = [_]State{ .idle, .writing, .closing, .closing, .closing, .closing, .closing, .closing, .free };
    var state: State = .free;
    var actions: [events.len]Action = undefined;
    for (events, states, 0..) |event, expected, index| {
        const got = transition(state, event);
        try testing.expectEqual(expected, got.to);
        actions[index] = got.action;
        state = got.to;
    }
    try testing.expectEqual(Action.cancel, actions[5]);
    try testing.expectEqual(Action.resubmit, actions[6]);
    try testing.expectEqual(Action.return_buffer, actions[7]);
    try testing.expectEqual(Action.release, actions[8]);
}

test "connection_state: every listed transition fits the state it lands in" {
    var checked: u32 = 0;
    for (listed_cases) |case| {
        const result: Transition = .{ .to = case.to, .action = case.action, .deadline = case.deadline };
        try testing.expect(fits(result));
        checked += 1;
    }
    try testing.expectEqual(@as(u32, listed_cases.len), checked);
    // And one that doesn't for every arm of both switches, so each arm can fail.
    const misfits = [_]Transition{
        .{ .to = .writing, .action = .receive, .deadline = .keep },
        .{ .to = .reading_head, .action = .next_request, .deadline = .keep },
        .{ .to = .idle, .action = .{ .respond = .close }, .deadline = .keep },
        .{ .to = .closing, .action = .{ .send_refusal = .bad_request }, .deadline = .keep },
        .{ .to = .idle, .action = .send_rest, .deadline = .keep },
        .{ .to = .writing, .action = .drop, .deadline = .keep },
        .{ .to = .idle, .action = .cancel, .deadline = .keep },
        .{ .to = .writing, .action = .return_buffer, .deadline = .keep },
        .{ .to = .closing, .action = .release, .deadline = .keep },
        .{ .to = .free, .action = .none, .deadline = .clear },
        .{ .to = .free, .action = .resubmit, .deadline = .clear },
        .{ .to = .free, .action = .release, .deadline = .keep },
        .{ .to = .closing, .action = .none, .deadline = .clear },
        .{ .to = .reading_head, .action = .receive, .deadline = .idle },
        .{ .to = .writing, .action = .send_rest, .deadline = .read },
        .{ .to = .idle, .action = .receive, .deadline = .write },
    };
    for (misfits) |misfit| try testing.expect(!fits(misfit));
}

test "connection_state: consistent and eventValid refuse what no listed pair does" {
    // Each breaks one of consistent's rules while fitting the state it lands in.
    const breaks = [_]struct { from: State, result: Transition }{
        // A kept deadline across a move other than head to body.
        .{ .from = .idle, .result = .{ .to = .writing, .action = .{ .respond = .close }, .deadline = .keep } },
        // A resubmit that moves.
        .{ .from = .idle, .result = .{ .to = .reading_head, .action = .resubmit, .deadline = .read } },
        // Into closing without the write deadline its drop needs.
        .{ .from = .writing, .result = .{ .to = .closing, .action = .drop, .deadline = .keep } },
        // Out of closing to anything but free.
        .{ .from = .closing, .result = .{ .to = .writing, .action = .send_rest, .deadline = .write } },
    };
    for (breaks) |case| {
        try testing.expect(fits(case.result));
        try testing.expect(!consistent(case.from, case.result));
    }
    for (listed_cases) |case| {
        const result: Transition = .{ .to = case.to, .action = case.action, .deadline = case.deadline };
        try testing.expect(consistent(case.from, result));
    }
    // A refusal never carries a success status.
    try testing.expect(!eventValid(.{ .received = .{ .invalid = .ok } }));
    try testing.expect(!eventValid(.{ .received = .{ .invalid = .not_found } }));
    try testing.expect(eventValid(.{ .received = .{ .invalid = .content_too_large } }));
}
