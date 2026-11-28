//! Deterministic simulator for the I/O boundary.
//!
//! Job: stand in for the network, the clock, the database and the random source, driven by
//! one seed. Time moves only when `tick` is called. Each submitted operation completes after a
//! seeded delay, so completions arrive out of submission order. Faults of every kind the
//! contract names, and short sends, are drawn from a seeded PRNG and counted. A failing seed
//! replays exactly.
//!
//! Five seeded streams keep each kind of draw independent of the others:
//!   outcomes   each operation's delay and result, drawn when it is submitted
//!   schedule   which free slot an operation takes and where each poll starts its scan
//!   random     the bytes `randomBytes` hands out
//!   stick      whether a send or a receive sticks, drawn for each while sticking is on
//!   drops      which drops fail, and how a drop or a cancel ends each pending operation
//! So how often a workload polls, how many nonces it draws, or when it drops or cancels a
//! connection never changes any operation's own drawn result, or which operations stick
//! by draw.
//!
//! Accepts: an accept's delay is the wait for a connection to arrive. When it completes, the
//! arrival takes an entry in the connection table attached with `attachTable`, under a fake
//! socket number never handed out before; a full table refuses it with `error.TableFull`,
//! as the real type does, and counts the refusal. Whether the connection fails before it
//! arrives is drawn at submit, like every other outcome, so the same seed refuses the same
//! arrivals in the same order. An accept that completes with `error.Backpressure` starts
//! the wait the real type keeps: until `constants.io_accept_backpressure_wait_ns` of
//! simulated time has passed, `submit` refuses every accept with `error.AcceptTooSoon`,
//! draws nothing and changes nothing but the wait's refusal count (`io.AcceptWait`, the
//! type the real one keeps too), so the loop is tested against it. As on the real type, at
//! most `constants.accepts_in_flight_max` accepts may be in flight; another crashes, before
//! the queue is checked (`io.SlotShare.assertAcceptRoom`).
//!
//! Sends, receives and cancels go through the attached table with the same calls the real
//! type makes. The peer is looked up at submit, before the queue is checked, so a free,
//! stale or out-of-range peer, or an entry with no room for the operation
//! (`Table.assertRoomFor`), crashes as it does on the real type; the operation is counted
//! on its entry (`Table.operationSubmitted`) until its completion uncounts it
//! (`Table.operationCompleted`), so the table refuses to release that entry with
//! `error.OperationsInFlight` meanwhile. Code that releases early or sends on a stale id
//! fails in simulation, not first on the real type.
//!
//! Receives: every connection's client sends the same bytes, set with `setClientStream`,
//! and then closes. Each receive draws at submit how much of what is left it reads: 1 to
//! the least of its buffer, what is left and the chunk bound, so a client can send a byte
//! at a time; or, as a fault, a reset (`error.PeerDown`), a moment's shortage
//! (`error.Backpressure`) or a client that closes early, mid-request (0 bytes). Once the
//! client has sent everything, a receive reads end of stream. The bytes land in the buffer
//! at completion. At submit the buffer is filled with `receive_poison` and hashed, so a
//! caller that writes into it while the receive is in flight crashes at the completion.
//! With sticking on, a receive may stick, drawn as for sends: a client that goes silent,
//! which only a drop, a cancel or the caller's deadline ends.
//!
//! Cancels: a cancel reaches, at submit, every send and receive in flight to its connection
//! that isn't due yet or is stuck: each completes with `error.Canceled` within the longest
//! delay, drawn from the drop stream. One due already had finished, and one a drop ended is
//! settled, so each keeps its result. The cancel completes after its own drawn delay with
//! the number it reached.
//!
//! Sticking and dropping: after `setDropFaults`, each send may stick, drawn at submit: it
//! never completes on its own, as a send to a client that stopped reading never does on the
//! real type, and every later send to that connection sticks too. `drop` ends it as the real type's shutdown does: every stuck send to that
//! connection completes with `error.PeerDown` within the longest delay, every send to it
//! still pending ends that way or keeps its own result (drawn), and every send submitted to
//! it afterwards completes with `error.PeerDown`. A receive to it ends the same way, as
//! end of stream or `error.PeerDown`, drawn, as the real type's shutdown ends one as end
//! of stream. A drop can fail, drawn too, leaving the
//! sends stuck; once one has worked, dropping again changes nothing and never fails, as a
//! second shutdown on the real type returns success or ENOTCONN. Each drop goes through the table's `dropAdmit` and each failure through its
//! `dropFailed`, the calls the real type makes, so `error.DropsExhausted` comes at the same
//! count. A connection the table has since released and handed out again is a new one: its
//! id carries the entry's next generation, so the drop of the old one doesn't reach it.
//!
//! Inputs: a seed, a fault rate in percent (at most `constants.sim_fault_percent_max`), for
//! sends, receives, cancels and accepts a connection table, and for receives the bytes each
//! client sends.
//! Outputs: the same contract as io/root.zig, plus counters a test can assert on.
//! Limits: at most `constants.sim_ticks_max` ticks per run, at most
//! `constants.io_operations_in_flight_max` operations in flight, and delays of at most
//! `constants.sim_completion_delay_ticks_max` ticks.
//!
//! Only tests and programs whose root file declares `pub const io_simulation = true;` may
//! use a `Sim`: `init`, `submit` and `randomBytes` each refuse to compile anywhere else, so
//! the seeded random source can't reach a production build.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const connections = @import("../live/connections.zig");
const io = @import("root.zig");

const slots_count = constants.io_operations_in_flight_max;
/// Operations in flight that may be anything but accepts and cancels; the rest are kept for
/// those, as on the real type.
const shared_slots_max = constants.io_shared_in_flight_max;

/// The first fake socket an arrival gets: above any descriptor a test or workload names as
/// its listener, so an arrival never shares a number with one, as with a real kernel.
const socket_first: io.Socket = 1 << 16;

/// Arrivals a run may have: every one gets a distinct fake socket that fits `io.Socket`.
const arrivals_max: u64 = std.math.maxInt(io.Socket) - socket_first;

/// Salts that separate the schedule and random streams from the outcome stream.
const schedule_salt: u64 = 0x9e37_79b9_7f4a_7c15;
const random_salt: u64 = 0xc2b2_ae3d_27d4_eb4f;
const drop_salt: u64 = 0x1656_67b1_9e37_79f9;
const stick_salt: u64 = 0x27d4_eb2f_1656_67c5;

/// An entry's slot in `Sim.dropped_ids` when no drop of it has worked, and in
/// `Sim.stream_ids` before any receive: index 0xffff, past any table, so it never equals a
/// live id.
const no_drop: io.PeerId = std.math.maxInt(io.PeerId);

/// What `submit` fills a receive's buffer with, so a caller's write into it shows.
pub const receive_poison: u8 = 0xa5;

/// Bytes one client may send: what one connection's request buffer holds, several times
/// over, so a stream can carry a few requests kept alive.
pub const client_stream_bytes_max: u32 = 4 * constants.http_request_size_max;

comptime {
    // The sentinel's index is past every entry the table may have.
    const parts: connections.IdParts = @bitCast(no_drop);
    assert(parts.index >= constants.http_connections_max);
}

/// Faults injected so far, one counter per error the contract names.
pub const Faults = struct {
    peer_down: u32 = 0,
    backpressure: u32 = 0,
    unavailable: u32 = 0,
    timeout: u32 = 0,
    /// Accepts whose connection failed before it arrived, or that found the system short.
    accept_peer_down: u32 = 0,
    accept_backpressure: u32 = 0,
    /// Receives whose connection reset, that found the system short, or whose client
    /// closed early, before it had sent everything.
    receive_peer_down: u32 = 0,
    receive_backpressure: u32 = 0,
    receive_closed_early: u32 = 0,

    pub fn total(self: Faults) u64 {
        const sends = @as(u64, self.peer_down) + self.backpressure;
        const executes = @as(u64, self.unavailable) + self.timeout;
        const accepts = @as(u64, self.accept_peer_down) + self.accept_backpressure;
        const receives = @as(u64, self.receive_peer_down) + self.receive_backpressure +
            self.receive_closed_early;
        assert(sends >= self.peer_down and sends >= self.backpressure);
        assert(executes >= self.unavailable and executes >= self.timeout);
        return sends + executes + accepts + receives;
    }
};

/// An accept's fault, drawn at submit. A full table is not drawn: it depends on the table
/// when the connection arrives.
const ArrivalError = error{ PeerDown, Backpressure };

/// What `submit` draws for an operation. A send's and a statement's result is final; an
/// accept draws only whether its connection fails, and takes its table entry on completion;
/// a receive draws how many bytes it reads, copied at completion; a cancel counts what it
/// reached.
const Drawn = union(io.Kind) {
    send: io.SendError!u32,
    execute: io.DatabaseError!void,
    accept: ArrivalError!void,
    receive: io.ReceiveError!u32,
    cancel: u32,
};

const Slot = struct {
    submission: io.Submission,
    due_tick: u32,
    /// Drawn at submit, turned into the result at completion.
    drawn: Drawn,
    /// Hash of the operation's bytes at submit; they must be unchanged at completion.
    bytes_hash: u64,
    /// A send or a receive that completes only once its connection is dropped or
    /// cancelled; `due_tick` waits till then.
    stuck: bool = false,
    /// A send or a receive whose connection was dropped: it completes with
    /// `error.PeerDown` (or, a receive, as end of stream), counted in `sends_dropped` or
    /// `receives_dropped`, not as an injected fault.
    by_drop: bool = false,
    /// A send or a receive a cancel reached: it completes with `error.Canceled`, counted in
    /// `canceled`, not as an injected fault.
    by_cancel: bool = false,
    /// Where a receive's bytes start in the client stream; 0 for every other kind.
    stream_at: u32 = 0,
};

pub const Sim = struct {
    outcomes: std.Random.DefaultPrng,
    schedule: std.Random.DefaultPrng,
    random_source: std.Random.DefaultPrng,
    stick_source: std.Random.DefaultPrng,
    drop_source: std.Random.DefaultPrng,
    fault_percent: u8,
    /// Chance, in percent, that a send sticks until its connection is dropped.
    stick_percent: u8,
    /// Chance, in percent, that a drop fails and leaves its connection's sends stuck.
    drop_fail_percent: u8,
    /// By entry index, the id of the connection whose drop last worked, or `no_drop`. Only
    /// an equal id counts as dropped, so a reused entry starts undropped.
    dropped_ids: [constants.http_connections_max]io.PeerId,
    /// Sends that stuck, sends a drop ended with PeerDown, drops tried (failed or not, as
    /// the real type counts its shutdowns) and drops that failed.
    sends_stuck: u32,
    sends_dropped: u32,
    dropped: u64,
    drops_failed: u64,
    ticks: u32,
    now_ns: io.Instant,
    slots: [slots_count]?Slot,
    in_flight: u32,
    /// Operations in flight that are sends: never more than `shared_slots_max`.
    sends_in_flight: u32,
    /// Operations in flight that aren't accepts, counted against the share kept from
    /// accepts through the same calls as on the real type.
    share: io.SlotShare,
    submitted: u64,
    completed: u64,
    bytes_sent: u64,
    short_sends: u32,
    statements: u32,
    random_bytes: u64,
    faults: Faults,
    /// Where arrivals take their entries; set once by `attachTable`, before any accept.
    table: ?*connections.Table,
    /// The bytes every connection's client sends, then closes; set once by
    /// `setClientStream`, before any receive.
    client_stream: ?[]const u8,
    /// The most bytes one receive reads, however much room its buffer has.
    receive_chunk_max: u32,
    /// By entry index, the connection whose client stream `stream_read` counts, or
    /// `no_drop` before its first receive; a new id on the entry starts the stream again.
    stream_ids: [constants.http_connections_max]io.PeerId,
    /// By entry index, how much of the client stream receives have taken so far.
    stream_read: [constants.http_connections_max]u32,
    /// Bytes receives handed back, receives that read end of stream, receives a drop ended,
    /// operations a cancel reached, and cancels completed.
    bytes_received: u64,
    /// Receives that stuck: their clients went silent.
    receives_stuck: u32,
    receives_ended: u32,
    receives_dropped: u32,
    canceled: u32,
    cancels: u32,
    /// Arrivals that took a table entry, and arrivals a full table refused.
    accepted: u64,
    refused: u64,
    /// The wait after an accept completed with `Backpressure`, kept through the same calls
    /// as on the real type, and the accepts it refused.
    accept_wait: io.AcceptWait,
    /// Connections `release` has freed.
    released: u64,

    pub fn init(seed: u64, fault_percent: u8) Sim {
        comptime assertSimulationAllowed();
        assert(fault_percent <= constants.sim_fault_percent_max);
        const result: Sim = .{
            .outcomes = .init(seed),
            .schedule = .init(seed ^ schedule_salt),
            .random_source = .init(seed ^ random_salt),
            .stick_source = .init(seed ^ stick_salt),
            .drop_source = .init(seed ^ drop_salt),
            .fault_percent = fault_percent,
            .stick_percent = 0,
            .drop_fail_percent = 0,
            .dropped_ids = @splat(no_drop),
            .sends_stuck = 0,
            .sends_dropped = 0,
            .dropped = 0,
            .drops_failed = 0,
            .ticks = 0,
            .now_ns = 0,
            .slots = @splat(null),
            .in_flight = 0,
            .sends_in_flight = 0,
            .share = .{},
            .submitted = 0,
            .completed = 0,
            .bytes_sent = 0,
            .short_sends = 0,
            .statements = 0,
            .random_bytes = 0,
            .faults = .{},
            .table = null,
            .client_stream = null,
            .receive_chunk_max = constants.http_request_size_max,
            .stream_ids = @splat(no_drop),
            .stream_read = @splat(0),
            .bytes_received = 0,
            .receives_stuck = 0,
            .receives_ended = 0,
            .receives_dropped = 0,
            .canceled = 0,
            .cancels = 0,
            .accepted = 0,
            .refused = 0,
            .accept_wait = .{},
            .released = 0,
        };
        assert(result.ticks == 0);
        assert(result.in_flight == 0);
        return result;
    }

    /// Gives sends the connection table their peers live in, and arrivals the table to take
    /// their entries in. Call it once, before the first send or accept; the table is the
    /// caller's and must outlive every send and accept.
    pub fn attachTable(self: *Sim, table: *connections.Table) void {
        assert(self.table == null);
        assert(self.accepted + self.refused == 0);
        assert(table.capacity() > 0);
        self.table = table;
    }

    /// Gives every connection's client `stream` to send, at most `chunk_max` bytes a
    /// receive (1 sends a byte at a time), then end of stream. Call it once, before the
    /// first submission, so a seed replays the same run; the bytes are the caller's and
    /// must outlive every receive.
    pub fn setClientStream(self: *Sim, stream: []const u8, chunk_max: u32) void {
        assert(self.submitted == 0);
        assert(self.client_stream == null);
        assert(stream.len > 0 and stream.len <= client_stream_bytes_max);
        assert(chunk_max > 0 and chunk_max <= constants.http_request_size_max);
        self.client_stream = stream;
        self.receive_chunk_max = chunk_max;
    }

    /// Lets sends and receives stick and drops fail, each at its chance in percent:
    /// sticking at most `constants.sim_fault_percent_max`, failing drops at most 100, so a
    /// test can make every drop fail and reach the bound. Call it before the first submission, so a seed
    /// replays the same run; both start at 0, and then nothing sticks or fails to drop.
    pub fn setDropFaults(self: *Sim, stick_percent: u8, drop_fail_percent: u8) void {
        assert(self.submitted == 0);
        assert(stick_percent <= constants.sim_fault_percent_max);
        assert(drop_fail_percent <= 100);
        self.stick_percent = stick_percent;
        self.drop_fail_percent = drop_fail_percent;
    }

    /// Advances simulated time by one tick.
    pub fn tick(self: *Sim) void {
        assert(self.ticks < constants.sim_ticks_max);
        self.ticks += 1;
        self.now_ns += constants.tick_ns;
        assert(self.now_ns == @as(u64, self.ticks) * constants.tick_ns);
    }

    pub fn now(self: *Sim) io.Instant {
        assert(self.ticks <= constants.sim_ticks_max);
        assert(self.now_ns == @as(u64, self.ticks) * constants.tick_ns);
        return self.now_ns;
    }

    /// Queues one operation to complete after a seeded delay of 0 to
    /// `sim_completion_delay_ticks_max` ticks, capped at the run's last tick, with its result
    /// drawn now. A full table returns `error.QueueFull`; a send, receive or statement, with
    /// those holding their whole share (`shared_slots_max`), `error.SlotsKeptForAccepts`; a
    /// cancel, with cancels holding theirs, `error.CancelsFull`; and an accept while the
    /// wait after a Backpressure runs `error.AcceptTooSoon`, as on the real type, in that
    /// order when more than one holds; each draws nothing and takes no slot, and only the
    /// last changes a count, the wait's refusals. An id already in flight breaks the
    /// contract and crashes, full table or not, and so do an accept past
    /// `constants.accepts_in_flight_max` and an operation its peer's entry has no room for,
    /// through the same checks as on the real type. The one exception to the delay: a send
    /// or a receive that sticks (`setDropFaults`) completes only once its connection is
    /// dropped or cancelled.
    pub fn submit(self: *Sim, submission: io.Submission) io.SubmitError!void {
        comptime assertSimulationAllowed();
        assert(self.in_flight <= slots_count);
        assertOperation(submission.operation);
        // A peer's operation names its entry, and an arrival takes one, so both need a
        // table; a receive needs the bytes its client sends.
        assert(submission.operation == .execute or self.table != null);
        assert(submission.operation != .receive or self.client_stream != null);
        // Looked up before anything changes, as the real type does: an operation naming a
        // peer that isn't live in the table (free, stale or past its end), or whose entry
        // has no room for it, is a caller's bug and crashes, full queue or not.
        if (io.operationPeer(submission.operation)) |peer| {
            self.table.?.assertRoomFor(peer, submission.operation);
        }
        const counted_before = self.countedOnPeer(submission.operation);
        self.assertIdNotInFlight(submission.id);
        // A second accept past `constants.accepts_in_flight_max` is a caller's bug, checked
        // before the queue through the same call as on the real type.
        self.share.assertAcceptRoom(submission.operation);
        assert(self.sends_in_flight <= shared_slots_max);
        if (self.in_flight == slots_count) return error.QueueFull;
        // The operations past shared_slots_max are kept for accepts and cancels.
        try self.share.admit(submission.operation, slots_count - self.in_flight);
        if (submission.operation == .accept) try self.accept_wait.admit(self.now_ns);

        // Admitted: from here the buffer of a receive belongs to this type.
        if (submission.operation == .receive) @memset(submission.operation.receive.buffer, receive_poison);
        const index = self.freeSlot();
        const delay_max = constants.sim_completion_delay_ticks_max;
        const delay = self.outcomes.random().uintAtMost(u32, delay_max);
        // Never due after the run's last tick, so every accepted operation can complete.
        const due_tick = @min(self.ticks + delay, constants.sim_ticks_max);
        assert(due_tick >= self.ticks);
        self.slots[index] = self.fated(.{
            .submission = submission,
            .due_tick = due_tick,
            .drawn = self.draw(submission.operation),
            .bytes_hash = hashOperation(submission.operation),
        });
        self.in_flight += 1;
        self.share.taken(submission.operation);
        if (submission.operation == .send) self.sends_in_flight += 1;
        self.submitted += 1;
        // Counted on the peer's entry until it completes, through the same call the real
        // type makes, so the table refuses to release the entry meanwhile.
        if (self.table) |table| table.operationSubmitted(submission.operation);
        const added: u32 = @intFromBool(io.operationPeer(submission.operation) != null);
        assert(self.countedOnPeer(submission.operation) == counted_before + added);
        assert(self.slots[index] != null);
        assert(self.completed + self.in_flight == self.submitted);
    }

    /// What the peer's entry counts of an operation's kind, read through `Table.get`, which
    /// crashes unless the peer is live; 0 for an accept or a statement, which name no peer,
    /// and for a statement with no table attached.
    fn countedOnPeer(self: *const Sim, operation: io.Operation) u32 {
        const table = self.table orelse {
            assert(operation == .execute); // `submit` checked every other kind has a table.
            return 0;
        };
        const count = table.operationCount(operation);
        assert(count <= slots_count);
        return count;
    }

    /// Moves operations that are due into `completions` and returns how many. The scan starts
    /// at a slot drawn from the schedule stream, so operations due on the same tick also come
    /// back in a seeded order. With nothing due it returns 0 and changes nothing else.
    pub fn poll(self: *Sim, completions: []io.Completion) u32 {
        assert(completions.len > 0);
        assert(completions.len <= slots_count);
        const in_flight_before = self.in_flight;
        const start = self.schedule.random().uintLessThan(u32, slots_count);

        var count: u32 = 0;
        var step: u32 = 0;
        while (step < slots_count and count < completions.len) : (step += 1) {
            const index = (start + step) % slots_count;
            const slot = self.slots[index] orelse continue;
            if (slot.stuck or slot.due_tick > self.ticks) continue;
            self.slots[index] = null;
            completions[count] = self.complete(slot);
            count += 1;
        }
        assert(step <= slots_count);
        assert(count <= in_flight_before);
        self.in_flight -= count;
        assert(self.completed + self.in_flight == self.submitted);
        return count;
    }

    /// Fills `buffer` from the seeded random stream. Same seed, same bytes. Never fails, but
    /// keeps the contract's error so callers handle the production failure.
    pub fn randomBytes(self: *Sim, buffer: []u8) io.RandomError!void {
        comptime assertSimulationAllowed();
        assert(buffer.len > 0);
        assert(buffer.len <= constants.io_random_bytes_max);
        const drawn: u32 = @intCast(buffer.len);
        const before = self.random_bytes;
        self.random_source.random().bytes(buffer);
        self.random_bytes += drawn;
        assert(self.random_bytes == before + drawn);
    }

    /// Drops `peer`'s connection, which must be live, as the real type's shutdown does: see
    /// "Sticking and dropping" above. Takes no slot and completes nothing itself. A drawn
    /// failure leaves every operation as it was and counts on the entry; the failure that
    /// reaches `constants.io_drop_attempts_max`, and every drop after it, returns
    /// `error.DropsExhausted`, the later ones drawing nothing.
    pub fn drop(self: *Sim, peer: io.PeerId) io.DropError!void {
        comptime assertSimulationAllowed();
        assert(self.table != null); // Only a connection in a table can be dropped.
        const table = self.table.?;
        const entry = table.get(peer);
        // The checks the real type makes: every send counted on the entry is in flight here.
        assert(entry.sends_in_flight <= self.sends_in_flight);
        assert(self.sends_in_flight <= self.in_flight);
        try table.dropAdmit(peer);
        self.dropped += 1;
        // Shut down already: on the real type a second shutdown returns success or
        // ENOTCONN, neither a failure, and everything was settled by the first.
        if (self.isDropped(peer)) return;
        if (self.chance(self.drop_fail_percent)) {
            self.drops_failed += 1;
            return table.dropFailed(peer);
        }
        const parts: connections.IdParts = @bitCast(peer);
        self.dropped_ids[parts.index] = peer;
        self.endOperations(peer);
        // Nothing sent to or received from a dropped connection waits any more.
        assert(self.stuckTo(peer) == 0);
    }

    /// Frees `peer`'s entry, which must be live, through the table call the real type makes
    /// (`Table.release`), so an early release fails in simulation as it would there: while a
    /// send, a receive or a cancel is in flight on it, `error.OperationsInFlight`, and
    /// nothing changes. The fake socket needs no closing. Draws nothing.
    pub fn release(self: *Sim, peer: io.PeerId) io.ReleaseError!void {
        comptime assertSimulationAllowed();
        assert(self.table != null); // Only a connection in a table can be released.
        const table = self.table.?;
        assert(table.lookup(peer) != null); // A live connection only, as on the real type.
        const socket = try table.release(peer);
        assert(socket >= 0);
        self.released += 1;
        assert(table.lookup(peer) == null);
    }

    /// Ends the sends and the receive in flight to a just dropped `peer`: each stuck one
    /// completes within the longest delay, capped at the run's last tick; each one still
    /// pending either keeps its own result or ends on its own tick, drawn. One due already
    /// had finished before the drop, and one a cancel reached is settled; each keeps its
    /// result. A send ends with PeerDown; a receive with PeerDown or end of stream, drawn.
    /// At most `slots_count` steps.
    fn endOperations(self: *Sim, peer: io.PeerId) void {
        assert(self.isDropped(peer));
        const ended_before = self.sendsEndedBy(peer);
        var index: u32 = 0;
        while (index < slots_count) : (index += 1) {
            const slot = if (self.slots[index]) |*slot| slot else continue;
            const kind: io.Kind = slot.submission.operation;
            if (kind != .send and kind != .receive) continue;
            if (io.operationPeer(slot.submission.operation).? != peer) continue;
            if (slot.by_cancel) continue;
            if (slot.stuck) {
                const delay = self.drop_source.random().uintAtMost(u32, constants.sim_completion_delay_ticks_max);
                slot.due_tick = @min(self.ticks + delay, constants.sim_ticks_max);
                slot.stuck = false;
            } else if (slot.by_drop or slot.due_tick <= self.ticks or self.drop_source.random().boolean()) {
                continue;
            }
            slot.drawn = self.endedByDrop(kind);
            slot.by_drop = true;
        }
        assert(index == slots_count);
        // A drop only ever adds sends it ends, never takes one back.
        assert(self.sendsEndedBy(peer) >= ended_before);
    }

    /// The result a drop gives a send or a receive it ends: a send PeerDown; a receive
    /// PeerDown or end of stream, drawn from the drop stream.
    fn endedByDrop(self: *Sim, kind: io.Kind) Drawn {
        assert(kind == .send or kind == .receive);
        const result: Drawn = if (kind == .send)
            .{ .send = error.PeerDown }
        else if (self.drop_source.random().boolean())
            .{ .receive = error.PeerDown }
        else
            .{ .receive = 0 };
        assert(@as(io.Kind, result) == kind);
        return result;
    }

    /// Reaches, for a cancel of `peer` being submitted, every send and receive in flight to
    /// it that isn't settled: stuck, or not due yet and not ended by a drop. Each completes
    /// with `error.Canceled` within the longest delay, drawn from the drop stream. Returns
    /// how many it reached. At most `slots_count` steps.
    fn cancelReach(self: *Sim, peer: io.PeerId) u32 {
        assert(self.table != null); // A cancel names a peer in a table.
        var reached: u32 = 0;
        var index: u32 = 0;
        while (index < slots_count) : (index += 1) {
            const slot = if (self.slots[index]) |*slot| slot else continue;
            const kind: io.Kind = slot.submission.operation;
            if (kind != .send and kind != .receive) continue;
            if (io.operationPeer(slot.submission.operation).? != peer) continue;
            if (slot.by_drop or slot.by_cancel) continue;
            if (!slot.stuck and slot.due_tick <= self.ticks) continue;
            const delay = self.drop_source.random().uintAtMost(u32, constants.sim_completion_delay_ticks_max);
            slot.due_tick = @min(self.ticks + delay, constants.sim_ticks_max);
            slot.stuck = false;
            slot.by_cancel = true;
            slot.drawn = if (kind == .send) .{ .send = error.Canceled } else .{ .receive = error.Canceled };
            reached += 1;
        }
        assert(index == slots_count);
        // Nothing to the cancelled connection waits on its own any more.
        assert(self.stuckTo(peer) == 0);
        return reached;
    }

    /// Sends in flight to `peer` that a drop has ended. At most `slots_count` steps.
    fn sendsEndedBy(self: *const Sim, peer: io.PeerId) u32 {
        assert(self.table != null);
        var ended: u32 = 0;
        for (self.slots) |maybe| {
            const slot = maybe orelse continue;
            if (slot.submission.operation != .send) continue;
            if (slot.by_drop and slot.submission.operation.send.peer == peer) ended += 1;
        }
        // Each is a send in flight, counted on the peer's entry.
        assert(ended <= self.table.?.get(peer).sends_in_flight);
        return ended;
    }

    /// Whether `peer`'s connection has been dropped, a drop of it having worked.
    fn isDropped(self: *const Sim, peer: io.PeerId) bool {
        const parts: connections.IdParts = @bitCast(peer);
        assert(parts.index < constants.http_connections_max);
        const dropped_id = self.dropped_ids[parts.index];
        // Only a working drop records an id, and only its entry's own index.
        assert(dropped_id == no_drop or @as(connections.IdParts, @bitCast(dropped_id)).index == parts.index);
        return dropped_id == peer;
    }

    /// Sends in flight that are stuck. At most `slots_count` steps.
    fn stuckSends(self: *const Sim) u32 {
        var stuck: u32 = 0;
        for (self.slots) |maybe| {
            const slot = maybe orelse continue;
            if (slot.stuck and slot.submission.operation == .send) stuck += 1;
        }
        assert(stuck <= self.sends_in_flight);
        assert(stuck <= self.sends_stuck);
        return stuck;
    }

    /// Stuck sends in flight to `peer`. At most `slots_count` steps.
    fn stuckSendsTo(self: *const Sim, peer: io.PeerId) u32 {
        assert(self.table != null); // Sends name peers in a table.
        var stuck: u32 = 0;
        for (self.slots) |maybe| {
            const slot = maybe orelse continue;
            if (!slot.stuck or slot.submission.operation != .send) continue;
            if (slot.submission.operation.send.peer == peer) stuck += 1;
        }
        assert(stuck <= self.table.?.get(peer).sends_in_flight);
        return stuck;
    }

    /// Stuck sends and receives in flight to `peer`. At most `slots_count` steps.
    fn stuckTo(self: *const Sim, peer: io.PeerId) u32 {
        assert(self.table != null); // Both name peers in a table.
        var stuck: u32 = 0;
        for (self.slots) |maybe| {
            const slot = maybe orelse continue;
            if (!slot.stuck) continue;
            // Only a send or a receive sticks.
            assert(slot.submission.operation == .send or slot.submission.operation == .receive);
            if (io.operationPeer(slot.submission.operation).? == peer) stuck += 1;
        }
        const entry = self.table.?.get(peer);
        assert(stuck <= @as(u32, entry.sends_in_flight) + @intFromBool(entry.receiving));
        return stuck;
    }

    /// A new slot as its connection's state leaves it. A send to a dropped connection is
    /// PeerDown; a send to a connection with a send stuck already sticks too, as every
    /// later send on a socket whose client stopped reading waits on the real type; any
    /// other send sticks at the drawn chance. A receive is settled by `fatedReceive`, and a
    /// cancel reaches what is in flight to its connection (`cancelReach`). The stick roll
    /// comes from its own stream, drawn for every send and receive while sticking is on, so
    /// neither drops nor other connections' states change which operations stick.
    fn fated(self: *Sim, slot: Slot) Slot {
        var result = slot;
        const send = switch (slot.submission.operation) {
            .send => |send| send,
            .receive => return self.fatedReceive(slot),
            .cancel => |cancel| {
                result.drawn = .{ .cancel = self.cancelReach(cancel.peer) };
                return result;
            },
            .execute, .accept => return result,
        };
        const stuck_before = self.sends_stuck;
        const rolled = self.stickRoll();
        if (self.isDropped(send.peer)) {
            result.drawn = .{ .send = error.PeerDown };
            result.by_drop = true;
        } else if (rolled or self.stuckSendsTo(send.peer) > 0) {
            result.stuck = true;
            self.sends_stuck += 1;
        }
        assert(result.by_drop == self.isDropped(send.peer));
        assert(self.sends_stuck == stuck_before + @intFromBool(result.stuck));
        return result;
    }

    /// A new receive's slot: on a dropped connection it ends as a drop ends one; otherwise
    /// it sticks at the drawn chance (a client gone silent), or takes the bytes it drew from
    /// its client's stream, which land in its buffer at completion.
    fn fatedReceive(self: *Sim, slot: Slot) Slot {
        var result = slot;
        const receive = slot.submission.operation.receive;
        const read_before = self.streamRead(receive.peer);
        const rolled = self.stickRoll();
        if (self.isDropped(receive.peer)) {
            result.drawn = self.endedByDrop(.receive);
            result.by_drop = true;
        } else if (rolled) {
            result.stuck = true;
            self.receives_stuck += 1;
        } else {
            // A reset or a client that closed early has sent its last byte: the rest of its
            // stream is gone, so every later receive reads end of stream.
            const left: u32 = @intCast(self.client_stream.?.len - read_before);
            const ends = if (slot.drawn.receive) |count| count == 0 else |err| err == error.PeerDown;
            const count = slot.drawn.receive catch 0;
            result.stream_at = self.streamTake(receive.peer, count);
            if (ends) _ = self.streamTake(receive.peer, left - count);
        }
        // Only bytes that will land are taken from the stream, or all of it when it ends.
        const taken = self.streamRead(receive.peer) - read_before;
        assert(taken == 0 or !(result.stuck or result.by_drop));
        assert(taken <= self.client_stream.?.len - read_before);
        return result;
    }

    /// How much of its client's stream `peer`'s connection has received; 0 for a
    /// connection that hasn't received yet, a new one on its entry included.
    fn streamRead(self: *const Sim, peer: io.PeerId) u32 {
        const stream = self.client_stream.?; // `submit` checked it for every receive.
        const parts: connections.IdParts = @bitCast(peer);
        assert(parts.index < constants.http_connections_max);
        if (self.stream_ids[parts.index] != peer) return 0;
        const read = self.stream_read[parts.index];
        assert(read <= stream.len);
        return read;
    }

    /// Takes `count` bytes of `peer`'s client stream, starting a new connection's stream
    /// from its first byte, and returns where they start.
    fn streamTake(self: *Sim, peer: io.PeerId, count: u32) u32 {
        const at = self.streamRead(peer);
        const parts: connections.IdParts = @bitCast(peer);
        // `drawReceive` never draws past what is left.
        assert(count <= self.client_stream.?.len - at);
        self.stream_ids[parts.index] = peer;
        self.stream_read[parts.index] = at + count;
        assert(self.streamRead(peer) == at + count);
        return at;
    }

    /// One roll of the stick stream at `stick_percent`; draws nothing while it is 0, so a
    /// run that never sticks leaves the stream untouched.
    fn stickRoll(self: *Sim) bool {
        assert(self.stick_percent <= constants.sim_fault_percent_max);
        if (self.stick_percent == 0) return false;
        const roll = self.stick_source.random().uintLessThan(u8, 100);
        assert(roll < 100);
        return roll < self.stick_percent;
    }

    /// One roll of the drop stream at `percent`, at most 100; draws nothing at 0.
    fn chance(self: *Sim, percent: u8) bool {
        assert(percent <= 100);
        if (percent == 0) return false;
        const roll = self.drop_source.random().uintLessThan(u8, 100);
        assert(roll < 100);
        return roll < percent;
    }

    /// The contract says ids in flight are distinct, so a caller that reuses one has a bug:
    /// its two completions would be indistinguishable. Scans every slot, at most
    /// `slots_count` steps, and crashes on a match. Changes no state.
    fn assertIdNotInFlight(self: *const Sim, id: io.OperationId) void {
        var occupied: u32 = 0;
        var sends: u32 = 0;
        var accepts: u32 = 0;
        var cancels: u32 = 0;
        var index: u32 = 0;
        while (index < slots_count) : (index += 1) {
            const slot = self.slots[index] orelse continue;
            occupied += 1;
            if (slot.submission.operation == .send) sends += 1;
            if (slot.submission.operation == .accept) accepts += 1;
            if (slot.submission.operation == .cancel) cancels += 1;
            assert(slot.submission.id != id);
        }
        // The count of occupied slots, `in_flight`, `sends_in_flight` and the shares kept
        // for accepts and cancels are kept separately; they must agree.
        assert(occupied == self.in_flight);
        assert(sends == self.sends_in_flight);
        assert(occupied - accepts - cancels == self.share.others_in_flight);
        assert(accepts == self.share.accepts_in_flight);
        assert(cancels == self.share.cancels_in_flight);
    }

    /// Takes a free slot, scanning from a seeded offset.
    fn freeSlot(self: *Sim) u32 {
        assert(self.in_flight < slots_count);
        const start = self.schedule.random().uintLessThan(u32, slots_count);
        var step: u32 = 0;
        while (step < slots_count) : (step += 1) {
            if (self.slots[(start + step) % slots_count] == null) break;
        }
        // Fewer than slots_count operations are in flight, so the scan found a free slot.
        assert(step < slots_count);
        return (start + step) % slots_count;
    }

    fn draw(self: *Sim, operation: io.Operation) Drawn {
        assert(self.fault_percent <= constants.sim_fault_percent_max);
        const result: Drawn = switch (operation) {
            .send => |send| .{ .send = self.drawSend(send) },
            .execute => .{ .execute = self.drawExecute() },
            .accept => .{ .accept = self.drawArrival() },
            .receive => |receive| .{ .receive = self.drawReceive(receive) },
            // What a cancel reaches depends on what is in flight, not on a draw (`fated`).
            .cancel => .{ .cancel = 0 },
        };
        assert(@as(io.Kind, result) == @as(io.Kind, operation));
        return result;
    }

    /// A send fails, completes short, or sends every byte.
    fn drawSend(self: *Sim, send: io.Send) io.SendError!u32 {
        assert(send.bytes.len > 0);
        assert(send.bytes.len <= constants.http_response_size_max);
        const length: u32 = @intCast(send.bytes.len);
        if (self.fault()) {
            if (self.outcomes.random().boolean()) return error.PeerDown;
            return error.Backpressure;
        }
        if (length > 1 and self.fault()) {
            return 1 + self.outcomes.random().uintLessThan(u32, length - 1);
        }
        return length;
    }

    /// A receive's connection resets, the system is short, or its client closes early as a
    /// fault; otherwise it reads 1 to the least of its buffer, what its client has left and
    /// `receive_chunk_max`, or end of stream once its client has sent everything.
    fn drawReceive(self: *Sim, receive: io.Receive) io.ReceiveError!u32 {
        assert(receive.buffer.len > 0);
        assert(receive.buffer.len <= constants.http_request_size_max);
        const left: u32 = @intCast(self.client_stream.?.len - self.streamRead(receive.peer));
        // Every receive makes the same draws, whatever its connection's state, so a drop or
        // a stuck receive never shifts a later operation's draws: whether it faults, which
        // fault, and a raw count scaled into what is left.
        const faulted = self.fault();
        const which = self.outcomes.random().uintLessThan(u8, 3);
        const raw = self.outcomes.random().int(u32);
        if (faulted) {
            return switch (which) {
                0 => error.PeerDown,
                1 => error.Backpressure,
                else => 0, // The client closes before it has sent everything.
            };
        }
        if (left == 0) return 0;
        const most = @min(@min(left, self.receive_chunk_max), @as(u32, @intCast(receive.buffer.len)));
        assert(most > 0);
        // Multiply-high: `raw` scaled into 0 to most - 1, with no rejection loop.
        const count: u32 = 1 + @as(u32, @intCast((@as(u64, raw) * most) >> 32));
        assert(count >= 1 and count <= most);
        return count;
    }

    fn drawExecute(self: *Sim) io.DatabaseError!void {
        assert(self.fault_percent <= constants.sim_fault_percent_max);
        assert(self.in_flight < slots_count);
        if (self.fault()) {
            if (self.outcomes.random().boolean()) return error.Unavailable;
            return error.Timeout;
        }
    }

    /// An accept's connection fails before it arrives, the system is short, or it arrives.
    fn drawArrival(self: *Sim) ArrivalError!void {
        assert(self.fault_percent <= constants.sim_fault_percent_max);
        assert(self.table != null);
        if (self.fault()) {
            if (self.outcomes.random().boolean()) return error.PeerDown;
            return error.Backpressure;
        }
    }

    fn fault(self: *Sim) bool {
        assert(self.fault_percent <= constants.sim_fault_percent_max);
        const roll = self.outcomes.random().uintLessThan(u8, 100);
        assert(roll < 100);
        return roll < self.fault_percent;
    }

    /// Turns a slot's drawn outcome into its result and counts it. Crashes if the caller
    /// changed the operation's bytes while it was in flight.
    fn complete(self: *Sim, slot: Slot) io.Completion {
        assert(self.completed < self.submitted);
        assert(hashOperation(slot.submission.operation) == slot.bytes_hash);
        self.share.released(slot.submission.operation);
        // The table refused to release the peer while this was counted, so the id is still
        // live; `operationCompleted` crashes if it isn't.
        if (io.operationPeer(slot.submission.operation) != null) {
            self.table.?.operationCompleted(slot.submission.operation);
        }
        const result: io.Result = switch (slot.drawn) {
            .send => |sent| sent: {
                assert(self.sends_in_flight > 0); // Counted at submit.
                self.sends_in_flight -= 1;
                self.countSendEnd(slot, sent);
                break :sent .{ .send = sent };
            },
            .execute => |executed| executed: {
                self.countExecute(executed);
                break :executed .{ .execute = executed };
            },
            .accept => |arrival| .{ .accept = self.arrive(arrival) },
            .receive => |received| .{ .receive = self.land(slot, received) },
            .cancel => |reached| cancel: {
                self.cancels += 1;
                break :cancel .{ .cancel = reached };
            },
        };
        assert(@as(io.Kind, result) == @as(io.Kind, slot.submission.operation));
        self.completed += 1;
        return .{ .id = slot.submission.id, .result = result };
    }

    /// Counts how a send ended: by a drop, by a cancel, or as drawn.
    fn countSendEnd(self: *Sim, slot: Slot, sent: io.SendError!u32) void {
        const send = slot.submission.operation.send;
        // A drop ends a send only with PeerDown, and a cancel only with Canceled.
        assert(!slot.by_drop or sent == error.PeerDown);
        assert(slot.by_cancel == (sent == error.Canceled));
        if (slot.by_drop) {
            self.sends_dropped += 1;
        } else if (slot.by_cancel) {
            self.table.?.assertCanceled(send.peer); // The check the real type makes.
            self.canceled += 1;
        } else self.countSend(sent, send);
    }

    /// A receive's result: its drawn bytes copied from its client's stream into its buffer,
    /// or how a fault, a drop or a cancel ended it, each counted.
    fn land(self: *Sim, slot: Slot, received: io.ReceiveError!u32) io.ReceiveError!u32 {
        const receive = slot.submission.operation.receive;
        assert(!slot.by_cancel or received == error.Canceled);
        assert(slot.by_cancel == (received == error.Canceled));
        const faults_before = self.faults.total();
        const count = received catch |err| {
            if (slot.by_drop) {
                self.receives_dropped += 1;
            } else switch (err) {
                error.PeerDown => self.faults.receive_peer_down += 1,
                error.Backpressure => self.faults.receive_backpressure += 1,
                error.Canceled => {
                    self.table.?.assertCanceled(receive.peer); // The check the real type makes.
                    self.canceled += 1;
                },
            }
            return err;
        };
        if (count == 0) {
            if (slot.by_drop) {
                self.receives_dropped += 1;
            } else if (slot.stream_at < self.client_stream.?.len) {
                self.faults.receive_closed_early += 1;
            } else self.receives_ended += 1;
            return 0;
        }
        assert(!slot.by_drop and !slot.by_cancel);
        const stream = self.client_stream.?;
        assert(slot.stream_at + count <= stream.len); // Taken from the stream at submit.
        @memcpy(receive.buffer[0..count], stream[slot.stream_at..][0..count]);
        self.bytes_received += count;
        assert(self.faults.total() == faults_before);
        return count;
    }

    /// An arrival takes a table entry under a fresh fake socket; a full table refuses it and
    /// counts the refusal, and a drawn fault is counted and handed back.
    fn arrive(self: *Sim, arrival: ArrivalError!void) io.AcceptError!io.PeerId {
        assert(self.table != null); // `submit` checked it for every accept.
        const table = self.table.?;
        const faults_before = self.faults.total();
        const resume_before = self.accept_wait.resume_at;
        arrival catch |err| {
            switch (err) {
                error.PeerDown => self.faults.accept_peer_down += 1,
                error.Backpressure => {
                    self.faults.accept_backpressure += 1;
                    // Starts the wait, or starts it again, as the real type does.
                    self.accept_wait.begin(self.now_ns);
                },
            }
            // Only Backpressure touches the wait, as on the real type.
            assert(err == error.Backpressure or std.meta.eql(self.accept_wait.resume_at, resume_before));
            assert(self.faults.total() == faults_before + 1);
            return err;
        };
        const arrivals = self.accepted + self.refused;
        assert(arrivals < arrivals_max);
        const socket: io.Socket = socket_first + @as(io.Socket, @intCast(arrivals));
        const peer = table.acquire(socket) catch |err| switch (err) {
            error.TableFull => {
                self.refused += 1;
                assert(self.accepted + self.refused == arrivals + 1);
                return error.TableFull;
            },
        };
        self.accepted += 1;
        assert(table.get(peer).socket == socket);
        assert(self.faults.total() == faults_before);
        return peer;
    }

    fn countSend(self: *Sim, sent: io.SendError!u32, send: io.Send) void {
        assert(send.bytes.len > 0);
        const faults_before = self.faults.total();
        const bytes = sent catch |err| {
            switch (err) {
                error.PeerDown => self.faults.peer_down += 1,
                error.Backpressure => self.faults.backpressure += 1,
                error.Canceled => unreachable, // `countSendEnd` counts those.
            }
            assert(self.faults.total() == faults_before + 1);
            return;
        };
        assert(bytes > 0 and bytes <= send.bytes.len);
        if (bytes < send.bytes.len) self.short_sends += 1;
        self.bytes_sent += bytes;
    }

    fn countExecute(self: *Sim, executed: io.DatabaseError!void) void {
        const faults_before = self.faults.total();
        executed catch |err| {
            switch (err) {
                error.Unavailable => self.faults.unavailable += 1,
                error.Timeout => self.faults.timeout += 1,
            }
            assert(self.faults.total() == faults_before + 1);
            return;
        };
        self.statements += 1;
        assert(self.faults.total() == faults_before);
    }
};

/// Preconditions on an operation: a caller that breaks one has a bug, so these assert.
fn assertOperation(operation: io.Operation) void {
    switch (operation) {
        .send => |send| {
            const peer: connections.IdParts = @bitCast(send.peer);
            assert(peer.index < constants.http_connections_max);
            assert(send.bytes.len > 0);
            assert(send.bytes.len <= constants.http_response_size_max);
        },
        .execute => |execute| {
            assert(execute.statement.len > 0);
            assert(execute.statement.len <= constants.postgres_message_size_max);
        },
        .accept => |accept| assert(accept.listener >= 0),
        .receive => |receive| {
            const peer: connections.IdParts = @bitCast(receive.peer);
            assert(peer.index < constants.http_connections_max);
            assert(receive.buffer.len > 0);
            assert(receive.buffer.len <= constants.http_request_size_max);
        },
        .cancel => |cancel| {
            const peer: connections.IdParts = @bitCast(cancel.peer);
            assert(peer.index < constants.http_connections_max);
        },
    }
}

/// An accept and a cancel name no caller bytes; the listener or the peer is hashed, so every
/// kind is checked alike. A receive's buffer is hashed as `submit` poisoned it.
fn hashOperation(operation: io.Operation) u64 {
    const bytes: []const u8 = switch (operation) {
        .send => |send| send.bytes,
        .execute => |execute| execute.statement,
        .accept => |*accept| std.mem.asBytes(&accept.listener),
        .receive => |receive| receive.buffer,
        .cancel => |*cancel| std.mem.asBytes(&cancel.peer),
    };
    assert(bytes.len > 0);
    assert(bytes.len <= @max(constants.http_response_size_max, constants.postgres_message_size_max));
    return std.hash.Wyhash.hash(0, bytes);
}

/// Stops the build when a program that isn't a test or a declared simulation uses a `Sim`,
/// because its seeded random bytes would make every nonce predictable. A function body is
/// analyzed only when something calls it, so the check sits in each entry point.
fn assertSimulationAllowed() void {
    comptime {
        assert(@TypeOf(builtin.is_test) == bool);
        if (!builtin.is_test) {
            const root = @import("root");
            if (!@hasDecl(root, "io_simulation") or !root.io_simulation) {
                @compileError("io.sim.Sim is for tests and simulations only: declare " ++
                    "`pub const io_simulation = true;` in the simulation's root file");
            }
        }
        assert(builtin.is_test or @hasDecl(@import("root"), "io_simulation"));
    }
}

const testing = std.testing;

const recorded_max: u32 = 512;
const record_ticks_max: u32 = recorded_max + constants.sim_completion_delay_ticks_max + 1;

const Recording = struct {
    ids: [recorded_max]io.OperationId,
    /// The tick each operation was submitted and completed on, by id.
    submitted_tick: [recorded_max]u32,
    completed_tick: [recorded_max]u32,
    count: u32,
    sim: Sim,
};

/// Submits `recorded_max` operations, alternating sends and statements, at two per tick,
/// and records the order and the ticks their completions come back on. The sends go to
/// `fixture`'s peers, which must outlive the recording; every send is uncounted again
/// once its completion has come back.
fn record(fixture: *TableFixture, seed: u64, fault_percent: u8) !Recording {
    var recording: Recording = .{
        .ids = @splat(0),
        .submitted_tick = @splat(0),
        .completed_tick = @splat(0),
        .count = 0,
        .sim = .init(seed, fault_percent),
    };
    recording.sim.attachTable(&fixture.table);
    var next: io.OperationId = 0;
    var ticks: u32 = 0;
    while (ticks < record_ticks_max and recording.count < recorded_max) : (ticks += 1) {
        if (next < recorded_max) {
            // Two submissions per tick for at most 17 ticks stay far below the table's size.
            try recording.sim.submit(testSubmission(next));
            try recording.sim.submit(testSubmission(next + 1));
            recording.submitted_tick[@intCast(next)] = recording.sim.ticks;
            recording.submitted_tick[@intCast(next + 1)] = recording.sim.ticks;
            next += 2;
        }
        recording.sim.tick();
        drainInto(&recording);
    }
    assert(ticks <= record_ticks_max);
    assert(recording.count == recorded_max);
    assert(recording.sim.in_flight == 0);
    try fixture.expectNoSendsCounted();
    return recording;
}

fn drainInto(recording: *Recording) void {
    assert(recording.count <= recorded_max);
    var completions: [16]io.Completion = undefined;
    var batches: u32 = 0;
    while (batches < slots_count) : (batches += 1) {
        const count = recording.sim.poll(&completions);
        for (completions[0..count]) |completion| {
            recording.ids[recording.count] = completion.id;
            recording.completed_tick[@intCast(completion.id)] = recording.sim.ticks;
            recording.count += 1;
        }
        if (count == 0) break;
    }
    assert(batches < slots_count);
}

/// Even ids are sends to peer `id % test_peers` (so to the even-numbered peers only), and
/// odd ids are statements.
fn testSubmission(id: io.OperationId) io.Submission {
    assert(id <= recorded_max + slots_count);
    const operation: io.Operation = if (id % 2 == 0)
        .{ .send = .{ .peer = @intCast(id % test_peers), .bytes = "ping" } }
    else
        .{ .execute = .{ .statement = "select 1" } };
    const expected: io.Kind = if (id % 2 == 0) .send else .execute;
    assert(@as(io.Kind, operation) == expected);
    return .{ .id = id, .operation = operation };
}

/// The submission each id fills a whole table with: `testSubmission` within the share kept
/// from accepts and cancels, a cancel of one of the entries past the test peers in each
/// slot kept for cancels, and an accept in each slot past those. Needs a table of
/// `full_peers` entries.
fn fullSubmission(id: io.OperationId) io.Submission {
    assert(id < slots_count);
    // The share leaves at least one slot for the cancels and one for the accepts.
    comptime assert(shared_slots_max + constants.io_cancels_in_flight_max < slots_count);
    if (id < shared_slots_max) return testSubmission(id);
    const cancel = id - shared_slots_max;
    if (cancel < constants.io_cancels_in_flight_max) {
        return .{ .id = id, .operation = .{ .cancel = .{ .peer = test_peers + cancel } } };
    }
    return .{ .id = id, .operation = .{ .accept = .{ .listener = test_listener } } };
}

test "sim: same seed, same completion order and counts" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    const a = try record(&fixture, 42, 20);
    const b = try record(&fixture, 42, 20);
    try testing.expectEqualSlices(io.OperationId, &a.ids, &b.ids);
    try testing.expectEqual(a.sim.faults, b.sim.faults);
    try testing.expectEqual(a.sim.bytes_sent, b.sim.bytes_sent);
    try testing.expectEqual(a.sim.statements, b.sim.statements);
    const c = try record(&fixture, 43, 20);
    try testing.expect(!std.mem.eql(io.OperationId, &a.ids, &c.ids));
}

test "sim: delays reorder completions within the bound, each operation once" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    const run = try record(&fixture, 7, 0);
    var seen: [recorded_max]bool = @splat(false);
    var reordered = false;
    for (run.ids[0..run.count], 0..) |id, index| {
        try testing.expect(id < recorded_max);
        try testing.expect(!seen[@intCast(id)]);
        seen[@intCast(id)] = true;
        if (index > 0 and id < run.ids[index - 1]) reordered = true;
        // Never before the tick after submission, never later than the longest delay.
        const waited = run.completed_tick[@intCast(id)] - run.submitted_tick[@intCast(id)];
        try testing.expect(waited >= 1);
        try testing.expect(waited <= constants.sim_completion_delay_ticks_max);
    }
    try testing.expect(reordered);
    try testing.expectEqual(@as(u64, recorded_max), run.sim.completed);
    try testing.expectEqual(run.sim.submitted, run.sim.completed);
}

test "sim: a seeded run injects every fault kind and short sends" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    const run = try record(&fixture, 1, constants.sim_fault_percent_max);
    try testing.expect(run.sim.faults.peer_down > 0);
    try testing.expect(run.sim.faults.backpressure > 0);
    try testing.expect(run.sim.faults.unavailable > 0);
    try testing.expect(run.sim.faults.timeout > 0);
    try testing.expect(run.sim.short_sends > 0);
    try testing.expect(run.sim.faults.total() <= run.sim.completed);
}

test "sim: time moves only on tick" {
    var sim = Sim.init(1, 0);
    try testing.expectEqual(@as(io.Instant, 0), sim.now());
    sim.tick();
    try testing.expectEqual(constants.tick_ns, sim.now());
}

test "sim: a poll with nothing due returns 0 and changes nothing" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(5, 0);
    sim.attachTable(&fixture.table);
    var completions: [4]io.Completion = undefined;
    try testing.expectEqual(@as(u32, 0), sim.poll(&completions));
    try sim.submit(testSubmission(0));
    var polls: u32 = 0;
    while (polls <= constants.sim_completion_delay_ticks_max) : (polls += 1) {
        // An operation is due only once its delay has passed; until then nothing changes.
        const count = sim.poll(&completions);
        if (count == 1) break;
        try testing.expectEqual(@as(u32, 0), count);
        try testing.expectEqual(@as(u32, 1), sim.in_flight);
        try testing.expectEqual(@as(u64, 0), sim.completed);
        sim.tick();
    }
    try testing.expect(polls <= constants.sim_completion_delay_ticks_max);
    try testing.expectEqual(@as(u32, 0), sim.in_flight);
    try testing.expectEqual(@as(u64, 1), sim.completed);
}

test "sim: a zero fault rate never fails and never sends short" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(7, 0);
    sim.attachTable(&fixture.table);
    try sim.submit(.{ .id = 1, .operation = .{ .send = .{ .peer = 0, .bytes = "hello" } } });
    try sim.submit(.{ .id = 2, .operation = .{ .execute = .{ .statement = "select 1" } } });
    var completions: [4]io.Completion = undefined;
    var count: u32 = 0;
    var ticks: u32 = 0;
    while (ticks <= constants.sim_completion_delay_ticks_max) : (ticks += 1) {
        sim.tick();
        count += sim.poll(completions[count..]);
    }
    try testing.expectEqual(@as(u32, 2), count);
    for (completions[0..count]) |completion| switch (completion.result) {
        .send => |sent| try testing.expectEqual(@as(u32, 5), try sent),
        .execute => |executed| try executed,
        // Nothing here submits an accept, a receive or a cancel.
        .accept, .receive, .cancel => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(@as(u64, 0), sim.faults.total());
    try testing.expectEqual(@as(u64, 5), sim.bytes_sent);
    try testing.expectEqual(@as(u32, 0), sim.short_sends);
}

test "sim: a full table refuses a submission and changes nothing" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(full_peers);
    defer fixture.tearDown();
    var sim = Sim.init(3, 0);
    sim.attachTable(&fixture.table);
    var id: io.OperationId = 0;
    while (id < slots_count) : (id += 1) try sim.submit(fullSubmission(id));
    // The refused submission is a send to peer 0, which holds every eighth id's send: it
    // must not be counted on the entry.
    const refused = testSubmission(id);
    try testing.expectEqual(io.Kind.send, @as(io.Kind, refused.operation));
    const entry_before = fixture.table.get(refused.operation.send.peer).*;
    const peer_sends = (shared_slots_max + test_peers - 1) / test_peers;
    try testing.expectEqual(@as(connections.SendCount, peer_sends), entry_before.sends_in_flight);
    try testing.expectError(error.QueueFull, sim.submit(refused));
    // A full queue wins over a full share, for a cancel as for a send.
    const cancel: io.Submission = .{ .id = id, .operation = .{ .cancel = .{ .peer = test_peers - 1 } } };
    try testing.expectError(error.QueueFull, sim.submit(cancel));
    try testing.expectEqual(entry_before, fixture.table.get(refused.operation.send.peer).*);
    try testing.expectEqual(slots_count, sim.in_flight);
    try testing.expectEqual(@as(u64, slots_count), sim.submitted);

    var completions: [1]io.Completion = undefined;
    var ticks: u32 = 0;
    while (ticks <= constants.sim_completion_delay_ticks_max) : (ticks += 1) sim.tick();
    try testing.expectEqual(@as(u32, 1), sim.poll(&completions));
    // The freed slot takes the kind that left it: an accept's slot stays kept for accepts,
    // and a cancel's for cancels.
    try sim.submit(fullSubmission(completions[0].id));
    try testing.expectEqual(slots_count, sim.in_flight);
}

test "sim: past the share kept from accepts, a send and a statement are refused and an accept still goes in" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(full_peers);
    defer fixture.tearDown();
    var sim = Sim.init(5, 0);
    sim.attachTable(&fixture.table);
    // The share filled with sends and statements alike: both count against it.
    var id: io.OperationId = 0;
    while (id < shared_slots_max) : (id += 1) try sim.submit(testSubmission(id));
    try testing.expectEqual(shared_slots_max, sim.share.others_in_flight);
    try testing.expectEqual(shared_slots_max - shared_slots_max / 2, sim.sends_in_flight);
    // Neither refusal may count a send on its peer's entry, take a slot or draw anything.
    // Peer 0 holds every eighth id's send.
    const entry_before = fixture.table.get(0).*;
    try testing.expectEqual(@as(connections.SendCount, shared_slots_max / test_peers + 1), entry_before.sends_in_flight);
    const slots_before = sim.slots;
    const outcomes_before = sim.outcomes.s;
    const send: io.Submission = .{ .id = id, .operation = .{ .send = .{ .peer = 0, .bytes = "s" } } };
    const statement: io.Submission = .{ .id = id, .operation = .{ .execute = .{ .statement = "select 1" } } };
    try testing.expectError(error.SlotsKeptForAccepts, sim.submit(send));
    try testing.expectError(error.SlotsKeptForAccepts, sim.submit(statement));
    try testing.expectEqual(entry_before, fixture.table.get(0).*);
    try testing.expectEqual(shared_slots_max, sim.in_flight);
    try testing.expectEqual(shared_slots_max, sim.share.others_in_flight);
    try testing.expectEqual(@as(u64, shared_slots_max), sim.submitted);
    try testing.expectEqualDeep(slots_before, sim.slots);
    try testing.expectEqual(outcomes_before, sim.outcomes.s);

    // The operations kept back take an accept and the cancels; then the table is full for
    // every kind. A second accept would pass `constants.accepts_in_flight_max`, a caller's
    // bug that stops the process before the queue is checked (the startup-trip harness
    // covers it).
    const accept: io.Submission = .{ .id = id, .operation = .{ .accept = .{ .listener = test_listener } } };
    try sim.submit(accept);
    try testing.expectEqual(shared_slots_max + 1, sim.in_flight);
    var cancel: u32 = 0;
    while (cancel < constants.io_cancels_in_flight_max) : (cancel += 1) {
        // Ids past any the test hands out elsewhere.
        const cancel_id: io.OperationId = 2 * slots_count + cancel;
        try sim.submit(.{ .id = cancel_id, .operation = .{ .cancel = .{ .peer = test_peers + cancel } } });
    }
    try testing.expectEqual(slots_count, sim.in_flight);
    try testing.expectEqual(constants.io_cancels_in_flight_max, sim.share.cancels_in_flight);
    try testing.expectEqual(shared_slots_max, sim.share.others_in_flight);
    try testing.expectEqual(constants.accepts_in_flight_max, sim.share.accepts_in_flight);
    try testing.expectError(error.QueueFull, sim.submit(.{ .id = id + 1, .operation = statement.operation }));
    try testing.expectError(error.QueueFull, sim.submit(.{ .id = id + 1, .operation = send.operation }));

    // Every operation completes and is uncounted, from the share and from its peer.
    var completions: [slots_count]io.Completion = undefined;
    var ticks: u32 = 0;
    while (ticks <= constants.sim_completion_delay_ticks_max) : (ticks += 1) sim.tick();
    try testing.expectEqual(slots_count, sim.poll(&completions));
    try testing.expectEqual(@as(u32, 0), sim.sends_in_flight);
    try testing.expectEqual(@as(u32, 0), sim.share.others_in_flight);
    try testing.expectEqual(@as(u32, 0), sim.share.accepts_in_flight);
    try testing.expectEqual(@as(u32, 0), sim.share.cancels_in_flight);
    try testing.expectEqual(@as(u32, 0), sim.in_flight);
    try fixture.expectNoSendsCounted();
}

test "sim: an accept counts against no share, so a send still takes the share's last place" {
    // The share counts operations, not free slots: with an accept in flight beside one
    // operation fewer than the share, the share's last place goes to a send.
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(6, 0);
    sim.attachTable(&fixture.table);
    try sim.submit(.{ .id = 0, .operation = .{ .accept = .{ .listener = test_listener } } });
    var id: io.OperationId = 1;
    while (id < shared_slots_max) : (id += 1) try sim.submit(testSubmission(id));
    try testing.expectEqual(shared_slots_max, sim.in_flight);
    try testing.expectEqual(shared_slots_max - 1, sim.share.others_in_flight);
    try sim.submit(.{ .id = id, .operation = .{ .send = .{ .peer = 1, .bytes = "s" } } });
    try testing.expectEqual(shared_slots_max + 1, sim.in_flight);
    try testing.expectEqual(shared_slots_max, sim.share.others_in_flight);

    // Once the accept completes, its slot is free but kept: a statement is refused, and
    // another accept takes it.
    var completions: [slots_count]io.Completion = undefined;
    var ticks: u32 = 0;
    var accept_done = false;
    while (ticks <= constants.sim_completion_delay_ticks_max and !accept_done) : (ticks += 1) {
        sim.tick();
        const count = sim.poll(&completions);
        for (completions[0..count]) |completion| {
            if (completion.result == .accept) accept_done = true;
            // Anything else that completes is put straight back, so only the accept's
            // slot is free afterwards.
            if (completion.result != .accept) try sim.submit(testSubmission(completion.id));
        }
    }
    try testing.expect(accept_done);
    try testing.expectEqual(shared_slots_max, sim.in_flight);
    try testing.expectEqual(shared_slots_max, sim.share.others_in_flight);
    const statement: io.Submission = .{ .id = id + 1, .operation = .{ .execute = .{ .statement = "select 1" } } };
    try testing.expectError(error.SlotsKeptForAccepts, sim.submit(statement));
    try sim.submit(.{ .id = id + 1, .operation = .{ .accept = .{ .listener = test_listener } } });
    try testing.expectEqual(shared_slots_max + 1, sim.in_flight);
}

test "sim: an id may be reused once its operation has completed" {
    // Ids need be distinct only while in flight. With every other slot still full, the id
    // that just completed is accepted again, three times over.
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(full_peers);
    defer fixture.tearDown();
    var sim = Sim.init(17, 0);
    sim.attachTable(&fixture.table);
    var id: io.OperationId = 0;
    while (id < slots_count) : (id += 1) try sim.submit(fullSubmission(id));
    var completions: [1]io.Completion = undefined;
    var ticks: u32 = 0;
    while (ticks <= constants.sim_completion_delay_ticks_max) : (ticks += 1) sim.tick();
    var round: u32 = 0;
    while (round < 3) : (round += 1) {
        try testing.expectEqual(@as(u32, 1), sim.poll(&completions));
        try testing.expectEqual(slots_count - 1, sim.in_flight);
        const reused = completions[0].id;
        try testing.expect(reused < slots_count);
        try sim.submit(fullSubmission(reused));
        try testing.expectEqual(slots_count, sim.in_flight);
    }
    try testing.expectEqual(@as(u64, 3), sim.completed);
    try testing.expectEqual(@as(u64, slots_count + 3), sim.submitted);
}

test "sim: an operation submitted on the last tick still completes" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(13, 0);
    sim.attachTable(&fixture.table);
    var ticks: u32 = 0;
    while (ticks < constants.sim_ticks_max - 1) : (ticks += 1) sim.tick();
    try sim.submit(testSubmission(0));
    try sim.submit(testSubmission(1));
    sim.tick();
    try testing.expectEqual(constants.sim_ticks_max, sim.ticks);
    var completions: [2]io.Completion = undefined;
    try testing.expectEqual(@as(u32, 2), sim.poll(&completions));
    try testing.expectEqual(@as(u32, 0), sim.in_flight);
}

test "sim: same seed, same random bytes" {
    var a = Sim.init(9, 0);
    var b = Sim.init(9, 0);
    var c = Sim.init(10, 0);
    var bytes_a: [24]u8 = undefined;
    var bytes_b: [24]u8 = undefined;
    var bytes_c: [24]u8 = undefined;
    try a.randomBytes(&bytes_a);
    try b.randomBytes(&bytes_b);
    try c.randomBytes(&bytes_c);
    try testing.expectEqualSlices(u8, &bytes_a, &bytes_b);
    try testing.expect(!std.mem.eql(u8, &bytes_a, &bytes_c));
    try testing.expectEqual(@as(u64, 24), a.random_bytes);
}

test "sim: drawing random bytes and polling often leave outcomes unchanged" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    const plain = try record(&fixture, 11, constants.sim_fault_percent_max);
    // Same seed and submissions, but this run draws a nonce and polls before every tick too.
    var busy = Sim.init(11, constants.sim_fault_percent_max);
    busy.attachTable(&fixture.table);
    var completions: [16]io.Completion = undefined;
    var nonce: [24]u8 = undefined;
    var id: io.OperationId = 0;
    var ticks: u32 = 0;
    while (ticks < record_ticks_max) : (ticks += 1) {
        if (id < recorded_max) {
            try busy.submit(testSubmission(id));
            try busy.submit(testSubmission(id + 1));
            id += 2;
        }
        try busy.randomBytes(&nonce);
        _ = busy.poll(&completions);
        busy.tick();
        var batches: u32 = 0;
        while (batches < slots_count and busy.poll(&completions) > 0) : (batches += 1) {}
    }
    try testing.expectEqual(@as(u32, 0), busy.in_flight);
    try testing.expectEqual(plain.sim.completed, busy.completed);
    try testing.expectEqual(plain.sim.faults, busy.faults);
    try testing.expectEqual(plain.sim.short_sends, busy.short_sends);
    try testing.expectEqual(plain.sim.bytes_sent, busy.bytes_sent);
}

/// A small connection table for accept tests, set up in place because a `Sim` keeps a
/// pointer to it.
const TableFixture = struct {
    startup: StartupAllocator,
    gpa: std.mem.Allocator,
    table: connections.Table,

    fn setUp(self: *TableFixture, size: u32) !void {
        assert(size > 0);
        assert(size <= constants.http_connections_max);
        self.startup = .init(testing.allocator, @as(u64, size) * connections.entry_bytes);
        self.gpa = self.startup.allocator();
        self.table = try connections.Table.init(self.gpa, size);
        self.startup.finishStartup();
        assert(self.table.count() == 0);
    }

    /// A table of `size` entries, every one in use, for sends. A fresh table hands out
    /// entry 0 first, each under generation 0, so peer `n` is entry `n`, as
    /// `testSubmission` names it.
    fn setUpPeers(self: *TableFixture, size: u32) !void {
        try self.setUp(size);
        var index: u32 = 0;
        while (index < size) : (index += 1) {
            const peer = try self.table.acquire(peerSocket(index));
            assert(peer == index);
        }
        assert(index == size);
        assert(self.table.count() == size);
    }

    /// Every entry in use has no send counted, as when every send has completed.
    fn expectNoSendsCounted(self: *const TableFixture) !void {
        var checked: u32 = 0;
        for (self.table.entries) |entry| {
            if (entry.state == .free) continue;
            try testing.expectEqual(@as(connections.SendCount, 0), entry.sends_in_flight);
            checked += 1;
        }
        try testing.expectEqual(self.table.count(), checked);
    }

    fn tearDown(self: *TableFixture) void {
        assert(self.table.capacity() > 0);
        self.startup.beginShutdown();
        self.table.deinit(self.gpa);
        assert(self.startup.bytes_live == 0);
    }
};

/// The peers the send tests name: `testSubmission` sends to peer `id % test_peers`.
const test_peers: u32 = 8;
/// The test peers, then one entry for each cancel `fullSubmission` keeps in flight, apart
/// from the peers sends go to, since a cancelled entry takes no more sends.
const full_peers: u32 = test_peers + constants.io_cancels_in_flight_max;

/// The fake socket a send test's entry holds: below any arrival's, and distinct per entry.
fn peerSocket(index: u32) io.Socket {
    assert(index < constants.http_connections_max);
    comptime assert(test_listener + 1 + constants.http_connections_max < socket_first);
    return test_listener + 1 + @as(io.Socket, @intCast(index));
}

const StartupAllocator = @import("../startup_allocator.zig").StartupAllocator;

fn acceptSubmission(id: io.OperationId) io.Submission {
    assert(id < slots_count); // The tests below keep at most a table's worth in flight.
    comptime assert(test_listener < socket_first);
    return .{ .id = id, .operation = .{ .accept = .{ .listener = test_listener } } };
}

const test_listener: io.Socket = 3;

/// Ticks until every operation in flight has completed, collecting at most
/// `completions.len` of them. Returns how many arrived.
fn drainAll(sim: *Sim, completions: []io.Completion) u32 {
    assert(completions.len > 0);
    assert(sim.in_flight <= completions.len);
    var count: u32 = 0;
    var ticks: u32 = 0;
    while (ticks <= constants.sim_completion_delay_ticks_max) : (ticks += 1) {
        sim.tick();
        if (count < completions.len) count += sim.poll(completions[count..]);
    }
    assert(sim.in_flight == 0);
    return count;
}

test "sim: accepts take table entries under fresh sockets until the table is full" {
    var fixture: TableFixture = undefined;
    try fixture.setUp(4);
    defer fixture.tearDown();
    var sim = Sim.init(21, 0);
    sim.attachTable(&fixture.table);
    // One accept in flight at a time, as `constants.accepts_in_flight_max` allows.
    var completions: [6]io.Completion = undefined;
    var id: io.OperationId = 0;
    while (id < 6) : (id += 1) {
        try sim.submit(acceptSubmission(id));
        try testing.expectEqual(@as(u32, 1), drainAll(&sim, completions[@intCast(id)..][0..1]));
    }

    var sockets_seen: [6]io.Socket = @splat(-1);
    var accepted: u32 = 0;
    var refused: u32 = 0;
    // Arrivals take entries in completion order, so a refusal may come only once all four
    // entries were taken: a refusal with room left fails here, not only in the totals.
    for (completions) |completion| {
        if (completion.result.accept) |peer| {
            try testing.expectEqual(@as(u32, 0), refused);
            const socket = fixture.table.get(peer).socket;
            try testing.expect(socket >= socket_first);
            try testing.expect(std.mem.findScalar(io.Socket, &sockets_seen, socket) == null);
            sockets_seen[accepted] = socket;
            accepted += 1;
        } else |err| {
            try testing.expectEqual(error.TableFull, err);
            try testing.expectEqual(@as(u32, 4), accepted);
            refused += 1;
        }
    }
    try testing.expectEqual(@as(u32, 4), accepted);
    try testing.expectEqual(@as(u32, 2), refused);
    try testing.expectEqual(@as(u64, 4), sim.accepted);
    try testing.expectEqual(@as(u64, 2), sim.refused);
    try testing.expectEqual(@as(u32, 4), fixture.table.count());
    try testing.expectEqual(@as(u64, 0), sim.faults.total());
    for (completions) |completion| {
        if (completion.result.accept) |peer| _ = try fixture.table.release(peer) else |_| {}
    }
}

/// Runs `ids.len` accepts at the largest fault rate into a table of `size`, one at a time
/// as `constants.accepts_in_flight_max` allows, waiting out each Backpressure by ticking.
/// Records each completion's id and outcome (the peer, or 1, 2 or 3 shifted past any peer
/// for TableFull, PeerDown and Backpressure) in completion order, and returns the
/// simulator.
fn acceptRun(seed: u64, size: u32, ids: []io.OperationId, results: []u64) !Sim {
    assert(ids.len == results.len);
    assert(ids.len <= slots_count);
    var fixture: TableFixture = undefined;
    try fixture.setUp(size);
    defer fixture.tearDown();
    var sim = Sim.init(seed, constants.sim_fault_percent_max);
    sim.attachTable(&fixture.table);
    var completions: [slots_count]io.Completion = undefined;
    var count: u32 = 0;
    for (ids, 0..) |_, index| {
        // Each accept drains before the next, so at most one wait runs, of `wait_ticks`.
        var ticks: u32 = 0;
        while (sim.accept_wait.resume_at) |resume_at| : (ticks += 1) {
            if (sim.now() >= resume_at) break;
            assert(ticks < wait_ticks);
            sim.tick();
        }
        try sim.submit(acceptSubmission(index));
        count += drainAll(&sim, completions[count..][0..1]);
    }
    try testing.expectEqual(@as(u32, @intCast(ids.len)), count);
    for (completions[0..count], ids, results) |completion, *id, *result| {
        id.* = completion.id;
        result.* = if (completion.result.accept) |peer| peer else |err| switch (err) {
            error.TableFull => 1 << 32,
            error.PeerDown => 2 << 32,
            error.Backpressure => 3 << 32,
        };
    }
    try testing.expectEqual(fixture.table.count(), @as(u32, @intCast(sim.accepted)));
    // Release every entry, so the fixture's shutdown sees a table it can free.
    for (completions[0..count]) |completion| {
        if (completion.result.accept) |peer| _ = try fixture.table.release(peer) else |_| {}
    }
    sim.table = null;
    return sim;
}

test "sim: same seed, same accepts, refusals and faults, in the same order" {
    const runs = 64;
    var ids_a: [runs]io.OperationId = undefined;
    var ids_b: [runs]io.OperationId = undefined;
    var ids_c: [runs]io.OperationId = undefined;
    var results_a: [runs]u64 = undefined;
    var results_b: [runs]u64 = undefined;
    var results_c: [runs]u64 = undefined;
    const a = try acceptRun(5, 16, &ids_a, &results_a);
    const b = try acceptRun(5, 16, &ids_b, &results_b);
    _ = try acceptRun(6, 16, &ids_c, &results_c);
    try testing.expectEqualSlices(io.OperationId, &ids_a, &ids_b);
    try testing.expectEqualSlices(u64, &results_a, &results_b);
    // One accept at a time completes in submission order, so another seed shows in the
    // outcomes, not the order.
    try testing.expectEqualSlices(io.OperationId, &ids_a, &ids_c);
    try testing.expect(!std.mem.eql(u64, &results_a, &results_c));
    try testing.expectEqual(a.faults, b.faults);
    try testing.expectEqual(a.refused, b.refused);
    // At a 50% fault rate, about 32 of 64 arrive, so 16 entries fill and the rest are
    // refused; both accept faults occur.
    try testing.expectEqual(@as(u64, 16), a.accepted);
    try testing.expect(a.refused > 0);
    try testing.expect(a.faults.accept_peer_down > 0);
    try testing.expect(a.faults.accept_backpressure > 0);
    try testing.expectEqual(@as(u64, runs), a.accepted + a.refused + a.faults.total());
}

/// Ticks in the wait after a Backpressure.
const wait_ticks: u32 = @intCast(constants.io_accept_backpressure_wait_ns / constants.tick_ns);

test "sim: after Backpressure an accept is refused until the wait is over, sends are not" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(11, 0);
    sim.attachTable(&fixture.table);
    sim.tick();
    // A connection that failed says nothing of the system's descriptors: no wait.
    try testing.expectError(error.PeerDown, sim.arrive(error.PeerDown));
    try testing.expectEqual(@as(?io.Instant, null), sim.accept_wait.resume_at);
    try testing.expectError(error.Backpressure, sim.arrive(error.Backpressure));
    const resume_at = sim.now() + constants.io_accept_backpressure_wait_ns;
    try testing.expectEqual(@as(?io.Instant, resume_at), sim.accept_wait.resume_at);

    // Refused through the last tick before the wait ends, drawing nothing and taking no
    // slot: only the refusal count changes.
    var ticks: u32 = 0;
    while (ticks < wait_ticks) : (ticks += 1) {
        var expected = sim;
        expected.accept_wait.refused += 1;
        try testing.expectError(error.AcceptTooSoon, sim.submit(acceptSubmission(0)));
        try testing.expectEqual(expected, sim);
        sim.tick();
    }
    try testing.expectEqual(@as(u64, wait_ticks), sim.accept_wait.refused);
    // A send isn't held back by the wait.
    try sim.submit(.{ .id = 1, .operation = .{ .send = .{ .peer = 0, .bytes = "s" } } });
    // On the tick the wait ends, the accept goes in and the wait is cleared.
    try testing.expectEqual(resume_at, sim.now());
    try sim.submit(acceptSubmission(0));
    try testing.expectEqual(@as(?io.Instant, null), sim.accept_wait.resume_at);
    try testing.expectEqual(@as(u32, 2), sim.in_flight);
    var completions: [2]io.Completion = undefined;
    try testing.expectEqual(@as(u32, 2), drainAll(&sim, &completions));
    try fixture.expectNoSendsCounted();
}

test "sim: a second Backpressure starts the wait again" {
    var fixture: TableFixture = undefined;
    try fixture.setUp(4);
    defer fixture.tearDown();
    var sim = Sim.init(12, 0);
    sim.attachTable(&fixture.table);
    try testing.expectError(error.Backpressure, sim.arrive(error.Backpressure));
    var ticks: u32 = 0;
    while (ticks < wait_ticks - 1) : (ticks += 1) sim.tick();
    try testing.expectError(error.Backpressure, sim.arrive(error.Backpressure));
    // The first wait would end on the next tick; the second still runs then.
    sim.tick();
    try testing.expectError(error.AcceptTooSoon, sim.submit(acceptSubmission(0)));
    ticks = 0;
    while (ticks < wait_ticks - 1) : (ticks += 1) sim.tick();
    try sim.submit(acceptSubmission(0));
    try testing.expectEqual(@as(u64, 1), sim.accept_wait.refused);
    var completions: [1]io.Completion = undefined;
    try testing.expectEqual(@as(u32, 1), drainAll(&sim, &completions));
    _ = try fixture.table.release(try completions[0].result.accept);
}

test "sim: with the share full, the slot kept for accepts still waits out a Backpressure" {
    // A full queue and a running wait can't both meet an accept: a full queue already holds
    // `constants.accepts_in_flight_max` accepts, so another would be a caller's bug. The
    // nearest case is the share full and the kept slot free: the accept is refused by the
    // wait, not by the share, and the wait's count says so.
    comptime assert(slots_count - shared_slots_max == constants.accepts_in_flight_max + constants.io_cancels_in_flight_max);
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(13, 0);
    sim.attachTable(&fixture.table);
    var id: io.OperationId = 0;
    while (id < shared_slots_max) : (id += 1) try sim.submit(testSubmission(id));
    try testing.expectError(error.SlotsKeptForAccepts, sim.submit(testSubmission(id)));
    try testing.expectError(error.Backpressure, sim.arrive(error.Backpressure));
    const accept: io.Submission = .{ .id = id, .operation = .{ .accept = .{ .listener = test_listener } } };
    try testing.expectError(error.AcceptTooSoon, sim.submit(accept));
    try testing.expectEqual(@as(u64, 1), sim.accept_wait.refused);
    try testing.expectEqual(@as(u32, 0), sim.share.accepts_in_flight);
    // Once the wait is over, the accept takes the kept slot; only the cancels' stay free.
    var ticks: u32 = 0;
    while (ticks < wait_ticks) : (ticks += 1) sim.tick();
    try sim.submit(accept);
    try testing.expectEqual(slots_count - constants.io_cancels_in_flight_max, sim.in_flight);
    try testing.expectEqual(constants.accepts_in_flight_max, sim.share.accepts_in_flight);
    var completions: [slots_count]io.Completion = undefined;
    try testing.expectEqual(shared_slots_max + 1, drainAll(&sim, &completions));
    try fixture.expectNoSendsCounted();
    // Every entry holds a test peer, so the arrival finds the table full.
    var accepts: u32 = 0;
    for (completions[0 .. shared_slots_max + 1]) |completion| {
        if (completion.result != .accept) continue;
        try testing.expectError(error.TableFull, completion.result.accept);
        accepts += 1;
    }
    try testing.expectEqual(@as(u32, 1), accepts);
}

test "sim: a release with a send in flight is refused until the send completes" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(23, 0);
    sim.attachTable(&fixture.table);
    const peer: io.PeerId = 3;
    const send: io.Send = .{ .peer = peer, .bytes = "held" };
    try sim.submit(.{ .id = 1, .operation = .{ .send = send } });
    try sim.submit(.{ .id = 2, .operation = .{ .send = send } });
    try testing.expectEqual(@as(connections.SendCount, 2), fixture.table.get(peer).sends_in_flight);
    const entry_before = fixture.table.get(peer).*;
    try testing.expectError(error.OperationsInFlight, fixture.table.release(peer));
    try testing.expectEqual(entry_before, fixture.table.get(peer).*);
    try testing.expectEqual(test_peers, fixture.table.count());

    // One completion at a time: with one send still in flight, the release is still refused.
    var completions: [1]io.Completion = undefined;
    var done: u32 = 0;
    var ticks: u32 = 0;
    while (ticks <= constants.sim_completion_delay_ticks_max and done < 2) : (ticks += 1) {
        sim.tick();
        var polls: u32 = 0;
        while (polls < 2 and sim.poll(&completions) == 1) : (polls += 1) {
            done += 1;
            try testing.expect(completions[0].id == 1 or completions[0].id == 2);
            try testing.expectEqual(@as(u32, send.bytes.len), try completions[0].result.send);
            const left: connections.SendCount = @intCast(2 - done);
            try testing.expectEqual(left, fixture.table.get(peer).sends_in_flight);
            if (left > 0) try testing.expectError(error.OperationsInFlight, fixture.table.release(peer));
        }
    }
    try testing.expectEqual(@as(u32, 2), done);
    try testing.expectEqual(peerSocket(3), try fixture.table.release(peer));
    try testing.expect(fixture.table.lookup(peer) == null);
    try testing.expectEqual(test_peers - 1, fixture.table.count());
}

/// What `sendSoak` did, for the test to check that every path ran.
const SoakCounts = struct {
    sends: u32 = 0,
    completions: u32 = 0,
    releases_refused: u32 = 0,
    reconnects: u32 = 0,
    /// FNV-1a over every completion's id, in order, so a replay that completed the same
    /// totals in another order still differs.
    trace: u64 = 0xcbf29ce484222325,
};

const soak_steps: u32 = 4_000;
/// The last steps only tick, so every send in flight completes.
const soak_steps_total: u32 = soak_steps + constants.sim_completion_delay_ticks_max + 1;

/// A soak's simulator and its model: each entry's live id and its sends in flight, and the
/// entry each operation id's send went to (an id is its step number).
const Soak = struct {
    sim: Sim,
    table: *connections.Table,
    ids: [test_peers]io.PeerId,
    sends: [test_peers]u32,
    op_entry: [soak_steps]u8,
    counts: SoakCounts,

    /// A send to `entry`'s live id, unless every slot is in use.
    fn send(soak: *Soak, step_index: u32, entry: u32) !void {
        assert(step_index < soak_steps);
        assert(entry < test_peers);
        // A tick follows a send three times in eight, and nothing waits more than the
        // longest delay, so the soak holds a few dozen sends at most, never every slot;
        // the full-slot paths have tests of their own.
        assert(soak.sim.in_flight < slots_count);
        const operation: io.Send = .{ .peer = soak.ids[entry], .bytes = "soak" };
        try soak.sim.submit(.{ .id = step_index, .operation = .{ .send = operation } });
        soak.op_entry[step_index] = @intCast(entry);
        soak.sends[entry] += 1;
        soak.counts.sends += 1;
    }

    /// A release of `entry`: refused, changing nothing, exactly while the model counts a
    /// send on it; otherwise it succeeds, and the entry is taken again at once under its
    /// next generation, so the old id must find nothing.
    fn release(soak: *Soak, entry: u32) !void {
        assert(entry < test_peers);
        const table = soak.table;
        const before = table.get(soak.ids[entry]).*;
        const socket = table.release(soak.ids[entry]) catch |err| {
            try testing.expectEqual(error.OperationsInFlight, err);
            try testing.expect(soak.sends[entry] > 0);
            try testing.expectEqual(before, table.get(soak.ids[entry]).*);
            soak.counts.releases_refused += 1;
            return;
        };
        try testing.expectEqual(@as(u32, 0), soak.sends[entry]);
        try testing.expectEqual(before.socket, socket);
        // The free stack hands back the entry just released, under a new generation.
        const again = try table.acquire(socket);
        const old: connections.IdParts = @bitCast(soak.ids[entry]);
        const new: connections.IdParts = @bitCast(again);
        try testing.expectEqual(old.index, new.index);
        try testing.expectEqual(old.generation + 1, new.generation);
        try testing.expect(table.lookup(soak.ids[entry]) == null);
        soak.ids[entry] = again;
        soak.counts.reconnects += 1;
    }

    /// One tick, then every completion due, each uncounted from the entry its send went to.
    fn tick(soak: *Soak) !void {
        const completed_before = soak.counts.completions;
        const in_flight_before = soak.sim.in_flight;
        soak.sim.tick();
        var completions: [16]io.Completion = undefined;
        var batches: u32 = 0;
        while (batches < slots_count) : (batches += 1) {
            const count = soak.sim.poll(&completions);
            for (completions[0..count]) |completion| {
                try testing.expect(completion.id < soak_steps);
                try testing.expectEqual(io.Kind.send, @as(io.Kind, completion.result));
                const done = soak.op_entry[@intCast(completion.id)];
                try testing.expect(soak.sends[done] > 0);
                soak.sends[done] -= 1;
                soak.counts.completions += 1;
                soak.counts.trace = (soak.counts.trace ^ completion.id) *% 0x100000001b3;
            }
            if (count < completions.len) break;
        }
        try testing.expect(batches < slots_count);
        // Every completion taken left the simulator: none lost, none taken twice.
        assert(soak.counts.completions - completed_before == in_flight_before - soak.sim.in_flight);
    }

    /// Each entry's count in the table equals the model's, and together they are every
    /// operation the simulator holds.
    fn check(soak: *const Soak) !void {
        var counted: u32 = 0;
        for (soak.ids, soak.sends) |id, expected| {
            try testing.expectEqual(expected, soak.table.get(id).sends_in_flight);
            counted += expected;
        }
        try testing.expectEqual(soak.sim.in_flight, counted);
        try testing.expectEqual(test_peers, soak.table.count());
    }
};

/// Seeded steps over `test_peers` live connections: half are sends to a random peer, one
/// in eight a release of a random peer, and the rest ticks that take every completion due.
/// After every step the table's counts match the model's (see `Soak`).
fn sendSoak(seed: u64) !SoakCounts {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var prng: std.Random.DefaultPrng = .init(seed ^ 0x5e9d_50a4);
    const random = prng.random();
    var soak: Soak = .{
        .sim = .init(seed, constants.sim_fault_percent_max),
        .table = &fixture.table,
        .ids = undefined,
        .sends = @splat(0),
        .op_entry = undefined,
        .counts = .{},
    };
    soak.sim.attachTable(&fixture.table);
    for (&soak.ids, 0..) |*id, index| id.* = @intCast(index);

    var step_index: u32 = 0;
    while (step_index < soak_steps_total) : (step_index += 1) {
        const action: u8 = if (step_index < soak_steps) random.uintLessThan(u8, 8) else 7;
        const entry = random.uintLessThan(u32, test_peers);
        switch (action) {
            0...3 => try soak.send(step_index, entry),
            4 => try soak.release(entry),
            else => try soak.tick(),
        }
        try soak.check();
    }
    assert(step_index == soak_steps_total);
    try testing.expectEqual(@as(u32, 0), soak.sim.in_flight);
    try testing.expectEqual(soak.counts.sends, soak.counts.completions);
    try fixture.expectNoSendsCounted();
    return soak.counts;
}

test "sim: seeded sends, releases and reconnects keep the table's counts with the model" {
    const seeds = [_]u64{ 1, 2, 0x5eed };
    for (seeds) |seed| {
        const counts = try sendSoak(seed);
        // Every path ran: sends completed, releases were refused with sends in flight and
        // allowed without, and entries were taken again under new generations.
        try testing.expect(counts.sends > soak_steps / 4);
        try testing.expect(counts.releases_refused > 0);
        try testing.expect(counts.reconnects > 0);
        try testing.expectEqual(counts, try sendSoak(seed));
    }
}

/// Submits sends of "stuck?" to `peer` from id `first` until one sticks, at most `tries`,
/// and returns its id. Fails the test if none sticks.
fn submitUntilStuck(sim: *Sim, peer: io.PeerId, first: io.OperationId, tries: u32) !io.OperationId {
    assert(sim.stick_percent > 0);
    assert(tries <= shared_slots_max);
    var id = first;
    while (id < first + tries) : (id += 1) {
        const stuck_before = sim.sends_stuck;
        try sim.submit(.{ .id = id, .operation = .{ .send = .{ .peer = peer, .bytes = "stuck?" } } });
        if (sim.sends_stuck > stuck_before) return id;
    }
    return error.TestNothingStuck;
}

test "sim: a stuck send completes only once its connection is dropped, then with PeerDown" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(31, 0);
    sim.setDropFaults(constants.sim_fault_percent_max, 0);
    sim.attachTable(&fixture.table);
    const peer: io.PeerId = 2;
    const stuck_id = try submitUntilStuck(&sim, peer, 0, 32);
    var completions: [slots_count]io.Completion = undefined;
    var ticks: u32 = 0;
    var done: u32 = 0;
    // Far past the longest delay, only the stuck send is left, still holding its entry.
    while (ticks < 4 * constants.sim_completion_delay_ticks_max) : (ticks += 1) {
        sim.tick();
        done += sim.poll(completions[done..]);
    }
    for (completions[0..done]) |completion| try testing.expect(completion.id != stuck_id);
    try testing.expectEqual(sim.stuckSends(), sim.in_flight);
    try testing.expect(sim.in_flight >= 1);
    try testing.expectError(error.OperationsInFlight, fixture.table.release(peer));

    try sim.drop(peer);
    try testing.expectEqual(@as(u32, 0), sim.stuckSends());
    // A send after the drop can't stick or succeed either.
    try sim.submit(.{ .id = 100, .operation = .{ .send = .{ .peer = peer, .bytes = "late" } } });
    const pending = sim.in_flight;
    try testing.expectEqual(pending, drainAll(&sim, completions[0..pending]));
    for (completions[0..pending]) |completion| try testing.expectError(error.PeerDown, completion.result.send);
    try testing.expectEqual(pending, sim.sends_dropped);
    // Ended by the drop, not injected: no fault is counted.
    try testing.expectEqual(@as(u64, 0), sim.faults.total());
    try testing.expectEqual(@as(u64, 1), sim.dropped);
    try testing.expectEqual(peerSocket(2), try fixture.table.release(peer));
    _ = try fixture.table.acquire(peerSocket(2));
}

test "sim: a drop reaches only its connection, and a reused entry starts undropped" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(32, 0);
    sim.attachTable(&fixture.table);
    try sim.submit(.{ .id = 1, .operation = .{ .send = .{ .peer = 4, .bytes = "other" } } });
    try sim.drop(5);
    // Dropping again works and changes nothing more.
    try sim.drop(5);
    try testing.expectEqual(@as(u64, 2), sim.dropped);
    var completions: [2]io.Completion = undefined;
    try testing.expectEqual(@as(u32, 1), drainAll(&sim, completions[0..1]));
    try testing.expectEqual(@as(u32, 5), try completions[0].result.send);

    // The entry, released and taken again, carries its next generation: not dropped.
    try testing.expectEqual(peerSocket(5), try fixture.table.release(5));
    const reused = try fixture.table.acquire(peerSocket(5));
    const parts: connections.IdParts = @bitCast(reused);
    try testing.expectEqual(@as(connections.Index, 5), parts.index);
    try testing.expect(!sim.isDropped(reused));
    try sim.submit(.{ .id = 2, .operation = .{ .send = .{ .peer = reused, .bytes = "new" } } });
    try testing.expectEqual(@as(u32, 1), drainAll(&sim, completions[0..1]));
    try testing.expectEqual(@as(u32, 3), try completions[0].result.send);
    try testing.expectEqual(@as(u32, 0), sim.sends_dropped);
    try testing.expectEqual(peerSocket(5), try fixture.table.release(reused));
    _ = try fixture.table.acquire(peerSocket(5));
}

test "sim: release refuses while a send is in flight, then frees the entry, drawing nothing" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(33, 0);
    sim.attachTable(&fixture.table);
    try sim.submit(.{ .id = 1, .operation = .{ .send = .{ .peer = 2, .bytes = "in flight" } } });
    const outcomes_before = sim.outcomes;
    try testing.expectError(error.OperationsInFlight, sim.release(2));
    try testing.expect(fixture.table.lookup(2) != null);
    try testing.expectEqual(@as(u64, 0), sim.released);
    // A peer with nothing in flight goes at once, and its id is stale from then on.
    try sim.release(3);
    try testing.expectEqual(@as(?*const connections.Entry, null), fixture.table.lookup(3));
    var completions: [1]io.Completion = undefined;
    try testing.expectEqual(@as(u32, 1), drainAll(&sim, &completions));
    try sim.release(2);
    try testing.expectEqual(@as(u64, 2), sim.released);
    try testing.expectEqual(test_peers - 2, fixture.table.count());
    // Releasing drew nothing: the outcome stream is where the send's draw left it.
    try testing.expectEqual(outcomes_before.s, sim.outcomes.s);
}

test "sim: drops draw only from their own stream, and never change what sticks" {
    // A table each, as each simulator counts its sends on its own entries.
    var plain_fixture: TableFixture = undefined;
    try plain_fixture.setUpPeers(test_peers);
    defer plain_fixture.tearDown();
    var dropping_fixture: TableFixture = undefined;
    try dropping_fixture.setUpPeers(test_peers);
    defer dropping_fixture.tearDown();
    var plain = Sim.init(33, 20);
    var dropping = Sim.init(33, 20);
    // A low stick rate, so when each connection's first send sticks is what a leak changes.
    plain.setDropFaults(10, constants.sim_fault_percent_max);
    dropping.setDropFaults(10, constants.sim_fault_percent_max);
    plain.attachTable(&plain_fixture.table);
    dropping.attachTable(&dropping_fixture.table);
    var id: io.OperationId = 0;
    var drops_drew = false;
    while (id < 128) : (id += 1) {
        // Sends to the even-numbered peers and statements; peer 2 is dropped midway, with
        // sends pending and stuck, and dropped again every fourth submission after.
        if (id >= 24 and id % 4 == 0) {
            const drops_before = dropping.drop_source.s;
            dropping.drop(2) catch |err| switch (err) {
                error.DropsExhausted => {},
            };
            if (!std.meta.eql(drops_before, dropping.drop_source.s)) drops_drew = true;
        }
        const plain_stuck = plain.sends_stuck;
        const dropping_stuck = dropping.sends_stuck;
        try plain.submit(testSubmission(id));
        try dropping.submit(testSubmission(id));
        // Each send to a connection nothing drops sticks in both runs or in neither.
        const to_peer_2 = id % 2 == 0 and id % test_peers == 2;
        if (!to_peer_2) {
            try testing.expectEqual(plain.sends_stuck - plain_stuck, dropping.sends_stuck - dropping_stuck);
        }
        try testing.expectEqual(plain.outcomes.s, dropping.outcomes.s);
        try testing.expectEqual(plain.stick_source.s, dropping.stick_source.s);
        try testing.expectEqual(plain.schedule.s, dropping.schedule.s);
    }
    try testing.expect(drops_drew);
    try testing.expect(dropping.sends_stuck > 0);
    try testing.expectEqual(plain.submitted, dropping.submitted);
    // Only peer 2's sends differ: every other peer has the same sends stuck in both runs.
    var peer: io.PeerId = 0;
    while (peer < test_peers) : (peer += 2) {
        if (peer == 2) continue;
        try testing.expectEqual(plain.stuckSendsTo(peer), dropping.stuckSendsTo(peer));
    }
    try testing.expectEqual(test_peers, peer);
}

// Every drop of a connection with a stuck send fails, till the bound: each failure leaves
// the send stuck, the one that reaches the bound says so, and every drop after it is
// refused before any draw, as the real type calls no shutdown then.
test "sim: failed drops count to the bound through the table, and past it nothing is drawn" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(34, 0);
    sim.setDropFaults(constants.sim_fault_percent_max, 100);
    sim.attachTable(&fixture.table);
    const peer: io.PeerId = 1;
    _ = try submitUntilStuck(&sim, peer, 0, 32);
    const stuck = sim.stuckSendsTo(peer);
    const bound = constants.io_drop_attempts_max;
    var attempts: u32 = 0;
    while (attempts < bound - 1) : (attempts += 1) {
        try sim.drop(peer);
        const failed: connections.DropCount = @intCast(attempts + 1);
        try testing.expectEqual(failed, fixture.table.get(peer).drops_failed);
        try testing.expectEqual(stuck, sim.stuckSendsTo(peer));
    }
    try testing.expectError(error.DropsExhausted, sim.drop(peer));
    try testing.expectEqual(@as(connections.DropCount, bound), fixture.table.get(peer).drops_failed);
    try testing.expectEqual(@as(u64, bound), sim.drops_failed);
    try testing.expectEqual(@as(u64, bound), sim.dropped);
    try testing.expectEqual(stuck, sim.stuckSendsTo(peer));
    // Refused from then on before any draw, and the send stays stuck.
    const drops_before = sim.drop_source.s;
    try testing.expectError(error.DropsExhausted, sim.drop(peer));
    try testing.expectEqual(drops_before, sim.drop_source.s);
    try testing.expectEqual(@as(u64, bound), sim.dropped);
    try testing.expectEqual(stuck, sim.stuckSendsTo(peer));
}

/// Drops each connection, with a stuck send, until a drop works or its drops run out, at a
/// 50% failure rate; returns how many failed drops left a stuck send stuck.
fn dropUntilWorks(seed: u64) !u32 {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(seed, 0);
    sim.setDropFaults(constants.sim_fault_percent_max, constants.sim_fault_percent_max);
    sim.attachTable(&fixture.table);
    var failed_while_stuck: u32 = 0;
    var peer: io.PeerId = 0;
    while (peer < test_peers) : (peer += 1) {
        _ = try submitUntilStuck(&sim, peer, peer * 32, 32);
        var attempts: u32 = 0;
        while (attempts < constants.io_drop_attempts_max) : (attempts += 1) {
            const stuck_before = sim.stuckSendsTo(peer);
            sim.drop(peer) catch |err| switch (err) {
                error.DropsExhausted => {},
            };
            if (sim.isDropped(peer)) break;
            try testing.expectEqual(stuck_before, sim.stuckSendsTo(peer));
            failed_while_stuck += 1;
        }
        if (!sim.isDropped(peer)) continue;
        try testing.expectEqual(@as(u32, 0), sim.stuckSendsTo(peer));
        // Dropping again changes nothing more and never fails, as on the real type.
        const slots_before = sim.slots;
        const drops_before = sim.drop_source.s;
        const failed_before = sim.drops_failed;
        try sim.drop(peer);
        try testing.expectEqualDeep(slots_before, sim.slots);
        try testing.expectEqual(drops_before, sim.drop_source.s);
        try testing.expectEqual(failed_before, sim.drops_failed);
    }
    try testing.expectEqual(test_peers, peer);
    return failed_while_stuck;
}

test "sim: a drop that works after failures ends the stuck sends, and dropping again changes nothing" {
    // Which drops fail is drawn, so two seeds show failures that leave a send stuck.
    var failed_while_stuck: u32 = 0;
    for ([_]u64{ 34, 35 }) |seed| failed_while_stuck += try dropUntilWorks(seed);
    try testing.expect(failed_while_stuck > 0);
}

/// What `dropSoak` did, for the test to check that every path ran and that a seed replays.
const DropSoakCounts = struct {
    sends: u32 = 0,
    refused_share: u32 = 0,
    accepts: u32 = 0,
    /// Accepts that completed while sends held the whole share kept from them.
    accepts_while_share_full: u32 = 0,
    stuck: u32 = 0,
    dropped: u32 = 0,
    /// FNV-1a over every completion's id, in order.
    trace: u64 = 0xcbf29ce484222325,
};

const drop_soak_ticks: u32 = 640;
/// Sends `dropSoak` submits each tick until the share is full. Reason: at least
/// `sim_fault_percent_max` of them stick (more, since a send behind a stuck one on the same
/// connection sticks too), so the share fills within the first half of the run, by about
/// tick 130 of 640 in practice, and the rest of the run meets a full share; the comptime
/// check below fails if a larger ring outgrows it.
const drop_soak_sends_per_tick: u32 = 64;
/// Sends per tick once the share is full: enough to meet the full share every tick without
/// paying a full ring's worth of refused submissions.
const drop_soak_sends_when_full: u32 = 2;
const drop_soak_accept_id: io.OperationId = 1 << 32;

comptime {
    // The sends that stick at the lowest rate, over half the run, pass the share, so the run
    // ends with the share full and sends refused.
    assert((@as(u64, drop_soak_ticks / 2) * drop_soak_sends_per_tick * constants.sim_fault_percent_max) / 100 > shared_slots_max);
    // Send ids never reach the accepts' ids.
    assert(@as(u64, drop_soak_ticks) * drop_soak_sends_per_tick <= drop_soak_accept_id);
    assert(drop_soak_sends_when_full > 0 and drop_soak_sends_when_full < drop_soak_sends_per_tick);
}

/// The model `dropSoak` checks the table against: each peer's sends in flight, by the
/// entry each send id went to.
const DropSoak = struct {
    sim: Sim,
    table: *connections.Table,
    sends: [test_peers]u32 = @splat(0),
    send_entry: [drop_soak_ticks * drop_soak_sends_per_tick]u8 = undefined,
    accept_in_flight: bool = false,
    accepts_submitted: u64 = 0,
    counts: DropSoakCounts = .{},

    /// Keeps one accept in flight; a refusal waits for a later tick.
    fn keepAccepting(soak: *DropSoak) !void {
        assert(soak.sim.table != null);
        if (soak.accept_in_flight) return;
        const id = drop_soak_accept_id + soak.accepts_submitted;
        const accept: io.Operation = .{ .accept = .{ .listener = test_listener } };
        soak.sim.submit(.{ .id = id, .operation = accept }) catch |err| switch (err) {
            error.QueueFull, error.AcceptTooSoon => return,
            // Never for an accept.
            error.SlotsKeptForAccepts, error.CancelsFull => return error.TestUnexpectedResult,
        };
        soak.accepts_submitted += 1;
        soak.accept_in_flight = true;
        // Every accept counted as completed was submitted first.
        assert(soak.counts.accepts < soak.accepts_submitted);
    }

    /// A send to `entry`; the share kept from accepts may refuse it.
    fn send(soak: *DropSoak, id: io.OperationId, entry: u32) !void {
        assert(entry < test_peers);
        assert(id < soak.send_entry.len);
        const operation: io.Send = .{ .peer = entry, .bytes = "soak" };
        soak.sim.submit(.{ .id = id, .operation = .{ .send = operation } }) catch |err| switch (err) {
            error.SlotsKeptForAccepts, error.QueueFull => {
                soak.counts.refused_share += 1;
                return;
            },
            // Only for an accept or a cancel.
            error.AcceptTooSoon, error.CancelsFull => return error.TestUnexpectedResult,
        };
        soak.send_entry[@intCast(id)] = @intCast(entry);
        soak.sends[entry] += 1;
        soak.counts.sends += 1;
    }

    /// One tick, then every completion due: sends uncounted from the model, accepted
    /// connections released at once.
    fn tick(soak: *DropSoak) !void {
        assert(soak.sim.table == soak.table);
        const in_flight_before = soak.sim.in_flight;
        soak.sim.tick();
        const share_full = soak.sim.share.others_in_flight == shared_slots_max;
        var completions: [slots_count]io.Completion = undefined;
        const count = soak.sim.poll(&completions);
        for (completions[0..count]) |completion| {
            soak.counts.trace = (soak.counts.trace ^ completion.id) *% 0x100000001b3;
            switch (completion.result) {
                .send => {
                    const entry = soak.send_entry[@intCast(completion.id)];
                    try testing.expect(soak.sends[entry] > 0);
                    soak.sends[entry] -= 1;
                },
                .accept => |accepted| {
                    try testing.expect(completion.id >= drop_soak_accept_id);
                    soak.accept_in_flight = false;
                    const peer = accepted catch |err| switch (err) {
                        error.PeerDown, error.Backpressure => continue,
                        // Accepted connections are released at once, so the table has room.
                        error.TableFull => return error.TestUnexpectedResult,
                    };
                    _ = try soak.table.release(peer);
                    soak.counts.accepts += 1;
                    if (share_full) soak.counts.accepts_while_share_full += 1;
                },
                .execute, .receive, .cancel => return error.TestUnexpectedResult,
            }
        }
        var entry: u32 = 0;
        while (entry < test_peers) : (entry += 1) {
            try testing.expectEqual(soak.sends[entry], soak.table.get(entry).sends_in_flight);
        }
        // Every completion taken left the simulator: none lost, none taken twice.
        assert(soak.sim.in_flight == in_flight_before - count);
    }
};

/// Seeded ticks over `test_peers` connections whose sends stick half the time, with one
/// accept kept in flight: the stuck sends fill the share kept from accepts while accepts
/// keep completing. Then every connection is dropped, the sends drain, and every entry is
/// released.
fn dropSoak(seed: u64) !DropSoakCounts {
    var fixture: TableFixture = undefined;
    try fixture.setUp(2 * test_peers);
    defer fixture.tearDown();
    var peer: u32 = 0;
    while (peer < test_peers) : (peer += 1) assert(try fixture.table.acquire(peerSocket(peer)) == peer);
    var prng: std.Random.DefaultPrng = .init(seed ^ 0xd209_50a4);
    var soak: DropSoak = .{ .sim = .init(seed, 10), .table = &fixture.table };
    soak.sim.setDropFaults(constants.sim_fault_percent_max, 0);
    soak.sim.attachTable(&fixture.table);
    var ticks: u32 = 0;
    while (ticks < drop_soak_ticks) : (ticks += 1) {
        const full = soak.sim.share.others_in_flight == shared_slots_max;
        const sends = if (full) drop_soak_sends_when_full else drop_soak_sends_per_tick;
        var sent: u32 = 0;
        while (sent < sends) : (sent += 1) {
            try soak.send(ticks * drop_soak_sends_per_tick + sent, prng.random().uintLessThan(u32, test_peers));
        }
        assert(sent == sends);
        try soak.keepAccepting();
        try soak.tick();
    }
    soak.counts.stuck = soak.sim.sends_stuck;
    // Only sends that went in can stick.
    assert(soak.counts.stuck <= soak.counts.sends);
    peer = 0;
    while (peer < test_peers) : (peer += 1) try soak.sim.drop(peer);
    ticks = 0;
    while (ticks <= constants.sim_completion_delay_ticks_max) : (ticks += 1) try soak.tick();
    soak.counts.dropped = soak.sim.sends_dropped;
    // Only sends that went in can be ended by a drop.
    assert(soak.counts.dropped <= soak.counts.sends);
    try testing.expectEqual(@as(u32, 0), soak.sim.in_flight);
    try testing.expectEqual(@as(u32, 0), soak.sim.sends_in_flight);
    peer = 0;
    while (peer < test_peers) : (peer += 1) try testing.expectEqual(peerSocket(peer), try fixture.table.release(peer));
    try testing.expectEqual(@as(u32, 0), fixture.table.count());
    fixture.table.assertInvariants();
    return soak.counts;
}

test "sim: seeded stuck sends fill the share while accepts keep completing; drops free every entry" {
    const seeds = [_]u64{ 1, 2, 0x5eed };
    for (seeds) |seed| {
        const counts = try dropSoak(seed);
        // Stuck sends complete only when dropped, so the share caps them.
        try testing.expect(counts.stuck > shared_slots_max / 2);
        try testing.expect(counts.stuck <= shared_slots_max);
        try testing.expect(counts.refused_share > 0);
        try testing.expect(counts.accepts_while_share_full > 0);
        try testing.expect(counts.dropped > 0);
        try testing.expectEqual(counts, try dropSoak(seed));
    }
}

const client_request = "GET /status HTTP/1.1\r\nHost: coalition.example\r\n\r\n";

/// Receives on `peer` into `buffer`, one at a time, each taken back before the next goes in,
/// until one reads end of stream or fails, appending what lands after `filled`. Returns how
/// many bytes landed; `ended` says how the last receive ended. At most `receives_max`.
fn receiveAll(sim: *Sim, peer: io.PeerId, buffer: []u8, first: io.OperationId, ended: *?io.ReceiveError!u32) !u32 {
    const receives_max: u32 = 4 * client_stream_bytes_max;
    var filled: u32 = 0;
    var receives: u32 = 0;
    while (receives < receives_max) : (receives += 1) {
        if (filled == buffer.len) return error.TestBufferFull;
        const into = buffer[filled..];
        try sim.submit(.{ .id = first + receives, .operation = .{ .receive = .{ .peer = peer, .buffer = into } } });
        // The buffer belongs to the simulator until the completion: it holds the poison.
        try testing.expect(std.mem.allEqual(u8, into, receive_poison));
        var completions: [1]io.Completion = undefined;
        try testing.expectEqual(@as(u32, 1), drainAll(sim, &completions));
        try testing.expectEqual(first + receives, completions[0].id);
        const received = completions[0].result.receive catch |err| {
            ended.* = err;
            return filled;
        };
        if (received == 0) {
            ended.* = 0;
            return filled;
        }
        filled += received;
    }
    return error.TestTooManyReceives;
}

test "sim: receives read the client's stream a byte at a time when bounded, then end of stream" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(21, 0);
    sim.attachTable(&fixture.table);
    sim.setClientStream(client_request, 1);
    var buffer: [constants.http_request_size_max]u8 = undefined;
    var ended: ?io.ReceiveError!u32 = null;
    const filled = try receiveAll(&sim, 2, &buffer, 0, &ended);
    // Every byte arrived once, in order, one per receive, and then the client closed.
    try testing.expectEqualStrings(client_request, buffer[0..filled]);
    try testing.expectEqual(@as(?io.ReceiveError!u32, 0), ended);
    try testing.expectEqual(@as(u64, client_request.len), sim.bytes_received);
    try testing.expectEqual(@as(u64, client_request.len + 1), sim.completed);
    try testing.expectEqual(@as(u32, 1), sim.receives_ended);
    try testing.expect(!fixture.table.get(2).receiving);
    // Another connection's client sends its own copy from the start.
    var other: [client_request.len + 1]u8 = undefined;
    const other_filled = try receiveAll(&sim, 3, &other, 1000, &ended);
    try testing.expectEqualStrings(client_request, other[0..other_filled]);
}

test "sim: unbounded receives read the stream in drawn chunks; a reused entry's client starts again" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(22, 0);
    sim.attachTable(&fixture.table);
    sim.setClientStream(client_request, constants.http_request_size_max);
    var buffer: [constants.http_request_size_max]u8 = undefined;
    var ended: ?io.ReceiveError!u32 = null;
    const filled = try receiveAll(&sim, 4, &buffer, 0, &ended);
    try testing.expectEqualStrings(client_request, buffer[0..filled]);
    // Released and taken again under a new id, the entry's client sends from the start.
    try testing.expectEqual(peerSocket(4), try fixture.table.release(4));
    const reused = try fixture.table.acquire(peerSocket(4));
    try testing.expect(reused != 4);
    const again = try receiveAll(&sim, reused, &buffer, 100, &ended);
    try testing.expectEqualStrings(client_request, buffer[0..again]);
}

test "sim: a seeded run draws every receive fault and short reads" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(23, constants.sim_fault_percent_max);
    sim.attachTable(&fixture.table);
    sim.setClientStream(client_request, constants.http_request_size_max);
    var buffer: [constants.http_request_size_max]u8 = undefined;
    var peers: [test_peers]io.PeerId = undefined;
    for (&peers, 0..) |*peer, index| peer.* = index;
    var rounds: u32 = 0;
    var next: io.OperationId = 0;
    while (rounds < 64) : (rounds += 1) {
        var ended: ?io.ReceiveError!u32 = null;
        const slot = rounds % test_peers;
        const filled = try receiveAll(&sim, peers[slot], &buffer, next, &ended);
        next += 1000;
        // Whatever landed is the stream's start, however the receives ended.
        try testing.expectEqualStrings(client_request[0..filled], buffer[0..filled]);
        // The connection ends, and its entry comes back under a new id.
        try testing.expectEqual(peerSocket(slot), try fixture.table.release(peers[slot]));
        peers[slot] = try fixture.table.acquire(peerSocket(slot));
    }
    try testing.expect(sim.faults.receive_peer_down > 0);
    try testing.expect(sim.faults.receive_backpressure > 0);
    try testing.expect(sim.faults.receive_closed_early > 0);
    try testing.expect(sim.receives_ended > 0);
}

test "sim: a cancel ends a stuck receive and stuck sends with Canceled, and counts what it reached" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(24, 0);
    sim.attachTable(&fixture.table);
    sim.setClientStream(client_request, 1);
    // Every send and receive sticks, as on a client that went silent and stopped reading.
    sim.setDropFaults(constants.sim_fault_percent_max, 0);
    const peer: io.PeerId = 5;
    var buffer: [8]u8 = undefined;
    var id: io.OperationId = 0;
    while (sim.receives_stuck == 0 and id < 64) : (id += 1) {
        try sim.submit(.{ .id = id, .operation = .{ .receive = .{ .peer = peer, .buffer = &buffer } } });
        var completions: [1]io.Completion = undefined;
        if (sim.receives_stuck == 0) _ = drainAll(&sim, &completions);
    }
    try testing.expectEqual(@as(u32, 1), sim.receives_stuck);
    const receive_id = id - 1;
    const send_id = try submitUntilStuck(&sim, peer, 100, 64);
    try testing.expect(sim.stuckTo(peer) >= 2);
    const in_flight = sim.in_flight;
    try sim.submit(.{ .id = 200, .operation = .{ .cancel = .{ .peer = peer } } });
    try testing.expect(fixture.table.get(peer).canceled);
    try testing.expectEqual(@as(u32, 0), sim.stuckTo(peer));
    var completions: [slots_count]io.Completion = undefined;
    try testing.expectEqual(in_flight + 1, drainAll(&sim, &completions));
    var reached: u32 = 0;
    var canceled: u32 = 0;
    for (completions[0 .. in_flight + 1]) |completion| switch (completion.result) {
        .cancel => |count| reached = count,
        .receive => |received| {
            try testing.expectEqual(receive_id, completion.id);
            try testing.expectError(error.Canceled, received);
            canceled += 1;
        },
        .send => |sent| {
            // The sends before the stuck one completed on their own; the rest are cancelled.
            if (completion.id >= send_id) try testing.expectError(error.Canceled, sent);
            if (sent == error.Canceled) canceled += 1;
        },
        .accept, .execute => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(canceled, reached);
    try testing.expectEqual(canceled, sim.canceled);
    try testing.expect(reached >= 2);
    try testing.expectEqual(@as(u32, 1), sim.cancels);
    try testing.expectEqual(@as(u64, 0), sim.faults.total());
    try testing.expect(!fixture.table.get(peer).busy());
    _ = try fixture.table.release(peer);
    _ = try fixture.table.acquire(peerSocket(peer));
}

test "sim: a drop ends a stuck receive with PeerDown or end of stream, both drawn over seeds" {
    var ends: [2]u32 = .{ 0, 0 };
    var seed: u64 = 1;
    while (seed <= 32) : (seed += 1) {
        var fixture: TableFixture = undefined;
        try fixture.setUpPeers(test_peers);
        defer fixture.tearDown();
        var sim = Sim.init(seed, 0);
        sim.attachTable(&fixture.table);
        sim.setClientStream(client_request, 1);
        sim.setDropFaults(constants.sim_fault_percent_max, 0);
        var buffer: [8]u8 = undefined;
        var id: io.OperationId = 0;
        var completions: [1]io.Completion = undefined;
        while (sim.receives_stuck == 0 and id < 64) : (id += 1) {
            try sim.submit(.{ .id = id, .operation = .{ .receive = .{ .peer = 1, .buffer = &buffer } } });
            if (sim.receives_stuck == 0) _ = drainAll(&sim, &completions);
        }
        try testing.expectEqual(@as(u32, 1), sim.receives_stuck);
        try sim.drop(1);
        try testing.expectEqual(@as(u32, 1), drainAll(&sim, &completions));
        if (completions[0].result.receive) |received| {
            try testing.expectEqual(@as(u32, 0), received);
            ends[0] += 1;
        } else |err| {
            try testing.expectEqual(error.PeerDown, err);
            ends[1] += 1;
        }
        try testing.expectEqual(@as(u32, 1), sim.receives_dropped);
        try testing.expectEqual(@as(u64, 0), sim.faults.total());
    }
    try testing.expect(ends[0] > 0 and ends[1] > 0);
}

test "sim: past the cancels' share a cancel is refused with CancelsFull and changes nothing" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(full_peers + 1);
    defer fixture.tearDown();
    var sim = Sim.init(25, 0);
    sim.attachTable(&fixture.table);
    var cancel: u32 = 0;
    while (cancel < constants.io_cancels_in_flight_max) : (cancel += 1) {
        try sim.submit(.{ .id = cancel, .operation = .{ .cancel = .{ .peer = test_peers + cancel } } });
    }
    const last: io.PeerId = full_peers;
    const entry_before = fixture.table.get(last).*;
    const outcomes_before = sim.outcomes.s;
    const refused: io.Submission = .{ .id = cancel, .operation = .{ .cancel = .{ .peer = last } } };
    try testing.expectError(error.CancelsFull, sim.submit(refused));
    try testing.expectEqual(entry_before, fixture.table.get(last).*);
    try testing.expectEqual(outcomes_before, sim.outcomes.s);
    try testing.expectEqual(constants.io_cancels_in_flight_max, sim.in_flight);
    // A send still goes in beside a full cancels' share, and the cancel once one is back.
    try sim.submit(.{ .id = cancel + 1, .operation = .{ .send = .{ .peer = 0, .bytes = "s" } } });
    var completions: [slots_count]io.Completion = undefined;
    try testing.expectEqual(constants.io_cancels_in_flight_max + 1, drainAll(&sim, &completions));
    try sim.submit(refused);
    try testing.expectEqual(@as(u32, 1), drainAll(&sim, &completions));
    try testing.expectEqual(@as(u32, 0), completions[0].result.cancel);
}

test "sim: a cancel skips what a drop settled or what was due, and a later drop leaves Canceled alone" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(26, 0);
    sim.attachTable(&fixture.table);
    sim.setDropFaults(constants.sim_fault_percent_max, 0);
    // Peer 1: a stuck send, ended by a working drop, then cancelled: the cancel reaches none.
    const dropped_id = try submitUntilStuck(&sim, 1, 0, 64);
    try sim.drop(1);
    try sim.submit(.{ .id = 300, .operation = .{ .cancel = .{ .peer = 1 } } });
    // Peer 2: a stuck send, cancelled, then dropped: it stays Canceled.
    const canceled_id = try submitUntilStuck(&sim, 2, 100, 64);
    try sim.submit(.{ .id = 301, .operation = .{ .cancel = .{ .peer = 2 } } });
    try sim.drop(2);
    var completions: [slots_count]io.Completion = undefined;
    const count = drainAll(&sim, &completions);
    var reached_by: [2]u32 = .{ 0, 0 };
    var canceled_sends: u32 = 0;
    for (completions[0..count]) |completion| switch (completion.result) {
        .send => |sent| {
            if (completion.id == dropped_id) try testing.expectError(error.PeerDown, sent);
            if (completion.id == canceled_id) try testing.expectError(error.Canceled, sent);
            // Only peer 2's sends, ids from 100, may be cancelled.
            if (sent == error.Canceled) {
                try testing.expect(completion.id >= 100);
                canceled_sends += 1;
            }
        },
        .cancel => |reached| reached_by[@intCast(completion.id - 300)] = reached,
        .accept, .execute, .receive => return error.TestUnexpectedResult,
    };
    // Peer 1's sends were all settled by its drop; peer 2's pending ones were reached.
    try testing.expectEqual(@as(u32, 0), reached_by[0]);
    try testing.expectEqual(canceled_sends, reached_by[1]);
    try testing.expect(canceled_sends >= 1);
    try testing.expectEqual(canceled_sends, sim.canceled);
}

test "sim: a cancel leaves an operation that was due already with its own result" {
    var fixture: TableFixture = undefined;
    try fixture.setUpPeers(test_peers);
    defer fixture.tearDown();
    var sim = Sim.init(27, 0);
    sim.attachTable(&fixture.table);
    try sim.submit(.{ .id = 0, .operation = .{ .send = .{ .peer = 3, .bytes = "due" } } });
    // Past the longest delay, so the send has finished, though nothing has polled it.
    var ticks: u32 = 0;
    while (ticks <= constants.sim_completion_delay_ticks_max) : (ticks += 1) sim.tick();
    try sim.submit(.{ .id = 1, .operation = .{ .cancel = .{ .peer = 3 } } });
    var completions: [2]io.Completion = undefined;
    try testing.expectEqual(@as(u32, 2), drainAll(&sim, &completions));
    for (completions) |completion| switch (completion.result) {
        .send => |sent| try testing.expectEqual(@as(u32, 3), try sent),
        .cancel => |reached| try testing.expectEqual(@as(u32, 0), reached),
        .accept, .execute, .receive => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(@as(u32, 0), sim.canceled);
}
