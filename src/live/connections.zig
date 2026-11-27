//! Connection table (roadmap core 4): maps each `PeerId` to its socket, its state and its
//! request head scan.
//!
//! Job:
//!   Hand out a `PeerId` for every accepted connection and take it back when the connection
//!   closes. A `PeerId` carries the index of an entry in a table allocated once at startup,
//!   so looking up a connection is one bounds-checked array access and the table never
//!   grows.
//!
//! Inputs:
//!   An allocator during startup (a `StartupAllocator`), the table's size, and the socket of
//!   each accepted connection.
//!
//! Outputs:
//!   `PeerId`s, the entry each one names, each connection's `HeadScan` for the request
//!   parser, and each socket back again on release, for the caller to close.
//!
//! Limits (src/constants.zig):
//!   http_connections_max: the largest table; callers may pass a smaller size to `init`.
//!   http_connection_entry_size_max: bytes of table state per connection, counted in the
//!   memory table.
//!
//! Free entries' indices sit on a stack, so `acquire` and `release` take constant time and
//! the entry released last is handed out first, under a new id. A full table refuses the
//! connection with `error.TableFull` and leaves every entry as it was.
//!
//! Each entry carries the connection's `HeadScan`, so the parser resumes its search for the
//! end of a request head between reads. `acquire` hands out an entry with an empty scan and
//! `release` empties it again, so a free entry never holds scan state and a reused entry
//! never inherits the last connection's.
//!
//! A `PeerId` names an entry and a generation of it: the low 16 bits of the 64 are the
//! entry's index and the high 48 bits the entry's generation, which `release` advances,
//! wrapping. An id handed out before a release is stale afterwards, so an I/O completion
//! that still names the old connection can't reach the next connection on that entry:
//! completions find their entry through `lookup`, which returns null for a stale id.
//! `get`, `headScan`, `setState` and `release` are for callers holding a live id, and
//! assert it is live.
//!
//! The limit: after 2^48 releases of one entry its generation is back where it started.
//! The free stack hands the same entry out again first, so a peer that keeps connecting
//! and closing gets the same entry back each time, as fast as the server can accept. Even at one release every
//! microsecond, far past what accept sustains, 2^48 releases take more than eight years,
//! which `generation_wrap_years_min` checks at compile time. No send or timer is meant to
//! hold an id for years, so a stale id doesn't match a later connection's in practice. At that rate a
//! 16-bit generation would wrap in under a tenth of a second and a 20-bit one in about a
//! second, which a timer or a slow client's write could easily outlast.
//!
//! Sends in flight: the I/O type captures a send's socket number when the send is
//! submitted, and the kernel may take the send later. If the entry were released and its
//! socket closed in between, Linux would hand the same number to the next accepted
//! connection, and the queued send would reach the wrong client. So each entry counts its
//! sends in flight: `sendSubmitted` raises the count, `sendCompleted` lowers it, and
//! `release` refuses with `error.OperationsInFlight`, changing nothing, while it is above zero.
//! A refusal is a state the caller meets in normal running (a second send still queued
//! when the first fails with `PeerDown`), so it is an error to handle, not a bug: the
//! caller stops sending on that connection and releases it after its last completion. A
//! send to a client that stops reading never completes on its own, so the caller first
//! drops the connection through the I/O type (`drop` in the I/O contract), which fails
//! every send still pending on its socket.
//!
//! Receives and cancels in flight (roadmap core 3b) hold the socket the same way, so the
//! entry counts them too, and `release` refuses while either is in flight. Each entry has at
//! most one receive in flight (`receiveSubmitted`), since two would split the connection's
//! bytes between their buffers, and at most one cancel. Once a cancel has been submitted the
//! entry is `canceled` until it is released, and no send or receive may be submitted on it:
//! the cancel reaches only what was in flight when it went in, so anything later could be
//! left stuck. A send or receive that completes with `error.Canceled` must have a canceled
//! entry (`assertCanceled`).
//!
//! Failed drops: a drop can fail (an errno shutdown(2) doesn't document), leaving the sends
//! pending. The I/O type counts each failure on the entry (`dropFailed`) and asks the entry
//! before each drop (`dropAdmit`); once `constants.io_drop_attempts_max` have failed, both
//! return `error.DropsExhausted`, so a socket that keeps failing can't be retried for ever.
//! The real type and the simulator make the same two calls. `release` clears the count, so
//! a reused entry starts with none.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const io = @import("../io/root.zig");
const http_request = @import("http_request.zig");
const connection_state = @import("connection_state.zig");

pub const PeerId = io.PeerId;

/// The position of an entry in the table: the low 16 bits of a `PeerId`.
pub const Index = u16;

/// How many times an entry has been released, wrapping: the high 48 bits of a `PeerId`.
pub const Generation = u48;

/// A `PeerId` split into its parts. A packed struct lays its fields out from the least
/// significant bit, so `@bitCast` between the two puts `index` in the low 16 bits and does
/// no arithmetic that could overflow. Every bit of the id belongs to one of the two
/// fields, so every id the table hands out round-trips through `@bitCast` unchanged.
pub const IdParts = packed struct(PeerId) {
    index: Index,
    generation: Generation,
};

/// The fewest years one entry's generation takes to wrap, released once every microsecond
/// with no pause. A release follows an accept and a close, so the real rate is far lower.
pub const generation_wrap_years_min: u64 = 8;

/// Releases per second the wrap check assumes for one entry: one every microsecond.
const releases_per_second_max: u64 = 1_000_000;

const seconds_per_year: u64 = 365 * 24 * 60 * 60;

/// A Linux file descriptor, as the I/O boundary defines it.
pub const Socket = io.Socket;

/// How far the search for the end of the current request head has got.
pub const HeadScan = http_request.HeadScan;

pub const AcquireError = error{TableFull};

/// `OperationsInFlight`: the connection still has sends, a receive or a cancel the kernel may
/// act on, so its socket must stay open; release it after the last one completes.
pub const ReleaseError = error{OperationsInFlight};

/// Sends in flight on one connection. Never more than the I/O type has slots for.
pub const SendCount = u16;

/// Failed drops of one connection. Never more than `constants.io_drop_attempts_max`.
pub const DropCount = u8;

pub const InitError = error{OutOfMemory};

/// Where a connection is in its life: the states of `connection_state.zig`, whose
/// transitions say which events move an entry between them.
pub const State = connection_state.State;

pub const Entry = struct {
    /// Meaningful only while `state` is not `free`.
    socket: Socket,
    state: State,
    /// Empty whenever `state` is `free`; the request parser advances it while the head is
    /// read (`idle` and `reading_head`).
    scan: HeadScan = .{},
    /// The generation every live id for this entry carries. Kept while the entry is free:
    /// `release` advances it, and the next `acquire` hands it out.
    generation: Generation = 0,
    /// Sends submitted on this connection whose completions haven't come back. Zero
    /// whenever `state` is `free`: `release` refuses while it is above zero.
    sends_in_flight: SendCount = 0,
    /// Drops of this connection that failed, leaving its sends pending. Zero whenever
    /// `state` is `free`: `release` clears it.
    drops_failed: DropCount = 0,
    /// A receive is in flight on this connection: at most one at a time. False whenever
    /// `state` is `free`: `release` refuses while it is set.
    receiving: bool = false,
    /// A cancel is in flight on this connection: at most one at a time. False whenever
    /// `state` is `free`: `release` refuses while it is set.
    cancel_in_flight: bool = false,
    /// A cancel has been submitted on this connection, so no send or receive may be any
    /// more. False whenever `state` is `free`: `release` clears it.
    canceled: bool = false,

    /// Whether any operation in flight still names this entry's socket.
    pub fn busy(self: *const Entry) bool {
        // A receive or a cancel in flight names a live connection's socket.
        assert(!(self.receiving or self.cancel_in_flight) or self.socket >= 0);
        // A cancel in flight marks the entry canceled for the rest of its life.
        assert(!self.cancel_in_flight or self.canceled);
        return self.sends_in_flight > 0 or self.receiving or self.cancel_in_flight;
    }
};

/// Bytes of table state one connection costs: its entry plus its slot on the free stack.
pub const entry_bytes: u32 = @sizeOf(Entry) + @sizeOf(Index);

comptime {
    assert(entry_bytes <= constants.http_connection_entry_size_max);
    assert(constants.http_connections_max > 0);
    // Every entry's index fits the low 16 bits of a PeerId.
    assert(constants.http_connections_max - 1 <= std.math.maxInt(Index));
    // The layout the docs promise: index in the low 16 bits, generation in the high 48.
    assert(@as(PeerId, @bitCast(IdParts{ .index = 1, .generation = 2 })) == 0x0002_0001);
    const generation_only: PeerId = @bitCast(IdParts{
        .index = 0,
        .generation = std.math.maxInt(Generation),
    });
    assert(generation_only == 0xffff_ffff_ffff_0000);
    // One entry, released as fast as releases_per_second_max allows, takes at least
    // generation_wrap_years_min years to bring its generation back to an id it handed out.
    const releases_per_wrap: u64 = std.math.maxInt(Generation) + 1;
    const releases_per_year: u64 = releases_per_second_max * seconds_per_year;
    assert(releases_per_wrap / releases_per_year >= generation_wrap_years_min);
    // Every operation in flight could be a send on one connection; its count still fits.
    assert(constants.io_operations_in_flight_max <= std.math.maxInt(SendCount));
    // An accept moves a free entry to idle, which acquire does directly.
    assert(connection_state.moves(.free, .idle));
    // Every failed drop the bound allows fits an entry's count.
    assert(constants.io_drop_attempts_max <= std.math.maxInt(DropCount));
}

pub const Table = struct {
    entries: []Entry,
    /// Free entries, a stack of indices: `free_indices[0..free_count]` are not in use.
    free_indices: []Index,
    free_count: u32,

    /// Allocates a table of `size` entries, all free. Call it during startup only.
    pub fn init(allocator: std.mem.Allocator, size: u32) InitError!Table {
        assert(size > 0);
        assert(size <= constants.http_connections_max);
        const entries = try allocator.alloc(Entry, size);
        errdefer allocator.free(entries);
        const free_indices = try allocator.alloc(Index, size);
        @memset(entries, .{ .socket = -1, .state = .free });
        // Push the indices in reverse, so the first acquire hands out entry 0.
        var position: u32 = 0;
        while (position < size) : (position += 1) {
            assert(position < free_indices.len);
            free_indices[position] = @intCast(size - 1 - position);
        }
        assert(position == size);
        const table: Table = .{
            .entries = entries,
            .free_indices = free_indices,
            .free_count = size,
        };
        table.assertInvariants();
        return table;
    }

    /// Frees the table's memory. Call it during shutdown only.
    pub fn deinit(self: *Table, allocator: std.mem.Allocator) void {
        self.assertInvariants();
        assert(self.entries.len == self.free_indices.len);
        allocator.free(self.free_indices);
        allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn capacity(self: *const Table) u32 {
        assert(self.entries.len == self.free_indices.len);
        assert(self.entries.len <= constants.http_connections_max);
        return @intCast(self.entries.len);
    }

    /// Connections in use.
    pub fn count(self: *const Table) u32 {
        const table_capacity = self.capacity();
        assert(table_capacity > 0);
        assert(self.free_count <= table_capacity);
        return table_capacity - self.free_count;
    }

    /// Takes a free entry for `socket` and returns its id, which carries the entry's
    /// current generation. The entry starts in `idle`, with an empty head scan. When
    /// every entry is in use, returns `error.TableFull` and changes nothing.
    pub fn acquire(self: *Table, socket: Socket) AcquireError!PeerId {
        assert(socket >= 0);
        const count_before = self.count();
        if (self.free_count == 0) {
            assert(count_before == self.capacity());
            return error.TableFull;
        }
        self.free_count -= 1;
        const index = self.free_indices[self.free_count];
        assert(index < self.capacity());
        const entry = &self.entries[index];
        assert(entry.state == .free); // A stacked index names a free entry.
        assert(entry.scan.resume_at == 0); // release empties the scan of every entry it frees.
        assert(entry.socket == -1); // release clears the socket of every entry it frees.
        assert(!entry.busy()); // release refuses an entry with anything in flight.
        assert(entry.drops_failed == 0); // release clears the failed drops of every entry.
        assert(!entry.canceled); // release clears the cancel of every entry.
        entry.socket = socket;
        entry.state = .idle;
        const id: PeerId = @bitCast(IdParts{ .index = index, .generation = entry.generation });
        assert(self.count() == count_before + 1);
        return id;
    }

    /// Returns `id`'s entry to the free stack, emptying its head scan and advancing its
    /// generation, so `id` is stale from now on. Hands back the socket, which the caller
    /// must close. While the connection has sends, a receive or a cancel in flight, returns
    /// `error.OperationsInFlight` and changes nothing. Releasing an entry not in use, or through
    /// a stale id, is a bug.
    pub fn release(self: *Table, id: PeerId) ReleaseError!Socket {
        const count_before = self.count();
        assert(count_before > 0);
        const index = self.liveIndex(id);
        const entry = &self.entries[index];
        const socket = entry.socket;
        assert(socket >= 0);
        if (entry.busy()) return error.OperationsInFlight;
        const generation_next = entry.generation +% 1;
        entry.* = .{ .socket = -1, .state = .free, .generation = generation_next };
        assert(self.free_count < self.capacity()); // An entry in use has no slot on the stack.
        self.free_indices[self.free_count] = index;
        self.free_count += 1;
        assert(self.count() == count_before - 1);
        return socket;
    }

    /// The entry `id` names, if it is in use under `id`'s generation; null for a free entry
    /// or a stale id (one released since it was handed out). For I/O completions, which
    /// can arrive after their connection was released. An index past the table is a bug,
    /// not a stale id: every id comes from `acquire`.
    pub fn lookup(self: *const Table, id: PeerId) ?*const Entry {
        const parts: IdParts = @bitCast(id);
        assert(parts.index < self.capacity());
        const entry = &self.entries[parts.index];
        if (entry.state == .free) return null;
        if (entry.generation != parts.generation) return null;
        assert(entry.socket >= 0);
        return entry;
    }

    /// The entry `id` names, which must be in use under `id`'s generation. Read-only:
    /// change its state through `setState`, its head scan through `headScan`, and free it
    /// through `release`.
    pub fn get(self: *const Table, id: PeerId) *const Entry {
        const entry = &self.entries[self.liveIndex(id)];
        assert(entry.socket >= 0);
        // The parser never resumes past the last three bytes of the largest request.
        assert(entry.scan.resume_at <= constants.http_request_size_max - 3);
        return entry;
    }

    /// The head scan of `id`'s connection, which must be live and reading a head (`idle` or
    /// `reading_head`), for the request parser to advance. `acquire` and `release` empty
    /// it; nothing else in the table touches it.
    pub fn headScan(self: *Table, id: PeerId) *HeadScan {
        const entry = &self.entries[self.liveIndex(id)];
        // Only a connection reading a head is parsed.
        assert(entry.state == .idle or entry.state == .reading_head);
        // The parser backs off three bytes from the end of a buffer of at most
        // http_request_size_max bytes, so it never resumes past that.
        assert(entry.scan.resume_at <= constants.http_request_size_max - 3);
        return &entry.scan;
    }

    /// Moves `id`'s connection to `state`, which some event of the state machine must lead
    /// to from where the connection is (`connection_state.moves`). Only `release` frees an
    /// entry, so the free stack and the entries always agree.
    pub fn setState(self: *Table, id: PeerId, state: State) void {
        assert(state != .free); // Free an entry through release.
        const entry = &self.entries[self.liveIndex(id)];
        assert(connection_state.moves(entry.state, state)); // A move no event leads to.
        // A parsed head empties the scan, so a connection never reads a body or writes with
        // a scan part way, and a connection kept alive goes back to idle with it empty.
        const scan_empty = entry.scan.resume_at == 0;
        assert(scan_empty or (state != .writing and state != .reading_body and state != .idle));
        entry.state = state;
    }

    /// Counts a send just submitted on `id`'s connection, which must be live. Until the
    /// matching `sendCompleted`, `release` refuses the entry, so its socket stays open and
    /// its number can't pass to another connection.
    pub fn sendSubmitted(self: *Table, id: PeerId) void {
        const entry = &self.entries[self.liveIndex(id)];
        assert(entry.socket >= 0);
        // The I/O type has at most this many operations in flight, sends or not.
        assert(entry.sends_in_flight < constants.io_operations_in_flight_max);
        // A cancel reaches only what was in flight when it went in.
        assert(!entry.canceled);
        entry.sends_in_flight += 1;
    }

    /// Counts a send on `id`'s connection as completed. `id` must still be live: `release`
    /// refused it while the send was in flight, so a stale id here means a send outlived
    /// its connection, or was never counted.
    pub fn sendCompleted(self: *Table, id: PeerId) void {
        const entry = &self.entries[self.liveIndex(id)];
        assert(entry.socket >= 0);
        assert(entry.sends_in_flight > 0); // A completion for a send never counted.
        entry.sends_in_flight -= 1;
    }

    /// Counts a receive just submitted on `id`'s connection, which must be live, have no
    /// receive in flight already and not be canceled. Until the matching `receiveCompleted`,
    /// `release` refuses the entry.
    pub fn receiveSubmitted(self: *Table, id: PeerId) void {
        const entry = &self.entries[self.liveIndex(id)];
        assert(entry.socket >= 0);
        // Two receives would split the connection's bytes between their buffers.
        assert(!entry.receiving);
        // A cancel reaches only what was in flight when it went in.
        assert(!entry.canceled);
        entry.receiving = true;
    }

    /// Counts the receive on `id`'s connection as completed. `id` must still be live, as for
    /// `sendCompleted`.
    pub fn receiveCompleted(self: *Table, id: PeerId) void {
        const entry = &self.entries[self.liveIndex(id)];
        assert(entry.socket >= 0);
        assert(entry.receiving); // A completion for a receive never counted.
        entry.receiving = false;
    }

    /// Counts a cancel just submitted on `id`'s connection, which must be live and have no
    /// cancel in flight already. The entry is canceled from now until it is released: no
    /// send or receive may be submitted on it. Until the matching `cancelCompleted`,
    /// `release` refuses the entry.
    pub fn cancelSubmitted(self: *Table, id: PeerId) void {
        const entry = &self.entries[self.liveIndex(id)];
        assert(entry.socket >= 0);
        // The caller waits for one cancel's completion before it submits another.
        assert(!entry.cancel_in_flight);
        entry.cancel_in_flight = true;
        entry.canceled = true;
    }

    /// Counts the cancel on `id`'s connection as completed. `id` must still be live, as for
    /// `sendCompleted`. The entry stays canceled.
    pub fn cancelCompleted(self: *Table, id: PeerId) void {
        const entry = &self.entries[self.liveIndex(id)];
        assert(entry.canceled); // Set by cancelSubmitted, cleared only by release.
        assert(entry.cancel_in_flight); // A completion for a cancel never counted.
        entry.cancel_in_flight = false;
    }

    /// Stops the process unless `id`'s connection, which must be live, takes one more
    /// operation of `kind` right now: a send or a receive only before any cancel, a second
    /// receive or a second cancel never while one is in flight. The I/O type calls it
    /// before it checks anything that can refuse the submission, so a caller's bug stops
    /// the process however full the queue is. Changes nothing.
    pub fn assertRoomFor(self: *const Table, id: PeerId, kind: io.Kind) void {
        const entry = &self.entries[self.liveIndex(id)];
        assert(entry.socket >= 0);
        assert(kind != .accept and kind != .execute); // Neither names a connection.
        switch (kind) {
            .send => assert(!entry.canceled),
            .receive => assert(!entry.canceled and !entry.receiving),
            .cancel => assert(!entry.cancel_in_flight),
            .accept, .execute => unreachable, // Asserted above.
        }
    }

    /// Counts `operation` on its peer's entry, just submitted: a send, a receive or a
    /// cancel, through the call for its kind. The real type and the simulator both call
    /// this, so the counts can't differ between them.
    pub fn operationSubmitted(self: *Table, operation: io.Operation) void {
        const count_before = self.operationCount(operation);
        switch (operation) {
            .send => |send| self.sendSubmitted(send.peer),
            .receive => |receive| self.receiveSubmitted(receive.peer),
            .cancel => |cancel| self.cancelSubmitted(cancel.peer),
            .accept, .execute => {},
        }
        const added: u32 = @intFromBool(io.operationPeer(operation) != null);
        assert(self.operationCount(operation) == count_before + added);
        // A cancel marks its entry for the rest of the connection's life.
        assert(operation != .cancel or self.get(operation.cancel.peer).canceled);
    }

    /// Uncounts `operation` on its peer's entry, just completed, through the call for its
    /// kind; the peer must still be live.
    pub fn operationCompleted(self: *Table, operation: io.Operation) void {
        const peer = io.operationPeer(operation).?; // Only a peer's operation is counted.
        const count_before = self.operationCount(operation);
        assert(count_before > 0);
        switch (operation) {
            .send => self.sendCompleted(peer),
            .receive => self.receiveCompleted(peer),
            .cancel => self.cancelCompleted(peer),
            .accept, .execute => unreachable, // Asserted above: they name no peer.
        }
        assert(self.operationCount(operation) == count_before - 1);
    }

    /// What `operation`'s peer entry counts of its kind: the sends in flight, or 1 while a
    /// receive or a cancel is; 0 for an accept or a statement, which name no peer.
    pub fn operationCount(self: *const Table, operation: io.Operation) u32 {
        const counted: u32 = switch (operation) {
            .send => |send| self.get(send.peer).sends_in_flight,
            .receive => |receive| @intFromBool(self.get(receive.peer).receiving),
            .cancel => |cancel| @intFromBool(self.get(cancel.peer).cancel_in_flight),
            .accept, .execute => 0,
        };
        assert(io.operationPeer(operation) != null or counted == 0);
        assert(counted <= constants.io_operations_in_flight_max);
        return counted;
    }

    /// Stops the process unless `id`'s connection, which must be live, has been canceled:
    /// for an I/O type handing back a send or a receive that completed with
    /// `error.Canceled`, which only a cancel of its connection causes.
    pub fn assertCanceled(self: *const Table, id: PeerId) void {
        const entry = &self.entries[self.liveIndex(id)];
        assert(entry.socket >= 0);
        assert(entry.canceled);
    }

    /// Refuses a drop of `id`'s connection, which must be live, with `error.DropsExhausted`
    /// once `constants.io_drop_attempts_max` of its drops have failed. Changes nothing. The
    /// I/O type calls it before it tries the drop.
    pub fn dropAdmit(self: *const Table, id: PeerId) io.DropError!void {
        const entry = &self.entries[self.liveIndex(id)];
        assert(entry.socket >= 0);
        // dropFailed counts no failure past the bound.
        assert(entry.drops_failed <= constants.io_drop_attempts_max);
        if (entry.drops_failed == constants.io_drop_attempts_max) return error.DropsExhausted;
    }

    /// Counts a failed drop of `id`'s connection, which must be live and admitted by
    /// `dropAdmit`; returns `error.DropsExhausted` when that failure was the last one allowed,
    /// so the caller learns at once that it must cancel instead.
    pub fn dropFailed(self: *Table, id: PeerId) io.DropError!void {
        const entry = &self.entries[self.liveIndex(id)];
        assert(entry.socket >= 0);
        // dropAdmit refused a drop past the bound, so no failure is counted past it.
        assert(entry.drops_failed < constants.io_drop_attempts_max);
        entry.drops_failed += 1;
        if (entry.drops_failed == constants.io_drop_attempts_max) return error.DropsExhausted;
    }

    /// The index of `id`'s entry, checking that `id` is live: inside the table, naming an
    /// entry in use, and carrying that entry's generation. For callers holding a live id;
    /// completions, which may hold a stale one, go through `lookup`.
    fn liveIndex(self: *const Table, id: PeerId) Index {
        const parts: IdParts = @bitCast(id);
        assert(parts.index < self.capacity());
        const entry = &self.entries[parts.index];
        assert(entry.state != .free); // An entry not in use.
        assert(entry.generation == parts.generation); // A stale id: released since.
        return parts.index;
    }

    /// Checks that the free stack and the entries agree: every stacked index is free and
    /// stacked once, and no other entry is free. It walks the whole table, so it runs at
    /// startup, at shutdown and in tests; each method keeps cheaper checks of its own.
    pub fn assertInvariants(self: *const Table) void {
        const table_capacity = self.capacity();
        assert(self.free_count <= table_capacity);
        var stacked: std.bit_set.Static(constants.http_connections_max) = .empty;
        for (self.free_indices[0..self.free_count]) |index| {
            assert(index < table_capacity);
            assert(self.entries[index].state == .free);
            assert(self.entries[index].scan.resume_at == 0); // A free entry holds no scan.
            assert(self.entries[index].socket == -1);
            assert(!self.entries[index].busy()); // release refuses those.
            assert(self.entries[index].drops_failed == 0); // release clears them.
            assert(!self.entries[index].canceled); // release clears it.
            assert(!stacked.isSet(index)); // An index on the free stack twice.
            stacked.set(index);
        }
        for (self.entries, 0..) |entry, index| {
            assert((entry.state == .free) == stacked.isSet(index));
        }
    }
};

const testing = std.testing;
const StartupAllocator = @import("../startup_allocator.zig").StartupAllocator;

const connection_row_name = "Connection table entry and free-index slot, one per connection";

/// The table's row in the memory table.
fn memoryRow() constants.MemoryRow {
    var found: ?constants.MemoryRow = null;
    for (constants.memory_table) |row| {
        if (std.mem.eql(u8, row.name, connection_row_name)) {
            assert(found == null);
            found = row;
        }
    }
    const row = found.?;
    assert(row.count > 0);
    return row;
}

test "connections: fill to the limit, then the next acquire fails and changes nothing" {
    // The budget is exactly the table's memory-table row, so a full table fits its row.
    const row = memoryRow();
    const size = constants.http_connections_max;
    var startup = StartupAllocator.init(testing.allocator, row.count * row.size);
    const gpa = startup.allocator();
    var table = try Table.init(gpa, size);
    startup.finishStartup();

    var expected: PeerId = 0;
    while (expected < size) : (expected += 1) {
        const socket: Socket = @intCast(expected + 3);
        try testing.expectEqual(expected, try table.acquire(socket));
        try testing.expectEqual(socket, table.get(expected).socket);
    }
    table.assertInvariants();
    try testing.expectEqual(size, table.count());

    try testing.expectError(error.TableFull, table.acquire(99));
    try testing.expectEqual(size, table.count());
    try testing.expectEqual(@as(u32, 0), table.free_count);
    try testing.expectEqual(@as(Socket, 3), table.get(0).socket);
    try testing.expectEqual(@as(Socket, size + 2), table.get(size - 1).socket);
    table.assertInvariants();

    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "connections: a refused acquire leaves every entry and free index as it was" {
    var startup = StartupAllocator.init(testing.allocator, 4 * entry_bytes);
    const gpa = startup.allocator();
    var table = try Table.init(gpa, 4);
    startup.finishStartup();

    _ = try table.acquire(10);
    _ = try table.acquire(11);
    _ = try table.acquire(12);
    _ = try table.acquire(13);
    table.setState(2, .writing);
    var entries_before: [4]Entry = undefined;
    var free_indices_before: [4]Index = undefined;
    @memcpy(&entries_before, table.entries);
    @memcpy(&free_indices_before, table.free_indices);

    try testing.expectError(error.TableFull, table.acquire(14));
    try testing.expectEqualSlices(Entry, &entries_before, table.entries);
    try testing.expectEqualSlices(Index, &free_indices_before, table.free_indices);
    try testing.expectEqual(@as(u32, 0), table.free_count);

    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "connections: release hands back the socket, then acquire reuses the entry anew" {
    var startup = StartupAllocator.init(testing.allocator, 4 * entry_bytes);
    const gpa = startup.allocator();
    var table = try Table.init(gpa, 4);
    startup.finishStartup();

    const first = try table.acquire(10);
    const second = try table.acquire(11);
    try testing.expectEqual(@as(PeerId, 0), first);
    try testing.expectEqual(@as(PeerId, 1), second);
    table.setState(first, .writing);
    try testing.expectEqual(State.writing, table.get(first).state);

    try testing.expectEqual(@as(Socket, 10), try table.release(first));
    try testing.expectEqual(@as(u32, 1), table.count());
    table.assertInvariants();

    const reused = try table.acquire(12);
    try testing.expect(reused != first);
    const first_parts: IdParts = @bitCast(first);
    const reused_parts: IdParts = @bitCast(reused);
    try testing.expectEqual(first_parts.index, reused_parts.index);
    try testing.expectEqual(first_parts.generation +% 1, reused_parts.generation);
    // The old id is stale: lookup refuses it, and the new one finds the same entry.
    try testing.expectEqual(@as(?*const Entry, null), table.lookup(first));
    try testing.expectEqual(table.get(reused), table.lookup(reused).?);
    try testing.expectEqual(State.idle, table.get(reused).state);
    try testing.expectEqual(@as(Socket, 12), table.get(reused).socket);
    try testing.expectEqual(@as(Socket, 11), table.get(second).socket);
    try testing.expectEqual(@as(u32, 2), table.count());
    table.assertInvariants();

    try testing.expectEqual(@as(Socket, 11), try table.release(second));
    try testing.expectEqual(@as(Socket, 12), try table.release(reused));
    try testing.expectEqual(@as(u32, 0), table.count());
    table.assertInvariants();

    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "connections: a connection with sends in flight is refused release, changing nothing" {
    var startup = StartupAllocator.init(testing.allocator, 4 * entry_bytes);
    const gpa = startup.allocator();
    var table = try Table.init(gpa, 4);
    startup.finishStartup();

    const busy = try table.acquire(10);
    const idle = try table.acquire(11);
    table.sendSubmitted(busy);
    table.sendSubmitted(busy);
    try testing.expectEqual(@as(SendCount, 2), table.get(busy).sends_in_flight);
    var entries_before: [4]Entry = undefined;
    var free_indices_before: [4]Index = undefined;
    @memcpy(&entries_before, table.entries);
    @memcpy(&free_indices_before, table.free_indices);

    // Refused while either send is in flight; the entry, its id and the stack stay as they were.
    try testing.expectError(error.OperationsInFlight, table.release(busy));
    try testing.expectEqualSlices(Entry, &entries_before, table.entries);
    try testing.expectEqualSlices(Index, &free_indices_before, table.free_indices);
    try testing.expectEqual(@as(u32, 2), table.count());
    try testing.expectEqual(table.get(busy), table.lookup(busy).?);
    table.sendCompleted(busy);
    try testing.expectError(error.OperationsInFlight, table.release(busy));
    try testing.expectEqual(@as(u32, 2), table.count());
    // The other connection's count is its own: it releases at once.
    try testing.expectEqual(@as(Socket, 11), try table.release(idle));
    table.assertInvariants();

    // After the last completion the release goes through, and the entry comes back empty.
    table.sendCompleted(busy);
    try testing.expectEqual(@as(Socket, 10), try table.release(busy));
    try testing.expectEqual(@as(?*const Entry, null), table.lookup(busy));
    const reused = try table.acquire(12);
    try testing.expectEqual(@as(SendCount, 0), table.get(reused).sends_in_flight);
    table.assertInvariants();

    _ = try table.release(reused);
    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "connections: one connection can count a send in every I/O slot" {
    var startup = StartupAllocator.init(testing.allocator, entry_bytes);
    const gpa = startup.allocator();
    var table = try Table.init(gpa, 1);
    startup.finishStartup();

    const id = try table.acquire(10);
    const sends_max = constants.io_operations_in_flight_max;
    var sends: u32 = 0;
    while (sends < sends_max) : (sends += 1) table.sendSubmitted(id);
    try testing.expectEqual(@as(SendCount, @intCast(sends_max)), table.get(id).sends_in_flight);
    try testing.expectError(error.OperationsInFlight, table.release(id));
    while (sends > 0) : (sends -= 1) table.sendCompleted(id);
    try testing.expectEqual(@as(SendCount, 0), table.get(id).sends_in_flight);
    try testing.expectEqual(@as(Socket, 10), try table.release(id));

    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "connections: a fresh entry starts with an empty head scan" {
    var startup = StartupAllocator.init(testing.allocator, 2 * entry_bytes);
    const gpa = startup.allocator();
    var table = try Table.init(gpa, 2);
    startup.finishStartup();

    for (table.entries) |entry| try testing.expectEqual(@as(u32, 0), entry.scan.resume_at);
    const id = try table.acquire(10);
    try testing.expectEqual(@as(u32, 0), table.get(id).scan.resume_at);
    try testing.expectEqual(@as(u32, 0), table.headScan(id).resume_at);

    _ = try table.release(id);
    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "connections: an entry released mid-scan is acquired again with an empty scan" {
    var startup = StartupAllocator.init(testing.allocator, 2 * entry_bytes);
    const gpa = startup.allocator();
    var table = try Table.init(gpa, 2);
    startup.finishStartup();

    const first = try table.acquire(10);
    const other = try table.acquire(11);
    // Half a request head: the parser asks for more and remembers where it got to.
    const partial = "GET /index HTTP/1.1\r\nHost: example\r\n";
    try testing.expectError(error.Incomplete, http_request.parse(partial, table.headScan(first)));
    try testing.expect(table.get(first).scan.resume_at > 0);
    // The other connection's scan is its own, and resumes through the table to a request.
    try testing.expectEqual(@as(u32, 0), table.get(other).scan.resume_at);
    const grown = "POST /form HTTP/1.1\r\nHost: example\r\nContent-Length: 0\r\n\r\n";
    const cut: u32 = 30;
    try testing.expectError(error.Incomplete, http_request.parse(grown[0..cut], table.headScan(other)));
    try testing.expect(table.get(other).scan.resume_at > 0);
    const resumed = try http_request.parse(grown, table.headScan(other));
    try testing.expectEqual(@as(u32, grown.len), resumed.head_len);
    try testing.expectEqual(@as(u32, 0), table.get(other).scan.resume_at);
    table.setState(other, .writing);

    _ = try table.release(first);
    const first_index = @as(IdParts, @bitCast(first)).index;
    try testing.expectEqual(@as(u32, 0), table.entries[first_index].scan.resume_at);
    table.assertInvariants();
    const reused = try table.acquire(12);
    try testing.expectEqual(first_index, @as(IdParts, @bitCast(reused)).index);
    try testing.expectEqual(@as(?*const Entry, null), table.lookup(first));
    try testing.expectEqual(@as(u32, 0), table.get(reused).scan.resume_at);
    // A new connection's head parses from the start of its buffer.
    const whole = "GET / HTTP/1.1\r\nHost: example\r\n\r\n";
    const request = try http_request.parse(whole, table.headScan(reused));
    try testing.expectEqual(@as(u32, whole.len), request.head_len);
    try testing.expectEqual(@as(u32, 0), table.get(reused).scan.resume_at);

    _ = try table.release(other);
    _ = try table.release(reused);
    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "connections: a smaller table refuses at its own size" {
    var startup = StartupAllocator.init(testing.allocator, 2 * entry_bytes);
    const gpa = startup.allocator();
    var table = try Table.init(gpa, 2);
    startup.finishStartup();

    try testing.expectEqual(@as(u32, 2), table.capacity());
    _ = try table.acquire(5);
    _ = try table.acquire(6);
    try testing.expectError(error.TableFull, table.acquire(7));
    try testing.expectEqual(@as(u32, 2), table.count());
    table.assertInvariants();

    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "connections: init past the budget returns OutOfMemory and leaks nothing" {
    // Room for the entries but not the free stack, so the second allocation fails and the
    // first is freed again.
    const size = constants.http_connections_max;
    var startup = StartupAllocator.init(testing.allocator, @as(u64, size) * @sizeOf(Entry));
    const gpa = startup.allocator();
    try testing.expectError(error.OutOfMemory, Table.init(gpa, size));
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
    // The same budget holds a smaller table whole.
    var table = try Table.init(gpa, size / 2);
    try testing.expect(startup.bytes_live > 0);
    startup.finishStartup();
    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "connections: the memory table counts a full table" {
    const row = memoryRow();
    try testing.expect(row.count >= constants.http_connections_max);
    try testing.expect(row.size >= entry_bytes);
    const budget = constants.memory_budget_bytes;
    try testing.expect(constants.memoryTableFits(&constants.memory_table, budget));
}

/// What the seeded test expects of each entry of its table.
/// The seeded test's table size: small, so random runs often hit full and empty.
const seeded_size: u32 = 64;

const SeededModel = struct {
    /// The socket each entry in use was given, or -1.
    sockets: [seeded_size]Socket = @splat(-1),
    /// The live id of each entry in use; meaningful only where `sockets` isn't -1.
    ids: [seeded_size]PeerId = undefined,
    /// The last id each entry was released under, stale ever since.
    stale_ids: [seeded_size]?PeerId = @splat(null),
    /// Releases of each entry so far, which its generation must match.
    releases: [seeded_size]u32 = @splat(0),
    /// Sends in flight on each entry in use, which its count must match.
    sends: [seeded_size]SendCount = @splat(0),
    in_use: u32 = 0,

    /// One accept: a free entry under the generation its releases predict, or a refusal
    /// only when full. Returns whether the table refused.
    fn accept(model: *SeededModel, table: *Table, socket: Socket, random: std.Random) !bool {
        assert(model.in_use <= seeded_size);
        const id = table.acquire(socket) catch |err| switch (err) {
            error.TableFull => {
                try testing.expectEqual(seeded_size, model.in_use);
                return true;
            },
        };
        const parts: IdParts = @bitCast(id);
        try testing.expectEqual(@as(Socket, -1), model.sockets[parts.index]);
        const generation: Generation = model.releases[parts.index];
        try testing.expectEqual(generation, parts.generation);
        try testing.expectEqual(@as(u32, 0), table.get(id).scan.resume_at);
        // Leave some scans part way, so releases mid-scan are exercised too.
        const resume_max = constants.http_request_size_max - 3;
        table.headScan(id).resume_at = random.uintAtMost(u32, resume_max);
        model.sockets[parts.index] = socket;
        model.ids[parts.index] = id;
        model.in_use += 1;
        assert(model.in_use <= seeded_size);
        return false;
    }

    /// A random connection in use, found by probing from a random entry.
    fn pick(model: *const SeededModel, random: std.Random) Index {
        assert(model.in_use > 0);
        var index = random.uintLessThan(Index, seeded_size);
        var probes: u32 = 0;
        while (model.sockets[index] == -1) : (probes += 1) {
            assert(probes < seeded_size);
            index = @intCast((index + 1) % seeded_size);
        }
        assert(model.sockets[index] >= 0);
        return index;
    }

    /// One send submitted on, or completed for, a random connection in use. Completes when
    /// that connection has the most sends the I/O type could have in flight.
    fn send(model: *SeededModel, table: *Table, random: std.Random) !void {
        const index = model.pick(random);
        const id = model.ids[index];
        const sends_max = constants.io_operations_in_flight_max;
        const complete = model.sends[index] == sends_max or
            (model.sends[index] > 0 and random.boolean());
        if (complete) {
            table.sendCompleted(id);
            model.sends[index] -= 1;
        } else {
            table.sendSubmitted(id);
            model.sends[index] += 1;
        }
        try testing.expectEqual(model.sends[index], table.get(id).sends_in_flight);
        assert(model.sends[index] <= sends_max);
    }

    /// One close of a random connection in use. With sends in flight the table must refuse
    /// it and change nothing; the model then completes one, so later closes can go through.
    /// Returns whether the table refused.
    fn close(model: *SeededModel, table: *Table, random: std.Random) !bool {
        const index = model.pick(random);
        const id = model.ids[index];
        if (model.sends[index] > 0) {
            const entry_before = table.entries[index];
            try testing.expectError(error.OperationsInFlight, table.release(id));
            try testing.expectEqual(entry_before, table.entries[index]);
            table.sendCompleted(id);
            model.sends[index] -= 1;
            return true;
        }
        try testing.expectEqual(model.sockets[index], try table.release(id));
        try testing.expectEqual(@as(u32, 0), table.entries[index].scan.resume_at);
        model.sockets[index] = -1;
        model.stale_ids[index] = id;
        model.releases[index] += 1;
        model.in_use -= 1;
        assert(model.in_use < seeded_size);
        return false;
    }
};

test "connections: seeded random accepts and closes against a model, filling the table" {
    const size = seeded_size;
    const steps_max: u32 = 20_000;
    var startup = StartupAllocator.init(testing.allocator, size * entry_bytes);
    const gpa = startup.allocator();
    var table = try Table.init(gpa, size);
    startup.finishStartup();

    var prng: std.Random.DefaultPrng = .init(0x5eed);
    const random = prng.random();
    var model: SeededModel = .{};
    var full_refusals: u32 = 0;
    var busy_refusals: u32 = 0;
    var stale_lookups: u32 = 0;
    var step: u32 = 0;
    while (step < steps_max) : (step += 1) {
        // Lean toward accepts, so the table fills and refuses; sends are as common as closes.
        const roll = random.uintLessThan(u8, 10);
        if (roll < 5) {
            const socket: Socket = @intCast(100 + step);
            if (try model.accept(&table, socket, random)) full_refusals += 1;
        } else if (model.in_use > 0 and roll < 7) {
            try model.send(&table, random);
        } else if (model.in_use > 0) {
            if (try model.close(&table, random)) busy_refusals += 1;
        }
        // A completion naming any released id finds nothing, whether its entry is free or
        // was handed out again.
        if (model.stale_ids[random.uintLessThan(Index, size)]) |stale| {
            try testing.expectEqual(@as(?*const Entry, null), table.lookup(stale));
            stale_lookups += 1;
        }
        try testing.expectEqual(model.in_use, table.count());
        if (step % 1024 == 0) table.assertInvariants();
    }
    table.assertInvariants();
    try testing.expect(full_refusals > 0);
    try testing.expect(busy_refusals > 0);
    try testing.expect(stale_lookups > 0);

    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "connections: lookup finds a live id and refuses a free entry's id" {
    var startup = StartupAllocator.init(testing.allocator, 2 * entry_bytes);
    const gpa = startup.allocator();
    var table = try Table.init(gpa, 2);
    startup.finishStartup();

    // Entry 1 has never been handed out, and entry 0 is free again after a release: an
    // id naming either, at any generation, finds nothing.
    const id = try table.acquire(10);
    try testing.expectEqual(table.get(id), table.lookup(id).?);
    const never_handed_out: PeerId = @bitCast(IdParts{ .index = 1, .generation = 0 });
    try testing.expectEqual(@as(?*const Entry, null), table.lookup(never_handed_out));
    _ = try table.release(id);
    try testing.expectEqual(@as(?*const Entry, null), table.lookup(id));
    const advanced: PeerId = @bitCast(IdParts{ .index = 0, .generation = 1 });
    try testing.expectEqual(@as(?*const Entry, null), table.lookup(advanced));
    // The next acquire hands out exactly that advanced id.
    try testing.expectEqual(advanced, try table.acquire(11));
    try testing.expectEqual(@as(Socket, 11), table.lookup(advanced).?.socket);

    _ = try table.release(advanced);
    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "connections: an entry's first id stays stale across 65,536 reuses" {
    // One entry, so the free stack hands it back on every acquire. 65,536 reuses wrapped a 16-bit generation back to the first id; the 48-bit one
    // must leave that id stale at every step, and the newest id live.
    var startup = StartupAllocator.init(testing.allocator, entry_bytes);
    const gpa = startup.allocator();
    var table = try Table.init(gpa, 1);
    startup.finishStartup();

    const first = try table.acquire(10);
    try testing.expectEqual(@as(Generation, 0), @as(IdParts, @bitCast(first)).generation);
    const cycles: u32 = std.math.maxInt(u16) + 1;
    var id = first;
    var cycle: u32 = 0;
    while (cycle < cycles) : (cycle += 1) {
        const socket: Socket = @intCast(11 + cycle % 1000);
        try testing.expectEqual(table.get(id).socket, try table.release(id));
        const next = try table.acquire(socket);
        try testing.expect(next != first);
        try testing.expectEqual(@as(?*const Entry, null), table.lookup(first));
        try testing.expectEqual(@as(?*const Entry, null), table.lookup(id));
        try testing.expectEqual(socket, table.lookup(next).?.socket);
        id = next;
    }
    try testing.expectEqual(cycles, cycle);
    // The generation counted every release: none was lost to a narrower field.
    const parts: IdParts = @bitCast(id);
    try testing.expectEqual(@as(Index, 0), parts.index);
    try testing.expectEqual(@as(Generation, cycles), parts.generation);
    // The low 32 bits are the id a 16-bit generation would give, which had wrapped back to
    // the first id; the full id differs from it, and the first id stays stale.
    const narrow_now: u32 = @truncate(id);
    const narrow_first: u32 = @truncate(first);
    try testing.expectEqual(narrow_first, narrow_now);
    try testing.expect(id != first);
    try testing.expectEqual(@as(?*const Entry, null), table.lookup(first));

    _ = try table.release(id);
    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "connections: an id differing from the live one in any single generation bit is stale" {
    // Every one of the generation's 48 bits takes part in the check: an id that matches the
    // live id but for one bit, from the lowest to the top one, finds nothing.
    var startup = StartupAllocator.init(testing.allocator, 2 * entry_bytes);
    const gpa = startup.allocator();
    var table = try Table.init(gpa, 2);
    startup.finishStartup();

    _ = try table.acquire(10);
    const live = try table.acquire(11);
    try testing.expectEqual(@as(Index, 1), @as(IdParts, @bitCast(live)).index);
    const bits: u32 = @bitSizeOf(Generation);
    var bit: u32 = 0;
    while (bit < bits) : (bit += 1) {
        const flip: Generation = @as(Generation, 1) << @intCast(bit);
        const other: PeerId = @bitCast(IdParts{ .index = 1, .generation = flip });
        try testing.expect(other != live);
        try testing.expectEqual(@as(?*const Entry, null), table.lookup(other));
    }
    try testing.expectEqual(bits, bit);
    try testing.expectEqual(@as(Socket, 11), table.lookup(live).?.socket);

    _ = try table.release(live);
    _ = try table.release(@bitCast(IdParts{ .index = 0, .generation = 0 }));
    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "connections: a generation wraps to zero, and only the newest id is live" {
    // 2^48 releases can't run in a test, so the entry starts free just below its largest
    // generation, as if released that many times, and the last few releases wrap it.
    var startup = StartupAllocator.init(testing.allocator, entry_bytes);
    const gpa = startup.allocator();
    var table = try Table.init(gpa, 1);
    startup.finishStartup();

    const generation_max = std.math.maxInt(Generation);
    const steps: u32 = 4;
    table.entries[0].generation = generation_max - @as(Generation, steps - 2);
    table.assertInvariants();
    var id = try table.acquire(10);
    const before_wrap = id;
    var step: u32 = 0;
    while (step < steps) : (step += 1) {
        const socket: Socket = @intCast(11 + step);
        try testing.expectEqual(table.get(id).socket, try table.release(id));
        const next = try table.acquire(socket);
        try testing.expectEqual(@as(?*const Entry, null), table.lookup(id));
        try testing.expectEqual(socket, table.lookup(next).?.socket);
        const generation_was = @as(IdParts, @bitCast(id)).generation;
        const generation_now = @as(IdParts, @bitCast(next)).generation;
        try testing.expectEqual(generation_was +% 1, generation_now);
        id = next;
    }
    try testing.expectEqual(steps, step);
    // The wrap went through the largest generation to zero and on, never carrying into
    // the index.
    const parts: IdParts = @bitCast(id);
    try testing.expectEqual(@as(Index, 0), parts.index);
    try testing.expectEqual(@as(Generation, 1), parts.generation);
    const last_stale: PeerId = @bitCast(IdParts{ .index = 0, .generation = generation_max });
    try testing.expectEqual(@as(?*const Entry, null), table.lookup(last_stale));
    try testing.expectEqual(@as(?*const Entry, null), table.lookup(before_wrap));

    _ = try table.release(id);
    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "connections: failed drops are counted to the bound, per connection, and release clears them" {
    var startup = StartupAllocator.init(testing.allocator, 2 * entry_bytes);
    const gpa = startup.allocator();
    var table = try Table.init(gpa, 2);
    startup.finishStartup();

    const failing = try table.acquire(10);
    const other = try table.acquire(11);
    const bound = constants.io_drop_attempts_max;
    var failures: DropCount = 0;
    // Every failure before the last is admitted again; the last says so at once.
    while (failures < bound - 1) : (failures += 1) {
        try table.dropAdmit(failing);
        try table.dropFailed(failing);
    }
    try table.dropAdmit(failing);
    try testing.expectError(error.DropsExhausted, table.dropFailed(failing));
    try testing.expectEqual(@as(DropCount, bound), table.get(failing).drops_failed);
    // From then on every drop is refused, and the refusal changes nothing.
    const entry_before = table.get(failing).*;
    try testing.expectError(error.DropsExhausted, table.dropAdmit(failing));
    try testing.expectEqual(entry_before, table.get(failing).*);
    // The other connection's count is its own.
    try table.dropAdmit(other);
    try testing.expectEqual(@as(DropCount, 0), table.get(other).drops_failed);

    // A reused entry starts with no failed drops.
    try testing.expectEqual(@as(Socket, 10), try table.release(failing));
    const reused = try table.acquire(12);
    try testing.expectEqual(@as(DropCount, 0), table.get(reused).drops_failed);
    try table.dropAdmit(reused);
    table.assertInvariants();

    _ = try table.release(reused);
    _ = try table.release(other);
    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "connections: a receive or a cancel in flight refuses release, changing nothing, and each is counted alone" {
    var startup = StartupAllocator.init(testing.allocator, 4 * entry_bytes);
    const gpa = startup.allocator();
    var table = try Table.init(gpa, 4);
    startup.finishStartup();

    const reading = try table.acquire(10);
    const closing = try table.acquire(11);
    const receive: io.Operation = .{ .receive = .{ .peer = reading, .buffer = &.{} } };
    const cancel: io.Operation = .{ .cancel = .{ .peer = closing } };
    table.assertRoomFor(reading, .receive);
    table.operationSubmitted(receive);
    table.assertRoomFor(closing, .cancel);
    table.operationSubmitted(cancel);
    try testing.expect(table.get(reading).receiving);
    try testing.expect(!table.get(reading).canceled);
    try testing.expect(table.get(closing).cancel_in_flight and table.get(closing).canceled);
    // Each kind is counted only on its own peer, and only as its own kind.
    try testing.expectEqual(@as(u32, 1), table.operationCount(receive));
    try testing.expectEqual(@as(u32, 1), table.operationCount(cancel));
    try testing.expectEqual(@as(SendCount, 0), table.get(reading).sends_in_flight);
    try testing.expect(!table.get(closing).receiving);

    var entries_before: [4]Entry = undefined;
    @memcpy(&entries_before, table.entries);
    try testing.expectError(error.OperationsInFlight, table.release(reading));
    try testing.expectError(error.OperationsInFlight, table.release(closing));
    try testing.expectEqualSlices(Entry, &entries_before, table.entries);
    try testing.expectEqual(@as(u32, 2), table.count());

    // The completions uncount them; the cancelled entry stays cancelled until release.
    table.operationCompleted(receive);
    table.operationCompleted(cancel);
    try testing.expectEqual(@as(u32, 0), table.operationCount(receive));
    try testing.expectEqual(@as(u32, 0), table.operationCount(cancel));
    try testing.expect(table.get(closing).canceled);
    table.assertCanceled(closing);
    // A second cancel may follow once the first is back, and a second receive likewise.
    table.assertRoomFor(closing, .cancel);
    table.assertRoomFor(reading, .receive);
    table.assertRoomFor(reading, .send);

    try testing.expectEqual(@as(Socket, 10), try table.release(reading));
    try testing.expectEqual(@as(Socket, 11), try table.release(closing));
    // A reused entry starts with nothing in flight and no cancel.
    const reused = try table.acquire(12);
    try testing.expect(!table.get(reused).receiving);
    try testing.expect(!table.get(reused).cancel_in_flight and !table.get(reused).canceled);
    table.assertRoomFor(reused, .send);
    table.assertInvariants();

    _ = try table.release(reused);
    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "connections: the entry still fits its budget with the receive and cancel flags" {
    // The flags take bytes the generation's alignment already pads.
    try testing.expect(entry_bytes <= constants.http_connection_entry_size_max);
    // The same bytes as before the flags: they fill padding, so the memory table's row holds.
    try testing.expectEqual(@as(u32, 26), entry_bytes);
}
