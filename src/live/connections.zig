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
//! A `PeerId` names an entry and a generation of it: the low 16 bits are the entry's index
//! and the high 16 bits the entry's generation, which `release` advances, wrapping. An id
//! handed out before a release is stale afterwards, so an I/O completion that still names
//! the old connection can't reach the next connection on that entry: completions find
//! their entry through `lookup`, which returns null for a stale id. `get`, `headScan`,
//! `setState` and `release` are for callers holding a live id, and assert it is live.
//!
//! The limit: after 65,536 releases of one entry its generation is back where it started,
//! so an id stays distinct from every later one for 65,535 reuses of its entry. The free
//! stack hands the same entry out again first, so work in flight on a connection must not
//! outlast that many reuses of its entry.
//!
//! Sends in flight: the I/O type captures a send's socket number when the send is
//! submitted, and the kernel may take the send later. If the entry were released and its
//! socket closed in between, Linux would hand the same number to the next accepted
//! connection, and the queued send would reach the wrong client. So each entry counts its
//! sends in flight: `sendSubmitted` raises the count, `sendCompleted` lowers it, and
//! `release` refuses with `error.SendsInFlight`, changing nothing, while it is above zero.
//! A refusal is a state the caller meets in normal running (a second send still queued
//! when the first fails with `PeerDown`), so it is an error to handle, not a bug: the
//! caller stops sending on that connection and releases it after its last completion.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const io = @import("../io/root.zig");
const http_request = @import("http_request.zig");

pub const PeerId = io.PeerId;

/// The position of an entry in the table: the low half of a `PeerId`.
pub const Index = u16;

/// How many times an entry has been released, wrapping: the high half of a `PeerId`.
pub const Generation = u16;

/// A `PeerId` split into its halves. A packed struct lays its fields out from the least
/// significant bit, so `@bitCast` between the two puts `index` in the low 16 bits and does
/// no arithmetic that could overflow.
pub const IdParts = packed struct(PeerId) {
    index: Index,
    generation: Generation,
};

/// A Linux file descriptor, as the I/O boundary defines it.
pub const Socket = io.Socket;

/// How far the search for the end of the current request head has got.
pub const HeadScan = http_request.HeadScan;

pub const AcquireError = error{TableFull};

/// `SendsInFlight`: the connection still has sends the kernel may act on, so its socket
/// must stay open; release it after the last one completes.
pub const ReleaseError = error{SendsInFlight};

/// Sends in flight on one connection. Never more than the I/O type has slots for.
pub const SendCount = u16;

pub const InitError = error{OutOfMemory};

/// Where a connection is in its request and response.
pub const State = enum(u8) {
    /// Not in use: the entry's index is on the free stack.
    free,
    /// Reading a request head or body.
    reading,
    /// Writing a response.
    writing,
};

pub const Entry = struct {
    /// Meaningful only while `state` is not `free`.
    socket: Socket,
    state: State,
    /// Empty whenever `state` is `free`; the request parser advances it while reading.
    scan: HeadScan = .{},
    /// The generation every live id for this entry carries. Kept while the entry is free:
    /// `release` advances it, and the next `acquire` hands it out.
    generation: Generation = 0,
    /// Sends submitted on this connection whose completions haven't come back. Zero
    /// whenever `state` is `free`: `release` refuses while it is above zero.
    sends_in_flight: SendCount = 0,
};

/// Bytes of table state one connection costs: its entry plus its slot on the free stack.
pub const entry_bytes: u32 = @sizeOf(Entry) + @sizeOf(Index);

comptime {
    assert(entry_bytes <= constants.http_connection_entry_size_max);
    assert(constants.http_connections_max > 0);
    // Every entry's index fits the low half of a PeerId.
    assert(constants.http_connections_max - 1 <= std.math.maxInt(Index));
    // The layout the docs promise: index in the low half, generation in the high half.
    assert(@as(PeerId, @bitCast(IdParts{ .index = 1, .generation = 2 })) == 0x0002_0001);
    // Every operation in flight could be a send on one connection; its count still fits.
    assert(constants.io_operations_in_flight_max <= std.math.maxInt(SendCount));
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
    /// current generation. The entry starts in `reading`, with an empty head scan. When
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
        assert(entry.sends_in_flight == 0); // release refuses an entry with sends in flight.
        entry.socket = socket;
        entry.state = .reading;
        const id: PeerId = @bitCast(IdParts{ .index = index, .generation = entry.generation });
        assert(self.count() == count_before + 1);
        return id;
    }

    /// Returns `id`'s entry to the free stack, emptying its head scan and advancing its
    /// generation, so `id` is stale from now on. Hands back the socket, which the caller
    /// must close. While the connection has sends in flight, returns
    /// `error.SendsInFlight` and changes nothing. Releasing an entry not in use, or through
    /// a stale id, is a bug.
    pub fn release(self: *Table, id: PeerId) ReleaseError!Socket {
        const count_before = self.count();
        assert(count_before > 0);
        const index = self.liveIndex(id);
        const entry = &self.entries[index];
        const socket = entry.socket;
        assert(socket >= 0);
        if (entry.sends_in_flight > 0) return error.SendsInFlight;
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

    /// The head scan of `id`'s connection, which must be live and reading, for the request
    /// parser to advance. `acquire` and `release` empty it; nothing else in the table
    /// touches it.
    pub fn headScan(self: *Table, id: PeerId) *HeadScan {
        const entry = &self.entries[self.liveIndex(id)];
        assert(entry.state == .reading); // Only a connection reading a head is parsed.
        // The parser backs off three bytes from the end of a buffer of at most
        // http_request_size_max bytes, so it never resumes past that.
        assert(entry.scan.resume_at <= constants.http_request_size_max - 3);
        return &entry.scan;
    }

    /// Moves `id`'s connection between reading and writing. Only `release` frees an entry,
    /// so the free stack and the entries always agree.
    pub fn setState(self: *Table, id: PeerId, state: State) void {
        assert(state != .free); // Free an entry through release.
        const entry = &self.entries[self.liveIndex(id)];
        // A parsed head empties the scan, so a connection never writes with a scan part way.
        assert(state != .writing or entry.scan.resume_at == 0);
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
            assert(self.entries[index].sends_in_flight == 0); // release refuses those.
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
    try testing.expectEqual(State.reading, table.get(reused).state);
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
    try testing.expectError(error.SendsInFlight, table.release(busy));
    try testing.expectEqualSlices(Entry, &entries_before, table.entries);
    try testing.expectEqualSlices(Index, &free_indices_before, table.free_indices);
    try testing.expectEqual(@as(u32, 2), table.count());
    try testing.expectEqual(table.get(busy), table.lookup(busy).?);
    table.sendCompleted(busy);
    try testing.expectError(error.SendsInFlight, table.release(busy));
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
    try testing.expectError(error.SendsInFlight, table.release(id));
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
        const generation: Generation = @truncate(model.releases[parts.index]);
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
            try testing.expectError(error.SendsInFlight, table.release(id));
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

test "connections: a generation wraps to zero, and only the newest id is live" {
    // One entry, released and acquired again until its generation wraps past its largest
    // value back to zero. At every step only the newest id is live.
    var startup = StartupAllocator.init(testing.allocator, entry_bytes);
    const gpa = startup.allocator();
    var table = try Table.init(gpa, 1);
    startup.finishStartup();

    const first = try table.acquire(10);
    try testing.expectEqual(@as(Generation, 0), @as(IdParts, @bitCast(first)).generation);
    const cycles: u32 = std.math.maxInt(Generation) + 1;
    var id = first;
    var cycle: u32 = 0;
    while (cycle < cycles) : (cycle += 1) {
        const socket: Socket = @intCast(11 + cycle % 1000);
        try testing.expectEqual(table.get(id).socket, try table.release(id));
        const next = try table.acquire(socket);
        try testing.expectEqual(@as(?*const Entry, null), table.lookup(id));
        try testing.expectEqual(socket, table.lookup(next).?.socket);
        id = next;
    }
    try testing.expectEqual(cycles, cycle);
    // After 65,536 releases the generation is back at zero: the first id names the live
    // connection again. A completion would have to wait out that many reuses of its entry
    // to be misrouted.
    try testing.expectEqual(first, id);
    const generation_max = std.math.maxInt(Generation);
    const last_stale: PeerId = @bitCast(IdParts{ .index = 0, .generation = generation_max });
    try testing.expectEqual(@as(?*const Entry, null), table.lookup(last_stale));

    _ = try table.release(id);
    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}
