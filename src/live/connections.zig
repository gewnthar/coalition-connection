//! Connection table (roadmap core 4): maps each `PeerId` to its socket and its state.
//!
//! Job:
//!   Hand out a `PeerId` for every accepted connection and take it back when the connection
//!   closes. A `PeerId` is an index into a table allocated once at startup, so looking up a
//!   connection is one bounds-checked array access and the table never grows.
//!
//! Inputs:
//!   An allocator during startup (a `StartupAllocator`), the table's size, and the socket of
//!   each accepted connection.
//!
//! Outputs:
//!   `PeerId`s, the entry each one names, and each socket back again on release, for the
//!   caller to close.
//!
//! Limits (src/constants.zig):
//!   http_connections_max: the largest table; callers may pass a smaller size to `init`.
//!   http_connection_entry_size_max: bytes of table state per connection, counted in the
//!   memory table.
//!
//! Free ids sit on a stack, so `acquire` and `release` take constant time and the id
//! released last is handed out first. A full table refuses the connection with
//! `error.TableFull` and leaves every entry as it was.
//!
//! Not yet: a released id can be handed out again at once, so an I/O completion that still
//! names the old connection would reach the new one. The slice that routes completions to
//! connections adds a generation count to each id.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const io = @import("../io/root.zig");

pub const PeerId = io.PeerId;

/// A Linux file descriptor, as the I/O boundary defines it.
pub const Socket = io.Socket;

pub const AcquireError = error{TableFull};

pub const InitError = error{OutOfMemory};

/// Where a connection is in its request and response.
pub const State = enum(u8) {
    /// Not in use: the entry's id is on the free stack.
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
};

/// Bytes of table state one connection costs: its entry plus its slot on the free stack.
pub const entry_bytes: u32 = @sizeOf(Entry) + @sizeOf(PeerId);

comptime {
    assert(entry_bytes <= constants.http_connection_entry_size_max);
    assert(constants.http_connections_max > 0);
}

pub const Table = struct {
    entries: []Entry,
    /// Free ids, a stack: `free_ids[0..free_count]` are the ids not in use.
    free_ids: []PeerId,
    free_count: u32,

    /// Allocates a table of `size` entries, all free. Call it during startup only.
    pub fn init(allocator: std.mem.Allocator, size: u32) InitError!Table {
        assert(size > 0);
        assert(size <= constants.http_connections_max);
        const entries = try allocator.alloc(Entry, size);
        errdefer allocator.free(entries);
        const free_ids = try allocator.alloc(PeerId, size);
        @memset(entries, .{ .socket = -1, .state = .free });
        // Push the ids in reverse, so the first acquire hands out id 0.
        var position: u32 = 0;
        while (position < size) : (position += 1) {
            assert(position < free_ids.len);
            free_ids[position] = size - 1 - position;
        }
        assert(position == size);
        const table: Table = .{ .entries = entries, .free_ids = free_ids, .free_count = size };
        table.assertInvariants();
        return table;
    }

    /// Frees the table's memory. Call it during shutdown only.
    pub fn deinit(self: *Table, allocator: std.mem.Allocator) void {
        self.assertInvariants();
        assert(self.entries.len == self.free_ids.len);
        allocator.free(self.free_ids);
        allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn capacity(self: *const Table) u32 {
        assert(self.entries.len == self.free_ids.len);
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

    /// Takes a free entry for `socket` and returns its id. The entry starts in `reading`.
    /// When every entry is in use, returns `error.TableFull` and changes nothing.
    pub fn acquire(self: *Table, socket: Socket) AcquireError!PeerId {
        assert(socket >= 0);
        const count_before = self.count();
        if (self.free_count == 0) {
            assert(count_before == self.capacity());
            return error.TableFull;
        }
        self.free_count -= 1;
        const id = self.free_ids[self.free_count];
        assert(id < self.capacity());
        const entry = &self.entries[id];
        assert(entry.state == .free); // A free id names a free entry.
        entry.* = .{ .socket = socket, .state = .reading };
        assert(self.count() == count_before + 1);
        return id;
    }

    /// Returns `id`'s entry to the free stack and hands back its socket, which the caller
    /// must close. Releasing an entry not in use is a bug.
    pub fn release(self: *Table, id: PeerId) Socket {
        assert(id < self.capacity());
        const count_before = self.count();
        assert(count_before > 0);
        const entry = &self.entries[id];
        assert(entry.state != .free); // Release of an entry not in use.
        const socket = entry.socket;
        assert(socket >= 0);
        entry.* = .{ .socket = -1, .state = .free };
        self.free_ids[self.free_count] = id;
        self.free_count += 1;
        assert(self.count() == count_before - 1);
        return socket;
    }

    /// The entry `id` names, which must be in use. Read-only: change its state through
    /// `setState`, and free it through `release`.
    pub fn get(self: *const Table, id: PeerId) *const Entry {
        assert(id < self.capacity());
        const entry = &self.entries[id];
        assert(entry.state != .free); // Lookup of an entry not in use.
        assert(entry.socket >= 0);
        return entry;
    }

    /// Moves `id`'s connection between reading and writing. Only `release` frees an entry,
    /// so the free stack and the entries always agree.
    pub fn setState(self: *Table, id: PeerId, state: State) void {
        assert(id < self.capacity());
        assert(state != .free); // Free an entry through release.
        const entry = &self.entries[id];
        assert(entry.state != .free); // State change of an entry not in use.
        entry.state = state;
    }

    /// Checks that the free stack and the entries agree: every stacked id is free and stacked
    /// once, and no other entry is free. It walks the whole table, so it runs at startup,
    /// at shutdown and in tests; each method keeps cheaper checks of its own.
    pub fn assertInvariants(self: *const Table) void {
        const table_capacity = self.capacity();
        assert(self.free_count <= table_capacity);
        var stacked: std.bit_set.Static(constants.http_connections_max) = .empty;
        for (self.free_ids[0..self.free_count]) |id| {
            assert(id < table_capacity);
            assert(self.entries[id].state == .free);
            assert(!stacked.isSet(id)); // An id on the free stack twice.
            stacked.set(id);
        }
        for (self.entries, 0..) |entry, index| {
            assert((entry.state == .free) == stacked.isSet(index));
        }
    }
};

const testing = std.testing;
const StartupAllocator = @import("../startup_allocator.zig").StartupAllocator;

const connection_row_name = "Connection table entry and free-id slot, one per connection";

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

test "connections: a refused acquire leaves every entry and free id as it was" {
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
    var free_ids_before: [4]PeerId = undefined;
    @memcpy(&entries_before, table.entries);
    @memcpy(&free_ids_before, table.free_ids);

    try testing.expectError(error.TableFull, table.acquire(14));
    try testing.expectEqualSlices(Entry, &entries_before, table.entries);
    try testing.expectEqualSlices(PeerId, &free_ids_before, table.free_ids);
    try testing.expectEqual(@as(u32, 0), table.free_count);

    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}

test "connections: release hands back the socket, then acquire reuses the entry" {
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

    try testing.expectEqual(@as(Socket, 10), table.release(first));
    try testing.expectEqual(@as(u32, 1), table.count());
    table.assertInvariants();

    const reused = try table.acquire(12);
    try testing.expectEqual(first, reused);
    try testing.expectEqual(State.reading, table.get(reused).state);
    try testing.expectEqual(@as(Socket, 12), table.get(reused).socket);
    try testing.expectEqual(@as(Socket, 11), table.get(second).socket);
    try testing.expectEqual(@as(u32, 2), table.count());
    table.assertInvariants();

    try testing.expectEqual(@as(Socket, 11), table.release(second));
    try testing.expectEqual(@as(Socket, 12), table.release(reused));
    try testing.expectEqual(@as(u32, 0), table.count());
    table.assertInvariants();

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

test "connections: seeded random accepts and closes against a model, filling the table" {
    // A small table, so random runs often hit full and empty. The model holds the socket
    // each id in use was given, or -1.
    const size: u32 = 64;
    const steps_max: u32 = 20_000;
    var startup = StartupAllocator.init(testing.allocator, size * entry_bytes);
    const gpa = startup.allocator();
    var table = try Table.init(gpa, size);
    startup.finishStartup();

    var prng: std.Random.DefaultPrng = .init(0x5eed);
    const random = prng.random();
    var model_sockets: [size]Socket = @splat(-1);
    var in_use: u32 = 0;
    var full_refusals: u32 = 0;
    var step: u32 = 0;
    while (step < steps_max) : (step += 1) {
        // Lean toward accepts, so the table fills and refuses.
        if (random.uintLessThan(u8, 8) < 5) {
            const socket: Socket = @intCast(100 + step);
            if (table.acquire(socket)) |id| {
                try testing.expectEqual(@as(Socket, -1), model_sockets[id]);
                model_sockets[id] = socket;
                in_use += 1;
            } else |err| switch (err) {
                error.TableFull => {
                    try testing.expectEqual(size, in_use);
                    full_refusals += 1;
                },
            }
        } else if (in_use > 0) {
            var id = random.uintLessThan(PeerId, size);
            var probes: u32 = 0;
            while (model_sockets[id] == -1) : (probes += 1) {
                assert(probes < size);
                id = (id + 1) % size;
            }
            try testing.expectEqual(model_sockets[id], table.release(id));
            model_sockets[id] = -1;
            in_use -= 1;
        }
        try testing.expectEqual(in_use, table.count());
    }
    table.assertInvariants();
    try testing.expect(full_refusals > 0);

    startup.beginShutdown();
    table.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}
