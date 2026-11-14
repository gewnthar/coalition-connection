//! Every limit in Coalition Connection lives here, each with the reason for its value.
//!
//! Memory is sized once at startup from these numbers and never grows afterwards, so
//! raising a limit raises startup memory instead of risking a run-time allocation. The
//! memory table in the Memory section adds up every buffer sized from these limits, and the
//! build fails if the total exceeds `memory_budget_bytes`. Values marked "provisional" are first
//! estimates; docs/roadmap.md lists the slice that confirms each one.

const std = @import("std");
const assert = std.debug.assert;

// ---- Scale -------------------------------------------------------------------------

/// Users (people) one install serves. Reason: a large coalition is about 25,000 pilots;
/// the next power of two leaves headroom. Provisional.
pub const users_max: u32 = 32_768;

/// Characters one user may register, the main plus alts. Reason: covers heavy multi-boxers
/// while bounding every per-user loop. Provisional.
pub const characters_per_user_max: u32 = 64;

/// Characters across the whole install. Reason: eight per user on average, far below the
/// per-user maximum, because most pilots register a handful. Provisional.
pub const characters_max: u32 = 262_144;

// ---- States, groups and permissions ------------------------------------------------

/// Access states (member, blue, guest and so on). Reason: Alliance Auth installs use a
/// handful; 32 keeps state evaluation a short bounded scan.
pub const states_max: u32 = 32;

/// Groups across the install. Reason: coalitions run hundreds of interest and role
/// groups; 2,048 leaves room without unbounded tables. Provisional.
pub const groups_max: u32 = 2_048;

/// Groups one user may belong to. Reason: bounds the per-user permission scan.
pub const groups_per_user_max: u32 = 256;

/// Distinct permissions. Reason: one per admin action and data view, with headroom.
pub const permissions_max: u32 = 512;

// ---- ESI client ----------------------------------------------------------------------

/// ESI requests in flight at once. Reason: bounds sockets and response buffers, and
/// keeps the client polite toward a shared public API.
pub const esi_requests_in_flight_max: u32 = 32;

/// Largest single ESI response body. Reason: the biggest paged routes (assets, wallet
/// journals) return up to 1,000 rows per page; 4 MiB holds one page with headroom.
pub const esi_response_size_max: u32 = 4 * 1024 * 1024;

/// Distinct ESI rate-limit groups tracked. Reason: ESI meters routes in named groups,
/// each with its own token bucket; this bounds the bucket table.
pub const esi_rate_limit_groups_max: u32 = 128;

/// Stop sending when ESI's remaining error allowance falls to this. Reason: hitting the
/// error limit blocks the whole application for the rest of the window.
pub const esi_error_limit_floor: u32 = 10;

/// Retries for one ESI request. Reason: a bounded retry loop; persistent failures go back
/// to the scheduler instead of spinning.
pub const esi_retries_max: u32 = 3;

// ---- HTTP and live updates -----------------------------------------------------------

/// Client connections (pages and websockets). Reason: nginx sits in front; this bounds
/// the connection table sized at startup. Provisional.
pub const http_connections_max: u32 = 4_096;

/// Bytes of connection-table state per connection: its entry (socket, state, generation,
/// request head scan and count of sends in flight) plus its slot on the free-index stack.
/// Reason: the table is sized once at startup and counted in the memory table;
/// `src/live/connections.zig` checks at compile time that its entry fits. The entry and its
/// slot take 18 of the 20 bytes on every target: 13 bytes of fields, padded to 16 by the
/// socket's 4-byte alignment, plus a 2-byte slot. Three more bytes of fields still fit in
/// the padding; anything past that means raising this number in review.
pub const http_connection_entry_size_max: u32 = 20;

/// Largest HTTP request head plus body. Reason: forms are small; anything larger is
/// rejected before parsing.
pub const http_request_size_max: u32 = 16 * 1024;

/// Header fields in one HTTP request. Reason: browsers send about 10 to 20 and Cloudflare
/// adds a handful; 64 leaves headroom while bounding the header table and every lookup.
pub const http_headers_max: u32 = 64;

/// Largest rendered HTTP response. Reason: the biggest planned page (a full audit view)
/// fits; bigger views paginate.
pub const http_response_size_max: u32 = 1024 * 1024;

/// Header fields a handler adds to one HTTP response, besides the Content-Length and
/// Connection fields the response writer adds itself. Reason: a page sets a few (type,
/// caching, cookies, security headers); 32 bounds the writer's loop with room to spare.
pub const http_response_headers_max: u32 = 32;

/// Response buffers, each `http_response_size_max` bytes, shared by all connections.
/// Reason: a connection holds one only while it renders a page and writes it to nginx on
/// the local socket, and nginx buffers responses for slow clients, so a buffer is back in
/// the pool within milliseconds. That holds only while nginx's proxy buffering stays on
/// with room for a full response (roadmap core 48). A connection that finds the pool empty
/// waits for a buffer. One buffer per connection would take 4 GiB. Provisional.
pub const http_response_buffers_max: u32 = 64;

/// Open websockets. Reason: one per watching page; never more than the connections.
pub const websocket_connections_max: u32 = http_connections_max;

/// Largest websocket message. Reason: a live update carries one changed page fragment.
pub const websocket_message_size_max: u32 = 64 * 1024;

/// Live events kept for catch-up. Reason: a reconnecting page replays from the last event
/// it saw; a page further behind than this, or than `live_events_backlog_bytes_max`, reloads
/// instead.
pub const live_events_backlog_max: u32 = 65_536;

/// Bytes of event fragments kept for catch-up, across the whole backlog. Reason: a live
/// update is usually a few KiB, far below `websocket_message_size_max`, so this still holds
/// thousands of events. The oldest event is dropped when either this or
/// `live_events_backlog_max` is reached. A backlog of full-size events would take 4 GiB.
/// Provisional.
pub const live_events_backlog_bytes_max: u32 = 64 * 1024 * 1024;

// ---- Storage -------------------------------------------------------------------------

/// Postgres connections. Reason: the database gives out before the app; a small pool
/// keeps load predictable.
pub const postgres_connections_max: u32 = 16;

/// Largest Postgres protocol message. Reason: bounds the receive buffer per connection.
pub const postgres_message_size_max: u32 = 1024 * 1024;

/// Valkey connections, including one for pub/sub. Reason: Valkey is single-threaded, so
/// more connections add no throughput.
pub const valkey_connections_max: u32 = 8;

/// Largest Valkey reply. Reason: sessions and live events are small.
pub const valkey_message_size_max: u32 = 512 * 1024;

/// Largest audit-log entry. Reason: an entry records who, what, when and a short reason.
pub const audit_entry_size_max: u32 = 4 * 1024;

// ---- Config file ---------------------------------------------------------------------

/// Largest config file. Reason: the file holds a handful of settings, so 4 KiB is far more
/// than a real one needs and bounds the read buffer.
pub const config_file_size_max: u32 = 4 * 1024;

/// Working memory for parsing the config file, one fixed region used once at startup and
/// freed before the server runs. Reason: the heaviest file src/config.zig's prescan lets
/// through (the most fields with the longest names) needs under 20 KiB, measured on 0.17.1;
/// 64 KiB leaves three times that, and a test parses each heavy shape against it.
pub const config_parse_scratch_size_max: u32 = 64 * 1024;

/// Bytes the config loader holds while it runs: the file buffer (the largest file, one
/// byte more so an oversized file is seen, and the parser's sentinel) and the parse
/// scratch. Reason: counted in the memory table; src/config.zig checks it matches.
pub const config_load_bytes_max: u64 = config_file_size_max + 2 + config_parse_scratch_size_max;

/// Longest local socket path, in bytes. Reason: Linux's `sun_path` holds 108 bytes,
/// including the NUL that ends the path.
pub const config_socket_path_max: u32 = 107;

/// Longest path of the config file itself, in bytes, as the server's one command-line
/// argument. Reason: Linux's `PATH_MAX` is 4096 bytes including the NUL that ends a path, so
/// no longer path can be opened, and the bound caps the scan for the argument's end.
pub const config_file_path_max: u32 = 4095;

/// Fields in the config file. Reason: the file holds two today; 16 leaves room for later
/// settings and bounds what the ZON parser is given.
pub const config_fields_max: u32 = 16;

/// read calls for the config file. Reason: a regular file of at most
/// `config_file_size_max` bytes reads whole in one or two calls; the bound leaves room for
/// signals and stops a file that keeps growing.
pub const config_read_attempts_max: u32 = 8;

// ---- Importer and services -----------------------------------------------------------

/// Largest single record in an Alliance Auth export. Reason: the importer streams the
/// export one record at a time through a fixed buffer.
pub const import_record_size_max: u32 = 1024 * 1024;

/// Changes sent to Mumble or XMPP in one batch. Reason: batching over per-item work, with
/// a bound on each batch.
pub const service_sync_batch_max: u32 = 256;

// ---- Taxes, audits and SRP -----------------------------------------------------------

/// Ore types with their own tax rate. Reason: EVE has a few hundred ore and moon ore
/// variants. Provisional.
pub const ore_types_max: u32 = 512;

/// SRP programs (alliance and corporation). Reason: one per alliance and corporation
/// that runs SRP, with headroom.
pub const srp_programs_max: u32 = 64;

/// Doctrines. Reason: coalitions keep tens of active doctrines.
pub const doctrines_max: u32 = 256;

/// Skill requirements in one doctrine skill set. Reason: a fit needs at most a few
/// hundred skills.
pub const doctrine_skills_max: u32 = 512;

// ---- I/O boundary --------------------------------------------------------------------

/// Operations submitted to the I/O boundary and not yet completed. Reason: bounds the
/// in-flight table, as an io_uring queue depth does, so a submission past it fails with
/// `error.QueueFull` instead of growing anything. It is also the real ring's submission
/// queue depth, so it must be a power of two of at most 32,768. Provisional: roadmap core 3
/// sizes it against the connection table, since each connection may keep a read in flight.
pub const io_operations_in_flight_max: u32 = 256;

/// Bytes the real I/O type's io_uring ring and in-flight table may take: the ring mapping
/// (header, completion entries, submission index) and the submission entries, each in whole
/// pages, plus the type itself with its slots. Reason: about 34 KiB at 256 operations with
/// 4 KiB pages; 256 KiB still holds the worst case with 64 KiB pages. `io.real` checks its
/// worst-case estimate against this at compile time, and the kernel's mapping at startup.
pub const io_ring_size_max: u64 = 256 * 1024;

/// Random bytes one call to the I/O boundary may draw. Reason: the largest draw is a 32-byte
/// key; token nonces are 24 bytes.
pub const io_random_bytes_max: u32 = 64;

/// getrandom calls one draw of random bytes may make. Reason: a draw of at most
/// `io_random_bytes_max` bytes is normally whole in one call; a signal or a short read costs
/// a retry, and the bound stops a signal storm from spinning the event loop.
pub const io_random_attempts_max: u32 = 8;

/// Connections the kernel queues on the local listener before the server accepts them.
/// Reason: nginx is the only client and opens a few connections per worker, so a queue of
/// 512 rides out a burst between two accepts; Linux caps it at `net.core.somaxconn`
/// (4,096 by default), so asking for more than that buys nothing. Provisional: the server
/// loop (roadmap core 3) confirms it under load.
pub const listener_backlog: u32 = 512;

/// bind calls opening the local listener may take. Reason: the first bind finds the path
/// free, or finds a socket a server that stopped left behind; the second runs after that
/// stale socket is removed. A path still taken after that is a process binding it without
/// the path's lock, and startup refuses rather than retrying.
pub const listener_bind_attempts_max: u32 = 2;

/// Permission bits of the local listener's socket file. Reason: connecting to a Unix socket
/// needs write permission on the file, so the server's user and its group may connect and
/// nobody else; nginx connects through the group the pod's units give it. Set explicitly,
/// not left to the umask. Provisional: the nginx unit (roadmap core 48) confirms it.
pub const listener_socket_mode: u32 = 0o660;

// ---- Open files ----------------------------------------------------------------------

/// Accepts the server keeps in flight at once. Reason: each accept's completion already
/// holds a new socket the kernel opened, before the table is asked for an entry, so every
/// accept in flight needs a descriptor of its own; one at a time is enough for nginx, the
/// only client. Provisional: the server loop keeps to it.
pub const accepts_in_flight_max: u32 = 1;

/// File descriptors the server holds open besides its connections' sockets, at most, at
/// any one moment:
///   3  standard input, output and error (startup closes every other inherited one);
///   1  the config file, open only while it is read;
///   1  the io_uring ring;
///   1  the local listener's socket;
///   1  the listener's lock file, held until the listener closes;
///   `accepts_in_flight_max`  the new socket each accept in flight completes with, which a
///      full connection table closes at once.
/// A released connection's socket is closed before the next accept is submitted, so it
/// needs no line of its own. Reason: the server refuses to start unless the open-file
/// limit covers every connection the config allows plus these, so an accept never fails
/// for want of a descriptor while the table has room. A component that holds descriptors
/// of its own (Postgres, Valkey, ESI) adds its line here in the change that opens them.
pub const descriptors_besides_connections: u32 = 3 + 1 + 1 + 1 + 1 + accepts_in_flight_max;

/// The open-file limit the largest config needs: one descriptor for each of
/// `http_connections_max` connections, plus `descriptors_besides_connections`. Startup
/// works out the need from the config's own connection limit, which is at most this.
pub const descriptors_needed_max: u64 = @as(u64, http_connections_max) + descriptors_besides_connections;

// ---- Memory --------------------------------------------------------------------------

/// Total memory the process may take at startup. Reason: fits a small virtual server
/// with room for Postgres and Valkey beside it. Provisional.
pub const memory_budget_bytes: u64 = 1024 * 1024 * 1024;

/// One kind of buffer allocated at startup: `count` buffers of `size` bytes each.
pub const MemoryRow = struct {
    name: []const u8,
    count: u64,
    size: u64,
};

/// Rows the memory table may hold. Reason: bounds the loop that adds it up; one row per
/// kind of startup buffer leaves plenty of room.
pub const memory_table_rows_max: u32 = 64;

/// Every buffer sized from the limits above. The comptime block after the limits adds it up
/// and fails the build when the total exceeds `memory_budget_bytes`. Startup buffers not yet
/// built are not rows yet: the slice that adds one (the response-buffer wait queue in roadmap
/// core 3; lookup tables in core 33 and core 38) adds its row here in the same change. The
/// table counts memory sized at startup (heap buffers, and the io_uring ring the kernel maps
/// for the real I/O type, with its in-flight slots), not stacks or the program itself.
pub const memory_table = [_]MemoryRow{
    .{
        .name = "Connection table entry and free-index slot, one per connection",
        .count = http_connections_max,
        .size = http_connection_entry_size_max,
    },
    .{
        .name = "HTTP request buffer, one per connection",
        .count = http_connections_max,
        .size = http_request_size_max,
    },
    .{
        .name = "HTTP response buffer pool",
        .count = http_response_buffers_max,
        .size = http_response_size_max,
    },
    .{
        .name = "Websocket send buffer, one per websocket",
        .count = websocket_connections_max,
        .size = websocket_message_size_max,
    },
    .{
        .name = "Live event backlog",
        .count = 1,
        .size = live_events_backlog_bytes_max,
    },
    .{
        .name = "ESI response buffer, one per request in flight",
        .count = esi_requests_in_flight_max,
        .size = esi_response_size_max,
    },
    .{
        .name = "Postgres receive buffer, one per connection",
        .count = postgres_connections_max,
        .size = postgres_message_size_max,
    },
    .{
        .name = "Valkey reply buffer, one per connection",
        .count = valkey_connections_max,
        .size = valkey_message_size_max,
    },
    .{
        .name = "io_uring ring and in-flight table of the real I/O type",
        .count = 1,
        .size = io_ring_size_max,
    },
    .{
        .name = "Config file buffer and parse scratch, freed before the server runs",
        .count = 1,
        .size = config_load_bytes_max,
    },
    .{
        .name = "Importer record buffer",
        .count = 1,
        .size = import_record_size_max,
    },
};

/// Adds up count times size over `table`. Returns `error.Overflow` instead of wrapping, so a
/// table too large to add up fails the build instead of passing it.
pub fn memoryTableBytes(table: []const MemoryRow) error{Overflow}!u64 {
    assert(table.len > 0);
    assert(table.len <= memory_table_rows_max);
    var total: u64 = 0;
    for (table) |row| {
        assert(row.count > 0);
        assert(row.size > 0);
        const row_bytes = @mulWithOverflow(row.count, row.size);
        if (row_bytes[1] != 0) return error.Overflow;
        const sum = @addWithOverflow(total, row_bytes[0]);
        if (sum[1] != 0) return error.Overflow;
        total = sum[0];
        assert(total >= row_bytes[0]);
    }
    // Every row adds at least one byte.
    assert(total >= table.len);
    return total;
}

/// Whether the buffers in `table` fit in `budget` bytes. A table too large to add up does
/// not fit.
pub fn memoryTableFits(table: []const MemoryRow, budget: u64) bool {
    assert(table.len > 0);
    assert(budget > 0);
    const total = memoryTableBytes(table) catch |err| switch (err) {
        error.Overflow => return false,
    };
    assert(total > 0);
    return total <= budget;
}

// ---- Simulation and fuzzing ----------------------------------------------------------

/// Simulated time per tick, in nanoseconds. Reason: 10 ms is finer than any timeout.
pub const tick_ns: u64 = 10 * 1_000_000;

/// Ticks in one simulation run. Reason: about 16 simulated minutes per seed keeps a CI
/// run short; longer soaks run many seeds.
pub const sim_ticks_max: u32 = 100_000;

/// Highest fault rate the simulator injects, in percent. Reason: above this, runs test
/// only the failure path.
pub const sim_fault_percent_max: u8 = 50;

/// Longest delay, in ticks, before the simulator completes an operation. Reason: 16 ticks is
/// 160 ms, a slow peer or a slow query; delays drawn up to this reorder completions, and
/// longer stalls are modeled as faults.
pub const sim_completion_delay_ticks_max: u32 = 16;

/// Iterations in one fuzz run. Reason: bounded so a CI run finishes in seconds.
pub const fuzz_iterations_max: u32 = 100_000;

comptime {
    assert(characters_max >= users_max);
    assert(characters_per_user_max <= characters_max);
    assert(groups_per_user_max <= groups_max);
    assert(websocket_connections_max <= http_connections_max);
    // The smallest header line is "a:" plus CRLF, 4 bytes, so a full header table must fit.
    assert(http_headers_max * 4 < http_request_size_max);
    assert(websocket_message_size_max <= http_response_size_max);
    assert(http_response_headers_max > 0);
    assert(esi_error_limit_floor > 0);
    assert(esi_retries_max > 0);
    assert(sim_fault_percent_max < 100);
    assert(tick_ns > 0);
    assert(http_response_buffers_max > 0);
    assert(http_response_buffers_max <= http_connections_max);
    assert(http_connection_entry_size_max > 0);
    // The backlog holds at least one event of the largest size.
    assert(live_events_backlog_bytes_max >= websocket_message_size_max);
    assert(memory_table.len <= memory_table_rows_max);
    assert(io_operations_in_flight_max > 0);
    assert(std.math.isPowerOfTwo(io_operations_in_flight_max));
    assert(io_operations_in_flight_max <= 32_768);
    assert(io_random_bytes_max >= 32);
    assert(io_random_attempts_max >= 2);
    assert(accepts_in_flight_max > 0 and accepts_in_flight_max <= io_operations_in_flight_max);
    // fs.nr_open defaults to 1,048,576, and no hard open-file limit can pass it unless an
    // administrator raises that sysctl, so the largest config must fit below it.
    assert(descriptors_needed_max <= 1024 * 1024);
    // A simulated run must leave room to drain every delayed completion.
    assert(sim_completion_delay_ticks_max < sim_ticks_max);
}

// The memory budget: the buffers in the memory table, added up, must fit.
comptime {
    if (!memoryTableFits(&memory_table, memory_budget_bytes)) {
        @compileError("memory_table: startup buffers exceed memory_budget_bytes");
    }
}

test "constants: limits are positive and consistent" {
    try std.testing.expect(users_max > 0);
    try std.testing.expect(characters_max >= users_max);
    try std.testing.expect(states_max > 0);
    try std.testing.expect(esi_requests_in_flight_max <= http_connections_max);
    try std.testing.expect(memory_budget_bytes >= esi_response_size_max);
}

test "constants: the memory table fits the budget" {
    const total = try memoryTableBytes(&memory_table);
    try std.testing.expect(total > 0);
    try std.testing.expect(total <= memory_budget_bytes);
    try std.testing.expect(memoryTableFits(&memory_table, memory_budget_bytes));
}

test "constants: memoryTableBytes adds count times size" {
    const table = [_]MemoryRow{
        .{ .name = "three of five", .count = 3, .size = 5 },
        .{ .name = "one of seven", .count = 1, .size = 7 },
    };
    try std.testing.expectEqual(@as(u64, 22), try memoryTableBytes(&table));
    try std.testing.expectEqual(@as(u64, 15), try memoryTableBytes(table[0..1]));
    const largest = [_]MemoryRow{
        .{ .name = "exactly the largest u64", .count = 1, .size = std.math.maxInt(u64) },
    };
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), try memoryTableBytes(&largest));
}

test "constants: memoryTableBytes reports overflow instead of wrapping" {
    const product = [_]MemoryRow{
        .{ .name = "count times size overflows", .count = std.math.maxInt(u64), .size = 2 },
    };
    try std.testing.expectError(error.Overflow, memoryTableBytes(&product));
    const sum = [_]MemoryRow{
        .{ .name = "largest row", .count = 1, .size = std.math.maxInt(u64) },
        .{ .name = "one more byte", .count = 1, .size = 1 },
    };
    try std.testing.expectError(error.Overflow, memoryTableBytes(&sum));
}

test "constants: memoryTableFits refuses one byte over the budget" {
    const table = [_]MemoryRow{
        .{ .name = "four of eight", .count = 4, .size = 8 },
        .{ .name = "one of three", .count = 1, .size = 3 },
    };
    try std.testing.expect(memoryTableFits(&table, 35));
    try std.testing.expect(memoryTableFits(&table, 36));
    try std.testing.expect(!memoryTableFits(&table, 34));
    const overflow = [_]MemoryRow{
        .{ .name = "count times size overflows", .count = std.math.maxInt(u64), .size = 2 },
    };
    try std.testing.expect(!memoryTableFits(&overflow, std.math.maxInt(u64)));
}

/// Test helper: the real memory table with `extra` appended, the shape a slice that adds a
/// startup buffer gives it.
fn memoryTableWith(
    comptime extra_len: u32,
    extra: [extra_len]MemoryRow,
) [memory_table.len + extra_len]MemoryRow {
    if (memory_table.len + extra_len > memory_table_rows_max) {
        @compileError("memoryTableWith: the table plus the extra rows exceeds memory_table_rows_max");
    }
    comptime assert(extra_len > 0);
    for (extra) |row| {
        assert(row.count > 0);
        assert(row.size > 0);
    }
    var table: [memory_table.len + extra_len]MemoryRow = undefined;
    @memcpy(table[0..memory_table.len], &memory_table);
    @memcpy(table[memory_table.len..], &extra);
    return table;
}

/// Test helper: the bytes left in `memory_budget_bytes` after the real memory table.
fn memoryTableRoomLeft() error{Overflow}!u64 {
    // The margin tests add up to a few KiB past the budget; this keeps those sums far from
    // the top of u64.
    comptime assert(memory_budget_bytes < std.math.maxInt(u64) / 2);
    const total = try memoryTableBytes(&memory_table);
    // Every row takes at least a byte, and the build refuses a table over the budget, so the
    // subtraction can't underflow and the room is below the whole budget.
    assert(total >= memory_table.len);
    assert(total <= memory_budget_bytes);
    const room = memory_budget_bytes - total;
    assert(room < memory_budget_bytes);
    return room;
}

test "constants: the real memory table plus a row of exactly the room left fits" {
    const room = try memoryTableRoomLeft();
    if (room == 0) {
        // No row fits when the table already fills the budget; the bare table is the margin.
        try std.testing.expect(memoryTableFits(&memory_table, memory_budget_bytes));
        return;
    }
    const table = memoryTableWith(1, .{
        .{ .name = "exactly the room left", .count = 1, .size = room },
    });
    try std.testing.expectEqual(memory_budget_bytes, try memoryTableBytes(&table));
    try std.testing.expect(memoryTableFits(&table, memory_budget_bytes));
}

test "constants: the real memory table plus a row one byte over the room left does not fit" {
    const room = try memoryTableRoomLeft();
    const table = memoryTableWith(1, .{
        .{ .name = "one byte more than the room left", .count = 1, .size = room + 1 },
    });
    try std.testing.expectEqual(memory_budget_bytes + 1, try memoryTableBytes(&table));
    try std.testing.expect(!memoryTableFits(&table, memory_budget_bytes));
}

test "constants: the real memory table at its margin with a row of one buffer per connection" {
    // A new row is usually count times size, so the margin is also checked through the
    // multiply, with a per-connection row: the largest buffers that fit, then one byte more in
    // each. The room left is 0.4 GiB today; the count drops to the room only when the room is
    // smaller than one byte per connection.
    const room = try memoryTableRoomLeft();
    if (room == 0) return;
    const count: u64 = @min(@as(u64, http_connections_max), room);
    const size = room / count;
    const remainder = room - count * size;
    try std.testing.expect(remainder < count);
    const largest = memoryTableWith(1, .{
        .{ .name = "the largest buffer per connection that fits", .count = count, .size = size },
    });
    try std.testing.expectEqual(memory_budget_bytes - remainder, try memoryTableBytes(&largest));
    try std.testing.expect(memoryTableFits(&largest, memory_budget_bytes));
    // One byte more in each buffer adds `count` bytes, more than the remainder, so it is over.
    const over = memoryTableWith(1, .{
        .{ .name = "one byte more per connection", .count = count, .size = size + 1 },
    });
    try std.testing.expectEqual(
        memory_budget_bytes - remainder + count,
        try memoryTableBytes(&over),
    );
    try std.testing.expect(!memoryTableFits(&over, memory_budget_bytes));
}

test "constants: the real memory table counts every planned buffer" {
    // Written out by hand from the limits, so a dropped or added row, or a row whose count or
    // size names a limit of a different value, fails here. Limits that share a value (several
    // are 1 MiB) can't be told apart by the total. A slice that adds a startup buffer adds its
    // row to the table and its term to this sum in the same change.
    const connections: u64 = http_connections_max;
    const expected: u64 = connections * http_connection_entry_size_max +
        connections * http_request_size_max +
        @as(u64, http_response_buffers_max) * http_response_size_max +
        @as(u64, websocket_connections_max) * websocket_message_size_max +
        live_events_backlog_bytes_max +
        @as(u64, esi_requests_in_flight_max) * esi_response_size_max +
        @as(u64, postgres_connections_max) * postgres_message_size_max +
        @as(u64, valkey_connections_max) * valkey_message_size_max +
        io_ring_size_max +
        config_load_bytes_max +
        import_record_size_max;
    const rows: u32 = memory_table.len;
    try std.testing.expectEqual(@as(u32, 11), rows);
    try std.testing.expectEqual(expected, try memoryTableBytes(&memory_table));
}
