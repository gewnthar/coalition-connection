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

/// Largest HTTP request head plus body. Reason: forms are small; anything larger is
/// rejected before parsing.
pub const http_request_size_max: u32 = 16 * 1024;

/// Header fields in one HTTP request. Reason: browsers send about 10 to 20 and Cloudflare
/// adds a handful; 64 leaves headroom while bounding the header table and every lookup.
pub const http_headers_max: u32 = 64;

/// Largest rendered HTTP response. Reason: the biggest planned page (a full audit view)
/// fits; bigger views paginate.
pub const http_response_size_max: u32 = 1024 * 1024;

/// Response buffers, each `http_response_size_max` bytes, shared by all connections.
/// Reason: a connection holds one only while it renders a page and writes it to nginx on
/// the local socket, and nginx buffers responses for slow clients, so a buffer is back in
/// the pool within milliseconds. That holds only while nginx's proxy buffering stays on
/// with room for a full response (roadmap 1.48). A connection that finds the pool empty
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
/// and fails the build when the total exceeds `memory_budget_bytes`. Small per-connection
/// state and lookup tables are not rows yet: the slice that adds one (roadmap 1.3, 1.33 and
/// 1.38 among them) adds its row here in the same change. The table counts startup heap
/// buffers only, not stacks or the program itself.
pub const memory_table = [_]MemoryRow{
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
    assert(esi_error_limit_floor > 0);
    assert(esi_retries_max > 0);
    assert(sim_fault_percent_max < 100);
    assert(tick_ns > 0);
    assert(http_response_buffers_max > 0);
    assert(http_response_buffers_max <= http_connections_max);
    // The backlog holds at least one event of the largest size.
    assert(live_events_backlog_bytes_max >= websocket_message_size_max);
    assert(memory_table.len <= memory_table_rows_max);
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
