//! Every limit in Coalition Connection lives here, each with the reason for its value.
//!
//! Memory is sized once at startup from these numbers and never grows afterwards, so
//! raising a limit raises the startup memory budget instead of risking a run-time
//! allocation. Values marked "provisional" are first estimates; docs/roadmap.md lists
//! the slice that confirms each one.

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

/// Largest rendered HTTP response. Reason: the biggest planned page (a full audit view)
/// fits; bigger views paginate.
pub const http_response_size_max: u32 = 1024 * 1024;

/// Open websockets. Reason: one per watching page; never more than the connections.
pub const websocket_connections_max: u32 = http_connections_max;

/// Largest websocket message. Reason: a live update carries one changed page fragment.
pub const websocket_message_size_max: u32 = 64 * 1024;

/// Live events kept for catch-up. Reason: a reconnecting page replays from the last event
/// it saw; a page further behind than this reloads instead.
pub const live_events_backlog_max: u32 = 65_536;

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
    assert(websocket_message_size_max <= http_response_size_max);
    assert(esi_error_limit_floor > 0);
    assert(esi_retries_max > 0);
    assert(sim_fault_percent_max < 100);
    assert(tick_ns > 0);
}

test "constants: limits are positive and consistent" {
    try std.testing.expect(users_max > 0);
    try std.testing.expect(characters_max >= users_max);
    try std.testing.expect(states_max > 0);
    try std.testing.expect(esi_requests_in_flight_max <= http_connections_max);
    try std.testing.expect(memory_budget_bytes >= esi_response_size_max);
}
