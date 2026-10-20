//! Storage: Postgres, Valkey and the audit log.
//!
//! Job:
//!   Own every byte that must survive a restart. Postgres holds the durable records;
//!   Valkey holds sessions, queues and live-update pub/sub and is never the source of
//!   truth. Both wire protocols are written in Zig over the I/O boundary. The audit log
//!   records every admin action and every view of a member's private data.
//!
//! Inputs:
//!   Statements and records from the other components, through the I/O boundary.
//!
//! Outputs:
//!   Query results and explicit errors; audit-log entries.
//!
//! Limits (src/constants.zig):
//!   postgres_connections_max
//!   postgres_message_size_max
//!   valkey_connections_max
//!   valkey_message_size_max
//!   audit_entry_size_max
//!
//! Status: stub. No feature code yet; see docs/roadmap.md (core milestone, storage slices).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

comptime {
    assert(constants.postgres_connections_max > 0);
    assert(constants.audit_entry_size_max <= constants.postgres_message_size_max);
}

test "storage: stub compiles and its limits are set" {
    try std.testing.expect(constants.postgres_connections_max > 0);
    try std.testing.expect(constants.postgres_message_size_max > 0);
    try std.testing.expect(constants.valkey_connections_max > 0);
    try std.testing.expect(constants.valkey_message_size_max > 0);
    try std.testing.expect(constants.audit_entry_size_max > 0);
}
