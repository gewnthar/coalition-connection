//! Service sync: Mumble and XMPP.
//!
//! Job:
//!   Keep each user's Mumble and XMPP accounts and roles in step with their state and
//!   groups: create, update and remove access in batches, and retry failed changes.
//!
//! Inputs:
//!   Access change events; the service servers' current accounts.
//!
//! Outputs:
//!   Account and role changes sent to Mumble and XMPP; a sync status per user.
//!
//! Limits (src/constants.zig):
//!   service_sync_batch_max
//!
//! Status: stub. No feature code yet; see docs/roadmap.md (core milestone, service slices).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

comptime {
    assert(constants.service_sync_batch_max > 0);
    assert(constants.service_sync_batch_max <= constants.users_max);
}

test "services: stub compiles and its limits are set" {
    try std.testing.expect(constants.service_sync_batch_max > 0);
}
