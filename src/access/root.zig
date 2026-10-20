//! States, groups and permissions.
//!
//! Job:
//!   Decide what each user may see and do, the way Alliance Auth does: a user's state comes
//!   from their main character's corporation and alliance; groups are joined by request,
//!   approval or automatically; permissions come from the state and the groups. Every
//!   decision is a pure function of its inputs, so it can be compared with Alliance Auth.
//!
//! Inputs:
//!   Character affiliations (from the ESI client), group memberships, admin changes.
//!
//! Outputs:
//!   Each user's state, groups and permissions; change events for live updates and services.
//!
//! Limits (src/constants.zig):
//!   states_max
//!   groups_max
//!   groups_per_user_max
//!   permissions_max
//!
//! Status: stub. No feature code yet; see docs/roadmap.md (core milestone, access slices).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

comptime {
    assert(constants.groups_per_user_max <= constants.groups_max);
    assert(constants.states_max > 0);
}

test "access: stub compiles and its limits are set" {
    try std.testing.expect(constants.states_max > 0);
    try std.testing.expect(constants.groups_max > 0);
    try std.testing.expect(constants.groups_per_user_max > 0);
    try std.testing.expect(constants.permissions_max > 0);
}
