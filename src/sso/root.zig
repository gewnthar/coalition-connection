//! EVE SSO login, mains and alts.
//!
//! Job:
//!   Log a user in through EVE SSO (OAuth 2.0 authorization code flow) and verify the
//!   returned token before trusting any claim in it.
//!   Link characters to a user: one main, any number of alts up to the limit, and detect a
//!   character that changed hands (its owner hash changed) so it is unlinked.
//!
//! Inputs:
//!   SSO callbacks (code and state), tokens from EVE's token endpoint, signing keys.
//!
//! Outputs:
//!   A session for the user; character links; stored refresh tokens for the ESI client.
//!
//! Limits (src/constants.zig):
//!   characters_per_user_max
//!   characters_max
//!   users_max
//!
//! Status: stub. No feature code yet; see docs/roadmap.md (core milestone, SSO slices).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

comptime {
    assert(constants.characters_per_user_max <= constants.characters_max);
    assert(constants.users_max <= constants.characters_max);
}

test "sso: stub compiles and its limits are set" {
    try std.testing.expect(constants.characters_per_user_max > 0);
    try std.testing.expect(constants.characters_max > 0);
    try std.testing.expect(constants.users_max > 0);
}
