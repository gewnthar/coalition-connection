//! Ship replacement (SRP) for alliance and corporation programs.
//!
//! Job:
//!   Run each SRP program with its own rules, budget and approvers. Losses arrive from ESI
//!   killmails; each goes through the same checks (doctrine fit, skills at the moment of
//!   the loss, ship rules) before a reviewer decides, and payouts go into the same ledger
//!   as taxes. Every override and waiver is logged with a reason.
//!
//! Inputs:
//!   Killmails from the ESI client; doctrines; skill history from audits; reviewer actions.
//!
//! Outputs:
//!   SRP requests, decisions and ledger payouts.
//!
//! Limits (src/constants.zig):
//!   srp_programs_max
//!   doctrines_max
//!   doctrine_skills_max
//!
//! Status: stub. No feature code yet; see docs/roadmap.md (SRP milestone).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

comptime {
    assert(constants.srp_programs_max > 0);
    assert(constants.doctrine_skills_max > 0);
}

test "srp: stub compiles and its limits are set" {
    try std.testing.expect(constants.srp_programs_max > 0);
    try std.testing.expect(constants.doctrines_max > 0);
    try std.testing.expect(constants.doctrine_skills_max > 0);
}
