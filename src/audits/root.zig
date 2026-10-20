//! Character audits for vetting and spy-hunting.
//!
//! Job:
//!   Read registered characters' private data from ESI (assets, contacts, contracts,
//!   corporation history, mail, wallet, skills and skill queue), keep its history, find
//!   characters, check that users registered every character, and alert when one is
//!   removed. This is the most sensitive data in the system: every view is audit-logged.
//!
//! Inputs:
//!   ESI responses for each registered character's private routes.
//!
//! Outputs:
//!   Stored audit records and history; alerts; skill history for SRP checks.
//!
//! Limits (src/constants.zig):
//!   characters_max
//!   esi_response_size_max
//!
//! Status: stub. No feature code yet; see docs/roadmap.md (audits milestone).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

comptime {
    assert(constants.characters_max > 0);
    assert(constants.esi_response_size_max <= constants.memory_budget_bytes);
}

test "audits: stub compiles and its limits are set" {
    try std.testing.expect(constants.characters_max > 0);
    try std.testing.expect(constants.esi_response_size_max > 0);
}
