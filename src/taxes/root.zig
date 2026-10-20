//! Moon and mining taxes.
//!
//! Job:
//!   Tax ore mined at corporation moons (and optionally all mining) per ore type, priced
//!   from a market source, and keep each payer's balance in a double-entry ledger with
//!   credits, interest and payments matched from the corporation wallet. Results must match
//!   the old tax app to the ISK before cutover.
//!
//! Inputs:
//!   Mining ledgers and wallet journals from the ESI client; prices; tax rules.
//!
//! Outputs:
//!   Ledger entries and balances; flags for unknown characters mining your moons.
//!
//! Limits (src/constants.zig):
//!   ore_types_max
//!
//! Status: stub. No feature code yet; see docs/roadmap.md (taxes milestone).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

comptime {
    assert(constants.ore_types_max > 0);
    assert(constants.ore_types_max <= 65_535); // Ore indexes fit in a u16.
}

test "taxes: stub compiles and its limits are set" {
    try std.testing.expect(constants.ore_types_max > 0);
}
