//! Alliance Auth importer.
//!
//! Job:
//!   Read an Alliance Auth data export (Django's dumpdata JSON) one record at a time and
//!   load what ESI can't give back: users, characters and tokens, states and groups, tax
//!   balances and payments, SRP history and older audit records. The export contains ESI
//!   tokens, so it is treated like a password file. The same code drives the shadow run.
//!
//! Inputs:
//!   A dumpdata JSON file, streamed through a fixed buffer.
//!
//! Outputs:
//!   Records written through storage; a report of every record skipped and why.
//!
//! Limits (src/constants.zig):
//!   import_record_size_max
//!
//! Status: stub. No feature code yet; see docs/roadmap.md (core milestone, importer slices).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

comptime {
    assert(constants.import_record_size_max <= constants.postgres_message_size_max);
    assert(constants.import_record_size_max > 0);
}

test "importer: stub compiles and its limits are set" {
    try std.testing.expect(constants.import_record_size_max > 0);
}
