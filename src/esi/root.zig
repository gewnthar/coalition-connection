//! ESI client.
//!
//! Job:
//!   Fetch data from EVE's ESI API for every other component, within ESI's limits: track
//!   each rate-limit group's token bucket from the response headers, stop before the error
//!   limit, honour Retry-After, use ETags to skip unchanged data, and walk paged routes.
//!   It never decides what to fetch; callers queue requests and it schedules them.
//!
//! Inputs:
//!   Queued requests (route, character, token) from other components; ESI responses.
//!
//! Outputs:
//!   Response bodies handed back to the caller, or an explicit error per request.
//!
//! Limits (src/constants.zig):
//!   esi_requests_in_flight_max
//!   esi_response_size_max
//!   esi_rate_limit_groups_max
//!   esi_error_limit_floor
//!   esi_retries_max
//!
//! Status: stub. No feature code yet; see docs/roadmap.md (core milestone, ESI slices).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

comptime {
    assert(constants.esi_error_limit_floor > 0);
    assert(constants.esi_requests_in_flight_max <= constants.http_connections_max);
}

test "esi: stub compiles and its limits are set" {
    try std.testing.expect(constants.esi_requests_in_flight_max > 0);
    try std.testing.expect(constants.esi_response_size_max > 0);
    try std.testing.expect(constants.esi_rate_limit_groups_max > 0);
    try std.testing.expect(constants.esi_error_limit_floor > 0);
    try std.testing.expect(constants.esi_retries_max > 0);
}
