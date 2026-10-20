//! Live updates: server-rendered pages plus a websocket that pushes changes.
//!
//! Job:
//!   Render pages as HTML on the server and, when something changes, push the changed
//!   fragment to every page watching it. Every event has an id, so a page that reconnects
//!   catches up from the last event it saw; every page still works with the socket down.
//!
//! Inputs:
//!   Change events from the other components (through Valkey pub/sub); HTTP and websocket
//!   connections from browsers.
//!
//! Outputs:
//!   HTML pages and websocket messages carrying page fragments.
//!
//! Limits (src/constants.zig):
//!   http_connections_max
//!   http_request_size_max
//!   http_response_size_max
//!   websocket_connections_max
//!   websocket_message_size_max
//!   live_events_backlog_max
//!
//! Status: stub. No feature code yet; see docs/roadmap.md (core milestone, live-update slices).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

comptime {
    assert(constants.websocket_connections_max <= constants.http_connections_max);
    assert(constants.websocket_message_size_max <= constants.http_response_size_max);
}

test "live: stub compiles and its limits are set" {
    try std.testing.expect(constants.http_connections_max > 0);
    try std.testing.expect(constants.http_request_size_max > 0);
    try std.testing.expect(constants.http_response_size_max > 0);
    try std.testing.expect(constants.websocket_connections_max > 0);
    try std.testing.expect(constants.websocket_message_size_max > 0);
    try std.testing.expect(constants.live_events_backlog_max > 0);
}
