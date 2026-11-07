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
//!   http_connection_entry_size_max
//!   http_request_size_max
//!   http_headers_max
//!   http_response_size_max
//!   http_response_headers_max
//!   http_response_buffers_max
//!   websocket_connections_max
//!   websocket_message_size_max
//!   live_events_backlog_max
//!   live_events_backlog_bytes_max
//!
//! Status: the connection table (roadmap core 4) is in `connections.zig` and the HTTP/1.1
//! request parser (roadmap core 5) in `http_request.zig`, and the response writer (roadmap
//! core 6) in `http_response.zig`; the rest is a stub. See docs/roadmap.md (core milestone,
//! live-update slices).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const connections = @import("connections.zig");
pub const http_request = @import("http_request.zig");
pub const http_response = @import("http_response.zig");

comptime {
    assert(constants.websocket_connections_max <= constants.http_connections_max);
    assert(constants.websocket_message_size_max <= constants.http_response_size_max);
}

test "live: stub compiles and its limits are set" {
    try std.testing.expect(constants.http_connections_max > 0);
    try std.testing.expect(constants.http_request_size_max > 0);
    try std.testing.expect(constants.http_headers_max > 0);
    try std.testing.expect(constants.http_response_size_max > 0);
    try std.testing.expect(constants.http_response_buffers_max > 0);
    try std.testing.expect(constants.websocket_connections_max > 0);
    try std.testing.expect(constants.websocket_message_size_max > 0);
    try std.testing.expect(constants.live_events_backlog_max > 0);
    try std.testing.expect(constants.live_events_backlog_bytes_max > 0);
}

test {
    _ = connections;
    _ = http_request;
    _ = http_response;
}
