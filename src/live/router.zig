//! Router (roadmap slice core 6, with the response writer).
//!
//! Job: choose the response for each request the parser accepted. Release 0.1 serves one
//! fixed page at "/" for GET and HEAD. Any other path is 404 Not Found, whatever the method,
//! and any other method on "/" is 405 Method Not Allowed with an Allow field naming GET and
//! HEAD (RFC 9110, section 15.5.6).
//!
//! Inputs: a `Request` from the parser. The parser has already refused every path nginx
//! would rewrite before matching its location rules ("//", dot segments, any percent-escape,
//! a backslash or a '#'), so the path matched here, byte for byte, is the path nginx matched.
//! Outputs: a `Response` for the writer (`http_response.write`). Its fields and body are
//! static, so they never overlap the response buffer they are written into. A HEAD gets
//! the GET's head, Content-Length included, without the body.
//! Limits: none of its own; the page and its fields fit `http_response_size_max` and
//! `http_response_headers_max`, checked at compile time below.
//!
//! The router never decides that a connection closes: `close` stays false, and the caller
//! closes after an HTTP/1.0 request or one carrying "Connection: close". Paths are matched
//! exactly and case-sensitively, and the query (after '?') is ignored. "OPTIONS *" names no
//! resource, so it gets 404 like any other path; nginx answers it before it reaches the app.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const http_request = @import("http_request.zig");
const http_response = @import("http_response.zig");

const Request = http_request.Request;
const Response = http_response.Response;
const Header = http_response.Header;

/// The 0.1 page: fixed text, the same on every request.
pub const page =
    \\<!doctype html>
    \\<html lang="en">
    \\<head>
    \\<meta charset="utf-8">
    \\<meta name="viewport" content="width=device-width, initial-scale=1">
    \\<title>Coalition Connection</title>
    \\</head>
    \\<body>
    \\<h1>Coalition Connection</h1>
    \\<p>The server is running. Sign-in comes in a later release.</p>
    \\</body>
    \\</html>
    \\
;

const page_headers = [_]Header{
    .{ .name = "Content-Type", .value = "text/html; charset=utf-8" },
};

/// The methods "/" answers, as the Allow field of a 405 names them.
const allow_headers = [_]Header{
    .{ .name = "Allow", .value = "GET, HEAD" },
};

/// The page's head exactly as the writer emits it.
const page_head = "HTTP/1.1 200 OK\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    std.fmt.comptimePrint("Content-Length: {d}\r\n", .{page.len}) ++
    "\r\n";

comptime {
    // The page and its head fit one response buffer, with the Connection field a caller
    // may add for a closing connection.
    assert(page_head.len + "Connection: close\r\n".len + page.len <= constants.http_response_size_max);
    assert(page_headers.len <= constants.http_response_headers_max);
    assert(allow_headers.len <= constants.http_response_headers_max);
}

/// The response to `request`.
pub fn route(request: *const Request) Response {
    const target = request.target;
    assert(target.len > 0);
    assert(target[0] == '/' or (target.len == 1 and target[0] == '*'));
    const head = request.method == .head;
    const result: Response = if (!std.mem.eql(u8, path(target), "/"))
        .{ .status = .not_found, .omit_body = head }
    else switch (request.method) {
        .get, .head => .{ .status = .ok, .headers = &page_headers, .body = page, .omit_body = head },
        .post, .put, .delete, .options, .patch => .{
            .status = .method_not_allowed,
            .headers = &allow_headers,
            .omit_body = head,
        },
    };
    // Only GET and HEAD get the page, and only a 405 names the allowed methods.
    assert((result.status == .ok) == (result.body.len > 0));
    assert(result.status != .ok or request.method == .get or request.method == .head);
    assert((result.status == .method_not_allowed) == (result.headers.ptr == &allow_headers));
    return result;
}

/// The target up to its first '?': "/a?b" gives "/a". "*" is its own path.
fn path(target: []const u8) []const u8 {
    assert(target.len > 0);
    assert(target.len <= constants.http_request_size_max);
    const end = std.mem.findScalar(u8, target, '?') orelse target.len;
    const result = target[0..end];
    assert(result.len >= 1 and result[0] == target[0]);
    assert(result.len == target.len or target[result.len] == '?');
    return result;
}

// ---- Tests ----------------------------------------------------------------------------

const testing = std.testing;

/// Parses `text` as one whole head and returns the request.
fn parsed(text: []const u8) !Request {
    var scan: http_request.HeadScan = .{};
    const request = try http_request.parse(text, &scan);
    try testing.expectEqual(@as(u32, @intCast(text.len)), request.head_len);
    return request;
}

/// Routes `text` and writes the response into `buffer`, returning the bytes written.
fn respond(text: []const u8, buffer: []u8) ![]const u8 {
    const request = try parsed(text);
    const len = try http_response.write(buffer, route(&request));
    return buffer[0..len];
}

test "router: GET / gets 200 and the page, byte for byte" {
    var buffer: [2048]u8 = undefined;
    const out = try respond("GET / HTTP/1.1\r\nHost: a\r\n\r\n", &buffer);
    try testing.expectEqualStrings(page_head ++ page, out);
}

test "router: HEAD / gets the GET's head without the body" {
    var buffer: [2048]u8 = undefined;
    const out = try respond("HEAD / HTTP/1.1\r\nHost: a\r\n\r\n", &buffer);
    try testing.expectEqualStrings(page_head, out);
}

test "router: the query is ignored, and HTTP/1.0 gets the same page" {
    const texts = [_][]const u8{
        "GET /?a=1 HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET /? HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET /?next=/x HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET / HTTP/1.0\r\n\r\n",
    };
    for (texts) |text| {
        var buffer: [2048]u8 = undefined;
        try testing.expectEqualStrings(page_head ++ page, try respond(text, &buffer));
    }
}

test "router: any other path is 404, whatever the method" {
    const not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    const texts = [_][]const u8{
        "GET /x HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET /x?a HTTP/1.1\r\nHost: a\r\n\r\n",
        "HEAD /x HTTP/1.1\r\nHost: a\r\n\r\n",
        "POST /x HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET /index.html HTTP/1.1\r\nHost: a\r\n\r\n",
        // Matched exactly: a longer path is not "/".
        "GET /a/ HTTP/1.1\r\nHost: a\r\n\r\n",
        "OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n",
    };
    for (texts) |text| {
        var buffer: [256]u8 = undefined;
        try testing.expectEqualStrings(not_found, try respond(text, &buffer));
    }
}

test "router: every other method on / is 405 with Allow: GET, HEAD" {
    const not_allowed = "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, HEAD\r\nContent-Length: 0\r\n\r\n";
    const methods = [_][]const u8{ "POST", "PUT", "DELETE", "OPTIONS", "PATCH" };
    // Every method the parser accepts is GET, HEAD or one of these.
    try testing.expectEqual(@typeInfo(http_request.Method).@"enum".field_names.len, methods.len + 2);
    inline for (methods) |method| {
        var buffer: [256]u8 = undefined;
        const text = method ++ " / HTTP/1.1\r\nHost: a\r\n\r\n";
        try testing.expectEqualStrings(not_allowed, try respond(text, &buffer));
    }
}

test "router: a target nginx would rewrite never reaches the router" {
    const texts = [_][]const u8{
        "GET //. HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET /a/.. HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET /%2e HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET /%2F HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET /%61 HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET /#a HTTP/1.1\r\nHost: a\r\n\r\n",
    };
    for (texts) |text| {
        try testing.expectError(error.TargetInvalid, parsed(text));
    }
}

test "router: the page response fits a buffer exactly, and one byte less is refused" {
    const request = try parsed("GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    const response = route(&request);
    const total = page_head.len + page.len;
    var buffer: [total]u8 = undefined;
    try testing.expectEqual(@as(u32, total), try http_response.write(&buffer, response));
    try testing.expectError(error.ResponseTooLarge, http_response.write(buffer[0 .. total - 1], response));
}
