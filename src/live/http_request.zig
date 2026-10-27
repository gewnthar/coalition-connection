//! HTTP/1.1 request parser (roadmap slice core 5).
//!
//! Job: parse the request line and header fields of one request from a caller-owned buffer.
//! Never allocates and never copies: every slice in the returned `Request` points into the
//! caller's buffer, so the buffer must outlive the `Request`.
//!
//! Inputs: the bytes received so far on one connection, at most `http_request_size_max`.
//! Outputs: a `Request`, `error.Incomplete` when the head has not fully arrived yet (read
//! more and parse again), or a named error for each kind of bad input so the caller can
//! choose the response status.
//! Limits: `http_request_size_max` (head plus body) and `http_headers_max`.
//!
//! Strict by design. The server sits behind a proxy, and a lenient parser that disagrees
//! with the proxy about where a request ends invites request smuggling. So lines end in
//! CRLF only, obsolete line folding is refused, a header name must touch its colon, there
//! is at most one Content-Length, and Transfer-Encoding is refused: request bodies are small
//! forms, so chunked uploads are not needed.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

const size_max = constants.http_request_size_max;
const headers_max = constants.http_headers_max;

comptime {
    assert(size_max >= 16);
    assert(headers_max > 0);
    // Offsets are u32, and `head_len + content_length` must not overflow.
    assert(size_max <= std.math.maxInt(u32) / 2);
}

/// Methods the server answers. Others get `error.MethodUnsupported` (501).
pub const Method = enum { get, head, post, put, delete, options, patch };

pub const Version = enum { http_1_0, http_1_1 };

pub const Header = struct {
    name: []const u8,
    /// Leading and trailing spaces and tabs removed.
    value: []const u8,
};

pub const Request = struct {
    method: Method,
    /// Origin form ("/path?query"), or "*" for OPTIONS.
    target: []const u8,
    version: Version,
    headers: [headers_max]Header,
    header_count: u32,
    /// Bytes of the request line, the header lines and the empty line that ends them.
    /// The body, if any, starts here.
    head_len: u32,
    /// Body length from Content-Length; 0 when the header is absent.
    content_length: u32,

    /// The value of the first header named `name`, compared without regard to case.
    pub fn header(self: *const Request, name: []const u8) ?[]const u8 {
        assert(self.header_count <= headers_max);
        assert(name.len > 0);
        for (self.headers[0..self.header_count]) |field| {
            if (equalIgnoreCase(field.name, name)) return field.value;
        }
        return null;
    }
};

pub const Error = error{
    /// The empty line that ends the head has not arrived yet. Not a bad request.
    Incomplete,
    /// Head, or head plus Content-Length, is longer than `http_request_size_max` (413 or 431).
    RequestTooLarge,
    /// Not "method SP target SP version", or the line is empty.
    RequestLineInvalid,
    /// The method is empty or has a character that is not allowed in a token.
    MethodInvalid,
    /// A well-formed method the server does not answer (501).
    MethodUnsupported,
    TargetInvalid,
    /// Not of the form "HTTP/d.d".
    VersionInvalid,
    /// Well formed, but not HTTP/1.0 or HTTP/1.1 (505).
    VersionUnsupported,
    /// A header line with no colon.
    HeaderLineInvalid,
    /// A header name that is empty or has a character not allowed in a token, including
    /// the space or tab of an obsolete folded line or of "Name : value".
    HeaderNameInvalid,
    /// A header value with a control character other than tab.
    HeaderValueInvalid,
    /// More than `http_headers_max` header fields (431).
    HeadersTooMany,
    /// HTTP/1.1 requires exactly one Host header.
    HostMissing,
    HostDuplicate,
    /// Content-Length is empty or not all digits.
    ContentLengthInvalid,
    ContentLengthDuplicate,
    /// Transfer-Encoding is present (501). See the file comment.
    TransferEncodingUnsupported,
};

/// Parses one request head from `buffer`, which holds the bytes received so far.
pub fn parse(buffer: []const u8) Error!Request {
    assert(buffer.len <= size_max);
    const buffer_len: u32 = @intCast(buffer.len);
    const head_len = findHeadEnd(buffer) orelse {
        if (buffer_len == size_max) return error.RequestTooLarge;
        return error.Incomplete;
    };
    assert(head_len >= 4);
    assert(head_len <= buffer_len);
    const head = buffer[0..head_len];

    const request_line = nextLine(head, 0);
    var request: Request = undefined;
    try parseRequestLine(request_line.text, &request);
    request.header_count = try parseHeaders(head, request_line.next, &request.headers);
    request.head_len = head_len;
    request.content_length = try checkFraming(&request);

    assert(request.header_count <= headers_max);
    assert(request.head_len + request.content_length <= size_max);
    return request;
}

/// Index just past the first CRLF CRLF, or null if there is none yet.
fn findHeadEnd(buffer: []const u8) ?u32 {
    assert(buffer.len <= size_max);
    const len: u32 = @intCast(buffer.len);
    if (len < 4) return null;
    var index: u32 = 0;
    while (index <= len - 4) : (index += 1) {
        const window = buffer[index..][0..4];
        if (window[0] == '\r' and window[1] == '\n' and window[2] == '\r' and window[3] == '\n') {
            assert(index + 4 <= len);
            return index + 4;
        }
    }
    assert(index == len - 3);
    return null;
}

const Line = struct {
    /// The line without its CRLF. May hold a stray CR or LF; the validators reject those.
    text: []const u8,
    /// Index of the next line's first byte.
    next: u32,
};

/// The line starting at `start`. `head` ends in CRLF CRLF, so every line has a CRLF.
fn nextLine(head: []const u8, start: u32) Line {
    assert(head.len >= 4 and head.len <= size_max);
    assert(start + 2 <= head.len);
    const len: u32 = @intCast(head.len);
    var index: u32 = start;
    while (index < len - 2) : (index += 1) {
        if (head[index] == '\r' and head[index + 1] == '\n') {
            return .{ .text = head[start..index], .next = index + 2 };
        }
    }
    // No earlier CRLF, so the line ends at the head's final CRLF.
    assert(index == len - 2);
    assert(head[len - 2] == '\r' and head[len - 1] == '\n');
    return .{ .text = head[start .. len - 2], .next = len };
}

fn parseRequestLine(line: []const u8, request: *Request) Error!void {
    assert(line.len < size_max);
    if (line.len == 0) return error.RequestLineInvalid;
    const first_space = findByte(line, 0, ' ') orelse return error.RequestLineInvalid;
    const second_space = findByte(line, first_space + 1, ' ') orelse return error.RequestLineInvalid;
    assert(first_space < second_space);

    request.method = try parseMethod(line[0..first_space]);
    const target = line[first_space + 1 .. second_space];
    if (!isTargetValid(target, request.method)) return error.TargetInvalid;
    request.target = target;
    // A third space lands in the version and fails its check.
    request.version = try parseVersion(line[second_space + 1 ..]);
    assert(request.target.len > 0);
}

const method_names = [_]struct { name: []const u8, method: Method }{
    .{ .name = "GET", .method = .get },
    .{ .name = "HEAD", .method = .head },
    .{ .name = "POST", .method = .post },
    .{ .name = "PUT", .method = .put },
    .{ .name = "DELETE", .method = .delete },
    .{ .name = "OPTIONS", .method = .options },
    .{ .name = "PATCH", .method = .patch },
};

/// Methods are case-sensitive: "get" is a valid token but not the GET method.
fn parseMethod(text: []const u8) Error!Method {
    assert(text.len < size_max);
    if (!isToken(text)) return error.MethodInvalid;
    for (method_names) |entry| {
        if (equalBytes(text, entry.name)) return entry.method;
    }
    assert(text.len > 0);
    return error.MethodUnsupported;
}

fn parseVersion(text: []const u8) Error!Version {
    assert(text.len < size_max);
    if (text.len != 8 or !equalBytes(text[0..5], "HTTP/")) return error.VersionInvalid;
    if (!isDigit(text[5]) or text[6] != '.' or !isDigit(text[7])) return error.VersionInvalid;
    assert(text[0] == 'H');
    if (text[5] != '1') return error.VersionUnsupported;
    if (text[7] == '1') return .http_1_1;
    if (text[7] == '0') return .http_1_0;
    return error.VersionUnsupported;
}

/// Origin form only, since the server sits behind a proxy; "*" only for OPTIONS.
fn isTargetValid(target: []const u8, method: Method) bool {
    assert(target.len < size_max);
    if (target.len == 0) return false;
    if (target.len == 1 and target[0] == '*') return method == .options;
    if (target[0] != '/') return false;
    for (target) |byte| {
        // Visible ASCII only; anything else must arrive percent-encoded.
        if (byte < 0x21 or byte > 0x7e) return false;
    }
    assert(target[0] == '/');
    return true;
}

/// Parses header lines from `start` up to and including the empty line that ends the head.
/// Returns the number of header fields stored in `headers`.
fn parseHeaders(head: []const u8, start: u32, headers: *[headers_max]Header) Error!u32 {
    assert(start >= 2);
    assert(start <= head.len - 2);
    var position: u32 = start;
    var count: u32 = 0;
    while (count < headers_max) : (count += 1) {
        const line = nextLine(head, position);
        position = line.next;
        if (line.text.len == 0) {
            // findHeadEnd stopped at the first CRLF CRLF, so the only empty line is the last.
            assert(position == head.len);
            return count;
        }
        headers[count] = try parseHeaderLine(line.text);
    }
    assert(count == headers_max);
    const after = nextLine(head, position);
    if (after.text.len != 0) return error.HeadersTooMany;
    assert(after.next == head.len);
    return count;
}

fn parseHeaderLine(line: []const u8) Error!Header {
    assert(line.len > 0);
    assert(line.len < size_max);
    const colon = findByte(line, 0, ':') orelse return error.HeaderLineInvalid;
    const name = line[0..colon];
    if (!isToken(name)) return error.HeaderNameInvalid;
    const value = trimWhitespace(line[colon + 1 ..]);
    for (value) |byte| {
        // Tab, visible ASCII, space and obs-text (0x80 and up); no other control bytes.
        if (byte == 0x7f or (byte < 0x20 and byte != '\t')) return error.HeaderValueInvalid;
    }
    return .{ .name = name, .value = value };
}

/// Checks the headers that decide where the request ends. Returns the body length.
fn checkFraming(request: *const Request) Error!u32 {
    assert(request.header_count <= headers_max);
    assert(request.head_len <= size_max);
    var host_count: u32 = 0;
    var content_length: ?u32 = null;
    for (request.headers[0..request.header_count]) |field| {
        if (equalIgnoreCase(field.name, "host")) {
            host_count += 1;
        } else if (equalIgnoreCase(field.name, "transfer-encoding")) {
            return error.TransferEncodingUnsupported;
        } else if (equalIgnoreCase(field.name, "content-length")) {
            if (content_length != null) return error.ContentLengthDuplicate;
            content_length = try parseContentLength(field.value);
        }
    }
    if (host_count > 1) return error.HostDuplicate;
    if (host_count == 0 and request.version == .http_1_1) return error.HostMissing;

    const body_len = content_length orelse 0;
    // Both terms are at most size_max, so the sum cannot overflow a u32.
    if (request.head_len + body_len > size_max) return error.RequestTooLarge;
    assert(host_count <= 1);
    return body_len;
}

fn parseContentLength(value: []const u8) Error!u32 {
    assert(value.len < size_max);
    if (value.len == 0) return error.ContentLengthInvalid;
    var result: u32 = 0;
    for (value) |byte| {
        if (!isDigit(byte)) return error.ContentLengthInvalid;
        // Checked before each step, so result stays at most 10 * size_max + 9.
        if (result > size_max) return error.RequestTooLarge;
        result = result * 10 + (byte - '0');
    }
    if (result > size_max) return error.RequestTooLarge;
    assert(result <= size_max);
    return result;
}

// ---- Byte helpers: small and bounded by their slice lengths ---------------------------

/// Index of the first `byte` at or after `start`, or null.
fn findByte(text: []const u8, start: u32, byte: u8) ?u32 {
    assert(text.len < size_max);
    assert(start <= text.len);
    const len: u32 = @intCast(text.len);
    var index: u32 = start;
    while (index < len) : (index += 1) {
        if (text[index] == byte) return index;
    }
    assert(index == len);
    return null;
}

/// RFC 9110 token: one or more of the "tchar" characters.
fn isToken(text: []const u8) bool {
    assert(text.len < size_max);
    if (text.len == 0) return false;
    for (text) |byte| {
        if (!isTokenChar(byte)) return false;
    }
    assert(text.len > 0);
    return true;
}

fn isTokenChar(byte: u8) bool {
    const result = switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
    // Tokens never hold whitespace, separators or control bytes.
    assert(!result or (byte > 0x20 and byte < 0x7f));
    assert(!result or (byte != ':' and byte != '"'));
    return result;
}

fn isDigit(byte: u8) bool {
    const result = byte >= '0' and byte <= '9';
    assert(!result or byte - '0' <= 9);
    assert(result or byte < '0' or byte > '9');
    return result;
}

fn trimWhitespace(text: []const u8) []const u8 {
    assert(text.len < size_max);
    var start: u32 = 0;
    var end: u32 = @intCast(text.len);
    while (start < end and (text[start] == ' ' or text[start] == '\t')) start += 1;
    while (end > start and (text[end - 1] == ' ' or text[end - 1] == '\t')) end -= 1;
    assert(start <= end);
    assert(end <= text.len);
    return text[start..end];
}

fn equalBytes(a: []const u8, b: []const u8) bool {
    assert(a.len < size_max);
    assert(b.len < size_max);
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

fn equalIgnoreCase(a: []const u8, b: []const u8) bool {
    assert(a.len < size_max);
    assert(b.len < size_max);
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (lowerAscii(x) != lowerAscii(y)) return false;
    }
    return true;
}

fn lowerAscii(byte: u8) u8 {
    const result = if (byte >= 'A' and byte <= 'Z') byte + ('a' - 'A') else byte;
    assert(result < 'A' or result > 'Z');
    assert((result == byte) or (byte >= 'A' and byte <= 'Z'));
    return result;
}

// ---- Tests ----------------------------------------------------------------------------

const testing = std.testing;

test "http_request: a simple GET" {
    const request = try parse("GET /index.html?tab=alts HTTP/1.1\r\nHost: example.test\r\n\r\n");
    try testing.expectEqual(Method.get, request.method);
    try testing.expectEqualStrings("/index.html?tab=alts", request.target);
    try testing.expectEqual(Version.http_1_1, request.version);
    try testing.expectEqual(@as(u32, 1), request.header_count);
    try testing.expectEqualStrings("Host", request.headers[0].name);
    try testing.expectEqualStrings("example.test", request.headers[0].value);
    try testing.expectEqual(@as(u32, 0), request.content_length);
}

test "http_request: head_len points at the body, and Content-Length is read" {
    const text = "POST /login HTTP/1.1\r\nHost: a\r\nContent-Length: 7\r\n\r\nname=ok";
    const request = try parse(text);
    try testing.expectEqual(Method.post, request.method);
    try testing.expectEqual(@as(u32, 7), request.content_length);
    try testing.expectEqualStrings("name=ok", text[request.head_len..]);
}

test "http_request: header lookup ignores case and values are trimmed" {
    const request = try parse("GET / HTTP/1.1\r\nhOsT:  a  \r\nX-Empty:\r\nCookie:\tk=v\t\r\n\r\n");
    try testing.expectEqualStrings("a", request.header("Host").?);
    try testing.expectEqualStrings("", request.header("x-empty").?);
    try testing.expectEqualStrings("k=v", request.header("COOKIE").?);
    try testing.expect(request.header("Missing") == null);
}

test "http_request: every method and version" {
    const cases = [_]struct { text: []const u8, method: Method, version: Version }{
        .{ .text = "GET / HTTP/1.0\r\n\r\n", .method = .get, .version = .http_1_0 },
        .{ .text = "HEAD / HTTP/1.0\r\n\r\n", .method = .head, .version = .http_1_0 },
        .{ .text = "POST / HTTP/1.0\r\n\r\n", .method = .post, .version = .http_1_0 },
        .{ .text = "PUT / HTTP/1.0\r\n\r\n", .method = .put, .version = .http_1_0 },
        .{ .text = "DELETE / HTTP/1.1\r\nHost: a\r\n\r\n", .method = .delete, .version = .http_1_1 },
        .{ .text = "OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n", .method = .options, .version = .http_1_1 },
        .{ .text = "PATCH / HTTP/1.1\r\nHost: a\r\n\r\n", .method = .patch, .version = .http_1_1 },
    };
    for (cases) |case| {
        const request = try parse(case.text);
        try testing.expectEqual(case.method, request.method);
        try testing.expectEqual(case.version, request.version);
        try testing.expectEqual(@as(u32, @intCast(case.text.len)), request.head_len);
    }
}

test "http_request: incomplete heads ask for more bytes" {
    const cases = [_][]const u8{
        "",
        "G",
        "GET / HTTP/1.1",
        "GET / HTTP/1.1\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\n\r",
        // Bare LF never ends the head.
        "GET / HTTP/1.1\nHost: a\n\n",
    };
    for (cases) |text| {
        try testing.expectError(error.Incomplete, parse(text));
    }
}

test "http_request: each bad input has its own error" {
    const cases = [_]struct { text: []const u8, err: Error }{
        .{ .text = "\r\n\r\n", .err = error.RequestLineInvalid },
        .{ .text = "GET\r\n\r\n", .err = error.RequestLineInvalid },
        .{ .text = "GET /\r\n\r\n", .err = error.RequestLineInvalid },
        .{ .text = " / HTTP/1.1\r\nHost: a\r\n\r\n", .err = error.MethodInvalid },
        .{ .text = "G(T / HTTP/1.1\r\nHost: a\r\n\r\n", .err = error.MethodInvalid },
        .{ .text = "get / HTTP/1.1\r\nHost: a\r\n\r\n", .err = error.MethodUnsupported },
        .{ .text = "TRACE / HTTP/1.1\r\nHost: a\r\n\r\n", .err = error.MethodUnsupported },
        .{ .text = "GET  / HTTP/1.1\r\nHost: a\r\n\r\n", .err = error.TargetInvalid },
        .{ .text = "GET http://a/ HTTP/1.1\r\nHost: a\r\n\r\n", .err = error.TargetInvalid },
        .{ .text = "GET * HTTP/1.1\r\nHost: a\r\n\r\n", .err = error.TargetInvalid },
        .{ .text = "GET /\x7f HTTP/1.1\r\nHost: a\r\n\r\n", .err = error.TargetInvalid },
        .{ .text = "GET / HTTP/1.1 \r\nHost: a\r\n\r\n", .err = error.VersionInvalid },
        .{ .text = "GET / http/1.1\r\nHost: a\r\n\r\n", .err = error.VersionInvalid },
        .{ .text = "GET / HTTP/11\r\nHost: a\r\n\r\n", .err = error.VersionInvalid },
        .{ .text = "GET / HTTP/2.0\r\nHost: a\r\n\r\n", .err = error.VersionUnsupported },
        .{ .text = "GET / HTTP/1.2\r\nHost: a\r\n\r\n", .err = error.VersionUnsupported },
        .{ .text = "GET / HTTP/1.1\r\nHost a\r\n\r\n", .err = error.HeaderLineInvalid },
        .{ .text = "GET / HTTP/1.1\r\n: a\r\n\r\n", .err = error.HeaderNameInvalid },
        .{ .text = "GET / HTTP/1.1\r\nHost : a\r\n\r\n", .err = error.HeaderNameInvalid },
        .{ .text = "GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n", .err = error.HeaderLineInvalid },
        .{ .text = "GET / HTTP/1.1\r\nHost: a\r\n x: y\r\n\r\n", .err = error.HeaderNameInvalid },
        .{ .text = "GET / HTTP/1.1\r\nHost: a\x00b\r\n\r\n", .err = error.HeaderValueInvalid },
        .{ .text = "GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n", .err = error.HeaderValueInvalid },
        .{ .text = "GET / HTTP/1.1\r\nHost: a\nX: b\r\n\r\n", .err = error.HeaderValueInvalid },
        .{ .text = "GET / HTTP/1.1\r\n\r\n", .err = error.HostMissing },
        .{ .text = "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", .err = error.HostDuplicate },
        .{ .text = "GET / HTTP/1.1\r\nHost: a\r\nContent-Length:\r\n\r\n", .err = error.ContentLengthInvalid },
        .{ .text = "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: +1\r\n\r\n", .err = error.ContentLengthInvalid },
        .{ .text = "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1, 1\r\n\r\n", .err = error.ContentLengthInvalid },
        .{ .text = "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n", .err = error.ContentLengthDuplicate },
        .{ .text = "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999\r\n\r\n", .err = error.RequestTooLarge },
        .{ .text = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n", .err = error.TransferEncodingUnsupported },
    };
    for (cases) |case| {
        testing.expectError(case.err, parse(case.text)) catch |err| {
            std.debug.print("failing case: {s}\n", .{case.text});
            return err;
        };
    }
}

/// Test helper: a request head with `count` header fields, written into `buffer`.
fn buildHead(buffer: *[size_max]u8, count: u32) []const u8 {
    assert(count <= headers_max + 1);
    const request_line = "GET / HTTP/1.0\r\n";
    const field = "X-A: b\r\n";
    comptime assert(request_line.len + (headers_max + 1) * field.len + 2 <= size_max);
    var len: u32 = 0;
    @memcpy(buffer[0..request_line.len], request_line);
    len += request_line.len;
    var index: u32 = 0;
    while (index < count) : (index += 1) {
        @memcpy(buffer[len..][0..field.len], field);
        len += field.len;
    }
    @memcpy(buffer[len..][0..2], "\r\n");
    len += 2;
    assert(len == request_line.len + count * field.len + 2);
    return buffer[0..len];
}

test "http_request: header count at and past http_headers_max" {
    var buffer: [size_max]u8 = undefined;
    var count: u32 = 0;
    while (count <= headers_max) : (count += 1) {
        const request = try parse(buildHead(&buffer, count));
        try testing.expectEqual(count, request.header_count);
    }
    try testing.expectError(error.HeadersTooMany, parse(buildHead(&buffer, headers_max + 1)));
}

test "http_request: size limits on the head and on head plus body" {
    const buffer: [size_max]u8 = @splat('a');
    // A full buffer with no end of head can never become a request.
    try testing.expectError(error.RequestTooLarge, parse(&buffer));
    try testing.expectError(error.Incomplete, parse(buffer[0 .. size_max - 1]));

    const head = "POST / HTTP/1.0\r\nContent-Length: ";
    var text: [64]u8 = undefined;
    @memcpy(text[0..head.len], head);
    const body_fits = size_max - (head.len + 5 + 4);
    const fits = try std.fmt.bufPrint(text[head.len..], "{d:0>5}\r\n\r\n", .{body_fits});
    const fit_request = try parse(text[0 .. head.len + fits.len]);
    try testing.expectEqual(@as(u32, size_max), fit_request.head_len + fit_request.content_length);
    const over = try std.fmt.bufPrint(text[head.len..], "{d:0>5}\r\n\r\n", .{body_fits + 1});
    try testing.expectError(error.RequestTooLarge, parse(text[0 .. head.len + over.len]));
}
