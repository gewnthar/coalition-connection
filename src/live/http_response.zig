//! HTTP/1.1 response writer (roadmap slice core 6).
//!
//! Job: write one response (status line, header fields, Content-Length and body) into a
//! caller-owned buffer, and choose the status for each request the parser refuses.
//! Never allocates: the caller lends a buffer, normally one of the shared response buffers.
//!
//! Inputs: a `Response` (status, the handler's header fields, the body, and whether the
//! connection closes after it) and a buffer of at most `http_response_size_max` bytes.
//! Outputs: the number of bytes written, or a named error. On an error the buffer holds
//! partial output that must not be sent.
//! Limits: `http_response_size_max` and `http_response_headers_max`.
//!
//! Strict by design, like the parser. The writer adds Content-Length itself, so the length
//! on the wire is always the body's, and it refuses header fields that would contradict it
//! or the connection's framing (Content-Length, Transfer-Encoding, Connection and the other
//! hop-by-hop fields). Names must be tokens, and values must hold no CR, LF or other control
//! byte and no leading or trailing whitespace, so text taken from a request can't end a
//! header line early and smuggle in a header or a second response.
//!
//! Not covered yet: statuses without a body (1xx, 204, 304) and the websocket upgrade (101,
//! which needs "Connection: Upgrade"). A comptime check below refuses those codes until the
//! writer handles them. The router, which picks a handler for each request, is a later slice.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const http_request = @import("http_request.zig");

const size_max = constants.http_response_size_max;
const headers_max = constants.http_response_headers_max;

/// The statuses the server sends. The integer value is the status code on the wire.
pub const Status = enum(u16) {
    ok = 200,
    bad_request = 400,
    content_too_large = 413,
    request_header_fields_too_large = 431,
    not_implemented = 501,
    http_version_not_supported = 505,
};

/// The longest status line the writer emits.
const status_line_size_max: u32 = 64;

/// The status line, CRLF included, with the reason phrase from RFC 9110, section 15.
pub fn statusLine(status: Status) []const u8 {
    const result: []const u8 = switch (status) {
        .ok => "HTTP/1.1 200 OK\r\n",
        .bad_request => "HTTP/1.1 400 Bad Request\r\n",
        .content_too_large => "HTTP/1.1 413 Content Too Large\r\n",
        .request_header_fields_too_large => "HTTP/1.1 431 Request Header Fields Too Large\r\n",
        .not_implemented => "HTTP/1.1 501 Not Implemented\r\n",
        .http_version_not_supported => "HTTP/1.1 505 HTTP Version Not Supported\r\n",
    };
    assert(result.len <= status_line_size_max);
    assert(std.mem.endsWith(u8, result, "\r\n"));
    return result;
}

/// Lines the writer adds after the handler's fields, at their longest.
const tail_size_max: u32 = "Connection: close\r\n".len + "Content-Length: ".len +
    decimal_digits_max + "\r\n\r\n".len;

comptime {
    // Each status line carries its own code, a reason phrase and fits its limit; and no
    // status is one the writer can't frame yet (no body allowed, or an upgrade).
    for (@typeInfo(Status).@"enum".field_names) |name| {
        const status = @field(Status, name);
        const value: u16 = @backingInt(status);
        const line = statusLine(status);
        var digits: [decimal_digits_max]u8 = undefined;
        assert(std.mem.eql(u8, line[0.."HTTP/1.1 ".len], "HTTP/1.1 "));
        assert(std.mem.eql(u8, line["HTTP/1.1 ".len..][0..4], formatDecimal(value, &digits) ++ " "));
        assert(line.len > "HTTP/1.1 000 \r\n".len);
        assert(value >= 200 and value <= 599 and value != 204 and value != 304);
    }
    // A refusal (status line, Connection and Content-Length, no fields) fits a buffer.
    assert(status_line_size_max + tail_size_max <= size_max);
}

/// The status for a request the parser refused, or null for `error.Incomplete`, which is
/// not a refusal: read more bytes and parse again. The switch names every parser error, so
/// a new one fails to compile here until it is given a status. A request line too long for
/// the buffer also ends as `HeadTooLarge` (431): the parser can't tell it from a long head,
/// so the server never sends 414.
pub fn statusForParseError(err: http_request.Error) ?Status {
    const result: ?Status = switch (err) {
        error.Incomplete => null,
        error.HeadTooLarge, error.HeadersTooMany => .request_header_fields_too_large,
        error.ContentTooLarge => .content_too_large,
        error.MethodUnsupported, error.TransferEncodingUnsupported => .not_implemented,
        error.VersionUnsupported => .http_version_not_supported,
        error.RequestLineInvalid,
        error.MethodInvalid,
        error.TargetInvalid,
        error.VersionInvalid,
        error.HeaderLineInvalid,
        error.HeaderNameInvalid,
        error.HeaderValueInvalid,
        error.HostMissing,
        error.HostDuplicate,
        error.ContentLengthInvalid,
        error.ContentLengthDuplicate,
        error.RealIpDuplicate,
        => .bad_request,
    };
    // Guards later edits of the arms: only Incomplete waits, and a refusal is never a 2xx.
    assert((result == null) == (err == error.Incomplete));
    assert(result == null or @backingInt(result.?) >= 400);
    return result;
}

/// The response to a request the parser refused: its status, no body, and the connection
/// closes, because after a refused head the server can't tell where the next request
/// starts. Null for `error.Incomplete`. For a 413 the client may still be sending its body:
/// the caller shuts down its sending side and drains for a moment before it closes, or the
/// kernel's reset over unread bytes can discard the response before the client reads it.
pub fn forParseError(err: http_request.Error) ?Response {
    const status = statusForParseError(err) orelse return null;
    const result: Response = .{ .status = status, .close = true };
    // The size refusals are 4xx and the unsupported features 5xx, never the other way.
    const size_error = err == error.HeadTooLarge or err == error.HeadersTooMany or
        err == error.ContentTooLarge;
    assert(!size_error or @backingInt(result.status) < 500);
    assert(@backingInt(result.status) >= 400);
    return result;
}

pub const Header = struct {
    /// A token, such as "Content-Type". The fields in `reserved_names` are refused.
    name: []const u8,
    /// Written as given: no CR, LF or control byte other than tab, and no leading or
    /// trailing space or tab. Must not point into the buffer being written.
    value: []const u8,
};

pub const Response = struct {
    status: Status,
    /// At most `http_response_headers_max`, written in order.
    headers: []const Header = &.{},
    /// Must not overlap the buffer the response is written into.
    body: []const u8 = "",
    /// For a HEAD request: Content-Length states the body's length, but the body itself is
    /// not written (RFC 9110, section 9.3.2).
    omit_body: bool = false,
    /// Adds "Connection: close": the server closes the connection after this response.
    /// When false the writer says nothing, so the caller still closes after an HTTP/1.0
    /// request, whose default is to close.
    close: bool = false,
};

pub const Error = error{
    /// The response is longer than the buffer (an exact fit is fine).
    ResponseTooLarge,
    /// More than `http_response_headers_max` header fields.
    HeadersTooMany,
    /// A header name that is empty or has a character not allowed in a token.
    HeaderNameInvalid,
    /// A header value holding CR, LF or another control byte other than tab, or starting
    /// or ending with a space or tab.
    HeaderValueInvalid,
    /// A header the writer sets itself, or another hop-by-hop field (see `reserved_names`).
    HeaderReserved,
};

/// Writes `response` into `buffer` and returns its length in bytes. Checks every header
/// field and the body's length before writing anything, so those errors are reported
/// even when the buffer is small.
pub fn write(buffer: []u8, response: Response) Error!u32 {
    assert(buffer.len <= size_max);
    assert(!overlaps(buffer, response.body));
    try checkHeaders(buffer, response.headers);
    // Refusing a body longer than the whole buffer here keeps its length within a u32.
    const sent_len: usize = if (response.omit_body) 0 else response.body.len;
    if (sent_len > buffer.len or response.body.len > size_max) return error.ResponseTooLarge;
    const body_len: u32 = @intCast(response.body.len);

    var out: Cursor = .{ .buffer = buffer };
    try out.append(statusLine(response.status));
    for (response.headers) |field| {
        try out.appendHeader(field.name, field.value);
    }
    if (response.close) try out.appendHeader("Connection", "close");
    try out.append("Content-Length: ");
    try out.appendDecimal(body_len);
    try out.append("\r\n\r\n");
    const head_len = out.len;
    if (!response.omit_body) try out.append(response.body);

    assert(std.mem.startsWith(u8, buffer[0..head_len], "HTTP/1.1 "));
    assert(std.mem.endsWith(u8, buffer[0..head_len], "\r\n\r\n"));
    return out.len;
}

/// Checks the handler's header fields: their count, lengths, names and values.
fn checkHeaders(buffer: []const u8, headers: []const Header) Error!void {
    assert(buffer.len <= size_max);
    if (headers.len > headers_max) return error.HeadersTooMany;
    for (headers) |field| {
        // A field written over the buffer would change after it was checked.
        assert(!overlaps(buffer, field.name));
        assert(!overlaps(buffer, field.value));
        // Values may come from storage or a request: too long is an error, not a crash.
        if (field.name.len > size_max or field.value.len > size_max) {
            return error.ResponseTooLarge;
        }
        if (!isToken(field.name)) return error.HeaderNameInvalid;
        if (isReserved(field.name)) return error.HeaderReserved;
        if (!isValueValid(field.value)) return error.HeaderValueInvalid;
    }
}

/// Appends to a buffer, refusing any write that doesn't fit the room left.
const Cursor = struct {
    buffer: []u8,
    len: u32 = 0,

    fn append(self: *Cursor, bytes: []const u8) Error!void {
        assert(self.buffer.len <= size_max);
        // @memcpy needs its source and destination apart.
        assert(!overlaps(self.buffer, bytes));
        // Compare with the room left rather than adding to len, so no sum can overflow.
        const room: u32 = @as(u32, @intCast(self.buffer.len)) - self.len;
        if (bytes.len > room) return error.ResponseTooLarge;
        const count: u32 = @intCast(bytes.len);
        @memcpy(self.buffer[self.len..][0..count], bytes);
        self.len += count;
    }

    fn appendHeader(self: *Cursor, name: []const u8, value: []const u8) Error!void {
        // write checked the handler's fields; the writer's own must pass the same checks.
        assert(isToken(name));
        assert(isValueValid(value));
        try self.append(name);
        try self.append(": ");
        try self.append(value);
        try self.append("\r\n");
    }

    fn appendDecimal(self: *Cursor, value: u32) Error!void {
        var digits: [decimal_digits_max]u8 = undefined;
        const text = formatDecimal(value, &digits);
        // Two ways of counting digits must agree.
        assert(text.len == decimalLength(value));
        assert(text.len == decimal_digits_max or value < std.math.pow(u64, 10, @intCast(text.len)));
        try self.append(text);
    }
};

/// Digits in the largest u32, 4294967295.
const decimal_digits_max: u32 = 10;

/// Writes `value` in decimal at the end of `digits` and returns the digits used.
fn formatDecimal(value: u32, digits: *[decimal_digits_max]u8) []const u8 {
    var rest: u32 = value;
    var start: u32 = decimal_digits_max;
    // One digit per pass; a u32 has at most ten, so the loop ends by then.
    while (start > 0) {
        start -= 1;
        digits[start] = '0' + @as(u8, @intCast(rest % 10));
        rest /= 10;
        if (rest == 0) break;
    }
    assert(rest == 0);
    // No leading zero, except for zero itself.
    assert(digits[start] != '0' or value == 0);
    return digits[start..];
}

/// Digits needed to write `value` in decimal.
fn decimalLength(value: u32) u32 {
    var rest: u32 = value / 10;
    var length: u32 = 1;
    while (rest > 0 and length < decimal_digits_max) : (length += 1) rest /= 10;
    assert(rest == 0);
    assert(length == 1 or value >= 10);
    return length;
}

/// Whether two slices share a byte. Empty slices share none.
fn overlaps(buffer: []const u8, other: []const u8) bool {
    if (buffer.len == 0 or other.len == 0) return false;
    const a_start = @intFromPtr(buffer.ptr);
    const b_start = @intFromPtr(other.ptr);
    // Slices of real memory never wrap the address space, so neither sum overflows.
    assert(a_start <= std.math.maxInt(usize) - buffer.len);
    assert(b_start <= std.math.maxInt(usize) - other.len);
    return a_start < b_start + other.len and b_start < a_start + buffer.len;
}

/// Fields the writer sets itself, and the other hop-by-hop fields (RFC 9110, section 7.6.1)
/// that would contradict the connection's framing. Upgrade comes back with the websocket
/// slice, through the writer rather than a handler's field.
const reserved_names = [_][]const u8{
    "content-length", "transfer-encoding", "connection", "keep-alive",
    "upgrade",        "te",                "trailer",    "proxy-connection",
};

const reserved_name_size_max: u32 = "transfer-encoding".len;

comptime {
    // Lowercase tokens, so a case-insensitive match finds them, within their stated limit.
    for (reserved_names) |reserved| {
        assert(isToken(reserved));
        assert(reserved.len <= reserved_name_size_max);
        for (reserved) |byte| assert(!std.ascii.isUpper(byte));
    }
}

fn isReserved(name: []const u8) bool {
    assert(isToken(name));
    const result = for (reserved_names) |reserved| {
        if (std.ascii.eqlIgnoreCase(name, reserved)) break true;
    } else false;
    assert(!result or name.len <= reserved_name_size_max);
    return result;
}

/// RFC 9110 token: one or more of the "tchar" characters. The request parser has its own
/// copy; both follow the same grammar, and both are tested against it.
fn isToken(text: []const u8) bool {
    assert(text.len <= size_max);
    if (text.len == 0) return false;
    for (text) |byte| {
        const tchar = switch (byte) {
            'a'...'z', 'A'...'Z', '0'...'9' => true,
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
            else => false,
        };
        if (!tchar) return false;
    }
    // Tokens never hold the bytes that end a header line or its name.
    assert(std.mem.findAny(u8, text, "\r\n: \t") == null);
    return true;
}

/// RFC 9110 field-value: tab, space, visible ASCII and obs-text (0x80 and up), with no
/// space or tab first or last; no CR, LF or other control byte.
fn isValueValid(text: []const u8) bool {
    assert(text.len <= size_max);
    if (text.len > 0) {
        const first = text[0];
        const last = text[text.len - 1];
        if (first == ' ' or first == '\t' or last == ' ' or last == '\t') return false;
    }
    for (text) |byte| {
        if (byte == 0x7f or (byte < 0x20 and byte != '\t')) return false;
    }
    assert(std.mem.findAny(u8, text, "\r\n") == null);
    return true;
}

// ---- Tests ----------------------------------------------------------------------------

const testing = std.testing;

test "http_response: a 200 with headers and a body, byte for byte" {
    var buffer: [256]u8 = undefined;
    const headers = [_]Header{
        .{ .name = "Content-Type", .value = "text/html; charset=utf-8" },
        .{ .name = "Cache-Control", .value = "no-store" },
    };
    const len = try write(&buffer, .{ .status = .ok, .headers = &headers, .body = "<p>hi</p>" });
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/html; charset=utf-8\r\n" ++
        "Cache-Control: no-store\r\n" ++
        "Content-Length: 9\r\n" ++
        "\r\n" ++
        "<p>hi</p>", buffer[0..len]);
}

test "http_response: an empty body still states its length, and close adds Connection" {
    var buffer: [128]u8 = undefined;
    const len = try write(&buffer, .{ .status = .bad_request, .close = true });
    try testing.expectEqualStrings(
        "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        buffer[0..len],
    );
}

test "http_response: every status writes its code and reason" {
    const cases = [_]struct { status: Status, line: []const u8 }{
        .{ .status = .ok, .line = "HTTP/1.1 200 OK\r\n" },
        .{ .status = .bad_request, .line = "HTTP/1.1 400 Bad Request\r\n" },
        .{ .status = .content_too_large, .line = "HTTP/1.1 413 Content Too Large\r\n" },
        .{
            .status = .request_header_fields_too_large,
            .line = "HTTP/1.1 431 Request Header Fields Too Large\r\n",
        },
        .{ .status = .not_implemented, .line = "HTTP/1.1 501 Not Implemented\r\n" },
        .{
            .status = .http_version_not_supported,
            .line = "HTTP/1.1 505 HTTP Version Not Supported\r\n",
        },
    };
    // One case per status, so a status added without a case fails here.
    try testing.expectEqual(@typeInfo(Status).@"enum".field_names.len, cases.len);
    for (cases) |case| {
        var buffer: [128]u8 = undefined;
        const len = try write(&buffer, .{ .status = case.status });
        try testing.expect(std.mem.startsWith(u8, buffer[0..len], case.line));
        try testing.expect(std.mem.endsWith(u8, buffer[0..len], "\r\nContent-Length: 0\r\n\r\n"));
    }
}

test "http_response: an exact fit is written, and every shorter buffer is refused" {
    const response: Response = .{
        .status = .ok,
        .headers = &.{.{ .name = "X-A", .value = "b" }},
        .body = "0123456789",
        .close = true,
    };
    var exact: [128]u8 = undefined;
    const len = try write(&exact, response);
    try testing.expect(len < exact.len);
    try testing.expectEqual(len, try write(exact[0..len], response));
    // Every shorter buffer ends inside the status line, a header, the length or the body.
    var short: u32 = 0;
    while (short < len) : (short += 1) {
        try testing.expectError(error.ResponseTooLarge, write(exact[0..short], response));
    }
}

test "http_response: Content-Length is the body's length across digit counts" {
    var body: [1000]u8 = undefined;
    @memset(&body, 'x');
    const cases = [_]struct { len: u32, field: []const u8 }{
        .{ .len = 1, .field = "Content-Length: 1\r\n" },
        .{ .len = 9, .field = "Content-Length: 9\r\n" },
        .{ .len = 10, .field = "Content-Length: 10\r\n" },
        .{ .len = 99, .field = "Content-Length: 99\r\n" },
        .{ .len = 100, .field = "Content-Length: 100\r\n" },
        .{ .len = 1000, .field = "Content-Length: 1000\r\n" },
    };
    for (cases) |case| {
        var buffer: [1100]u8 = undefined;
        const len = try write(&buffer, .{ .status = .ok, .body = body[0..case.len] });
        try testing.expect(std.mem.find(u8, buffer[0..len], case.field) != null);
        try testing.expect(std.mem.endsWith(u8, buffer[0..len], body[0..case.len]));
    }
}

test "http_response: decimal digits match for edge values" {
    const cases = [_]struct { value: u32, text: []const u8 }{
        .{ .value = 0, .text = "0" },
        .{ .value = 7, .text = "7" },
        .{ .value = 10, .text = "10" },
        .{ .value = size_max, .text = "1048576" },
        .{ .value = std.math.maxInt(u32), .text = "4294967295" },
    };
    for (cases) |case| {
        var digits: [decimal_digits_max]u8 = undefined;
        try testing.expectEqualStrings(case.text, formatDecimal(case.value, &digits));
        try testing.expectEqual(@as(u32, @intCast(case.text.len)), decimalLength(case.value));
    }
}

var full_buffer: [size_max]u8 = undefined;
var full_body: [size_max + 1]u8 = undefined;

test "http_response: a response filling a whole response buffer fits, one more byte doesn't" {
    const head = "HTTP/1.1 200 OK\r\nContent-Length: 1048532\r\n\r\n";
    const body_len: u32 = size_max - head.len;
    try testing.expectEqual(@as(u32, 1048532), body_len);
    @memset(&full_body, 'y');
    const len = try write(&full_buffer, .{ .status = .ok, .body = full_body[0..body_len] });
    try testing.expectEqual(size_max, len);
    try testing.expectEqualStrings(head, full_buffer[0..head.len]);
    try testing.expectError(
        error.ResponseTooLarge,
        write(&full_buffer, .{ .status = .ok, .body = full_body[0 .. body_len + 1] }),
    );
    // A body longer than the whole buffer is refused before anything is written.
    full_buffer[0] = 0xaa;
    try testing.expectError(error.ResponseTooLarge, write(&full_buffer, .{ .status = .ok, .body = &full_body }));
    try testing.expectEqual(@as(u8, 0xaa), full_buffer[0]);
}

test "http_response: a body longer than a small buffer is refused before any write" {
    var buffer: [8]u8 = @splat(0xaa);
    try testing.expectError(error.ResponseTooLarge, write(&buffer, .{ .status = .ok, .body = "123456789" }));
    try testing.expectEqualSlices(u8, &@as([8]u8, @splat(0xaa)), &buffer);
}

test "http_response: omit_body states the body's length but leaves the body out" {
    var buffer: [128]u8 = undefined;
    const len = try write(&buffer, .{ .status = .ok, .body = "<p>hello</p>", .omit_body = true });
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n", buffer[0..len]);
    // The body only needs to fit when it is sent: a HEAD answer fits where the GET doesn't.
    var small: [48]u8 = undefined;
    try testing.expectError(error.ResponseTooLarge, write(&small, .{ .status = .ok, .body = full_body[0..1000] }));
    const head_len = try write(&small, .{ .status = .ok, .body = full_body[0..1000], .omit_body = true });
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n", small[0..head_len]);
}

test "http_response: overlaps finds shared bytes and only shared bytes" {
    const bytes: [16]u8 = @splat(0);
    try testing.expect(!overlaps(bytes[0..4], bytes[4..8]));
    try testing.expect(!overlaps(bytes[4..8], bytes[0..4]));
    try testing.expect(overlaps(bytes[0..5], bytes[4..8]));
    try testing.expect(overlaps(bytes[4..8], bytes[0..5]));
    try testing.expect(overlaps(bytes[0..16], bytes[6..7]));
    try testing.expect(overlaps(bytes[6..7], bytes[0..16]));
    try testing.expect(overlaps(bytes[2..9], bytes[2..9]));
    try testing.expect(!overlaps(bytes[0..0], bytes[0..16]));
    try testing.expect(!overlaps(bytes[0..16], bytes[3..3]));
}

test "http_response: bad header fields each have their own error" {
    const cases = [_]struct { field: Header, expected: Error }{
        .{ .field = .{ .name = "", .value = "v" }, .expected = error.HeaderNameInvalid },
        .{ .field = .{ .name = "Bad Name", .value = "v" }, .expected = error.HeaderNameInvalid },
        .{ .field = .{ .name = "Name:", .value = "v" }, .expected = error.HeaderNameInvalid },
        .{ .field = .{ .name = "X\r\nY", .value = "v" }, .expected = error.HeaderNameInvalid },
        .{ .field = .{ .name = "X\"A", .value = "v" }, .expected = error.HeaderNameInvalid },
        .{ .field = .{ .name = "X(A)", .value = "v" }, .expected = error.HeaderNameInvalid },
        .{ .field = .{ .name = "X@A", .value = "v" }, .expected = error.HeaderNameInvalid },
        .{ .field = .{ .name = "X/A", .value = "v" }, .expected = error.HeaderNameInvalid },
        .{ .field = .{ .name = "X\x80", .value = "v" }, .expected = error.HeaderNameInvalid },
        .{ .field = .{ .name = "X-A", .value = "a\x1fb" }, .expected = error.HeaderValueInvalid },
        .{ .field = .{ .name = "X-A", .value = "a\x0eb" }, .expected = error.HeaderValueInvalid },
        .{ .field = .{ .name = "X-A", .value = " a" }, .expected = error.HeaderValueInvalid },
        .{ .field = .{ .name = "X-A", .value = "a\t" }, .expected = error.HeaderValueInvalid },
        .{ .field = .{ .name = "X-A", .value = " " }, .expected = error.HeaderValueInvalid },
        .{ .field = .{ .name = "X-A", .value = "a\r\nSet-Cookie: s=1" }, .expected = error.HeaderValueInvalid },
        .{ .field = .{ .name = "X-A", .value = "a\nb" }, .expected = error.HeaderValueInvalid },
        .{ .field = .{ .name = "X-A", .value = "a\rb" }, .expected = error.HeaderValueInvalid },
        .{ .field = .{ .name = "X-A", .value = "a\x00b" }, .expected = error.HeaderValueInvalid },
        .{ .field = .{ .name = "X-A", .value = "a\x7fb" }, .expected = error.HeaderValueInvalid },
        .{ .field = .{ .name = "Content-Length", .value = "5" }, .expected = error.HeaderReserved },
        .{ .field = .{ .name = "content-length", .value = "5" }, .expected = error.HeaderReserved },
        .{ .field = .{ .name = "Transfer-Encoding", .value = "chunked" }, .expected = error.HeaderReserved },
        .{ .field = .{ .name = "CONNECTION", .value = "keep-alive" }, .expected = error.HeaderReserved },
        .{ .field = .{ .name = "Keep-Alive", .value = "timeout=5" }, .expected = error.HeaderReserved },
        .{ .field = .{ .name = "Upgrade", .value = "websocket" }, .expected = error.HeaderReserved },
        .{ .field = .{ .name = "TE", .value = "trailers" }, .expected = error.HeaderReserved },
        .{ .field = .{ .name = "Trailer", .value = "X" }, .expected = error.HeaderReserved },
        .{ .field = .{ .name = "Proxy-Connection", .value = "close" }, .expected = error.HeaderReserved },
    };
    for (cases) |case| {
        // A large buffer, so the error comes from the field and not from the room left.
        var buffer: [256]u8 = undefined;
        const headers = [_]Header{case.field};
        try testing.expectError(case.expected, write(&buffer, .{ .status = .ok, .headers = &headers }));
        // The field is checked first, so even an empty buffer reports it.
        try testing.expectError(case.expected, write(buffer[0..0], .{ .status = .ok, .headers = &headers }));
    }
}

test "http_response: values may hold tabs, spaces and obs-text; names may hold any tchar" {
    var buffer: [256]u8 = undefined;
    const headers = [_]Header{
        .{ .name = "X-Tchars!#$%&'*+-.^_`|~09az", .value = "a\tb c \xe2\x9c\x93" },
        .{ .name = "X-Empty", .value = "" },
        .{ .name = "Connection-Id", .value = "7" },
    };
    const len = try write(&buffer, .{ .status = .ok, .headers = &headers });
    try testing.expect(std.mem.find(u8, buffer[0..len], "X-Tchars!#$%&'*+-.^_`|~09az: a\tb c \xe2\x9c\x93\r\n") != null);
    try testing.expect(std.mem.find(u8, buffer[0..len], "\r\nX-Empty: \r\n") != null);
    try testing.expect(std.mem.find(u8, buffer[0..len], "\r\nConnection-Id: 7\r\n") != null);
}

test "http_response: a header field longer than any response is an error, not a crash" {
    var buffer: [64]u8 = undefined;
    // Longer than any response buffer, so the field checks would assert on it.
    @memset(&full_body, 'y');
    const long: []const u8 = &full_body;
    try testing.expectError(
        error.ResponseTooLarge,
        write(&buffer, .{ .status = .ok, .headers = &.{.{ .name = "X-A", .value = long }} }),
    );
}

test "http_response: header count at and past http_response_headers_max" {
    var fields: [headers_max + 1]Header = undefined;
    @memset(&fields, .{ .name = "X-A", .value = "b" });
    var buffer: [headers_max * 16 + 128]u8 = undefined;
    const len = try write(&buffer, .{ .status = .ok, .headers = fields[0..headers_max] });
    try testing.expectEqual(@as(usize, headers_max), std.mem.count(u8, buffer[0..len], "X-A: b\r\n"));
    try testing.expectError(error.HeadersTooMany, write(&buffer, .{ .status = .ok, .headers = &fields }));
}

test "http_response: every parser error maps to its status" {
    const cases = [_]struct { err: http_request.Error, status: ?Status }{
        .{ .err = error.Incomplete, .status = null },
        .{ .err = error.HeadTooLarge, .status = .request_header_fields_too_large },
        .{ .err = error.HeadersTooMany, .status = .request_header_fields_too_large },
        .{ .err = error.ContentTooLarge, .status = .content_too_large },
        .{ .err = error.MethodUnsupported, .status = .not_implemented },
        .{ .err = error.TransferEncodingUnsupported, .status = .not_implemented },
        .{ .err = error.VersionUnsupported, .status = .http_version_not_supported },
        .{ .err = error.RequestLineInvalid, .status = .bad_request },
        .{ .err = error.MethodInvalid, .status = .bad_request },
        .{ .err = error.TargetInvalid, .status = .bad_request },
        .{ .err = error.VersionInvalid, .status = .bad_request },
        .{ .err = error.HeaderLineInvalid, .status = .bad_request },
        .{ .err = error.HeaderNameInvalid, .status = .bad_request },
        .{ .err = error.HeaderValueInvalid, .status = .bad_request },
        .{ .err = error.HostMissing, .status = .bad_request },
        .{ .err = error.HostDuplicate, .status = .bad_request },
        .{ .err = error.ContentLengthInvalid, .status = .bad_request },
        .{ .err = error.ContentLengthDuplicate, .status = .bad_request },
        .{ .err = error.RealIpDuplicate, .status = .bad_request },
    };
    // One distinct case per parser error, so an error added without a case fails here.
    try testing.expectEqual(@typeInfo(http_request.Error).error_set.error_names.?.len, cases.len);
    for (cases, 0..) |a, i| {
        for (cases[i + 1 ..]) |b| try testing.expect(a.err != b.err);
    }
    for (cases) |case| {
        try testing.expectEqual(case.status, statusForParseError(case.err));
        const response = forParseError(case.err);
        try testing.expectEqual(case.status == null, response == null);
        if (response) |r| {
            try testing.expectEqual(case.status.?, r.status);
            try testing.expect(r.close);
            try testing.expectEqual(@as(usize, 0), r.body.len);
            try testing.expectEqual(@as(usize, 0), r.headers.len);
        }
    }
}

/// One header more than the parser takes: Host plus `http_headers_max` more.
const request_with_too_many_headers = text: {
    var text: []const u8 = "GET / HTTP/1.1\r\nHost: a\r\n";
    for (0..constants.http_headers_max) |_| text = text ++ "X: y\r\n";
    break :text text ++ "\r\n";
};

test "http_response: refused requests from the parser become complete responses" {
    const cases = [_]struct { request: []const u8, response: []const u8 }{
        .{
            .request = "GET / HTTP/2.0\r\nHost: a\r\n\r\n",
            .response = "HTTP/1.1 505 HTTP Version Not Supported\r\n",
        },
        .{
            .request = "BREW / HTTP/1.1\r\nHost: a\r\n\r\n",
            .response = "HTTP/1.1 501 Not Implemented\r\n",
        },
        .{
            .request = "GET / HTTP/1.1\r\n\r\n",
            .response = "HTTP/1.1 400 Bad Request\r\n",
        },
        .{
            .request = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 999999\r\n\r\n",
            .response = "HTTP/1.1 413 Content Too Large\r\n",
        },
        .{
            .request = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
            .response = "HTTP/1.1 400 Bad Request\r\n",
        },
        .{
            .request = request_with_too_many_headers,
            .response = "HTTP/1.1 431 Request Header Fields Too Large\r\n",
        },
    };
    for (cases) |case| {
        var scan: http_request.HeadScan = .{};
        const err = if (http_request.parse(case.request, &scan)) |_| return error.TestUnexpectedResult else |e| e;
        const response = forParseError(err) orelse return error.TestUnexpectedResult;
        var buffer: [128]u8 = undefined;
        const len = try write(&buffer, response);
        const tail = "Connection: close\r\nContent-Length: 0\r\n\r\n";
        try testing.expectEqual(case.response.len + tail.len, len);
        try testing.expect(std.mem.startsWith(u8, buffer[0..len], case.response));
        try testing.expect(std.mem.endsWith(u8, buffer[0..len], tail));
    }
}
