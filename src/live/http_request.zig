//! HTTP/1.1 request parser (roadmap slice core 5).
//!
//! Job: parse the request line and header fields of one request from a caller-owned buffer.
//! Never allocates and never copies: every slice in the returned `Request` points into the
//! caller's buffer, so the buffer must outlive the `Request`.
//!
//! Inputs: the bytes received so far on one connection, at most `http_request_size_max`, and
//! that connection's `HeadScan`, which remembers how far the search for the end of the head
//! got. A client that sends one byte at a time therefore costs linear work, not quadratic.
//! Outputs: a `Request`, `error.Incomplete` when the head has not fully arrived yet (read
//! more and parse again with the same `HeadScan`), or a named error for each kind of bad
//! input so the caller can choose the response status.
//! Limits: `http_request_size_max` (head plus body) and `http_headers_max`.
//!
//! Strict by design. The server sits behind a proxy, and a lenient parser that disagrees
//! with the proxy about where a request ends invites request smuggling. So lines end in
//! CRLF only, obsolete line folding is refused, a header name must touch its colon, there
//! is at most one Content-Length, and Transfer-Encoding is refused: request bodies are small
//! forms, so chunked uploads are not needed.
//!
//! There is also at most one X-Real-IP. The proxy replaces any copy the client sent with
//! its own, so two copies mean the request did not come through the proxy as expected; it
//! is refused rather than guessing which one to believe. Whether a single copy is trusted
//! at all is decided later, by where the connection came from, not here.

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
    // parseContentLength rejects `result > size_max` before each `result * 10 + digit`,
    // so its largest intermediate value is `size_max * 10 + 9`, which must fit a u32.
    assert(size_max <= (std.math.maxInt(u32) - 9) / 10);
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
    /// The buffer is full and the head has not ended: the head alone is longer than
    /// `http_request_size_max` (431 Request Header Fields Too Large).
    HeadTooLarge,
    /// The head ended, but head plus Content-Length is longer than `http_request_size_max`,
    /// or Content-Length alone is (413 Content Too Large).
    ContentTooLarge,
    /// Not "method SP target SP version", or the line is empty.
    RequestLineInvalid,
    /// The method is empty or has a character that is not allowed in a token.
    MethodInvalid,
    /// A well-formed method the server does not answer (501).
    MethodUnsupported,
    /// Not origin form ("*" only for OPTIONS), a byte outside visible ASCII or a '#', or a
    /// path nginx would rewrite before matching it (see `isPathNormal`).
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
    /// More than one X-Real-IP field. See the file comment.
    RealIpDuplicate,
    /// Transfer-Encoding is present (501). See the file comment.
    TransferEncodingUnsupported,
};

/// Where the search for the end of the head resumes. Keep one per connection, starting at
/// `.{}`, and pass it to every `parse` of that connection's buffer. Only `error.Incomplete`
/// leaves it partway through the buffer; every other answer resets it to `.{}`, so the next
/// request starts over. Between calls that return `error.Incomplete` the buffer may only
/// grow: the bytes already scanned must not change. Whoever empties, compacts or reuses the
/// buffer for another connection without a final answer (a disconnect, say) sets the scan
/// back to `.{}` too.
pub const HeadScan = struct {
    /// Every CRLF CRLF that starts before this index has been ruled out.
    resume_at: u32 = 0,
};

/// Parses one request head from `buffer`, which holds the bytes received so far, resuming
/// the search for its end where `scan` left off. Call it after each read until it returns a
/// `Request` or an error other than `error.Incomplete`, then not again for that request:
/// the body is complete once the buffer holds `head_len + content_length` bytes. Calling it
/// again would parse the whole head again on every read.
pub fn parse(buffer: []const u8, scan: *HeadScan) Error!Request {
    assert(buffer.len <= size_max);
    // The buffer only grows between calls, so the scan never resumes past its end.
    assert(scan.resume_at <= buffer.len -| 3);
    const buffer_len: u32 = @intCast(buffer.len);
    const head_len = findHeadEnd(buffer, scan.resume_at) orelse {
        if (buffer_len == size_max) {
            // A full buffer with no end of head is a final answer, like any other error.
            scan.* = .{};
            return error.HeadTooLarge;
        }
        // Back off three bytes, so a CRLF CRLF split across reads is still found.
        scan.resume_at = buffer_len -| 3;
        return error.Incomplete;
    };
    scan.* = .{};
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

/// Index just past the first CRLF CRLF that starts at or after `start`, or null if there is
/// none yet. The caller has ruled out every CRLF CRLF that starts before `start`.
fn findHeadEnd(buffer: []const u8, start: u32) ?u32 {
    assert(buffer.len <= size_max);
    assert(start <= buffer.len -| 3);
    const len: u32 = @intCast(buffer.len);
    if (len < 4) return null;
    var index: u32 = start;
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

/// Origin form only, since the server sits behind a proxy; "*" only for OPTIONS. No '#'
/// anywhere: a fragment is never part of a request target (RFC 9112, section 3.2), and nginx
/// ends the path at one. The path, the part before any '?', must be one nginx leaves as it
/// is (see `isPathNormal`). The rest of the query isn't checked: nginx doesn't normalize it,
/// and the router never matches on it.
fn isTargetValid(target: []const u8, method: Method) bool {
    assert(target.len < size_max);
    if (target.len == 0) return false;
    if (target.len == 1 and target[0] == '*') return method == .options;
    if (target[0] != '/') return false;
    for (target) |byte| {
        // Visible ASCII only; anything else must arrive percent-encoded.
        if (byte < 0x21 or byte > 0x7e or byte == '#') return false;
    }
    const path_len = findByte(target, 0, '?') orelse @as(u32, @intCast(target.len));
    // The path ends at the first '?' or at the end of the target.
    assert(path_len == target.len or target[path_len] == '?');
    assert(findByte(target[0..path_len], 0, '?') == null);
    return isPathNormal(target[0..path_len]);
}

/// Whether nginx would match its location rules against `path` exactly as it is, so nginx
/// and the router agree on which path was asked for. Before it matches, nginx merges "//",
/// resolves "." and ".." segments and decodes every percent-escape; the server does none of
/// that, so it refuses every path one of those would change: an empty segment ("//"), a "."
/// or ".." segment, and any '%'. A backslash is refused too, as a path separator on some
/// systems. A trailing slash ("/a/") is an ordinary path. Escapes in the query are fine.
fn isPathNormal(path: []const u8) bool {
    assert(path.len >= 1 and path.len < size_max);
    assert(path[0] == '/');
    const len: u32 = @intCast(path.len);
    var segment_start: u32 = 1;
    var index: u32 = 1;
    while (index < len) : (index += 1) {
        switch (path[index]) {
            '/' => {
                const segment = path[segment_start..index];
                if (segment.len == 0 or isDotSegment(segment)) return false;
                segment_start = index + 1;
            },
            '%', '\\' => return false,
            else => {},
        }
    }
    assert(index == len);
    if (isDotSegment(path[segment_start..])) return false;
    // Each '/' after the first closed a non-empty segment, so none follows another.
    assert(std.mem.find(u8, path, "//") == null);
    return true;
}

fn isDotSegment(segment: []const u8) bool {
    assert(segment.len < size_max);
    // The caller splits at every '/', so a segment never holds one.
    assert(findByte(segment, 0, '/') == null);
    return equalBytes(segment, ".") or equalBytes(segment, "..");
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

/// Checks the headers that decide where the request ends, and that Host, Content-Length
/// and X-Real-IP each appear at most once, so `Request.header` returns the only copy of
/// each. Returns the body length.
fn checkFraming(request: *const Request) Error!u32 {
    assert(request.header_count <= headers_max);
    assert(request.head_len <= size_max);
    var host_count: u32 = 0;
    var real_ip_count: u32 = 0;
    var content_length: ?u32 = null;
    for (request.headers[0..request.header_count]) |field| {
        if (equalIgnoreCase(field.name, "host")) {
            host_count += 1;
        } else if (equalIgnoreCase(field.name, "x-real-ip")) {
            real_ip_count += 1;
        } else if (equalIgnoreCase(field.name, "transfer-encoding")) {
            return error.TransferEncodingUnsupported;
        } else if (equalIgnoreCase(field.name, "content-length")) {
            if (content_length != null) return error.ContentLengthDuplicate;
            content_length = try parseContentLength(field.value);
        }
    }
    if (host_count > 1) return error.HostDuplicate;
    if (host_count == 0 and request.version == .http_1_1) return error.HostMissing;
    if (real_ip_count > 1) return error.RealIpDuplicate;

    const body_len = content_length orelse 0;
    // Both terms are at most size_max, so the sum cannot overflow a u32.
    if (request.head_len + body_len > size_max) return error.ContentTooLarge;
    // Each field adds to at most one count, so the counts can't pass the field count.
    assert(host_count + real_ip_count <= request.header_count);
    return body_len;
}

fn parseContentLength(value: []const u8) Error!u32 {
    assert(value.len < size_max);
    if (value.len == 0) return error.ContentLengthInvalid;
    var result: u32 = 0;
    for (value) |byte| {
        if (!isDigit(byte)) return error.ContentLengthInvalid;
        // Once past size_max the value only grows, so stop multiplying but keep checking
        // that every byte is a digit: "1000000x" is malformed (400), not too large (413).
        // Checked before each step, so result stays at most 10 * size_max + 9, which the
        // comptime block at the top of this file proves fits a u32.
        if (result <= size_max) result = result * 10 + (byte - '0');
        assert(result <= size_max * 10 + 9);
    }
    if (result > size_max) return error.ContentTooLarge;
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

/// Test helper: parses `text` as if it arrived in one read. Only an incomplete head leaves
/// the scan partway through, three bytes before the end; every other answer resets it.
fn parseWhole(text: []const u8) !Request {
    assert(text.len <= size_max);
    var scan: HeadScan = .{};
    const result = parse(text, &scan);
    assert(scan.resume_at <= text.len);
    const incomplete = if (result) |_| false else |err| err == error.Incomplete;
    const expected: u32 = if (incomplete) @intCast(text.len -| 3) else 0;
    try testing.expectEqual(expected, scan.resume_at);
    const head_found = std.mem.find(u8, text, "\r\n\r\n") != null;
    try testing.expect(head_found or std.meta.isError(result));
    return result;
}

/// Test helper: fails unless `a` and `b` are the same error, or requests with the same
/// fields pointing at the same bytes.
fn expectSameResult(a: anyerror!Request, b: anyerror!Request) !void {
    const left = a catch |err_a| {
        try testing.expectError(err_a, b);
        return;
    };
    const right = try b;
    assert(left.header_count <= headers_max);
    assert(right.header_count <= headers_max);
    try testing.expectEqual(left.method, right.method);
    try testing.expectEqual(left.version, right.version);
    try testing.expectEqual(left.target.ptr, right.target.ptr);
    try testing.expectEqual(left.target.len, right.target.len);
    try testing.expectEqual(left.head_len, right.head_len);
    try testing.expectEqual(left.content_length, right.content_length);
    try testing.expectEqual(left.header_count, right.header_count);
    for (left.headers[0..left.header_count], right.headers[0..right.header_count]) |x, y| {
        try testing.expectEqual(x.name.ptr, y.name.ptr);
        try testing.expectEqual(x.name.len, y.name.len);
        try testing.expectEqual(x.value.ptr, y.value.ptr);
        try testing.expectEqual(x.value.len, y.value.len);
    }
}

/// Test helper: feeds `text` one byte at a time through one `HeadScan`, as a slow client
/// would send it, and checks the answer matches parsing it in one read.
fn expectSameWhenSplit(text: []const u8) !void {
    assert(text.len <= size_max);
    var scan: HeadScan = .{};
    var len: u32 = 0;
    var result: Error!Request = error.Incomplete;
    // The empty buffer is one call too, so a client that sends nothing yet is covered.
    while (len <= text.len) : (len += 1) {
        result = parse(text[0..len], &scan);
        if (result) |_| break else |err| if (err != error.Incomplete) break;
        // Each incomplete read leaves the scan three bytes short of the end, never further back.
        try testing.expectEqual(len -| 3, scan.resume_at);
    }
    // The loop stops at a final answer or after the read that held every byte.
    assert(len <= text.len + 1);
    // Any final answer resets the scan for the next request.
    const final = if (result) |_| true else |err| err != error.Incomplete;
    // An incomplete text ran the loop to its end, whose last read held every byte.
    const expected: u32 = if (final) 0 else @intCast(text.len -| 3);
    try testing.expectEqual(expected, scan.resume_at);
    try expectSameResult(parseWhole(text), result);
}

test "http_request: a simple GET" {
    const request = try parseWhole("GET /index.html?tab=alts HTTP/1.1\r\nHost: example.test\r\n\r\n");
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
    const request = try parseWhole(text);
    try testing.expectEqual(Method.post, request.method);
    try testing.expectEqual(@as(u32, 7), request.content_length);
    try testing.expectEqualStrings("name=ok", text[request.head_len..]);
}

test "http_request: header lookup ignores case and values are trimmed" {
    const request = try parseWhole("GET / HTTP/1.1\r\nhOsT:  a  \r\nX-Empty:\r\nCookie:\tk=v\t\r\n\r\n");
    try testing.expectEqualStrings("a", request.header("Host").?);
    try testing.expectEqualStrings("", request.header("x-empty").?);
    try testing.expectEqualStrings("k=v", request.header("COOKIE").?);
    try testing.expect(request.header("Missing") == null);
}

test "http_request: one X-Real-IP is read, and only that name, in any case, counts" {
    const one = "GET / HTTP/1.1\r\nHost: a\r\nx-real-ip:  192.0.2.7 \r\n\r\n";
    try expectSameWhenSplit(one);
    const request = try parseWhole(one);
    try testing.expectEqualStrings("192.0.2.7", request.header("X-Real-IP").?);

    // Fields whose names only start or end like X-Real-IP are other fields.
    const lookalikes = "GET / HTTP/1.1\r\nHost: a\r\nX-Real-IP: 192.0.2.7\r\n" ++
        "X-Real-IP-Chain: 192.0.2.8\r\nX-X-Real-IP: 192.0.2.9\r\n\r\n";
    try expectSameWhenSplit(lookalikes);
    const other = try parseWhole(lookalikes);
    try testing.expectEqual(@as(u32, 4), other.header_count);
    try testing.expectEqualStrings("192.0.2.7", other.header("X-Real-IP").?);
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
        try expectSameWhenSplit(case.text);
        const request = try parseWhole(case.text);
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
        try testing.expectError(error.Incomplete, parseWhole(text));
        try expectSameWhenSplit(text);
    }
}

test "http_request: each bad input has its own error" {
    const real_ip_twice = "GET / HTTP/1.1\r\nHost: a\r\nX-Real-IP: 192.0.2.1\r\nX-Real-IP: 192.0.2.2\r\n";
    // A Content-Length that parses but can't fit after any head: the size refusal comes last.
    const size_max_text = std.fmt.comptimePrint("{d}", .{size_max});
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
        .{ .text = real_ip_twice ++ "\r\n", .err = error.RealIpDuplicate },
        .{
            .text = "GET / HTTP/1.1\r\nx-real-ip: 192.0.2.1\r\nHost: a\r\nX-REAL-IP: 192.0.2.1\r\n\r\n",
            .err = error.RealIpDuplicate,
        },
        .{ .text = "GET / HTTP/1.0\r\nX-Real-IP: 192.0.2.1\r\nX-Real-IP:\r\n\r\n", .err = error.RealIpDuplicate },
        // Which refusal wins when a second X-Real-IP comes with another fault.
        .{ .text = "GET / HTTP/1.1\r\nX-Real-IP: 192.0.2.1\r\nX-Real-IP: 192.0.2.2\r\n\r\n", .err = error.HostMissing },
        .{ .text = real_ip_twice ++ "Transfer-Encoding: chunked\r\n\r\n", .err = error.TransferEncodingUnsupported },
        .{ .text = real_ip_twice ++ "Content-Length: " ++ size_max_text ++ "\r\n\r\n", .err = error.RealIpDuplicate },
        .{ .text = "GET / HTTP/1.1\r\nHost: a\r\nContent-Length:\r\n\r\n", .err = error.ContentLengthInvalid },
        .{ .text = "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: +1\r\n\r\n", .err = error.ContentLengthInvalid },
        .{ .text = "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1, 1\r\n\r\n", .err = error.ContentLengthInvalid },
        .{ .text = "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n", .err = error.ContentLengthDuplicate },
        .{ .text = "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999\r\n\r\n", .err = error.ContentTooLarge },
        .{ .text = "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999x\r\n\r\n", .err = error.ContentLengthInvalid },
        .{ .text = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n", .err = error.TransferEncodingUnsupported },
    };
    for (cases) |case| {
        expectSameWhenSplit(case.text) catch |err| {
            std.debug.print("failing split case: {s}\n", .{case.text});
            return err;
        };
        testing.expectError(case.err, parseWhole(case.text)) catch |err| {
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

/// A GET for `target`, as a whole head.
fn targetRequest(comptime target: []const u8) []const u8 {
    return "GET " ++ target ++ " HTTP/1.1\r\nHost: a\r\n\r\n";
}

test "http_request: paths nginx would rewrite are refused" {
    const targets = [_][]const u8{
        // Empty segments, which nginx merges.
        targetRequest("//"),
        targetRequest("//a"),
        targetRequest("/a//b"),
        targetRequest("/a//"),
        // Dot segments, which nginx resolves, inside the path and at its end.
        targetRequest("/./a"),
        targetRequest("/a/./b"),
        targetRequest("/../a"),
        targetRequest("/a/../b"),
        targetRequest("/."),
        targetRequest("/.."),
        targetRequest("/a/."),
        targetRequest("/a/.."),
        targetRequest("/..?q=1"),
        // Escapes, which nginx decodes, and a raw backslash.
        targetRequest("/%2e"),
        targetRequest("/%2E%2E/a"),
        targetRequest("/a%2fb"),
        targetRequest("/a%5Cb"),
        targetRequest("/a%00"),
        targetRequest("/%61dmin"),
        targetRequest("/a%20b"),
        targetRequest("/%"),
        targetRequest("/a%2?q"),
        targetRequest("/a\\b"),
        // A fragment, which nginx cuts off the path, in the path or the query.
        targetRequest("/#"),
        targetRequest("/a#b"),
        targetRequest("/a/.#"),
        targetRequest("/?q#f"),
    };
    for (targets) |text| {
        try testing.expectError(error.TargetInvalid, parseWhole(text));
        try expectSameWhenSplit(text);
    }
}

test "http_request: ordinary paths and queries still parse" {
    const cases = [_]struct { text: []const u8, target: []const u8 }{
        .{ .text = targetRequest("/"), .target = "/" },
        .{ .text = targetRequest("/a/b/"), .target = "/a/b/" },
        .{ .text = targetRequest("/.well-known/x"), .target = "/.well-known/x" },
        .{ .text = targetRequest("/a.b/..c/.../d."), .target = "/a.b/..c/.../d." },
        // The query is the client's own business: nginx passes it through unchanged.
        .{ .text = targetRequest("/?next=//a/../b"), .target = "/?next=//a/../b" },
        .{ .text = targetRequest("/sso?state=%2F%2e%00%5c%"), .target = "/sso?state=%2F%2e%00%5c%" },
        .{ .text = targetRequest("/a?"), .target = "/a?" },
        .{ .text = "OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n", .target = "*" },
    };
    for (cases) |case| {
        try expectSameWhenSplit(case.text);
        const request = try parseWhole(case.text);
        try testing.expectEqualStrings(case.target, request.target);
    }
}

test "http_request: every escape is refused in the path and accepted in the query" {
    const in_path = comptime targetRequest("/%00");
    const in_query = comptime targetRequest("/?%00");
    const digits = "0123456789abcdef";
    var value: u32 = 0;
    while (value <= 0xff) : (value += 1) {
        var path_text: [in_path.len]u8 = in_path[0..in_path.len].*;
        path_text["GET /%".len] = digits[value >> 4];
        path_text["GET /%".len + 1] = digits[value & 0xf];
        try testing.expectError(error.TargetInvalid, parseWhole(&path_text));
        var query_text: [in_query.len]u8 = in_query[0..in_query.len].*;
        query_text["GET /?%".len] = digits[value >> 4];
        query_text["GET /?%".len + 1] = digits[value & 0xf];
        const request = try parseWhole(&query_text);
        try testing.expectEqualStrings(query_text["GET ".len..][0.."/?%00".len], request.target);
    }
    try testing.expectEqual(@as(u32, 0x100), value);
}

test "http_request: header count at and past http_headers_max" {
    var buffer: [size_max]u8 = undefined;
    var count: u32 = 0;
    while (count <= headers_max) : (count += 1) {
        const request = try parseWhole(buildHead(&buffer, count));
        try testing.expectEqual(count, request.header_count);
    }
    try testing.expectError(error.HeadersTooMany, parseWhole(buildHead(&buffer, headers_max + 1)));
}

test "http_request: size limits on the head and on head plus body" {
    const buffer: [size_max]u8 = @splat('a');
    // A full buffer with no end of head can never become a request.
    try testing.expectError(error.HeadTooLarge, parseWhole(&buffer));
    try testing.expectError(error.Incomplete, parseWhole(buffer[0 .. size_max - 1]));

    const head = "POST / HTTP/1.0\r\nContent-Length: ";
    var text: [64]u8 = undefined;
    @memcpy(text[0..head.len], head);
    const body_fits = size_max - (head.len + 5 + 4);
    const fits = try std.fmt.bufPrint(text[head.len..], "{d:0>5}\r\n\r\n", .{body_fits});
    const fit_request = try parseWhole(text[0 .. head.len + fits.len]);
    try testing.expectEqual(@as(u32, size_max), fit_request.head_len + fit_request.content_length);
    const over = try std.fmt.bufPrint(text[head.len..], "{d:0>5}\r\n\r\n", .{body_fits + 1});
    try testing.expectError(error.ContentTooLarge, parseWhole(text[0 .. head.len + over.len]));
}

/// Test helper: a head of exactly `size_max` bytes, padded by one header value, whose
/// Content-Length is the single digit `body_digit`. The buffer is full and the head ends.
fn buildFullHead(buffer: *[size_max]u8, body_digit: u8) []const u8 {
    assert(body_digit >= '0');
    assert(body_digit <= '9');
    const prefix = "POST / HTTP/1.0\r\nContent-Length: ";
    const middle = "\r\nX-Pad: ";
    const end = "\r\n\r\n";
    const fixed = prefix.len + 1 + middle.len + end.len;
    comptime assert(fixed < size_max);
    @memcpy(buffer[0..prefix.len], prefix);
    buffer[prefix.len] = body_digit;
    @memcpy(buffer[prefix.len + 1 ..][0..middle.len], middle);
    @memset(buffer[prefix.len + 1 + middle.len ..][0 .. size_max - fixed], 'a');
    @memcpy(buffer[size_max - end.len ..], end);
    assert(findHeadEnd(buffer, 0) == size_max);
    return buffer;
}

test "http_request: a full buffer whose head ends is never a head too large" {
    var buffer: [size_max]u8 = undefined;
    // The head fills the buffer exactly and has no body: a request.
    const exact = try parseWhole(buildFullHead(&buffer, '0'));
    try testing.expectEqual(@as(u32, size_max), exact.head_len);
    try testing.expectEqual(@as(u32, 0), exact.content_length);
    // The same head with a one-byte body: the head itself fit, so 413, not 431.
    try testing.expectError(error.ContentTooLarge, parseWhole(buildFullHead(&buffer, '1')));
    // The same head with the last byte of its terminator replaced never ends: 431.
    _ = buildFullHead(&buffer, '0');
    buffer[size_max - 1] = 'a';
    try testing.expectError(error.HeadTooLarge, parseWhole(&buffer));
}

test "http_request: Content-Length accepts size_max, refuses past it, and never overflows" {
    var text: [32]u8 = undefined;
    const at = try std.fmt.bufPrint(&text, "{d}", .{size_max});
    try testing.expectEqual(@as(u32, size_max), try parseContentLength(at));
    const leading_zeros = try std.fmt.bufPrint(&text, "000{d}", .{size_max});
    try testing.expectEqual(@as(u32, size_max), try parseContentLength(leading_zeros));
    const past = try std.fmt.bufPrint(&text, "{d}", .{size_max + 1});
    try testing.expectError(error.ContentTooLarge, parseContentLength(past));
    // The widest step the loop takes: result is exactly size_max, then * 10 + 9.
    const widest_step = try std.fmt.bufPrint(&text, "{d}9", .{size_max});
    try testing.expectError(error.ContentTooLarge, parseContentLength(widest_step));
    // Overflow detector: without the check inside the loop, this wraps past maxInt(u32)
    // and panics, so it proves the loop stops before the multiply can overflow.
    try testing.expectError(error.ContentTooLarge, parseContentLength("4294967296"));
    // A value that is already too large but then turns out malformed is malformed.
    try testing.expectError(error.ContentLengthInvalid, parseContentLength("99999999999x"));
    try testing.expectError(error.ContentLengthInvalid, parseContentLength("4294967296 "));
}

test "http_request: a head split across two reads at every point" {
    const text = "POST /login HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nok";
    const whole = try parseWhole(text);
    var split: u32 = 0;
    while (split <= text.len) : (split += 1) {
        var scan: HeadScan = .{};
        const first = parse(text[0..split], &scan);
        if (split < whole.head_len) {
            try testing.expectError(error.Incomplete, first);
            try testing.expectEqual(split -| 3, scan.resume_at);
        } else {
            try expectSameResult(whole, first);
        }
        try expectSameResult(whole, parse(text, &scan));
        try testing.expectEqual(@as(u32, 0), scan.resume_at);
    }
}

test "http_request: the scan resets after a head, ready for the next request" {
    var scan: HeadScan = .{};
    const first = "GET /a HTTP/1.1\r\nHost: a\r\n\r\n";
    try testing.expectError(error.Incomplete, parse(first[0 .. first.len - 1], &scan));
    try testing.expect(scan.resume_at > 0);
    _ = try parse(first, &scan);
    try testing.expectEqual(@as(u32, 0), scan.resume_at);
    // The next request starts at the front of the buffer again, with a short head.
    const second = "GET /b HTTP/1.0\r\n\r\n";
    const request = try parse(second, &scan);
    try testing.expectEqualStrings("/b", request.target);
}

test "http_request: a full buffer fed in pieces is a head too large, as in one read" {
    const buffer: [size_max]u8 = @splat('a');
    const piece: u32 = 1000;
    comptime assert(piece < size_max);
    var scan: HeadScan = .{};
    var len: u32 = piece;
    while (len < size_max) : (len += piece) {
        try testing.expectError(error.Incomplete, parse(buffer[0..len], &scan));
        try testing.expectEqual(len - 3, scan.resume_at);
    }
    try testing.expectError(error.HeadTooLarge, parse(&buffer, &scan));
    // A final answer, so the scan is reset for whatever reuses the buffer.
    try testing.expectEqual(@as(u32, 0), scan.resume_at);
}

test "http_request: the end of the head is searched for from the resume point only" {
    // A CRLF CRLF before `start` was ruled out by an earlier call, so it is not found again.
    try testing.expectEqual(@as(?u32, 4), findHeadEnd("\r\n\r\nab", 0));
    try testing.expectEqual(@as(?u32, null), findHeadEnd("\r\n\r\nab", 1));
    try testing.expectEqual(@as(?u32, 10), findHeadEnd("a\r\n\r\nb\r\n\r\n", 2));
    // At the boundary: a CRLF CRLF that starts at `start` is found; one before it is not.
    try testing.expectEqual(@as(?u32, 5), findHeadEnd("x\r\n\r\n", 1));
    try testing.expectEqual(@as(?u32, null), findHeadEnd("x\r\n\r\n", 2));
}

test "http_request: bytes after the head, fed one at a time, still stop at the first head" {
    const pipelined = "GET / HTTP/1.1\r\nHost: a\r\n\r\nGET /b HTTP/1.0\r\n\r\n";
    try expectSameWhenSplit(pipelined);
    const request = try parseWhole(pipelined);
    try testing.expectEqualStrings("/", request.target);
    try testing.expectEqualStrings("GET /b HTTP/1.0\r\n\r\n", pipelined[request.head_len..]);

    var buffer: [size_max]u8 = undefined;
    try expectSameWhenSplit(buildHead(&buffer, headers_max));
    try expectSameWhenSplit(buildHead(&buffer, headers_max + 1));
}
