//! Seeded fuzzer: `zig build fuzz -Dseed=<n>`.
//!
//! Targets, each run for `fuzz_iterations_max` iterations from the same seed:
//!   bounded_queue  random pushes and pops, checked against a trivial model after every step.
//!   http_request   valid requests from a generator, sometimes mutated or truncated, checked
//!                  against what the generator wrote; plus cases at each size and field-count
//!                  limit with the exact error expected, and a check that the run reached
//!                  every one of those limits.
//! Each component adds its own target as it lands (parsers first). A failing seed replays
//! exactly.

const std = @import("std");
const assert = std.debug.assert;
const cc = @import("coalition_connection");
const build_options = @import("build_options");

const capacity: u32 = 16;
const Queue = cc.BoundedQueue(u32, capacity);

/// The model: values are sequence numbers, so FIFO order means pops return them in order.
const Model = struct {
    next_push: u32 = 0,
    next_pop: u32 = 0,

    fn len(self: Model) u32 {
        assert(self.next_push >= self.next_pop);
        assert(self.next_push - self.next_pop <= capacity);
        return self.next_push - self.next_pop;
    }
};

/// Mismatch: the code under test disagreed with the model. LimitMissed: the run never
/// generated a case at one of the limits it is meant to reach.
const FuzzError = error{ Mismatch, LimitMissed };

fn step(random: std.Random, queue: *Queue, model: *Model) FuzzError!void {
    assert(queue.count() == model.len());
    assert(model.next_push >= model.next_pop);
    if (random.boolean()) {
        if (queue.push(model.next_push)) {
            model.next_push += 1;
        } else |err| switch (err) {
            error.Full => if (model.len() != capacity) return error.Mismatch,
            error.Empty => return error.Mismatch,
        }
    } else {
        if (queue.pop()) |value| {
            if (value != model.next_pop) return error.Mismatch;
            model.next_pop += 1;
        } else |err| switch (err) {
            error.Empty => if (model.len() != 0) return error.Mismatch,
            error.Full => return error.Mismatch,
        }
    }
    if (queue.count() != model.len()) return error.Mismatch;
}

fn runQueue(seed: u64) FuzzError!void {
    comptime assert(cc.constants.fuzz_iterations_max > 0);
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var queue: Queue = .{};
    var model: Model = .{};

    var iteration: u32 = 0;
    while (iteration < cc.constants.fuzz_iterations_max) : (iteration += 1) {
        step(random, &queue, &model) catch |err| {
            std.debug.print("fuzz bounded_queue: seed={d} failed at iteration {d}\n", .{ seed, iteration });
            return err;
        };
    }
    assert(iteration == cc.constants.fuzz_iterations_max);
    std.debug.print("fuzz bounded_queue: seed={d} iterations={d} ok\n", .{ seed, iteration });
}

// ---- http_request ------------------------------------------------------------------

const http = cc.live.http_request;
/// The parser's own limit, so the generator can reach every size boundary.
const http_buffer_size: u32 = cc.constants.http_request_size_max;
const headers_max: u32 = cc.constants.http_headers_max;

const http_methods = [_]struct { name: []const u8, method: http.Method }{
    .{ .name = "GET", .method = .get },
    .{ .name = "POST", .method = .post },
    .{ .name = "DELETE", .method = .delete },
    .{ .name = "OPTIONS", .method = .options },
};

/// What the generator wrote, so the parser's answer can be checked against it.
const HttpModel = struct {
    method: http.Method,
    header_count: u32,
    content_length: u32,
    len: u32,
};

/// The limit a generated case sits on, so the run can count which limits it reached.
const HttpLimit = enum {
    none,
    /// Exactly `http_headers_max` fields: the largest count that parses.
    headers_at_max,
    /// `http_headers_max + 1` fields.
    headers_too_many,
    /// Head plus Content-Length is exactly `http_request_size_max`.
    request_exact_fit,
    /// The head fits, but head plus Content-Length does not.
    body_too_large,
    /// A full buffer with no end of head.
    buffer_full,
    /// One byte short of a full buffer, with no end of head: still incomplete.
    buffer_one_short,
    /// A small head and a multi-digit Content-Length that makes the request exactly full.
    content_length_exact_fit,
    /// The same, one byte over.
    content_length_one_over,
    /// A five-digit Content-Length above `http_request_size_max`.
    content_length_over_max,
    /// A Content-Length of 6 to 20 digits.
    content_length_digits_over,
};

/// A limit case: the bytes written, the error the parser must return (null for success)
/// and which limit the case sits on.
const HttpCase = struct {
    model: HttpModel,
    expected: ?http.Error,
    limit: HttpLimit,
};

/// How often the run reached each limit. Every count must end above zero.
const HttpCounts = struct {
    headers_at_max: u32 = 0,
    headers_too_many: u32 = 0,
    request_exact_fit: u32 = 0,
    body_too_large: u32 = 0,
    buffer_full: u32 = 0,
    buffer_one_short: u32 = 0,
    content_length_exact_fit: u32 = 0,
    content_length_one_over: u32 = 0,
    content_length_over_max: u32 = 0,
    content_length_digits_over: u32 = 0,

    fn add(self: *HttpCounts, limit: HttpLimit) void {
        const before = self.total();
        assert(before < cc.constants.fuzz_iterations_max);
        switch (limit) {
            .none => {},
            .headers_at_max => self.headers_at_max += 1,
            .headers_too_many => self.headers_too_many += 1,
            .request_exact_fit => self.request_exact_fit += 1,
            .body_too_large => self.body_too_large += 1,
            .buffer_full => self.buffer_full += 1,
            .buffer_one_short => self.buffer_one_short += 1,
            .content_length_exact_fit => self.content_length_exact_fit += 1,
            .content_length_one_over => self.content_length_one_over += 1,
            .content_length_over_max => self.content_length_over_max += 1,
            .content_length_digits_over => self.content_length_digits_over += 1,
        }
        const expected: u32 = if (limit == .none) before else before + 1;
        assert(self.total() == expected);
    }

    /// At most one count per iteration, so the sum fits a u32.
    fn total(self: *const HttpCounts) u32 {
        comptime assert(cc.constants.fuzz_iterations_max < std.math.maxInt(u32) / 2);
        var sum: u32 = 0;
        sum += self.headers_at_max;
        sum += self.headers_too_many;
        sum += self.request_exact_fit;
        sum += self.body_too_large;
        sum += self.buffer_full;
        sum += self.buffer_one_short;
        sum += self.content_length_exact_fit;
        sum += self.content_length_one_over;
        sum += self.content_length_over_max;
        sum += self.content_length_digits_over;
        assert(sum <= cc.constants.fuzz_iterations_max);
        return sum;
    }

    fn allReached(self: *const HttpCounts) bool {
        const sum = self.total();
        assert(sum <= cc.constants.fuzz_iterations_max);
        assert(sum >= self.headers_at_max);
        return self.headers_at_max > 0 and self.headers_too_many > 0 and
            self.request_exact_fit > 0 and self.body_too_large > 0 and
            self.buffer_full > 0 and self.buffer_one_short > 0 and
            self.content_length_exact_fit > 0 and self.content_length_one_over > 0 and
            self.content_length_over_max > 0 and self.content_length_digits_over > 0;
    }

    fn print(self: *const HttpCounts, seed: u64) void {
        const sum = self.total();
        assert(sum <= cc.constants.fuzz_iterations_max);
        std.debug.print("fuzz http_request: seed={d} limit cases={d}\n", .{ seed, sum });
        std.debug.print(
            "  headers_at_max={d} headers_too_many={d} request_exact_fit={d} body_too_large={d}\n",
            .{ self.headers_at_max, self.headers_too_many, self.request_exact_fit, self.body_too_large },
        );
        std.debug.print(
            "  buffer_full={d} buffer_one_short={d}\n",
            .{ self.buffer_full, self.buffer_one_short },
        );
        std.debug.print(
            "  content_length_exact_fit={d} content_length_one_over={d} content_length_over_max={d} content_length_digits_over={d}\n",
            .{ self.content_length_exact_fit, self.content_length_one_over, self.content_length_over_max, self.content_length_digits_over },
        );
    }
};

fn append(buffer: *[http_buffer_size]u8, len: u32, text: []const u8) u32 {
    assert(len <= http_buffer_size);
    assert(len + text.len <= http_buffer_size);
    @memcpy(buffer[len..][0..text.len], text);
    return len + @as(u32, @intCast(text.len));
}

/// Writes `count` copies of `byte` at `len`.
fn appendFill(buffer: *[http_buffer_size]u8, len: u32, count: u32, byte: u8) u32 {
    assert(len <= http_buffer_size);
    assert(count <= http_buffer_size - len);
    @memset(buffer[len..][0..count], byte);
    assert(count == 0 or buffer[len + count - 1] == byte);
    return len + count;
}

/// Writes `value` in decimal, without leading zeros.
fn appendDecimal(buffer: *[http_buffer_size]u8, len: u32, value: u32) u32 {
    const digits_max: u32 = 10;
    var digits: [digits_max]u8 = undefined;
    var count: u32 = 0;
    var rest: u32 = value;
    while (count < digits_max) {
        digits[digits_max - 1 - count] = '0' + @as(u8, @intCast(rest % 10));
        count += 1;
        rest /= 10;
        if (rest == 0) break;
    }
    assert(rest == 0);
    assert(count >= 1 and count <= digits_max);
    return append(buffer, len, digits[digits_max - count ..]);
}

/// Writes a valid request: a method, Host, up to 7 extra fields and a one-digit Content-Length.
fn httpGenerate(random: std.Random, buffer: *[http_buffer_size]u8) HttpModel {
    const choice = http_methods[random.uintLessThan(u32, http_methods.len)];
    var len: u32 = append(buffer, 0, choice.name);
    len = append(buffer, len, if (choice.method == .options) " * HTTP/1.1\r\n" else " /p?q=1 HTTP/1.1\r\n");
    len = append(buffer, len, "Host: example.test\r\n");
    const extra = random.uintLessThan(u32, 8);
    var index: u32 = 0;
    while (index < extra) : (index += 1) {
        len = append(buffer, len, if (random.boolean()) "X-Field: \tvalue \r\n" else "cookie:k=v\r\n");
    }
    const content_length = random.uintLessThan(u8, 10);
    len = append(buffer, len, "Content-Length: ");
    buffer[len] = '0' + content_length;
    len = append(buffer, len + 1, "\r\n\r\n");
    assert(index == extra);
    assert(len <= http_buffer_size);
    return .{ .method = choice.method, .header_count = extra + 2, .content_length = content_length, .len = len };
}

/// Writes `http_headers_max - 1`, `http_headers_max` or `http_headers_max + 1` fields,
/// counting Host and Content-Length. Only the last is too many.
fn httpGenerateFields(random: std.Random, buffer: *[http_buffer_size]u8) HttpCase {
    const request_line = "GET /p HTTP/1.1\r\nHost: example.test\r\n";
    const field_long = "X-Field: \tvalue \r\n";
    const end = "Content-Length: 0\r\n\r\n";
    comptime assert(headers_max >= 3);
    comptime assert(request_line.len + (headers_max + 1) * field_long.len + end.len <= http_buffer_size);

    const total: u32 = headers_max - 1 + random.uintLessThan(u32, 3);
    assert(total >= 2);
    const extra = total - 2;
    assert(extra <= headers_max - 1);
    var len: u32 = append(buffer, 0, request_line);
    var index: u32 = 0;
    while (index < extra) : (index += 1) {
        len = append(buffer, len, if (random.boolean()) field_long else "cookie:k=v\r\n");
    }
    len = append(buffer, len, end);
    assert(index == extra);

    const model: HttpModel = .{ .method = .get, .header_count = total, .content_length = 0, .len = len };
    if (total > headers_max) return .{ .model = model, .expected = error.HeadersTooMany, .limit = .headers_too_many };
    if (total == headers_max) return .{ .model = model, .expected = null, .limit = .headers_at_max };
    return .{ .model = model, .expected = null, .limit = .none };
}

/// Writes a complete head whose length is within 16 bytes of `http_request_size_max`,
/// made long by one header value, with a one-digit Content-Length that may push head plus
/// body past the limit.
fn httpGenerateLong(random: std.Random, buffer: *[http_buffer_size]u8) HttpCase {
    const prefix = "POST /p HTTP/1.1\r\nHost: example.test\r\nX-Long: ";
    const middle = "\r\nContent-Length: ";
    const end = "\r\n\r\n";
    const slack_max: u32 = 16;
    const fixed: u32 = prefix.len + middle.len + 1 + end.len;
    comptime assert(fixed + slack_max < http_buffer_size);

    const head_len = http_buffer_size - random.uintLessThan(u32, slack_max + 1);
    const content_length = random.uintLessThan(u8, 10);
    const letter = 'a' + random.uintLessThan(u8, 26);
    var len: u32 = append(buffer, 0, prefix);
    len = appendFill(buffer, len, head_len - fixed, letter);
    len = append(buffer, len, middle);
    buffer[len] = '0' + content_length;
    len = append(buffer, len + 1, end);
    assert(len == head_len);

    const model: HttpModel = .{ .method = .post, .header_count = 3, .content_length = content_length, .len = len };
    const request_len = head_len + content_length;
    if (request_len > http_buffer_size) return .{ .model = model, .expected = error.RequestTooLarge, .limit = .body_too_large };
    if (request_len == http_buffer_size) return .{ .model = model, .expected = null, .limit = .request_exact_fit };
    return .{ .model = model, .expected = null, .limit = .none };
}

/// Writes a head that never ends: a header value that runs to the end of the buffer, or
/// to one byte before it.
fn httpGenerateOverflow(random: std.Random, buffer: *[http_buffer_size]u8) HttpCase {
    const prefix = "GET /p HTTP/1.1\r\nHost: example.test\r\nX-Long: ";
    comptime assert(prefix.len + 1 < http_buffer_size);
    const target = http_buffer_size - random.uintLessThan(u32, 2);
    const letter = 'a' + random.uintLessThan(u8, 26);
    // The buffer may end partway into a terminator, which must still not end the head.
    const tails = [_][]const u8{ "", "\r", "\r\n", "\r\n\r" };
    const tail = tails[random.uintLessThan(u32, tails.len)];
    var len: u32 = append(buffer, 0, prefix);
    len = appendFill(buffer, len, target - len - @as(u32, @intCast(tail.len)), letter);
    len = append(buffer, len, tail);
    assert(len == target);

    const model: HttpModel = .{ .method = .get, .header_count = 0, .content_length = 0, .len = len };
    if (len == http_buffer_size) return .{ .model = model, .expected = error.RequestTooLarge, .limit = .buffer_full };
    return .{ .model = model, .expected = error.Incomplete, .limit = .buffer_one_short };
}

/// Writes a small head whose Content-Length has several digits: an exact fit, one byte
/// over, a five-digit value above `http_request_size_max`, or 6 to 20 digits. Leading
/// zeros are sometimes added; they do not change the value.
fn httpGenerateBody(random: std.Random, buffer: *[http_buffer_size]u8) HttpCase {
    const prefix = "POST /p HTTP/1.1\r\nHost: example.test\r\nContent-Length: ";
    const end = "\r\n\r\n";
    const zeros_max: u32 = 3;
    // The exact-fit value is near http_buffer_size, so it has exactly five digits.
    comptime assert(http_buffer_size >= 10_000 + prefix.len + zeros_max + 5 + end.len);
    comptime assert(http_buffer_size < 99_999);

    const zeros = random.uintLessThan(u32, zeros_max + 1);
    var len: u32 = append(buffer, 0, prefix);
    len = appendFill(buffer, len, zeros, '0');
    const variant = random.uintLessThan(u32, 4);
    const end_len: u32 = end.len;
    const fit: u32 = http_buffer_size - (len + 5 + end_len);
    var model: HttpModel = .{ .method = .post, .header_count = 2, .content_length = 0, .len = 0 };
    var case: HttpCase = .{ .model = model, .expected = error.RequestTooLarge, .limit = .content_length_one_over };
    switch (variant) {
        0 => {
            len = appendDecimal(buffer, len, fit);
            model.content_length = fit;
            case.expected = null;
            case.limit = .content_length_exact_fit;
        },
        1 => len = appendDecimal(buffer, len, fit + 1),
        2 => {
            const value = http_buffer_size + 1 + random.uintLessThan(u32, 99_999 - http_buffer_size);
            len = appendDecimal(buffer, len, value);
            case.limit = .content_length_over_max;
        },
        else => {
            len = appendFill(buffer, len, 6 + random.uintLessThan(u32, 15), '9');
            case.limit = .content_length_digits_over;
        },
    }
    len = append(buffer, len, end);
    assert(variant >= 2 or len + fit == http_buffer_size);
    model.len = len;
    case.model = model;
    return case;
}

/// Parses a limit case, unmutated and whole, and checks the exact answer.
fn httpCheckCase(case: HttpCase, buffer: *const [http_buffer_size]u8, counts: *HttpCounts) FuzzError!void {
    assert(case.model.len > 0);
    assert(case.model.len <= http_buffer_size);
    const input = buffer[0..case.model.len];
    const request = http.parse(input) catch |err| {
        const expected = case.expected orelse {
            std.debug.print("fuzz http_request: {s} case rejected with {s}\n", .{ @tagName(case.limit), @errorName(err) });
            return error.Mismatch;
        };
        if (err != expected) {
            std.debug.print("fuzz http_request: {s} case: expected {s}, got {s}\n", .{ @tagName(case.limit), @errorName(expected), @errorName(err) });
            return error.Mismatch;
        }
        counts.add(case.limit);
        return;
    };
    if (case.expected) |expected| {
        std.debug.print("fuzz http_request: {s} case parsed, expected {s}\n", .{ @tagName(case.limit), @errorName(expected) });
        return error.Mismatch;
    }
    httpCheckParsed(case, input, &request) catch |err| {
        std.debug.print("fuzz http_request: {s} case parsed to the wrong request\n", .{@tagName(case.limit)});
        return err;
    };
    counts.add(case.limit);
}

/// Checks a parsed limit case against the model. Every limit case that parses ends with
/// its Content-Length field, so the last stored field must be that one.
fn httpCheckParsed(case: HttpCase, input: []const u8, request: *const http.Request) FuzzError!void {
    assert(case.expected == null);
    assert(input.len == case.model.len);
    try httpCheckAlways(input, request);
    if (request.method != case.model.method) return error.Mismatch;
    if (request.header_count != case.model.header_count) return error.Mismatch;
    if (request.content_length != case.model.content_length) return error.Mismatch;
    if (request.head_len != case.model.len) return error.Mismatch;
    if (request.header_count == 0) return error.Mismatch;
    const last = request.headers[request.header_count - 1];
    if (!std.mem.eql(u8, last.name, "Content-Length")) return error.Mismatch;
}

/// Properties every successful parse must have, valid input or not.
fn httpCheckAlways(input: []const u8, request: *const http.Request) FuzzError!void {
    assert(input.len <= http_buffer_size);
    assert(request.header_count <= cc.constants.http_headers_max);
    if (request.head_len < 4 or request.head_len > input.len) return error.Mismatch;
    const end = input[request.head_len - 4 .. request.head_len];
    if (end[0] != '\r' or end[1] != '\n' or end[2] != '\r' or end[3] != '\n') return error.Mismatch;
    if (request.head_len + request.content_length > cc.constants.http_request_size_max) return error.Mismatch;
    if (request.target.len == 0) return error.Mismatch;
    for (request.headers[0..request.header_count]) |field| {
        if (field.name.len == 0) return error.Mismatch;
        for (field.value) |byte| {
            if (byte == '\r' or byte == '\n' or byte == 0) return error.Mismatch;
        }
    }
}

fn httpStep(random: std.Random, buffer: *[http_buffer_size]u8, counts: *HttpCounts) FuzzError!void {
    // One step in 16 each writes a field-count case, a long head, a head that never ends
    // or a long body.
    switch (random.uintLessThan(u32, 16)) {
        0 => return httpCheckCase(httpGenerateFields(random, buffer), buffer, counts),
        1 => return httpCheckCase(httpGenerateLong(random, buffer), buffer, counts),
        2 => return httpCheckCase(httpGenerateOverflow(random, buffer), buffer, counts),
        3 => return httpCheckCase(httpGenerateBody(random, buffer), buffer, counts),
        else => {},
    }
    const model = httpGenerate(random, buffer);
    assert(model.len > 0);
    const mutations = random.uintLessThan(u32, 4);
    var index: u32 = 0;
    while (index < mutations) : (index += 1) {
        buffer[random.uintLessThan(u32, model.len)] = random.int(u8);
    }
    const truncated = random.uintLessThan(u32, 4) == 0;
    const len = if (truncated) random.uintLessThan(u32, model.len) else model.len;
    assert(len <= model.len);
    const input = buffer[0..len];

    const request = http.parse(input) catch |err| {
        if (mutations > 0) return; // Bad input: any named error is a correct answer.
        // A cut-off valid request is always incomplete, because its only CRLF CRLF is at the end.
        if (truncated and err == error.Incomplete) return;
        std.debug.print("fuzz http_request: valid input rejected with {s}\n", .{@errorName(err)});
        return error.Mismatch;
    };
    try httpCheckAlways(input, &request);
    if (mutations > 0) return;
    if (truncated) return error.Mismatch; // An incomplete head must not parse.
    if (request.method != model.method) return error.Mismatch;
    if (request.header_count != model.header_count) return error.Mismatch;
    if (request.content_length != model.content_length) return error.Mismatch;
    if (request.head_len != model.len) return error.Mismatch;
}

fn runHttp(seed: u64) FuzzError!void {
    comptime assert(http_buffer_size == cc.constants.http_request_size_max);
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var buffer: [http_buffer_size]u8 = undefined;
    var counts: HttpCounts = .{};

    var iteration: u32 = 0;
    while (iteration < cc.constants.fuzz_iterations_max) : (iteration += 1) {
        httpStep(random, &buffer, &counts) catch |err| {
            std.debug.print("fuzz http_request: seed={d} failed at iteration {d}\n", .{ seed, iteration });
            return err;
        };
    }
    assert(iteration == cc.constants.fuzz_iterations_max);
    counts.print(seed);
    if (!counts.allReached()) {
        std.debug.print("fuzz http_request: seed={d} missed a limit\n", .{seed});
        return error.LimitMissed;
    }
    std.debug.print("fuzz http_request: seed={d} iterations={d} ok\n", .{ seed, iteration });
}

pub fn main() FuzzError!void {
    const seed: u64 = build_options.seed;
    comptime assert(cc.constants.fuzz_iterations_max > 0);
    comptime assert(http_buffer_size > 0);
    try runQueue(seed);
    try runHttp(seed);
}
