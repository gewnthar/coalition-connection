//! Seeded fuzzer: `zig build fuzz -Dseed=<n>`.
//!
//! Targets, each run for `fuzz_iterations_max` iterations from the same seed:
//!   bounded_queue  random pushes and pops, checked against a trivial model after every step.
//!   http_request   valid requests from a generator, sometimes mutated or truncated, checked
//!                  against what the generator wrote; plus cases at each size and field-count
//!                  limit with the exact error expected, and a check that the run reached
//!                  every one of those limits. Every input is also fed again in reads of
//!                  random sizes, split at random points, and must get the same answer.
//!   http_response  generated responses, valid or with a name or value fault in a field,
//!                  written into buffers of the exact length, one byte short or at random,
//!                  checked byte for byte against a model in fuzz/http_response.zig, with
//!                  every outcome, fault pair and limit required to come up (see that file).
//!   config         valid config files from a generator, sometimes mutated, plus random
//!                  bytes and random runs of ZON tokens: every input must give a config or a
//!                  named error, never a crash, and an unmutated file must give exactly the
//!                  values the generator wrote. The run must reach success, syntax errors
//!                  and the nesting limit.
//! Each component adds its own target as it lands (parsers first). A failing seed replays
//! exactly.

const std = @import("std");
const assert = std.debug.assert;
const cc = @import("coalition_connection");
const build_options = @import("build_options");
const http_response_fuzz = @import("http_response.zig");

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
    /// X-Real-IP fields written; more than one must be refused.
    real_ip_fields: u32 = 0,
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
    /// A valid request with two or more X-Real-IP fields, in any case.
    real_ip_duplicate,
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
    real_ip_duplicate: u32 = 0,

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
            .real_ip_duplicate => self.real_ip_duplicate += 1,
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
        sum += self.real_ip_duplicate;
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
            self.content_length_over_max > 0 and self.content_length_digits_over > 0 and
            self.real_ip_duplicate > 0;
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
        std.debug.print("  real_ip_duplicate={d}\n", .{self.real_ip_duplicate});
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

/// X-Real-IP fields as a client might spell them; the parser must count each one.
const http_real_ip_fields = [_][]const u8{
    "X-Real-IP: 192.0.2.1\r\n",
    "x-real-ip:192.0.2.1\r\n",
    "X-REAL-IP: \t198.51.100.2 \r\n",
};

/// Writes a valid request: a method, Host, up to 7 extra fields and a one-digit Content-Length.
/// About one extra field in eight is an X-Real-IP, so some requests carry two or more and
/// must be refused with `error.RealIpDuplicate`.
fn httpGenerate(random: std.Random, buffer: *[http_buffer_size]u8) HttpModel {
    const choice = http_methods[random.uintLessThan(u32, http_methods.len)];
    var len: u32 = append(buffer, 0, choice.name);
    len = append(buffer, len, if (choice.method == .options) " * HTTP/1.1\r\n" else " /p?q=1 HTTP/1.1\r\n");
    len = append(buffer, len, "Host: example.test\r\n");
    const extra = random.uintLessThan(u32, 8);
    var real_ip_fields: u32 = 0;
    var index: u32 = 0;
    while (index < extra) : (index += 1) {
        if (random.uintLessThan(u32, 8) == 0) {
            len = append(buffer, len, http_real_ip_fields[random.uintLessThan(u32, http_real_ip_fields.len)]);
            real_ip_fields += 1;
        } else {
            len = append(buffer, len, if (random.boolean()) "X-Field: \tvalue \r\n" else "cookie:k=v\r\n");
        }
    }
    assert(real_ip_fields <= extra);
    const content_length = random.uintLessThan(u8, 10);
    len = append(buffer, len, "Content-Length: ");
    buffer[len] = '0' + content_length;
    len = append(buffer, len + 1, "\r\n\r\n");
    assert(index == extra);
    assert(len <= http_buffer_size);
    return .{
        .method = choice.method,
        .header_count = extra + 2,
        .content_length = content_length,
        .len = len,
        .real_ip_fields = real_ip_fields,
    };
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
    if (request_len > http_buffer_size) return .{ .model = model, .expected = error.ContentTooLarge, .limit = .body_too_large };
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
    if (len == http_buffer_size) return .{ .model = model, .expected = error.HeadTooLarge, .limit = .buffer_full };
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
    var case: HttpCase = .{ .model = model, .expected = error.ContentTooLarge, .limit = .content_length_one_over };
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

/// Parses `input` as if it arrived in one read.
fn httpParseWhole(input: []const u8) http.Error!http.Request {
    assert(input.len <= http_buffer_size);
    var scan: http.HeadScan = .{};
    const result = http.parse(input, &scan);
    assert(scan.resume_at <= input.len);
    return result;
}

/// Feeds `input` through one `HeadScan` in reads of random sizes, as a client's bytes
/// arrive, and checks the answer matches `whole`, the answer for one read. Small reads of 1
/// to 4 bytes make a CRLF CRLF straddle two reads; large ones cover the rest quickly.
fn httpCheckSplit(random: std.Random, input: []const u8, whole: http.Error!http.Request) FuzzError!void {
    assert(input.len <= http_buffer_size);
    const input_len: u32 = @intCast(input.len);
    var scan: http.HeadScan = .{};
    var result: http.Error!http.Request = error.Incomplete;
    var len: u32 = 0;
    var reads: u32 = 0;
    // Each read adds at least one byte, so input_len + 1 parses (the first of an empty
    // buffer) always reach the end.
    while (reads <= input_len) : (reads += 1) {
        result = http.parse(input[0..len], &scan);
        if (result) |_| break else |err| if (err != error.Incomplete) break;
        // An incomplete read leaves the scan three bytes short of the end.
        if (scan.resume_at != len -| 3) return error.Mismatch;
        if (len == input_len) break;
        const remaining = input_len - len;
        const small = random.boolean();
        const limit = if (small) @min(remaining, 4) else remaining;
        len += 1 + random.uintLessThan(u32, limit);
    }
    assert(reads <= input_len);
    assert(len <= input_len);
    // Any final answer resets the scan for the next request.
    const final = if (result) |_| true else |err| err != error.Incomplete;
    if (final and scan.resume_at != 0) return error.Mismatch;
    // A head found early decides the answer, so stopping there must agree with one read.
    try httpSameResult(whole, result);
    const request = whole catch return;
    try httpCheckSplitAtEnd(input, request.head_len, whole);
}

/// Two reads, the first ending one, two or three bytes before the end of the head, so the
/// CRLF CRLF straddles them at each place it can.
fn httpCheckSplitAtEnd(input: []const u8, head_len: u32, whole: http.Error!http.Request) FuzzError!void {
    assert(head_len >= 4);
    assert(head_len <= input.len);
    var back: u32 = 1;
    while (back <= 3) : (back += 1) {
        var scan: http.HeadScan = .{};
        const first = http.parse(input[0 .. head_len - back], &scan);
        if (first) |_| return error.Mismatch else |err| if (err != error.Incomplete) return error.Mismatch;
        try httpSameResult(whole, http.parse(input, &scan));
        if (scan.resume_at != 0) return error.Mismatch;
    }
}

/// Mismatch unless `a` and `b` are the same error, or requests with the same fields
/// pointing at the same bytes.
fn httpSameResult(a: http.Error!http.Request, b: http.Error!http.Request) FuzzError!void {
    const left = a catch |err_a| {
        const err_b = if (b) |_| return error.Mismatch else |err| err;
        if (err_a != err_b) return error.Mismatch;
        return;
    };
    const right = b catch return error.Mismatch;
    assert(left.header_count <= headers_max);
    assert(right.header_count <= headers_max);
    if (left.method != right.method or left.version != right.version) return error.Mismatch;
    if (left.target.ptr != right.target.ptr or left.target.len != right.target.len) return error.Mismatch;
    if (left.head_len != right.head_len) return error.Mismatch;
    if (left.content_length != right.content_length) return error.Mismatch;
    if (left.header_count != right.header_count) return error.Mismatch;
    for (left.headers[0..left.header_count], right.headers[0..right.header_count]) |x, y| {
        if (x.name.ptr != y.name.ptr or x.name.len != y.name.len) return error.Mismatch;
        if (x.value.ptr != y.value.ptr or x.value.len != y.value.len) return error.Mismatch;
    }
}

/// Parses a limit case, unmutated and whole, and checks the exact answer, then checks the
/// same bytes split into random reads get it too.
fn httpCheckCase(
    random: std.Random,
    case: HttpCase,
    buffer: *const [http_buffer_size]u8,
    counts: *HttpCounts,
) FuzzError!void {
    assert(case.model.len > 0);
    assert(case.model.len <= http_buffer_size);
    const input = buffer[0..case.model.len];
    const whole = httpParseWhole(input);
    httpCheckSplit(random, input, whole) catch |err| {
        std.debug.print("fuzz http_request: {s} case split into reads got another answer\n", .{@tagName(case.limit)});
        return err;
    };
    const request = whole catch |err| {
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
        0 => return httpCheckCase(random, httpGenerateFields(random, buffer), buffer, counts),
        1 => return httpCheckCase(random, httpGenerateLong(random, buffer), buffer, counts),
        2 => return httpCheckCase(random, httpGenerateOverflow(random, buffer), buffer, counts),
        3 => return httpCheckCase(random, httpGenerateBody(random, buffer), buffer, counts),
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

    const whole = httpParseWhole(input);
    httpCheckSplit(random, input, whole) catch |err| {
        std.debug.print("fuzz http_request: input split into reads got another answer\n", .{});
        return err;
    };
    const request = whole catch |err| {
        if (mutations > 0) return; // Bad input: any named error is a correct answer.
        // A cut-off valid request is always incomplete, because its only CRLF CRLF is at the end.
        if (truncated and err == error.Incomplete) return;
        if (!truncated and model.real_ip_fields > 1 and err == error.RealIpDuplicate) {
            counts.add(.real_ip_duplicate);
            return;
        }
        std.debug.print("fuzz http_request: valid input rejected with {s}\n", .{@errorName(err)});
        return error.Mismatch;
    };
    try httpCheckAlways(input, &request);
    if (mutations > 0) return;
    if (truncated) return error.Mismatch; // An incomplete head must not parse.
    if (model.real_ip_fields > 1) return error.Mismatch; // A second X-Real-IP must not parse.
    if ((request.header("X-Real-IP") != null) != (model.real_ip_fields == 1)) return error.Mismatch;
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

const config = cc.config;
const config_file_size_max = cc.constants.config_file_size_max;

/// The values a generated config file holds.
const ConfigModel = struct {
    socket_path: [cc.constants.config_socket_path_max]u8,
    socket_path_len: u32,
    connections_max: u32,
};

/// How a config input was made, so the result can be judged.
const ConfigKind = enum(u8) { valid, mutated, random_bytes, random_tokens, many_fields, heavy };

const ConfigCounts = struct {
    ok: u32 = 0,
    syntax: u32 = 0,
    too_many_fields: u32 = 0,
    /// Never expected: every input the prescan passes fits the scratch region.
    too_complex: u32 = 0,
    other: u32 = 0,

    fn add(counts: *ConfigCounts, result: config.ParseError!config.Config) void {
        const total_before = counts.ok + counts.syntax + counts.too_many_fields + counts.too_complex + counts.other;
        assert(total_before < cc.constants.fuzz_iterations_max);
        if (result) |_| {
            counts.ok += 1;
        } else |err| switch (err) {
            error.ConfigSyntax => counts.syntax += 1,
            error.ConfigTooManyFields => counts.too_many_fields += 1,
            error.ConfigTooComplex => counts.too_complex += 1,
            else => counts.other += 1,
        }
        assert(counts.ok + counts.syntax + counts.too_many_fields + counts.too_complex + counts.other == total_before + 1);
    }
};

comptime {
    // A generated file is the path, a limit of at most ten digits and under 64 bytes of
    // ZON around them, so it always fits: configGenerate's bufPrint can't fail.
    assert(cc.constants.config_socket_path_max + 10 + 64 < config_file_size_max);
}

/// Writes a valid config file into `buffer` and returns its length and the values in it.
fn configGenerate(random: std.Random, buffer: *[config_file_size_max:0]u8, model: *ConfigModel) u32 {
    const path_chars = "abcdefghijklmnopqrstuvwxyz0123456789-_./ (){}[]!";
    model.socket_path_len = random.intRangeAtMost(u32, 1, cc.constants.config_socket_path_max);
    model.socket_path[0] = '/';
    var index: u32 = 1;
    while (index < model.socket_path_len) : (index += 1) {
        model.socket_path[index] = path_chars[random.uintLessThan(u32, path_chars.len)];
    }
    model.connections_max = random.intRangeAtMost(u32, 1, cc.constants.http_connections_max);
    const path = model.socket_path[0..model.socket_path_len];
    const written = std.fmt.bufPrint(buffer, ".{{\n    .socket_path = \"{s}\",\n    .connections_max = {d},\n}}\n", .{
        path, model.connections_max,
    }) catch unreachable; // The comptime block above proves it fits.
    assert(written.len < config_file_size_max);
    assert(index == model.socket_path_len);
    return @intCast(written.len);
}

/// Changes, inserts or deletes up to eight bytes, or appends a run of one byte.
fn configMutate(random: std.Random, buffer: *[config_file_size_max:0]u8, len: u32) u32 {
    assert(len > 0 and len <= config_file_size_max);
    var new_len = len;
    const mutations = random.intRangeAtMost(u32, 1, 8);
    var mutation: u32 = 0;
    while (mutation < mutations) : (mutation += 1) {
        const at = random.uintLessThan(u32, new_len);
        switch (random.uintLessThan(u8, 4)) {
            0 => buffer[at] = random.int(u8),
            1 => if (new_len < config_file_size_max) {
                std.mem.copyBackwards(u8, buffer[at + 1 .. new_len + 1], buffer[at..new_len]);
                buffer[at] = random.int(u8);
                new_len += 1;
            },
            2 => if (new_len > 1) {
                std.mem.copyForwards(u8, buffer[at .. new_len - 1], buffer[at + 1 .. new_len]);
                new_len -= 1;
            },
            else => {
                const run = @min(random.uintAtMost(u32, 64), config_file_size_max - new_len);
                @memset(buffer[new_len..][0..run], "({[\"/\\"[random.uintLessThan(u32, 6)]);
                new_len += run;
            },
        }
    }
    assert(mutation == mutations);
    assert(new_len > 0 and new_len <= config_file_size_max);
    return new_len;
}

/// Fills up to the whole file with random bytes, or with random ZON tokens.
fn configRandom(random: std.Random, buffer: *[config_file_size_max:0]u8, tokens: bool) u32 {
    const token_set = [_][]const u8{
        ".{",   "{",      "}",       ".",    "=",    ",",       "\"", "a",      "1",     " ",      "\n",
        "(",    "//",     "\\",      "\r",   "\t",   ".a = 1,", "-",  "\"\\\n", "\\x",   "struct", "const",
        "try ", "break ", "return ", "\x00", "\x7f", "true",    "_",  "0x1F",   "1.5e3",
    };
    // Mostly short inputs keep the run fast; one in sixteen fills the file.
    const len_max: u32 = if (random.uintLessThan(u8, 16) == 0) config_file_size_max else 256;
    const len = random.uintAtMost(u32, len_max);
    if (!tokens) {
        random.bytes(buffer[0..len]);
        assert(len <= config_file_size_max);
        return len;
    }
    var index: u32 = 0;
    var picks: u32 = 0;
    while (index < len) : (picks += 1) {
        assert(picks < config_file_size_max);
        const token = token_set[random.uintLessThan(u32, token_set.len)];
        const take = @min(token.len, len - index);
        @memcpy(buffer[index..][0..take], token[0..take]);
        index += @intCast(take);
    }
    assert(index == len);
    return len;
}

/// Writes a file of up to half again `config_fields_max` well-formed fields the config
/// doesn't know, and returns its length and how many fields it holds.
fn configManyFields(random: std.Random, buffer: *[config_file_size_max:0]u8, fields: *u32) u32 {
    const fields_max = cc.constants.config_fields_max;
    comptime assert((fields_max + fields_max / 2) * 16 + 8 < config_file_size_max);
    fields.* = random.uintAtMost(u32, fields_max + fields_max / 2);
    buffer[0] = '.';
    buffer[1] = '{';
    var len: u32 = 2;
    var field: u32 = 0;
    while (field < fields.*) : (field += 1) {
        const written = std.fmt.bufPrint(buffer[len..], " .f{d} = {d},", .{ field, field }) catch unreachable; // The comptime assert above bounds it.
        len += @intCast(written.len);
    }
    assert(field == fields.*);
    buffer[len] = '}';
    len += 1;
    assert(len < config_file_size_max);
    return len;
}

/// Appends `count` bytes drawn from `alphabet` at `len` and returns the new length.
fn configAppendFrom(random: std.Random, buffer: *[config_file_size_max:0]u8, len: u32, count: u32, alphabet: []const u8) u32 {
    assert(len + count <= config_file_size_max);
    assert(alphabet.len > 0);
    for (buffer[len..][0..count]) |*byte| byte.* = alphabet[random.uintLessThan(u32, @intCast(alphabet.len))];
    return len + count;
}

/// Writes a file the prescan accepts but that is as heavy as it can make it for the parser:
/// up to `config_fields_max` fields with long names (keywords too), long numbers and long
/// strings full of escapes and non-ASCII bytes, filling the file.
fn configHeavy(random: std.Random, buffer: *[config_file_size_max:0]u8) u32 {
    const names = [_][]const u8{ "socket_path", "connections_max", "struct", "try", "comptime", "_", "a" };
    const string_chunks = [_][]const u8{ "\\u{10ffff}", "\\x41", "\\\"", "\\\\", "\xc3\xa9", "\xff", "a", " ", "\\n" };
    const fields = random.intRangeAtMost(u32, 1, cc.constants.config_fields_max);
    const room: u32 = config_file_size_max / fields - 8;
    var len: u32 = 0;
    buffer[0] = '.';
    buffer[1] = '{';
    len = 2;
    var field: u32 = 0;
    while (field < fields) : (field += 1) {
        const name = names[random.uintLessThan(u32, names.len)];
        const name_len = @min(room / 4, @as(u32, @intCast(name.len)) + random.uintAtMost(u32, room / 4));
        buffer[len] = '.';
        len = configAppendFrom(random, buffer, len + 1, 1, name[0..1]);
        len = configAppendFrom(random, buffer, len, name_len - 1, name);
        @memcpy(buffer[len..][0..3], " = ");
        len += 3;
        const value_room = room - name_len - 6;
        if (random.boolean()) {
            len = configAppendFrom(random, buffer, len, 1, "0123456789");
            len = configAppendFrom(random, buffer, len, value_room - 1, "0123456789abcdefxXoOb_eE");
        } else {
            buffer[len] = '"';
            len += 1;
            var used: u32 = 0;
            var chunks: u32 = 0;
            while (chunks < value_room) : (chunks += 1) {
                const chunk = string_chunks[random.uintLessThan(u32, string_chunks.len)];
                if (used + chunk.len + 2 > value_room) break;
                @memcpy(buffer[len..][0..chunk.len], chunk);
                len += @intCast(chunk.len);
                used += @intCast(chunk.len);
            }
            buffer[len] = '"';
            len += 1;
        }
        buffer[len] = ',';
        len += 1;
    }
    assert(field == fields);
    buffer[len] = '}';
    len += 1;
    assert(len <= config_file_size_max);
    return len;
}

fn configStep(random: std.Random, buffer: *[config_file_size_max:0]u8, scratch: []u8, counts: *ConfigCounts) FuzzError!void {
    var model: ConfigModel = undefined;
    var fields: u32 = 0;
    const kind: ConfigKind = @fromBackingInt(@intCast(random.uintLessThan(u8, 6)));
    const len: u32 = switch (kind) {
        .heavy => configHeavy(random, buffer),
        .many_fields => configManyFields(random, buffer, &fields),
        .valid => configGenerate(random, buffer, &model),
        .mutated => configMutate(random, buffer, configGenerate(random, buffer, &model)),
        .random_bytes => configRandom(random, buffer, false),
        .random_tokens => configRandom(random, buffer, true),
    };
    assert(len <= config_file_size_max);
    buffer[len] = 0;
    var report: config.SyntaxReport = .{};
    const result = config.parse(buffer[0..len :0], scratch, &report);
    counts.add(result);
    // Every syntax report names a place in the file.
    assert(report.errors == 0 or (report.line > 0 and report.column > 0));
    const syntax = if (result) |_| false else |err| err == error.ConfigSyntax;
    if (syntax != (report.errors > 0)) return error.Mismatch;
    if (kind == .many_fields) {
        // Unknown fields are a syntax error, unless there are too many to read at all.
        const over = fields > cc.constants.config_fields_max;
        const expected: config.ParseError = if (over) error.ConfigTooManyFields else error.ConfigSyntax;
        if (result) |_| return error.Mismatch else |err| if (err != expected) return error.Mismatch;
        return;
    }
    if (kind != .valid) return; // Bad input: a config or any named error is a correct answer.
    const parsed = result catch |err| {
        std.debug.print("fuzz config: valid file rejected with {s}\n", .{@errorName(err)});
        return error.Mismatch;
    };
    if (!std.mem.eql(u8, parsed.socketPath(), model.socket_path[0..model.socket_path_len])) return error.Mismatch;
    if (parsed.connections_max != model.connections_max) return error.Mismatch;
}

fn runConfig(seed: u64) FuzzError!void {
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    const scratch = std.heap.page_allocator.alloc(u8, cc.constants.config_parse_scratch_size_max) catch {
        std.debug.print("fuzz config: no memory for the parse scratch\n", .{});
        return error.Mismatch;
    };
    defer std.heap.page_allocator.free(scratch);
    assert(scratch.len == cc.constants.config_parse_scratch_size_max);
    var buffer: [config_file_size_max:0]u8 = undefined;
    var counts: ConfigCounts = .{};

    var iteration: u32 = 0;
    while (iteration < cc.constants.fuzz_iterations_max) : (iteration += 1) {
        configStep(random, &buffer, scratch, &counts) catch |err| {
            std.debug.print("fuzz config: seed={d} failed at iteration {d}\n", .{ seed, iteration });
            return err;
        };
    }
    std.debug.print("fuzz config: seed={d} ok={d} syntax={d} too_many_fields={d} too_complex={d} other={d}\n", .{
        seed, counts.ok, counts.syntax, counts.too_many_fields, counts.too_complex, counts.other,
    });
    assert(counts.ok + counts.syntax + counts.too_many_fields + counts.too_complex + counts.other == iteration);
    if (counts.too_complex > 0) {
        std.debug.print("fuzz config: seed={d} an input outgrew the parse scratch\n", .{seed});
        return error.Mismatch;
    }
    if (counts.ok == 0 or counts.syntax == 0 or counts.too_many_fields == 0) {
        std.debug.print("fuzz config: seed={d} missed an outcome\n", .{seed});
        return error.LimitMissed;
    }
    std.debug.print("fuzz config: seed={d} iterations={d} ok\n", .{ seed, iteration });
}

/// Stack for the config target's thread. Reason: the parser must stay shallow on every
/// input the prescan passes; a small stack turns any regression into a crash here instead
/// of a deep recursion that the main thread's 8 MiB would hide.
const config_stack_size: u32 = 256 * 1024;

fn runConfigThread(seed: u64, failure: *?FuzzError, finished: *bool) void {
    assert(!finished.*);
    assert(failure.* == null);
    runConfig(seed) catch |err| {
        failure.* = err;
    };
    finished.* = true;
}

pub fn main() FuzzError!void {
    const seed: u64 = build_options.seed;
    comptime assert(cc.constants.fuzz_iterations_max > 0);
    comptime assert(http_buffer_size > 0);
    try runQueue(seed);
    try runHttp(seed);
    try http_response_fuzz.run(seed);
    var config_failure: ?FuzzError = null;
    var config_finished = false;
    const spawn_config: std.Thread.SpawnConfig = .{ .stack_size = config_stack_size };
    const thread = std.Thread.spawn(spawn_config, runConfigThread, .{ seed, &config_failure, &config_finished }) catch {
        std.debug.print("fuzz config: could not start its thread\n", .{});
        return error.Mismatch;
    };
    thread.join();
    assert(config_finished);
    if (config_failure) |err| return err;
}
