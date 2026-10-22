//! Seeded fuzzer: `zig build fuzz -Dseed=<n>`.
//!
//! Targets, each run for `fuzz_iterations_max` iterations from the same seed:
//!   bounded_queue  random pushes and pops, checked against a trivial model after every step.
//!   http_request   valid requests from a generator, sometimes mutated or truncated, checked
//!                  against what the generator wrote.
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

const FuzzError = error{Mismatch};

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
const http_buffer_size: u32 = 512;

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

fn append(buffer: *[http_buffer_size]u8, len: u32, text: []const u8) u32 {
    assert(len <= http_buffer_size);
    assert(len + text.len <= http_buffer_size);
    @memcpy(buffer[len..][0..text.len], text);
    return len + @as(u32, @intCast(text.len));
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

fn httpStep(random: std.Random, buffer: *[http_buffer_size]u8) FuzzError!void {
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
    comptime assert(http_buffer_size <= cc.constants.http_request_size_max);
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var buffer: [http_buffer_size]u8 = undefined;

    var iteration: u32 = 0;
    while (iteration < cc.constants.fuzz_iterations_max) : (iteration += 1) {
        httpStep(random, &buffer) catch |err| {
            std.debug.print("fuzz http_request: seed={d} failed at iteration {d}\n", .{ seed, iteration });
            return err;
        };
    }
    assert(iteration == cc.constants.fuzz_iterations_max);
    std.debug.print("fuzz http_request: seed={d} iterations={d} ok\n", .{ seed, iteration });
}

pub fn main() FuzzError!void {
    const seed: u64 = build_options.seed;
    comptime assert(cc.constants.fuzz_iterations_max > 0);
    comptime assert(http_buffer_size > 0);
    try runQueue(seed);
    try runHttp(seed);
}
