//! Fuzz target for the HTTP response writer (`cc.live.http_response.write`).
//!
//! Each iteration generates a response (status, header fields, body, `omit_body`, `close`)
//! and a buffer length, then checks `write` against a model kept here, written apart from
//! the writer: its own status table, token and value grammar, reserved-name list and
//! decimal formatting.
//!
//! What a pass proves, every iteration:
//!   - the error is the one the model predicts, in the writer's documented order: the field
//!     count, then each field in turn (too long, name, reserved name, value), then the body
//!     against the buffer, then the whole response against the buffer;
//!   - a field error or a body longer than the buffer leaves the buffer untouched, as
//!     `write` promises ("checks ... before writing anything");
//!   - a success writes exactly the model's bytes and nothing past them;
//!   - nothing past the buffer's end changes, whatever the outcome.
//!
//! Most responses are valid and small. Some fields carry one fault each; some responses
//! sit on a limit: exactly `http_response_headers_max` fields, one more, a buffer of the
//! exact length or one byte short, a response filling a whole response buffer or one byte
//! over, and a HEAD response whose body is larger than the buffer. The run fails with
//! `error.LimitMissed` if any of those never came up.

const std = @import("std");
const assert = std.debug.assert;
const cc = @import("coalition_connection");

const writer = cc.live.http_response;
const size_max: u32 = cc.constants.http_response_size_max;
const fields_max: u32 = cc.constants.http_response_headers_max;

pub const Error = error{ Mismatch, LimitMissed };

/// Bytes after the buffer that must never change.
const guard_bytes: u32 = 64;
/// Fields a generated response may carry: one past the limit.
const fields_generated_max: u32 = fields_max + 1;
const name_len_max: u32 = 24;
const value_len_max: u32 = 48;
const body_small_max: u32 = 512;
/// Extra bytes a random buffer may have past the response's length.
const buffer_slack_max: u32 = 64;

/// The writer's output, plus a guard region after the largest buffer.
var out_backing: [size_max + guard_bytes]u8 = undefined;
/// The model's bytes for a response that fits.
var model_bytes: [size_max]u8 = undefined;
/// Random bytes for bodies; one past `size_max`, so a body can be one byte too long.
var body_source: [size_max + 1]u8 = undefined;
/// 'a' bytes, a valid token and a valid value, for fields one byte longer than any
/// response.
var long_source: [size_max + 1]u8 = undefined;

/// Per-iteration storage for generated names and values.
var names: [fields_generated_max][name_len_max]u8 = undefined;
var values: [fields_generated_max][value_len_max]u8 = undefined;
var fields: [fields_generated_max]writer.Header = undefined;

comptime {
    assert(fields_max > 0);
    // A response of `fields_generated_max` small fields fits well inside a buffer.
    assert(fields_generated_max * (name_len_max + 2 + value_len_max + 2) + 256 < size_max);
}

/// One fault a generated field may carry.
const Fault = enum(u8) {
    none,
    name_empty,
    name_bad_byte,
    name_reserved,
    value_edge_whitespace,
    value_control_byte,
    name_too_long,
    value_too_long,
};

/// The limit an iteration sits on, so the run can show it reached each one.
const Limit = enum(u8) {
    none,
    fields_at_max,
    fields_too_many,
    exact_fit,
    one_short,
    full_buffer_fit,
    full_buffer_one_over,
    omit_body_larger_than_buffer,
};

/// How often each outcome came up. Every count must end above zero.
const Counts = struct {
    limits: [std.enums.values(Limit).len]u32 = @splat(0),
    faults: [std.enums.values(Fault).len]u32 = @splat(0),
    /// Errors the model predicted, by kind, and successes.
    errors: [5]u32 = @splat(0),
    successes: u32 = 0,

    fn reachedAll(self: *const Counts) bool {
        assert(self.successes <= cc.constants.fuzz_iterations_max);
        assert(self.limits.len == std.enums.values(Limit).len);
        for (self.limits[1..]) |count| if (count == 0) return false;
        for (self.faults[1..]) |count| if (count == 0) return false;
        for (self.errors) |count| if (count == 0) return false;
        return self.successes > 0;
    }
};

fn errorIndex(err: writer.Error) u32 {
    const index: u32 = switch (err) {
        error.ResponseTooLarge => 0,
        error.HeadersTooMany => 1,
        error.HeaderNameInvalid => 2,
        error.HeaderValueInvalid => 3,
        error.HeaderReserved => 4,
    };
    assert(index < 5);
    assert((index == 0) == (err == error.ResponseTooLarge));
    return index;
}

// ---- The model -------------------------------------------------------------------------

/// The status line, written here apart from the writer's table (RFC 9110, section 15).
fn modelStatusLine(status: writer.Status) []const u8 {
    const line: []const u8 = switch (status) {
        .ok => "HTTP/1.1 200 OK\r\n",
        .bad_request => "HTTP/1.1 400 Bad Request\r\n",
        .content_too_large => "HTTP/1.1 413 Content Too Large\r\n",
        .request_header_fields_too_large => "HTTP/1.1 431 Request Header Fields Too Large\r\n",
        .not_implemented => "HTTP/1.1 501 Not Implemented\r\n",
        .http_version_not_supported => "HTTP/1.1 505 HTTP Version Not Supported\r\n",
    };
    assert(std.mem.startsWith(u8, line, "HTTP/1.1 "));
    assert(std.mem.endsWith(u8, line, "\r\n"));
    return line;
}

const tchar_symbols = "!#$%&'*+-.^_`|~";

fn modelIsTchar(byte: u8) bool {
    const result = std.ascii.isAlphanumeric(byte) or std.mem.findScalar(u8, tchar_symbols, byte) != null;
    assert(!result or byte > ' ');
    assert(!result or byte < 0x7f);
    return result;
}

fn modelIsToken(text: []const u8) bool {
    assert(text.len <= size_max);
    if (text.len == 0) return false;
    for (text) |byte| if (!modelIsTchar(byte)) return false;
    // A token never holds a byte that ends a header line or its name.
    assert(std.mem.findAny(u8, text, "\r\n: \t") == null);
    return true;
}

fn modelIsValue(text: []const u8) bool {
    assert(text.len <= size_max);
    for (text) |byte| {
        if (byte == 0x7f) return false;
        if (byte < ' ' and byte != '\t') return false;
    }
    if (text.len == 0) return true;
    const edges = [2]u8{ text[0], text[text.len - 1] };
    for (edges) |edge| if (edge == ' ' or edge == '\t') return false;
    assert(std.mem.findAny(u8, text, "\r\n") == null);
    return true;
}

/// Field names the writer must refuse, kept here apart from its own list.
const model_reserved = [_][]const u8{
    "Content-Length", "Transfer-Encoding", "Connection", "Keep-Alive",
    "Upgrade",        "TE",                "Trailer",    "Proxy-Connection",
};

fn modelIsReserved(name: []const u8) bool {
    assert(name.len > 0);
    assert(name.len <= size_max);
    for (model_reserved) |reserved| {
        if (std.ascii.eqlIgnoreCase(name, reserved)) return true;
    }
    return false;
}

/// The error `write` must return before it writes anything, or null.
fn modelEarlyError(response: writer.Response, buffer_len: u32) ?writer.Error {
    assert(buffer_len <= size_max);
    assert(response.headers.len <= fields_generated_max);
    if (response.headers.len > fields_max) return error.HeadersTooMany;
    for (response.headers) |field| {
        if (field.name.len > size_max or field.value.len > size_max) return error.ResponseTooLarge;
        if (!modelIsToken(field.name)) return error.HeaderNameInvalid;
        if (modelIsReserved(field.name)) return error.HeaderReserved;
        if (!modelIsValue(field.value)) return error.HeaderValueInvalid;
    }
    const sent_len: u64 = if (response.omit_body) 0 else response.body.len;
    if (response.body.len > size_max or sent_len > buffer_len) return error.ResponseTooLarge;
    return null;
}

/// The response's full length on the wire, for fields that passed the early checks.
fn modelLength(response: writer.Response) u64 {
    assert(response.headers.len <= fields_max);
    assert(response.body.len <= size_max);
    var length: u64 = modelStatusLine(response.status).len;
    for (response.headers) |field| length += field.name.len + ": ".len + field.value.len + "\r\n".len;
    if (response.close) length += "Connection: close\r\n".len;
    length += "Content-Length: ".len + std.fmt.count("{d}", .{response.body.len}) + "\r\n\r\n".len;
    if (!response.omit_body) length += response.body.len;
    assert(length > response.body.len or response.omit_body);
    return length;
}

/// Writes the model's bytes for a response of `length` bytes into `model_bytes`.
fn modelWrite(response: writer.Response, length: u32) void {
    assert(length <= size_max);
    assert(modelLength(response) == length);
    var len: usize = put(0, modelStatusLine(response.status));
    for (response.headers) |field| {
        len = put(len, field.name);
        len = put(len, ": ");
        len = put(len, field.value);
        len = put(len, "\r\n");
    }
    if (response.close) len = put(len, "Connection: close\r\n");
    // Digits in the largest u64; printInt writes into a buffer this size without an error.
    var digits: [20]u8 = undefined;
    const digits_len = std.fmt.printInt(&digits, response.body.len, 10, .lower, .{});
    len = put(len, "Content-Length: ");
    len = put(len, digits[0..digits_len]);
    len = put(len, "\r\n\r\n");
    if (!response.omit_body) len = put(len, response.body);
    assert(len == length);
}

fn put(len: usize, bytes: []const u8) usize {
    assert(len <= size_max);
    assert(len + bytes.len <= size_max);
    @memcpy(model_bytes[len..][0..bytes.len], bytes);
    return len + bytes.len;
}

// ---- The generator ---------------------------------------------------------------------

fn pickFault(random: std.Random) Fault {
    // One field in 32 carries a fault, spread evenly over the kinds.
    if (random.uintLessThan(u32, 32) != 0) return .none;
    const faults = comptime std.enums.values(Fault);
    const fault = faults[1 + random.uintLessThan(u32, faults.len - 1)];
    assert(fault != .none);
    assert(@backingInt(fault) < faults.len);
    return fault;
}

/// A random valid token of 1 to `name_len_max` bytes in `names[index]`.
fn validName(random: std.Random, index: u32) []const u8 {
    assert(index < fields_generated_max);
    const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" ++ tchar_symbols;
    const len = 1 + random.uintLessThan(u32, name_len_max);
    for (names[index][0..len]) |*byte| byte.* = alphabet[random.uintLessThan(u32, alphabet.len)];
    // "X-" first keeps it clear of the reserved names, which the faults reach on purpose.
    if (len >= 2) @memcpy(names[index][0..2], "X-");
    assert(modelIsToken(names[index][0..len]));
    assert(len < 2 or !modelIsReserved(names[index][0..len]));
    return names[index][0..len];
}

/// A random valid value of 0 to `value_len_max` bytes in `values[index]`: visible ASCII,
/// obs-text, and spaces and tabs inside.
fn validValue(random: std.Random, index: u32) []const u8 {
    assert(index < fields_generated_max);
    const len = random.uintLessThan(u32, value_len_max + 1);
    for (values[index][0..len]) |*byte| {
        byte.* = switch (random.uintLessThan(u32, 8)) {
            0 => ' ',
            1 => '\t',
            2 => 0x80 + random.uintLessThan(u8, 0x80),
            else => '!' + random.uintLessThan(u8, 0x7f - '!'),
        };
    }
    if (len > 0) {
        for ([2]u32{ 0, len - 1 }) |edge| {
            if (values[index][edge] == ' ' or values[index][edge] == '\t') values[index][edge] = 'v';
        }
    }
    assert(modelIsValue(values[index][0..len]));
    assert(len <= value_len_max);
    return values[index][0..len];
}

/// Field `index`, valid or carrying `fault`.
fn genField(random: std.Random, index: u32, fault: Fault) writer.Header {
    assert(index < fields_generated_max);
    var name = validName(random, index);
    var value = validValue(random, index);
    switch (fault) {
        .none => {},
        .name_empty => name = names[index][0..0],
        .name_bad_byte => {
            const bad = " :\t\r\n()<>@,;\\\"/[]?={}\x00\x7f\x80\xff";
            names[index][random.uintLessThan(usize, name.len)] = bad[random.uintLessThan(u32, bad.len)];
        },
        .name_reserved => {
            const reserved = model_reserved[random.uintLessThan(u32, model_reserved.len)];
            for (reserved, names[index][0..reserved.len]) |byte, *out| {
                out.* = if (random.boolean()) std.ascii.toLower(byte) else std.ascii.toUpper(byte);
            }
            name = names[index][0..reserved.len];
        },
        .value_edge_whitespace => {
            if (value.len == 0) value = values[index][0..1];
            const edge = if (random.boolean()) 0 else value.len - 1;
            values[index][edge] = if (random.boolean()) ' ' else '\t';
        },
        .value_control_byte => {
            if (value.len == 0) value = values[index][0..1];
            const control = random.uintLessThan(u8, 33);
            values[index][random.uintLessThan(usize, value.len)] = switch (control) {
                9 => 0x7f, // Tab is allowed, so it stands in for DEL.
                32 => 0x7f,
                else => control,
            };
        },
        .name_too_long => name = &long_source,
        .value_too_long => value = &long_source,
    }
    assert(fault != .none or (modelIsToken(name) and modelIsValue(value)));
    assert(name.len <= size_max + 1 and value.len <= size_max + 1);
    return .{ .name = name, .value = value };
}

/// A body of `len` bytes from a random place in `body_source`.
fn genBody(random: std.Random, len: u32) []const u8 {
    assert(len <= body_source.len);
    const start = random.uintLessThan(u32, @intCast(body_source.len - len + 1));
    const body = body_source[start..][0..len];
    assert(body.len == len);
    assert(start + len <= body_source.len);
    return body;
}

const Case = struct {
    response: writer.Response,
    buffer_len: u32,
    limit: Limit,
};

/// A response with `count` fields, the faults recorded in `counts`.
fn genFields(random: std.Random, count: u32, faults_allowed: bool, counts: *Counts) []const writer.Header {
    assert(count <= fields_generated_max);
    var index: u32 = 0;
    while (index < count) : (index += 1) {
        const fault: Fault = if (faults_allowed) pickFault(random) else .none;
        counts.faults[@backingInt(fault)] += 1;
        fields[index] = genField(random, index, fault);
    }
    assert(index == count);
    return fields[0..count];
}

fn genStatus(random: std.Random) writer.Status {
    const statuses = comptime std.enums.values(writer.Status);
    const status = statuses[random.uintLessThan(u32, statuses.len)];
    assert(modelStatusLine(status).len > "HTTP/1.1 000 \r\n".len);
    assert(@backingInt(status) >= 200);
    return status;
}

/// An everyday case: a few fields, a small body (now and then one near the limit), and a
/// buffer of the exact length, one byte short, or a random length around it.
fn genSmall(random: std.Random, counts: *Counts) Case {
    const shape = random.uintLessThan(u32, 64);
    const count: u32 = switch (shape) {
        0 => fields_max,
        1 => fields_max + 1,
        else => random.uintLessThan(u32, 6),
    };
    var response: writer.Response = .{
        .status = genStatus(random),
        .headers = genFields(random, count, true, counts),
        .omit_body = random.uintLessThan(u32, 8) == 0,
        .close = random.boolean(),
    };
    const large = random.uintLessThan(u32, 128) == 0;
    const body_len = if (large) size_max - 16 + random.uintLessThan(u32, 18) else random.uintLessThan(u32, body_small_max + 1);
    response.body = genBody(random, body_len);
    assert(response.headers.len == count);

    // The buffer is sized from the model's length when the fields pass, else at random.
    const fits_early = modelEarlyError(response, size_max) == null;
    const length: u64 = if (fits_early) modelLength(response) else random.uintLessThan(u32, 4096);
    const capped: u32 = @intCast(@min(length, size_max));
    const buffer_len: u32 = switch (random.uintLessThan(u32, 4)) {
        0 => capped,
        1 => capped -| 1,
        else => @intCast(@min(size_max, random.uintLessThan(u64, capped + buffer_slack_max + 1))),
    };
    assert(buffer_len <= size_max);
    return .{ .response = response, .buffer_len = buffer_len, .limit = .none };
}

/// A response filling a whole response buffer exactly, or one byte over.
fn genFill(random: std.Random, counts: *Counts, over: bool) Case {
    var response: writer.Response = .{
        .status = genStatus(random),
        .headers = genFields(random, random.uintLessThan(u32, 4), false, counts),
        .close = random.boolean(),
    };
    // The body's length has seven digits for any head this small, so the head's length
    // is known before the body is chosen.
    const seven_digits: u32 = 1_000_000;
    response.body = body_source[0..seven_digits];
    const head = modelLength(response) - seven_digits;
    const body_len: u32 = @intCast(size_max - head + @intFromBool(over));
    assert(body_len >= seven_digits and body_len < 10 * seven_digits);
    response.body = genBody(random, body_len);
    assert(modelLength(response) == @as(u64, size_max) + @intFromBool(over));
    return .{
        .response = response,
        .buffer_len = size_max,
        .limit = if (over) .full_buffer_one_over else .full_buffer_fit,
    };
}

// ---- The check -------------------------------------------------------------------------

/// Which limit a case sits on, from its shape and the model.
fn limitOf(case: Case, early: ?writer.Error) Limit {
    assert(case.buffer_len <= size_max);
    assert(case.response.headers.len <= fields_generated_max);
    if (case.limit != .none) return case.limit;
    const response = case.response;
    if (early == null) {
        const length = modelLength(response);
        if (response.headers.len == fields_max and length <= case.buffer_len) return .fields_at_max;
        if (response.omit_body and response.body.len > case.buffer_len and length <= case.buffer_len) {
            return .omit_body_larger_than_buffer;
        }
        if (length == case.buffer_len) return .exact_fit;
        if (length == @as(u64, case.buffer_len) + 1) return .one_short;
    }
    if (early) |err| {
        if (err == error.HeadersTooMany) return .fields_too_many;
    }
    return .none;
}

/// Runs `write` on one case and compares it with the model.
fn check(random: std.Random, case: Case, counts: *Counts) Error!void {
    assert(case.buffer_len <= size_max);
    assert(case.response.headers.len <= fields_generated_max);
    const sentinel = random.int(u8);
    const touched = out_backing[0 .. case.buffer_len + guard_bytes];
    @memset(touched, sentinel);
    const early = modelEarlyError(case.response, case.buffer_len);
    const length: ?u64 = if (early == null) modelLength(case.response) else null;
    const expected: ?writer.Error = early orelse
        if (length.? > case.buffer_len) error.ResponseTooLarge else null;

    const result = writer.write(out_backing[0..case.buffer_len], case.response);
    // Nothing past the buffer ever changes.
    if (!std.mem.allEqual(u8, out_backing[case.buffer_len..][0..guard_bytes], sentinel)) return error.Mismatch;
    if (result) |written| {
        if (expected != null) return error.Mismatch;
        if (written != length.?) return error.Mismatch;
        modelWrite(case.response, written);
        if (!std.mem.eql(u8, out_backing[0..written], model_bytes[0..written])) return error.Mismatch;
        if (!std.mem.allEqual(u8, out_backing[written..case.buffer_len], sentinel)) return error.Mismatch;
        counts.successes += 1;
    } else |err| {
        if (expected == null or expected.? != err) return error.Mismatch;
        // An early error is found before anything is written.
        if (early != null and !std.mem.allEqual(u8, out_backing[0..case.buffer_len], sentinel)) {
            return error.Mismatch;
        }
        counts.errors[errorIndex(err)] += 1;
    }
    counts.limits[@backingInt(limitOf(case, early))] += 1;
}

fn report(counts: *const Counts, seed: u64) void {
    assert(counts.limits.len > 0);
    assert(counts.faults.len > 0);
    std.debug.print("fuzz http_response: seed={d} successes={d}\n", .{ seed, counts.successes });
    for (std.enums.values(Limit), counts.limits) |limit, count| {
        std.debug.print("  {t}={d}", .{ limit, count });
    }
    std.debug.print("\n", .{});
    for (std.enums.values(Fault), counts.faults) |fault, count| {
        std.debug.print("  {t}={d}", .{ fault, count });
    }
    std.debug.print("\n  errors (too large, too many, name, value, reserved)={any}\n", .{counts.errors});
}

pub fn run(seed: u64) Error!void {
    comptime assert(cc.constants.fuzz_iterations_max > 0);
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    random.bytes(&body_source);
    @memset(&long_source, 'a');
    var counts: Counts = .{};

    var iteration: u32 = 0;
    while (iteration < cc.constants.fuzz_iterations_max) : (iteration += 1) {
        const case = switch (random.uintLessThan(u32, 512)) {
            0 => genFill(random, &counts, false),
            1 => genFill(random, &counts, true),
            else => genSmall(random, &counts),
        };
        check(random, case, &counts) catch |err| {
            std.debug.print("fuzz http_response: seed={d} failed at iteration {d}\n", .{ seed, iteration });
            return err;
        };
    }
    assert(iteration == cc.constants.fuzz_iterations_max);
    report(&counts, seed);
    if (!counts.reachedAll()) {
        std.debug.print("fuzz http_response: seed={d} missed a limit, fault or error\n", .{seed});
        return error.LimitMissed;
    }
    std.debug.print("fuzz http_response: seed={d} iterations={d} ok\n", .{ seed, iteration });
}
