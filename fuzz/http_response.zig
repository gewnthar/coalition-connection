//! Fuzz target for the HTTP response writer (`cc.live.http_response.write`).
//!
//! Each iteration generates a response (status, header fields, body, `omit_body`, `close`)
//! and a buffer length, then checks `write` against a model kept here. The token and value
//! grammar and the decimal formatting (std.fmt) are written apart from the writer's. The
//! status table and the reserved-name list are a second copy of RFC 9110 (sections 15 and
//! 7.6.1), checked by hand against it: a mistake shared with the writer's copy would not be
//! seen here. The order of the early checks is the writer's documented one, and the run
//! makes every pair of faults below meet inside one field, so a change to that order fails.
//!
//! What a pass proves, every iteration:
//!   - the outcome is the one the model predicts, in this order: the field count, then each
//!     field in turn (either length too long, then the name, then a reserved name, then the
//!     value), then the body against the buffer, then the whole response against the buffer;
//!   - a field error or a body longer than the buffer leaves the buffer untouched, as
//!     `write` promises ("checks ... before writing anything");
//!   - a success writes exactly the model's bytes and changes nothing after them.
//! The bytes after the buffer are also checked, as defence in depth: `write` gets a slice,
//! so in a safe build a write past it panics first.
//!
//! The run fails with `error.LimitMissed` unless every outcome, every pair of name and value
//! faults deciding an outcome, every Content-Length digit count from 1 to 7, and every limit
//! came up: exactly `http_response_headers_max` fields and one more, a buffer of the exact
//! length and one byte short, a response filling a whole response buffer and one byte over,
//! and a HEAD response whose body is larger than the buffer.

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
/// Extra bytes a random buffer may have past the response's length.
const buffer_slack_max: u32 = 64;
/// Fields a whole-buffer response carries at most.
const fill_fields_max: u32 = 3;
/// Content-Length digit counts the run must write: up to that of `size_max + 1`.
const digits_max: u32 = 7;

/// The writer's output, plus a guard region after the largest buffer.
var out_backing: [size_max + guard_bytes]u8 = undefined;
/// The model's bytes for a response that fits.
var model_bytes: [size_max]u8 = undefined;
/// Random bytes for bodies; one past `size_max`, so a body can be one byte too long.
var body_source: [size_max + 1]u8 = undefined;
/// 'a' bytes, a valid token and a valid value, for fields one byte longer than any
/// response.
var long_source: [size_max + 1]u8 = undefined;
/// Every byte the token grammar refuses, built from the model at the start of the run.
var bad_name_bytes: [256]u8 = undefined;
var bad_name_count: u32 = 0;

/// Per-iteration storage for generated names and values.
var names: [fields_generated_max][name_len_max + 1]u8 = undefined;
var values: [fields_generated_max][value_len_max]u8 = undefined;
var fields: [fields_generated_max]writer.Header = undefined;

/// The longest status line, written by `modelStatusLine`.
const status_line_max: u32 = "HTTP/1.1 431 Request Header Fields Too Large\r\n".len;
/// The longest head a whole-buffer response can have, with a seven-digit Content-Length.
const fill_head_max: u32 = status_line_max + fill_fields_max * (name_len_max + 2 + value_len_max + 2) +
    "Connection: close\r\n".len + "Content-Length: ".len + digits_max + "\r\n\r\n".len;

comptime {
    // `genFill` chooses a body of `size_max - head` bytes, plus one, and assumes its length
    // has seven digits: it must stay in [10^6, 10^7) for every head it can build.
    assert(size_max - fill_head_max >= 1_000_000);
    assert(@as(u64, size_max) + 1 < 10_000_000);
    // `bodyLength` draws up to `digits_max` digits and caps at `size_max + 1`.
    assert(std.math.pow(u64, 10, digits_max - 1) <= size_max);
}

/// A fault in a field's name. `near_reserved` is not a fault: a reserved name with one byte
/// added or removed, which the writer must accept.
const NameFault = enum(u8) { none, empty, bad_byte, reserved, too_long, near_reserved };
/// A fault in a field's value.
const ValueFault = enum(u8) { none, edge_whitespace, control_byte, too_long };

/// The faults one field carries.
const Faults = struct { name: NameFault, value: ValueFault };

const name_faults = std.enums.values(NameFault);
const value_faults = std.enums.values(ValueFault);

/// What `write` returned, split by where a ResponseTooLarge came from.
const Outcome = enum(u8) {
    success,
    fields_too_many,
    field_too_long,
    name_invalid,
    reserved,
    value_invalid,
    body_too_large,
    response_too_large,
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

/// The model's prediction for one case.
const Prediction = struct {
    outcome: Outcome,
    /// The field that decided a field outcome, or null.
    field: ?u32 = null,
};

/// How often each outcome, deciding fault pair, digit count and limit came up.
const Counts = struct {
    outcomes: [std.enums.values(Outcome).len]u32 = @splat(0),
    limits: [std.enums.values(Limit).len]u32 = @splat(0),
    /// [name fault][value fault] of the field that decided a field outcome, or of every
    /// field in a successful response.
    pairs: [name_faults.len][value_faults.len]u32 = @splat(@splat(0)),
    /// Successes by Content-Length digit count, 1 to `digits_max`.
    digits: [digits_max]u32 = @splat(0),

    fn total(self: *const Counts) u64 {
        var sum: u64 = 0;
        for (self.outcomes) |count| sum += count;
        var limits: u64 = 0;
        for (self.limits) |count| limits += count;
        // Every iteration counts one outcome and one limit (`none` included).
        assert(sum == limits);
        assert(sum <= cc.constants.fuzz_iterations_max);
        return sum;
    }

    fn reachedAll(self: *const Counts) bool {
        assert(self.total() == cc.constants.fuzz_iterations_max);
        for (self.outcomes) |count| if (count == 0) return false;
        for (self.limits[1..]) |count| if (count == 0) return false;
        for (self.digits) |count| if (count == 0) return false;
        for (self.pairs, 0..) |row, name| {
            for (row) |count| if (count == 0) return false;
            assert(name < name_faults.len);
        }
        return true;
    }
};

// ---- The model -------------------------------------------------------------------------

/// The status line, a second copy of RFC 9110, section 15.
fn modelStatusLine(status: writer.Status) []const u8 {
    const line: []const u8 = switch (status) {
        .ok => "HTTP/1.1 200 OK\r\n",
        .bad_request => "HTTP/1.1 400 Bad Request\r\n",
        .not_found => "HTTP/1.1 404 Not Found\r\n",
        .method_not_allowed => "HTTP/1.1 405 Method Not Allowed\r\n",
        .content_too_large => "HTTP/1.1 413 Content Too Large\r\n",
        .request_header_fields_too_large => "HTTP/1.1 431 Request Header Fields Too Large\r\n",
        .not_implemented => "HTTP/1.1 501 Not Implemented\r\n",
        .http_version_not_supported => "HTTP/1.1 505 HTTP Version Not Supported\r\n",
    };
    // The code in the line is the enum's value.
    var code: [3]u8 = undefined;
    _ = std.fmt.printInt(&code, @backingInt(status), 10, .lower, .{});
    assert(std.mem.eql(u8, line["HTTP/1.1 ".len..][0..3], &code));
    assert(line.len <= status_line_max);
    return line;
}

const tchar_symbols = "!#$%&'*+-.^_`|~";

fn modelIsTchar(byte: u8) bool {
    const symbol = std.mem.findScalar(u8, tchar_symbols, byte) != null;
    const result = std.ascii.isAlphanumeric(byte) or symbol;
    // RFC 9110 tchar is visible ASCII less the delimiters.
    assert(!result or (byte > ' ' and byte < 0x7f));
    assert(!result or std.mem.findScalar(u8, "\"(),/:;<=>?@[\\]{}", byte) == null);
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

/// Field names the writer must refuse: its own framing fields and the hop-by-hop fields of
/// RFC 9110, section 7.6.1. A second copy of the writer's list.
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

/// The outcome `write` must give before it writes anything, or null.
fn modelEarly(response: writer.Response, buffer_len: u32) ?Prediction {
    assert(buffer_len <= size_max);
    assert(response.headers.len <= fields_generated_max);
    if (response.headers.len > fields_max) return .{ .outcome = .fields_too_many };
    for (response.headers, 0..) |field, index| {
        const at: u32 = @intCast(index);
        if (field.name.len > size_max or field.value.len > size_max) {
            return .{ .outcome = .field_too_long, .field = at };
        }
        if (!modelIsToken(field.name)) return .{ .outcome = .name_invalid, .field = at };
        if (modelIsReserved(field.name)) return .{ .outcome = .reserved, .field = at };
        if (!modelIsValue(field.value)) return .{ .outcome = .value_invalid, .field = at };
    }
    const sent_len: u64 = if (response.omit_body) 0 else response.body.len;
    if (response.body.len > size_max or sent_len > buffer_len) return .{ .outcome = .body_too_large };
    return null;
}

fn digitCount(value: u64) u32 {
    const count: u32 = @intCast(std.fmt.count("{d}", .{value}));
    assert(count >= 1 and count <= 20);
    assert(count == 1 or value >= std.math.pow(u64, 10, count - 1));
    return count;
}

/// The response's full length on the wire, for fields that passed the early checks.
fn modelLength(response: writer.Response) u64 {
    assert(response.headers.len <= fields_max);
    assert(response.body.len <= size_max + 1);
    var length: u64 = modelStatusLine(response.status).len;
    for (response.headers) |field| length += field.name.len + ": ".len + field.value.len + "\r\n".len;
    if (response.close) length += "Connection: close\r\n".len;
    length += "Content-Length: ".len + digitCount(response.body.len) + "\r\n\r\n".len;
    const head = length;
    if (!response.omit_body) length += response.body.len;
    assert(head > "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n".len);
    assert(length - head == if (response.omit_body) 0 else response.body.len);
    return length;
}

/// Writes the model's bytes for a response of `length` bytes into `model_bytes`.
fn modelWrite(response: writer.Response, length: u32) void {
    assert(length <= size_max);
    assert(modelLength(response) == length);
    var len: u32 = put(0, modelStatusLine(response.status));
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

fn put(len: u32, bytes: []const u8) u32 {
    assert(len <= size_max);
    assert(bytes.len <= size_max - len);
    const count: u32 = @intCast(bytes.len);
    @memcpy(model_bytes[len..][0..count], bytes);
    return len + count;
}

/// The byte a scratch region holds at `index` before the call, so a stray write of any
/// one value shows up at most places.
fn pattern(seed: u8, index: u32) u8 {
    const byte: u8 = seed ^ @as(u8, @truncate(index *% 0x9e));
    assert(byte ^ seed == @as(u8, @truncate(index *% 0x9e)));
    assert(index < out_backing.len);
    return byte;
}

fn holdsPattern(seed: u8, start: u32, end: u32) bool {
    assert(start <= end);
    assert(end <= out_backing.len);
    var index = start;
    while (index < end) : (index += 1) {
        if (out_backing[index] != pattern(seed, index)) return false;
    }
    return true;
}

// ---- The generator ---------------------------------------------------------------------

/// A pair of faults for one field. One field in 32 carries a name fault and one in 32 a
/// value fault, independently, and one in 64 carries both, so every pair comes up.
fn pickFaults(random: std.Random) Faults {
    const both = random.uintLessThan(u32, 64) == 0;
    const name: NameFault = if (both or random.uintLessThan(u32, 32) == 0)
        name_faults[1 + random.uintLessThan(u32, name_faults.len - 1)]
    else
        .none;
    const value: ValueFault = if (both or random.uintLessThan(u32, 32) == 0)
        value_faults[1 + random.uintLessThan(u32, value_faults.len - 1)]
    else
        .none;
    assert(!both or name != .none);
    assert(!both or value != .none);
    return .{ .name = name, .value = value };
}

/// A random valid token of 1 to `name_len_max` bytes in `names[index]`, never reserved.
fn validName(random: std.Random, index: u32) []const u8 {
    assert(index < fields_generated_max);
    const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" ++ tchar_symbols;
    const len = 1 + random.uintLessThan(u32, name_len_max);
    for (names[index][0..len]) |*byte| byte.* = alphabet[random.uintLessThan(u32, alphabet.len)];
    // "X-" first keeps two-byte and longer names clear of the reserved ones; the near
    // misses come from their own fault kind.
    if (len >= 2) @memcpy(names[index][0..2], "X-");
    const name = names[index][0..len];
    assert(modelIsToken(name));
    assert(!modelIsReserved(name));
    return name;
}

/// A reserved name, each letter in random case, with one byte added at either end or its
/// last byte dropped: still a token, no longer reserved.
fn nearReserved(random: std.Random, index: u32) []const u8 {
    assert(index < fields_generated_max);
    const reserved = model_reserved[random.uintLessThan(u32, model_reserved.len)];
    const out = &names[index];
    var len: u32 = @intCast(reserved.len);
    const start: u32 = switch (random.uintLessThan(u32, 3)) {
        0 => 0, // A byte after it.
        1 => 1, // A byte before it.
        else => 0, // Its last byte dropped, below.
    };
    for (reserved, out[start..][0..reserved.len]) |byte, *slot| {
        slot.* = if (random.boolean()) std.ascii.toLower(byte) else std.ascii.toUpper(byte);
    }
    const extra = "xX0-_~";
    if (start == 1) {
        out[0] = extra[random.uintLessThan(u32, extra.len)];
        len += 1;
    } else if (random.boolean()) {
        out[len] = extra[random.uintLessThan(u32, extra.len)];
        len += 1;
    } else {
        len -= 1;
    }
    const name = out[0..len];
    assert(modelIsToken(name));
    assert(!modelIsReserved(name));
    return name;
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
    const value = values[index][0..len];
    assert(modelIsValue(value));
    assert(std.mem.findAny(u8, value, "\r\n\x00\x7f") == null);
    return value;
}

fn faultyName(random: std.Random, index: u32, fault: NameFault) []const u8 {
    assert(index < fields_generated_max);
    assert(bad_name_count > 0);
    const name = validName(random, index);
    const result: []const u8 = switch (fault) {
        .none => name,
        .empty => names[index][0..0],
        .bad_byte => bad: {
            const at = random.uintLessThan(u32, @intCast(name.len));
            names[index][at] = bad_name_bytes[random.uintLessThan(u32, bad_name_count)];
            break :bad name;
        },
        .reserved => reserved: {
            const reserved = model_reserved[random.uintLessThan(u32, model_reserved.len)];
            for (reserved, names[index][0..reserved.len]) |byte, *out| {
                out.* = if (random.boolean()) std.ascii.toLower(byte) else std.ascii.toUpper(byte);
            }
            break :reserved names[index][0..reserved.len];
        },
        .too_long => &long_source,
        .near_reserved => nearReserved(random, index),
    };
    assert((fault == .none or fault == .near_reserved) == (result.len > 0 and result.len <= size_max and
        modelIsToken(result) and !modelIsReserved(result)));
    return result;
}

fn faultyValue(random: std.Random, index: u32, fault: ValueFault) []const u8 {
    assert(index < fields_generated_max);
    var value = validValue(random, index);
    // An edge or control fault needs a byte to put it on.
    if (value.len == 0 and fault != .none and fault != .too_long) {
        values[index][0] = 'v';
        value = values[index][0..1];
    }
    switch (fault) {
        .none => {},
        .edge_whitespace => {
            const edge = if (random.boolean()) 0 else value.len - 1;
            values[index][edge] = if (random.boolean()) ' ' else '\t';
        },
        .control_byte => {
            // 0x00 to 0x1f less tab, or DEL: 32 bytes.
            const pick = random.uintLessThan(u8, 32);
            const control: u8 = if (pick == '\t') 0x7f else pick;
            values[index][random.uintLessThan(u32, @intCast(value.len))] = control;
        },
        .too_long => value = &long_source,
    }
    assert((fault == .none) == (value.len <= size_max and modelIsValue(value)));
    assert(value.len <= size_max + 1);
    return value;
}

/// A body of `len` bytes from a random place in `body_source`.
fn genBody(random: std.Random, len: u32) []const u8 {
    assert(len <= body_source.len);
    const start = random.uintLessThan(u32, @intCast(body_source.len - len + 1));
    const body = body_source[start..][0..len];
    assert(@intFromPtr(body.ptr) >= @intFromPtr(&body_source));
    assert(@intFromPtr(body.ptr) + body.len <= @intFromPtr(&body_source) + body_source.len);
    return body;
}

/// A body length: one to four digits mostly, five and six now and then, and in one case of
/// 128 a length within 16 bytes of `size_max` or one past it.
fn bodyLength(random: std.Random) u32 {
    const roll = random.uintLessThan(u32, 128);
    if (roll == 0) return size_max - 16 + random.uintLessThan(u32, 18);
    const digits: u32 = switch (roll) {
        1, 2 => 6,
        3...6 => 5,
        else => 1 + random.uintLessThan(u32, 4),
    };
    const low: u32 = if (digits == 1) 0 else std.math.pow(u32, 10, digits - 1);
    const high: u32 = std.math.pow(u32, 10, digits) - 1;
    const len = random.intRangeAtMost(u32, low, high);
    assert(digitCount(len) == digits);
    assert(len <= size_max + 1);
    return len;
}

const Case = struct {
    response: writer.Response,
    buffer_len: u32,
    limit: Limit,
    /// The faults each field was given.
    faults: [fields_generated_max]Faults,
};

/// `count` fields, recording each field's faults in `case`.
fn genFields(random: std.Random, count: u32, faults_allowed: bool, case: *Case) []const writer.Header {
    assert(count <= fields_generated_max);
    assert(faults_allowed or count <= fill_fields_max);
    var index: u32 = 0;
    while (index < count) : (index += 1) {
        const faults: Faults = if (faults_allowed) pickFaults(random) else .{ .name = .none, .value = .none };
        case.faults[index] = faults;
        fields[index] = .{
            .name = faultyName(random, index, faults.name),
            .value = faultyValue(random, index, faults.value),
        };
    }
    assert(index == count);
    return fields[0..count];
}

fn genStatus(random: std.Random) writer.Status {
    const statuses = comptime std.enums.values(writer.Status);
    const index = random.uintLessThan(u32, statuses.len);
    const status = statuses[index];
    assert(index < statuses.len);
    assert(modelStatusLine(status).len > "HTTP/1.1 000 \r\n".len);
    return status;
}

/// An everyday case: a few fields, a body, and a buffer of the exact length, one byte
/// short, or a random length around it.
fn genSmall(random: std.Random) Case {
    var case: Case = .{ .response = .{ .status = genStatus(random) }, .buffer_len = 0, .limit = .none, .faults = undefined };
    const count: u32 = switch (random.uintLessThan(u32, 64)) {
        0 => fields_max,
        1 => fields_max + 1,
        else => random.uintLessThan(u32, 6),
    };
    case.response.headers = genFields(random, count, true, &case);
    case.response.omit_body = random.uintLessThan(u32, 8) == 0;
    case.response.close = random.boolean();
    case.response.body = genBody(random, bodyLength(random));

    // The buffer is sized from the model's length when the fields pass, else at random.
    const length: u64 = if (modelEarly(case.response, size_max) == null)
        modelLength(case.response)
    else
        random.uintLessThan(u32, 4096);
    const capped: u32 = @intCast(@min(length, size_max));
    case.buffer_len = switch (random.uintLessThan(u32, 4)) {
        0 => capped,
        1 => capped -| 1,
        else => @intCast(@min(size_max, random.uintLessThan(u64, capped + buffer_slack_max + 1))),
    };
    assert(case.buffer_len <= size_max);
    assert(case.response.headers.len == count);
    return case;
}

/// A response filling a whole response buffer exactly, or one byte over.
fn genFill(random: std.Random, over: bool) Case {
    var case: Case = .{ .response = .{ .status = genStatus(random) }, .buffer_len = size_max, .limit = undefined, .faults = undefined };
    case.limit = if (over) .full_buffer_one_over else .full_buffer_fit;
    case.response.headers = genFields(random, random.uintLessThan(u32, fill_fields_max + 1), false, &case);
    case.response.close = random.boolean();
    // The comptime block shows the body's length has seven digits for any head built
    // here, so the head's length is known before the body is chosen.
    const seven_digits: u32 = 1_000_000;
    case.response.body = body_source[0..seven_digits];
    const head = modelLength(case.response) - seven_digits;
    assert(head <= fill_head_max);
    const body_len: u32 = @intCast(size_max - head + @intFromBool(over));
    case.response.body = genBody(random, body_len);
    assert(modelLength(case.response) == @as(u64, size_max) + @intFromBool(over));
    return case;
}

// ---- The check -------------------------------------------------------------------------

/// Which limit a case sits on, from its shape and the model.
fn limitOf(case: *const Case, prediction: Prediction) Limit {
    assert(case.buffer_len <= size_max);
    assert(case.response.headers.len <= fields_generated_max);
    if (case.limit != .none) return case.limit;
    const response = case.response;
    if (prediction.outcome == .fields_too_many) return .fields_too_many;
    const early = prediction.outcome != .success and prediction.outcome != .response_too_large;
    if (early) return .none;
    const length = modelLength(response);
    const fits = length <= case.buffer_len;
    if (response.headers.len == fields_max and fits) return .fields_at_max;
    if (response.omit_body and response.body.len > case.buffer_len and fits) return .omit_body_larger_than_buffer;
    if (length == case.buffer_len) return .exact_fit;
    if (length == @as(u64, case.buffer_len) + 1) return .one_short;
    return .none;
}

fn predict(case: *const Case) Prediction {
    assert(case.buffer_len <= size_max);
    assert(case.response.headers.len <= fields_generated_max);
    if (modelEarly(case.response, case.buffer_len)) |early| return early;
    const fits = modelLength(case.response) <= case.buffer_len;
    return .{ .outcome = if (fits) .success else .response_too_large };
}

fn outcomeOf(err: writer.Error, prediction: Prediction) Outcome {
    // ResponseTooLarge has three sources; the prediction names the one the model expects,
    // and any other prediction makes it a mismatch.
    const outcome: Outcome = switch (err) {
        error.HeadersTooMany => .fields_too_many,
        error.HeaderNameInvalid => .name_invalid,
        error.HeaderValueInvalid => .value_invalid,
        error.HeaderReserved => .reserved,
        error.ResponseTooLarge => switch (prediction.outcome) {
            .field_too_long, .body_too_large, .response_too_large => prediction.outcome,
            else => .response_too_large,
        },
    };
    assert(outcome != .success);
    assert(err == error.ResponseTooLarge or outcome != .response_too_large);
    return outcome;
}

/// Runs `write` on one case and compares it with the model.
fn check(random: std.Random, case: *const Case, counts: *Counts) Error!void {
    assert(case.buffer_len <= size_max);
    assert(case.response.headers.len <= fields_generated_max);
    const seed = random.int(u8);
    const end = case.buffer_len + guard_bytes;
    for (out_backing[0..end], 0..) |*byte, index| byte.* = pattern(seed, @intCast(index));
    const prediction = predict(case);

    const result = writer.write(out_backing[0..case.buffer_len], case.response);
    if (!holdsPattern(seed, case.buffer_len, end)) return error.Mismatch;
    const outcome: Outcome = if (result) |_| .success else |err| outcomeOf(err, prediction);
    if (outcome != prediction.outcome) return error.Mismatch;
    if (result) |written| {
        if (written != modelLength(case.response)) return error.Mismatch;
        modelWrite(case.response, written);
        if (!std.mem.eql(u8, out_backing[0..written], model_bytes[0..written])) return error.Mismatch;
        if (!holdsPattern(seed, written, case.buffer_len)) return error.Mismatch;
        counts.digits[digitCount(case.response.body.len) - 1] += 1;
        for (case.faults[0..case.response.headers.len]) |faults| {
            counts.pairs[@backingInt(faults.name)][@backingInt(faults.value)] += 1;
        }
    } else |_| {
        // An early outcome is decided before anything is written.
        const late = outcome == .response_too_large;
        if (!late and !holdsPattern(seed, 0, case.buffer_len)) return error.Mismatch;
        if (prediction.field) |field| {
            const faults = case.faults[field];
            counts.pairs[@backingInt(faults.name)][@backingInt(faults.value)] += 1;
        }
    }
    counts.outcomes[@backingInt(outcome)] += 1;
    counts.limits[@backingInt(limitOf(case, prediction))] += 1;
}

fn report(counts: *const Counts, seed: u64) void {
    const total = counts.total();
    assert(total == cc.constants.fuzz_iterations_max);
    std.debug.print("fuzz http_response: seed={d} cases={d}\n", .{ seed, total });
    for (std.enums.values(Outcome), counts.outcomes) |outcome, count| std.debug.print("  {t}={d}", .{ outcome, count });
    std.debug.print("\n", .{});
    for (std.enums.values(Limit)[1..], counts.limits[1..]) |limit, count| std.debug.print("  {t}={d}", .{ limit, count });
    std.debug.print("\n  Content-Length digits 1 to {d}: {any}\n", .{ digits_max, counts.digits });
    var pairs_min: u32 = std.math.maxInt(u32);
    for (counts.pairs) |row| {
        for (row) |count| pairs_min = @min(pairs_min, count);
    }
    std.debug.print("  fewest cases for one name and value fault pair: {d}\n", .{pairs_min});
    assert(pairs_min <= total);
}

/// Fills the run's fixed sources: random body bytes, the long field, and the bytes the
/// token grammar refuses.
fn prepare(random: std.Random) void {
    random.bytes(&body_source);
    @memset(&long_source, 'a');
    bad_name_count = 0;
    var byte: u32 = 0;
    while (byte < 256) : (byte += 1) {
        if (modelIsTchar(@intCast(byte))) continue;
        bad_name_bytes[bad_name_count] = @intCast(byte);
        bad_name_count += 1;
    }
    // 77 tchars: 62 letters and digits and 15 symbols.
    assert(bad_name_count == 256 - 62 - tchar_symbols.len);
    assert(modelIsValue(long_source[0..size_max]) and modelIsToken(long_source[0..size_max]));
}

pub fn run(seed: u64) Error!void {
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    prepare(random);
    var counts: Counts = .{};

    var iteration: u32 = 0;
    while (iteration < cc.constants.fuzz_iterations_max) : (iteration += 1) {
        const case = switch (random.uintLessThan(u32, 512)) {
            0 => genFill(random, false),
            1 => genFill(random, true),
            else => genSmall(random),
        };
        check(random, &case, &counts) catch |err| {
            std.debug.print("fuzz http_response: seed={d} failed at iteration {d}\n", .{ seed, iteration });
            return err;
        };
        assert(counts.total() == iteration + 1);
    }
    report(&counts, seed);
    if (!counts.reachedAll()) {
        std.debug.print("fuzz http_response: seed={d} missed an outcome, fault pair, digit count or limit\n", .{seed});
        return error.LimitMissed;
    }
    std.debug.print("fuzz http_response: seed={d} iterations={d} ok\n", .{ seed, iteration });
}
