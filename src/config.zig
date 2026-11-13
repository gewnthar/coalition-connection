//! Config file (roadmap core 8): the settings the server reads once at startup.
//!
//! Job:
//!   Read one ZON file into a fixed buffer, parse it, and check every value against its
//!   limit in src/constants.zig, so a bad file stops the server before it serves anything.
//!
//! Inputs:
//!   The file's path, and a `StartupAllocator` for the file buffer and the parser's scratch
//!   memory. Both are freed again before `load` returns, so startup ends with only the
//!   `Config` value itself.
//!
//! Outputs:
//!   A `Config`, or a named error for each way the file can be wrong. A syntax error is
//!   logged by line and column only, never with the file's text or the parser's message,
//!   because a message can quote what it rejected.
//!
//! Limits (src/constants.zig):
//!   config_file_size_max: the largest file.
//!   config_parse_scratch_size_max: the parser's working memory, a fixed region.
//!   config_socket_path_max: the longest local socket path (Linux `sun_path`).
//!   config_read_attempts_max: read calls for one file.
//!   config_fields_max: the most fields the file may hold.
//!   http_connections_max: the largest connection limit the file may set.
//!
//! The file holds only what the first release needs: where the local socket lives, which
//! nginx reaches, and how many client connections to accept. For example:
//!
//!   .{
//!       .socket_path = "/run/coalition-connection/app.sock",
//!       .connections_max = 1024,
//!   }
//!
//! Every field is required and unknown fields are refused, so a typo can't silently fall
//! back to a default.
//!
//! Before the standard library's ZON parser sees the file, `prescan` checks it has exactly
//! that shape: one flat struct literal of at most `config_fields_max` fields, each a string
//! or a number, in ASCII outside strings and comments (so no byte-order mark). The parser
//! recurses through nested expressions, and a few kilobytes of `(` alone overflow its
//! stack, so a loop of our own keeps everything it is given shallow and small.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const constants = @import("constants.zig");

const file_size_max = constants.config_file_size_max;
const scratch_size_max = constants.config_parse_scratch_size_max;
const socket_path_max = constants.config_socket_path_max;

comptime {
    assert(file_size_max > 0);
    assert(scratch_size_max > file_size_max);
    // The socket path's length is kept in a u8.
    assert(socket_path_max > 0 and socket_path_max <= std.math.maxInt(u8));
    assert(constants.config_read_attempts_max > 0);
    assert(constants.config_fields_max > 0);
}

comptime {
    // The memory table's row is exactly what load takes.
    assert(load_bytes == constants.config_load_bytes_max);
}

pub const ReadError = error{
    /// The file could not be opened or is not a regular file: missing, not readable, a
    /// directory, device or FIFO, or the process is out of descriptors or memory.
    ConfigUnavailable,
    /// A read failed part way (an I/O error), or the file took more than
    /// `config_read_attempts_max` read calls (short reads or signals).
    ConfigReadFailed,
    /// The file is larger than `config_file_size_max`.
    ConfigTooLarge,
};

pub const ParseError = error{
    /// Not valid ZON for a `Config`: bad syntax, a missing, unknown or mistyped field.
    ConfigSyntax,
    /// The parser needed more than `config_parse_scratch_size_max` bytes of working memory.
    ConfigTooComplex,
    /// More fields than `config_fields_max`.
    ConfigTooManyFields,
    /// The socket path is the empty string.
    SocketPathEmpty,
    /// The socket path is longer than `config_socket_path_max`.
    SocketPathTooLong,
    /// The socket path doesn't start with `/`, so it would depend on the working directory.
    /// A network address (`0.0.0.0:8080`) or an abstract socket name lands here too: the
    /// server listens only on a local socket file.
    SocketPathNotAbsolute,
    /// The path holds a NUL byte, which would cut it short at the kernel.
    SocketPathHasNul,
    /// A connection limit of 0, which would refuse every client.
    ConnectionsZero,
    /// More connections than `http_connections_max`, the table's compile-time size.
    ConnectionsOverMax,
};

pub const LoadError = ReadError || ParseError || error{OutOfMemory};

/// Bytes `load` takes from the startup allocator, and gives back before it returns: the
/// file buffer (one byte past the limit, so an oversized file is seen, plus the parser's
/// sentinel) and the parser's scratch. The memory table's row is this number.
pub const load_bytes: u64 = file_buffer_size + scratch_size_max;

const file_buffer_size: u32 = file_size_max + 2;

/// Where the parser stopped on a syntax error: the first error's line and column, both
/// from 1, and how many errors it found. Zero everywhere when there was none.
pub const SyntaxReport = struct {
    line: u32 = 0,
    column: u32 = 0,
    errors: u32 = 0,
};

pub const Config = struct {
    socket_path_bytes: [socket_path_max]u8,
    socket_path_len: u8,
    connections_max: u32,

    pub fn socketPath(self: *const Config) []const u8 {
        assert(self.socket_path_len > 0);
        assert(self.socket_path_len <= socket_path_max);
        return self.socket_path_bytes[0..self.socket_path_len];
    }
};

/// The file's shape, as the ZON parser sees it. The path is a slice into the parser's
/// scratch memory, so it is checked and copied into a `Config` before that memory goes.
const FileFields = struct {
    socket_path: []const u8,
    connections_max: u32,
};

/// Reads and parses the config file at `path`, using `startup` for the file buffer and the
/// parser's scratch memory and freeing both before it returns.
pub fn load(startup: std.mem.Allocator, path: [:0]const u8) LoadError!Config {
    assert(path.len > 0);
    const buffer = try startup.alloc(u8, file_buffer_size);
    defer startup.free(buffer);
    const scratch = try startup.alloc(u8, scratch_size_max);
    defer startup.free(scratch);

    const source = try readFile(path, buffer);
    // The source is the start of the buffer, and the parser's sentinel follows it.
    assert(source.ptr == buffer.ptr and buffer[source.len] == 0);
    var report: SyntaxReport = .{};
    const config = parse(source, scratch, &report) catch |err| {
        if (err == error.ConfigSyntax) {
            assert(report.errors > 0);
            std.log.err("config {s}:{d}:{d}: not a valid config ({d} errors)", .{
                path, report.line, report.column, report.errors,
            });
        }
        return err;
    };
    assert(report.errors == 0);
    return config;
}

/// Reads the whole file at `path` into `buffer`, NUL-terminated. `buffer` must hold
/// `file_buffer_size` bytes: room to see one byte too many, and the sentinel.
pub fn readFile(path: [:0]const u8, buffer: []u8) ReadError![:0]const u8 {
    assert(path.len > 0);
    assert(buffer.len == file_buffer_size);
    // Non-blocking, so a FIFO at the path can't stall startup in open.
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOCTTY = true, .NONBLOCK = true };
    const open_rc = linux.open(path, flags, 0);
    const fd: linux.fd_t = switch (linux.errno(open_rc)) {
        .SUCCESS => @intCast(open_rc),
        else => return error.ConfigUnavailable,
    };
    defer _ = linux.close(fd);
    if (!isRegularFile(fd)) return error.ConfigUnavailable;

    const room = buffer[0 .. file_size_max + 1];
    const len = try readAll(fd, room);
    assert(len <= room.len);
    if (len > file_size_max) return error.ConfigTooLarge;
    buffer[len] = 0;
    return buffer[0..len :0];
}

/// Whether `fd` is a regular file: not a directory, FIFO, socket or device, any of which
/// could block or never end.
fn isRegularFile(fd: linux.fd_t) bool {
    assert(fd >= 0);
    var status: linux.Statx = undefined;
    const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &status);
    if (linux.errno(rc) != .SUCCESS) return false;
    if (!status.mask.TYPE) return false;
    // The kernel filled in the type it said it did.
    assert(status.mode & linux.S.IFMT != 0);
    return linux.S.ISREG(status.mode);
}

/// Reads from `fd` until end of file or until `room` is full, and returns the bytes read.
fn readAll(fd: linux.fd_t, room: []u8) ReadError!u32 {
    assert(fd >= 0);
    assert(room.len > 0 and room.len <= std.math.maxInt(u32));
    var len: u32 = 0;
    var attempts: u32 = 0;
    while (len < room.len) : (attempts += 1) {
        if (attempts == constants.config_read_attempts_max) return error.ConfigReadFailed;
        const rest = room[len..];
        const rc = linux.read(fd, rest.ptr, rest.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) break; // End of file.
                assert(rc <= rest.len); // read never reports more than it was given.
                len += @intCast(rc);
            },
            .INTR => {},
            // EIO and the rest: the file can't be read whole.
            else => return error.ConfigReadFailed,
        }
    }
    assert(attempts <= constants.config_read_attempts_max);
    assert(len <= room.len);
    return len;
}

/// Parses `source` into a `Config`, with `scratch` as the parser's only memory. On a syntax
/// error `report` says where; it is left untouched otherwise.
pub fn parse(source: [:0]const u8, scratch: []u8, report: *SyntaxReport) ParseError!Config {
    assert(source.len <= file_size_max);
    // Tests pass a smaller region to reach ConfigTooComplex.
    assert(scratch.len > 0 and scratch.len <= scratch_size_max);
    assert(report.errors == 0);
    try prescan(source, report);
    // The parser's scratch and its results share one fixed region, freed as a whole when
    // this returns: nothing it allocates outlives the call.
    var fixed: std.heap.FixedBufferAllocator = .init(scratch);
    var diagnostics: std.zon.parse.Diagnostics = undefined;
    const fields = std.zon.parse.fromSlice(FileFields, .{
        .gpa = fixed.allocator(),
        .arena = fixed.allocator(),
        .source = source,
        .diagnostics = &diagnostics,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.ConfigTooComplex,
        error.ParseZon => {
            reportSyntax(&diagnostics, report);
            return error.ConfigSyntax;
        },
    };
    // The path the parser returns lives in the scratch region, and is copied out by check.
    assert(@intFromPtr(fields.socket_path.ptr) >= @intFromPtr(scratch.ptr) or fields.socket_path.len == 0);
    return check(fields);
}

/// The prescan's place in the file. It reads the one shape a config file may have, a flat
/// struct literal of `.name = value` fields whose values are strings or numbers, with
/// spaces, tabs, line breaks and `//` comments between tokens.
const Shape = struct {
    source: [:0]const u8,
    index: u32 = 0,
    line: u32 = 1,
    line_start: u32 = 0,
    report: *SyntaxReport,

    fn peek(shape: *const Shape) u8 {
        assert(shape.index <= shape.source.len);
        // Past the end, the sentinel 0 reads as a byte no rule accepts.
        const byte = shape.source[shape.index];
        assert(shape.index < shape.source.len or byte == 0);
        return byte;
    }

    fn fail(shape: *const Shape) ParseError {
        assert(shape.index >= shape.line_start);
        assert(shape.report.errors == 0);
        shape.report.* = .{ .line = shape.line, .column = shape.index - shape.line_start + 1, .errors = 1 };
        return error.ConfigSyntax;
    }

    fn expect(shape: *Shape, byte: u8) ParseError!void {
        assert(byte != 0);
        if (shape.peek() != byte) return shape.fail();
        shape.index += 1;
        assert(shape.source[shape.index - 1] == byte);
    }

    fn newline(shape: *Shape) void {
        assert(shape.source[shape.index] == '\n');
        shape.index += 1;
        shape.line += 1;
        shape.line_start = shape.index;
        assert(shape.source[shape.line_start - 1] == '\n');
    }

    /// Skips spaces, tabs, line breaks (LF, or CR LF) and `//` comments.
    fn skipSpace(shape: *Shape) ParseError!void {
        const len: u32 = @intCast(shape.source.len);
        assert(shape.index <= len);
        const index_before = shape.index;
        while (shape.index < len) {
            const byte = shape.peek();
            if (byte == ' ' or byte == '\t') {
                shape.index += 1;
            } else if (byte == '\n') {
                shape.newline();
            } else if (byte == '\r') {
                if (shape.source[shape.index + 1] != '\n') return shape.fail();
                shape.index += 1;
            } else if (byte == '/' and shape.source[shape.index + 1] == '/') {
                try shape.skipComment();
            } else break;
        }
        assert(shape.index >= index_before and shape.index <= len);
    }

    /// Skips a `//` comment up to its line break. A comment may hold any byte but control
    /// characters other than tab, which the ZON tokenizer refuses there too. Doc comments
    /// (`///` and `//!`) are tokens to the tokenizer, not space, so they are refused.
    fn skipComment(shape: *Shape) ParseError!void {
        const len: u32 = @intCast(shape.source.len);
        assert(shape.peek() == '/');
        const third = shape.source[shape.index + 2];
        const doc = third == '!' or (third == '/' and shape.source[shape.index + 3] != '/');
        if (doc) return shape.fail();
        shape.index += 2;
        while (shape.index < len) : (shape.index += 1) {
            const byte = shape.peek();
            if (byte == '\n') break;
            if (byte == '\r' and shape.source[shape.index + 1] == '\n') continue;
            if (comment_refused[byte]) return shape.fail();
        }
        // Stopped at the line break or the end of the file.
        assert(shape.peek() == '\n' or shape.index == len);
    }

    /// A field name: a letter or `_`, then letters, digits and `_`.
    fn name(shape: *Shape) ParseError!void {
        const start = shape.index;
        switch (shape.peek()) {
            'a'...'z', 'A'...'Z', '_' => shape.index += 1,
            else => return shape.fail(),
        }
        const len: u32 = @intCast(shape.source.len);
        while (shape.index < len) : (shape.index += 1) {
            if (!word_bytes[shape.peek()]) break;
        }
        assert(shape.index > start);
        assert(!word_bytes[shape.peek()]); // Stopped at the first byte past the name.
    }

    /// A string on one line, or a number: a digit, then digits, letters and `_` (the parser
    /// checks which numbers are real). No `.`, so the tokenizer always sees one number token
    /// and never a field-access chain. No other value is ever needed.
    fn value(shape: *Shape) ParseError!void {
        const start = shape.index;
        const len: u32 = @intCast(shape.source.len);
        switch (shape.peek()) {
            '"' => try shape.string(),
            '0'...'9' => while (shape.index < len) : (shape.index += 1) {
                if (!word_bytes[shape.peek()]) break;
            },
            else => return shape.fail(),
        }
        assert(shape.index > start);
        // A string ends past its closing quote; a number at its first byte past the token.
        assert(shape.source[shape.index - 1] == '"' or !word_bytes[shape.peek()]);
    }

    fn string(shape: *Shape) ParseError!void {
        const len: u32 = @intCast(shape.source.len);
        assert(shape.peek() == '"'); // value checked the opening quote.
        try shape.expect('"');
        while (shape.index < len) : (shape.index += 1) {
            const byte = shape.peek();
            if (byte == '"') break;
            if (string_refused[byte]) return shape.fail();
            // An escape takes the next byte too, which must not end the line.
            if (byte == '\\') {
                shape.index += 1;
                if (shape.index == len or string_refused[shape.peek()]) return shape.fail();
            }
        }
        try shape.expect('"');
        assert(shape.source[shape.index - 1] == '"');
    }
};

/// Bytes no comment may hold: control characters other than tab, and DEL. The ZON
/// tokenizer refuses them there too.
const comment_refused: [256]bool = table: {
    var table: [256]bool = @splat(false);
    for (0..0x20) |byte| table[byte] = byte != '\t';
    table[0x7f] = true;
    break :table table;
};

/// Bytes no string may hold: every control character, tab included, and DEL, as the ZON
/// tokenizer has it.
const string_refused: [256]bool = table: {
    var table: [256]bool = @splat(false);
    for (0..0x20) |byte| table[byte] = true;
    table[0x7f] = true;
    break :table table;
};

/// Bytes a field name or a number may continue with: letters, digits and `_`.
const word_bytes: [256]bool = table: {
    var table: [256]bool = @splat(false);
    for ('a'..'z' + 1) |byte| table[byte] = true;
    for ('A'..'Z' + 1) |byte| table[byte] = true;
    for ('0'..'9' + 1) |byte| table[byte] = true;
    table['_'] = true;
    break :table table;
};

/// Refuses, before the ZON parser runs, anything but a flat struct literal of at most
/// `config_fields_max` fields with string or number values. The standard library's parser
/// recurses through nested expressions and recovers from errors inside containers, so a
/// few kilobytes of the wrong input overflow its stack; this loop of our own keeps every
/// input it accepts shallow and small.
fn prescan(source: [:0]const u8, report: *SyntaxReport) ParseError!void {
    assert(source.len <= file_size_max);
    assert(report.errors == 0);
    var shape: Shape = .{ .source = source, .report = report };
    try shape.skipSpace();
    try shape.expect('.');
    try shape.expect('{');
    var fields: u32 = 0;
    while (fields <= constants.config_fields_max) {
        try shape.skipSpace();
        if (shape.peek() == '}') break;
        if (fields == constants.config_fields_max) return error.ConfigTooManyFields;
        try shape.expect('.');
        try shape.name();
        try shape.skipSpace();
        try shape.expect('=');
        try shape.skipSpace();
        try shape.value();
        fields += 1;
        try shape.skipSpace();
        if (shape.peek() != ',') break;
        shape.index += 1;
    }
    assert(fields <= constants.config_fields_max);
    try shape.expect('}');
    try shape.skipSpace();
    if (shape.index != source.len) return shape.fail();
    assert(report.errors == 0);
}

/// Copies where the parser stopped into `report`, without any of the file's text.
fn reportSyntax(diagnostics: *const std.zon.parse.Diagnostics, report: *SyntaxReport) void {
    // The parser reports at least one error whenever it fails with ParseZon.
    assert(diagnostics.errors.len > 0);
    assert(report.errors == 0);
    const first = diagnostics.errors[0];
    report.* = .{
        .line = saturate(first.loc.line) +| 1,
        .column = saturate(first.loc.column) +| 1,
        .errors = saturate(diagnostics.errors.len),
    };
    assert(report.errors > 0 and report.line > 0);
}

fn saturate(value: usize) u32 {
    const result: u32 = std.math.cast(u32, value) orelse std.math.maxInt(u32);
    assert(result <= value);
    assert(result == value or result == std.math.maxInt(u32));
    return result;
}

/// Checks each field against its limit and copies the path out of the parser's memory.
fn check(fields: FileFields) ParseError!Config {
    const path = fields.socket_path;
    if (path.len == 0) return error.SocketPathEmpty;
    if (path.len > socket_path_max) return error.SocketPathTooLong;
    if (path[0] != '/') return error.SocketPathNotAbsolute;
    if (std.mem.findScalar(u8, path, 0) != null) return error.SocketPathHasNul;
    if (fields.connections_max == 0) return error.ConnectionsZero;
    if (fields.connections_max > constants.http_connections_max) return error.ConnectionsOverMax;

    var config: Config = .{
        .socket_path_bytes = @splat(0),
        .socket_path_len = @intCast(path.len),
        .connections_max = fields.connections_max,
    };
    @memcpy(config.socket_path_bytes[0..path.len], path);
    assert(std.mem.eql(u8, config.socketPath(), path));
    assert(config.connections_max > 0 and config.connections_max <= constants.http_connections_max);
    return config;
}

const testing = std.testing;
const StartupAllocator = @import("startup_allocator.zig").StartupAllocator;

const valid_source =
    \\.{
    \\    .socket_path = "/run/coalition-connection/app.sock",
    \\    .connections_max = 1024,
    \\}
;

/// The test's scratch region, as large as the server's.
var test_scratch: [scratch_size_max]u8 = undefined;

fn parseTest(source: [:0]const u8) ParseError!Config {
    assert(source.len <= file_size_max);
    var report: SyntaxReport = .{};
    const result = parse(source, &test_scratch, &report);
    const syntax = if (result) |_| false else |err| err == error.ConfigSyntax;
    // A report is written exactly when the answer is a syntax error.
    assert(syntax == (report.errors > 0));
    return result;
}

test "config: a valid file parses to its values" {
    const config = try parseTest(valid_source);
    try testing.expectEqualStrings("/run/coalition-connection/app.sock", config.socketPath());
    try testing.expectEqual(@as(u32, 1024), config.connections_max);
}

test "config: limits at their maximum are accepted" {
    const a_run: [socket_path_max - 1]u8 = @splat('a');
    const path = "/" ++ a_run;
    const source = std.fmt.comptimePrint(".{{ .socket_path = \"{s}\", .connections_max = {d} }}", .{
        path, constants.http_connections_max,
    });
    const config = try parseTest(source);
    try testing.expectEqualStrings(path, config.socketPath());
    try testing.expectEqual(constants.http_connections_max, config.connections_max);
}

test "config: each bad value has its own error" {
    const a_run: [socket_path_max]u8 = @splat('a');
    const cases = [_]struct { source: [:0]const u8, expected: ParseError }{
        .{ .source = ".{ .socket_path = \"\", .connections_max = 1 }", .expected = error.SocketPathEmpty },
        .{ .source = ".{ .socket_path = \"run/app.sock\", .connections_max = 1 }", .expected = error.SocketPathNotAbsolute },
        .{ .source = ".{ .socket_path = \"/run/a\\x00b\", .connections_max = 1 }", .expected = error.SocketPathHasNul },
        .{ .source = ".{ .socket_path = \"/run/app.sock\", .connections_max = 0 }", .expected = error.ConnectionsZero },
        .{
            .source = std.fmt.comptimePrint(".{{ .socket_path = \"/run/app.sock\", .connections_max = {d} }}", .{
                constants.http_connections_max + 1,
            }),
            .expected = error.ConnectionsOverMax,
        },
        .{
            .source = ".{ .socket_path = \"/" ++ a_run ++ "\", .connections_max = 1 }",
            .expected = error.SocketPathTooLong,
        },
    };
    for (cases) |case| try testing.expectError(case.expected, parseTest(case.source));
}

test "config: a network address in place of the socket path is SocketPathNotAbsolute" {
    // The server listens only on a local socket, so the field takes a path and nothing else.
    const sources = [_][:0]const u8{
        ".{ .socket_path = \"0.0.0.0:8080\", .connections_max = 1 }",
        ".{ .socket_path = \"127.0.0.1:8080\", .connections_max = 1 }",
        ".{ .socket_path = \"[::]:443\", .connections_max = 1 }",
        ".{ .socket_path = \"localhost:8080\", .connections_max = 1 }",
        ".{ .socket_path = \"tcp://0.0.0.0:80\", .connections_max = 1 }",
        ".{ .socket_path = \"unix:/run/app.sock\", .connections_max = 1 }",
        ".{ .socket_path = \"\\x00app\", .connections_max = 1 }",
    };
    for (sources) |source| try testing.expectError(error.SocketPathNotAbsolute, parseTest(source));
}

test "config: bad syntax, missing, unknown and mistyped fields are syntax errors" {
    const sources = [_][:0]const u8{
        "",
        ".{ .socket_path = \"/run/app.sock\", .connections_max = 1",
        ".{ .socket_path = \"/run/app.sock\" }",
        ".{ .connections_max = 1 }",
        ".{ .socket_path = \"/run/app.sock\", .connections_max = 1, .port = 80 }",
        ".{ .socket_path = 7, .connections_max = 1 }",
        ".{ .socket_path = \"/run/app.sock\", .connections_max = -1 }",
        ".{ .socket_path = \"/run/app.sock\", .connections_max = 4294967296 }",
        ".{ .socket_path = \"/run/app.sock\", .connections_max = 1.5 }",
    };
    for (sources) |source| try testing.expectError(error.ConfigSyntax, parseTest(source));
}

test "config: a syntax error reports its line and column" {
    var report: SyntaxReport = .{};
    const source = ".{\n    .socket_path = \"/run/app.sock\",\n    .connections_max = 1,\n    .port = 80,\n}";
    try testing.expectError(error.ConfigSyntax, parse(source, &test_scratch, &report));
    try testing.expectEqual(@as(u32, 4), report.line);
    try testing.expect(report.column > 0);
    try testing.expect(report.errors > 0);
}

test "config: too little scratch memory is ConfigTooComplex, not a crash" {
    var small: [64]u8 = undefined;
    var report: SyntaxReport = .{};
    try testing.expectError(error.ConfigTooComplex, parse(valid_source, &small, &report));
    try testing.expectEqual(@as(u32, 0), report.errors);
}

test "config: comments, tabs, CR LF and strings holding any printable byte are accepted" {
    const source = "// The local socket nginx reaches: (any [text] {here} is fine) -!\r\n" ++
        ".{\r\n\t.socket_path = \"/run/a (b) [c] {d} \\\"e\\\" \\\\ !\", // trailing note\n" ++
        "\t.connections_max = 8 , }\n// done";
    const config = try parseTest(source);
    try testing.expectEqualStrings("/run/a (b) [c] {d} \"e\" \\ !", config.socketPath());
}

test "config: anything but the flat shape is a syntax error at its own place" {
    const cases = [_]struct { source: [:0]const u8, line: u32, column: u32 }{
        .{ .source = ".{\n  .socket_path = \"/run/app.sock\",\n  .connections_max = (1),\n}", .line = 3, .column = 22 },
        .{ .source = "// a comment line\n.{ .connections_max = -1 }", .line = 2, .column = 23 },
        .{ .source = ".{ .a = .{} }", .line = 1, .column = 9 },
        .{ .source = ".{ .a = 1 } / x", .line = 1, .column = 13 },
        .{ .source = ".{ .a = true }", .line = 1, .column = 9 },
        .{ .source = ".{ a = 1 }", .line = 1, .column = 4 },
        .{ .source = "struct { }", .line = 1, .column = 1 },
        .{ .source = ".{ .a = \"x\n\" }", .line = 1, .column = 11 },
        .{ .source = ".{ .a = \"x\\\n\" }", .line = 1, .column = 12 },
        .{ .source = ".{ .a = 1 }\r.", .line = 1, .column = 12 },
        .{ .source = ".{ .a = 1 } // bell \x07", .line = 1, .column = 21 },
        .{ .source = ".{ .a = 1 }}", .line = 1, .column = 12 },
        .{ .source = ".{ .a = 1 .b = 2 }", .line = 1, .column = 11 },
        // A dot in a number would let the tokenizer see a chain of field accesses.
        .{ .source = ".{ .a = 1.a.a }", .line = 1, .column = 10 },
        .{ .source = ".{ .a = 1.5 }", .line = 1, .column = 10 },
        // Doc comments are tokens, not space; four slashes are a plain comment again.
        .{ .source = "/// doc\n.{}", .line = 1, .column = 1 },
        .{ .source = ".{} //! doc", .line = 1, .column = 5 },
        .{ .source = "//// plain\n.{ .a = \"\t\" }", .line = 2, .column = 10 },
    };
    for (cases) |case| {
        var report: SyntaxReport = .{};
        try testing.expectError(error.ConfigSyntax, parse(case.source, &test_scratch, &report));
        try testing.expectEqual(SyntaxReport{ .line = case.line, .column = case.column, .errors = 1 }, report);
    }
}

test "config: inputs that overflow the ZON parser's stack are refused before it runs" {
    // Each of these, filling the file, sends the standard library's recursive parser
    // thousands of levels deep; the escaped line break hid the rest from an earlier,
    // looser prescan, and the parser's error recovery inside `struct` then reached it.
    const fills = [_][]const u8{ "(", "struct{\"\\\nconst a=", "try ", "comptime ", ".{.a=" };
    for (fills) |fill| {
        var source: [file_size_max:0]u8 = undefined;
        @memcpy(source[0..fill.len], fill);
        @memset(source[fill.len..], fill[fill.len - 1]);
        source[file_size_max] = 0;
        var report: SyntaxReport = .{};
        try testing.expectError(error.ConfigSyntax, parse(&source, &test_scratch, &report));
        try testing.expect(report.errors == 1);
    }
}

/// Test helper: prints at `len` in `buffer` and returns the new length.
fn printAt(buffer: []u8, len: u32, comptime format: []const u8, args: anytype) !u32 {
    assert(len <= buffer.len);
    const written = try std.fmt.bufPrint(buffer[len..], format, args);
    const new_len = len + @as(u32, @intCast(written.len));
    assert(new_len <= buffer.len);
    return new_len;
}

test "config: more fields than the limit is ConfigTooManyFields; at the limit it reaches the parser" {
    var source: [file_size_max:0]u8 = undefined;
    var len = try printAt(&source, 0, ".{{", .{});
    var field: u32 = 0;
    while (field < constants.config_fields_max) : (field += 1) {
        len = try printAt(&source, len, " .f{d} = 1,", .{field});
    }
    const at_limit_len = len;
    len = try printAt(&source, len, " }}", .{});
    source[len] = 0;
    // Sixteen unknown fields: the parser refuses them, which proves the prescan let them by.
    try testing.expectError(error.ConfigSyntax, parseTest(source[0..len :0]));
    len = try printAt(&source, at_limit_len, " .x = 1 }}", .{});
    source[len] = 0;
    try testing.expectError(error.ConfigTooManyFields, parseTest(source[0..len :0]));
}

test "config: the largest files the prescan accepts fit the scratch region" {
    // The heaviest shapes for the parser: the most fields with the longest names, one
    // string of nothing but escapes, and one number of thousands of digits.
    var source: [file_size_max:0]u8 = undefined;
    const shapes = [_]struct { head: []const u8, fill: u8, tail: []const u8 }{
        .{ .head = ".{ .socket_path = \"", .fill = 'a', .tail = "\", .connections_max = 1 }" },
        .{ .head = ".{ .socket_path = \"/", .fill = 0, .tail = "\", .connections_max = 1 }" },
        .{ .head = ".{ .socket_path = \"/r\", .connections_max = 1", .fill = '0', .tail = " }" },
        .{ .head = ".{ .", .fill = 'n', .tail = " = 1 }" },
    };
    for (shapes) |shape| {
        @memcpy(source[0..shape.head.len], shape.head);
        const fill_end = file_size_max - shape.tail.len;
        if (shape.fill == 0) {
            // \x41 escapes, four bytes each.
            var index: u32 = @intCast(shape.head.len);
            while (index + 4 <= fill_end) : (index += 4) @memcpy(source[index..][0..4], "\\x41");
            @memset(source[index..fill_end], 'b');
        } else @memset(source[shape.head.len..fill_end], shape.fill);
        @memcpy(source[fill_end..file_size_max], shape.tail);
        source[file_size_max] = 0;
        const result = parseTest(&source);
        if (result) |_| {} else |err| try testing.expect(err != error.ConfigTooComplex);
    }
    // Sixteen fields with names as long as the file allows.
    var len: u32 = 2;
    @memcpy(source[0..2], ".{");
    const name_len: u32 = (file_size_max - 8 - constants.config_fields_max * 8) / constants.config_fields_max;
    var field: u32 = 0;
    while (field < constants.config_fields_max) : (field += 1) {
        source[len] = '.';
        @memset(source[len + 1 ..][0..name_len], 'a' + @as(u8, @intCast(field)));
        len += 1 + name_len;
        @memcpy(source[len..][0..5], " = 1,");
        len += 5;
    }
    source[len] = '}';
    source[len + 1] = 0;
    const result = parseTest(source[0 .. len + 1 :0]);
    try testing.expectError(error.ConfigSyntax, result);
}

/// A file holding `bytes`, with no name on disk: a memfd, read back through its
/// /proc/self/fd path. The caller closes `fd`.
const TestFile = struct {
    fd: linux.fd_t,
    path_bytes: [32:0]u8,

    fn init(bytes: []const u8) !TestFile {
        const rc = linux.memfd_create("config-test", linux.MFD.CLOEXEC);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
        var file: TestFile = .{ .fd = @intCast(rc), .path_bytes = @splat(0) };
        errdefer _ = linux.close(file.fd);
        if (bytes.len > 0) {
            const written = linux.write(file.fd, bytes.ptr, bytes.len);
            try testing.expectEqual(linux.E.SUCCESS, linux.errno(written));
            try testing.expectEqual(bytes.len, written);
        }
        _ = try std.fmt.bufPrint(&file.path_bytes, "/proc/self/fd/{d}", .{file.fd});
        return file;
    }

    fn path(file: *const TestFile) [:0]const u8 {
        assert(file.fd >= 0);
        const result = std.mem.sliceTo(&file.path_bytes, 0);
        assert(std.mem.startsWith(u8, result, "/proc/self/fd/"));
        return result;
    }

    fn deinit(file: *TestFile) void {
        assert(file.fd >= 0);
        assert(linux.errno(linux.close(file.fd)) == .SUCCESS);
        file.* = undefined;
    }
};

var test_buffer: [file_buffer_size]u8 = undefined;

test "config: readFile returns the whole file, NUL-terminated" {
    var file = try TestFile.init(valid_source);
    defer file.deinit();
    const source = try readFile(file.path(), &test_buffer);
    try testing.expectEqualStrings(valid_source, source);
    try testing.expectEqual(@as(u8, 0), source.ptr[source.len]);
}

test "config: a file of exactly the largest size is read; one byte more is ConfigTooLarge" {
    const largest: [file_size_max + 1]u8 = @splat(' ');
    var exact = try TestFile.init(largest[0..file_size_max]);
    defer exact.deinit();
    try testing.expectEqual(@as(usize, file_size_max), (try readFile(exact.path(), &test_buffer)).len);
    var over = try TestFile.init(&largest);
    defer over.deinit();
    try testing.expectError(error.ConfigTooLarge, readFile(over.path(), &test_buffer));
}

test "config: a missing file, a directory, a device or a FIFO is ConfigUnavailable" {
    try testing.expectError(error.ConfigUnavailable, readFile("/nonexistent/config.zon", &test_buffer));
    try testing.expectError(error.ConfigUnavailable, readFile("/", &test_buffer));
    // An endless device would fill the buffer and look merely too large.
    try testing.expectError(error.ConfigUnavailable, readFile("/dev/zero", &test_buffer));
    var fds: [2]linux.fd_t = undefined;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })));
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);
    var path_bytes: [32:0]u8 = @splat(0);
    _ = try std.fmt.bufPrint(&path_bytes, "/proc/self/fd/{d}", .{fds[0]});
    const path = std.mem.sliceTo(&path_bytes, 0);
    try testing.expectError(error.ConfigUnavailable, readFile(path, &test_buffer));
}

test "config: an I/O error part way through is ConfigReadFailed" {
    // The kernel calls /proc/self/mem a regular file, but reading address 0 fails with EIO.
    try testing.expectError(error.ConfigReadFailed, readFile("/proc/self/mem", &test_buffer));
}

test "config: a file that needs more read calls than the bound is ConfigReadFailed" {
    // Each read of a packet socket returns one packet, here one byte, so the bound runs
    // out long before the room does.
    var fds: [2]linux.fd_t = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0, &fds);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);
    var packet: u32 = 0;
    while (packet <= constants.config_read_attempts_max) : (packet += 1) {
        try testing.expectEqual(@as(usize, 1), linux.write(fds[1], "x", 1));
    }
    try testing.expectError(error.ConfigReadFailed, readAll(fds[0], test_buffer[0 .. file_size_max + 1]));
}

test "config: an empty file reads as empty and parses as a syntax error" {
    var file = try TestFile.init("");
    defer file.deinit();
    const source = try readFile(file.path(), &test_buffer);
    try testing.expectEqual(@as(usize, 0), source.len);
    try testing.expectError(error.ConfigSyntax, parseTest(source));
}

test "config: load reads and checks a file, then frees everything it allocated" {
    var file = try TestFile.init(valid_source);
    defer file.deinit();
    var startup = StartupAllocator.init(testing.allocator, load_bytes);
    const config = try load(startup.allocator(), file.path());
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
    startup.finishStartup();
    try testing.expectEqualStrings("/run/coalition-connection/app.sock", config.socketPath());
    try testing.expectEqual(@as(u32, 1024), config.connections_max);

    // A budget one byte short of the file buffer and scratch fails before reading anything.
    var short = StartupAllocator.init(testing.allocator, load_bytes - 1);
    try testing.expectError(error.OutOfMemory, load(short.allocator(), file.path()));
    try testing.expectEqual(@as(u64, 0), short.bytes_live);
}

test "config: load of a file with a bad value frees everything too" {
    var file = try TestFile.init(".{ .socket_path = \"/run/app.sock\", .connections_max = 0 }");
    defer file.deinit();
    var startup = StartupAllocator.init(testing.allocator, load_bytes);
    try testing.expectError(error.ConnectionsZero, load(startup.allocator(), file.path()));
    try testing.expectEqual(@as(u64, 0), startup.bytes_live);
}
