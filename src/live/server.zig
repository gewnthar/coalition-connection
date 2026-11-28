//! Server loop (roadmap core 3 and core 6).
//!
//! Job:
//!   Join the pieces 0.1 needs into one loop, so a request gets a page back: keep one
//!   accept in flight on the listener, receive each connection's request into its own
//!   buffer, parse the head as it arrives, route a whole request, write the response into a
//!   buffer from the shared pool and send it, then keep the connection for its next request
//!   or close it. Every connection moves only through the connection state machine
//!   (`connection_state.zig`): the loop turns each completion, parse result and deadline
//!   into an `Event`, carries out the `Action` the transition returns, sets the `Deadline`
//!   it names, and changes the entry's state only through `Table.setState`.
//!
//! Generic over the I/O type (`comptime IO: type`, checked against the I/O contract), so the
//! simulator drives exactly this code, faults and all, and the server drives it with the
//! real io_uring type.
//!
//! Inputs:
//!   Completions from the I/O type; the clock it reads; one listening socket.
//!
//! Outputs:
//!   Submissions to the I/O type: accepts, receives, sends, cancels; drops and releases.
//!
//! Limits (src/constants.zig):
//!   A connection table of up to `http_connections_max` entries, each with one request
//!   buffer of `http_request_size_max` bytes; a pool of `http_response_buffers_max`
//!   response buffers of `http_response_size_max` bytes; `server_connection_state_size_max`
//!   bytes of loop state per connection; `http_requests_per_connection_max` requests per
//!   connection; the idle, read and write timeouts. Everything is allocated in `init`,
//!   during startup, and nothing after.
//!
//! One tick, bounded: poll completions in batches of `server_completions_batch`, at most
//! `polls_per_tick_max` polls, handling each as it comes; read the clock; then one pass over
//! the table (resubmit what was refused on an earlier tick, hand the machine the drops that
//! ran out, the deadlines that passed and the closing connections with nothing left in
//! flight); then submit the accept if none is in flight and no wait after Backpressure
//! runs. A refused submission waits for the next tick, never retried in the same one.
//!
//! A connection that finds the response pool empty, or others already waiting, queues in
//! `writing` for a buffer: buffers go to waiters in the order they asked, before the pass
//! over the table, and a waiter whose write deadline passes leaves the queue and is dropped.
//!
//! Requests: a head arrives byte by byte as often as whole; the parser resumes where it
//! left off (the entry's `HeadScan`). A head the parser refuses gets that error's status
//! and the connection closes. A whole request is routed (`router.zig`) and answered. The
//! connection closes after the response when the request asks for it (HTTP/1.0, or
//! "Connection: close"), when bytes followed the request's end (no pipelining), or when it
//! was the connection's last allowed request. Routing reads the request again from the
//! connection's buffer, which holds it untouched until the response has gone, so nothing
//! of a request outlives the transition that saw it whole.
//!
//! Not yet: `main` doesn't run this loop, a 413 is sent and closed at once rather than
//! after a moment's drain, and nothing checks the listener's peer (roadmap core 51); those
//! land with the server program.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const io = @import("../io/root.zig");
const connections = @import("connections.zig");
const machine = @import("connection_state.zig");
const http_request = @import("http_request.zig");
const http_response = @import("http_response.zig");
const router = @import("router.zig");
const StartupAllocator = @import("../startup_allocator.zig").StartupAllocator;

const Table = connections.Table;
const request_size = constants.http_request_size_max;
const response_size = constants.http_response_size_max;
const batch = constants.server_completions_batch;

/// The index an accept's operation id carries: past every entry of the largest table.
const accept_index: u32 = std.math.maxInt(u16);
/// An operation id is a serial above the 16 bits of its entry's index.
const index_mask: io.OperationId = std.math.maxInt(u16);
/// The largest serial that still fits above the index.
const serial_max: u64 = std.math.maxInt(u48);

/// Polls in one tick. Reason: enough to take every operation the ring can hold, in
/// batches, with one poll to spare. Operations submitted during the polls may finish in
/// time for a later poll of the same tick, so the bound, not an empty poll, is what
/// keeps a busy tick from running on.
pub const polls_per_tick_max: u32 = constants.io_operations_in_flight_max / batch + 1;

comptime {
    assert(constants.http_connections_max <= accept_index);
    assert(constants.http_response_buffers_max <= std.math.maxInt(u16));
    assert(batch <= constants.io_operations_in_flight_max);
    assert(@sizeOf(?Conn) <= constants.server_connection_state_size_max);
}

/// How long each of a connection's deadlines runs, in nanoseconds on the I/O type's clock,
/// and how many requests one connection serves. The server takes the defaults; a
/// simulation scales the deadlines to its ticks and lowers the request limit to reach it.
pub const Settings = struct {
    idle_ns: u64 = constants.http_idle_timeout_ns,
    read_ns: u64 = constants.http_read_timeout_ns,
    write_ns: u64 = constants.http_write_timeout_ns,
    requests_max: u32 = constants.http_requests_per_connection_max,

    /// The longest of the three deadlines, for the bound on a clock reading.
    fn longest(settings: Settings) u64 {
        assert(settings.read_ns > 0 and settings.write_ns > 0 and settings.idle_ns > 0);
        const result = @max(settings.idle_ns, @max(settings.read_ns, settings.write_ns));
        assert(result >= settings.idle_ns and result >= settings.read_ns and result >= settings.write_ns);
        return result;
    }
};

pub const InitError = error{OutOfMemory};

/// What the loop has done. For metrics and tests; two simulated runs with the same seed
/// must match field for field.
pub const Counts = struct {
    accepts: u64 = 0,
    /// Accepts that handed back no connection: the table was full, the peer went, or the
    /// system was short; the last of these counted apart too, since the loop then waits.
    accept_failures: u64 = 0,
    accept_backpressure: u64 = 0,
    /// Accepts the I/O type refused with AcceptTooSoon: never, while the loop waits out
    /// every Backpressure itself.
    accept_too_soon: u64 = 0,
    receives: u64 = 0,
    bytes_received: u64 = 0,
    /// Whole requests read, and heads the parser refused.
    requests: u64 = 0,
    refusals: u64 = 0,
    sends: u64 = 0,
    bytes_sent: u64 = 0,
    /// Responses whose last byte went out.
    responses: u64 = 0,
    /// Submissions refused for now, and completions that said Backpressure: each tried
    /// again on a later tick.
    retries: u64 = 0,
    /// Replies that queued for a response buffer, and waiting connections whose deadline
    /// dropped them before one came.
    buffer_waits: u64 = 0,
    waits_dropped: u64 = 0,
    /// Deadlines met while reading (idle or read), while writing, and while closing.
    deadlines_reading: u64 = 0,
    deadlines_writing: u64 = 0,
    deadlines_closing: u64 = 0,
    drops: u64 = 0,
    exhausted: u64 = 0,
    cancels: u64 = 0,
    releases: u64 = 0,
    trace: u64 = fnv_offset,
};

const fnv_offset: u64 = 0xcbf29ce484222325;
const fnv_prime: u64 = 0x100000001b3;

/// The response a connection writes once it holds a buffer: the routed page for its
/// request, closing after it or not, or a refusal's status, always closing.
const Reply = union(enum) {
    respond: machine.After,
    refusal: http_response.Status,
};

/// The loop's own state for one connection, beside its table entry.
const Conn = struct {
    peer: io.PeerId,
    /// When the state's deadline passes, or null with none.
    deadline: ?io.Instant = null,
    /// The receive or send in flight, and the cancel in flight, by id.
    operation: ?io.OperationId = null,
    cancel: ?io.OperationId = null,
    /// A submission refused, or a completion that said Backpressure, to submit on a later
    /// tick than `retry_tick`.
    retry: ?io.Kind = null,
    retry_tick: u64 = 0,
    /// The reply waiting in the queue for a response buffer; `response` is null meanwhile.
    waiting: ?Reply = null,
    /// Bytes in the request buffer; the head's length once it parsed (0 before), and the
    /// whole request's.
    filled: u32 = 0,
    head_len: u32 = 0,
    request_len: u32 = 0,
    /// Requests read on this connection.
    requests: u32 = 0,
    /// The response buffer held, the response's length in it, and how much has gone.
    response: ?u16 = null,
    response_len: u32 = 0,
    sent: u32 = 0,
    /// Whether the connection closes once the response has gone.
    after: machine.After = .keep_open,
    /// A drop returned DropsExhausted: the next pass hands the machine `drop_exhausted`,
    /// outside the transition that dropped, so no transition runs inside another.
    exhausted: bool = false,
};

pub fn Server(comptime IO: type) type {
    comptime io.assertContract(IO);
    return struct {
        const Self = @This();

        io: *IO,
        table: *Table,
        listener: io.Socket,
        settings: Settings,
        /// One per table entry, by index; null while the entry is free.
        conns: []?Conn,
        /// One request buffer per table entry, by index.
        request_buffers: []u8,
        /// The response pool, and its free buffers, a stack: `free[0..free_count]`.
        response_buffers: []u8,
        free: []u16,
        free_count: u32,
        /// Connections waiting for a response buffer, by index, in the order they asked: a
        /// ring of one slot per entry, `waiters[waiters_head..][0..waiters_count]`, wrapping.
        waiters: []u16,
        waiters_head: u32,
        waiters_count: u32,
        /// The latest clock reading, taken at the start of a tick and again after its polls.
        now: io.Instant,
        ticks: u64,
        serial: u64,
        /// The accept in flight, by id; whether to keep one in flight; and when an accept
        /// may go again after one came back with Backpressure.
        accept: ?io.OperationId,
        accepting: bool,
        accept_resume_at: ?io.Instant,
        /// An accept came back with Backpressure during this tick's polls.
        accept_backpressure: bool,
        counts: Counts,

        /// Sizes everything from the table and `buffers_count` response buffers, during
        /// startup. The I/O type and the table are the caller's and must outlive this; the
        /// I/O type must already hold the table (`Real.init`, `Sim.attachTable`).
        pub fn init(
            startup: *StartupAllocator,
            io_type: *IO,
            table: *Table,
            listener: io.Socket,
            buffers_count: u32,
            settings: Settings,
        ) InitError!Self {
            assert(startup.allocationAllowed());
            assert(table.capacity() > 0 and table.capacity() <= constants.http_connections_max);
            assert(buffers_count > 0 and buffers_count <= constants.http_response_buffers_max);
            assert(listener >= 0 and table.count() == 0);
            assert(settings.longest() < std.math.maxInt(io.Instant) / 2);
            assert(settings.requests_max > 0 and settings.requests_max <= constants.http_requests_per_connection_max);
            const gpa = startup.allocator();
            const capacity = table.capacity();
            const conns = try gpa.alloc(?Conn, capacity);
            errdefer gpa.free(conns);
            const request_buffers = try gpa.alloc(u8, @as(u64, capacity) * request_size);
            errdefer gpa.free(request_buffers);
            const response_buffers = try gpa.alloc(u8, @as(u64, buffers_count) * response_size);
            errdefer gpa.free(response_buffers);
            const free = try gpa.alloc(u16, buffers_count);
            errdefer gpa.free(free);
            const waiters = try gpa.alloc(u16, capacity);
            @memset(conns, null);
            for (free, 0..) |*slot, index| slot.* = @intCast(buffers_count - 1 - index);
            const result: Self = .{
                .io = io_type,
                .table = table,
                .listener = listener,
                .settings = settings,
                .conns = conns,
                .request_buffers = request_buffers,
                .response_buffers = response_buffers,
                .free = free,
                .free_count = buffers_count,
                .waiters = waiters,
                .waiters_head = 0,
                .waiters_count = 0,
                .now = io_type.now(),
                .ticks = 0,
                .serial = 0,
                .accept = null,
                .accepting = true,
                .accept_resume_at = null,
                .accept_backpressure = false,
                .counts = .{},
            };
            assert(result.free[result.free_count - 1] == 0); // The first taken is buffer 0.
            return result;
        }

        /// Frees what `init` took, during shutdown, once no connection is left and nothing
        /// is in flight.
        pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
            assert(self.table.count() == 0);
            assert(self.accept == null);
            assert(self.free_count == self.free.len); // Every buffer is back.
            assert(self.waiters_count == 0);
            gpa.free(self.waiters);
            gpa.free(self.free);
            gpa.free(self.response_buffers);
            gpa.free(self.request_buffers);
            gpa.free(self.conns);
            self.* = undefined;
        }

        /// Stops keeping an accept in flight. The one in flight, if any, still completes and
        /// its connection is served; nothing new is accepted after it.
        pub fn stopAccepting(self: *Self) void {
            assert(self.accepting);
            // The accept in flight, if any, is still the loop's to take back.
            assert(self.accept == null or (self.accept.? & index_mask) == accept_index);
            self.accepting = false;
        }

        /// Whether nothing is left: no connection, no accept in flight.
        pub fn finished(self: *const Self) bool {
            assert(self.free_count <= self.free.len);
            const result = self.table.count() == 0 and self.accept == null;
            assert(!result or self.free_count == self.free.len);
            return result;
        }

        /// One tick of the loop (see the file comment). Returns the completions it handled,
        /// so a caller that found none can wait before the next tick.
        pub fn tick(self: *Self) u32 {
            const ticks_before = self.ticks;
            assert(self.serial <= serial_max);
            self.ticks += 1;
            self.now = self.io.now();
            var completions: [batch]io.Completion = undefined;
            var handled: u32 = 0;
            var polls: u32 = 0;
            while (polls < polls_per_tick_max) : (polls += 1) {
                const count = self.io.poll(&completions);
                assert(count <= batch);
                for (completions[0..count]) |completion| self.onCompletion(completion);
                handled += count;
                if (count < batch) break;
            }
            assert(polls <= polls_per_tick_max);
            // Read after the polls, so the wait after a Backpressure they handed back is
            // never early (src/io/root.zig, Accepts).
            self.now = self.io.now();
            if (self.accept_backpressure) {
                self.accept_backpressure = false;
                self.accept_resume_at = self.now + constants.io_accept_backpressure_wait_ns;
            }
            // Buffers given back during the polls go to the connections that asked first.
            self.serveWaiters();
            self.sweep();
            // And the ones the pass gave back, so no buffer stays free while one waits.
            self.serveWaiters();
            assert(self.free_count == 0 or self.waiters_count == 0);
            self.keepAccepting();
            assert(self.ticks == ticks_before + 1);
            return handled;
        }

        fn trace(self: *Self, value: u64) void {
            // Called while a tick handles what an operation it submitted brought back.
            assert(self.ticks > 0);
            assert(self.serial > 0);
            self.counts.trace = (self.counts.trace ^ value) *% fnv_prime;
        }

        /// A fresh id for an operation of entry `index` (or `accept_index`): a serial no id
        /// in flight holds, above the index, so a completion names its connection.
        fn nextId(self: *Self, index: u32) io.OperationId {
            assert(index < self.conns.len or index == accept_index);
            assert(self.serial < serial_max); // About 2^48 operations: centuries of traffic.
            self.serial += 1;
            const id: io.OperationId = (self.serial << 16) | index;
            assert((id & index_mask) == index);
            return id;
        }

        fn connAt(self: *Self, index: u32) *Conn {
            assert(index < self.conns.len);
            assert(self.conns[index] != null); // A completion or a pass names a live entry.
            const conn = &self.conns[index].?;
            assert(@as(connections.IdParts, @bitCast(conn.peer)).index == index);
            return conn;
        }

        fn requestBuffer(self: *Self, index: u32) []u8 {
            assert(index < self.conns.len);
            assert(self.request_buffers.len == self.conns.len * request_size);
            return self.request_buffers[index * request_size ..][0..request_size];
        }

        fn responseBuffer(self: *Self, buffer: u16) []u8 {
            assert(buffer < self.free.len);
            assert(self.response_buffers.len == self.free.len * response_size);
            return self.response_buffers[@as(usize, buffer) * response_size ..][0..response_size];
        }

        /// Hands a completion to the accept or to its connection, after checking it is the
        /// operation in flight there: anything else is a broken I/O type.
        fn onCompletion(self: *Self, completion: io.Completion) void {
            assert((completion.id >> 16) > 0 and (completion.id >> 16) <= self.serial);
            self.trace(completion.id);
            const index: u32 = @intCast(completion.id & index_mask);
            if (index == accept_index) {
                assert(completion.result == .accept);
                assert(self.accept == completion.id);
                self.accept = null;
                return self.onAccepted(completion.result.accept);
            }
            const conn = self.connAt(index);
            switch (completion.result) {
                .cancel => {
                    assert(conn.cancel == completion.id);
                    conn.cancel = null;
                },
                .receive => |result| {
                    assert(conn.operation == completion.id);
                    conn.operation = null;
                    self.onReceived(index, result);
                },
                .send => |result| {
                    assert(conn.operation == completion.id);
                    conn.operation = null;
                    self.onSent(index, result);
                },
                .accept, .execute => unreachable, // Ids of these carry no entry's index.
            }
        }

        fn onAccepted(self: *Self, result: io.AcceptError!io.PeerId) void {
            assert(self.accept == null);
            const peer = result catch |err| {
                self.counts.accept_failures += 1;
                switch (err) {
                    // The I/O type refuses accepts for a while; `tick` sets when they resume.
                    error.Backpressure => {
                        self.accept_backpressure = true;
                        self.counts.accept_backpressure += 1;
                    },
                    // Closed already by the I/O type, or gone: accept the next one.
                    error.TableFull, error.PeerDown => {},
                }
                return;
            };
            const index: u32 = @as(connections.IdParts, @bitCast(peer)).index;
            assert(self.conns[index] == null); // Handed out twice.
            const entry = self.table.get(peer);
            // A new connection starts empty, on a reused entry too.
            assert(entry.state == .idle and !entry.busy() and !entry.canceled);
            assert(entry.scan.resume_at == 0);
            self.conns[index] = .{ .peer = peer };
            self.counts.accepts += 1;
            // Acquire set idle already; the transition gives the action and the deadline.
            const transition = machine.transition(.free, .accepted);
            assert(transition.to == .idle);
            self.setDeadline(&self.conns[index].?, transition.deadline);
            self.act(index, transition.action);
        }

        /// Moves `index`'s connection by `event`: the entry's new state through the table,
        /// the deadline, then the action.
        fn apply(self: *Self, index: u32, event: machine.Event) void {
            assert(event != .accepted); // `onAccepted` takes an arrival.
            const conn = self.connAt(index);
            const peer = conn.peer;
            const from = self.table.get(peer).state;
            const transition = machine.transition(from, event);
            self.trace((@as(u64, @backingInt(from)) << 8) | @backingInt(transition.to));
            // Only release frees an entry.
            if (transition.to != from and transition.to != .free) self.table.setState(peer, transition.to);
            self.setDeadline(conn, transition.deadline);
            self.act(index, transition.action);
            assert((transition.to == .free) == (self.conns[index] == null));
            assert(transition.to == .free or self.table.get(peer).state == transition.to);
        }

        fn setDeadline(self: *Self, conn: *Conn, deadline: machine.Deadline) void {
            // A clock reading has centuries of room below the top of a u64.
            assert(self.now <= std.math.maxInt(io.Instant) - self.settings.longest());
            conn.deadline = switch (deadline) {
                .keep => conn.deadline,
                .clear => null,
                .idle => self.now + self.settings.idle_ns,
                .read => self.now + self.settings.read_ns,
                .write => self.now + self.settings.write_ns,
            };
            assert((deadline == .clear) == (conn.deadline == null) or deadline == .keep);
        }

        fn act(self: *Self, index: u32, action: machine.Action) void {
            const conn = self.connAt(index);
            assert(self.table.lookup(conn.peer) != null);
            // Nothing new goes to a connection waiting for a buffer but a drop.
            assert(conn.waiting == null or action == .drop);
            switch (action) {
                .none => {},
                // `conn.retry` already names it: it goes on the next tick.
                .resubmit => assert(conn.retry != null),
                .receive => self.submitReceive(index),
                .respond => |after| self.startReply(index, .{ .respond = after }),
                .send_refusal => |status| self.startReply(index, .{ .refusal = status }),
                .send_rest => self.submitSend(index),
                .next_request => {
                    self.returnBuffer(conn);
                    // The parser left the scan empty when the head parsed.
                    assert(self.table.get(conn.peer).scan.resume_at == 0);
                    conn.filled = 0;
                    conn.head_len = 0;
                    conn.request_len = 0;
                    conn.after = .keep_open;
                    self.submitReceive(index);
                },
                .return_buffer => self.returnBuffer(conn),
                .drop => self.dropConn(index),
                .cancel => self.submitCancel(index),
                .release => self.release(index),
            }
        }

        /// Writes `reply` into a buffer from the pool and sends it, or, with the pool empty
        /// or others waiting already, queues behind them: each takes a buffer in the order
        /// it asked (`serveWaiters`), so none waits for ever while later ones are served.
        fn startReply(self: *Self, index: u32, reply: Reply) void {
            const conn = self.connAt(index);
            assert(conn.operation == null); // Half-duplex: the receive came back first.
            assert(conn.response == null and conn.retry == null and conn.waiting == null);
            if (self.free_count == 0 or self.waiters_count > 0) {
                assert(self.waiters_count < self.waiters.len); // At most one slot per entry.
                const tail = (self.waiters_head + self.waiters_count) % self.waitersLen();
                self.waiters[tail] = @intCast(index);
                self.waiters_count += 1;
                conn.waiting = reply;
                self.counts.buffer_waits += 1;
                return;
            }
            self.sendReply(index, reply);
        }

        fn waitersLen(self: *const Self) u32 {
            assert(self.waiters.len == self.conns.len);
            assert(self.waiters_count <= self.waiters.len);
            return @intCast(self.waiters.len);
        }

        /// Hands free buffers to the waiting connections, first come first served. At most
        /// one step per waiter.
        fn serveWaiters(self: *Self) void {
            const count_before = self.waiters_count;
            var served: u32 = 0;
            while (self.free_count > 0 and self.waiters_count > 0) : (served += 1) {
                assert(served < count_before);
                const index: u32 = self.waiters[self.waiters_head];
                self.waiters_head = (self.waiters_head + 1) % self.waitersLen();
                self.waiters_count -= 1;
                const conn = self.connAt(index);
                const reply = conn.waiting.?; // A dropped waiter left the queue.
                conn.waiting = null;
                self.sendReply(index, reply);
            }
            assert(self.waiters_count == count_before - served);
        }

        /// Takes `index` out of the waiting queue, keeping the others' order: its deadline
        /// dropped it. At most one step per waiter.
        fn removeWaiter(self: *Self, index: u32) void {
            const count_before = self.waiters_count;
            assert(count_before > 0);
            const len = self.waitersLen();
            var kept: u32 = 0;
            var step: u32 = 0;
            while (step < count_before) : (step += 1) {
                const waiter = self.waiters[(self.waiters_head + step) % len];
                if (waiter == index) continue;
                self.waiters[(self.waiters_head + kept) % len] = waiter;
                kept += 1;
            }
            // It was there exactly once.
            assert(kept == count_before - 1);
            self.waiters_count = kept;
        }

        /// Takes a free buffer, writes `reply` into it and sends it.
        fn sendReply(self: *Self, index: u32, reply: Reply) void {
            const conn = self.connAt(index);
            assert(self.free_count > 0);
            assert(conn.response == null and conn.waiting == null);
            self.free_count -= 1;
            const buffer = self.free[self.free_count];
            conn.waiting = null;
            conn.response = buffer;
            conn.sent = 0;
            conn.after = switch (reply) {
                .respond => |after| after,
                .refusal => .close,
            };
            conn.response_len = self.writeReply(index, reply, self.responseBuffer(buffer));
            assert(conn.response_len > 0 and conn.response_len <= response_size);
            self.submitSend(index);
        }

        /// The response for `reply`, written into `buffer`; returns its length. A page is
        /// routed from the request still whole in the connection's buffer, parsed again
        /// from its start with a scan of its own.
        fn writeReply(self: *Self, index: u32, reply: Reply, buffer: []u8) u32 {
            const conn = self.connAt(index);
            assert(buffer.len == response_size);
            const response: http_response.Response = switch (reply) {
                .refusal => |status| .{ .status = status, .close = true },
                .respond => |after| respond: {
                    assert(conn.head_len > 0 and conn.request_len <= conn.filled);
                    var scan: http_request.HeadScan = .{};
                    const head = self.requestBuffer(index)[0..conn.head_len];
                    // It parsed when it arrived, and its bytes haven't changed since.
                    const request = http_request.parse(head, &scan) catch |err| {
                        std.debug.panic("server: a parsed head failed to parse again: {t}", .{err});
                    };
                    assert(request.head_len == conn.head_len);
                    var routed = router.route(&request);
                    routed.close = after == .close;
                    break :respond routed;
                },
            };
            // The router's pages and every refusal fit a buffer, checked at compile time
            // there and in the writer, so a failure here is a bug in one of them.
            const len = http_response.write(buffer, response) catch |err| {
                std.debug.panic("server: a {d} response didn't fit its buffer: {t}", .{ @backingInt(response.status), err });
            };
            assert(len > 0);
            return len;
        }

        /// Gives the connection's response buffer back to the pool, if it holds one. Never
        /// while a send in flight may still read it.
        fn returnBuffer(self: *Self, conn: *Conn) void {
            assert(self.free_count <= self.free.len);
            assert(conn.waiting == null); // A waiter holds no buffer.
            const buffer = conn.response orelse return;
            assert(conn.operation == null);
            assert(self.table.get(conn.peer).sends_in_flight == 0);
            assert(self.free_count < self.free.len);
            self.free[self.free_count] = buffer;
            self.free_count += 1;
            conn.response = null;
            conn.response_len = 0;
            conn.sent = 0;
        }

        fn submitReceive(self: *Self, index: u32) void {
            const conn = self.connAt(index);
            assert(conn.operation == null and conn.retry == null);
            // A request that fills the buffer is whole or refused before another receive.
            assert(conn.filled < request_size);
            const into = self.requestBuffer(index)[conn.filled..];
            const operation: io.Operation = .{ .receive = .{ .peer = conn.peer, .buffer = into } };
            if (self.submitted(conn, .{ .id = self.nextId(index), .operation = operation })) {
                self.counts.receives += 1;
            }
        }

        fn submitSend(self: *Self, index: u32) void {
            const conn = self.connAt(index);
            assert(conn.operation == null and conn.retry == null);
            assert(conn.sent < conn.response_len);
            const buffer = self.responseBuffer(conn.response.?);
            const bytes = buffer[conn.sent..conn.response_len];
            const operation: io.Operation = .{ .send = .{ .peer = conn.peer, .bytes = bytes } };
            if (self.submitted(conn, .{ .id = self.nextId(index), .operation = operation })) {
                self.counts.sends += 1;
            }
        }

        fn submitCancel(self: *Self, index: u32) void {
            const conn = self.connAt(index);
            assert(conn.cancel == null and conn.retry == null);
            assert(self.table.get(conn.peer).state == .closing);
            const operation: io.Operation = .{ .cancel = .{ .peer = conn.peer } };
            if (self.submitted(conn, .{ .id = self.nextId(index), .operation = operation })) {
                self.counts.cancels += 1;
            }
        }

        /// Submits `submission` for `conn`, recording its id, or records a refusal to submit
        /// again on the next tick. Returns whether it went in.
        fn submitted(self: *Self, conn: *Conn, submission: io.Submission) bool {
            const kind: io.Kind = submission.operation;
            assert(kind == .send or kind == .receive or kind == .cancel);
            self.io.submit(submission) catch |err| switch (err) {
                error.QueueFull, error.SlotsKeptForAccepts, error.CancelsFull => {
                    self.retryLater(conn, kind);
                    self.counts.retries += 1;
                    return false;
                },
                // The contract refuses only an accept with AcceptTooSoon.
                error.AcceptTooSoon => unreachable,
            };
            if (kind == .cancel) conn.cancel = submission.id else conn.operation = submission.id;
            assert(conn.retry == null);
            return true;
        }

        /// Records a refused submission, or a completion that said Backpressure, to go again
        /// on a later tick.
        fn retryLater(self: *Self, conn: *Conn, kind: io.Kind) void {
            assert(kind == .send or kind == .receive or kind == .cancel);
            assert(conn.retry == null);
            conn.retry = kind;
            conn.retry_tick = self.ticks;
        }

        /// Submits again what was refused, or said Backpressure, on an earlier tick.
        fn resubmit(self: *Self, index: u32) void {
            const conn = self.connAt(index);
            const kind = conn.retry orelse return;
            assert(conn.retry_tick <= self.ticks);
            if (conn.retry_tick == self.ticks) return; // Next tick, as the machine says.
            conn.retry = null;
            switch (kind) {
                .receive => self.submitReceive(index),
                .send => self.submitSend(index),
                .cancel => self.submitCancel(index),
                .accept, .execute => unreachable, // `retryLater` takes neither.
            }
            assert(conn.retry == null or conn.retry_tick == self.ticks);
        }

        fn onReceived(self: *Self, index: u32, result: io.ReceiveError!u32) void {
            const conn = self.connAt(index);
            const state = self.table.get(conn.peer).state;
            // Half-duplex: a receive goes only to a connection reading, or one closing.
            assert(state != .free and state != .writing);
            assert(!self.table.get(conn.peer).receiving);
            const count = result catch |err| switch (err) {
                error.Backpressure => if (state == .closing) return self.apply(index, .receive_ended) else {
                    self.retryLater(conn, .receive);
                    self.counts.retries += 1;
                    return self.apply(index, .retry);
                },
                error.PeerDown, error.Canceled => return self.apply(index, .receive_ended),
            };
            if (count == 0) return self.apply(index, .receive_ended);
            // A closing connection's bytes are ignored.
            if (state == .closing) return self.apply(index, .{ .received = .head_short });
            assert(count <= request_size - conn.filled);
            conn.filled += count;
            self.counts.bytes_received += count;
            self.apply(index, .{ .received = self.classify(index) });
        }

        /// What the request buffer holds now, as the state machine names it: parsing the
        /// head until it ends, then counting the body in.
        fn classify(self: *Self, index: u32) machine.Received {
            const conn = self.connAt(index);
            assert(conn.filled > 0 and conn.filled <= request_size);
            if (conn.head_len == 0) {
                const buffer = self.requestBuffer(index)[0..conn.filled];
                const request = http_request.parse(buffer, self.table.headScan(conn.peer)) catch |err| {
                    const status = http_response.statusForParseError(err) orelse return .head_short;
                    self.counts.refusals += 1;
                    return .{ .invalid = status };
                };
                conn.head_len = request.head_len;
                conn.request_len = request.head_len + request.content_length;
                conn.after = if (requestCloses(&request)) .close else .keep_open;
            }
            assert(conn.head_len > 0 and conn.request_len <= request_size);
            if (conn.filled < conn.request_len) return .body_short;
            conn.requests += 1;
            self.counts.requests += 1;
            assert(conn.requests <= self.settings.requests_max);
            // Bytes past the request's end are another request: no pipelining, so close.
            const pipelined = conn.filled > conn.request_len;
            const last = conn.requests == self.settings.requests_max;
            return .{ .complete = if (last or pipelined) .close else conn.after };
        }

        fn onSent(self: *Self, index: u32, result: io.SendError!u32) void {
            const conn = self.connAt(index);
            const state = self.table.get(conn.peer).state;
            assert(state == .writing or state == .closing);
            assert(conn.response != null and conn.sent < conn.response_len);
            const sent = result catch |err| switch (err) {
                error.Backpressure => if (state == .closing) return self.apply(index, .send_failed) else {
                    self.retryLater(conn, .send);
                    self.counts.retries += 1;
                    return self.apply(index, .retry);
                },
                error.PeerDown, error.Canceled => return self.apply(index, .send_failed),
            };
            assert(sent <= conn.response_len - conn.sent);
            conn.sent += sent;
            self.counts.bytes_sent += sent;
            if (conn.sent < conn.response_len) return self.apply(index, .sent_part);
            self.counts.responses += 1;
            self.apply(index, .{ .sent_all = conn.after });
        }

        /// Drops the connection when something is in flight; otherwise drained follows on
        /// this tick's pass. A submission waiting for a later tick waits no more: closing
        /// takes nothing new but a cancel.
        fn dropConn(self: *Self, index: u32) void {
            const conn = self.connAt(index);
            assert(self.table.get(conn.peer).state == .closing);
            if (conn.retry) |kind| if (kind != .cancel) {
                conn.retry = null;
                // Nothing in flight reads a buffer held for a refused send.
                if (kind == .send) self.returnBuffer(conn);
            };
            if (conn.waiting != null) {
                self.removeWaiter(index);
                conn.waiting = null;
                self.counts.waits_dropped += 1;
            }
            if (!self.table.get(conn.peer).busy()) return;
            self.counts.drops += 1;
            self.io.drop(conn.peer) catch |err| switch (err) {
                error.DropsExhausted => {
                    self.counts.exhausted += 1;
                    // A cancel already going, or due, covers it.
                    if (conn.cancel == null and conn.retry == null) conn.exhausted = true;
                },
            };
            assert(!conn.exhausted or self.table.get(conn.peer).drops_failed == constants.io_drop_attempts_max);
        }

        fn release(self: *Self, index: u32) void {
            const conn = self.connAt(index);
            const peer = conn.peer;
            assert(conn.operation == null and conn.cancel == null and conn.retry == null);
            assert(conn.response == null and self.table.get(peer).state == .closing);
            assert(!self.table.get(peer).busy());
            self.io.release(peer) catch |err| switch (err) {
                // Drained means nothing is in flight.
                error.OperationsInFlight => unreachable,
            };
            self.counts.releases += 1;
            self.conns[index] = null;
            assert(self.table.lookup(peer) == null);
        }

        /// One bounded pass over the table: what was refused goes again, then the machine
        /// gets each drop that ran out, each deadline that passed, and each closing
        /// connection with nothing left in flight.
        fn sweep(self: *Self) void {
            assert(self.table.count() <= self.conns.len);
            var index: u32 = 0;
            var live: u32 = 0;
            while (index < self.conns.len) : (index += 1) {
                if (self.conns[index] == null) continue;
                live += 1;
                self.resubmit(index);
                const conn = self.connAt(index);
                if (conn.exhausted) {
                    conn.exhausted = false;
                    self.apply(index, .drop_exhausted);
                }
                if (conn.deadline) |deadline| if (self.now >= deadline) {
                    switch (self.table.get(conn.peer).state) {
                        .free => unreachable, // A live entry is never free.
                        .idle, .reading_head, .reading_body => self.counts.deadlines_reading += 1,
                        .writing => self.counts.deadlines_writing += 1,
                        .closing => self.counts.deadlines_closing += 1,
                    }
                    self.apply(index, .deadline);
                };
                const entry = self.table.get(conn.peer);
                // A cancel refused for room has nothing left to reach once nothing is in
                // flight, so it isn't owed any more and the entry can drain.
                if (entry.state == .closing and !entry.busy() and conn.retry == .cancel) conn.retry = null;
                const drained = !entry.busy() and conn.retry == null and !conn.exhausted;
                if (entry.state == .closing and drained) self.apply(index, .drained);
            }
            // Only `drained` frees an entry, after it was counted here.
            assert(live >= self.table.count());
        }

        /// Keeps one accept in flight while accepting, once any wait after a Backpressure
        /// is over. A refusal waits for the next tick.
        fn keepAccepting(self: *Self) void {
            assert(self.accept == null or (self.accept.? & index_mask) == accept_index);
            if (!self.accepting or self.accept != null) return;
            if (self.accept_resume_at) |resume_at| {
                if (self.now < resume_at) return;
                self.accept_resume_at = null;
            }
            const id = self.nextId(accept_index);
            const operation: io.Operation = .{ .accept = .{ .listener = self.listener } };
            self.io.submit(.{ .id = id, .operation = operation }) catch |err| switch (err) {
                // Tried again on the next tick.
                error.QueueFull => return,
                error.AcceptTooSoon => {
                    self.counts.accept_too_soon += 1;
                    return;
                },
                // The contract never refuses an accept so.
                error.SlotsKeptForAccepts, error.CancelsFull => unreachable,
            };
            self.accept = id;
            assert(self.accept_resume_at == null);
        }

        /// Every connection keeps the rules its state sets, as the table counts it. For
        /// tests and simulations, after a tick; at most one step per entry.
        pub fn checkInvariants(self: *const Self) void {
            var live: u32 = 0;
            var waiting: u32 = 0;
            for (self.conns, 0..) |maybe, index| {
                const conn = maybe orelse continue;
                live += 1;
                assert(self.table.lookup(conn.peer) != null);
                const entry = self.table.lookup(conn.peer).?;
                assert(@as(connections.IdParts, @bitCast(conn.peer)).index == index);
                // Half-duplex: one receive or one send at most, as the table counts them.
                assert(!(entry.receiving and entry.sends_in_flight > 0) and entry.sends_in_flight <= 1);
                assert((conn.operation != null) == (entry.receiving or entry.sends_in_flight == 1));
                assert((conn.cancel != null) == entry.cancel_in_flight);
                assert(conn.waiting == null or (conn.response == null and conn.retry == null));
                switch (entry.state) {
                    .free => unreachable,
                    .idle, .reading_head, .reading_body => {
                        assert(entry.receiving or conn.retry == .receive);
                        assert(conn.response == null and !entry.canceled);
                    },
                    .writing => assert(entry.sends_in_flight == 1 or conn.retry == .send or conn.waiting != null),
                    .closing => assert((conn.retry == null or conn.retry.? == .cancel) and conn.waiting == null),
                }
                if (conn.waiting != null) waiting += 1;
            }
            assert(live == self.table.count());
            assert(waiting == self.waiters_count);
            assert(self.free_count == 0 or self.waiters_count == 0);
        }
    };
}

/// Whether a request asks the server to close after answering it: HTTP/1.0, or a
/// Connection field of "close".
fn requestCloses(request: *const http_request.Request) bool {
    assert(request.head_len > 0);
    assert(request.header_count <= constants.http_headers_max);
    if (request.version == .http_1_0) return true;
    const value = request.header("Connection") orelse return false;
    return std.ascii.eqlIgnoreCase(value, "close");
}

// ---- Tests ----------------------------------------------------------------------------

const testing = std.testing;
const builtin = @import("builtin");
const linux = std.os.linux;
const Sim = io.sim.Sim;

/// What every simulated client sends, a byte at a time, then it closes: a GET of the page
/// and a POST and a HEAD kept alive, then a method the server doesn't answer, refused.
const request_get = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
const request_post = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nok";
const request_head = "HEAD /x HTTP/1.1\r\nHost: a\r\n\r\n";
const request_refused = "BREW / HTTP/1.1\r\nHost: a\r\n\r\n";
const client_stream = request_get ++ request_post ++ request_head ++ request_refused;
/// Requests a client's stream holds that are answered, and the one refused.
const client_answered: u32 = 3;

/// The bytes the server sends one client that sent its whole stream: the router's answer
/// to each request kept alive, then the refusal, which closes.
fn clientResponseBytes() !u64 {
    comptime assert(client_stream.len < constants.http_request_size_max);
    assert(client_answered + 1 == std.mem.count(u8, client_stream, " HTTP/1.1\r\n"));
    var buffer: [2048]u8 = undefined;
    var total: u64 = 0;
    for ([_][]const u8{ request_get, request_post, request_head }) |text| {
        var scan: http_request.HeadScan = .{};
        const request = try http_request.parse(text, &scan);
        total += try http_response.write(&buffer, router.route(&request));
    }
    var scan: http_request.HeadScan = .{};
    const refused = http_request.parse(request_refused, &scan);
    try testing.expectError(error.MethodUnsupported, refused);
    const status = http_response.statusForParseError(error.MethodUnsupported).?;
    total += try http_response.write(&buffer, .{ .status = status, .close = true });
    return total;
}

/// A simulated run: the table, the simulator and the loop, set up in place because the
/// simulator and the loop keep pointers to the table and to each other.
const SimRun = struct {
    startup: StartupAllocator,
    /// Taken during startup; frees everything at shutdown.
    gpa: std.mem.Allocator,
    table: Table,
    sim: Sim,
    server: Server(Sim),

    const listener: io.Socket = 3;

    fn budget(capacity: u32, buffers: u32) u64 {
        assert(capacity > 0 and capacity <= constants.http_connections_max);
        assert(buffers > 0 and buffers <= constants.http_response_buffers_max);
        const per_connection: u64 = connections.entry_bytes + @sizeOf(?Conn) + request_size + @sizeOf(u16);
        return per_connection * capacity + @as(u64, buffers) * (response_size + @sizeOf(u16));
    }

    fn setUp(run: *SimRun, seed: u64, faults: Faults, capacity: u32, buffers: u32, settings: Settings) !void {
        assert(capacity > 0 and buffers > 0);
        assert(faults.percent <= constants.sim_fault_percent_max);
        run.startup = .init(testing.allocator, budget(capacity, buffers));
        run.gpa = run.startup.allocator();
        run.table = try Table.init(run.gpa, capacity);
        run.sim = .init(seed, faults.percent);
        run.sim.setDropFaults(faults.stick_percent, faults.drop_fail_percent);
        run.sim.setClientStream(client_stream, 1);
        run.sim.attachTable(&run.table);
        run.server = try .init(&run.startup, &run.sim, &run.table, listener, buffers, settings);
        // Exactly the bytes counted: nothing hidden.
        try testing.expectEqual(budget(capacity, buffers), run.startup.bytes_live);
        run.startup.finishStartup();
    }

    /// `accepting` ticks, then ticks without accepting until nothing is left, checking the
    /// loop's invariants after each.
    fn drive(run: *SimRun, accepting: u32) !void {
        assert(accepting < constants.sim_ticks_max);
        assert(run.sim.ticks == 0 and run.server.accepting);
        var tick: u32 = 0;
        while (tick < accepting) : (tick += 1) run.step();
        run.server.stopAccepting();
        while (!run.server.finished() or run.sim.in_flight > 0) : (tick += 1) {
            if (tick == constants.sim_ticks_max - 1) return error.TestUnexpectedResult;
            run.step();
        }
        try testing.expectEqual(@as(u32, 0), run.table.count());
        try testing.expectEqual(run.server.counts.accepts, run.server.counts.releases);
        try testing.expectEqual(run.server.counts.releases, run.sim.released);
        try testing.expectEqual(run.sim.bytes_sent, run.server.counts.bytes_sent);
        try testing.expectEqual(run.sim.bytes_received, run.server.counts.bytes_received);
        // The loop waits out every Backpressure itself, so no accept was early.
        try testing.expectEqual(@as(u64, 0), run.sim.accept_wait.refused);
        try testing.expectEqual(@as(u64, 0), run.server.counts.accept_too_soon);
    }

    fn step(run: *SimRun) void {
        const ticks_before = run.sim.ticks;
        assert(ticks_before < constants.sim_ticks_max);
        run.sim.tick();
        _ = run.server.tick();
        run.server.checkInvariants();
        assert(run.sim.ticks == ticks_before + 1);
    }

    fn tearDown(run: *SimRun) void {
        assert(run.sim.in_flight == 0);
        run.startup.beginShutdown();
        run.server.deinit(run.gpa);
        run.table.deinit(run.gpa);
        assert(run.startup.bytes_live == 0);
    }
};

const Faults = struct {
    percent: u8 = 0,
    stick_percent: u8 = 0,
    drop_fail_percent: u8 = 0,
};

/// Deadlines in ticks of simulated time, so a run sees each many times: a byte takes at
/// most `sim_completion_delay_ticks_max` ticks, so a request of under 60 bytes arrives
/// within the read deadline unless its client goes silent.
fn simSettings(write_ticks: u64) Settings {
    assert(write_ticks > 0);
    const result: Settings = .{
        .idle_ns = 1_000 * constants.tick_ns,
        .read_ns = 1_500 * constants.tick_ns,
        .write_ns = write_ticks * constants.tick_ns,
    };
    assert(request_post.len * (constants.sim_completion_delay_ticks_max + 1) * constants.tick_ns < result.read_ns);
    return result;
}

/// The simulator holds every slot of the ring, so runs live in static memory rather than
/// on the stack.
var sim_runs: [1]SimRun = undefined;

test "server: byte-at-a-time clients get every answer and the refusal, then every entry is released" {
    const run = &sim_runs[0];
    try run.setUp(1, .{}, 16, 4, simSettings(400));
    // Torn down only on success: a failed run leaks, which the test allocator reports,
    // rather than stopping the whole test binary on a teardown assertion.
    try run.drive(3_000);
    const counts = run.server.counts;
    run.tearDown();
    // With no faults every client sends its whole stream and gets all four answers.
    try testing.expect(counts.accepts > 16); // Entries were reused.
    try testing.expect(counts.accept_failures > 0); // The table filled: arrivals were refused.
    try testing.expectEqual(counts.accepts * client_answered, counts.requests);
    try testing.expectEqual(counts.accepts, counts.refusals);
    try testing.expectEqual(counts.accepts * (client_answered + 1), counts.responses);
    try testing.expectEqual(counts.accepts * try clientResponseBytes(), counts.bytes_sent);
    try testing.expectEqual(counts.accepts * client_stream.len, counts.bytes_received);
    // Nothing was late, dropped or refused for room.
    const late = counts.deadlines_reading + counts.deadlines_writing + counts.deadlines_closing;
    try testing.expectEqual(@as(u64, 0), late + counts.drops + counts.retries + counts.cancels);
}

test "server: the request limit closes a connection after its last allowed answer" {
    const run = &sim_runs[0];
    var settings = simSettings(400);
    settings.requests_max = 2;
    try run.setUp(3, .{}, 16, 4, settings);
    try run.drive(2_000);
    const counts = run.server.counts;
    run.tearDown();
    // Each client gets the page and the POST's answer; the second closes, so the HEAD and
    // the refused request are never read.
    try testing.expectEqual(counts.accepts * 2, counts.requests);
    try testing.expectEqual(counts.accepts * 2, counts.responses);
    try testing.expectEqual(@as(u64, 0), counts.refusals);
    try testing.expectEqual(counts.accepts * (request_get.len + request_post.len), counts.bytes_received);
}

test "server: one response buffer for many connections: each waits its turn, and all are answered" {
    const run = &sim_runs[0];
    try run.setUp(2, .{}, 32, 1, simSettings(2_000));
    try run.drive(2_000);
    const counts = run.server.counts;
    run.tearDown();
    try testing.expect(counts.buffer_waits > 0);
    try testing.expectEqual(counts.accepts * (client_answered + 1), counts.responses);
    try testing.expectEqual(counts.accepts * try clientResponseBytes(), counts.bytes_sent);
    try testing.expectEqual(@as(u64, 0), counts.deadlines_writing + counts.waits_dropped);
}

test "server: a connection whose write deadline passes while it waits for a buffer is dropped and released" {
    const run = &sim_runs[0];
    // One buffer for 32 connections, and a write deadline shorter than the queue takes.
    try run.setUp(4, .{}, 32, 1, simSettings(20));
    try run.drive(2_000);
    const counts = run.server.counts;
    run.tearDown();
    try testing.expect(counts.waits_dropped > 0);
    try testing.expect(counts.deadlines_writing >= counts.waits_dropped);
    // Every one that was answered got whole answers; drive checked every entry released.
    try testing.expect(counts.responses > 0 and counts.responses < counts.accepts * (client_answered + 1));
}

test "server: faults, silent clients and failing drops: every path is taken, and a seed replays exactly" {
    const faults: Faults = .{ .percent = 1, .stick_percent = 1, .drop_fail_percent = 50 };
    var backpressure: u64 = 0;
    var seed: u64 = 1;
    while (seed <= 3) : (seed += 1) {
        var runs: [2]Counts = undefined;
        for (&runs) |*counts| {
            const run = &sim_runs[0];
            try run.setUp(seed, faults, 32, 4, simSettings(100));
            try run.drive(6_000);
            counts.* = run.server.counts;
            run.tearDown();
        }
        const first = runs[0];
        try testing.expectEqualDeep(first, runs[1]);
        // A seed that reaches none of these paths tests too little.
        try testing.expect(first.deadlines_reading > 0 and first.drops > 0 and first.exhausted > 0);
        try testing.expect(first.cancels > 0 and first.retries > 0 and first.responses > 0);
        try testing.expect(first.trace != fnv_offset);
        backpressure += first.accept_backpressure;
    }
    // Some accept came back with Backpressure, and the loop waited it out (drive checks
    // the I/O type refused none as too soon).
    try testing.expect(backpressure > 0);
}

/// Ticks a test over a real socket may take. Reason: each tick that finds nothing waits a
/// millisecond, so this is seconds, far past what a local socket needs.
const real_ticks_max: u32 = 5_000;

/// The real I/O type and its ring, in static memory: it holds a slot for every operation
/// the ring can.
var real_io: io.real.Real = undefined;

/// A test over a real Unix socket: a private directory under /tmp, the listener in it, a
/// table, the real I/O type and the loop.
const RealRun = struct {
    dir: [48:0]u8,
    path: [64:0]u8,
    startup: StartupAllocator,
    gpa: std.mem.Allocator,
    table: Table,
    listener: io.listener.Listener,
    server: Server(io.real.Real),
    /// What the client has read so far, and how much `readDone` waits for: that many
    /// bytes, or end of stream when 0.
    reading: Reading,
    want: u32,

    const capacity: u32 = 4;

    fn setUp(run: *RealRun) !void {
        comptime assert("/tmp/cc-server-ffffffffffffffff/s".len < @typeInfo(@TypeOf(run.path)).array.len);
        var random: [8]u8 = undefined;
        try testing.expectEqual(random.len, linux.getrandom(&random, random.len, 0));
        const tag = std.mem.readInt(u64, &random, .little);
        _ = try std.fmt.bufPrintSentinel(&run.dir, "/tmp/cc-server-{x}", .{tag}, 0);
        _ = try std.fmt.bufPrintSentinel(&run.path, "/tmp/cc-server-{x}/s", .{tag}, 0);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mkdir(&run.dir, 0o700)));
        errdefer run.removeDir();
        const per_connection: u64 = connections.entry_bytes + @sizeOf(?Conn) + request_size + @sizeOf(u16);
        const budget = per_connection * capacity + response_size + @sizeOf(u16);
        run.startup = .init(testing.allocator, budget);
        run.gpa = run.startup.allocator();
        run.table = try Table.init(run.gpa, capacity);
        errdefer run.table.deinit(run.gpa);
        run.listener = try io.listener.open(std.mem.sliceTo(&run.path, 0));
        errdefer run.listener.close();
        real_io = try io.real.Real.init(&run.startup, &run.table);
        errdefer real_io.deinit();
        run.server = try .init(&run.startup, &real_io, &run.table, run.listener.socket, 1, .{});
        // Exactly the bytes counted, the ring's own memory being the kernel's: nothing hidden.
        try testing.expectEqual(budget, run.startup.bytes_live);
        run.startup.finishStartup();
        assert(run.table.count() == 0);
    }

    /// Ticks until `done` holds, waiting a millisecond after a tick that found nothing.
    fn tickUntil(run: *RealRun, comptime done: fn (*RealRun, linux.fd_t) bool, client: linux.fd_t) !void {
        assert(client >= -1);
        var ticks: u32 = 0;
        while (!done(run, client)) : (ticks += 1) {
            if (ticks == real_ticks_max) return error.TestUnexpectedResult;
            if (run.server.tick() == 0) {
                const pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
                _ = linux.nanosleep(&pause, null);
            }
            run.server.checkInvariants();
        }
        assert(ticks <= real_ticks_max);
    }

    /// Stops accepting, then serves one more client that connects and closes at once, so
    /// the accept in flight completes, and ticks until nothing is left.
    fn finish(run: *RealRun) !void {
        assert(run.server.accepting);
        assert(run.server.accept != null); // The loop keeps one in flight.
        run.server.stopAccepting();
        const last = try run.connect();
        _ = linux.close(last);
        try run.tickUntil(finishedDone, -1);
        try testing.expectEqual(run.server.counts.accepts, real_io.released);
    }

    fn finishedDone(run: *RealRun, client: linux.fd_t) bool {
        assert(client == -1);
        assert(!run.server.accepting);
        return run.server.finished();
    }

    /// A client socket connected to the listener: the kernel completes it from the
    /// listener's backlog, before anything accepts it.
    fn connect(run: *RealRun) !linux.fd_t {
        const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
        const client: linux.fd_t = @intCast(rc);
        assert(client > linux.STDERR_FILENO);
        errdefer _ = linux.close(client);
        var address: linux.sockaddr.un = .{ .path = @splat(0) };
        const path = std.mem.sliceTo(&run.path, 0);
        @memcpy(address.path[0..path.len], path);
        assert(path.len < address.path.len and address.path[path.len] == 0);
        const connected = linux.connect(client, @ptrCast(&address), @sizeOf(linux.sockaddr.un));
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(connected));
        return client;
    }

    fn tearDown(run: *RealRun) void {
        assert(run.table.count() == 0);
        real_io.deinit();
        run.listener.close();
        run.startup.beginShutdown();
        run.server.deinit(run.gpa);
        run.table.deinit(run.gpa);
        assert(run.startup.bytes_live == 0);
        run.removeDir();
    }

    /// Removes the lock file the listener leaves beside its socket, then the directory.
    fn removeDir(run: *RealRun) void {
        var lock: [72:0]u8 = undefined;
        // The path and the suffix fit the buffer, so the print can't run out of room.
        assert(std.mem.sliceTo(&run.path, 0).len + ".lock".len < lock.len);
        const lock_path = std.fmt.bufPrintSentinel(&lock, "{s}.lock", .{std.mem.sliceTo(&run.path, 0)}, 0) catch unreachable;
        assert(std.mem.endsWith(u8, lock_path, ".lock"));
        // The directory is this test's own, 0700 from its mkdir, so the lock in it is ours.
        _ = linux.unlink(lock_path);
        if (linux.errno(linux.rmdir(&run.dir)) != .SUCCESS) std.log.warn("test dir {s}: rmdir failed", .{&run.dir});
    }
};

/// Writes all of `bytes` to a blocking client socket.
fn clientWrite(client: linux.fd_t, bytes: []const u8) !void {
    assert(bytes.len > 0);
    assert(client > linux.STDERR_FILENO);
    const written = linux.write(client, bytes.ptr, bytes.len);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(written));
    // A local socket's buffer takes a short request whole.
    try testing.expectEqual(bytes.len, written);
}

/// What a client has read so far, and whether it has read end of stream.
const Reading = struct {
    bytes: [4096]u8 = undefined,
    len: u32 = 0,
    ended: bool = false,
};

/// Reads what has arrived, without waiting, and says whether the client holds the bytes
/// `run.want` names, or end of stream when it wants none.
fn readDone(run: *RealRun, client: linux.fd_t) bool {
    assert(client >= 0);
    // Room left, so a read of 0 means end of stream, never a full buffer.
    assert(run.reading.len < run.reading.bytes.len);
    const room = run.reading.bytes[run.reading.len..];
    const rc = linux.recvfrom(client, room.ptr, room.len, linux.MSG.DONTWAIT, null, null);
    if (linux.errno(rc) == .SUCCESS) {
        if (rc == 0) run.reading.ended = true;
        run.reading.len += @intCast(rc);
    }
    return if (run.want == 0) run.reading.ended else run.reading.len >= run.want;
}

/// Clears what the client has read and sets what `readDone` waits for.
fn expectRead(run: *RealRun, want: usize) void {
    assert(want <= run.reading.bytes.len);
    // Room left past what is wanted, and nothing wanted shorter than a status line.
    assert(want < run.reading.bytes.len);
    assert(want == 0 or want >= "HTTP/1.1 200 OK\r\n".len);
    run.reading = .{};
    run.want = @intCast(want);
}

/// The response the router gives `text`, written with or without Connection: close.
fn expectedResponse(text: []const u8, close: bool, buffer: []u8) ![]const u8 {
    assert(text.len > 0);
    assert(buffer.len > 0);
    var scan: http_request.HeadScan = .{};
    const request = try http_request.parse(text, &scan);
    var response = router.route(&request);
    response.close = close;
    const len = try http_response.write(buffer, response);
    return buffer[0..len];
}

test "server: over a real Unix socket, a client gets the page, then a HEAD that closes" {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;
    var run: RealRun = undefined;
    try run.setUp();
    const client = try run.connect();
    defer _ = linux.close(client);
    var expected_bytes: [2048]u8 = undefined;

    // A kept-alive GET gets the page, byte for byte, and the connection stays open.
    try clientWrite(client, request_get);
    const page = try expectedResponse(request_get, false, &expected_bytes);
    expectRead(&run, page.len);
    try run.tickUntil(readDone, client);
    try testing.expectEqualStrings(page, run.reading.bytes[0..run.reading.len]);
    try testing.expect(!run.reading.ended);

    // A HEAD asking to close gets the page's head with Connection: close, then end of stream.
    const head_close = "HEAD / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    try clientWrite(client, head_close);
    const head = try expectedResponse(head_close, true, &expected_bytes);
    expectRead(&run, 0);
    try run.tickUntil(readDone, client);
    try testing.expectEqualStrings(head, run.reading.bytes[0..run.reading.len]);
    try testing.expect(std.mem.find(u8, head, "Connection: close\r\n") != null);
    try testing.expectEqual(@as(u64, 2), run.server.counts.responses);
    try run.finish();
    try testing.expectEqual(@as(u64, 2), run.server.counts.accepts);
    run.tearDown();
}

test "server: over a real Unix socket, a refused head gets its status and the connection closes" {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;
    var run: RealRun = undefined;
    try run.setUp();
    const client = try run.connect();
    defer _ = linux.close(client);
    try clientWrite(client, "GET / HTTP/1.1\r\n\r\n"); // HTTP/1.1 without a Host field.
    expectRead(&run, 0);
    try run.tickUntil(readDone, client);
    const refusal = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    try testing.expectEqualStrings(refusal, run.reading.bytes[0..run.reading.len]);
    try testing.expectEqual(@as(u64, 1), run.server.counts.refusals);
    try run.finish();
    run.tearDown();
}

test "server: over a real Unix socket, pipelined bytes and HTTP/1.0 each close after one answer" {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;
    var run: RealRun = undefined;
    try run.setUp();
    var expected_bytes: [2048]u8 = undefined;
    const texts = [_][]const u8{
        // A second request behind the first: no pipelining, so only the first is answered.
        request_get ++ request_get,
        // HTTP/1.0 closes by default.
        "GET / HTTP/1.0\r\n\r\n",
    };
    for (texts) |text| {
        const client = try run.connect();
        defer _ = linux.close(client);
        try clientWrite(client, text);
        expectRead(&run, 0);
        try run.tickUntil(readDone, client);
        const first = try expectedResponse(text, true, &expected_bytes);
        try testing.expectEqualStrings(first, run.reading.bytes[0..run.reading.len]);
    }
    try testing.expectEqual(@as(u64, texts.len), run.server.counts.responses);
    try run.finish();
    run.tearDown();
}
