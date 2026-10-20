//! I/O boundary: the only way any component reaches the network, the clock or the database.
//!
//! Job: define the contract an I/O type must meet, so the same component code runs against
//! the real system in production and against the deterministic simulator (`sim.zig`) in
//! tests. Components take the I/O type as a `comptime IO: type` parameter, which keeps
//! dispatch static: no function pointers and no hidden allocation.
//!
//! Contract (every method is `pub`, so `@hasDecl` sees it):
//!   now(self) Instant                                  monotonic clock, nanoseconds
//!   send(self, peer: PeerId, bytes) SendError!void     one outgoing message to a peer
//!   execute(self, statement) DatabaseError!void        one database statement
//!
//! Inputs: whatever the component hands to `send` and `execute`.
//! Outputs: time readings and explicit errors; every error is handled by the caller.
//! Limits: messages are at most `constants.http_response_size_max` bytes, statements at
//! most `constants.postgres_message_size_max` bytes.
//!
//! Status: contract and simulator only. The production implementation arrives with the
//! event-loop slice in docs/roadmap.md, and the contract grows (receive, connect, timers)
//! slice by slice.

const std = @import("std");
const assert = std.debug.assert;

pub const sim = @import("sim.zig");

/// Nanoseconds on a monotonic clock. Never wall-clock time.
pub const Instant = u64;

/// Index of a connection in the startup-sized connection table.
pub const PeerId = u32;

pub const SendError = error{ PeerDown, Backpressure };
pub const DatabaseError = error{ Unavailable, Timeout };

/// Fails compilation when `IO` does not meet the contract above.
pub fn assertContract(comptime IO: type) void {
    comptime {
        assert(@hasDecl(IO, "now"));
        assert(@hasDecl(IO, "send"));
        assert(@hasDecl(IO, "execute"));
    }
}

test "io: the simulator meets the contract" {
    assertContract(sim.Sim);
    try std.testing.expect(@hasDecl(sim.Sim, "now"));
}

test {
    _ = sim;
}
