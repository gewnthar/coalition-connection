//! Coalition Connection: an EVE Online coalition auth server.
//!
//! Rules: safety first, then speed; no allocation after startup; every loop bounded;
//! functions of at most 70 lines with at least two assertions; every error handled.
//! See docs/architecture.md for the components and docs/roadmap.md for the build order.

pub const constants = @import("constants.zig");
pub const BoundedQueue = @import("bounded_queue.zig").BoundedQueue;
pub const StartupAllocator = @import("startup_allocator.zig").StartupAllocator;
pub const io = @import("io/root.zig");

// Components, in build order.
pub const sso = @import("sso/root.zig");
pub const esi = @import("esi/root.zig");
pub const access = @import("access/root.zig");
pub const storage = @import("storage/root.zig");
pub const live = @import("live/root.zig");
pub const importer = @import("importer/root.zig");
pub const services = @import("services/root.zig");
pub const taxes = @import("taxes/root.zig");
pub const audits = @import("audits/root.zig");
pub const srp = @import("srp/root.zig");

test {
    _ = constants;
    _ = @import("bounded_queue.zig");
    _ = @import("startup_allocator.zig");
    _ = io;
    _ = sso;
    _ = esi;
    _ = access;
    _ = storage;
    _ = live;
    _ = importer;
    _ = services;
    _ = taxes;
    _ = audits;
    _ = srp;
}
