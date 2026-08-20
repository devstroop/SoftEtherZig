//! Bridge Module
//!
//! L2 network bridge: forwarding database (fdb), forwarding engine
//! (engine), and the data pump (loop) that shuttles raw Ethernet frames
//! between LAN ingress ports (AF_PACKET on Linux) and the SoftEther
//! session tunnel. Only active when `network_mode == .bridge`.

const std = @import("std");

// Submodules
pub const fdb = @import("fdb.zig");
pub const engine = @import("engine.zig");
pub const loop = @import("loop.zig");
pub const local_bridge = @import("local_bridge.zig");
pub const rate_limiter = @import("rate_limiter.zig");

// Re-export main types
pub const FdbTable = fdb.FdbTable;
pub const FdbEntry = fdb.FdbEntry;
pub const MacAddress = fdb.MacAddress;
pub const BridgeEngine = engine.BridgeEngine;
pub const ForwardAction = engine.ForwardAction;
pub const PortCounters = engine.PortCounters;
pub const BridgeLoop = loop.BridgeLoop;
pub const BridgeStats = loop.BridgeStats;
pub const SessionSink = loop.SessionSink;
pub const LocalBridge = local_bridge.LocalBridge;

// ============================================================================
// Tests
// ============================================================================

test {
    std.testing.refAllDecls(@This());
}