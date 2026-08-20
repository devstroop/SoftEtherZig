//! L2 bridge forwarding engine (proposal §4.3).
//!
//! Pure logic, no I/O: the packet pump (loop.zig, future milestone) feeds
//! frames; the engine learns MAC addresses, resolves unicast destinations,
//! and decides flooding. The engine operates over N ports sharing one FDB
//! (multi-ingress ready).
//!
//! Forwarding rules:
//! - **Learn** the source MAC per ingress frame.
//! - **Unicast** (known destination) → forward to exactly one port.
//! - **Broadcast / multicast / unknown-unicast** → flood to ALL other ports
//!   (never back to the source — **no-echo loop guard**).
//! - Per-port counters: forwarded / flooded / blocked.
//!
//! Documented limitation (proposal §4.3): multiple ingress NICs attached to
//! the *same LAN segment* can loop (no-echo alone is insufficient). The
//! bridge reports a warning at attach time if two ingress NICs look like
//! they share a segment; STP is deferred (§11 Q2).

const std = @import("std");
const fdb_mod = @import("fdb.zig");
const FdbTable = fdb_mod.FdbTable;
const MacAddress = fdb_mod.MacAddress;

/// Where a frame must be sent.
pub const ForwardAction = union(enum) {
    /// Known unicast destination on one port.
    unicast: u16,
    /// Flood to every port except `src_port` (no-echo loop guard).
    flood: void,
    /// The frame must not be forwarded (destination port == source port).
    drop: void,
};

/// Per-port traffic counters (proposal §4.3).
pub const PortCounters = struct {
    /// Frames forwarded to this port via unicast resolution.
    forwarded: u64 = 0,
    /// Frames that hit a full/blocked state (destination == source).
    blocked: u64 = 0,
    /// Frames flooded to this port (bcast/mcast/unknown-unicast).
    flooded: u64 = 0,
};

/// Destination MAC classification.
pub const DestKind = enum {
    broadcast,
    multicast,
    unicast,
};

/// The bridge engine: owns the shared FDB and per-port counters.
///
/// Not thread-safe by design — the bridge loop thread is the sole caller.
/// `now` is seconds since an arbitrary epoch (the pump injects its clock,
/// keeping tests deterministic).
pub const BridgeEngine = struct {
    fdb: FdbTable,
    /// Per-port counters; indexed by port id (u16, dense).
    counters: []PortCounters,
    /// Number of ports the engine was created for.
    port_count: u16,
    /// Aging timeout in seconds (default from FdbTable).
    aging_s: u32 = fdb_mod.DEFAULT_AGING_S,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, port_count: u16) !BridgeEngine {
        if (port_count == 0) return error.InvalidPortCount;
        const counters = try allocator.alloc(PortCounters, port_count);
        errdefer allocator.free(counters);
        @memset(counters, .{});
        return .{
            .fdb = try FdbTable.init(allocator),
            .counters = counters,
            .port_count = port_count,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BridgeEngine) void {
        self.fdb.deinit();
        self.allocator.free(self.counters);
        self.* = undefined;
    }

    /// Learn the source MAC of a frame (refresh or move). Table overflow
    /// is not fatal: the engine floods instead, so errors are swallowed.
    pub fn learn(self: *BridgeEngine, src_mac: MacAddress, src_port: u16, now: u32) void {
        self.fdb.learn(src_mac, src_port, now) catch |err| switch (err) {
            error.TableFull => {},
        };
    }

    /// Learn with explicit VLAN ID.
    pub fn learnVlan(self: *BridgeEngine, src_mac: MacAddress, src_port: u16, now: u32, vlan_id: u16) void {
        self.fdb.learnVlan(src_mac, src_port, now, vlan_id) catch |err| switch (err) {
            error.TableFull => {},
        };
    }

    /// Resolve the destination of a frame arriving on `src_port`.
    pub fn classifyDest(_: *const BridgeEngine, dst_mac: MacAddress) DestKind {
        if (isBroadcast(dst_mac)) return .broadcast;
        if (isMulticast(dst_mac)) return .multicast;
        return .unicast;
    }

    /// Decide where a frame must go. Never returns the source port
    /// (no-echo loop guard): if the only candidate port is the source
    /// itself, the frame is dropped. Uses VLAN 0 (untagged) by default.
    pub fn resolve(
        self: *const BridgeEngine,
        dst_mac: MacAddress,
        src_port: u16,
    ) ForwardAction {
        return self.resolveVlan(dst_mac, src_port, 0);
    }

    /// Resolve with explicit VLAN ID. The FDB lookup uses the composite
    /// (dst_mac, vlan_id) key.
    pub fn resolveVlan(
        self: *const BridgeEngine,
        dst_mac: MacAddress,
        src_port: u16,
        vlan_id: u16,
    ) ForwardAction {
        const kind = self.classifyDest(dst_mac);
        if (kind != .unicast) {
            if (self.port_count <= 1) return .drop;
            return .flood;
        }
        const dest_port = self.fdb.lookup(dst_mac, vlan_id) orelse {
            if (self.port_count <= 1) return .drop;
            return .flood;
        };
        if (dest_port == src_port) return .drop;
        return .{ .unicast = dest_port };
    }

    /// Record a forwarding outcome (called by the pump after `resolve`).
    /// The pump calls this once per port actually sent to, so counters
    /// reflect real traffic.
    pub fn noteForwarded(self: *BridgeEngine, port: u16, action: ForwardAction) void {
        if (port >= self.port_count) return;
        switch (action) {
            .unicast => self.counters[port].forwarded += 1,
            .flood => self.counters[port].flooded += 1,
            .drop => self.counters[port].blocked += 1,
        }
    }

    /// Age the FDB. Returns entries aged out this tick.
    pub fn age(self: *BridgeEngine, now: u32) usize {
        self.fdb.aging_s = self.aging_s;
        return self.fdb.age(now);
    }

    pub fn getCounters(self: *const BridgeEngine, port: u16) PortCounters {
        if (port >= self.port_count) return .{};
        return self.counters[port];
    }

    /// The engine's FDB (for diagnostics / stats).
    pub fn getFdb(self: *const BridgeEngine) *const FdbTable {
        return &self.fdb;
    }
};

/// Broadcast: FF:FF:FF:FF:FF:FF.
pub fn isBroadcast(mac: MacAddress) bool {
    for (mac) |b| {
        if (b != 0xFF) return false;
    }
    return true;
}

/// Multicast: low bit of the first octet set.
pub fn isMulticast(mac: MacAddress) bool {
    return (mac[0] & 0x01) != 0;
}

// ============================================================================
// Tests
// ============================================================================

fn makeMac(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) MacAddress {
    return .{ a, b, c, d, e, f };
}

test "engine learns src MAC and resolves known unicast" {
    var e = try BridgeEngine.init(std.testing.allocator, 4);
    defer e.deinit();

    e.learn(makeMac(2, 0, 0, 0, 0, 1), 1, 100);
    const action = e.resolve(makeMac(2, 0, 0, 0, 0, 1), 2);
    try std.testing.expectEqual(ForwardAction{ .unicast = 1 }, action);
}

test "engine no-echo: destination on source port is dropped" {
    var e = try BridgeEngine.init(std.testing.allocator, 4);
    defer e.deinit();

    e.learn(makeMac(2, 0, 0, 0, 0, 1), 1, 100);
    const action = e.resolve(makeMac(2, 0, 0, 0, 0, 1), 1);
    try std.testing.expectEqual(ForwardAction.drop, action);
}

test "engine floods broadcast and multicast to all other ports" {
    var e = try BridgeEngine.init(std.testing.allocator, 4);
    defer e.deinit();

    try std.testing.expectEqual(ForwardAction.flood, e.resolve(makeMac(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF), 2));
    try std.testing.expectEqual(ForwardAction.flood, e.resolve(makeMac(0x01, 0x00, 0x5E, 0x00, 0x00, 0x01), 2));
}

test "engine single-port network drops (no other port to flood to)" {
    var e = try BridgeEngine.init(std.testing.allocator, 1);
    defer e.deinit();

    try std.testing.expectEqual(ForwardAction.drop, e.resolve(makeMac(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF), 0));
    try std.testing.expectEqual(ForwardAction.drop, e.resolve(makeMac(2, 0, 0, 0, 0, 1), 0));
}

test "engine unknown-unicast floods" {
    var e = try BridgeEngine.init(std.testing.allocator, 3);
    defer e.deinit();

    const action = e.resolve(makeMac(9, 9, 9, 9, 9, 9), 1);
    try std.testing.expectEqual(ForwardAction.flood, action);
}

test "engine counters track forwarded/flooded/blocked" {
    var e = try BridgeEngine.init(std.testing.allocator, 3);
    defer e.deinit();

    e.learn(makeMac(2, 0, 0, 0, 0, 1), 1, 100);

    const a1 = e.resolve(makeMac(2, 0, 0, 0, 0, 1), 2); // unicast → 1
    e.noteForwarded(1, a1);
    const a2 = e.resolve(makeMac(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF), 2); // flood
    e.noteForwarded(0, a2);
    e.noteForwarded(1, a2);
    const a3 = e.resolve(makeMac(2, 0, 0, 0, 0, 1), 1); // no-echo → drop
    e.noteForwarded(0, a3);

    const c1 = e.getCounters(1);
    try std.testing.expectEqual(@as(u64, 1), c1.forwarded); // unicast
    try std.testing.expectEqual(@as(u64, 1), c1.flooded); // bcast flood
    const c0 = e.getCounters(0);
    try std.testing.expectEqual(@as(u64, 1), c0.flooded); // bcast flood
    try std.testing.expectEqual(@as(u64, 1), c0.blocked); // no-echo drop
}

test "engine aging via injected clock" {
    var e = try BridgeEngine.init(std.testing.allocator, 3);
    defer e.deinit();
    e.aging_s = 300;

    e.learn(makeMac(2, 0, 0, 0, 0, 1), 1, 0);
    e.learn(makeMac(2, 0, 0, 0, 0, 2), 2, 100);

    const aged = e.age(350);
    try std.testing.expectEqual(@as(usize, 1), aged);
    try std.testing.expectEqual(ForwardAction.flood, e.resolve(makeMac(2, 0, 0, 0, 0, 1), 2)); // aged → unknown → flood
    try std.testing.expectEqual(ForwardAction{ .unicast = 2 }, e.resolve(makeMac(2, 0, 0, 0, 0, 2), 1)); // still fresh
}