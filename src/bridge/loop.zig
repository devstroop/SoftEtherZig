//! Bridge packet pump (L2 Network Bridge proposal §4.2, H-1).
//!
//! Bridge connections do NOT run the client data loop (`runDataLoop`):
//! they run the pump in this module from connect() start. No two pumps ever
//! touch one session — there are no queue / keepalive / compression races.
//!
//! Architecture (proposal I-5 / I-7):
//! - The pump polls over [AF_PACKET ingress fds + session fd].
//! - Session blocks → `dispatchSessionBlock` → L2 frames out the LAN ports.
//! - LAN frames → `dispatchPortFrame` → `BridgeEngine` (learn/classify/resolve)
//!   → unicast to one port, or flood to the session + all other LAN ports.
//! - Keepalives continue at the session level (shared helper, issue #50).
//!
//! v1 limitations (documented):
//! - Single TCP connection (proposal I-14): multi-connection bridge is a
//!   later milestone; `max_connections` is ignored (WARN) by the caller.
//! - Frame budget 1514 (proposal §4.6): frames beyond the budget are not
//!   forwarded; the port layer counts them in `PortStats.drops` (H-3).
//! - UDP acceleration is NOT used for bridge traffic (v1 keeps the pump
//!   TCP-only; the data channel remains session-level keepalive).
//! - The client performs no DHCP/ARP: bridged LAN devices get their IP from
//!   the hub (SecureNAT or upstream bridge). The hub must permit bridge
//!   connections; the test scenario runs SecureNAT at the hub (L-3).
//!
//! The dispatch functions are pure (no I/O beyond `NetPort.write` and the
//! injected session sink), so the data path is deterministic and unit-
//! testable with in-memory ports.

const std = @import("std");
const Allocator = std.mem.Allocator;

const port_mod = @import("../adapter/port.zig");
const NetPort = port_mod.NetPort;
const engine_mod = @import("engine.zig");
const BridgeEngine = engine_mod.BridgeEngine;
const ForwardAction = engine_mod.ForwardAction;
const fdb_mod = @import("fdb.zig");
const MacAddress = fdb_mod.MacAddress;
const rate_limiter_mod = @import("rate_limiter.zig");
const TokenBucket = rate_limiter_mod.TokenBucket;

/// Must match `adapter/af_packet.zig`'s session L2 frame budget.
pub const SESSION_FRAME_BUDGET: usize = 1514;

/// 802.1Q VLAN tag ethertype (network byte order).
pub const VLAN_ETHERTYPE: u16 = 0x8100;
/// 802.1Q tag size in bytes.
pub const VLAN_TAG_SIZE: usize = 4;

/// Per-port bridge configuration (trunk/access, rate limiting).
pub const PortConfig = struct {
    /// Port VLAN mode.
    mode: PortVlanMode = .access,
    /// Native VLAN for trunk ports (untagged traffic assigned to this VLAN).
    native_vlan: u16 = 1,
    /// Allowed VLANs for trunk ports. Empty = all VLANs allowed.
    allowed_vlans: [32]u16 = .{0} ** 32,
    /// Number of valid entries in `allowed_vlans`.
    allowed_vlan_count: u8 = 0,
    /// Ingress rate limit (LAN → engine). null = unlimited.
    ingress_limit: ?TokenBucket.Config = null,
    /// Egress rate limit (engine → LAN). null = unlimited.
    egress_limit: ?TokenBucket.Config = null,
};

pub const PortVlanMode = enum {
    /// Access port: traffic is tagged with `native_vlan`; incoming 802.1Q
    /// tags are stripped.
    access,
    /// Trunk port: carries tagged traffic for multiple VLANs; native VLAN
    /// is assigned to untagged traffic.
    trunk,
};

/// 802.1Q VLAN tag parsed from an Ethernet frame.
pub const VlanTag = struct {
    vlan_id: u16,
    /// Priority code point (3 bits).
    pcp: u3 = 0,
    /// Drop eligible indicator.
    dei: bool = false,
};

/// Extract the 802.1Q VLAN tag from a frame, if present.
/// Returns null if the frame has no VLAN tag (ethertype != 0x8100).
pub fn parseVlanTag(frame: []const u8) ?VlanTag {
    if (frame.len < 14 + VLAN_TAG_SIZE) return null;
    const ethertype = std.mem.readInt(u16, frame[12..14], .big);
    if (ethertype != VLAN_ETHERTYPE) return null;
    const tci = std.mem.readInt(u16, frame[14..16], .big);
    return .{
        .pcp = @truncate(tci >> 13),
        .dei = (tci >> 12) & 1 != 0,
        .vlan_id = tci & 0x0FFF,
    };
}

/// Build the TCI (Tag Control Information) field from VLAN tag components.
pub fn buildTci(vlan_id: u16, pcp: u3, dei: bool) u16 {
    return (@as(u16, pcp) << 13) | (@as(u16, @intFromBool(dei)) << 12) | (vlan_id & 0x0FFF);
}

/// Insert a 802.1Q tag into a frame at offset 12 (after DST+SRC MACs).
/// The frame must be at least 14 bytes (ethernet header). Returns the
/// expanded frame. Caller provides an output buffer of sufficient size.
/// Returns error.FrameTooSmall if the frame is too short.
pub fn insertVlanTag(
    frame: []const u8,
    vlan_id: u16,
    pcp: u3,
    dei: bool,
    out: []u8,
) ![]u8 {
    if (frame.len < 14) return error.FrameTooSmall;
    const out_len = frame.len + VLAN_TAG_SIZE;
    if (out.len < out_len) return error.BufferTooSmall;

    // Copy DST + SRC MACs (12 bytes).
    @memcpy(out[0..12], frame[0..12]);
    // Insert 802.1Q ethertype.
    std.mem.writeInt(u16, out[12..14], VLAN_ETHERTYPE, .big);
    // TCI: PCP(3) | DEI(1) | VLAN_ID(12).
    std.mem.writeInt(u16, out[14..16], buildTci(vlan_id, pcp, dei), .big);
    // Copy remaining payload (original ethertype + data).
    @memcpy(out[16..out_len], frame[12..]);
    return out[0..out_len];
}

/// Strip the 802.1Q tag from a frame (shift payload left by 4 bytes).
/// Returns the shortened frame. Caller provides an output buffer.
pub fn stripVlanTag(frame: []const u8, out: []u8) ![]u8 {
    if (frame.len < 14 + VLAN_TAG_SIZE) return error.FrameTooSmall;
    const ethertype = std.mem.readInt(u16, frame[12..14], .big);
    if (ethertype != VLAN_ETHERTYPE) {
        // No VLAN tag — just copy through.
        if (out.len < frame.len) return error.BufferTooSmall;
        @memcpy(out[0..frame.len], frame);
        return out[0..frame.len];
    }
    const out_len = frame.len - VLAN_TAG_SIZE;
    if (out.len < out_len) return error.BufferTooSmall;
    // DST + SRC MACs.
    @memcpy(out[0..12], frame[0..12]);
    // Original ethertype (after the VLAN tag).
    @memcpy(out[12..14], frame[16..18]);
    // Payload.
    @memcpy(out[14..out_len], frame[18..]);
    return out[0..out_len];
}

/// Where incoming Ethernet frames (LAN → VPN) go. The pump never buffers
/// frames itself; the caller's `send` delivers one complete L2 frame.
pub const SessionSink = struct {
    ctx: *anyopaque,
    /// Send one L2 frame into the session (TLS + softether framing).
    /// Errors are counted in `BridgeStats.session_tx_errors`, never fatal.
    send: *const fn (ctx: *anyopaque, frame: []const u8) anyerror!void,
};

/// Aggregate bridge-wide stats (FFI `softether_get_bridge_stats`).
pub const BridgeStats = struct {
    /// Current FDB entry count (live).
    fdb_entries: u32 = 0,
    /// Frames forwarded to exactly one port (unicast resolution).
    forwarded: u64 = 0,
    /// Frames flooded (bcast/mcast/unknown-unicast) to session + ports.
    flooded: u64 = 0,
    /// Frames dropped by no-echo (destination port == source port).
    blocked: u64 = 0,
    /// L2 frames read from LAN ingress ports.
    lan_rx_pkts: u64 = 0,
    /// L2 frames written to LAN egress ports.
    lan_tx_pkts: u64 = 0,
    /// Bytes read from LAN ingress ports.
    lan_rx_bytes: u64 = 0,
    /// Bytes written to LAN egress ports.
    lan_tx_bytes: u64 = 0,
    /// Oversize frames dropped (frame budget, H-3) or port write rejections.
    drops: u64 = 0,
    /// L2 frames received from the session and dispatched to LAN ports.
    session_rx: u64 = 0,
    /// L2 frames sent into the session.
    session_tx: u64 = 0,
    /// Session sends that failed (connection dead, etc.).
    session_tx_errors: u64 = 0,
};

/// The bridge pump. Owns the shared `BridgeEngine`; the caller owns the
/// ports (lifecycle) and the session sink.
pub const BridgeLoop = struct {
    allocator: Allocator,
    /// LAN ingress/egress ports. The engine's port index == position in
    /// `ports`; `session_port` is the engine index of the uplink.
    ports: []NetPort,
    /// Shared FDB + forwarding engine.
    engine: BridgeEngine,
    /// Engine port index representing the session (uplink) side.
    session_port: u16,
    /// Destination for LAN → VPN frames.
    sink: SessionSink,
    /// Loop-local counters (session direction + drops).
    stats: BridgeStats = .{},
    /// Per-port egress rate limiters (engine → LAN).
    egress_limiters: []?TokenBucket,
    /// Per-port ingress rate limiters (LAN → engine).
    ingress_limiters: []?TokenBucket,
    /// Per-port VLAN configuration.
    port_configs: []PortConfig,

    pub fn init(
        allocator: Allocator,
        ports: []NetPort,
        sink: SessionSink,
        fdb_max: u32,
        fdb_aging_s: u32,
    ) !BridgeLoop {
        if (ports.len == 0) return error.NoIngressPorts;
        if (ports.len >= std.math.maxInt(u16)) return error.TooManyPorts;
        var engine = try BridgeEngine.init(allocator, @intCast(ports.len + 1));
        errdefer engine.deinit();
        engine.aging_s = fdb_aging_s;
        engine.fdb.max_entries = fdb_max;
        const owned_ports = try allocator.dupe(NetPort, ports);
        errdefer allocator.free(owned_ports);

        const egress_limiters = try allocator.alloc(?TokenBucket, ports.len);
        errdefer allocator.free(egress_limiters);
        @memset(egress_limiters, null);

        const ingress_limiters = try allocator.alloc(?TokenBucket, ports.len);
        errdefer allocator.free(ingress_limiters);
        @memset(ingress_limiters, null);

        const port_configs = try allocator.alloc(PortConfig, ports.len);
        errdefer allocator.free(port_configs);
        @memset(port_configs, .{});

        return .{
            .allocator = allocator,
            .ports = owned_ports,
            .engine = engine,
            .session_port = @intCast(ports.len),
            .sink = sink,
            .egress_limiters = egress_limiters,
            .ingress_limiters = ingress_limiters,
            .port_configs = port_configs,
        };
    }

    pub fn deinit(self: *BridgeLoop) void {
        self.allocator.free(self.egress_limiters);
        self.allocator.free(self.ingress_limiters);
        self.allocator.free(self.port_configs);
        self.allocator.free(self.ports);
        self.engine.deinit();
        self.* = undefined;
    }

    /// Configure rate limiting for a port. Pass null to disable.
    pub fn setPortRateLimit(self: *BridgeLoop, port: u16, ingress: ?TokenBucket.Config, egress: ?TokenBucket.Config) void {
        if (port >= self.ports.len) return;
        self.ingress_limiters[port] = if (ingress) |cfg| TokenBucket.init(cfg) else null;
        self.egress_limiters[port] = if (egress) |cfg| TokenBucket.init(cfg) else null;
    }

    /// Configure VLAN mode for a port.
    pub fn setPortVlan(self: *BridgeLoop, port: u16, config: PortConfig) void {
        if (port >= self.ports.len) return;
        self.port_configs[port] = config;
    }

    /// Live cumulative snapshot of the bridge's aggregated stats since the
    /// pump started. `forwarded`/`flooded`/`blocked` come from the engine's
    /// per-port counters (never loop-tracked), LAN traffic from per-port
    /// stats, session traffic from the loop's own counters — each event is
    /// counted in exactly one place, so repeated polling never inflates.
    pub fn getStats(self: *const BridgeLoop) BridgeStats {
        var s = self.stats;
        s.fdb_entries = @intCast(self.engine.fdb.len());
        for (self.ports, 0..) |*p, i| {
            const cnt = self.engine.getCounters(@intCast(i));
            s.forwarded += cnt.forwarded;
            s.flooded += cnt.flooded;
            s.blocked += cnt.blocked;
            const ps = p.getStats();
            s.lan_rx_pkts += ps.rx_pkts;
            s.lan_tx_pkts += ps.tx_pkts;
            s.lan_rx_bytes += ps.rx_bytes;
            s.lan_tx_bytes += ps.tx_bytes;
            s.drops += ps.drops;
        }
        // Include the session (uplink) port counters — LAN→session unicast
        // and session-side no-echo drops land there.
        const session_cnt = self.engine.getCounters(self.session_port);
        s.forwarded += session_cnt.forwarded;
        s.flooded += session_cnt.flooded;
        s.blocked += session_cnt.blocked;
        return s;
    }

    /// Forward one block received from the session to the LAN ports.
    ///
    /// The block is a complete L2 frame (14-byte Ethernet header included —
    /// softether sessions carry Ethernet frames end-to-end). The source MAC
    /// is learned on the session port; the destination resolves to a single
    /// LAN port or floods to all of them. No-echo is handled by the engine
    /// (a destination learned on the session port is never echoed back).
    pub fn dispatchSessionBlock(self: *BridgeLoop, block: []const u8) void {
        self.stats.session_rx += 1;
        if (block.len < 14) return; // runt — nothing to resolve
        if (block.len > SESSION_FRAME_BUDGET) {
            self.stats.drops += 1;
            return;
        }
        const src_mac: MacAddress = block[6..12].*;
        const dst_mac: MacAddress = block[0..6].*;
        if (!engine_mod.isMulticast(src_mac)) {
            self.engine.learn(src_mac, self.session_port, nowSeconds());
        }
        const action = self.engine.resolve(dst_mac, self.session_port);
        switch (action) {
            .unicast => |port_idx| {
                if (port_idx < self.ports.len) self.writePort(port_idx, block, action);
            },
            .flood => {
                for (self.ports, 0..) |_, i| {
                    self.writePort(@intCast(i), block, action);
                }
            },
            // A destination learned on the session port would echo the
            // block back into the session — engine no-echo.
            .drop => self.engine.noteForwarded(self.session_port, action),
        }
    }

    /// Forward one frame read from LAN port `port_index` (source side).
    ///
    /// Learns the source MAC on the ingress port, resolves the destination,
    /// then: unicast to a LAN port or to the session; flood to the session
    /// AND every other LAN port (broadcast/multicast/unknown-unicast must
    /// reach remote LANs through the tunnel too). Never back to the port
    /// it came from (engine no-echo).
    pub fn dispatchPortFrame(self: *BridgeLoop, port_index: u16, frame: []const u8) void {
        if (frame.len < 14) return;
        if (frame.len > SESSION_FRAME_BUDGET) {
            self.stats.drops += 1;
            return;
        }
        // Ingress rate limit check.
        if (port_index < self.ingress_limiters.len) {
            if (self.ingress_limiters[port_index]) |*limiter| {
                if (!limiter.consume(@intCast(frame.len))) {
                    self.stats.drops += 1;
                    return;
                }
            }
        }
        const src_mac: MacAddress = frame[6..12].*;
        const dst_mac: MacAddress = frame[0..6].*;
        if (!engine_mod.isMulticast(src_mac)) {
            self.engine.learn(src_mac, port_index, nowSeconds());
        }
        const action = self.engine.resolve(dst_mac, port_index);
        switch (action) {
            .unicast => |dest_port| {
                if (dest_port == self.session_port) {
                    self.sendToSession(frame);
                    self.engine.noteForwarded(self.session_port, action);
                } else if (dest_port < self.ports.len) {
                    self.writePort(dest_port, frame, action);
                }
            },
            .flood => {
                // To the session (remote LANs) + every LAN port except src.
                // Record the session delivery too — getStats() sums the
                // session-port counters, so an unrecorded flood would
                // underreport LAN-to-session broadcast deliveries.
                self.sendToSession(frame);
                self.engine.noteForwarded(self.session_port, action);
                for (self.ports, 0..) |_, i| {
                    if (i == port_index) continue;
                    self.writePort(@intCast(i), frame, action);
                }
            },
            .drop => self.engine.noteForwarded(port_index, action),
        }
    }

    /// Age the FDB. The pump calls this from its slow path once per second.
    pub fn age(self: *BridgeLoop, now: u32) usize {
        return self.engine.age(now);
    }

    fn writePort(self: *BridgeLoop, port_index: u16, frame: []const u8, action: ForwardAction) void {
        const p = &self.ports[port_index];
        // Egress rate limit check.
        if (self.egress_limiters[port_index]) |*limiter| {
            if (!limiter.consume(@intCast(frame.len))) {
                self.stats.drops += 1;
                return;
            }
        }
        // FrameTooLarge is already counted by the port layer's own stats,
        // which getStats() sums — no loop-side double count. TxBusy /
        // DeviceClosed: the port layer counted what it can.
        _ = p.write(frame) catch return;
        self.engine.noteForwarded(port_index, action);
    }

    fn sendToSession(self: *BridgeLoop, frame: []const u8) void {
        self.stats.session_tx += 1;
        self.sink.send(self.sink.ctx, frame) catch {
            self.stats.session_tx_errors += 1;
        };
    }
};

/// Seconds since the Unix epoch (injected into the engine clock).
fn nowSeconds() u32 {
    return @intCast(@max(0, std.time.timestamp()));
}

// ============================================================================
// Tests
// ============================================================================

/// In-memory fake port for deterministic dispatch tests.
const FakePort = struct {
    ifname: []const u8,
    out: std.ArrayListUnmanaged(u8),
    stats: port_mod.PortStats = .{},

    fn open(_: *anyopaque) anyerror!void {}
    fn close(_: *anyopaque) void {}
    fn read(_: *anyopaque, _: []u8) anyerror!?usize {
        return null; // tests drive dispatch directly
    }
    fn write(ctx: *anyopaque, data: []const u8) anyerror!usize {
        const self: *FakePort = @ptrCast(@alignCast(ctx));
        if (data.len > SESSION_FRAME_BUDGET) {
            self.stats.drops += 1;
            return error.FrameTooLarge;
        }
        try self.out.appendSlice(std.testing.allocator, data);
        self.stats.tx_pkts += 1;
        self.stats.tx_bytes += data.len;
        return data.len;
    }
    fn getFd(_: *anyopaque) std.posix.fd_t {
        return NetPort.invalid_fd;
    }
    fn getName(ctx: *anyopaque) []const u8 {
        const self: *FakePort = @ptrCast(@alignCast(ctx));
        return self.ifname;
    }
    fn getMac(_: *anyopaque) ?[6]u8 {
        return null;
    }
    fn getMtu(_: *anyopaque) usize {
        return SESSION_FRAME_BUDGET;
    }
    fn getLayer(_: *anyopaque) port_mod.PortLayer {
        return .l2;
    }
    fn setPromiscuous(_: *anyopaque, _: bool) void {}
    fn getStats(ctx: *anyopaque) port_mod.PortStats {
        const self: *FakePort = @ptrCast(@alignCast(ctx));
        return self.stats;
    }
};

fn fakeNetPort(fake: *FakePort) NetPort {
    return .{
        .impl = @ptrCast(fake),
        .vtable = &.{
            .open = &FakePort.open,
            .close = &FakePort.close,
            .read = &FakePort.read,
            .write = &FakePort.write,
            .getFd = &FakePort.getFd,
            .getName = &FakePort.getName,
            .getMac = &FakePort.getMac,
            .getMtu = &FakePort.getMtu,
            .getLayer = &FakePort.getLayer,
            .setPromiscuous = &FakePort.setPromiscuous,
            .getStats = &FakePort.getStats,
        },
    };
}

/// Captures frames sent into the session.
const SessionCapture = struct {
    frames: std.ArrayListUnmanaged([]u8),

    fn send(ctx: *anyopaque, frame: []const u8) anyerror!void {
        const self: *SessionCapture = @ptrCast(@alignCast(ctx));
        const owned = try std.testing.allocator.dupe(u8, frame);
        try self.frames.append(std.testing.allocator, owned);
    }

    fn deinit(self: *SessionCapture) void {
        for (self.frames.items) |f| std.testing.allocator.free(f);
        self.frames.deinit(std.testing.allocator);
    }
};

fn makeMac(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) MacAddress {
    return .{ a, b, c, d, e, f };
}

/// ARP-ethertyped frame built from src/dst MACs (payload zeroed).
fn buildFrame(src: MacAddress, dst: MacAddress) [14 + 42]u8 {
    var f: [14 + 42]u8 = undefined;
    @memcpy(f[0..6], &dst);
    @memcpy(f[6..12], &src);
    f[12] = 0x08;
    f[13] = 0x06;
    @memset(f[14..], 0);
    return f;
}

fn makeHost() struct {
    port0: *FakePort,
    port1: *FakePort,
    capture: *SessionCapture,
    loop: BridgeLoop,
} {
    const port0 = std.testing.allocator.create(FakePort) catch unreachable;
    const port1 = std.testing.allocator.create(FakePort) catch unreachable;
    const capture = std.testing.allocator.create(SessionCapture) catch unreachable;
    port0.* = .{ .ifname = "dummy0", .out = .empty };
    port1.* = .{ .ifname = "dummy1", .out = .empty };
    capture.* = .{ .frames = .empty };
    var ports = [_]NetPort{ fakeNetPort(port0), fakeNetPort(port1) };
    const loop = BridgeLoop.init(
        std.testing.allocator,
        &ports,
        .{ .ctx = capture, .send = &SessionCapture.send },
        4096,
        300,
    ) catch unreachable;
    return .{ .port0 = port0, .port1 = port1, .capture = capture, .loop = loop };
}

test "bridge loop: session block unicasts to a learned LAN port" {
    var h = makeHost();
    defer h.loop.deinit();
    defer h.capture.deinit();
    defer {
        h.port0.out.deinit(std.testing.allocator);
        h.port1.out.deinit(std.testing.allocator);
        std.testing.allocator.destroy(h.port0);
        std.testing.allocator.destroy(h.port1);
        std.testing.allocator.destroy(h.capture);
    }

    const mac_a = makeMac(2, 0, 0, 0, 0, 1);
    const mac_remote = makeMac(2, 0, 0, 0, 0, 9);

    // LAN device A (behind port 0) is learned via an inbound LAN frame.
    // Self-destined dst == src → engine drops it (no-echo) without flooding.
    const f_learn = buildFrame(mac_a, mac_a);
    h.loop.dispatchPortFrame(0, &f_learn);
    try std.testing.expectEqual(@as(usize, 0), h.capture.frames.items.len);

    // Session sends a frame from the remote host to A → unicast to port 0.
    const f_down = buildFrame(mac_remote, mac_a);
    h.loop.dispatchSessionBlock(&f_down);

    try std.testing.expectEqual(@as(usize, 0), h.capture.frames.items.len);
    try std.testing.expectEqualStrings(&f_down, h.port0.out.items);
    try std.testing.expectEqual(@as(usize, 0), h.port1.out.items.len);

    const stats = h.loop.getStats();
    try std.testing.expectEqual(@as(u32, 2), stats.fdb_entries);
    try std.testing.expectEqual(@as(u64, 1), stats.forwarded);
    try std.testing.expectEqual(@as(u64, 1), stats.session_rx);
    try std.testing.expectEqual(@as(u64, 1), stats.lan_tx_pkts);
}

test "bridge loop: LAN unicast to session and LAN broadcast floods" {
    var h = makeHost();
    defer h.loop.deinit();
    defer h.capture.deinit();
    defer {
        h.port0.out.deinit(std.testing.allocator);
        h.port1.out.deinit(std.testing.allocator);
        std.testing.allocator.destroy(h.port0);
        std.testing.allocator.destroy(h.port1);
        std.testing.allocator.destroy(h.capture);
    }

    const mac_a = makeMac(2, 0, 0, 0, 0, 1);
    const mac_b = makeMac(2, 0, 0, 0, 0, 2);
    const mac_remote = makeMac(2, 0, 0, 0, 0, 9);

    // Learn A on port 0, B on port 1, remote on session (via downlink block).
    const f_learn0 = buildFrame(mac_a, mac_a);
    h.loop.dispatchPortFrame(0, &f_learn0);
    const f_learn1 = buildFrame(mac_b, mac_b);
    h.loop.dispatchPortFrame(1, &f_learn1);
    const f_down = buildFrame(mac_remote, mac_a);
    h.loop.dispatchSessionBlock(&f_down);

    // (1) A → remote: unicast to session.
    const f_a2remote = buildFrame(mac_a, mac_remote);
    h.loop.dispatchPortFrame(0, &f_a2remote);
    try std.testing.expectEqual(@as(usize, 1), h.capture.frames.items.len);
    try std.testing.expectEqualStrings(&f_a2remote, h.capture.frames.items[0]);
    // The unicast LAN→session frame must NOT leak to port 1.
    try std.testing.expectEqual(@as(usize, 0), h.port1.out.items.len);

    // (2) A → B: unicast LAN→LAN (B learned on port 1).
    const f_a2b = buildFrame(mac_a, mac_b);
    h.loop.dispatchPortFrame(0, &f_a2b);
    try std.testing.expectEqualStrings(&f_a2b, h.port1.out.items);
    try std.testing.expectEqual(@as(usize, 1), h.capture.frames.items.len);

    // (3) Broadcast from port 0 → session + port 1 (never port 0).
    const f_bcast = buildFrame(mac_a, makeMac(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF));
    h.loop.dispatchPortFrame(0, &f_bcast);
    try std.testing.expectEqual(@as(usize, 2), h.capture.frames.items.len);
    const frame_len = 14 + 42;
    try std.testing.expectEqualStrings(&f_bcast, h.port1.out.items[frame_len..]);

    const stats = h.loop.getStats();
    try std.testing.expectEqual(@as(u64, 2), stats.session_tx);
    try std.testing.expectEqual(@as(u64, 3), stats.forwarded);
    // Port 1 flood delivery (LAN) + session flood delivery — the session
    // port counter is recorded for broadcast floods too.
    try std.testing.expectEqual(@as(u64, 2), stats.flooded);
}

test "bridge loop: no-echo — frame destined back to source port is blocked" {
    var h = makeHost();
    defer h.loop.deinit();
    defer h.capture.deinit();
    defer {
        h.port0.out.deinit(std.testing.allocator);
        h.port1.out.deinit(std.testing.allocator);
        std.testing.allocator.destroy(h.port0);
        std.testing.allocator.destroy(h.port1);
        std.testing.allocator.destroy(h.capture);
    }

    const mac_a = makeMac(2, 0, 0, 0, 0, 1);

    // Learn A on port 0, then a frame FROM A TO A arrives on port 0 — the
    // engine resolves dst on the same port as src → drop (no-echo).
    const f_learn = buildFrame(mac_a, mac_a);
    h.loop.dispatchPortFrame(0, &f_learn);
    const f_echo = buildFrame(mac_a, mac_a);
    h.loop.dispatchPortFrame(0, &f_echo);

    try std.testing.expectEqual(@as(usize, 0), h.capture.frames.items.len);
    try std.testing.expectEqual(@as(usize, 0), h.port0.out.items.len);
    const stats = h.loop.getStats();
    try std.testing.expectEqual(@as(u64, 2), stats.blocked);
}

test "bridge loop: frame budget enforcement + runt dropped" {
    var h = makeHost();
    defer h.loop.deinit();
    defer h.capture.deinit();
    defer {
        h.port0.out.deinit(std.testing.allocator);
        h.port1.out.deinit(std.testing.allocator);
        std.testing.allocator.destroy(h.port0);
        std.testing.allocator.destroy(h.port1);
        std.testing.allocator.destroy(h.capture);
    }

    // Runt frame → ignored.
    h.loop.dispatchPortFrame(0, &[_]u8{0} ** 8);
    // Oversize LAN frame → counted as drop, not forwarded.
    var big = [_]u8{0} ** (SESSION_FRAME_BUDGET + 1);
    @memcpy(big[0..6], &makeMac(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF));
    h.loop.dispatchPortFrame(0, &big);
    try std.testing.expectEqual(@as(usize, 0), h.capture.frames.items.len);

    // Oversize session block → counted as drop and never written to ports.
    h.loop.dispatchSessionBlock(&big);
    try std.testing.expectEqual(@as(usize, 0), h.port0.out.items.len);

    const stats = h.loop.getStats();
    try std.testing.expectEqual(@as(u64, 2), stats.drops);
    try std.testing.expectEqual(@as(u64, 1), stats.session_rx);
    try std.testing.expectEqual(@as(u64, 0), stats.session_tx);
}

test "bridge loop: multicast source never learned" {
    var h = makeHost();
    defer h.loop.deinit();
    defer h.capture.deinit();
    defer {
        h.port0.out.deinit(std.testing.allocator);
        h.port1.out.deinit(std.testing.allocator);
        std.testing.allocator.destroy(h.port0);
        std.testing.allocator.destroy(h.port1);
        std.testing.allocator.destroy(h.capture);
    }

    const mac_mcast = makeMac(0x01, 0x00, 0x5E, 0x00, 0x00, 0x01);
    const mac_a = makeMac(2, 0, 0, 0, 0, 1);

    // Multicast-sourced frame on port 0: floods to session + port 1,
    // and the multicast MAC is NOT learned (no FDB entry).
    const f_mcast = buildFrame(mac_mcast, mac_a);
    h.loop.dispatchPortFrame(0, &f_mcast);

    try std.testing.expectEqual(@as(usize, 1), h.capture.frames.items.len);
    try std.testing.expectEqual(@as(usize, 0), h.port0.out.items.len);
    try std.testing.expectEqual(@as(usize, 56), h.port1.out.items.len);

    const stats = h.loop.getStats();
    try std.testing.expectEqual(@as(u32, 0), stats.fdb_entries);
}

// ---- VLAN tag parsing tests ----

test "parseVlanTag: returns null for untagged frame" {
    const frame = buildFrame(makeMac(1, 0, 0, 0, 0, 1), makeMac(2, 0, 0, 0, 0, 1));
    try std.testing.expectEqual(@as(?VlanTag, null), parseVlanTag(&frame));
}

test "parseVlanTag: parses 802.1Q tag correctly" {
    var frame: [18 + 42]u8 = undefined;
    @memcpy(frame[0..6], &makeMac(2, 0, 0, 0, 0, 1)); // DST
    @memcpy(frame[6..12], &makeMac(1, 0, 0, 0, 0, 1)); // SRC
    // 802.1Q ethertype
    std.mem.writeInt(u16, frame[12..14], VLAN_ETHERTYPE, .big);
    // TCI: PCP=5, DEI=true, VLAN_ID=100
    const tci = buildTci(100, 5, true);
    std.mem.writeInt(u16, frame[14..16], tci, .big);
    // Original ethertype (IPv4)
    std.mem.writeInt(u16, frame[16..18], 0x0800, .big);
    @memset(frame[18..], 0);

    const tag = parseVlanTag(&frame);
    try std.testing.expect(tag != null);
    try std.testing.expectEqual(@as(u16, 100), tag.?.vlan_id);
    try std.testing.expectEqual(@as(u3, 5), tag.?.pcp);
    try std.testing.expectEqual(true, tag.?.dei);
}

test "insertVlanTag: inserts 4-byte tag at offset 12" {
    const src_frame = buildFrame(makeMac(1, 0, 0, 0, 0, 1), makeMac(2, 0, 0, 0, 0, 1));
    var out: [14 + 4 + 42]u8 = undefined;
    const result = try insertVlanTag(&src_frame, 100, 0, false, &out);
    try std.testing.expectEqual(@as(usize, 14 + 4 + 42), result.len);
    // VLAN ethertype at offset 12.
    try std.testing.expectEqual(VLAN_ETHERTYPE, std.mem.readInt(u16, result[12..14], .big));
    // VLAN ID = 100 at offset 14 (lower 12 bits of TCI).
    const tci_val = std.mem.readInt(u16, result[14..16], .big);
    try std.testing.expectEqual(@as(u16, 100), tci_val & 0x0FFF);
    // Original ethertype shifted to offset 16.
    try std.testing.expectEqual(@as(u16, 0x0806), std.mem.readInt(u16, result[16..18], .big));
}

test "stripVlanTag: removes 802.1Q tag" {
    // Build a VLAN-tagged frame.
    var tagged: [18 + 42]u8 = undefined;
    @memcpy(tagged[0..6], &makeMac(2, 0, 0, 0, 0, 1));
    @memcpy(tagged[6..12], &makeMac(1, 0, 0, 0, 0, 1));
    std.mem.writeInt(u16, tagged[12..14], VLAN_ETHERTYPE, .big);
    std.mem.writeInt(u16, tagged[14..16], buildTci(100, 0, false), .big);
    std.mem.writeInt(u16, tagged[16..18], 0x0806, .big); // ARP
    @memset(tagged[18..], 0);

    var out: [14 + 42]u8 = undefined;
    const result = try stripVlanTag(&tagged, &out);
    try std.testing.expectEqual(@as(usize, 14 + 42), result.len);
    // Original ethertype restored at offset 12.
    try std.testing.expectEqual(@as(u16, 0x0806), std.mem.readInt(u16, result[12..14], .big));
}

test "stripVlanTag: passthrough for untagged frame" {
    const src_frame = buildFrame(makeMac(1, 0, 0, 0, 0, 1), makeMac(2, 0, 0, 0, 0, 1));
    var out: [14 + 42]u8 = undefined;
    const result = try stripVlanTag(&src_frame, &out);
    try std.testing.expectEqual(@as(usize, 14 + 42), result.len);
    try std.testing.expectEqualStrings(&src_frame, result);
}

// ---- Rate limiter integration tests ----

test "bridge loop: egress rate limiter drops frames when bucket exhausted" {
    var h = makeHost();
    defer h.loop.deinit();
    defer h.capture.deinit();
    defer {
        h.port0.out.deinit(std.testing.allocator);
        h.port1.out.deinit(std.testing.allocator);
        std.testing.allocator.destroy(h.port0);
        std.testing.allocator.destroy(h.port1);
        std.testing.allocator.destroy(h.capture);
    }

    // Set very low egress rate limit on port 0: 1 byte/sec, 1 byte burst.
    h.loop.setPortRateLimit(0, null, .{ .rate = 1, .capacity = 1 });

    const mac_a = makeMac(2, 0, 0, 0, 0, 1);
    const mac_remote = makeMac(2, 0, 0, 0, 0, 9);

    // Learn A on port 0.
    const f_learn = buildFrame(mac_a, mac_a);
    h.loop.dispatchPortFrame(0, &f_learn);

    // Session sends to A → unicast to port 0. First frame should succeed
    // (burst), second should be rate-limited.
    const f_down = buildFrame(mac_remote, mac_a);
    h.loop.dispatchSessionBlock(&f_down);
    try std.testing.expectEqual(@as(usize, 1), h.port0.out.items.len);

    // Second frame should be dropped.
    h.loop.dispatchSessionBlock(&f_down);
    try std.testing.expectEqual(@as(usize, 1), h.port0.out.items.len);

    const stats = h.loop.getStats();
    try std.testing.expect(stats.drops >= 1);
}