//! SecureNAT orchestrator — wires virtual DHCP + NAT + ARP into a hub.
//!
//! C reference: `SecureNAT.c` `SnNewSecureNAT`, `SnSecureNATThread`.
//!
//! The `SecureNAT` struct owns the three sub-components (VirtualHost, DhcpServer,
//! NatEngine) and runs a background polling thread that:
//!
//!   1. Pops frames from the hub via `SessionPa.outbound`
//!   2. Routes ARP → VirtualHost, DHCP → DhcpServer, IPv4 → NatEngine
//!   3. Puts response frames back into the hub via `Hub.storePacket`
//!   4. Runs periodic maintenance (ARP cache, NAT sweep, DHCP leases)
//!
//! Thread-safety: the polling thread owns the sub-component state. The
//! hub's mutex guards `SessionPa.outbound` and `Hub.storePacket`.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

const hub_mod = @import("hub.zig");
const Hub = hub_mod.Hub;
const SessionPa = hub_mod.SessionPa;
const parseEthernet = hub_mod.parseEthernet;

const virtual_host_mod = @import("virtual_host.zig");
const VirtualHost = virtual_host_mod.VirtualHost;
const VirtualHostConfig = virtual_host_mod.VirtualHostConfig;

const dhcp_server_mod = @import("dhcp_server.zig");
const DhcpServer = dhcp_server_mod.DhcpServer;

const nat_mod = @import("nat.zig");
const NatEngine = nat_mod.NatEngine;

const log = std.log.scoped(.cedar_securenat);

// ============================================================================
// Constants
// ============================================================================

/// Polling interval in milliseconds (C: `VIRTUAL_POLLING_TIME` = 1s).
pub const POLL_INTERVAL_MS: i64 = 1_000;

/// NAT sweep interval in milliseconds (C: `NAT_TABLE_CHECK_INTERVAL` = 1s).
pub const NAT_SWEEP_INTERVAL_MS: i64 = 1_000;

/// Default virtual host IP: 192.168.30.1 (C: `NiSetDefaultVhOption`).
pub const DEFAULT_HOST_IP: u32 = (192 << 24) | (168 << 16) | (30 << 8) | 1;
/// Default subnet mask: 255.255.255.0.
pub const DEFAULT_HOST_MASK: u32 = 0xFFFFFF00;
/// Default DHCP range start: 192.168.30.10.
pub const DEFAULT_DHCP_START: u32 = (192 << 24) | (168 << 16) | (30 << 8) | 10;
/// Default DHCP range end: 192.168.30.200.
pub const DEFAULT_DHCP_END: u32 = (192 << 24) | (168 << 16) | (30 << 8) | 200;
/// Default DNS server: 192.168.30.1 (local gateway).
pub const DEFAULT_DNS1: u32 = DEFAULT_HOST_IP;
/// Default DNS server 2: 8.8.8.8.
pub const DEFAULT_DNS2: u32 = (8 << 24) | (8 << 16) | (8 << 8) | 8;
/// Default DHCP lease time: 7200s (2 hours) (C: `DHCP_DEFAULT_LEASE_TIME`).
pub const DEFAULT_LEASE_SECONDS: u32 = 7200;
/// Default NAT TCP timeout: 1800s (C: `NAT_TCP_TIMEOUT`).
pub const DEFAULT_NAT_TCP_TIMEOUT_S: u32 = 1800;
/// Default NAT UDP timeout: 60s (C: `NAT_UDP_TIMEOUT`).
pub const DEFAULT_NAT_UDP_TIMEOUT_S: u32 = 60;

// ============================================================================
// Ethernet protocol constants (C: TcpIp.h)
// ============================================================================

/// IPv4 ethertype (C: `MAC_PROTO_IPV4`).
const ETH_IPV4: u16 = 0x0800;
/// ARP ethertype (C: `MAC_PROTO_ARPV4`).
const ETH_ARP: u16 = 0x0806;

// ============================================================================
// SecureNAT config (C: VH_OPTION)
// ============================================================================

/// Virtual host / SecureNAT configuration (C: `VH_OPTION`).
///
/// Covers the gateway, DHCP server, and NAT settings. Defaults match
/// `NiSetDefaultVhOption` (Nat.c:1380).
pub const SecureNATConfig = struct {
    /// Enable the SecureNAT feature on this hub.
    enabled: bool = false,

    // -- Virtual host (gateway) --
    /// Gateway IP (C: `VH_OPTION.Ip`).
    host_ip: u32 = DEFAULT_HOST_IP,
    /// Subnet mask (C: `VH_OPTION.Mask`).
    host_mask: u32 = DEFAULT_HOST_MASK,

    // -- NAT --
    /// Enable outbound NAT (C: `VH_OPTION.UseNat`).
    use_nat: bool = true,
    /// NAT TCP timeout in seconds (C: `VH_OPTION.NatTcpTimeout`).
    nat_tcp_timeout_s: u32 = DEFAULT_NAT_TCP_TIMEOUT_S,
    /// NAT UDP timeout in seconds (C: `VH_OPTION.NatUdpTimeout`).
    nat_udp_timeout_s: u32 = DEFAULT_NAT_UDP_TIMEOUT_S,

    // -- DHCP server --
    /// Enable the virtual DHCP server (C: `VH_OPTION.UseDhcp`).
    use_dhcp: bool = true,
    /// DHCP range start (C: `VH_OPTION.DhcpLeaseIPStart`).
    dhcp_range_start: u32 = DEFAULT_DHCP_START,
    /// DHCP range end (C: `VH_OPTION.DhcpLeaseIPEnd`).
    dhcp_range_end: u32 = DEFAULT_DHCP_END,
    /// DHCP lease time in seconds (C: `VH_OPTION.DhcpExpireTimeSpan`).
    dhcp_lease_seconds: u32 = DEFAULT_LEASE_SECONDS,
    /// DNS server 1 handed to DHCP clients (C: `VH_OPTION.DhcpDnsServerAddress`).
    dns1: u32 = DEFAULT_DNS1,
    /// DNS server 2 (C: `VH_OPTION.DhcpDnsServerAddress2`).
    dns2: u32 = DEFAULT_DNS2,
    /// Domain name handed to DHCP clients (C: `VH_OPTION.DhcpDomainName`).
    domain_name: [128:0]u8 = .{0} ** 128,
};

// ============================================================================
// SecureNAT orchestrator
// ============================================================================

/// The SecureNAT instance — owns all sub-components and the hub SessionPa.
///
/// C reference: `SNAT` (SecureNAT.h:108).
pub const SecureNAT = struct {
    allocator: Allocator,
    config: SecureNATConfig,

    // -- Sub-components --
    virtual_host: VirtualHost,
    dhcp_server: DhcpServer,
    nat_engine: NatEngine,

    // -- Hub integration --
    /// The virtual session's packet adapter (attached to the hub).
    session_pa: *SessionPa,
    hub: *Hub,

    // -- Thread --
    thread: ?std.Thread = null,
    halt: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    // -- Timing --
    last_poll_tick: i64 = 0,
    last_nat_sweep_tick: i64 = 0,

    /// Create a new SecureNAT instance and attach it to `h`.
    ///
    /// C reference: `SnNewSecureNAT` (SecureNAT.c:217).
    pub fn init(allocator: Allocator, h: *Hub, config: SecureNATConfig) !*SecureNAT {
        const self = try allocator.create(SecureNAT);
        errdefer allocator.destroy(self);

        // Create the virtual host (ARP responder).
        const vh_config = VirtualHostConfig{
            .enabled = true,
            .host_ip = config.host_ip,
            .host_mask = config.host_mask,
        };
        const vh = VirtualHost.init(allocator, vh_config);

        // Create the DHCP server.
        const dhcp_config = dhcp_server_mod.Config{
            .enabled = config.use_dhcp,
            .host_ip = config.host_ip,
            .ip_start = config.dhcp_range_start,
            .ip_end = config.dhcp_range_end,
            .subnet_mask = config.host_mask,
            .gateway = config.host_ip,
            .dns1 = config.dns1,
            .dns2 = config.dns2,
            .lease_time = config.dhcp_lease_seconds,
            .domain_name = config.domain_name,
        };
        const dhcp = DhcpServer.init(allocator, dhcp_config);

        // Create the NAT engine.
        const nat_eng = NatEngine.init(allocator, config.host_ip, config.host_ip);

        // Create the hub SessionPa (virtual hidden session).
        const pa = try SessionPa.init(h, allocator, SNAT_USER_NAME);

        self.* = .{
            .allocator = allocator,
            .config = config,
            .virtual_host = vh,
            .dhcp_server = dhcp,
            .nat_engine = nat_eng,
            .session_pa = pa,
            .hub = h,
        };

        // Attach to the hub.
        h.attach(pa);

        log.info("SecureNAT created on hub '{s}' (ip={})", .{
            h.name,
            fmtIp(config.host_ip),
        });

        return self;
    }

    /// Tear down SecureNAT: stop the thread, detach from hub, free resources.
    pub fn deinit(self: *SecureNAT) void {
        self.stop();
        self.hub.detach(self.session_pa);
        self.session_pa.deinit();
        self.nat_engine.deinit();
        // DhcpServer and VirtualHost have no heap-allocated state beyond
        // their embedded containers; no explicit deinit needed.
        _ = self.dhcp_server;
        _ = self.virtual_host;
        const allocator = self.allocator;
        allocator.destroy(self);
    }

    /// Start the background polling thread.
    ///
    /// C reference: `SnSecureNATThread` (SecureNAT.c:108) — the thread
    /// creates an in-process session and runs `SessionMain`. We use a
    /// simplified polling loop instead, because the Zig `SessionMain`
    /// requires a `TunnelConnection` (wire I/O) which SecureNAT does not have.
    pub fn start(self: *SecureNAT) !void {
        if (self.thread != null) return; // already running
        self.halt.store(false, .release);
        self.thread = try std.Thread.spawn(.{}, pollingLoop, .{self});
    }

    /// Signal the polling thread to stop and wait for it to finish.
    pub fn stop(self: *SecureNAT) void {
        if (self.thread == null) return;
        self.halt.store(true, .release);
        self.thread.?.join();
        self.thread = null;
    }

    // ========================================================================
    // Polling loop (C: SnSecureNATThread → SessionMain → VirtualPolling)
    // ========================================================================

    /// The background thread that drives all SecureNAT processing.
    fn pollingLoop(self: *SecureNAT) void {
        log.info("SecureNAT polling thread started on hub '{s}'", .{self.hub.name});

        while (!self.halt.load(.acquire)) {
            const now = std.time.milliTimestamp();

            // 1. Drain frames from the hub (hub → virtual host).
            self.drainHubFrames(now);

            // 2. Run periodic maintenance.
            if (now - self.last_poll_tick >= POLL_INTERVAL_MS) {
                self.virtual_host.poll(now);
                self.last_poll_tick = now;
            }

            // 3. NAT sweep.
            if (self.config.use_nat and now - self.last_nat_sweep_tick >= NAT_SWEEP_INTERVAL_MS) {
                _ = self.nat_engine.sweep(now);
                self.last_nat_sweep_tick = now;
            }

            // 4. Sleep to avoid busy-spinning.
            std.Thread.sleep(1_000_000); // 1ms
        }

        log.info("SecureNAT polling thread stopped on hub '{s}'", .{self.hub.name});
    }

    /// Pop all pending frames from the hub and route them to sub-components.
    fn drainHubFrames(self: *SecureNAT, now: i64) void {
        while (true) {
            const frame = self.popHubFrame() orelse break;
            defer self.allocator.free(frame);
            self.routeFrame(frame, now);
        }
    }

    /// Pop one frame from the SessionPa outbound queue.
    fn popHubFrame(self: *SecureNAT) ?[]u8 {
        self.hub.mutex.lock();
        defer self.hub.mutex.unlock();
        if (self.session_pa.outbound.items.len == 0) return null;
        return self.session_pa.outbound.orderedRemove(0);
    }

    /// Route an incoming Ethernet frame to the appropriate sub-component.
    ///
    /// C reference: `VirtualLayer2` (Virtual.c:9818).
    fn routeFrame(self: *SecureNAT, frame: []const u8, now: i64) void {
        const parsed = parseEthernet(frame) orelse return;

        if (parsed.ethertype == ETH_ARP) {
            // ARP → VirtualHost responder.
            if (self.virtual_host.handleFrame(frame, now)) |response| {
                self.injectToHub(response.frame[0..response.len]);
            }
            return;
        }

        if (parsed.ethertype == ETH_IPV4) {
            // IPv4: check if it's a DHCP packet (UDP to/from port 67/68).
            if (isDhcpPacket(frame)) {
                if (self.dhcp_server.handleFrame(frame, now)) |response| {
                    self.injectToHub(response.frame[0..response.len]);
                }
                return;
            }

            // Regular IPv4 → NAT engine.
            if (self.config.use_nat) {
                // TODO: forwardPacket — currently a stub in nat.zig.
                // When implemented, this will:
                //   1. Look up / create a NAT flow entry
                //   2. Rewrite the source address
                //   3. Write to the outbound socket
                _ = self.nat_engine.forwardPacket(frame) catch {};
            }
        }
    }

    /// Inject a response frame into the hub (virtual host → hub).
    ///
    /// C reference: `VirtualGetNextPacket` + `InsertReveicedBlockToQueue`.
    fn injectToHub(self: *SecureNAT, frame: []const u8) void {
        self.hub.storePacket(self.session_pa, frame);
    }
};

// ============================================================================
// Helpers
// ============================================================================

/// Reserved SecureNAT username in the hub session list
/// (C: `SNAT_USER_NAME` = "SECURE_NAT").
const SNAT_USER_NAME = "SECURE_NAT";

/// Check if an IPv4 frame is a DHCP packet (UDP port 67 or 68).
/// Returns true if the frame's L4 is UDP and the destination or source port
/// is 67 (DHCP server) or 68 (DHCP client).
fn isDhcpPacket(frame: []const u8) bool {
    if (frame.len < 14 + 20 + 8) return false; // Eth + IP + UDP minimum
    const ip_hdr = frame[14 .. 14 + 20];
    const protocol = ip_hdr[9];
    if (protocol != 17) return false; // not UDP

    // UDP header starts at IP header + IHL.
    const ihl = (ip_hdr[0] & 0x0F) * 4;
    if (frame.len < 14 + ihl + 4) return false;
    const udp = frame[14 + ihl ..];
    const src_port = mem.readInt(u16, udp[0..2], .big);
    const dst_port = mem.readInt(u16, udp[2..4], .big);
    return (src_port == 67 or src_port == 68 or dst_port == 67 or dst_port == 68);
}

/// Format an IP address for log messages (host byte order → dotted string).
fn fmtIp(ip: u32) IpFmt {
    return .{ .ip = ip };
}

const IpFmt = struct {
    ip: u32,
    pub fn format(self: IpFmt, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        const b = [4]u8{
            @truncate(self.ip >> 24),
            @truncate(self.ip >> 16),
            @truncate(self.ip >> 8),
            @truncate(self.ip >> 0),
        };
        try writer.print("{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] });
    }
};

// ============================================================================
// Tests
// ============================================================================

test "SecureNATConfig defaults match C NiSetDefaultVhOption" {
    const c = SecureNATConfig{};
    try testing.expectEqual(DEFAULT_HOST_IP, c.host_ip);
    try testing.expectEqual(DEFAULT_HOST_MASK, c.host_mask);
    try testing.expect(c.use_nat);
    try testing.expect(c.use_dhcp);
    try testing.expectEqual(DEFAULT_DHCP_START, c.dhcp_range_start);
    try testing.expectEqual(DEFAULT_DHCP_END, c.dhcp_range_end);
    try testing.expectEqual(DEFAULT_LEASE_SECONDS, c.dhcp_lease_seconds);
    try testing.expectEqual(DEFAULT_NAT_TCP_TIMEOUT_S, c.nat_tcp_timeout_s);
    try testing.expectEqual(DEFAULT_NAT_UDP_TIMEOUT_S, c.nat_udp_timeout_s);
    try testing.expectEqual(DEFAULT_DNS1, c.dns1);
    try testing.expectEqual(DEFAULT_DNS2, c.dns2);
}

test "SecureNAT.isDhcpPacket detects DHCP traffic" {
    // Build a minimal Ethernet + IP + UDP frame with DHCP ports.
    var frame: [60]u8 = [_]u8{0} ** 60;

    // Ethernet: ethertype = 0x0800 (IPv4) at offset 12-13.
    frame[12] = 0x08;
    frame[13] = 0x00;

    // IP header: version=4, IHL=5 (20 bytes), protocol=17 (UDP).
    frame[14] = 0x45; // version=4, ihl=5
    frame[23] = 17; // protocol = UDP

    // UDP: src_port=68 (DHCP client), dst_port=67 (DHCP server).
    frame[14 + 20] = 0x00;
    frame[14 + 20 + 1] = 68; // src port = 68
    frame[14 + 20 + 2] = 0x00;
    frame[14 + 20 + 3] = 67; // dst port = 67

    try testing.expect(isDhcpPacket(&frame));

    // Non-DHCP: UDP port 80.
    frame[14 + 20 + 1] = 80;
    frame[14 + 20 + 3] = 80;
    try testing.expect(!isDhcpPacket(&frame));
}

test "SecureNAT.isDhcpPacket rejects short frames" {
    const frame = [_]u8{0} ** 10; // too short
    try testing.expect(!isDhcpPacket(&frame));
}

test "SecureNAT.isDhcpPacket rejects non-UDP" {
    var frame: [60]u8 = [_]u8{0} ** 60;
    frame[14] = 0x45; // IPv4
    frame[23] = 6; // TCP (not UDP)
    try testing.expect(!isDhcpPacket(&frame));
}

test "SecureNAT.init creates all components" {
    const allocator = testing.allocator;
    const h = try Hub.init(allocator, "TEST");
    defer h.deinit();

    const s = try SecureNAT.init(allocator, h, .{});
    defer s.deinit();

    try testing.expectEqual(@as(usize, 1), h.sessionCount()); // virtual session
    try testing.expectEqual(DEFAULT_HOST_IP, s.config.host_ip);
    try testing.expect(s.config.use_nat);
    try testing.expect(s.config.use_dhcp);
}

test "SecureNAT.init with custom config" {
    const allocator = testing.allocator;
    const h = try Hub.init(allocator, "TEST");
    defer h.deinit();

    const cfg = SecureNATConfig{
        .host_ip = 0x0A000001,
        .host_mask = 0xFF000000,
        .use_nat = false,
        .use_dhcp = false,
    };
    const s = try SecureNAT.init(allocator, h, cfg);
    defer s.deinit();

    try testing.expectEqual(@as(u32, 0x0A000001), s.config.host_ip);
    try testing.expect(!s.config.use_nat);
    try testing.expect(!s.config.use_dhcp);
}

test "SecureNAT.deinit detaches from hub" {
    const allocator = testing.allocator;
    const h = try Hub.init(allocator, "TEST");
    defer h.deinit();

    const s = try SecureNAT.init(allocator, h, .{});
    try testing.expectEqual(@as(usize, 1), h.sessionCount());
    s.deinit();

    try testing.expectEqual(@as(usize, 0), h.sessionCount());
}
