//! Hub Access List engine — packet filtering on ingress/egress.
//!
//! C reference: `ACCESS` struct (Network.h:1022), `IsPacketMaskedByAccessList`
//! (Hub.c:2150), `ApplyAccessListToStoredPacket` (Hub.c:2872).
//!
//! Each hub maintains a sorted list of `AccessRule` entries. On every packet
//! the engine evaluates conditions (AND logic) and the first matching rule
//! determines pass/discard. Rules are sorted by priority (lower = evaluated
//! first); within the same priority, discard rules sort before pass rules.
//!
//! Scope (M4):
//!   - MAC, IPv4, protocol, port conditions.
//!   - Hub-level protocol filters (PPPoE, OSPF, BPDU, IPv4/IPv6/NonIP).
//!   - Pass/discard action.
//!   - Delay/jitter/loss actions are stubbed (TODO M5).
//!   - URL redirect is stubbed (TODO M5).
//!   - User-file matching (include:/exclude:) is deferred.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const hub_mod = @import("hub.zig");
const ParsedFrame = hub_mod.ParsedFrame;

const log = std.log.scoped(.cedar_acl);

// ============================================================================
// Constants
// ============================================================================

/// Maximum access-list rules per hub (C: `MAX_ACCESSLISTS` = 32768).
pub const MAX_ACCESS_LISTS: usize = 32768;

// ============================================================================
// Access rule (C: ACCESS — Network.h:1022)
// ============================================================================

/// A single access-list rule. All enabled conditions must match (AND logic)
/// for the rule to fire. The first matching rule wins.
pub const AccessRule = struct {
    /// Rule ID (assigned by the hub, monotonically increasing).
    id: u32 = 0,
    /// Human-readable note.
    note: [64:0]u8 = .{0} ** 64,
    /// Enable/disable flag (C: `ACCESS.Active`).
    active: bool = true,
    /// Sort priority (lower = higher priority). C: `ACCESS.Priority`.
    priority: u32 = 0,
    /// true = DISCARD on match; false = PASS on match. C: `ACCESS.Discard`.
    discard: bool = false,

    // -- L2 MAC conditions --

    /// Match on source MAC?
    check_src_mac: bool = false,
    src_mac: [6]u8 = .{0} ** 6,
    src_mac_mask: [6]u8 = .{0} ** 6,

    /// Match on destination MAC?
    check_dst_mac: bool = false,
    dst_mac: [6]u8 = .{0} ** 6,
    dst_mac_mask: [6]u8 = .{0} ** 6,

    // -- L3 IPv4 conditions --

    /// Source IPv4 address (host byte order).
    src_ip: u32 = 0,
    /// Source subnet mask (host byte order).
    src_mask: u32 = 0,
    /// Destination IPv4 address (host byte order).
    dst_ip: u32 = 0,
    /// Destination subnet mask (host byte order).
    dst_mask: u32 = 0,

    // -- L4 protocol/port conditions --

    /// IP protocol number (0 = any). C: `ACCESS.Protocol`.
    protocol: u8 = 0,
    /// Source port range start (0 = any).
    src_port_start: u16 = 0,
    /// Source port range end (0 = any).
    src_port_end: u16 = 0,
    /// Destination port range start (0 = any).
    dst_port_start: u16 = 0,
    /// Destination port range end (0 = any).
    dst_port_end: u16 = 0,

    // -- TCP state condition --

    /// Match only established TCP (non-SYN)?
    check_tcp_state: bool = false,
    established: bool = false,

    // -- Actions (stubbed for M4) --

    /// Artificial delay in ms (0 = none). TODO M5.
    delay_ms: u32 = 0,
    /// Jitter in ms (0 = none). TODO M5.
    jitter_ms: u32 = 0,
    /// Packet loss probability 0-100 (0 = none). TODO M5.
    loss_percent: u32 = 0,
    /// HTTP redirect URL (empty = none). TODO M5.
    redirect_url: [256:0]u8 = .{0} ** 256,
};

// ============================================================================
// Hub protocol filter options (C: HUB_OPTION — Hub.h:213)
// ============================================================================

/// Hub-level protocol filter flags. These are applied before the per-rule
/// access list evaluation (C: `ApplyAccessListToStoredPacket` Phase A).
pub const HubFilters = struct {
    /// Drop PPPoE frames (EtherType 0x8863, 0x8864). C: `FilterPPPoE`.
    filter_pppoe: bool = false,
    /// Drop OSPF packets (IP protocol 89). C: `FilterOSPF`.
    filter_ospf: bool = false,
    /// Drop all IPv4 + ARP packets. C: `FilterIPv4`.
    filter_ipv4: bool = false,
    /// Drop all IPv6 packets. C: `FilterIPv6`.
    filter_ipv6: bool = false,
    /// Drop all non-IP, non-IPv6, non-ARP packets. C: `FilterNonIP`.
    filter_non_ip: bool = false,
    /// Drop BPDU (spanning tree) packets (EtherType 0x8942). C: `FilterBPDU`.
    filter_bpdu: bool = false,
};

// ============================================================================
// Access list (sorted container)
// ============================================================================

/// The hub's access list — a sorted array of rules.
pub const AccessList = struct {
    rules: std.ArrayListUnmanaged(AccessRule) = .{},
    allocator: Allocator,

    pub fn init(allocator: Allocator) AccessList {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *AccessList) void {
        self.rules.deinit(self.allocator);
    }

    /// Add a rule, maintaining sort order (by priority, then discard-first).
    /// Returns the assigned rule ID.
    pub fn add(self: *AccessList, rule: AccessRule) !u32 {
        if (self.rules.items.len >= MAX_ACCESS_LISTS) return error.TooManyRules;

        var r = rule;
        // Assign a unique ID if not already set.
        if (r.id == 0) {
            var max_id: u32 = 0;
            for (self.rules.items) |existing| {
                if (existing.id > max_id) max_id = existing.id;
            }
            r.id = max_id + 1;
        }

        // Find insertion point (sorted by priority ascending, discard-first).
        var insert_idx = self.rules.items.len;
        for (self.rules.items, 0..) |existing, i| {
            if (r.priority < existing.priority or
                (r.priority == existing.priority and r.discard and !existing.discard))
            {
                insert_idx = i;
                break;
            }
        }

        try self.rules.insert(self.allocator, insert_idx, r);
        return r.id;
    }

    /// Remove a rule by ID. Returns true if found and removed.
    pub fn remove(self: *AccessList, id: u32) bool {
        for (self.rules.items, 0..) |rule, i| {
            if (rule.id == id) {
                _ = self.rules.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Find a rule by ID.
    pub fn findById(self: *const AccessList, id: u32) ?*const AccessRule {
        for (self.rules.items) |*rule| {
            if (rule.id == id) return rule;
        }
        return null;
    }

    /// Find a mutable rule by ID.
    pub fn findByIdMut(self: *AccessList, id: u32) ?*AccessRule {
        for (self.rules.items) |*rule| {
            if (rule.id == id) return rule;
        }
        return null;
    }
};

// ============================================================================
// Packet context for ACL matching
// ============================================================================

/// Parsed packet fields for ACL evaluation. Extracted from the raw frame
/// once and reused across all rule evaluations.
pub const PacketContext = struct {
    /// Parsed Ethernet header.
    frame: ParsedFrame,
    /// IPv4 source address (host byte order). 0 = not IPv4.
    src_ip: u32 = 0,
    /// IPv4 destination address (host byte order). 0 = not IPv4.
    dst_ip: u32 = 0,
    /// IP protocol number. 0 = not IP.
    protocol: u8 = 0,
    /// L4 source port (TCP/UDP). 0 = not applicable.
    src_port: u16 = 0,
    /// L4 destination port (TCP/UDP). 0 = not applicable.
    dst_port: u16 = 0,
    /// TCP SYN flag (for established detection).
    tcp_syn: bool = false,
    /// TCP ACK flag.
    tcp_ack: bool = false,
    /// True if this is an ARP frame.
    is_arp: bool = false,
    /// True if this is an IPv6 frame.
    is_ipv6: bool = false,
};

/// Parse an Ethernet frame into a PacketContext for ACL evaluation.
pub fn parsePacketContext(frame: []const u8) ?PacketContext {
    const parsed = hub_mod.parseEthernet(frame) orelse return null;

    var ctx = PacketContext{
        .frame = parsed,
    };

    if (parsed.ethertype == 0x0806) {
        ctx.is_arp = true;
        return ctx;
    }

    if (parsed.ethertype == 0x0800) {
        // IPv4
        if (frame.len < 14 + 20) return ctx;
        const ip = frame[14..];
        const version_ihl = ip[0];
        const version = (version_ihl >> 4) & 0x0F;
        if (version != 4) return ctx;
        const ihl = (version_ihl & 0x0F) * 4;
        if (ip.len < ihl) return ctx;

        ctx.protocol = ip[9];
        ctx.src_ip = mem.readInt(u32, ip[12..16], .big);
        ctx.dst_ip = mem.readInt(u32, ip[16..20], .big);

        // Parse L4 ports for TCP/UDP.
        if (ctx.protocol == 6 or ctx.protocol == 17) { // TCP or UDP
            if (ip.len >= ihl + 4) {
                const l4 = ip[ihl..];
                ctx.src_port = mem.readInt(u16, l4[0..2], .big);
                ctx.dst_port = mem.readInt(u16, l4[2..4], .big);
            }
        }

        // TCP flags for established detection.
        if (ctx.protocol == 6 and ip.len >= ihl + 14) {
            const tcp = ip[ihl..];
            const flags = tcp[13];
            ctx.tcp_syn = (flags & 0x02) != 0;
            ctx.tcp_ack = (flags & 0x10) != 0;
        }
    } else if (parsed.ethertype == 0x86DD) {
        ctx.is_ipv6 = true;
    }

    return ctx;
}

// ============================================================================
// ACL matching engine (C: IsPacketMaskedByAccessList — Hub.c:2150)
// ============================================================================

/// Evaluate a single access rule against a packet context.
/// Returns true if the rule matches (all enabled conditions pass).
pub fn matchRule(rule: *const AccessRule, ctx: *const PacketContext) bool {
    if (!rule.active) return false;

    // Source MAC check.
    if (rule.check_src_mac) {
        for (0..6) |i| {
            if ((ctx.frame.src[i] & rule.src_mac_mask[i]) != (rule.src_mac[i] & rule.src_mac_mask[i])) {
                return false;
            }
        }
    }

    // Destination MAC check.
    if (rule.check_dst_mac) {
        for (0..6) |i| {
            if ((ctx.frame.dst[i] & rule.dst_mac_mask[i]) != (rule.dst_mac[i] & rule.dst_mac_mask[i])) {
                return false;
            }
        }
    }

    // Source IP subnet check.
    if (rule.src_mask != 0) {
        if ((ctx.src_ip & rule.src_mask) != (rule.src_ip & rule.src_mask)) {
            return false;
        }
    }

    // Destination IP subnet check.
    if (rule.dst_mask != 0) {
        if ((ctx.dst_ip & rule.dst_mask) != (rule.dst_ip & rule.dst_mask)) {
            return false;
        }
    }

    // Protocol check (0 = any).
    if (rule.protocol != 0 and ctx.protocol != rule.protocol) {
        return false;
    }

    // Source port range check (only for TCP/UDP).
    if (rule.src_port_start != 0 or rule.src_port_end != 0) {
        if (ctx.protocol != 6 and ctx.protocol != 17) return false;
        if (ctx.src_port < rule.src_port_start or ctx.src_port > rule.src_port_end) {
            return false;
        }
    }

    // Destination port range check (only for TCP/UDP).
    if (rule.dst_port_start != 0 or rule.dst_port_end != 0) {
        if (ctx.protocol != 6 and ctx.protocol != 17) return false;
        if (ctx.dst_port < rule.dst_port_start or ctx.dst_port > rule.dst_port_end) {
            return false;
        }
    }

    // TCP state check.
    if (rule.check_tcp_state) {
        if (ctx.protocol != 6) return false;
        if (rule.established) {
            // Established = ACK set (any packet with ACK is not a SYN).
            if (!ctx.tcp_ack) return false;
        } else {
            // SYN-only = SYN set and ACK not set.
            if (!ctx.tcp_syn or ctx.tcp_ack) return false;
        }
    }

    return true;
}

/// Evaluate the hub-level protocol filters (C: Phase A of
/// `ApplyAccessListToStoredPacket`). Returns true if the packet should be
/// dropped.
pub fn matchesHubFilters(ctx: *const PacketContext, filters: *const HubFilters) bool {
    // PPPoE: EtherType 0x8863 or 0x8864.
    if (filters.filter_pppoe) {
        if (ctx.frame.ethertype == 0x8863 or ctx.frame.ethertype == 0x8864) {
            return true;
        }
    }

    // BPDU: EtherType 0x8942.
    if (filters.filter_bpdu) {
        if (ctx.frame.ethertype == 0x8942) {
            return true;
        }
    }

    // OSPF: IPv4 protocol 89.
    if (filters.filter_ospf) {
        if (ctx.protocol == 89) {
            return true;
        }
    }

    // Filter all IPv4 + ARP.
    if (filters.filter_ipv4) {
        if (ctx.frame.ethertype == 0x0800 or ctx.is_arp) {
            return true;
        }
    }

    // Filter all IPv6.
    if (filters.filter_ipv6) {
        if (ctx.is_ipv6) {
            return true;
        }
    }

    // Filter non-IP (not IPv4, not IPv6, not ARP).
    if (filters.filter_non_ip) {
        if (ctx.frame.ethertype != 0x0800 and !ctx.is_ipv6 and !ctx.is_arp) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// ACL evaluation result
// ============================================================================

/// Result of evaluating the access list against a packet.
pub const AclResult = struct {
    /// true = packet should be passed; false = discard.
    pass: bool = true,
    /// The rule ID that matched, or 0 if no rule matched (default pass).
    matched_rule_id: u32 = 0,
    /// Delay in ms from the matched rule (0 = none).
    delay_ms: u32 = 0,
    /// Jitter in ms from the matched rule (0 = none).
    jitter_ms: u32 = 0,
    /// Packet loss % from the matched rule (0 = none).
    loss_percent: u32 = 0,
};

/// Evaluate the full access list against a packet context.
/// Returns the first matching rule's action. If no rule matches, the default
/// is PASS (C: packets without an ACL match are allowed through).
pub fn evaluateAccessList(rules: []const AccessRule, ctx: *const PacketContext) AclResult {
    for (rules) |*rule| {
        if (matchRule(rule, ctx)) {
            return .{
                .pass = !rule.discard,
                .matched_rule_id = rule.id,
                .delay_ms = rule.delay_ms,
                .jitter_ms = rule.jitter_ms,
                .loss_percent = rule.loss_percent,
            };
        }
    }
    // No rule matched → default pass.
    return .{ .pass = true };
}

// ============================================================================
// Traffic accounting (C: TRAFFIC / TRAFFIC_ENTRY — Cedar.h:958)
// ============================================================================

/// Per-direction traffic counters (C: `TRAFFIC_ENTRY`).
pub const TrafficEntry = struct {
    broadcast_count: u64 = 0,
    broadcast_bytes: u64 = 0,
    unicast_count: u64 = 0,
    unicast_bytes: u64 = 0,
};

/// Bidirectional traffic counters — send + receive (C: `TRAFFIC`).
pub const Traffic = struct {
    send: TrafficEntry = .{},
    recv: TrafficEntry = .{},

    /// Add another Traffic's counters into this one.
    pub fn add(self: *Traffic, other: *const Traffic) void {
        self.send.broadcast_count += other.send.broadcast_count;
        self.send.broadcast_bytes += other.send.broadcast_bytes;
        self.send.unicast_count += other.send.unicast_count;
        self.send.unicast_bytes += other.send.unicast_bytes;
        self.recv.broadcast_count += other.recv.broadcast_count;
        self.recv.broadcast_bytes += other.recv.broadcast_bytes;
        self.recv.unicast_count += other.recv.unicast_count;
        self.recv.unicast_bytes += other.recv.unicast_bytes;
    }

    /// Compute the delta (self minus old) and accumulate into self,
    /// resetting old to the current values. Used for periodic per-user/per-hub
    /// traffic accounting (C: `IncrementUserTraffic`, Session.c:614).
    pub fn delta(self: *Traffic, old: *Traffic) Traffic {
        var result = Traffic{};
        result.send.broadcast_count = self.send.broadcast_count - old.send.broadcast_count;
        result.send.broadcast_bytes = self.send.broadcast_bytes - old.send.broadcast_bytes;
        result.send.unicast_count = self.send.unicast_count - old.send.unicast_count;
        result.send.unicast_bytes = self.send.unicast_bytes - old.send.unicast_bytes;
        result.recv.broadcast_count = self.recv.broadcast_count - old.recv.broadcast_count;
        result.recv.broadcast_bytes = self.recv.broadcast_bytes - old.recv.broadcast_bytes;
        result.recv.unicast_count = self.recv.unicast_count - old.recv.unicast_count;
        result.recv.unicast_bytes = self.recv.unicast_bytes - old.recv.unicast_bytes;
        old.* = self.*;
        return result;
    }

    /// Total bytes (send + recv, unicast + broadcast).
    pub fn totalBytes(self: *const Traffic) u64 {
        return self.send.broadcast_bytes + self.send.unicast_bytes +
            self.recv.broadcast_bytes + self.recv.unicast_bytes;
    }
};

// ============================================================================
// Traffic accounting helpers (C: Session.c:914, Hub.c:6816)
// ============================================================================

/// Accumulate traffic counters into a destination Traffic struct.
/// Simple field-by-field addition (C: `AddTraffic`, Cedar.c:1847).
pub fn addTraffic(dst: *Traffic, diff: *const Traffic) void {
    dst.send.broadcast_count += diff.send.broadcast_count;
    dst.send.broadcast_bytes += diff.send.broadcast_bytes;
    dst.send.unicast_count += diff.send.unicast_count;
    dst.send.unicast_bytes += diff.send.unicast_bytes;
    dst.recv.broadcast_count += diff.recv.broadcast_count;
    dst.recv.broadcast_bytes += diff.recv.broadcast_bytes;
    dst.recv.unicast_count += diff.recv.unicast_count;
    dst.recv.unicast_bytes += diff.recv.unicast_bytes;
}

/// Accumulate per-session traffic into the hub-level and cedar-level totals.
/// Called once per main-loop iteration. Send/Recv are swapped from the
/// server's perspective (C: `AddTrafficForSession`, Session.c:914).
///
/// `session_traffic` is the per-session delta for this iteration.
/// `hub_traffic` is the hub's running total (accumulated into).
/// `cedar_traffic` is the cedar's running total (accumulated into, may be null).
pub fn addTrafficForSession(
    session_traffic: *const Traffic,
    hub_traffic: *Traffic,
    cedar_traffic: ?*Traffic,
) void {
    // Server's perspective: send ↔ recv are swapped.
    var swapped = Traffic{
        .send = session_traffic.recv,
        .recv = session_traffic.send,
    };
    addTraffic(hub_traffic, &swapped);
    if (cedar_traffic) |cedar| addTraffic(cedar, &swapped);
}

/// Compute the traffic delta for a session (current - old), apply it to a
/// user's traffic counters, and snapshot old = current.
/// Called every `INCREMENT_TRAFFIC_INTERVAL` (10 seconds).
/// (C: `IncrementUserTraffic`, Session.c:848).
pub fn incrementUserTraffic(
    session_traffic: *Traffic,
    old_traffic: *Traffic,
    user_traffic: ?*Traffic,
    group_traffic: ?*Traffic,
) Traffic {
    const delta = session_traffic.delta(old_traffic);
    if (user_traffic) |u| addTraffic(u, &delta);
    if (group_traffic) |g| addTraffic(g, &delta);
    return delta;
}

/// Compute the traffic delta for a hub (current - old), apply it to the
/// hub's total counters, and snapshot old = current.
/// Called every `INCREMENT_TRAFFIC_INTERVAL` (10 seconds).
/// (C: `IncrementHubTraffic`, Hub.c:6816).
pub fn incrementHubTraffic(
    hub_traffic: *Traffic,
    old_traffic: *Traffic,
) Traffic {
    return hub_traffic.delta(old_traffic);
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "AccessList.add sorts by priority" {
    const allocator = testing.allocator;
    var al = AccessList.init(allocator);
    defer al.deinit();

    _ = try al.add(.{ .id = 10, .priority = 100, .discard = false });
    _ = try al.add(.{ .id = 20, .priority = 10, .discard = false });
    _ = try al.add(.{ .id = 30, .priority = 50, .discard = true });

    // Should be sorted: 20 (prio 10), 30 (prio 50, discard), 10 (prio 100).
    try testing.expectEqual(@as(usize, 3), al.rules.items.len);
    try testing.expectEqual(@as(u32, 20), al.rules.items[0].id);
    try testing.expectEqual(@as(u32, 30), al.rules.items[1].id);
    try testing.expectEqual(@as(u32, 10), al.rules.items[2].id);
}

test "AccessList.add assigns IDs" {
    const allocator = testing.allocator;
    var al = AccessList.init(allocator);
    defer al.deinit();

    const id1 = try al.add(.{ .priority = 10 });
    const id2 = try al.add(.{ .priority = 20 });
    try testing.expect(id2 > id1);
}

test "AccessList.remove by ID" {
    const allocator = testing.allocator;
    var al = AccessList.init(allocator);
    defer al.deinit();

    _ = try al.add(.{ .id = 42, .priority = 10 });
    try testing.expect(al.remove(42));
    try testing.expect(!al.remove(42));
    try testing.expectEqual(@as(usize, 0), al.rules.items.len);
}

test "matchRule source MAC" {
    const rule = AccessRule{
        .check_src_mac = true,
        .src_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .src_mac_mask = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    };

    var ctx = PacketContext{
        .frame = .{
            .dst = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
            .src = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
            .ethertype = 0x0800,
            .broadcast = false,
        },
    };

    try testing.expect(matchRule(&rule, &ctx));

    ctx.frame.src = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x66 };
    try testing.expect(!matchRule(&rule, &ctx));
}

test "matchRule source MAC with mask" {
    const rule = AccessRule{
        .check_src_mac = true,
        .src_mac = .{ 0x00, 0x11, 0x00, 0x00, 0x00, 0x00 },
        .src_mac_mask = .{ 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 }, // Only match first 2 bytes
    };

    const ctx = PacketContext{
        .frame = .{
            .dst = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
            .src = .{ 0x00, 0x11, 0xAA, 0xBB, 0xCC, 0xDD },
            .ethertype = 0x0800,
            .broadcast = false,
        },
    };

    try testing.expect(matchRule(&rule, &ctx));
}

test "matchRule source IP subnet" {
    const rule = AccessRule{
        .src_ip = (192 << 24) | (168 << 16) | (1 << 8) | 0,
        .src_mask = 0xFFFFFF00, // /24
    };

    var ctx = PacketContext{
        .frame = .{
            .dst = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
            .src = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
            .ethertype = 0x0800,
            .broadcast = false,
        },
        .src_ip = (192 << 24) | (168 << 16) | (1 << 8) | 42,
    };

    try testing.expect(matchRule(&rule, &ctx));

    ctx.src_ip = (10 << 24) | (0 << 16) | (0 << 8) | 1;
    try testing.expect(!matchRule(&rule, &ctx));
}

test "matchRule protocol" {
    const rule = AccessRule{
        .protocol = 6, // TCP
    };

    var ctx = PacketContext{
        .frame = .{
            .dst = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
            .src = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
            .ethertype = 0x0800,
            .broadcast = false,
        },
        .protocol = 6,
    };

    try testing.expect(matchRule(&rule, &ctx));

    ctx.protocol = 17; // UDP
    try testing.expect(!matchRule(&rule, &ctx));
}

test "matchRule destination port range" {
    const rule = AccessRule{
        .protocol = 6,
        .dst_port_start = 80,
        .dst_port_end = 443,
    };

    var ctx = PacketContext{
        .frame = .{
            .dst = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
            .src = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
            .ethertype = 0x0800,
            .broadcast = false,
        },
        .protocol = 6,
        .dst_port = 443,
    };

    try testing.expect(matchRule(&rule, &ctx));

    ctx.dst_port = 8080;
    try testing.expect(!matchRule(&rule, &ctx));

    ctx.dst_port = 22;
    try testing.expect(!matchRule(&rule, &ctx));
}

test "matchRule TCP established" {
    const rule = AccessRule{
        .protocol = 6,
        .check_tcp_state = true,
        .established = true,
    };

    var ctx = PacketContext{
        .frame = .{
            .dst = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
            .src = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
            .ethertype = 0x0800,
            .broadcast = false,
        },
        .protocol = 6,
        .tcp_syn = false,
        .tcp_ack = true,
    };

    // ACK only = established
    try testing.expect(matchRule(&rule, &ctx));

    // SYN + ACK = also established
    ctx.tcp_syn = true;
    ctx.tcp_ack = true;
    try testing.expect(matchRule(&rule, &ctx));

    // SYN only = not established
    ctx.tcp_syn = true;
    ctx.tcp_ack = false;
    try testing.expect(!matchRule(&rule, &ctx));
}

test "evaluateAccessList first match wins" {
    const rules = [_]AccessRule{
        .{ .id = 1, .priority = 10, .discard = true, .protocol = 6 }, // TCP discard
        .{ .id = 2, .priority = 10, .discard = false, .protocol = 17 }, // UDP pass
        .{ .id = 3, .priority = 20, .discard = false }, // catch-all pass
    };

    const ctx = PacketContext{
        .frame = .{
            .dst = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
            .src = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
            .ethertype = 0x0800,
            .broadcast = false,
        },
        .protocol = 6,
    };

    const result = evaluateAccessList(&rules, &ctx);
    try testing.expect(!result.pass);
    try testing.expectEqual(@as(u32, 1), result.matched_rule_id);
}

test "evaluateAccessList default pass when no match" {
    const rules = [_]AccessRule{
        .{ .id = 1, .priority = 10, .discard = true, .src_ip = 0x0A000000, .src_mask = 0xFF000000 },
    };

    const ctx = PacketContext{
        .frame = .{
            .dst = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
            .src = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
            .ethertype = 0x0800,
            .broadcast = false,
        },
        .src_ip = 0xC0A80101, // 192.168.1.1 — doesn't match 10.x
    };

    const result = evaluateAccessList(&rules, &ctx);
    try testing.expect(result.pass);
    try testing.expectEqual(@as(u32, 0), result.matched_rule_id);
}

test "HubFilters matches PPPoE" {
    const filters = HubFilters{ .filter_pppoe = true };
    var ctx = PacketContext{
        .frame = .{
            .dst = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
            .src = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
            .ethertype = 0x8863,
            .broadcast = true,
        },
    };
    try testing.expect(matchesHubFilters(&ctx, &filters));

    ctx.frame.ethertype = 0x0800;
    try testing.expect(!matchesHubFilters(&ctx, &filters));
}

test "HubFilters matches OSPF" {
    const filters = HubFilters{ .filter_ospf = true };
    const ctx = PacketContext{
        .frame = .{
            .dst = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
            .src = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
            .ethertype = 0x0800,
            .broadcast = false,
        },
        .protocol = 89,
    };
    try testing.expect(matchesHubFilters(&ctx, &filters));
}

test "parsePacketContext IPv4" {
    // Build a minimal Ethernet + IP + TCP frame.
    var frame: [54]u8 = [_]u8{0} ** 54;

    // Ethernet: ethertype = 0x0800 at offset 12-13.
    frame[12] = 0x08;
    frame[13] = 0x00;

    // IP header: version=4, IHL=5 (20 bytes).
    frame[14] = 0x45;
    frame[23] = 6; // protocol = TCP

    // Src IP: 10.0.0.1
    frame[15] = 10;
    frame[16] = 0;
    frame[17] = 0;
    frame[18] = 1;

    // Dst IP: 192.168.1.1
    frame[19] = 192;
    frame[20] = 168;
    frame[21] = 1;
    frame[22] = 1;

    // TCP src port = 12345 (0x3039)
    frame[34] = 0x30;
    frame[35] = 0x39;

    // TCP dst port = 80 (0x0050)
    frame[36] = 0x00;
    frame[37] = 0x50;

    // TCP flags: SYN (0x02)
    frame[47] = 0x02;

    const ctx = parsePacketContext(&frame) orelse return error.TestFailed;
    try testing.expectEqual(@as(u32, (10 << 24) | 1), ctx.src_ip);
    try testing.expectEqual(@as(u32, (192 << 24) | (168 << 16) | (1 << 8) | 1), ctx.dst_ip);
    try testing.expectEqual(@as(u8, 6), ctx.protocol);
    try testing.expectEqual(@as(u16, 12345), ctx.src_port);
    try testing.expectEqual(@as(u16, 80), ctx.dst_port);
    try testing.expect(ctx.tcp_syn);
    try testing.expect(!ctx.tcp_ack);
}

test "AccessList.remove nonexistent returns false" {
    const allocator = testing.allocator;
    var al = AccessList.init(allocator);
    defer al.deinit();
    try testing.expect(!al.remove(999));
}

test "matchRule inactive rule never matches" {
    const rule = AccessRule{
        .active = false,
        .protocol = 6,
    };
    const ctx = PacketContext{
        .frame = .{
            .dst = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
            .src = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
            .ethertype = 0x0800,
            .broadcast = false,
        },
        .protocol = 6,
    };
    try testing.expect(!matchRule(&rule, &ctx));
}

test "matchRule destination MAC" {
    const rule = AccessRule{
        .check_dst_mac = true,
        .dst_mac = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
        .dst_mac_mask = .{ 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00 }, // First 3 bytes
    };

    const ctx = PacketContext{
        .frame = .{
            .dst = .{ 0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33 },
            .src = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
            .ethertype = 0x0800,
            .broadcast = false,
        },
    };

    try testing.expect(matchRule(&rule, &ctx));
}

test "AccessList.findById" {
    const allocator = testing.allocator;
    var al = AccessList.init(allocator);
    defer al.deinit();

    _ = try al.add(.{ .id = 42, .priority = 10 });
    try testing.expect(al.findById(42) != null);
    try testing.expect(al.findById(99) == null);
}

test "Traffic.add accumulates counters" {
    var a = Traffic{};
    a.send.unicast_count = 10;
    a.send.unicast_bytes = 1000;
    a.recv.broadcast_count = 5;

    const b = Traffic{
        .send = .{ .unicast_count = 3, .unicast_bytes = 300 },
        .recv = .{ .broadcast_count = 2, .broadcast_bytes = 200 },
    };
    a.add(&b);

    try testing.expectEqual(@as(u64, 13), a.send.unicast_count);
    try testing.expectEqual(@as(u64, 1300), a.send.unicast_bytes);
    try testing.expectEqual(@as(u64, 7), a.recv.broadcast_count);
    try testing.expectEqual(@as(u64, 200), a.recv.broadcast_bytes);
}

test "Traffic.delta computes and resets" {
    var traffic = Traffic{};
    traffic.send.unicast_count = 100;
    traffic.send.unicast_bytes = 50000;
    traffic.recv.unicast_count = 80;
    traffic.recv.unicast_bytes = 40000;

    var old = traffic;
    // Advance counters.
    traffic.send.unicast_count = 110;
    traffic.send.unicast_bytes = 55000;
    traffic.recv.unicast_count = 85;
    traffic.recv.unicast_bytes = 42500;

    const d = traffic.delta(&old);
    try testing.expectEqual(@as(u64, 10), d.send.unicast_count);
    try testing.expectEqual(@as(u64, 5000), d.send.unicast_bytes);
    try testing.expectEqual(@as(u64, 5), d.recv.unicast_count);
    try testing.expectEqual(@as(u64, 2500), d.recv.unicast_bytes);

    // old should now reflect the current state.
    try testing.expectEqual(@as(u64, 110), old.send.unicast_count);
    try testing.expectEqual(@as(u64, 85), old.recv.unicast_count);
}

test "Traffic.totalBytes" {
    const t = Traffic{
        .send = .{ .unicast_bytes = 1000, .broadcast_bytes = 500 },
        .recv = .{ .unicast_bytes = 2000, .broadcast_bytes = 100 },
    };
    try testing.expectEqual(@as(u64, 3600), t.totalBytes());
}

test "addTraffic accumulates correctly" {
    var dst = Traffic{};
    const diff = Traffic{
        .send = .{ .unicast_count = 10, .unicast_bytes = 5000 },
        .recv = .{ .broadcast_count = 3, .broadcast_bytes = 1500 },
    };
    addTraffic(&dst, &diff);
    addTraffic(&dst, &diff);
    try testing.expectEqual(@as(u64, 20), dst.send.unicast_count);
    try testing.expectEqual(@as(u64, 10000), dst.send.unicast_bytes);
    try testing.expectEqual(@as(u64, 6), dst.recv.broadcast_count);
    try testing.expectEqual(@as(u64, 3000), dst.recv.broadcast_bytes);
}

test "addTrafficForSession swaps send/recv" {
    var hub_traffic = Traffic{};
    const session_traffic = Traffic{
        .send = .{ .unicast_count = 5, .unicast_bytes = 2500 },
        .recv = .{ .unicast_count = 10, .unicast_bytes = 5000 },
    };
    addTrafficForSession(&session_traffic, &hub_traffic, null);
    // Hub sees: send = session.recv, recv = session.send
    try testing.expectEqual(@as(u64, 10), hub_traffic.send.unicast_count);
    try testing.expectEqual(@as(u64, 5000), hub_traffic.send.unicast_bytes);
    try testing.expectEqual(@as(u64, 5), hub_traffic.recv.unicast_count);
    try testing.expectEqual(@as(u64, 2500), hub_traffic.recv.unicast_bytes);
}

test "addTrafficForSession accumulates into cedar" {
    var hub_traffic = Traffic{};
    var cedar_traffic = Traffic{};
    const session_traffic = Traffic{
        .send = .{ .unicast_count = 1, .unicast_bytes = 100 },
        .recv = .{ .unicast_count = 2, .unicast_bytes = 200 },
    };
    addTrafficForSession(&session_traffic, &hub_traffic, &cedar_traffic);
    // Both hub and cedar should have the same (swapped) totals.
    try testing.expectEqual(cedar_traffic.send.unicast_count, hub_traffic.send.unicast_count);
    try testing.expectEqual(cedar_traffic.recv.unicast_count, hub_traffic.recv.unicast_count);
}

test "incrementUserTraffic computes delta and accumulates" {
    var session_traffic = Traffic{
        .send = .{ .unicast_count = 100, .unicast_bytes = 50000 },
        .recv = .{ .unicast_count = 80, .unicast_bytes = 40000 },
    };
    var old_traffic = session_traffic;
    var user_traffic = Traffic{};

    // Advance counters.
    session_traffic.send.unicast_count = 110;
    session_traffic.send.unicast_bytes = 55000;
    session_traffic.recv.unicast_count = 85;
    session_traffic.recv.unicast_bytes = 42500;

    const delta = incrementUserTraffic(&session_traffic, &old_traffic, &user_traffic, null);
    try testing.expectEqual(@as(u64, 10), delta.send.unicast_count);
    try testing.expectEqual(@as(u64, 5000), delta.send.unicast_bytes);
    try testing.expectEqual(@as(u64, 5), delta.recv.unicast_count);
    try testing.expectEqual(@as(u64, 2500), delta.recv.unicast_bytes);
    // User traffic should have accumulated the delta.
    try testing.expectEqual(@as(u64, 10), user_traffic.send.unicast_count);
}

test "incrementHubTraffic computes delta" {
    var hub_traffic = Traffic{
        .send = .{ .unicast_count = 500 },
        .recv = .{ .unicast_bytes = 25000 },
    };
    var old_traffic = hub_traffic;

    hub_traffic.send.unicast_count = 520;
    hub_traffic.recv.unicast_bytes = 30000;

    const delta = incrementHubTraffic(&hub_traffic, &old_traffic);
    try testing.expectEqual(@as(u64, 20), delta.send.unicast_count);
    try testing.expectEqual(@as(u64, 5000), delta.recv.unicast_bytes);
    // old should now reflect current.
    try testing.expectEqual(@as(u64, 520), old_traffic.send.unicast_count);
    try testing.expectEqual(@as(u64, 30000), old_traffic.recv.unicast_bytes);
}
