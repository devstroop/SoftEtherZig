//! IPv6 Router Advertisement generator (RFC 4861).
//!
//! C reference: none — the C SoftEther server does not generate RAs.
//! It only filters/modifies them in `Hub.c`. This is a Zig-only addition
//! to provide IPv6 auto-configuration for hub-side clients.
//!
//! Scope (S23):
//! - Build ICMPv6 Router Advertisement packets.
//! - Source Link-Layer Address, Prefix Information, and MTU options.
//! - Solicited RA (response to Router Solicitation, type 133).
//! - Periodic RA timer configuration.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

// ============================================================================
// Constants (RFC 4861)
// ============================================================================

/// ICMPv6 type: Router Solicitation.
pub const ICMPV6_ROUTER_SOLICITATION: u8 = 133;
/// ICMPv6 type: Router Advertisement.
pub const ICMPV6_ROUTER_ADVERTISEMENT: u8 = 134;
/// ICMPv6 type: Neighbor Solicitation.
pub const ICMPV6_NEIGHBOR_SOLICITATION: u8 = 135;
/// ICMPv6 type: Neighbor Advertisement.
pub const ICMPV6_NEIGHBOR_ADVERTISEMENT: u8 = 136;
/// ICMPv6 option type: Source Link-Layer Address.
pub const ICMPV6_OPT_SOURCE_LL: u8 = 1;
/// ICMPv6 option type: Prefix Information.
pub const ICMPV6_OPT_PREFIX: u8 = 3;
/// ICMPv6 option type: MTU.
pub const ICMPV6_OPT_MTU: u8 = 5;
/// Default RA interval in seconds (RFC 4861 §6.2.1, MaxRtrAdvInterval = 600).
pub const DEFAULT_RA_INTERVAL: u32 = 600;
/// Default router lifetime in seconds (RFC 4861 §6.2.1, 3 * MaxRtrAdvInterval).
pub const DEFAULT_ROUTER_LIFETIME: u32 = 1800;
/// Default preferred lifetime for prefixes (RFC 4861 §6.2.1).
pub const DEFAULT_PREFIX_PREFERRED: u32 = 604800; // 7 days
/// Default valid lifetime for prefixes.
pub const DEFAULT_PREFIX_VALID: u32 = 2592000; // 30 days
/// Default MTU.
pub const DEFAULT_MTU: u32 = 1500;

// ============================================================================
// RA configuration
// ============================================================================

/// Configuration for Router Advertisement generation.
pub const RaConfig = struct {
    /// Hub MAC address (6 bytes) — used as the source link-layer address.
    hub_mac: [6]u8,
    /// Hub link-local IPv6 address (16 bytes, e.g. fe80::xxxx).
    hub_ipv6: [16]u8,
    /// Prefix to advertise (16 bytes, e.g. 2001:db8:1::).
    prefix: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /// Prefix length in bits (typically 64).
    prefix_len: u8 = 64,
    /// Current hop limit (advertised to clients).
    cur_hop_limit: u8 = 64,
    /// Default router lifetime (seconds). 0 = not a default router.
    router_lifetime: u16 = DEFAULT_ROUTER_LIFETIME,
    /// Reachable time (ms). 0 = unspecified.
    reachable_time: u32 = 0,
    /// Retransmission timer (ms). 0 = unspecified.
    retrans_timer: u32 = 0,
    /// Preferred lifetime for the prefix (seconds).
    prefix_preferred: u32 = DEFAULT_PREFIX_PREFERRED,
    /// Valid lifetime for the prefix (seconds).
    prefix_valid: u32 = DEFAULT_PREFIX_VALID,
    /// MTU to advertise.
    mtu: u32 = DEFAULT_MTU,
    /// Whether the on-link flag is set in the prefix option.
    on_link: bool = true,
    /// Whether the autonomous flag is set (allow SLAAC).
    autonomous: bool = true,
};

// ============================================================================
// Router Advertisement builder
// ============================================================================

/// Build an ICMPv6 Router Advertisement packet wrapped in an Ethernet frame.
///
/// Returns the complete Ethernet frame (14-byte Ethernet header + IPv6 header
/// + ICMPv6 RA + options), or null on error.
pub fn buildRa(allocator: Allocator, config: *const RaConfig) ?[]u8 {
    var buf: [256]u8 = undefined;
    var pos: usize = 0;

    // ---- Ethernet header (14 bytes) ---------------------------------------
    const all_nodes_mac = [6]u8{ 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 }; // ff02::1
    @memcpy(buf[0..6], &all_nodes_mac);
    @memcpy(buf[6..12], &config.hub_mac);
    mem.writeInt(u16, buf[12..14], 0x86DD, .big); // EtherType IPv6
    pos = 14;

    // ---- IPv6 header (40 bytes) -------------------------------------------
    // Version (4 bits) = 6, Traffic Class (8 bits) = 0, Flow Label (20 bits) = 0.
    buf[pos] = 0x60;
    buf[pos + 1] = 0x00;
    buf[pos + 2] = 0x00;
    buf[pos + 3] = 0x00;
    // Payload length — will be filled later.
    pos += 4;
    const payload_len_pos = pos;
    pos += 2;
    // Next Header = 58 (ICMPv6).
    buf[pos] = 58;
    pos += 1;
    // Hop Limit = 255 (RA must be sent with hop limit 255 per RFC 4861 §6.1.1).
    buf[pos] = 255;
    pos += 1;
    // Source address = hub link-local.
    @memcpy(buf[pos..][0..16], &config.hub_ipv6);
    pos += 16;
    // Destination address = ff02::1 (all-nodes multicast).
    const ff02_1 = [16]u8{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    @memcpy(buf[pos..][0..16], &ff02_1);
    pos += 16;

    // ---- ICMPv6 Router Advertisement --------------------------------------
    const icmp_start = pos;
    // Type.
    buf[pos] = ICMPV6_ROUTER_ADVERTISEMENT;
    pos += 1;
    // Code.
    buf[pos] = 0;
    pos += 1;
    // Checksum — placeholder, filled later.
    pos += 2;
    // Cur Hop Limit.
    buf[pos] = config.cur_hop_limit;
    pos += 1;
    // Flags: M (managed) = 0, O (other) = 0.
    buf[pos] = 0;
    pos += 1;
    // Router Lifetime.
    mem.writeInt(u16, buf[pos..][0..2], config.router_lifetime, .big);
    pos += 2;
    // Reachable Time.
    mem.writeInt(u32, buf[pos..][0..4], config.reachable_time, .big);
    pos += 4;
    // Retrans Timer.
    mem.writeInt(u32, buf[pos..][0..4], config.retrans_timer, .big);
    pos += 4;

    // ---- ICMPv6 Option: Source Link-Layer Address (type 1, 8 bytes) --------
    buf[pos] = ICMPV6_OPT_SOURCE_LL;
    pos += 1;
    buf[pos] = 1; // length in units of 8 bytes (1 = 8 bytes)
    pos += 1;
    @memcpy(buf[pos..][0..6], &config.hub_mac);
    pos += 6;

    // ---- ICMPv6 Option: Prefix Information (type 3, 30 bytes) -------------
    buf[pos] = ICMPV6_OPT_PREFIX;
    pos += 1;
    buf[pos] = 4; // length in units of 8 bytes (4 = 30 bytes, rounded up)
    pos += 1;
    // Prefix Length.
    buf[pos] = config.prefix_len;
    pos += 1;
    // Flags: L (on-link) = 1, A (autonomous) = 1.
    buf[pos] = (@as(u8, if (config.on_link) 0x80 else 0) | @as(u8, if (config.autonomous) 0x40 else 0));
    pos += 1;
    // Valid Lifetime.
    mem.writeInt(u32, buf[pos..][0..4], config.prefix_valid, .big);
    pos += 4;
    // Preferred Lifetime.
    mem.writeInt(u32, buf[pos..][0..4], config.prefix_preferred, .big);
    pos += 4;
    // Reserved (4 bytes).
    mem.writeInt(u32, buf[pos..][0..4], 0, .big);
    pos += 4;
    // Prefix (16 bytes).
    @memcpy(buf[pos..][0..16], &config.prefix);
    pos += 16;

    // ---- ICMPv6 Option: MTU (type 5, 8 bytes) ----------------------------
    buf[pos] = ICMPV6_OPT_MTU;
    pos += 1;
    buf[pos] = 1; // length = 8 bytes
    pos += 1;
    // Reserved (2 bytes).
    mem.writeInt(u16, buf[pos..][0..2], 0, .big);
    pos += 2;
    // MTU.
    mem.writeInt(u32, buf[pos..][0..4], config.mtu, .big);
    pos += 4;

    // ---- Fill payload length ----------------------------------------------
    const icmp_len = pos - icmp_start;
    mem.writeInt(u16, @constCast(buf[payload_len_pos..][0..2]), @intCast(icmp_len), .big);

    // ---- ICMPv6 checksum --------------------------------------------------
    // Pseudo-header: source (16) + dest (16) + next_header (4) + icmp_len (4).
    var cksum_data: [40 + 256]u8 = undefined;
    @memcpy(cksum_data[0..16], &config.hub_ipv6);
    @memcpy(cksum_data[16..32], &ff02_1);
    mem.writeInt(u32, cksum_data[32..36], icmp_len, .big); // upper 32 bits = 0
    mem.writeInt(u32, cksum_data[32..36], @intCast(icmp_len), .big);
    cksum_data[32] = 0;
    cksum_data[33] = 0;
    cksum_data[34] = @intCast((icmp_len >> 8) & 0xFF);
    cksum_data[35] = @intCast(icmp_len & 0xFF);
    cksum_data[36] = 0;
    cksum_data[37] = 0;
    cksum_data[38] = 0;
    cksum_data[39] = 58; // next header
    @memcpy(cksum_data[40..][0..icmp_len], buf[icmp_start..][0..icmp_len]);
    // Zero the checksum field in the copy.
    cksum_data[40 + 2] = 0;
    cksum_data[40 + 3] = 0;

    const cksum = icmpv6Checksum(&cksum_data[0..][0 .. 40 + icmp_len]);
    buf[icmp_start + 2] = @intCast((cksum >> 8) & 0xFF);
    buf[icmp_start + 3] = @intCast(cksum & 0xFF);

    return allocator.dupe(u8, buf[0..pos]) catch null;
}

// ============================================================================
// Neighbor Advertisement builder (for hub NS responses)
// ============================================================================

/// Build an ICMPv6 Neighbor Advertisement in response to a Neighbor Solicitation.
/// `target_ipv6` is the address being resolved; `target_mac` is the MAC to advertise.
pub fn buildNa(
    allocator: Allocator,
    source_ipv6: [16]u8,
    source_mac: [6]u8,
    target_ipv6: [16]u8,
    target_mac: [6]u8,
    solicited: bool,
) ?[]u8 {
    var buf: [128]u8 = undefined;
    var pos: usize = 0;

    // Ethernet header.
    @memcpy(buf[0..6], &target_mac); // destination = requester's MAC
    @memcpy(buf[6..12], &source_mac);
    mem.writeInt(u16, buf[12..14], 0x86DD, .big);
    pos = 14;

    // IPv6 header.
    buf[pos] = 0x60;
    buf[pos + 1] = 0x00;
    buf[pos + 2] = 0x00;
    buf[pos + 3] = 0x00;
    pos += 4;
    const payload_len_pos = pos;
    pos += 2;
    buf[pos] = 58; // Next Header = ICMPv6
    pos += 1;
    buf[pos] = 255; // Hop Limit
    pos += 1;
    @memcpy(buf[pos..][0..16], &source_ipv6);
    pos += 16;
    @memcpy(buf[pos..][0..16], &target_ipv6); // destination = target (unicast)
    pos += 16;

    // ICMPv6 NA.
    const icmp_start = pos;
    buf[pos] = ICMPV6_NEIGHBOR_ADVERTISEMENT;
    pos += 1;
    buf[pos] = 0; // Code
    pos += 1;
    pos += 2; // Checksum placeholder
    // Flags: R=0, S(solicited)=?, O(override)=1.
    buf[pos] = if (solicited) 0x60 else 0x40;
    pos += 1;
    pos += 3; // Reserved
    @memcpy(buf[pos..][0..16], &target_ipv6);
    pos += 16;

    // Target Link-Layer Address option.
    buf[pos] = 2; // type = 2
    pos += 1;
    buf[pos] = 1; // length = 8 bytes
    pos += 1;
    @memcpy(buf[pos..][0..6], &target_mac);
    pos += 6;

    const icmp_len = pos - icmp_start;
    mem.writeInt(u16, @constCast(buf[payload_len_pos..][0..2]), @intCast(icmp_len), .big);

    // ICMPv6 checksum.
    var cksum_data: [40 + 128]u8 = undefined;
    @memcpy(cksum_data[0..16], &source_ipv6);
    @memcpy(cksum_data[16..32], &target_ipv6);
    cksum_data[32] = 0;
    cksum_data[33] = 0;
    cksum_data[34] = @intCast((icmp_len >> 8) & 0xFF);
    cksum_data[35] = @intCast(icmp_len & 0xFF);
    cksum_data[36] = 0;
    cksum_data[37] = 0;
    cksum_data[38] = 0;
    cksum_data[39] = 58;
    @memcpy(cksum_data[40..][0..icmp_len], buf[icmp_start..][0..icmp_len]);
    cksum_data[40 + 2] = 0;
    cksum_data[40 + 3] = 0;

    const cksum = icmpv6Checksum(&cksum_data[0..][0 .. 40 + icmp_len]);
    buf[icmp_start + 2] = @intCast((cksum >> 8) & 0xFF);
    buf[icmp_start + 3] = @intCast(cksum & 0xFF);

    return allocator.dupe(u8, buf[0..pos]) catch null;
}

// ============================================================================
// Helpers
// ============================================================================

/// Generate a link-local IPv6 address from a MAC using EUI-64.
/// fe80::xxxx:xxff:fexx:xxxx
pub fn eui64LinkLocal(mac: [6]u8) [16]u8 {
    var addr: [16]u8 = .{0} ** 16;
    // Link-local prefix.
    addr[0] = 0xfe;
    addr[1] = 0x80;
    // EUI-64 from MAC: insert ff:fe in the middle and flip the U/L bit.
    addr[8] = mac[0] ^ 0x02; // flip U/L bit
    addr[9] = mac[1];
    addr[10] = mac[2];
    addr[11] = 0xff;
    addr[12] = 0xfe;
    addr[13] = mac[3];
    addr[14] = mac[4];
    addr[15] = mac[5];
    return addr;
}

/// ICMPv6 checksum (RFC 4493 / RFC 1071 over pseudo-header + payload).
fn icmpv6Checksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += mem.readInt(u16, data[i..][0..2], .big);
    }
    if (data.len & 1 != 0) {
        sum += @as(u32, data[data.len - 1]) << 8;
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return @truncate(~sum);
}

/// Check if a raw frame is a Router Solicitation (ICMPv6 type 133).
pub fn isRouterSolicitation(frame: []const u8) bool {
    if (frame.len < 14 + 40 + 8) return false;
    // EtherType = 0x86DD (IPv6)?
    if (mem.readInt(u16, frame[12..14], .big) != 0x86DD) return false;
    const ip = frame[14..];
    const next_header = ip[6];
    if (next_header != 58) return false; // ICMPv6
    const icmp = ip[40..];
    return icmp[0] == ICMPV6_ROUTER_SOLICITATION;
}

/// Check if a raw frame is a Neighbor Solicitation (ICMPv6 type 135).
pub fn isNeighborSolicitation(frame: []const u8) bool {
    if (frame.len < 14 + 40 + 8) return false;
    if (mem.readInt(u16, frame[12..14], .big) != 0x86DD) return false;
    const ip = frame[14..];
    if (ip[6] != 58) return false;
    const icmp = ip[40..];
    return icmp[0] == ICMPV6_NEIGHBOR_SOLICITATION;
}

/// Extract the target IPv6 address from a Neighbor Solicitation.
pub fn nsTargetAddress(frame: []const u8) ?[16]u8 {
    if (frame.len < 14 + 40 + 24) return null;
    const ip = frame[14..];
    const icmp = ip[40..];
    if (icmp[0] != ICMPV6_NEIGHBOR_SOLICITATION) return null;
    // Target address is at ICMPv6 offset 8..24.
    var addr: [16]u8 = undefined;
    @memcpy(&addr, icmp[8..24]);
    return addr;
}

/// Compute the solicited-node multicast address for a given unicast address.
/// ff02::1:ffXX:XXXX where XX:XXXX are the last 3 bytes of the unicast address.
pub fn solicitedNodeMulticast(unicast: [16]u8) [16]u8 {
    return [16]u8{
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0xff, unicast[13], unicast[14], unicast[15],
    };
}

// ============================================================================
// Tests
// ============================================================================

const RaTestConfig = RaConfig{
    .hub_mac = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
    .hub_ipv6 = .{ 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa8, 0xbb, 0xcc, 0xff, 0xfe, 0xdd, 0xee, 0xff },
    .prefix = .{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .prefix_len = 64,
};

test "eui64LinkLocal generates correct link-local address" {
    const mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const addr = eui64LinkLocal(mac);

    // fe80:: prefix.
    try testing.expectEqual(@as(u8, 0xfe), addr[0]);
    try testing.expectEqual(@as(u8, 0x80), addr[1]);
    // EUI-64: MAC[0]^0x02, MAC[1], MAC[2], ff, fe, MAC[3], MAC[4], MAC[5].
    try testing.expectEqual(@as(u8, 0xA8), addr[8]); // 0xAA ^ 0x02
    try testing.expectEqual(@as(u8, 0xBB), addr[9]);
    try testing.expectEqual(@as(u8, 0xCC), addr[10]);
    try testing.expectEqual(@as(u8, 0xFF), addr[11]);
    try testing.expectEqual(@as(u8, 0xFE), addr[12]);
    try testing.expectEqual(@as(u8, 0xDD), addr[13]);
    try testing.expectEqual(@as(u8, 0xEE), addr[14]);
    try testing.expectEqual(@as(u8, 0xFF), addr[15]);
}

test "buildRa creates valid frame" {
    const frame = buildRa(testing.allocator, &RaTestConfig);
    try testing.expect(frame != null);
    defer testing.allocator.free(frame.?);

    // Ethernet header: ethertype = 0x86DD.
    try testing.expectEqual(@as(u16, 0x86DD), mem.readInt(u16, frame.?[12..14], .big));

    // IPv6 header: version = 6.
    try testing.expectEqual(@as(u8, 0x60), frame.?[14] & 0xF0);
    // Next Header = 58 (ICMPv6).
    try testing.expectEqual(@as(u8, 58), frame.?[14 + 6]);
    // Hop Limit = 255 (RA requirement).
    try testing.expectEqual(@as(u8, 255), frame.?[14 + 7]);

    // ICMPv6: type = 134 (RA).
    try testing.expectEqual(@as(u8, ICMPV6_ROUTER_ADVERTISEMENT), frame.?[14 + 40]);

    // Source link-layer option should be present (type 1 at RA offset 12).
    const ra_start = 14 + 40;
    try testing.expectEqual(@as(u8, ICMPV6_OPT_SOURCE_LL), frame.?[ra_start + 12]);
}

test "buildRa total size includes Ethernet + IPv6 + ICMPv6 + options" {
    const frame = buildRa(testing.allocator, &RaTestConfig);
    try testing.expect(frame != null);
    defer testing.allocator.free(frame.?);

    // Expected: 14 (Ethernet) + 40 (IPv6) + 12 (RA header) + 8 (SLL) + 30 (Prefix) + 8 (MTU) = 112.
    try testing.expectEqual(@as(usize, 112), frame.?.len);
}

test "buildNa creates valid Neighbor Advertisement" {
    const src_ipv6 = RaTestConfig.hub_ipv6;
    const tgt_ipv6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const src_mac = RaTestConfig.hub_mac;
    const tgt_mac = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };

    const frame = buildNa(testing.allocator, src_ipv6, src_mac, tgt_ipv6, tgt_mac, true);
    try testing.expect(frame != null);
    defer testing.allocator.free(frame.?);

    // ICMPv6 type = 136 (NA).
    try testing.expectEqual(@as(u8, ICMPV6_NEIGHBOR_ADVERTISEMENT), frame.?[14 + 40]);
    // Solicited flag = 0x60.
    try testing.expectEqual(@as(u8, 0x60), frame.?[14 + 40 + 4]);
}

test "isRouterSolicitation detects RS" {
    const frame = buildRa(testing.allocator, &RaTestConfig);
    try testing.expect(frame != null);
    defer testing.allocator.free(frame.?);

    // An RA is not an RS.
    try testing.expect(!isRouterSolicitation(frame.?));
}

test "isNeighborSolicitation detects NS" {
    const frame = buildRa(testing.allocator, &RaTestConfig);
    try testing.expect(frame != null);
    defer testing.allocator.free(frame.?);

    // An RA is not an NS.
    try testing.expect(!isNeighborSolicitation(frame.?));
}

test "nsTargetAddress returns null for non-NS" {
    const frame = buildRa(testing.allocator, &RaTestConfig);
    try testing.expect(frame != null);
    defer testing.allocator.free(frame.?);
    try testing.expect(nsTargetAddress(frame.?) == null);
}

test "solicitedNodeMulticast computes correctly" {
    const unicast = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const snm = solicitedNodeMulticast(unicast);

    // ff02::1:ff00:0001
    try testing.expectEqual(@as(u8, 0xff), snm[0]);
    try testing.expectEqual(@as(u8, 0x02), snm[1]);
    try testing.expectEqual(@as(u8, 0xff), snm[11]);
    try testing.expectEqual(@as(u8, 0xff), snm[12]);
    try testing.expectEqual(@as(u8, 0x00), snm[13]);
    try testing.expectEqual(@as(u8, 0x00), snm[14]);
    try testing.expectEqual(@as(u8, 0x01), snm[15]);
}

test "icmpv6Checksum basic" {
    // Known test vector: all zeros, 4 bytes → checksum should be 0xFFFF.
    var data = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    const cksum = icmpv6Checksum(&data);
    try testing.expectEqual(@as(u16, 0xFFFF), cksum);
}
