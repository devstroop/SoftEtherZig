const std = @import("std");

/// Calculate Internet checksum (RFC 1071)
/// Used for IP, ICMP, TCP, UDP checksums
pub fn calculateChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;

    // Add 16-bit words
    while (i + 1 < data.len) : (i += 2) {
        const word = (@as(u32, data[i]) << 8) | @as(u32, data[i + 1]);
        sum += word;
    }

    // Add last byte if odd length
    if (i < data.len) {
        sum += @as(u32, data[i]) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    return @truncate(~sum);
}

/// Recalculate ICMP checksum in-place
/// Returns true if checksum was updated
pub fn recalculateIcmpChecksum(ip_packet: []u8) bool {
    if (ip_packet.len < 20) return false;

    const ihl = (ip_packet[0] & 0x0F) * 4;
    if (ihl > ip_packet.len) return false;

    const protocol = ip_packet[9];
    if (protocol != 1) return false; // Not ICMP

    const icmp_data = ip_packet[ihl..];
    if (icmp_data.len < 8) return false;

    // Zero out checksum field
    icmp_data[2] = 0;
    icmp_data[3] = 0;

    // Calculate checksum
    const checksum = calculateChecksum(icmp_data);

    // Write checksum (big-endian)
    icmp_data[2] = @truncate(checksum >> 8);
    icmp_data[3] = @truncate(checksum & 0xFF);

    return true;
}

/// Recalculate TCP checksum in-place with pseudo-header
/// Returns true if checksum was updated
pub fn recalculateTcpChecksum(ip_packet: []u8) bool {
    if (ip_packet.len < 20) return false;

    const ihl = (ip_packet[0] & 0x0F) * 4;
    if (ihl > ip_packet.len) return false;

    const protocol = ip_packet[9];
    if (protocol != 6) return false; // Not TCP

    const tcp_data = ip_packet[ihl..];
    if (tcp_data.len < 20) return false;

    // Zero out checksum field
    tcp_data[16] = 0;
    tcp_data[17] = 0;

    // Build pseudo-header
    var pseudo: [12]u8 = undefined;
    @memcpy(pseudo[0..4], ip_packet[12..16]); // Source IP
    @memcpy(pseudo[4..8], ip_packet[16..20]); // Dest IP
    pseudo[8] = 0; // Reserved
    pseudo[9] = protocol; // Protocol
    const tcp_len = @as(u16, @truncate(tcp_data.len));
    pseudo[10] = @truncate(tcp_len >> 8);
    pseudo[11] = @truncate(tcp_len & 0xFF);

    // Calculate checksum over pseudo-header + TCP
    var sum: u32 = 0;
    var i: usize = 0;

    // Pseudo-header
    while (i < pseudo.len) : (i += 2) {
        const word = (@as(u32, pseudo[i]) << 8) | @as(u32, pseudo[i + 1]);
        sum += word;
    }

    // TCP data
    i = 0;
    while (i + 1 < tcp_data.len) : (i += 2) {
        const word = (@as(u32, tcp_data[i]) << 8) | @as(u32, tcp_data[i + 1]);
        sum += word;
    }
    if (i < tcp_data.len) {
        sum += @as(u32, tcp_data[i]) << 8;
    }

    // Fold and complement
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    const checksum: u16 = @truncate(~sum);

    // Write checksum
    tcp_data[16] = @truncate(checksum >> 8);
    tcp_data[17] = @truncate(checksum & 0xFF);

    return true;
}

/// Recalculate UDP checksum in-place with pseudo-header
/// Returns true if checksum was updated
pub fn recalculateUdpChecksum(ip_packet: []u8) bool {
    if (ip_packet.len < 20) return false;

    const ihl = (ip_packet[0] & 0x0F) * 4;
    if (ihl > ip_packet.len) return false;

    const protocol = ip_packet[9];
    if (protocol != 17) return false; // Not UDP

    const udp_data = ip_packet[ihl..];
    if (udp_data.len < 8) return false;

    // Zero out checksum field (UDP checksum is optional, can be 0)
    udp_data[6] = 0;
    udp_data[7] = 0;

    // Build pseudo-header
    var pseudo: [12]u8 = undefined;
    @memcpy(pseudo[0..4], ip_packet[12..16]); // Source IP
    @memcpy(pseudo[4..8], ip_packet[16..20]); // Dest IP
    pseudo[8] = 0; // Reserved
    pseudo[9] = protocol; // Protocol
    const udp_len = @as(u16, @truncate(udp_data.len));
    pseudo[10] = @truncate(udp_len >> 8);
    pseudo[11] = @truncate(udp_len & 0xFF);

    // Calculate checksum over pseudo-header + UDP
    var sum: u32 = 0;
    var i: usize = 0;

    // Pseudo-header
    while (i < pseudo.len) : (i += 2) {
        const word = (@as(u32, pseudo[i]) << 8) | @as(u32, pseudo[i + 1]);
        sum += word;
    }

    // UDP data
    i = 0;
    while (i + 1 < udp_data.len) : (i += 2) {
        const word = (@as(u32, udp_data[i]) << 8) | @as(u32, udp_data[i + 1]);
        sum += word;
    }
    if (i < udp_data.len) {
        sum += @as(u32, udp_data[i]) << 8;
    }

    // Fold and complement
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    var checksum: u16 = @truncate(~sum);

    // UDP checksum of 0 means no checksum, use 0xFFFF instead
    if (checksum == 0) {
        checksum = 0xFFFF;
    }

    // Write checksum
    udp_data[6] = @truncate(checksum >> 8);
    udp_data[7] = @truncate(checksum & 0xFF);

    return true;
}

test "ICMP checksum calculation" {
    // ICMP Echo Reply packet from test
    var packet = [_]u8{
        // IP header
        0x45, 0x00, 0x00, 0x54, 0x3F, 0x85, 0x00, 0x00, 0x40, 0x01, 0x28, 0xA6,
        0x0A, 0x15, 0x00, 0x01, 0x0A, 0x15, 0xFE, 0x53,
        // ICMP (type=0, code=0, checksum=wrong, id, seq, data)
        0x00, 0x00, 0x6A, 0x4F,
        0xC6, 0x0B, 0x00, 0x00, 0x68, 0xE5, 0x9B, 0x43, 0x00, 0x03, 0xE0, 0x75,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23,
    };

    const result = recalculateIcmpChecksum(&packet);
    try std.testing.expect(result);

    // Check new checksum (should be valid now)
    const icmp_checksum = (@as(u16, packet[22]) << 8) | @as(u16, packet[23]);
    std.debug.print("Recalculated ICMP checksum: 0x{X:0>4}\n", .{icmp_checksum});

    // Verify by recalculating - should get 0 when calculated over packet with checksum
    const icmp_data = packet[20..];
    const verify_sum = calculateChecksum(icmp_data);
    std.debug.print("Verification (should be 0 or 0xFFFF): 0x{X:0>4}\n", .{verify_sum});
}
