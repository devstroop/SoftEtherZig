//! IP Address Utilities
//!
//! Consolidated IP address parsing and formatting functions.
//! Used throughout the codebase for handling IPv4/IPv6 addresses.

const std = @import("std");

/// Parse IPv4 address string to u32 in host byte order (little-endian on x86/ARM)
/// Returns null if the string is not a valid IPv4 address.
///
/// Example: "192.168.1.1" -> 0x0101A8C0 (little-endian)
pub fn parseIpv4(str: []const u8) ?u32 {
    var octets: [4]u8 = [_]u8{ 0, 0, 0, 0 };
    var octet: u32 = 0;
    var octet_idx: usize = 0;

    for (str) |c| {
        if (c == '.') {
            if (octet > 255 or octet_idx >= 4) return null;
            octets[octet_idx] = @truncate(octet);
            octet_idx += 1;
            octet = 0;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
        } else {
            return null;
        }
    }

    if (octet > 255 or octet_idx != 3) return null;
    octets[3] = @truncate(octet);

    // Return in host byte order (little-endian) using bitcast
    return @as(u32, @bitCast(octets));
}

/// Format u32 IPv4 address to string
/// Pack protocol stores IPs in host byte order (little-endian on x86/ARM)
///
/// Example: 0x0101A8C0 -> "192.168.1.1"
pub fn formatIpv4(ip: u32, buffer: []u8) []const u8 {
    const ip_bytes: [4]u8 = @bitCast(ip);
    const result = std.fmt.bufPrint(buffer, "{d}.{d}.{d}.{d}", .{
        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
    }) catch return "";
    return result;
}

/// Convert u32 IP to byte array
pub fn ipToBytes(ip: u32) [4]u8 {
    return @bitCast(ip);
}

/// Convert byte array to u32 IP
pub fn bytesToIp(bytes: [4]u8) u32 {
    return @bitCast(bytes);
}

/// Convert IP from host byte order to network byte order (big-endian)
pub fn hostToNetwork(ip: u32) u32 {
    return @byteSwap(ip);
}

/// Convert IP from network byte order to host byte order
pub fn networkToHost(ip: u32) u32 {
    return @byteSwap(ip);
}

/// Format IP with port as "ip:port"
pub fn formatIpPort(ip: u32, port: u16, buffer: []u8) []const u8 {
    const ip_bytes: [4]u8 = @bitCast(ip);
    const result = std.fmt.bufPrint(buffer, "{d}.{d}.{d}.{d}:{d}", .{
        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], port,
    }) catch return "";
    return result;
}

/// Check if IP is in private range (RFC 1918)
pub fn isPrivate(ip: u32) bool {
    const bytes = ipToBytes(ip);
    // 10.0.0.0/8
    if (bytes[0] == 10) return true;
    // 172.16.0.0/12
    if (bytes[0] == 172 and bytes[1] >= 16 and bytes[1] <= 31) return true;
    // 192.168.0.0/16
    if (bytes[0] == 192 and bytes[1] == 168) return true;
    return false;
}

/// Check if IP is loopback (127.0.0.0/8)
pub fn isLoopback(ip: u32) bool {
    const bytes = ipToBytes(ip);
    return bytes[0] == 127;
}

/// Check if IP is link-local (169.254.0.0/16)
pub fn isLinkLocal(ip: u32) bool {
    const bytes = ipToBytes(ip);
    return bytes[0] == 169 and bytes[1] == 254;
}

// ============================================================================
// Tests
// ============================================================================

test "parseIpv4 valid addresses" {
    // Note: parseIpv4 returns IP in little-endian host byte order
    // 192.168.1.1 -> bytes [192, 168, 1, 1] -> u32 0x0101A8C0 on little-endian
    const ip = parseIpv4("192.168.1.1").?;
    const bytes = ipToBytes(ip);
    try std.testing.expectEqual(@as(u8, 192), bytes[0]);
    try std.testing.expectEqual(@as(u8, 168), bytes[1]);
    try std.testing.expectEqual(@as(u8, 1), bytes[2]);
    try std.testing.expectEqual(@as(u8, 1), bytes[3]);

    // 127.0.0.1
    const lo = parseIpv4("127.0.0.1").?;
    const lo_bytes = ipToBytes(lo);
    try std.testing.expectEqual(@as(u8, 127), lo_bytes[0]);
    try std.testing.expectEqual(@as(u8, 0), lo_bytes[1]);

    // 0.0.0.0
    try std.testing.expectEqual(@as(u32, 0x00000000), parseIpv4("0.0.0.0").?);
}

test "parseIpv4 invalid addresses" {
    try std.testing.expect(parseIpv4("invalid") == null);
    try std.testing.expect(parseIpv4("256.1.1.1") == null);
    try std.testing.expect(parseIpv4("1.2.3") == null);
    try std.testing.expect(parseIpv4("1.2.3.4.5") == null);
    try std.testing.expect(parseIpv4("") == null);
    try std.testing.expect(parseIpv4("a.b.c.d") == null);
}

test "formatIpv4" {
    var buf: [16]u8 = undefined;
    // Build IP from bytes [192, 168, 1, 1]
    const ip = bytesToIp(.{ 192, 168, 1, 1 });
    try std.testing.expectEqualStrings("192.168.1.1", formatIpv4(ip, &buf));

    const lo = bytesToIp(.{ 127, 0, 0, 1 });
    try std.testing.expectEqualStrings("127.0.0.1", formatIpv4(lo, &buf));

    try std.testing.expectEqualStrings("0.0.0.0", formatIpv4(0x00000000, &buf));
}

test "ipToBytes and bytesToIp roundtrip" {
    const bytes: [4]u8 = .{ 192, 168, 1, 1 };
    const ip = bytesToIp(bytes);
    try std.testing.expectEqual(bytes, ipToBytes(ip));
}

test "isPrivate" {
    try std.testing.expect(isPrivate(bytesToIp(.{ 10, 0, 0, 1 })));
    try std.testing.expect(isPrivate(bytesToIp(.{ 172, 16, 0, 1 })));
    try std.testing.expect(isPrivate(bytesToIp(.{ 192, 168, 1, 1 })));
    try std.testing.expect(!isPrivate(bytesToIp(.{ 8, 8, 8, 8 })));
}

test "isLoopback" {
    try std.testing.expect(isLoopback(bytesToIp(.{ 127, 0, 0, 1 })));
    try std.testing.expect(isLoopback(bytesToIp(.{ 127, 255, 255, 255 })));
    try std.testing.expect(!isLoopback(bytesToIp(.{ 128, 0, 0, 1 })));
}

test "isLinkLocal" {
    try std.testing.expect(isLinkLocal(bytesToIp(.{ 169, 254, 1, 1 })));
    try std.testing.expect(!isLinkLocal(bytesToIp(.{ 169, 255, 1, 1 })));
}
