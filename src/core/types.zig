//! Core Types
//!
//! Common types used throughout the codebase.

const std = @import("std");

/// MAC address (6 bytes)
pub const MacAddress = [6]u8;

/// IP address (IPv4 or IPv6)
pub const IpAddress = union(enum) {
    ipv4: [4]u8,
    ipv6: [16]u8,

    pub fn format(
        self: IpAddress,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        switch (self) {
            .ipv4 => |addr| {
                try writer.print("{d}.{d}.{d}.{d}", .{
                    addr[0], addr[1], addr[2], addr[3],
                });
            },
            .ipv6 => |addr| {
                try writer.print("{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
                    addr[0],  addr[1],  addr[2],  addr[3],
                    addr[4],  addr[5],  addr[6],  addr[7],
                    addr[8],  addr[9],  addr[10], addr[11],
                    addr[12], addr[13], addr[14], addr[15],
                });
            },
        }
    }

    /// Create IPv4 address from u32
    pub fn fromU32(ip: u32) IpAddress {
        return .{ .ipv4 = @bitCast(ip) };
    }

    /// Convert to u32 (IPv4 only)
    pub fn toU32(self: IpAddress) ?u32 {
        return switch (self) {
            .ipv4 => |addr| @bitCast(addr),
            .ipv6 => null,
        };
    }
};

/// VPN connection status
pub const ConnectionStatus = enum {
    disconnected,
    connecting,
    connected,
    disconnecting,
    error_state,
};

/// Protocol type
pub const ProtocolType = enum {
    tcp,
    udp,
};

/// VPN session statistics (basic)
pub const SessionStats = struct {
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    connected_time_ms: u64 = 0,
};

/// Network interface info
pub const InterfaceInfo = struct {
    name: []const u8,
    mac: MacAddress,
    ipv4: ?[4]u8 = null,
    ipv6: ?[16]u8 = null,
    mtu: u32 = 1500,
};

// ============================================================================
// Tests
// ============================================================================

test "IpAddress IPv4 formatting" {
    const ipv4 = IpAddress{ .ipv4 = .{ 192, 168, 1, 1 } };
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try ipv4.format("", .{}, fbs.writer());
    try std.testing.expectEqualStrings("192.168.1.1", fbs.getWritten());
}

test "IpAddress fromU32 and toU32" {
    const ip = IpAddress.fromU32(0xC0A80101);
    try std.testing.expectEqual(@as(u32, 0xC0A80101), ip.toU32().?);
}

test "MacAddress size" {
    try std.testing.expectEqual(@as(usize, 6), @sizeOf(MacAddress));
}
