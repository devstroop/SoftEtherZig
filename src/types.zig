const std = @import("std");

/// Common types used throughout the library
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

/// VPN session statistics
pub const SessionStats = struct {
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
    connected_time_ms: u64,
};

test "ip address formatting" {
    const ipv4 = IpAddress{ .ipv4 = .{ 192, 168, 1, 1 } };
    const str = try std.fmt.allocPrint(std.testing.allocator, "{any}", .{ipv4});
    defer std.testing.allocator.free(str);

    try std.testing.expectEqualStrings("192.168.1.1", str);
}
