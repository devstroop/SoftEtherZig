//! Adapter Wrapper
//!
//! Bridges the VPN client to the underlying virtual network adapter.
//! Provides TUN device management, routing, and packet I/O.

const std = @import("std");
const Allocator = std.mem.Allocator;

// Import adapter module
const adapter_mod = @import("mod.zig");
const VirtualAdapter = adapter_mod.VirtualAdapter;
pub const TunStats = adapter_mod.TunStats;

/// Adapter wrapper that bridges VpnClient to the real adapter implementation
pub const AdapterWrapper = struct {
    allocator: Allocator,
    real_adapter: ?VirtualAdapter,
    is_open: bool,
    device_name: [32]u8,
    device_name_len: usize,
    mac: [6]u8,
    ip_address: u32,
    gateway_ip: u32,
    netmask: u32,

    const Self = @This();

    /// Initialize adapter wrapper
    pub fn init(allocator: Allocator) Self {
        // Generate random locally-administered MAC
        var mac: [6]u8 = undefined;
        std.crypto.random.bytes(&mac);
        mac[0] = 0x02; // Locally administered
        mac[1] = 0x00;
        mac[2] = 0x5E;

        return .{
            .allocator = allocator,
            .real_adapter = VirtualAdapter.init(allocator),
            .is_open = false,
            .device_name = [_]u8{0} ** 32,
            .device_name_len = 0,
            .mac = mac,
            .ip_address = 0,
            .gateway_ip = 0,
            .netmask = 0,
        };
    }

    /// Clean up resources
    pub fn deinit(self: *Self) void {
        self.close();
    }

    /// Open the virtual network adapter
    pub fn open(self: *Self) !void {
        if (self.real_adapter) |*adapter| {
            try adapter.open();
            self.is_open = adapter.isOpen();

            // Copy device name if available
            if (adapter.getName()) |name| {
                const len = @min(name.len, self.device_name.len);
                @memcpy(self.device_name[0..len], name[0..len]);
                self.device_name_len = len;
            }

            // Copy MAC if available
            if (adapter.getMac()) |m| {
                self.mac = m;
            }
        } else {
            // Fallback stub behavior
            const name = "utun99";
            @memcpy(self.device_name[0..name.len], name);
            self.device_name_len = name.len;
            self.is_open = true;
        }
    }

    /// Close the adapter
    pub fn close(self: *Self) void {
        if (self.real_adapter) |*adapter| {
            adapter.close();
        }
        self.is_open = false;
    }

    /// Get device name
    pub fn getName(self: *const Self) ?[]const u8 {
        if (!self.is_open) return null;
        return self.device_name[0..self.device_name_len];
    }

    /// Get MAC address
    pub fn getMac(self: *const Self) [6]u8 {
        return self.mac;
    }

    /// Configure IP address
    pub fn configure(self: *Self, ip: u32, mask: u32, gateway: u32) void {
        self.ip_address = ip;
        self.netmask = mask;
        self.gateway_ip = gateway;
    }

    /// Configure full-tunnel routing (all traffic through VPN)
    pub fn configureFullTunnel(self: *Self, gateway: u32, server_ip: u32) void {
        self.gateway_ip = gateway;
        if (self.real_adapter) |*adapter| {
            adapter.configureFullTunnel(gateway, server_ip) catch |err| {
                std.log.err("Failed to configure full-tunnel routing: {}", .{err});
            };
        }
    }

    /// Process incoming packet from VPN
    pub fn processIncomingPacket(self: *Self, data: []const u8) ?[]u8 {
        if (self.real_adapter) |*adapter| {
            return adapter.processIncomingPacket(data) catch null;
        }
        return null;
    }

    /// Read a packet from the adapter (TUN device)
    pub fn read(self: *Self, buffer: []u8) !?usize {
        if (self.real_adapter) |*adapter| {
            return adapter.read(buffer);
        }
        return null;
    }

    /// Write a packet to the adapter (TUN device)
    pub fn write(self: *Self, data: []const u8) !usize {
        if (self.real_adapter) |*adapter| {
            return adapter.write(data);
        }
        return 0;
    }

    /// Get traffic statistics
    pub fn getStats(self: *const Self) ?TunStats {
        if (self.real_adapter) |*adapter| {
            return adapter.getStats();
        }
        return null;
    }

    /// Check if DHCP is complete
    pub fn isDhcpComplete(self: *const Self) bool {
        if (self.real_adapter) |*adapter| {
            return adapter.isDhcpComplete();
        }
        return false;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "AdapterWrapper init" {
    var wrapper = AdapterWrapper.init(std.testing.allocator);
    defer wrapper.deinit();

    try std.testing.expect(!wrapper.is_open);
    // MAC should be locally administered (first byte 0x02)
    try std.testing.expectEqual(@as(u8, 0x02), wrapper.mac[0]);
}

test "AdapterWrapper getMac" {
    var wrapper = AdapterWrapper.init(std.testing.allocator);
    defer wrapper.deinit();

    const mac = wrapper.getMac();
    try std.testing.expectEqual(@as(u8, 0x02), mac[0]);
    try std.testing.expectEqual(@as(u8, 0x00), mac[1]);
    try std.testing.expectEqual(@as(u8, 0x5E), mac[2]);
}

test "AdapterWrapper configure" {
    var wrapper = AdapterWrapper.init(std.testing.allocator);
    defer wrapper.deinit();

    wrapper.configure(0x0A150001, 0xFFFFFF00, 0x0A150001);

    try std.testing.expectEqual(@as(u32, 0x0A150001), wrapper.ip_address);
    try std.testing.expectEqual(@as(u32, 0xFFFFFF00), wrapper.netmask);
    try std.testing.expectEqual(@as(u32, 0x0A150001), wrapper.gateway_ip);
}

test "AdapterWrapper getName before open" {
    var wrapper = AdapterWrapper.init(std.testing.allocator);
    defer wrapper.deinit();

    // Should be null before opening
    try std.testing.expect(wrapper.getName() == null);
}
