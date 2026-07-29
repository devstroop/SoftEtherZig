//! Adapter Wrapper
//!
//! Bridges the VPN client to the underlying virtual network adapter.
//! Provides TUN device management, routing, and packet I/O.

const std = @import("std");
const builtin = @import("builtin");
const log = std.log.scoped(.adapter_tun);
const Allocator = std.mem.Allocator;

// Import adapter module
const adapter_mod = @import("mod.zig");
const VirtualAdapter = adapter_mod.VirtualAdapter;
pub const TunStats = adapter_mod.TunStats;

pub const InterfaceConfig = adapter_mod.InterfaceConfig;
pub const factory = @import("factory.zig");

/// Adapter wrapper that bridges VpnClient to the real adapter implementation
pub const AdapterWrapper = struct {
    allocator: Allocator,
    real_adapter: ?VirtualAdapter,
    is_open: bool,
    is_null_mode: bool,
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
            .is_null_mode = false,
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

    /// Open with runtime InterfaceConfig selection.
    /// When config is null or .tun with default settings, falls back to the
    /// legacy comptime PlatformDevice path (backward compatible).
    pub fn openWithConfig(self: *Self, iface: ?InterfaceConfig) !void {
        const config = iface orelse {
            try self.open();
            return;
        };
        switch (config) {
            .tun => |cfg| {
                if (cfg.device_name) |name| std.log.warn("device_name '{s}' ignored for TUN (not yet implemented)", .{name});
                try self.open();
                if (cfg.mtu != 1500) {
                    if (self.real_adapter) |*ra| try ra.setMtu(cfg.mtu);
                }
            },
            .tap => |cfg| {
                if (cfg.device_name) |name| std.log.warn("device_name '{s}' ignored for TAP (not yet implemented)", .{name});
                try self.openTap();
            },
            .fd => |cfg| {
                if (self.real_adapter) |*adapter| {
                    if (cfg.rx_fd) |rx| {
                        if (cfg.tx_fd) |tx| {
                            try adapter.openWithFds(rx, tx, "fd-adapter");
                            self.syncFromAdapter();
                            return;
                        }
                    }
                    try adapter.openWithFd(cfg.fd orelse return error.MissingFd, "fd-adapter");
                    self.syncFromAdapter();
                }
            },
            .bridge => |_| return error.BridgeNotImplemented,
            .null => {
                self.is_open = true;
                self.is_null_mode = true;
            },
        }
    }

    fn syncFromAdapter(self: *Self) void {
        if (self.real_adapter) |*adapter| {
            self.is_open = adapter.isOpen();
            if (adapter.getName()) |n| {
                const len = @min(n.len, self.device_name.len);
                @memcpy(self.device_name[0..len], n[0..len]);
                self.device_name_len = len;
            }
            if (adapter.getMac()) |m| {
                self.mac = m;
            }
        }
    }

    /// Open using an externally-provided file descriptor (for mobile platforms)
    pub fn openWithFd(self: *Self, fd: i32, name: []const u8) !void {
        if (self.real_adapter) |*adapter| {
            try adapter.openWithFd(fd, name);
            self.is_open = adapter.isOpen();

            if (adapter.getName()) |n| {
                const len = @min(n.len, self.device_name.len);
                @memcpy(self.device_name[0..len], n[0..len]);
                self.device_name_len = len;
            }

            if (adapter.getMac()) |m| {
                self.mac = m;
            }
        }
    }

    /// Open with separate rx (UL) and tx (DL) file descriptors (iOS dual socketpair).
    pub fn openWithFds(self: *Self, rx_fd: i32, tx_fd: i32, name: []const u8) !void {
        if (self.real_adapter) |*adapter| {
            try adapter.openWithFds(rx_fd, tx_fd, name);
            self.is_open = adapter.isOpen();

            if (adapter.getName()) |n| {
                const len = @min(n.len, self.device_name.len);
                @memcpy(self.device_name[0..len], n[0..len]);
                self.device_name_len = len;
            }

            if (adapter.getMac()) |m| {
                self.mac = m;
            }
        }
    }

    /// Open the adapter in TAP (L2 Ethernet) mode.
    /// On Linux, opens /dev/net/tun with IFF_TAP flag (true L2).
    /// On Windows, falls back to Wintun (L3 tunnel, not raw L2).
    /// macOS returns TapNotImplemented.
    pub fn openTap(self: *Self) !void {
        self.is_null_mode = false;
        if (self.real_adapter) |*adapter| {
            try adapter.openTap();
            self.is_open = adapter.isOpen();
            if (adapter.getName()) |n| {
                const len = @min(n.len, self.device_name.len);
                @memcpy(self.device_name[0..len], n[0..len]);
                self.device_name_len = len;
            }
            if (adapter.getMac()) |m| {
                self.mac = m;
            }
        }
    }

    /// Close the adapter
    pub fn close(self: *Self) void {
        if (self.real_adapter) |*adapter| {
            adapter.close();
        }
        self.is_open = false;
        self.is_null_mode = false;
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
        if (self.real_adapter) |*real| {
            if (real.device) |dev| {
                std.log.info("AdapterWrapper.configure: device present, calling dev.configure()", .{});
                dev.configure(ip, mask, gateway) catch |err| {
                    std.log.err("Failed to configure device: {}", .{err});
                };
            } else {
                std.log.warn("AdapterWrapper.configure: real_adapter set but device is null", .{});
            }
        } else {
            std.log.warn("AdapterWrapper.configure: real_adapter is null", .{});
        }
    }

    /// Configure IPv6 on the adapter
    pub fn configureIpv6(self: *Self, address: [16]u8, prefix_len: u8, gateway: []const u8) void {
        if (self.real_adapter) |*adapter| {
            adapter.configureIpv6(address, prefix_len, gateway) catch |err| {
                std.log.err("Failed to configure IPv6: {}", .{err});
            };
        }
    }

    /// Configure full-tunnel routing (all traffic through VPN)
    pub fn configureFullTunnel(self: *Self, gateway: u32, server_ip: u32) void {
        self.gateway_ip = gateway;
        if (builtin.os.tag == .linux and builtin.abi.isAndroid()) {
            std.log.info("Routing managed by Android VpnService.Builder; skipping native route setup", .{});
            return;
        }
        if (builtin.os.tag == .ios or builtin.os.tag == .tvos or builtin.os.tag == .watchos) {
            std.log.info("Routing managed by NEPacketTunnelProvider; skipping native route setup", .{});
            return;
        }
        if (self.real_adapter) |*adapter| {
            adapter.configureFullTunnel(gateway, server_ip) catch |err| {
                std.log.err("Failed to configure full-tunnel routing: {}", .{err});
            };
        }
    }

    /// Configure split-tunnel VPN routing (only specified networks through VPN).
    /// `routes_str` is a newline-separated list of CIDR notations.
    pub fn configureSplitTunnel(self: *Self, gateway: u32, routes_str: []const u8) void {
        self.gateway_ip = gateway;
        if (builtin.os.tag == .linux and builtin.abi.isAndroid()) {
            std.log.info("Routing managed by Android VpnService.Builder; skipping native route setup", .{});
            return;
        }
        if (builtin.os.tag == .ios or builtin.os.tag == .tvos or builtin.os.tag == .watchos) {
            std.log.info("Routing managed by NEPacketTunnelProvider; skipping native route setup", .{});
            return;
        }
        if (self.real_adapter) |*adapter| {
            adapter.configureSplitTunnel(gateway, routes_str) catch |err| {
                std.log.err("Failed to configure split-tunnel routing: {}", .{err});
            };
        }
    }

    /// Add custom IPv6 split-tunnel routes through a gateway.
    /// `routes_str` is a newline-separated list of IPv6 CIDR notations.
    pub fn addIpv6Routes(self: *Self, gateway: []const u8, routes_str: []const u8) void {
        if (builtin.os.tag == .linux and builtin.abi.isAndroid()) {
            return;
        }
        if (builtin.os.tag == .ios or builtin.os.tag == .tvos or builtin.os.tag == .watchos) {
            return;
        }
        if (self.real_adapter) |*adapter| {
            adapter.addIpv6Routes(gateway, routes_str) catch |err| {
                std.log.err("Failed to add custom IPv6 routes: {}", .{err});
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

    /// Replace the wrapped TUN fd (mobile only — after DHCP reconfiguration)
    pub fn replaceFd(self: *Self, new_fd: i32) !void {
        if (self.real_adapter) |*adapter| {
            try adapter.replaceFd(new_fd);
        } else {
            return error.DeviceNotOpen;
        }
    }

    /// Write a packet to the adapter (TUN device)
    pub fn write(self: *Self, data: []const u8) !usize {
        if (self.is_null_mode) return data.len;
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
