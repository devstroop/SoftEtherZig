const std = @import("std");

pub const InterfaceType = enum {
    tun,
    tap,
    fd,
    bridge,
    null,
};

pub const TunConfig = struct {
    device_name: ?[]const u8 = null,
    mtu: u16 = 1500,
    persist: bool = false,
};

pub const TapConfig = struct {
    device_name: ?[]const u8 = null,
    mtu: u16 = 1500,
};

pub const FdConfig = struct {
    fd: ?i32 = null,
    rx_fd: ?i32 = null,
    tx_fd: ?i32 = null,
};

pub const BridgeConfig = struct {
    ingress_iface: []const u8,
};

pub const InterfaceConfig = union(InterfaceType) {
    tun: TunConfig,
    tap: TapConfig,
    fd: FdConfig,
    bridge: BridgeConfig,
    null: void,

    /// Free heap-allocated fields (device_name, ingress_iface).
    pub fn deinit(self: *InterfaceConfig, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .tun => |*t| {
                if (t.device_name) |d| allocator.free(d);
            },
            .tap => |*t| {
                if (t.device_name) |d| allocator.free(d);
            },
            .bridge => |*b| allocator.free(b.ingress_iface),
            .fd, .null => {},
        }
    }
};

pub fn parseInterfaceConfig(allocator: std.mem.Allocator, value: []const u8) !InterfaceConfig {
    const eq_pos = std.mem.indexOfScalar(u8, value, ':') orelse {
        if (std.mem.eql(u8, value, "tun")) return .{ .tun = .{} };
        if (std.mem.eql(u8, value, "tap")) return .{ .tap = .{} };
        if (std.mem.eql(u8, value, "fd")) return .{ .fd = .{} };
        if (std.mem.eql(u8, value, "bridge")) return error.MissingBridgeIngress;
        if (std.mem.eql(u8, value, "null")) return .{ .null = {} };
        return error.InvalidInterfaceType;
    };

    const iface_type = value[0..eq_pos];
    const params = value[eq_pos + 1 ..];

    if (std.mem.eql(u8, iface_type, "tun")) {
        var config = TunConfig{};
        // Free device_name on any subsequent parse error
        var device_name_allocated = false;
        errdefer if (device_name_allocated) allocator.free(config.device_name.?);
        var it = std.mem.splitScalar(u8, params, ',');
        while (it.next()) |param| {
            if (std.mem.indexOfScalar(u8, param, '=')) |eq| {
                const key = param[0..eq];
                const val = param[eq + 1 ..];
                if (std.mem.eql(u8, key, "device")) {
                    if (config.device_name) |old| allocator.free(old);
                    config.device_name = try allocator.dupe(u8, val);
                    device_name_allocated = true;
                }
                if (std.mem.eql(u8, key, "mtu")) config.mtu = try std.fmt.parseInt(u16, val, 10);
                if (std.mem.eql(u8, key, "persist")) config.persist = std.mem.eql(u8, val, "true");
            }
        }
        return .{ .tun = config };
    }
    if (std.mem.eql(u8, iface_type, "tap")) {
        var config = TapConfig{};
        var device_name_allocated = false;
        errdefer if (device_name_allocated) allocator.free(config.device_name.?);
        var it = std.mem.splitScalar(u8, params, ',');
        while (it.next()) |param| {
            if (std.mem.indexOfScalar(u8, param, '=')) |eq| {
                const key = param[0..eq];
                const val = param[eq + 1 ..];
                if (std.mem.eql(u8, key, "device")) {
                    if (config.device_name) |old| allocator.free(old);
                    config.device_name = try allocator.dupe(u8, val);
                    device_name_allocated = true;
                }
                if (std.mem.eql(u8, key, "mtu")) config.mtu = try std.fmt.parseInt(u16, val, 10);
            }
        }
        return .{ .tap = config };
    }
    if (std.mem.eql(u8, iface_type, "fd")) {
        var config = FdConfig{};
        var it = std.mem.splitScalar(u8, params, ',');
        while (it.next()) |param| {
            if (std.mem.indexOfScalar(u8, param, '=')) |eq| {
                const key = param[0..eq];
                const val = param[eq + 1 ..];
                if (std.mem.eql(u8, key, "fd")) config.fd = try std.fmt.parseInt(i32, val, 10);
                if (std.mem.eql(u8, key, "rx_fd")) config.rx_fd = try std.fmt.parseInt(i32, val, 10);
                if (std.mem.eql(u8, key, "tx_fd")) config.tx_fd = try std.fmt.parseInt(i32, val, 10);
            }
        }
        return .{ .fd = config };
    }
    if (std.mem.eql(u8, iface_type, "bridge")) {
        var ingress: []const u8 = "";
        var it = std.mem.splitScalar(u8, params, ',');
        while (it.next()) |param| {
            if (std.mem.indexOfScalar(u8, param, '=')) |eq| {
                const key = param[0..eq];
                const val = param[eq + 1 ..];
                if (std.mem.eql(u8, key, "ingress")) ingress = val;
            }
        }
        if (ingress.len == 0) return error.MissingBridgeIngress;
        return .{ .bridge = .{ .ingress_iface = try allocator.dupe(u8, ingress) } };
    }

    return error.InvalidInterfaceType;
}
