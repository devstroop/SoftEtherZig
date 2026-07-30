const std = @import("std");
const builtin = @import("builtin");
const log = std.log.scoped(.adapter_factory);

const interface_config = @import("interface_config.zig");
const InterfaceConfig = interface_config.InterfaceConfig;
const mod = @import("mod.zig");

const VirtualAdapter = mod.VirtualAdapter;

pub const AdapterFactory = struct {
    pub fn create(allocator: std.mem.Allocator, config: InterfaceConfig) !VirtualAdapter {
        var adapter = VirtualAdapter.init(allocator);
        try openFromConfig(&adapter, config);
        return adapter;
    }

    pub fn openFromConfig(adapter: *VirtualAdapter, config: InterfaceConfig) !void {
        switch (config) {
            .tun => |cfg| {
                try adapter.open();
                errdefer adapter.close();
                if (cfg.mtu != 1500) try adapter.setMtu(cfg.mtu);
            },
            .tap => |cfg| {
                try adapter.openTap();
                errdefer adapter.close();
                if (cfg.mtu != 1500) try adapter.setMtu(cfg.mtu);
            },
            .fd => |cfg| {
                if (cfg.rx_fd) |rx| {
                    if (cfg.tx_fd) |tx| {
                        try adapter.openWithFds(rx, tx, "fd-adapter");
                        return;
                    }
                }
                try adapter.openWithFd(cfg.fd orelse return error.MissingFd, "fd-adapter");
            },
            .bridge => |_| {
                return error.BridgeNotImplemented;
            },
            .null => {
                adapter.device = null;
            },
        }
    }
};
