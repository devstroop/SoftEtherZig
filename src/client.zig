const std = @import("std");
const c_mod = @import("c.zig");
const c = c_mod.c;
const errors = @import("errors.zig");
const config = @import("config.zig");
const types = @import("types.zig");

const VpnError = errors.VpnError;
const ConnectionConfig = config.ConnectionConfig;

/// VPN Client wrapper using the C bridge layer
pub const VpnClient = struct {
    handle: ?*c_mod.VpnBridgeClient,
    allocator: std.mem.Allocator,
    config: ConnectionConfig,

    /// Initialize a new VPN client
    pub fn init(allocator: std.mem.Allocator, cfg: ConnectionConfig) !VpnClient {
        // Initialize the bridge library (once per program)
        // Note: BOOL in SoftEther is typedef'd as unsigned int (0 = FALSE, 1 = TRUE)
        const init_result = c.vpn_bridge_init(0); // 0 = FALSE (debug off)

        if (init_result != c_mod.VPN_BRIDGE_SUCCESS) {
            return VpnError.InitializationFailed;
        }

        // Create client instance
        const client_handle = c.vpn_bridge_create_client() orelse {
            return VpnError.ClientCreationFailed;
        };

        // Configure the client
        const host_z = try allocator.dupeZ(u8, cfg.server_name);
        defer allocator.free(host_z);

        const hub_z = try allocator.dupeZ(u8, cfg.hub_name);
        defer allocator.free(hub_z);

        // Extract username/password from auth
        const username = switch (cfg.auth) {
            .password => |p| p.username,
            else => "anonymous",
        };
        const password = switch (cfg.auth) {
            .password => |p| p.password,
            else => "",
        };
        const is_hashed = switch (cfg.auth) {
            .password => |p| p.is_hashed,
            else => false,
        };

        const user_z = try allocator.dupeZ(u8, username);
        defer allocator.free(user_z);

        const pass_z = try allocator.dupeZ(u8, password);
        defer allocator.free(pass_z);

        const config_result = if (is_hashed)
            c.vpn_bridge_configure_with_hash(
                client_handle,
                host_z.ptr,
                cfg.server_port,
                hub_z.ptr,
                user_z.ptr,
                pass_z.ptr,
            )
        else
            c.vpn_bridge_configure(
                client_handle,
                host_z.ptr,
                cfg.server_port,
                hub_z.ptr,
                user_z.ptr,
                pass_z.ptr,
            );

        if (config_result != c_mod.VPN_BRIDGE_SUCCESS) {
            c.vpn_bridge_free_client(client_handle);
            return VpnError.ConfigurationError;
        }

        const client = VpnClient{
            .handle = client_handle,
            .allocator = allocator,
            .config = cfg,
        };
        return client;
    }

    /// Clean up and free resources
    pub fn deinit(self: *VpnClient) void {
        if (self.handle) |handle| {
            c.vpn_bridge_free_client(handle);
            self.handle = null;
        }
    }

    /// Connect to VPN server
    pub fn connect(self: *VpnClient) !void {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        const result = c.vpn_bridge_connect(handle);
        if (result != c_mod.VPN_BRIDGE_SUCCESS) {
            return switch (result) {
                c_mod.VPN_BRIDGE_ERROR_CONNECT_FAILED => VpnError.ConnectionFailed,
                c_mod.VPN_BRIDGE_ERROR_AUTH_FAILED => VpnError.AuthenticationFailed,
                c_mod.VPN_BRIDGE_ERROR_INVALID_PARAM => VpnError.InvalidParameter,
                else => VpnError.OperationFailed,
            };
        }
    }

    /// Disconnect from VPN server
    pub fn disconnect(self: *VpnClient) !void {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        const result = c.vpn_bridge_disconnect(handle);
        if (result != c_mod.VPN_BRIDGE_SUCCESS) {
            return VpnError.OperationFailed;
        }
    }

    /// Get current connection status
    pub fn getStatus(self: *const VpnClient) types.ConnectionStatus {
        const handle = self.handle orelse return .error_state;

        const status = c.vpn_bridge_get_status(handle);
        return switch (status) {
            c_mod.VPN_STATUS_DISCONNECTED => .disconnected,
            c_mod.VPN_STATUS_CONNECTING => .connecting,
            c_mod.VPN_STATUS_CONNECTED => .connected,
            c_mod.VPN_STATUS_ERROR => .error_state,
            else => .error_state,
        };
    }

    /// Check if client is connected
    pub fn isConnected(self: *const VpnClient) bool {
        return self.getStatus() == .connected;
    }

    /// Get connection information (bytes sent/received, connection time)
    pub fn getConnectionInfo(self: *const VpnClient) !struct {
        bytes_sent: u64,
        bytes_received: u64,
        connected_seconds: u64,
    } {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        var bytes_sent: u64 = 0;
        var bytes_received: u64 = 0;
        var connected_time: u64 = 0;

        const result = c.vpn_bridge_get_connection_info(
            handle,
            &bytes_sent,
            &bytes_received,
            &connected_time,
        );

        if (result != c_mod.VPN_BRIDGE_SUCCESS) {
            return VpnError.OperationFailed;
        }

        return .{
            .bytes_sent = bytes_sent,
            .bytes_received = bytes_received,
            .connected_seconds = connected_time,
        };
    }

    /// Get TUN device name (e.g., "utun6")
    pub fn getDeviceName(self: *const VpnClient) ![64]u8 {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        var device_name: [64]u8 = undefined;
        const result = c.vpn_bridge_get_device_name(
            handle,
            &device_name,
            device_name.len,
        );

        if (result != c_mod.VPN_BRIDGE_SUCCESS) {
            return VpnError.OperationFailed;
        }

        return device_name;
    }

    /// Get learned IP address (0 if not yet learned)
    pub fn getLearnedIp(self: *const VpnClient) !u32 {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        var ip: u32 = 0;
        const result = c.vpn_bridge_get_learned_ip(handle, &ip);

        if (result != c_mod.VPN_BRIDGE_SUCCESS) {
            return VpnError.OperationFailed;
        }

        return ip;
    }

    /// Get learned gateway MAC address
    pub fn getGatewayMac(self: *const VpnClient) !?[6]u8 {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        var mac: [6]u8 = undefined;
        var has_mac: u32 = 0;
        const result = c.vpn_bridge_get_gateway_mac(handle, &mac, &has_mac);

        if (result != c_mod.VPN_BRIDGE_SUCCESS) {
            return VpnError.OperationFailed;
        }

        if (has_mac != 0) {
            return mac;
        }
        return null;
    }
};
