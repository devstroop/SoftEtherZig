const std = @import("std");
const c_mod = @import("c.zig");
const c = c_mod.c;
const errors = @import("errors.zig");
const config = @import("config.zig");
const types = @import("types.zig");

const VpnError = errors.VpnError;
const ConnectionConfig = config.ConnectionConfig;

/// Reconnection state information
pub const ReconnectInfo = struct {
    enabled: bool,
    should_reconnect: bool, // True if reconnection should be attempted
    attempt: u32, // Current attempt number
    max_attempts: u32, // Maximum attempts (0=infinite)
    current_backoff: u32, // Current backoff delay in seconds
    next_retry_time: u64, // Timestamp when next retry should occur
    consecutive_failures: u32, // Count of consecutive failures
    last_disconnect_time: u64, // When connection was lost
};

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

        // Configure IP version
        const ip_version_code: c_int = switch (cfg.ip_version) {
            .auto => c_mod.VPN_IP_VERSION_AUTO,
            .ipv4 => c_mod.VPN_IP_VERSION_IPV4,
            .ipv6 => c_mod.VPN_IP_VERSION_IPV6,
            .dual => c_mod.VPN_IP_VERSION_DUAL,
        };
        _ = c.vpn_bridge_set_ip_version(client_handle, ip_version_code);

        // Configure max connections
        _ = c.vpn_bridge_set_max_connection(client_handle, @intCast(cfg.max_connection));

        // Configure adapter type (Zig vs C adapter)
        if (cfg.use_zig_adapter) {
            _ = c.vpn_bridge_set_use_zig_adapter(client_handle, 1);
        }

        // Configure static IP if provided
        if (cfg.static_ip) |sip| {
            if (sip.ipv4_address) |ipv4| {
                const ipv4_z = try allocator.dupeZ(u8, ipv4);
                defer allocator.free(ipv4_z);

                const mask_z = if (sip.ipv4_netmask) |m| try allocator.dupeZ(u8, m) else null;
                defer if (mask_z) |m| allocator.free(m);

                const gw_z = if (sip.ipv4_gateway) |g| try allocator.dupeZ(u8, g) else null;
                defer if (gw_z) |g| allocator.free(g);

                _ = c.vpn_bridge_set_static_ipv4(
                    client_handle,
                    ipv4_z.ptr,
                    if (mask_z) |m| m.ptr else null,
                    if (gw_z) |g| g.ptr else null,
                );
            }

            if (sip.ipv6_address) |ipv6| {
                const ipv6_z = try allocator.dupeZ(u8, ipv6);
                defer allocator.free(ipv6_z);

                const gw6_z = if (sip.ipv6_gateway) |g| try allocator.dupeZ(u8, g) else null;
                defer if (gw6_z) |g| allocator.free(g);

                _ = c.vpn_bridge_set_static_ipv6(
                    client_handle,
                    ipv6_z.ptr,
                    sip.ipv6_prefix_len orelse 64,
                    if (gw6_z) |g| g.ptr else null,
                );
            }

            if (sip.dns_servers) |dns_list| {
                // Allocate C string array
                var dns_ptrs = try allocator.alloc([*c]const u8, dns_list.len);
                defer allocator.free(dns_ptrs);

                var dns_z_list = try allocator.alloc([]const u8, dns_list.len);
                defer {
                    for (dns_z_list) |dns_z| {
                        allocator.free(dns_z);
                    }
                    allocator.free(dns_z_list);
                }

                for (dns_list, 0..) |dns, i| {
                    dns_z_list[i] = try allocator.dupeZ(u8, dns);
                    dns_ptrs[i] = @ptrCast(dns_z_list[i].ptr);
                }

                _ = c.vpn_bridge_set_dns_servers(
                    client_handle,
                    @ptrCast(dns_ptrs.ptr),
                    @intCast(dns_list.len),
                );
            }
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

    // ============================================
    // Reconnection Management
    // ============================================

    /// Enable automatic reconnection with specified parameters.
    pub fn enableReconnect(
        self: *VpnClient,
        max_attempts: u32,
        min_backoff: u32,
        max_backoff: u32,
    ) !void {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        const result = c.vpn_bridge_enable_reconnect(
            handle,
            max_attempts,
            min_backoff,
            max_backoff,
        );

        if (result != 0) {
            return VpnError.ConnectionFailed;
        }
    }

    /// Disable automatic reconnection.
    pub fn disableReconnect(self: *VpnClient) !void {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        const result = c.vpn_bridge_disable_reconnect(handle);

        if (result != 0) {
            return VpnError.ConnectionFailed;
        }
    }

    /// Get current reconnection state and determine if reconnection should occur.
    pub fn getReconnectInfo(self: *const VpnClient) !ReconnectInfo {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        var enabled: u8 = 0;
        var attempt: u32 = 0;
        var max_attempts: u32 = 0;
        var current_backoff: u32 = 0;
        var next_retry_time: u64 = 0;
        var consecutive_failures: u32 = 0;
        var last_disconnect_time: u64 = 0;

        const result = c.vpn_bridge_get_reconnect_info(
            handle,
            &enabled,
            &attempt,
            &max_attempts,
            &current_backoff,
            &next_retry_time,
            &consecutive_failures,
            &last_disconnect_time,
        );

        if (result < 0) {
            return VpnError.ConnectionFailed;
        }

        return ReconnectInfo{
            .enabled = enabled != 0,
            .should_reconnect = result == 1,
            .attempt = attempt,
            .max_attempts = max_attempts,
            .current_backoff = current_backoff,
            .next_retry_time = next_retry_time,
            .consecutive_failures = consecutive_failures,
            .last_disconnect_time = last_disconnect_time,
        };
    }

    /// Mark current disconnect as user-requested (prevents reconnection).
    pub fn markUserDisconnect(self: *VpnClient) !void {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        const result = c.vpn_bridge_mark_user_disconnect(handle);

        if (result != 0) {
            return VpnError.ConnectionFailed;
        }
    }
};
