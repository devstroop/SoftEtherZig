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
        std.debug.print("[Zig] VpnClient.init() called\n", .{});

        // Initialize the bridge library (once per program)
        // Note: bool in C is typedef'd as unsigned int in SoftEther
        std.debug.print("[Zig] Calling vpn_bridge_init()...\n", .{});
        const init_result = c.vpn_bridge_init(0); // 0 = false
        std.debug.print("[Zig] vpn_bridge_init() returned: {}\n", .{init_result});

        if (init_result != c_mod.VPN_BRIDGE_SUCCESS) {
            return VpnError.InitializationFailed;
        }

        // Create client instance
        std.debug.print("[Zig] Calling vpn_bridge_create_client()...\n", .{});
        const client_handle = c.vpn_bridge_create_client() orelse {
            std.debug.print("[Zig] vpn_bridge_create_client() returned NULL!\n", .{});
            return VpnError.ClientCreationFailed;
        };
        std.debug.print("[Zig] vpn_bridge_create_client() returned: {*}\n", .{client_handle});

        // Configure the client
        std.debug.print("[Zig] Preparing configuration strings...\n", .{});
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

        const user_z = try allocator.dupeZ(u8, username);
        defer allocator.free(user_z);

        const pass_z = try allocator.dupeZ(u8, password);
        defer allocator.free(pass_z);

        std.debug.print("[Zig] Calling vpn_bridge_configure()...\n", .{});
        const config_result = c.vpn_bridge_configure(
            client_handle,
            host_z.ptr,
            cfg.server_port,
            hub_z.ptr,
            user_z.ptr,
            pass_z.ptr,
        );
        std.debug.print("[Zig] vpn_bridge_configure() returned: {}\n", .{config_result});

        if (config_result != c_mod.VPN_BRIDGE_SUCCESS) {
            c.vpn_bridge_free_client(client_handle);
            return VpnError.ConfigurationError;
        }

        std.debug.print("[Zig] Creating VpnClient struct...\n", .{});
        const client = VpnClient{
            .handle = client_handle,
            .allocator = allocator,
            .config = cfg,
        };
        std.debug.print("[Zig] VpnClient.init() complete!\n", .{});
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
};
