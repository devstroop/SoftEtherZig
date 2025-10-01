// SoftEther VPN Client Library - C FFI Interface
// Shared library interface for use from other programming languages

const std = @import("std");
const softether = @import("softether");

// Export C-compatible types and functions
export fn softether_vpn_init() callconv(.C) c_int {
    // Initialize library
    return 0;
}

export fn softether_vpn_cleanup() callconv(.C) void {
    // Cleanup library resources
}

// Opaque handle for VPN client
pub const VpnClientHandle = ?*anyopaque;

// Connection parameters structure (C-compatible)
pub const VpnConnectionParams = extern struct {
    server_name: [*:0]const u8,
    server_port: u16,
    hub_name: [*:0]const u8,
    account_name: [*:0]const u8,
    username: [*:0]const u8,
    password: [*:0]const u8,
    use_encrypt: bool,
    use_compress: bool,
};

// Connection status enum (C-compatible)
pub const VpnStatus = enum(c_int) {
    disconnected = 0,
    connecting = 1,
    connected = 2,
    error_state = 3,
};

// Connection info structure (C-compatible)
pub const VpnConnectionInfo = extern struct {
    bytes_sent: u64,
    bytes_received: u64,
    connected_seconds: u64,
};

// Create VPN client instance
export fn softether_vpn_client_create(params: *const VpnConnectionParams) callconv(.C) VpnClientHandle {
    _ = params;
    // TODO: Implement client creation
    return null;
}

// Free VPN client instance
export fn softether_vpn_client_free(handle: VpnClientHandle) callconv(.C) void {
    _ = handle;
    // TODO: Implement client cleanup
}

// Connect to VPN server
export fn softether_vpn_connect(handle: VpnClientHandle) callconv(.C) c_int {
    _ = handle;
    // TODO: Implement connection
    return -1;
}

// Disconnect from VPN server
export fn softether_vpn_disconnect(handle: VpnClientHandle) callconv(.C) c_int {
    _ = handle;
    // TODO: Implement disconnection
    return -1;
}

// Get connection status
export fn softether_vpn_get_status(handle: VpnClientHandle) callconv(.C) VpnStatus {
    _ = handle;
    return .disconnected;
}

// Get connection information
export fn softether_vpn_get_info(handle: VpnClientHandle, info: *VpnConnectionInfo) callconv(.C) c_int {
    _ = handle;
    _ = info;
    return -1;
}

// Check if connected
export fn softether_vpn_is_connected(handle: VpnClientHandle) callconv(.C) bool {
    _ = handle;
    return false;
}

// Get last error message
export fn softether_vpn_get_error(handle: VpnClientHandle) callconv(.C) [*:0]const u8 {
    _ = handle;
    return "Not implemented";
}
