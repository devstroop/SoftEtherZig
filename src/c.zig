// This file imports all C headers for SoftEther VPN
// Using a simplified bridge layer instead of importing all headers

pub const c = @cImport({
    // Import the bridge layer - a clean, minimal C API
    // Note: The include path is relative to the -I flag in build.zig
    @cInclude("bridge/softether_bridge.h");
});

// Re-export common types for convenience
pub const VpnBridgeClient = c.VpnBridgeClient;
pub const VpnBridgeStatus = c.VpnBridgeStatus;

// Status constants
pub const VPN_STATUS_DISCONNECTED = c.VPN_STATUS_DISCONNECTED;
pub const VPN_STATUS_CONNECTING = c.VPN_STATUS_CONNECTING;
pub const VPN_STATUS_CONNECTED = c.VPN_STATUS_CONNECTED;
pub const VPN_STATUS_ERROR = c.VPN_STATUS_ERROR;

// Error constants
pub const VPN_BRIDGE_SUCCESS = c.VPN_BRIDGE_SUCCESS;
pub const VPN_BRIDGE_ERROR_INIT_FAILED = c.VPN_BRIDGE_ERROR_INIT_FAILED;
pub const VPN_BRIDGE_ERROR_INVALID_PARAM = c.VPN_BRIDGE_ERROR_INVALID_PARAM;
pub const VPN_BRIDGE_ERROR_ALLOC_FAILED = c.VPN_BRIDGE_ERROR_ALLOC_FAILED;
pub const VPN_BRIDGE_ERROR_CONNECT_FAILED = c.VPN_BRIDGE_ERROR_CONNECT_FAILED;
pub const VPN_BRIDGE_ERROR_AUTH_FAILED = c.VPN_BRIDGE_ERROR_AUTH_FAILED;
pub const VPN_BRIDGE_ERROR_NOT_CONNECTED = c.VPN_BRIDGE_ERROR_NOT_CONNECTED;
pub const VPN_BRIDGE_ERROR_ALREADY_INIT = c.VPN_BRIDGE_ERROR_ALREADY_INIT;
pub const VPN_BRIDGE_ERROR_NOT_INIT = c.VPN_BRIDGE_ERROR_NOT_INIT;

// Note: In Zig 0.15+, we can't use `pub usingnamespace`
// Access C symbols via: const c = @import("c.zig").c;
