// SoftEther Zig FFI Header
// C-compatible interface for the Zig VPN client
// Build: zig build -Dtarget=aarch64-ios -Doptimize=ReleaseFast

#ifndef SOFTETHER_ZIG_H
#define SOFTETHER_ZIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Types
// ============================================================================

/// Opaque handle to the VPN client
typedef struct ZigVpnClient* ZigVpnClientHandle;

/// Connection state
typedef enum {
    ZIG_STATE_DISCONNECTED = 0,
    ZIG_STATE_CONNECTING = 1,
    ZIG_STATE_HANDSHAKING = 2,
    ZIG_STATE_AUTHENTICATING = 3,
    ZIG_STATE_ESTABLISHING = 4,
    ZIG_STATE_CONNECTED = 5,
    ZIG_STATE_DISCONNECTING = 6,
    ZIG_STATE_ERROR = 7
} ZigConnectionState;

/// Log level
typedef enum {
    ZIG_LOG_ERROR = 0,
    ZIG_LOG_WARN = 1,
    ZIG_LOG_INFO = 2,
    ZIG_LOG_DEBUG = 3,
    ZIG_LOG_TRACE = 4
} ZigLogLevel;

/// Session info returned after connection
typedef struct {
    uint32_t assigned_ip;      // Network byte order
    uint32_t subnet_mask;      // Network byte order  
    uint32_t gateway_ip;       // Network byte order
    uint8_t mac_address[6];
    uint8_t gateway_mac[6];
    uint32_t dns_servers[4];   // Up to 4 DNS servers
    uint8_t dns_count;
    char connected_server_ip[64];
} ZigSessionInfo;

/// Configuration for VPN connection
typedef struct {
    const char* server;
    uint16_t port;
    const char* hub;
    const char* username;
    const char* password_hash;  // SHA0 hash, base64 encoded
    
    bool use_encryption;
    bool use_compression;
    bool udp_acceleration;
    bool verify_certificate;
    
    uint8_t max_connections;
    uint32_t timeout_ms;
    uint16_t mtu;
    
    bool default_route;
} ZigVpnConfig;

// ============================================================================
// Callbacks
// ============================================================================

/// Called when connection state changes
typedef void (*ZigStateCallback)(void* user_data, ZigConnectionState state);

/// Called when connected with session info
typedef void (*ZigConnectedCallback)(void* user_data, const ZigSessionInfo* session);

/// Called when disconnected
typedef void (*ZigDisconnectedCallback)(void* user_data, const char* error_message);

/// Called when packets are received from VPN (Ethernet frames)
typedef void (*ZigPacketsCallback)(void* user_data, const uint8_t** packets, const size_t* lengths, size_t count);

/// Called for log messages
typedef void (*ZigLogCallback)(void* user_data, ZigLogLevel level, const char* message);

/// Called when server IP should be excluded from VPN routing
typedef bool (*ZigExcludeIpCallback)(void* user_data, const char* ip);

/// Callback structure
typedef struct {
    void* user_data;
    ZigStateCallback on_state_changed;
    ZigConnectedCallback on_connected;
    ZigDisconnectedCallback on_disconnected;
    ZigPacketsCallback on_packets_received;
    ZigLogCallback on_log;
    ZigExcludeIpCallback on_exclude_ip;
} ZigCallbacks;

// ============================================================================
// Client Lifecycle
// ============================================================================

/// Create a new VPN client instance
/// Returns NULL on failure
ZigVpnClientHandle zig_vpn_create(void);

/// Destroy a VPN client instance
void zig_vpn_destroy(ZigVpnClientHandle handle);

/// Set callbacks for the client
void zig_vpn_set_callbacks(ZigVpnClientHandle handle, const ZigCallbacks* callbacks);

// ============================================================================
// Connection
// ============================================================================

/// Connect to VPN server
/// Returns 0 on success, negative error code on failure
int32_t zig_vpn_connect(ZigVpnClientHandle handle, const ZigVpnConfig* config);

/// Disconnect from VPN server
void zig_vpn_disconnect(ZigVpnClientHandle handle);

/// Get current connection state
ZigConnectionState zig_vpn_get_state(ZigVpnClientHandle handle);

/// Check if connected
bool zig_vpn_is_connected(ZigVpnClientHandle handle);

// ============================================================================
// Data Transfer
// ============================================================================

/// Send packets to VPN server (Ethernet frames)
/// Returns number of packets sent, negative on error
int32_t zig_vpn_send_packets(ZigVpnClientHandle handle, 
                              const uint8_t** packets, 
                              const size_t* lengths, 
                              size_t count);

/// Send a single packet
int32_t zig_vpn_send_packet(ZigVpnClientHandle handle,
                             const uint8_t* packet,
                             size_t length);

// ============================================================================
// Statistics
// ============================================================================

/// Get bytes sent since connection
uint64_t zig_vpn_get_bytes_sent(ZigVpnClientHandle handle);

/// Get bytes received since connection
uint64_t zig_vpn_get_bytes_received(ZigVpnClientHandle handle);

/// Get packets sent since connection
uint64_t zig_vpn_get_packets_sent(ZigVpnClientHandle handle);

/// Get packets received since connection
uint64_t zig_vpn_get_packets_received(ZigVpnClientHandle handle);

// ============================================================================
// Version
// ============================================================================

/// Get library version string
const char* zig_vpn_version(void);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_ZIG_H
