// SoftEther C Backend - iOS FFI Header
// Wraps the original SoftEtherVPN C library for iOS integration
// Build: clang -c -target arm64-apple-ios -isysroot $(xcrun --sdk iphoneos --show-sdk-path)

#ifndef SOFTETHER_C_H
#define SOFTETHER_C_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// ============================================================================
// Types
// ============================================================================

/// Opaque handle to the VPN client
typedef struct SoftEtherClient* SoftEtherClientHandle;

/// Connection state
typedef enum {
    SE_STATE_DISCONNECTED = 0,
    SE_STATE_CONNECTING = 1,
    SE_STATE_HANDSHAKING = 2,
    SE_STATE_AUTHENTICATING = 3,
    SE_STATE_ESTABLISHING = 4,
    SE_STATE_CONNECTED = 5,
    SE_STATE_DISCONNECTING = 6,
    SE_STATE_ERROR = 7
} SoftEtherConnectionState;

/// Log level
typedef enum {
    SE_LOG_ERROR = 0,
    SE_LOG_WARN = 1,
    SE_LOG_INFO = 2,
    SE_LOG_DEBUG = 3,
    SE_LOG_TRACE = 4
} SoftEtherLogLevel;

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
    uint16_t mtu;
} SoftEtherSessionInfo;

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
} SoftEtherConfig;

// ============================================================================
// Callbacks
// ============================================================================

/// Called when connection state changes
typedef void (*SoftEtherStateCallback)(void* user_data, SoftEtherConnectionState state);

/// Called when connected with session info
typedef void (*SoftEtherConnectedCallback)(void* user_data, const SoftEtherSessionInfo* session);

/// Called when disconnected
typedef void (*SoftEtherDisconnectedCallback)(void* user_data, const char* error_message);

/// Called when packets are received from VPN (Ethernet frames)
typedef void (*SoftEtherPacketsCallback)(void* user_data, const uint8_t** packets, const size_t* lengths, size_t count);

/// Called for log messages
typedef void (*SoftEtherLogCallback)(void* user_data, SoftEtherLogLevel level, const char* message);

/// Called when server IP should be excluded from VPN routing
typedef bool (*SoftEtherExcludeIpCallback)(void* user_data, const char* ip);

/// Callback structure
typedef struct {
    void* user_data;
    SoftEtherStateCallback on_state_changed;
    SoftEtherConnectedCallback on_connected;
    SoftEtherDisconnectedCallback on_disconnected;
    SoftEtherPacketsCallback on_packets_received;
    SoftEtherLogCallback on_log;
    SoftEtherExcludeIpCallback on_exclude_ip;
} SoftEtherCallbacks;

// ============================================================================
// Client Lifecycle
// ============================================================================

/// Create a new VPN client instance
/// Returns NULL on failure
SoftEtherClientHandle softether_create(void);

/// Destroy a VPN client instance
void softether_destroy(SoftEtherClientHandle handle);

/// Set callbacks for the client
void softether_set_callbacks(SoftEtherClientHandle handle, const SoftEtherCallbacks* callbacks);

// ============================================================================
// Connection
// ============================================================================

/// Connect to VPN server
/// Returns 0 on success, negative error code on failure
int32_t softether_connect(SoftEtherClientHandle handle, const SoftEtherConfig* config);

/// Disconnect from VPN server
void softether_disconnect(SoftEtherClientHandle handle);

/// Get current connection state
SoftEtherConnectionState softether_get_state(SoftEtherClientHandle handle);

/// Check if connected
bool softether_is_connected(SoftEtherClientHandle handle);

// ============================================================================
// Data Transfer
// ============================================================================

/// Send packets to VPN server (Ethernet frames)
/// Returns number of packets sent, negative on error
int32_t softether_send_packets(SoftEtherClientHandle handle, 
                               const uint8_t** packets, 
                               const size_t* lengths, 
                               size_t count);

/// Send a single packet
int32_t softether_send_packet(SoftEtherClientHandle handle,
                              const uint8_t* packet,
                              size_t length);

// ============================================================================
// Statistics
// ============================================================================

/// Get bytes sent since connection
uint64_t softether_get_bytes_sent(SoftEtherClientHandle handle);

/// Get bytes received since connection
uint64_t softether_get_bytes_received(SoftEtherClientHandle handle);

/// Get packets sent since connection
uint64_t softether_get_packets_sent(SoftEtherClientHandle handle);

/// Get packets received since connection
uint64_t softether_get_packets_received(SoftEtherClientHandle handle);

// ============================================================================
// Version
// ============================================================================

/// Get library version string
const char* softether_version(void);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_C_H
