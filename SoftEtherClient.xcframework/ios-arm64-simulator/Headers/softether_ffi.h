#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct softether_client_t softether_client_t;

// Create a client from JSON config (same fields as config)
// Returns NULL on error.
softether_client_t* softether_client_create(const char* json_config);

// Connect/Disconnect; return 0 on success, negative on error.
int softether_client_connect(softether_client_t* handle);
int softether_client_disconnect(softether_client_t* handle);

// Free the handle when done
void softether_client_free(softether_client_t* handle);

// Frame I/O
// Register an RX callback to receive frames from the tunnel (called from an internal thread).
// The callback must be thread-safe and return quickly.
typedef void (*softether_rx_cb_t)(const uint8_t* data, uint32_t len, void* user);
int softether_client_set_rx_callback(softether_client_t* handle, softether_rx_cb_t cb, void* user);

// Send a single L2 frame into the tunnel. Returns 1 on queued, 0 if no link available, negative on error.
int softether_client_send_frame(softether_client_t* handle, const uint8_t* data, uint32_t len);

// IP-mode I/O (for NEPacketTunnelFlow on iOS):
// Register an RX callback to receive IPv4 packets (EtherType 0x0800 stripped). Non-IPv4 frames are dropped.
typedef void (*softether_ip_rx_cb_t)(const uint8_t* ip_packet, uint32_t len, void* user);
int softether_client_set_ip_rx_callback(softether_client_t* handle, softether_ip_rx_cb_t cb, void* user);

// Send a single IPv4 packet. Returns 1 on queued, 0 if no link available, or a negative error.
int softether_client_send_ip_packet(softether_client_t* handle, const uint8_t* data, uint32_t len);

// Networking helpers
// Add a static ARP entry mapping an IPv4 next-hop to a MAC address. Returns 0 on success.
int softether_client_arp_add(softether_client_t* handle, uint32_t ipv4_be, const uint8_t mac[6]);

// State callbacks
// Called on state changes: 0=Idle,1=Connecting,2=Established,3=Disconnecting
typedef void (*softether_state_cb_t)(int state, void* user);
int softether_client_set_state_callback(softether_client_t* handle, softether_state_cb_t cb, void* user);

// Event callback: level=0 info, 1 warn, 2 error; code is implementation-defined.
typedef void (*softether_event_cb_t)(int level, int code, const char* message, void* user);
int softether_client_set_event_callback(softether_client_t* handle, softether_event_cb_t cb, void* user);

// Utility helpers
// Validate a Base64 string and decode into a provided buffer; returns number of bytes or negative on error.
int softether_b64_decode(const char* b64, unsigned char* out_buf, unsigned int out_cap);

// Diagnostics helpers
char* softether_client_version(void);
void softether_string_free(char*);

// Retrieve and clear the last error message, or NULL if none. Must be freed with softether_string_free.
char* softether_client_last_error(softether_client_t* handle);

// Query current tunnel network settings (JSON: {assigned_ipv4, subnet_mask, gateway, dns_servers[]}).
// The returned string must be freed with softether_string_free.
char* softether_client_get_network_settings_json(softether_client_t* handle);

// Get the locally-administered source MAC used by this client. Writes 6 bytes to out_mac. Returns 0 on success.
int softether_client_get_mac(softether_client_t* handle, uint8_t out_mac[6]);

// Logging system (Phase 2: Log level control)
typedef enum {
    LOG_LEVEL_SILENT = 0,
    LOG_LEVEL_ERROR = 1,
    LOG_LEVEL_WARN = 2,
    LOG_LEVEL_INFO = 3,
    LOG_LEVEL_DEBUG = 4,
    LOG_LEVEL_TRACE = 5
} LogLevel;

void set_log_level(LogLevel level);
const char* get_log_level_name(LogLevel level);
LogLevel parse_log_level(const char* str);

// ============================================================================
// WorxVPN Integration Extensions
// ============================================================================

// Connection state codes (for state callback)
#define SOFTETHER_STATE_IDLE          0
#define SOFTETHER_STATE_CONNECTING    1
#define SOFTETHER_STATE_ESTABLISHED   2
#define SOFTETHER_STATE_DISCONNECTING 3
#define SOFTETHER_STATE_ERROR         4

// Event level codes (for event callback)
#define SOFTETHER_EVENT_INFO    0
#define SOFTETHER_EVENT_WARNING 1
#define SOFTETHER_EVENT_ERROR   2

// Common error codes (for event callback 'code' parameter)
#define SOFTETHER_ERROR_NONE              0
#define SOFTETHER_ERROR_DNS_FAILED        100
#define SOFTETHER_ERROR_CONNECTION_FAILED 101
#define SOFTETHER_ERROR_TIMEOUT           102
#define SOFTETHER_ERROR_AUTH_FAILED       401
#define SOFTETHER_ERROR_NETWORK_DOWN      503
#define SOFTETHER_ERROR_SERVER_UNREACHABLE 504
#define SOFTETHER_ERROR_PROTOCOL          505

// Connection statistics structure
typedef struct {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t connected_seconds;
    uint32_t current_rtt_ms;  // Round-trip time in milliseconds
} softether_connection_stats_t;

// Get connection statistics. Returns 0 on success, negative on error.
int softether_client_get_stats(softether_client_t* handle, softether_connection_stats_t* stats);

// Get current connection state (returns SOFTETHER_STATE_* constant)
int softether_client_get_state(softether_client_t* handle);

// Check if client is currently connected (convenience function)
int softether_client_is_connected(softether_client_t* handle);

// Reconnection control
// Enable/disable automatic reconnection. Returns 0 on success.
int softether_client_set_reconnect_enabled(softether_client_t* handle, int enabled);

// Set reconnection parameters. Returns 0 on success.
// max_attempts: 0 = infinite, >0 = limited attempts
// initial_delay_sec: Initial backoff delay in seconds
// max_delay_sec: Maximum backoff delay in seconds
int softether_client_set_reconnect_params(
    softether_client_t* handle,
    uint32_t max_attempts,
    uint32_t initial_delay_sec,
    uint32_t max_delay_sec
);

// Get reconnection status as JSON. Returns NULL if not in reconnection state.
// Format: {"enabled": true, "attempt": 3, "max_attempts": 10, "next_retry_sec": 30}
// Must be freed with softether_string_free.
char* softether_client_get_reconnect_status_json(softether_client_t* handle);

// Log management
// Register a callback to receive all log messages
// The callback receives: timestamp, level, source, message
typedef void (*softether_log_cb_t)(
    uint64_t timestamp_ms,
    int level,
    const char* source,
    const char* message,
    void* user
);
int softether_client_set_log_callback(softether_client_t* handle, softether_log_cb_t cb, void* user);

// Get recent logs as JSON array (last N entries). Must be freed with softether_string_free.
// Format: [{"timestamp": 1234567890, "level": 2, "source": "vpn", "message": "..."}]
char* softether_client_get_recent_logs_json(softether_client_t* handle, uint32_t max_entries);

// Clear all stored logs
void softether_client_clear_logs(softether_client_t* handle);

// Server information
// Get server information as JSON. Must be freed with softether_string_free.
// Format: {"server_name": "vpn.example.com", "server_product": "SoftEther VPN", "version": "4.39"}
char* softether_client_get_server_info_json(softether_client_t* handle);

// Configuration management
// Update client configuration (partial update). Returns 0 on success.
// Only applies to disconnected client. JSON can contain subset of config fields.
int softether_client_update_config(softether_client_t* handle, const char* json_config);

// Get current configuration as JSON. Must be freed with softether_string_free.
char* softether_client_get_config_json(softether_client_t* handle);

// Network diagnostics
// Perform basic connectivity test. Returns 0=success, 1=network down, 2=server unreachable, <0=error
int softether_client_test_connectivity(const char* server_name, uint16_t server_port, uint32_t timeout_ms);

// DNS resolution helper (for WorxVPN's cluster discovery)
// Resolve hostname and return JSON array of IP addresses. Must be freed with softether_string_free.
// Format: {"addresses": ["77.48.2.8", "2a01:5e06:100::1"], "cname": "cluster1.vpn.cloud"}
char* softether_dns_resolve(const char* hostname, const char* dns_server);

// Utility: Parse error code to human-readable message
const char* softether_error_message(int error_code);

// Platform integration helpers (iOS PacketTunnelProvider)
// Create client optimized for iOS Packet Tunnel Provider
// This variant uses IP-mode by default and optimizes for NEPacketTunnelFlow
softether_client_t* softether_client_create_for_ios(const char* json_config);

// Android VpnService integration
// File descriptor for VPN tunnel device (Android VpnService.Builder.establish())
int softether_client_get_tun_fd(softether_client_t* handle);
int softether_client_set_tun_fd(softether_client_t* handle, int fd);

// Memory and resource management
// Get memory usage statistics in bytes
uint64_t softether_client_get_memory_usage(softether_client_t* handle);

// Force cleanup of idle resources (call periodically in long-running apps)
void softether_client_cleanup_idle_resources(softether_client_t* handle);

#ifdef __cplusplus
}
#endif
