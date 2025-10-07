/*
 * SoftEther VPN - Zig Bridge Layer
 * 
 * This is a simplified C interface layer that bridges between
 * Zig and the complex SoftEther VPN C codebase.
 * 
 * Purpose: Provide a clean, minimal API that hides the complexity
 * of SoftEther's internal structures and functions.
 */

#ifndef SOFTETHER_BRIDGE_H
#define SOFTETHER_BRIDGE_H

#include <stdint.h>

// Forward declarations to avoid header conflicts
// We use uint32_t instead of BOOL to avoid bool/BOOL conflicts

#include <stdint.h>
#include <stddef.h>

/* bool is defined by Mayaqua/MayaType.h */

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================
 * Error Codes
 * ============================================ */
#define VPN_BRIDGE_SUCCESS              0
#define VPN_BRIDGE_ERROR_INIT_FAILED    (-1)
#define VPN_BRIDGE_ERROR_INVALID_PARAM  (-2)
#define VPN_BRIDGE_ERROR_ALLOC_FAILED   (-3)
#define VPN_BRIDGE_ERROR_CONNECT_FAILED (-4)
#define VPN_BRIDGE_ERROR_AUTH_FAILED    (-5)
#define VPN_BRIDGE_ERROR_NOT_CONNECTED  (-6)
#define VPN_BRIDGE_ERROR_ALREADY_INIT   (-7)
#define VPN_BRIDGE_ERROR_NOT_INIT       (-8)
#define VPN_BRIDGE_ERROR_INVALID_STATE  (-9)

// IP version modes
#define VPN_IP_VERSION_AUTO  0
#define VPN_IP_VERSION_IPV4  1
#define VPN_IP_VERSION_IPV6  2
#define VPN_IP_VERSION_DUAL  3

/* ============================================
 * Connection Status
 * ============================================ */
typedef enum {
    VPN_STATUS_DISCONNECTED = 0,
    VPN_STATUS_CONNECTING   = 1,
    VPN_STATUS_CONNECTED    = 2,
    VPN_STATUS_ERROR        = 3
} VpnBridgeStatus;

/* ============================================
 * Opaque Types
 * ============================================ */

// Opaque handle to the VPN client (hides SoftEther's CLIENT structure)
typedef struct VpnBridgeClient VpnBridgeClient;

/* ============================================
 * Library Initialization
 * ============================================ */

/**
 * Initialize the SoftEther library.
 * Must be called once before any other functions.
 * 
 * @param debug Enable debug logging (0 = FALSE, 1 = TRUE)
 * @return VPN_BRIDGE_SUCCESS on success, error code otherwise
 */
int vpn_bridge_init(uint32_t debug);

/**
 * Cleanup and free all SoftEther library resources.
 * Should be called once at program exit.
 */
void vpn_bridge_cleanup(void);

/**
 * Check if the library is initialized.
 * @return 1 if initialized, 0 otherwise
 */
uint32_t vpn_bridge_is_initialized(void);

/* ============================================
 * Client Management
 * ============================================ */

/**
 * Create a new VPN client instance.
 * 
 * @return VpnBridgeClient handle on success, NULL on failure
 */
VpnBridgeClient* vpn_bridge_create_client(void);

/**
 * Free a VPN client instance and release all resources.
 * 
 * @param client Client handle to free
 */
void vpn_bridge_free_client(VpnBridgeClient* client);

/* ============================================
 * Connection Configuration
 * ============================================ */

/**
 * Configure connection parameters.
 * Must be called before vpn_bridge_connect().
 * 
 * @param client     Client handle
 * @param hostname   VPN server hostname or IP
 * @param port       VPN server port (usually 443 or 992)
 * @param hub_name   Virtual HUB name
 * @param username   Username for authentication
 * @param password   Password for authentication
 * @return VPN_BRIDGE_SUCCESS on success, error code otherwise
 */
int vpn_bridge_configure(
    VpnBridgeClient* client,
    const char* hostname,
    uint16_t port,
    const char* hub_name,
    const char* username,
    const char* password
);

/**
 * Configure connection parameters with pre-hashed password.
 * Must be called before vpn_bridge_connect().
 * 
 * NOTE: SoftEther uses SHA-0 (not SHA-1) for password hashing!
 * Hash format: SHA-0(password + UPPERCASE(username))
 * The hash should be base64-encoded when passed to this function.
 * 
 * @param client        Client handle
 * @param hostname      VPN server hostname or IP
 * @param port          VPN server port (usually 443 or 992)
 * @param hub_name      Virtual HUB name
 * @param username      Username for authentication
 * @param password_hash Pre-hashed password (base64-encoded SHA-0, 20 bytes)
 * @return VPN_BRIDGE_SUCCESS on success, error code otherwise
 */
int vpn_bridge_configure_with_hash(
    VpnBridgeClient* client,
    const char* hostname,
    uint16_t port,
    const char* hub_name,
    const char* username,
    const char* password_hash
);

/* ============================================
 * Connection Operations
 * ============================================ */

/**
 * Establish VPN connection.
 * This is a blocking call that may take several seconds.
 * 
 * @param client Client handle
 * @return VPN_BRIDGE_SUCCESS on success, error code otherwise
 */
int vpn_bridge_connect(VpnBridgeClient* client);

/**
 * Disconnect from VPN server.
 * 
 * @param client Client handle
 * @return VPN_BRIDGE_SUCCESS on success, error code otherwise
 */
int vpn_bridge_disconnect(VpnBridgeClient* client);

/**
 * Get current connection status.
 * 
 * @param client Client handle
 * @return Current status enum
 */
VpnBridgeStatus vpn_bridge_get_status(const VpnBridgeClient* client);

/* ============================================
 * Connection Information
 * ============================================ */

/**
 * DHCP information structure
 */
typedef struct {
    uint32_t client_ip;       // Assigned IP address (network byte order)
    uint32_t subnet_mask;     // Subnet mask (network byte order)
    uint32_t gateway;         // Default gateway (network byte order)
    uint32_t dns_server1;     // Primary DNS server (network byte order)
    uint32_t dns_server2;     // Secondary DNS server (network byte order)
    uint32_t dhcp_server;     // DHCP server address (network byte order)
    uint32_t lease_time;      // Lease time in seconds
    char domain_name[256];    // Domain name
    uint32_t valid;           // Whether DHCP info is valid (0 = FALSE, 1 = TRUE)
} VpnBridgeDhcpInfo;

/**
 * Get connection information.
 * All out-parameters can be NULL if not needed.
 * 
 * @param client          Client handle
 * @param bytes_sent      OUT: Total bytes sent (can be NULL)
 * @param bytes_received  OUT: Total bytes received (can be NULL)
 * @param connected_time  OUT: Connection duration in seconds (can be NULL)
 * @return VPN_BRIDGE_SUCCESS on success, error code otherwise
 */
int vpn_bridge_get_connection_info(
    const VpnBridgeClient* client,
    uint64_t* bytes_sent,
    uint64_t* bytes_received,
    uint64_t* connected_time
);

/**
 * Get DHCP information from the VPN session.
 * 
 * @param client    Client handle
 * @param dhcp_info OUT: DHCP information structure to fill
 * @return VPN_BRIDGE_SUCCESS on success, error code otherwise
 */
int vpn_bridge_get_dhcp_info(
    const VpnBridgeClient* client,
    VpnBridgeDhcpInfo* dhcp_info
);

/**
 * Get last error code from client.
 * 
 * @param client Client handle
 * @return Last error code
 */
uint32_t vpn_bridge_get_last_error(const VpnBridgeClient* client);

/**
 * Get error message for an error code.
 * 
 * @param error_code Error code
 * @return Human-readable error message (static string, do not free)
 */
const char* vpn_bridge_get_error_message(int error_code);

/* ============================================
 * Version Information
 * ============================================ */

/**
 * Get bridge layer version.
 * @return Version string (static, do not free)
 */
const char* vpn_bridge_version(void);

/**
 * Get SoftEther library version.
 * @return Version string (static, do not free)
 */
const char* vpn_bridge_softether_version(void);

/* ============================================
 * Utility Functions
 * ============================================ */

/**
 * Generate SoftEther password hash.
 * 
 * This computes: SHA-0(password + UPPERCASE(username))
 * The result is base64-encoded and suitable for use with
 * vpn_bridge_configure_with_hash().
 * 
 * NOTE: Uses SHA-0 (not SHA-1) for compatibility with SoftEther protocol.
 * 
 * @param username    Username (will be uppercased internally)
 * @param password    Plain text password
 * @param output      Buffer to receive base64-encoded hash (min 32 bytes)
 * @param output_size Size of output buffer
 * @return VPN_BRIDGE_SUCCESS on success, error code otherwise
 */
int vpn_bridge_generate_password_hash(
    const char* username,
    const char* password,
    char* output,
    size_t output_size
);

/* ============================================
 * Runtime Network Information
 * ============================================ */

/**
 * Get TUN device name (e.g., "utun6").
 * Returns dynamic information from active connection.
 * 
 * @param client      Client handle
 * @param output      Buffer to receive device name
 * @param output_size Size of output buffer (recommended: 64 bytes)
 * @return VPN_BRIDGE_SUCCESS on success, error code otherwise
 */
int vpn_bridge_get_device_name(
    const VpnBridgeClient* client,
    char* output,
    size_t output_size
);

/**
 * Get learned or configured IP address.
 * Returns the IP address learned from network traffic or configured via DHCP.
 * 
 * @param client    Client handle
 * @param ip        OUT: IP address (network byte order), 0 if not yet learned
 * @return VPN_BRIDGE_SUCCESS on success, error code otherwise
 */
int vpn_bridge_get_learned_ip(
    const VpnBridgeClient* client,
    uint32_t* ip
);

/**
 * Get learned gateway MAC address.
 * Returns the gateway MAC address learned from ARP replies.
 * 
 * @param client     Client handle
 * @param mac        OUT: 6-byte MAC address buffer
 * @param has_mac    OUT: 1 if MAC was learned, 0 if not yet available
 * @return VPN_BRIDGE_SUCCESS on success, error code otherwise
 */
int vpn_bridge_get_gateway_mac(
    const VpnBridgeClient* client,
    uint8_t* mac,
    uint32_t* has_mac
);

/* ============================================
 * IP Configuration
 * ============================================ */

/**
 * Set IP version mode (auto, IPv4, IPv6, or dual-stack).
 * Must be called before vpn_bridge_connect().
 * 
 * @param client      Client handle
 * @param ip_version  IP version mode (VPN_IP_VERSION_AUTO, IPV4, IPV6, or DUAL)
 * @return VPN_BRIDGE_SUCCESS on success, error code otherwise
 */
/**
 * Set IP version preference for the connection.
 * Must be called before vpn_bridge_connect().
 */
int vpn_bridge_set_ip_version(VpnBridgeClient* client, int ip_version);

/**
 * Set maximum number of concurrent TCP connections (1-32).
 * Multiple connections improve throughput by parallelizing data transfer.
 * Must be called before vpn_bridge_connect().
 * 
 * @param client VPN client handle
 * @param max_connection Number of connections (1-32, default: 1)
 * @return VPN_BRIDGE_SUCCESS on success, error code otherwise
 */
int vpn_bridge_set_max_connection(VpnBridgeClient* client, uint32_t max_connection);

/**
 * Configure static IPv4 address (skip DHCP).
 * Must be called before vpn_bridge_connect().
 * 
 * @param client   Client handle
 * @param ip       IPv4 address string (e.g., "10.0.0.2")
 * @param netmask  IPv4 netmask string (e.g., "255.255.255.0"), can be NULL
 * @param gateway  IPv4 gateway string (e.g., "10.0.0.1"), can be NULL
 * @return VPN_BRIDGE_SUCCESS on success, error code otherwise
 */
int vpn_bridge_set_static_ipv4(VpnBridgeClient* client, const char* ip, const char* netmask, const char* gateway);

/**
 * Configure static IPv6 address (skip DHCPv6).
 * Must be called before vpn_bridge_connect().
 * 
 * @param client      Client handle
 * @param ip          IPv6 address string (e.g., "2001:db8::1")
 * @param prefix_len  IPv6 prefix length (e.g., 64)
 * @param gateway     IPv6 gateway string (e.g., "fe80::1"), can be NULL
 * @return VPN_BRIDGE_SUCCESS on success, error code otherwise
 */
int vpn_bridge_set_static_ipv6(VpnBridgeClient* client, const char* ip, uint8_t prefix_len, const char* gateway);

/**
 * Configure DNS servers (override DHCP).
 * Must be called before vpn_bridge_connect().
 * 
 * @param client       Client handle
 * @param dns_servers  Array of DNS server IP address strings
 * @param count        Number of DNS servers (max 8)
 * @return VPN_BRIDGE_SUCCESS on success, error code otherwise
 */
int vpn_bridge_set_dns_servers(VpnBridgeClient* client, const char** dns_servers, int count);

/**
 * Set the packet adapter type for the VPN client (must be called before connecting).
 * 
 * @param client         The VPN client
 * @param use_zig_adapter 1 to use Zig adapter (experimental), 0 to use C adapter (default)
 * @return VPN_BRIDGE_SUCCESS on success, error code on failure
 */
int vpn_bridge_set_use_zig_adapter(VpnBridgeClient* client, int use_zig_adapter);

/* ============================================
 * Reconnection Management
 * ============================================ */

/**
 * Enable automatic reconnection for a VPN client.
 * 
 * @param client       The VPN client
 * @param max_attempts Maximum reconnection attempts (0 = infinite)
 * @param min_backoff  Minimum backoff delay in seconds (default: 5)
 * @param max_backoff  Maximum backoff delay in seconds (default: 300)
 * @return 0 on success, -1 on error
 */
int vpn_bridge_enable_reconnect(
    VpnBridgeClient* client,
    uint32_t max_attempts,
    uint32_t min_backoff,
    uint32_t max_backoff
);

/**
 * Disable automatic reconnection for a VPN client.
 * 
 * @param client The VPN client
 * @return 0 on success, -1 on error
 */
int vpn_bridge_disable_reconnect(VpnBridgeClient* client);

/**
 * Get reconnection state and configuration.
 * 
 * @param client                The VPN client
 * @param enabled               Output: 1 if reconnect enabled, 0 if disabled
 * @param attempt               Output: Current attempt number
 * @param max_attempts          Output: Max attempts (0=infinite)
 * @param current_backoff       Output: Current backoff delay in seconds
 * @param next_retry_time       Output: When next retry should occur (ms since epoch)
 * @param consecutive_failures  Output: Count of consecutive failures
 * @param last_disconnect_time  Output: When connection was lost (ms since epoch)
 * @return 1 if should reconnect, 0 if should not reconnect, -1 on error
 */
int vpn_bridge_get_reconnect_info(
    const VpnBridgeClient* client,
    uint8_t* enabled,
    uint32_t* attempt,
    uint32_t* max_attempts,
    uint32_t* current_backoff,
    uint64_t* next_retry_time,
    uint32_t* consecutive_failures,
    uint64_t* last_disconnect_time
);

/**
 * Mark a disconnect as user-requested (e.g., Ctrl+C).
 * This prevents automatic reconnection.
 * 
 * @param client The VPN client
 * @return 0 on success, -1 on error
 */
int vpn_bridge_mark_user_disconnect(VpnBridgeClient* client);

/**
 * Calculate next backoff delay using exponential backoff algorithm.
 * Formula: delay = min(min_backoff * (2 ^ attempt), max_backoff)
 * 
 * @param client The VPN client
 * @return Calculated backoff delay in seconds
 */
uint32_t vpn_bridge_calculate_backoff(const VpnBridgeClient* client);

/**
 * Reset reconnection state after successful connection.
 * 
 * @param client The VPN client
 * @return 0 on success, -1 on error
 */
int vpn_bridge_reset_reconnect_state(VpnBridgeClient* client);

#ifdef __cplusplus
}
#endif

#endif /* SOFTETHER_BRIDGE_H */
