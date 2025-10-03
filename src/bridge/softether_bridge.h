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
#define VPN_BRIDGE_ERROR_INIT_FAILED    1
#define VPN_BRIDGE_ERROR_INVALID_PARAM  2
#define VPN_BRIDGE_ERROR_ALLOC_FAILED   3
#define VPN_BRIDGE_ERROR_CONNECT_FAILED 4
#define VPN_BRIDGE_ERROR_AUTH_FAILED    5
#define VPN_BRIDGE_ERROR_NOT_CONNECTED  6
#define VPN_BRIDGE_ERROR_ALREADY_INIT   7
#define VPN_BRIDGE_ERROR_NOT_INIT       8

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

#ifdef __cplusplus
}
#endif

#endif /* SOFTETHER_BRIDGE_H */
