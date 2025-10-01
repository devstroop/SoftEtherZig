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

/* SoftEther defines bool as unsigned int, not C99 _Bool */
/* We need to match that definition for ABI compatibility */
#ifndef bool
typedef unsigned int bool;
#define true 1
#define false 0
#endif

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
 * @param debug Enable debug logging
 * @return VPN_BRIDGE_SUCCESS on success, error code otherwise
 */
int vpn_bridge_init(bool debug);

/**
 * Cleanup and free all SoftEther library resources.
 * Should be called once at program exit.
 */
void vpn_bridge_cleanup(void);

/**
 * Check if the library is initialized.
 * @return true if initialized, false otherwise
 */
bool vpn_bridge_is_initialized(void);

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

#ifdef __cplusplus
}
#endif

#endif /* SOFTETHER_BRIDGE_H */
