/**
 * SoftEther VPN Client — C API Header
 *
 * Generated from libsoftether/src/ffi.zig exports.
 * Build: cd libsoftether && zig build shared-lib
 *
 * Usage:
 *   #include "softether.h"
 *   void* client = softether_create("vpn.example.com", 443, "DEFAULT", "user", "pass");
 *   int err = softether_connect(client);
 *   softether_destroy(client);
 */

#ifndef SOFTETHER_H
#define SOFTETHER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/* Opaque Handle                                                              */
/* ========================================================================== */

/** Opaque VPN client handle. */
typedef void* softether_client_t;

/* ========================================================================== */
/* Error Codes                                                                */
/* ========================================================================== */

typedef enum {
    SOFTETHER_OK                  =   0,
    SOFTETHER_ERR_INVALID_ARG     =  -1,
    SOFTETHER_ERR_ALREADY_CONN    =  -2,
    SOFTETHER_ERR_NOT_CONNECTED   =  -3,
    SOFTETHER_ERR_CONN_FAILED     =  -4,
    SOFTETHER_ERR_AUTH_FAILED     =  -5,
    SOFTETHER_ERR_DNS_FAILED      =  -6,
    SOFTETHER_ERR_TIMEOUT         =  -7,
    SOFTETHER_ERR_PROTOCOL        =  -8,
    SOFTETHER_ERR_ADAPTER         =  -9,
    SOFTETHER_ERR_SESSION         = -10,
    SOFTETHER_ERR_OUT_OF_MEMORY   = -11,
    SOFTETHER_ERR_CANCELLED       = -12,
    SOFTETHER_ERR_INTERNAL        = -99,
} softether_error_t;

/* ========================================================================== */
/* State & Event Enums                                                        */
/* ========================================================================== */

typedef enum {
    SOFTETHER_STATE_DISCONNECTED       = 0,
    SOFTETHER_STATE_RESOLVING_DNS      = 1,
    SOFTETHER_STATE_CONNECTING_TCP     = 2,
    SOFTETHER_STATE_SSL_HANDSHAKE      = 3,
    SOFTETHER_STATE_AUTHENTICATING     = 4,
    SOFTETHER_STATE_ESTABLISHING       = 5,
    SOFTETHER_STATE_CONFIGURING        = 6,
    SOFTETHER_STATE_CONNECTED          = 7,
    SOFTETHER_STATE_RECONNECTING       = 8,
    SOFTETHER_STATE_DISCONNECTING      = 9,
    SOFTETHER_STATE_ERROR              = 10,
} softether_state_t;

typedef enum {
    SOFTETHER_EVENT_STATE_CHANGED  = 0,
    SOFTETHER_EVENT_CONNECTED      = 1,
    SOFTETHER_EVENT_DISCONNECTED   = 2,
    SOFTETHER_EVENT_STATS_UPDATED  = 3,
    SOFTETHER_EVENT_ERROR          = 4,
} softether_event_t;

/* ========================================================================== */
/* Structs                                                                    */
/* ========================================================================== */

/** Connection statistics. */
typedef struct {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;
    int64_t  connect_time_ms;
    uint32_t reconnect_count;
    uint32_t _padding;
} softether_stats_t;

/* ========================================================================== */
/* Callback                                                                   */
/* ========================================================================== */

/**
 * Event callback function pointer.
 * @param event_type  One of softether_event_t values.
 * @param new_state   One of softether_state_t values.
 * @param user_data   User-provided context pointer.
 */
typedef void (*softether_event_callback_t)(int event_type, int new_state, void* user_data);

/* ========================================================================== */
/* Client Lifecycle                                                           */
/* ========================================================================== */

/**
 * Create a VPN client with password authentication.
 * @return Client handle, or NULL on failure. Must be freed with softether_destroy().
 */
softether_client_t softether_create(
    const char* server,
    uint16_t port,
    const char* hub,
    const char* username,
    const char* password
);

/**
 * Create a VPN client with anonymous authentication.
 * @return Client handle, or NULL on failure.
 */
softether_client_t softether_create_anonymous(
    const char* server,
    uint16_t port,
    const char* hub
);

/** Destroy a client and free all resources. Safe to call with NULL. */
void softether_destroy(softether_client_t client);

/* ========================================================================== */
/* Connection Management                                                      */
/* ========================================================================== */

/** Connect to the VPN server. Blocks until connected or error. */
int softether_connect(softether_client_t client);

/** Disconnect from the VPN server. */
int softether_disconnect(softether_client_t client);

/** Run the data loop (blocks). Call from a dedicated thread after connect(). */
int softether_run_data_loop(softether_client_t client);

/** Signal the data loop to stop. Non-blocking, safe from any thread. */
void softether_request_stop(softether_client_t client);

/* ========================================================================== */
/* State & Stats Queries                                                      */
/* ========================================================================== */

/** Get current connection state (softether_state_t). */
int softether_get_state(const softether_client_t client);

/** Check if currently connected. */
bool softether_is_connected(const softether_client_t client);

/** Fill stats struct. Returns 0 on success. */
int softether_get_stats(const softether_client_t client, softether_stats_t* out);

/** Get assigned VPN IP (host byte order, 0 if not assigned). */
uint32_t softether_get_assigned_ip(const softether_client_t client);

/** Get gateway IP (host byte order, 0 if not assigned). */
uint32_t softether_get_gateway_ip(const softether_client_t client);

/* ========================================================================== */
/* Configuration (call before connect)                                        */
/* ========================================================================== */

void softether_set_encryption(softether_client_t client, bool enabled);
void softether_set_compression(softether_client_t client, bool enabled);
void softether_set_verify_certificate(softether_client_t client, bool verify);
void softether_set_full_tunnel(softether_client_t client, bool enabled);
void softether_set_mtu(softether_client_t client, uint16_t mtu);
void softether_set_reconnect(softether_client_t client, bool enabled, uint32_t max_attempts);

/* ========================================================================== */
/* Event Callback                                                             */
/* ========================================================================== */

/** Register an event callback. Pass NULL to unregister. */
void softether_set_event_callback(
    softether_client_t client,
    softether_event_callback_t callback,
    void* user_data
);

/* ========================================================================== */
/* Version                                                                    */
/* ========================================================================== */

/** Get library version string. Returns pointer to static string. */
const char* softether_version(void);

#ifdef __cplusplus
}
#endif

#endif /* SOFTETHER_H */
