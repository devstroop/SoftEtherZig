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
    SOFTETHER_STATE_CONNECTING_TCP     = 1,
    SOFTETHER_STATE_SSL_HANDSHAKE      = 2,
    SOFTETHER_STATE_AUTHENTICATING     = 3,
    SOFTETHER_STATE_ESTABLISHING       = 4,
    SOFTETHER_STATE_CONFIGURING        = 5,
    SOFTETHER_STATE_CONNECTED          = 6,
    SOFTETHER_STATE_RECONNECTING       = 7,
    SOFTETHER_STATE_DISCONNECTING      = 8,
    SOFTETHER_STATE_ERROR              = 9,
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

/**
 * Create a VPN client with certificate (X.509) authentication.
 * PEM data is passed as pointer+length since PEM may contain embedded nulls.
 * All inputs are duped into FFI-owned memory.
 * @return Client handle, or NULL on failure.
 */
softether_client_t softether_create_certificate(
    const char* server,
    uint16_t port,
    const char* hub,
    const uint8_t* cert_pem,
    uint32_t cert_pem_len,
    const uint8_t* key_pem,
    uint32_t key_pem_len
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

/** Get DHCP-assigned subnet mask (host byte order, 0 if not assigned). */
uint32_t softether_get_assigned_mask(const softether_client_t client);

/**
 * Get the IPv4 server address actually connected to (host byte order, 0 if
 * not connected or if the target is IPv6). After a cluster redirect this
 * differs from the configured server hostname/IP and reveals which physical
 * backend the session landed on.
 */
uint32_t softether_get_effective_server_ip(const softether_client_t client);

/* ========================================================================== */
/* Configuration (call before connect)                                        */
/* ========================================================================== */

void softether_set_encryption(softether_client_t client, bool enabled);
void softether_set_compression(softether_client_t client, bool enabled);
void softether_set_verify_certificate(softether_client_t client, bool verify);
void softether_set_default_route(softether_client_t client, bool enabled);
void softether_set_mtu(softether_client_t client, uint16_t mtu);
void softether_set_reconnect(softether_client_t client, bool enabled, uint32_t max_attempts);

/** Set max parallel TCP connections (1-32). Out-of-range values are ignored. */
void softether_set_max_connections(softether_client_t client, uint8_t count);

/** Enable half-connection mode (separate upload/download TCP sockets). */
void softether_set_half_connection(softether_client_t client, bool enabled);

/** Set optional hostname for TLS/SNI. Pass empty string to clear. */
void softether_set_hostname(softether_client_t client, const char* hostname);

/** Enable VoIP / QoS packet prioritization. */
void softether_set_qos(softether_client_t client, bool enabled);

/** Switch to plain password auth (authtype=2) instead of hashed.
 *  Must be called BEFORE connect(). If not called, the client uses
 *  the default hashed-password auth (authtype=1). */
void softether_set_plain_password(softether_client_t client);

/** Enable UDP acceleration (requires server-side `use_udp_acceleration`).
 *  Out-of-range or unsupported values are ignored. */
void softether_set_udp_acceleration(softether_client_t client, bool enabled);

/** Set connection-establishment timeout in milliseconds (0 = use default). */
void softether_set_connect_timeout(softether_client_t client, uint32_t ms);

/** Set per-read timeout in milliseconds (0 = use default). */
void softether_set_read_timeout(softether_client_t client, uint32_t ms);

/** Set TCP keepalive interval in milliseconds (0 = disable). */
void softether_set_keepalive_interval(softether_client_t client, uint32_t ms);

/** Set IP version preference.
 *  version: 0=try both, 4=IPv4 only, 6=IPv6 only.
 *  Must be called before connect(). */
void softether_set_ip_version(softether_client_t client, int version);

/* ========================================================================== */
/* Routing Configuration                                                      */
/* ========================================================================== */

/** Set whether to accept routes pushed by the VPN server
 *  (DHCP option 121/249). Default: true. */
void softether_set_accept_pushed_routes(softether_client_t client, bool enabled);

/** Set whether custom split-tunnel routes are enabled.
 *  When enabled, only the networks listed in ipv4_include / ipv6_include
 *  are routed through the VPN (instead of full default-route tunnel).
 *  Default: false. */
void softether_set_enable_custom_routes(softether_client_t client, bool enabled);

/** Set IPv4 routes to INCLUDE (newline-separated CIDR notations).
 *  Only used when enable_custom_routes is true. Pass NULL or "" to clear. */
void softether_set_ipv4_include(softether_client_t client, const char* routes);

/** Set IPv4 routes to EXCLUDE (newline-separated CIDR notations).
 *  Only used when enable_custom_routes is true. Pass NULL or "" to clear. */
void softether_set_ipv4_exclude(softether_client_t client, const char* routes);

/** Set IPv6 routes to INCLUDE (newline-separated CIDR notations).
 *  Only used when enable_custom_routes is true. Pass NULL or "" to clear. */
void softether_set_ipv6_include(softether_client_t client, const char* routes);

/** Set IPv6 routes to EXCLUDE (newline-separated CIDR notations).
 *  Only used when enable_custom_routes is true. Pass NULL or "" to clear. */
void softether_set_ipv6_exclude(softether_client_t client, const char* routes);

/** Set tunnel file descriptor (utun fd) for packet I/O. Call after connect(). */
void softether_set_tunnel_fd(softether_client_t client, int32_t fd);

/**
 * Set separate tunnel file descriptors for UL (read) and DL (write) directions.
 * Used on iOS with dual socketpairs to prevent upload from starving download.
 * dl_fd = DL bridge fd (Zig -> Swift, for writing decrypted packets to utun).
 * ul_fd = UL bridge fd (Swift -> Zig, for reading upload packets from utun).
 * Must be called before connect(). Overrides softether_set_tunnel_fd().
 */
void softether_set_tunnel_fds(softether_client_t client, int32_t dl_fd, int32_t ul_fd);

/**
 * Replace the active TUN fd at runtime (mobile only).
 *
 * Used after DHCP completes and the platform re-creates the VpnService
 * tunnel with the server-assigned IP/mask.
 *
 * @return 0 on success, -1 on error.
 */
int softether_replace_tun_fd(softether_client_t client, int32_t fd);

/* ========================================================================== */
/* Event Callback                                                             */
/* ========================================================================== */

/** Register an event callback. Pass NULL to unregister. */
void softether_set_event_callback(
    softether_client_t client,
    softether_event_callback_t callback,
    void* user_data
);

/**
 * Set proxy configuration. Must be called before connect().
 * proxy_type: 0=none (clears), 1=HTTP, 2=SOCKS5.
 * host/port/username/password are ignored when proxy_type is 0.
 * Pass empty strings for username/password when the proxy doesn't require auth.
 */
void softether_set_proxy(softether_client_t client, int proxy_type, const char* host, uint16_t port, const char* username, const char* password);

/* ========================================================================== */
/* Diagnostics                                                                */
/* ========================================================================== */

/** Log levels passed to the external log sink. */
typedef enum {
    SOFTETHER_LOG_ERR  = 0,
    SOFTETHER_LOG_WARN = 1,
    SOFTETHER_LOG_INFO = 2,
    SOFTETHER_LOG_DBG  = 3,
} softether_log_level_t;

/** External log sink signature: receives level and a NUL-terminated UTF-8 message. */
typedef void (*softether_log_callback_t)(int level, const char* msg);

/**
 * Register a host-provided log sink. Called synchronously from libsoftether's
 * std.log, replacing platform-default logging (Android __android_log, iOS stderr).
 * Pass NULL to unregister and fall back to the default sink.
 *
 * Ownership: every message delivered to the callback is a heap-allocated
 * NUL-terminated string owned by libsoftether. The host MUST call
 * softether_free_log_text(msg) after copying the message, or the memory
 * leaks. Only a static fallback buffer (never the heap) is used on
 * allocation failure, and softether_free_log_text skips it — always call
 * the free for every callback invocation.
 *
 * Required on iOS NetworkExtension hosts where stderr capture races with
 * extension teardown — register a callback that calls os_log directly.
 */
void softether_set_log_callback(softether_log_callback_t cb);

/**
 * Release a log message previously delivered via softether_log_callback_t.
 * The message pointer is valid only until this call returns; it must not be
 * retained. Passing the static fallback buffer (or NULL) is a no-op.
 */
void softether_free_log_text(const char* msg);

/**
 * Set per-client verbose flag that gates DIAG throughput logs.
 * When false (default) the 1 Hz DIAG trace is suppressed. Controlled by
 * the UI switch (verbose_logging). Must be called before or while connected;
 * takes effect on the next DIAG interval.
 */
void softether_set_verbose(softether_client_t client, bool enabled);

/**
 * Bind libsoftether's outbound TLS sockets to a specific network interface
 * (Darwin IP_BOUND_IF / IPV6_BOUND_IF). Pass NULL or "" to clear.
 *
 * REQUIRED on iOS NEPacketTunnelProvider extensions: without this the kernel
 * NECP layer routes the extension's own VPN-server connection through the
 * tunnel that's about to be established, giving instant ECONNREFUSED. Pass
 * the underlying physical interface name (e.g. "en0" for Wi-Fi, "pdp_ip0"
 * for cellular) before softether_connect().
 *
 * No-op on non-Darwin platforms.
 */
void softether_set_bind_interface(const char* ifname);

/**
 * Host-provided TCP dial. When registered, libsoftether calls this instead of
 * doing its own DNS + POSIX connect(). Receives a NUL-terminated hostname and
 * port; must return a connected, blocking socket fd, or -1 on failure. The fd
 * is owned by libsoftether and will be close()d when the TLS session ends.
 *
 * REQUIRED on iOS NEPacketTunnelProvider extensions where NECP denies the
 * extension's own connect() to ANY destination once the tunnel config is
 * loaded. The host should dial via NEProvider.createTCPConnection (which
 * bypasses the tunnel) and bridge bytes between an NWTCPConnection and one
 * end of a socketpair. Returns the OTHER end of the socketpair to libsoftether.
 *
 * Pass NULL to clear and revert to the POSIX path.
 */
typedef int (*softether_tcp_dial_callback_t)(const char* host, uint16_t port);
void softether_set_tcp_dial_callback(softether_tcp_dial_callback_t cb);

/* ========================================================================== */
/* Version                                                                    */
/* ========================================================================== */

/** Get library version string. Returns pointer to static string. */
const char* softether_version(void);

#ifdef __cplusplus
}
#endif

#endif /* SOFTETHER_H */
