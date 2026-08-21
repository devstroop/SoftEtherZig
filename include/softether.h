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

/**
 * Get a human-readable string for an error code.
 * Returns a pointer to a static, NUL-terminated string.
 * Unknown codes return "Unknown error".
 */
const char* softether_error_string(int code);

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

/** Aggregate bridge-mode statistics (softether_get_bridge_stats). */
typedef struct {
    uint32_t fdb_entries;
    uint32_t _pad0;
    uint64_t forwarded;
    uint64_t flooded;
    uint64_t blocked;
    uint64_t lan_rx_pkts;
    uint64_t lan_tx_pkts;
    uint64_t lan_rx_bytes;
    uint64_t lan_tx_bytes;
    uint64_t drops;
    uint64_t session_rx;
    uint64_t session_tx;
    uint64_t session_tx_errors;
} softether_bridge_stats_t;

/** Aggregate monitor-mode statistics (softether_get_monitor_stats). */
typedef struct {
    uint64_t frames_captured;
    uint64_t frames_dropped;
    uint64_t bytes_captured;
    uint32_t ring_used;
    uint32_t _pad0;
    uint64_t pcap_records;
    uint64_t pcap_bytes;
    uint64_t pcap_write_errors;
} softether_monitor_stats_t;

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
/* Async Data Loop                                                            */
/* ========================================================================== */

/** Callback for each received frame in async mode. */
typedef void (*softether_data_loop_frame_fn)(
    softether_client_t client,
    const uint8_t* frame, uint32_t frame_len,
    void* user_data);

/** Callback when async data loop exits. error_code=0 on clean shutdown. */
typedef void (*softether_data_loop_done_fn)(
    softether_client_t client,
    int error_code,
    void* user_data);

/**
 * Start the data loop in a background thread with per-frame callbacks.
 * Must call softether_connect() first (which spawns the native data loop).
 * The frame_fn callback is invoked from the data loop thread for each
 * inbound Ethernet frame. Returns 0 on success, negative SoftetherError
 * on failure.
 */
int softether_run_data_loop_async(
    softether_client_t client,
    softether_data_loop_frame_fn frame_fn,
    softether_data_loop_done_fn done_fn,
    void* user_data);

/** Cancel a running async data loop (signal-safe, non-blocking). */
void softether_cancel_data_loop(softether_client_t client);

/* ========================================================================== */
/* State & Stats Queries                                                      */
/* ========================================================================== */

/** Get current connection state (softether_state_t). */
int softether_get_state(const softether_client_t client);

/** Check if currently connected. */
bool softether_is_connected(const softether_client_t client);

/** Fill stats struct. Returns 0 on success. */
int softether_get_stats(const softether_client_t client, softether_stats_t* out);

/**
 * Fill bridge-mode stats (zeroed when bridge mode is not active or the
 * pump is not running). Returns 0 on success.
 */
int softether_get_bridge_stats(const softether_client_t client, softether_bridge_stats_t* out);

/**
 * Fill monitor-mode stats (zeroed when monitor mode is not active or the
 * pump is not running). Returns 0 on success.
 */
int softether_get_monitor_stats(const softether_client_t client, softether_monitor_stats_t* out);

/**
 * Frames currently held in the monitor ring; 0 means an empty ring.
 * Returns -1 when the client is invalid or the monitor pump is not
 * running.
 */
int64_t softether_monitor_frame_count(const softether_client_t client);

/**
 * Copy one captured frame (index 0 = oldest) into out.
 * Returns bytes copied (0 when index is out of range or out_cap is 0),
 * or -1 when the client is invalid / monitor pump not running. The copy
 * is a stable snapshot taken under the loop mutex.
 */
int64_t softether_monitor_get_frame(const softether_client_t client, int64_t index,
                                    uint8_t* out, uintptr_t out_cap);

/** Get assigned VPN IP (host byte order, 0 if not assigned). */
uint32_t softether_get_assigned_ip(const softether_client_t client);

/** Get gateway IP (host byte order, 0 if not assigned). */
uint32_t softether_get_gateway_ip(const softether_client_t client);

/** Get DHCP-assigned subnet mask (host byte order, 0 if not assigned). */
uint32_t softether_get_assigned_mask(const softether_client_t client);

/** Get first DHCP-assigned DNS server (host byte order, 0 if none). */
uint32_t softether_get_assigned_dns1(const softether_client_t client);

/** Get second DHCP-assigned DNS server (host byte order, 0 if none). */
uint32_t softether_get_assigned_dns2(const softether_client_t client);

/**
 * Get the last error code for a failed connection. Returns the SoftetherError
 * enum value (negative on error, 0 = no error recorded).
 */
int softether_get_last_error(const softether_client_t client);

/**
 * Get the IPv4 server address actually connected to (host byte order, 0 if
 * not connected or if the target is IPv6). After a cluster redirect this
 * differs from the configured server hostname/IP and reveals which physical
 * backend the session landed on.
 */
uint32_t softether_get_effective_server_ip(const softether_client_t client);

/**
 * Get assigned IPv6 address (16 bytes copied into buf).
 * Returns 0 on success, -1 if not assigned or invalid arguments.
 */
int softether_get_assigned_ip_v6(const softether_client_t client, uint8_t buf[16]);

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

/** Set gratuitous ARP interval in milliseconds. Must be called before connect(). */
void softether_set_garp_interval(softether_client_t client, uint32_t ms);

/** Set TCP_NODELAY (disable Nagle's algorithm for low latency). Default: true. */
void softether_set_tcp_nodelay(softether_client_t client, bool enabled);

/** Set static IPv4 address. Must be called before connect(). */
void softether_set_static_ipv4(softether_client_t client, const char* addr);

/** Set static IPv4 netmask. Must be called before connect(). */
void softether_set_static_ipv4_netmask(softether_client_t client, const char* addr);

/** Set static IPv4 gateway. Must be called before connect(). */
void softether_set_static_ipv4_gateway(softether_client_t client, const char* addr);

/** Set static IPv6 address. Must be called before connect(). */
void softether_set_static_ipv6(softether_client_t client, const char* addr);

/** Set static IPv6 prefix length. Must be called before connect(). */
void softether_set_static_ipv6_prefix(softether_client_t client, uint8_t prefix);

/** Set static IPv6 gateway. Must be called before connect(). */
void softether_set_static_ipv6_gateway(softether_client_t client, const char* addr);

/** Set DNS servers (comma-separated IPs). Must be called before connect(). */
void softether_set_dns_servers(softether_client_t client, const char* servers);

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
/* Client Fingerprint (spoof SoftEther VPN Client identity)                    */
/* ========================================================================== */

/** Override client identification string. Pass NULL or "" to restore default. */
void softether_set_client_str(softether_client_t client, const char* str);

/** Override client version number. Pass 0 to restore default (444). */
void softether_set_client_ver(softether_client_t client, uint32_t ver);

/** Override client build number. Pass 0 to restore default (9807). */
void softether_set_client_build(softether_client_t client, uint32_t build);

/** Override OS name, version, title sent to server. Pass NULL to clear. */
void softether_set_os_info(softether_client_t client, const char* name, const char* version, const char* title);

/* ========================================================================== */
/* Android Integration                                                        */
/* ========================================================================== */

/**
 * Register Android VpnService.protect() callback to exempt TLS sockets from
 * VPN routing. Pass NULL to clear. Only meaningful on Android.
 */
typedef int32_t (*softether_android_protect_fn)(int32_t fd);
void softether_set_android_protect(softether_android_protect_fn cb);

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
 * Required on iOS NetworkExtension hosts where stderr capture races with
 * extension teardown — register a callback that calls os_log directly.
 */
void softether_set_log_callback(softether_log_callback_t cb);

/** Set whether the external log callback is exclusive (stops further output).
 *  Default: true (exclusive). */
void softether_set_log_callback_exclusive(bool exclusive);

/** Set the minimum log level at runtime. 0=err, 1=warn, 2=info, 3=debug. */
void softether_set_log_level_global(int level);

/** Compat shim — old two-arg API (client pointer is ignored). */
void softether_set_log_level(softether_client_t client, int level);

/** Per-client log level — delegates to softether_set_log_level_global. */
void softether_set_log_level_client(softether_client_t client, int level);

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
/* NIC enumeration                                                            */
/* ========================================================================== */

/**
 * Single NIC entry returned by softether_list_interfaces().
 *
 * Stable-id semantics: `mac` (hardware address) — or the Windows adapter
 * GUID carried in `name` — is the stable identity of an interface across
 * renames. POSIX device names (en0/eth1) and `index` alone are NOT stable:
 * the OS may rename interfaces or reuse indices across boots, while the MAC
 * (or GUID) identifies the same physical/virtual interface regardless.
 *
 * Interfaces WITHOUT a hardware address (e.g. utun on macOS) carry an
 * all-zero `mac` and have NO stable identity: do not use them as merge
 * keys. Treat entries with a zeroed `mac` as identity-on-name only for the
 * duration of a single enumeration.
 */
typedef struct {
    /* Interface name: POSIX ifname (NUL-terminated, <= 15 chars) or the
     * Windows adapter GUID string ("{...}", <= 39 chars). NUL-padded. */
    char name[64];
    /* Hardware address (6 bytes); all zeros for interfaces without one. */
    uint8_t mac[6];
    /* Platform interface index. */
    uint32_t index;
} softether_nic_info;

/**
 * Enumerate the host's network interfaces (loopback excluded).
 *
 * Fills out[0..cap] with {name, mac, index} entries.
 *
 * Returns:
 *   > 0        number of entries written into `out`
 *   < -2       truncated — the host has more than `cap` interfaces;
 *              the exact value is -(full_count + 2), so the buffer can be
 *              grown to `full_count` entries and the call retried. The
 *              offset guarantees truncation never collides with the
 *              reserved error codes below, even when the full count is 2.
 *   -1         invalid arguments (NULL out, cap <= 0)
 *   -2         enumeration failed
 */
int softether_list_interfaces(softether_nic_info* out, int cap);

/* ========================================================================== */
/* Network mode (L2 bridge proposal §5.1)                                     */
/* ========================================================================== */

/**
 * Set the network operating mode: 0=client (default), 1=bridge, 2=monitor.
 * Invalid values are ignored.
 *
 * The client stores the mode in its config AND its session flag, and the
 * connect path branches on the flag. Runtime is implemented for all three
 * modes: client runs the classic TUN data loop, bridge (issue #56) runs a
 * Linux AF_PACKET L2 pump, monitor (issue #55) runs a mirror-only capture
 * pump (bounded ring + optional PCAP). Calling this after connect() does
 * not affect the running session; the mode is applied on the next connect.
 */
void softether_set_network_mode(softether_client_t client, int mode);

/**
 * Append an ingress interface to the bridge list (deduped, owned copy).
 * Returns 0 on success, -1 on invalid client / empty name / OOM.
 */
int softether_add_ingress_interface(softether_client_t client, const char* name);

/**
 * Remove an ingress interface from the bridge list.
 * Returns 0 on success (or if not present), -1 on invalid client / OOM.
 */
int softether_remove_ingress_interface(softether_client_t client, const char* name);

/**
 * Set the monitor-mode PCAP capture path (owned copy; "" or NULL clears
 * it). The file is opened when the monitor pump starts (next connect);
 * a bad path aborts the monitor session with the raw file error.
 * Returns 0 on success, -1 on invalid client / OOM.
 */
int softether_set_monitor_pcap(softether_client_t client, const char* path);

/* ========================================================================== */
/* Version                                                                    */
/* ========================================================================== */

/** Get library version string. Returns pointer to static string. */
const char* softether_version(void);

/* ========================================================================== */
/* Embedded VPN Server (M15, issue #197)                                       */
/* ========================================================================== */

/** Opaque handle for the embedded VPN server. */
typedef void* softether_server_t;

/**
 * Create a new VPN server instance. Returns NULL on allocation failure.
 * The caller owns the handle and must call softether_server_destroy().
 *
 * @param hub_name      Virtual hub name (NULL → "DEFAULT").
 * @param admin_user    Admin username (NULL → "administrator").
 * @param admin_password Admin password (NULL → "softether").
 * @return Server handle, or NULL on failure.
 */
softether_server_t softether_server_create(
    const char* hub_name,
    const char* admin_user,
    const char* admin_password
);

/**
 * Build the server (cert, hubs, admin dispatch) and start listeners.
 * Calls build() + start() + waitForListening(5000) internally.
 * Returns 0 on success, negative SoftetherError on failure.
 */
int softether_server_start(softether_server_t server);

/**
 * Signal the server to stop accepting new connections.
 * Async-signal-safe — can be called from a signal handler.
 */
void softether_server_stop(softether_server_t server);

/**
 * Destroy the server and free all resources.
 * After this call the handle is invalid. NULL-safe.
 */
void softether_server_destroy(softether_server_t server);

/**
 * Returns 1 if the server is running, 0 if stopped, -1 for invalid handle.
 */
int softether_server_is_running(softether_server_t server);

/**
 * Block until at least one listener is accepting connections, or until
 * timeout_ms elapses. Returns 1 if ready, 0 on timeout, -1 on error.
 */
int softether_server_wait_for_listening(softether_server_t server, int64_t timeout_ms);

/**
 * Copy the hub name into out_buf (up to buf_len bytes including NUL).
 * Returns bytes written (excluding NUL), or -1 on error.
 */
int softether_server_get_hub_name(
    softether_server_t server,
    char* out_buf,
    int buf_len
);

/**
 * Copy the admin username into out_buf (up to buf_len bytes including NUL).
 * Returns bytes written (excluding NUL), or -1 on error.
 */
int softether_server_get_admin_user(
    softether_server_t server,
    char* out_buf,
    int buf_len
);

/**
 * Configure syslog forwarding. Empty hostname or port 0 disables forwarding.
 * Returns 0 on success, -1 on invalid arguments.
 */
int softether_server_set_syslog(
    softether_server_t server,
    const char* hostname,
    uint32_t port
);

/* ========================================================================== */
/* Session Enumeration (issue #194)                                            */
/* ========================================================================== */

/** C-compatible session info struct. */
typedef struct {
    char session_name[64];
    char username[256];
    char hub_name[256];
    uint32_t peer_ip;
    uint16_t peer_port;
    int64_t created_time;
    int active;  /* 1 = active, 0 = stop requested */
} softether_session_info_t;

/**
 * Enumerate sessions on a hub. Fills out_buf with up to max_count entries.
 * Returns the number of sessions written, or -1 on error.
 */
int softether_enum_sessions(
    softether_server_t server,
    const char* hub_name,
    softether_session_info_t* out_buf,
    int max_count
);

/**
 * Get status of a specific session. Fills out with session info.
 * Returns 0 on success, -1 on error.
 */
int softether_get_session_status(
    softether_server_t server,
    const char* hub_name,
    const char* session_name,
    softether_session_info_t* out
);

/**
 * Disconnect (stop) a session by name. Returns 0 on success, -1 on error.
 */
int softether_disconnect_session(
    softether_server_t server,
    const char* hub_name,
    const char* session_name
);

#ifdef __cplusplus
}
#endif

#endif /* SOFTETHER_H */
