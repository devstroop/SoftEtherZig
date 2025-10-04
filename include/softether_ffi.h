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

#ifdef __cplusplus
}
#endif
