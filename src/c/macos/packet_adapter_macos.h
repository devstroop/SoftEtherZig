// SoftEther VPN Zig Client - macOS Packet Adapter
// TUN device interface for packet forwarding

#ifndef PACKET_ADAPTER_MACOS_H
#define PACKET_ADAPTER_MACOS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../../SoftEtherVPN/src/Mayaqua/Mayaqua.h"
#include "../../SoftEtherVPN/src/Cedar/Cedar.h"

// Forward declarations - these are defined in CedarType.h, don't redefine them
// typedef struct SESSION SESSION;
// typedef struct PACKET_ADAPTER PACKET_ADAPTER;

// IP configuration passed from bridge layer
typedef struct IP_CONFIG {
    int ip_version;  // 0=auto, 1=ipv4, 2=ipv6, 3=dual
    bool use_static_ipv4;
    char static_ipv4[64];
    char static_ipv4_netmask[64];
    char static_ipv4_gateway[64];
    bool use_static_ipv6;
    char static_ipv6[128];
    int static_ipv6_prefix;
    char static_ipv6_gateway[128];
} IP_CONFIG;

// Global IP configuration (set by bridge layer before adapter init)
extern IP_CONFIG g_ip_config;

// macOS TUN device context
typedef struct MACOS_TUN_CONTEXT {
    int tun_fd;                      // TUN device file descriptor
    char device_name[64];            // Device name (e.g., "utun0")
    CANCEL *cancel;                  // Cancellation object for blocking I/O
    THREAD *read_thread;             // Background thread for reading packets
    THREAD *timer_thread;            // Timer thread for DHCP retries
    QUEUE *recv_queue;               // Queue of received packets
    LOCK *queue_lock;                // Lock for thread-safe queue access
    volatile bool halt;              // Stop flag
    SESSION *session;                // Associated session
    
    // Statistics
    UINT64 bytes_sent;
    UINT64 bytes_received;
    UINT64 packets_sent;
    UINT64 packets_received;
} MACOS_TUN_CONTEXT;

// Packet wrapper for queue
typedef struct TUN_PACKET {
    void *data;
    UINT size;
} TUN_PACKET;

// Create a new packet adapter for macOS TUN device
PACKET_ADAPTER* NewMacOsTunAdapter();

// Packet adapter callbacks (used by SoftEther internally)
UINT MacOsTunInit(SESSION *s);
CANCEL* MacOsTunGetCancel(SESSION *s);
UINT MacOsTunGetNextPacket(SESSION *s, void **data);
UINT MacOsTunPutPacket(SESSION *s, void *data, UINT size);
void MacOsTunFree(SESSION *s);

// TUN device management
int OpenMacOsTunDevice(char *device_name, size_t device_name_size);
void CloseMacOsTunDevice(int fd);

#ifdef __cplusplus
}
#endif

#endif // PACKET_ADAPTER_MACOS_H
