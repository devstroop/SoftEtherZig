// SoftEther VPN Zig Client - macOS Packet Adapter
// TUN device interface for packet forwarding

#ifndef PACKET_ADAPTER_MACOS_H
#define PACKET_ADAPTER_MACOS_H

#include "../../SoftEtherVPN_Stable/src/Mayaqua/Mayaqua.h"
#include "../../SoftEtherVPN_Stable/src/Cedar/Cedar.h"

// Forward declarations
typedef struct SESSION SESSION;
typedef struct PACKET_ADAPTER PACKET_ADAPTER;

// macOS TUN device context
typedef struct MACOS_TUN_CONTEXT {
    int tun_fd;                      // TUN device file descriptor
    char device_name[64];            // Device name (e.g., "utun0")
    CANCEL *cancel;                  // Cancellation object for blocking I/O
    THREAD *read_thread;             // Background thread for reading packets
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
bool MacOsTunInit(SESSION *s);
CANCEL* MacOsTunGetCancel(SESSION *s);
UINT MacOsTunGetNextPacket(SESSION *s, void **data);
bool MacOsTunPutPacket(SESSION *s, void *data, UINT size);
void MacOsTunFree(SESSION *s);

// TUN device management
int OpenMacOsTunDevice(char *device_name, size_t device_name_size);
void CloseMacOsTunDevice(int fd);

#endif // PACKET_ADAPTER_MACOS_H
