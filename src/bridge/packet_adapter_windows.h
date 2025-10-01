// SoftEther VPN Zig Client - Windows Packet Adapter Header

#ifndef PACKET_ADAPTER_WINDOWS_H
#define PACKET_ADAPTER_WINDOWS_H

#ifdef _WIN32

#include "../../SoftEtherVPN_Stable/src/Mayaqua/Mayaqua.h"
#include "../../SoftEtherVPN_Stable/src/Cedar/Cedar.h"
#include <windows.h>

// Packet structure for queuing
typedef struct TUN_PACKET {
    void *data;
    UINT size;
} TUN_PACKET;

// Windows TAP context
typedef struct WINDOWS_TAP_CONTEXT {
    SESSION *session;
    HANDLE tap_handle;
    char device_name[256];
    THREAD *read_thread;
    HANDLE read_event;
    HANDLE write_event;
    CANCEL *cancel;
    QUEUE *recv_queue;
    LOCK *queue_lock;
    bool halt;
    
    // Statistics
    UINT64 packets_sent;
    UINT64 packets_received;
    UINT64 bytes_sent;
    UINT64 bytes_received;
} WINDOWS_TAP_CONTEXT;

// Function declarations
PACKET_ADAPTER* NewWindowsTapAdapter();
bool WindowsTapInit(SESSION *s);
CANCEL* WindowsTapGetCancel(SESSION *s);
UINT WindowsTapGetNextPacket(SESSION *s, void **data);
bool WindowsTapPutPacket(SESSION *s, void *data, UINT size);
void WindowsTapFree(SESSION *s);

#endif // _WIN32

#endif // PACKET_ADAPTER_WINDOWS_H
