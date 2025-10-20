// SoftEther VPN Zig Client - Linux Packet Adapter Header

#ifndef PACKET_ADAPTER_LINUX_H
#define PACKET_ADAPTER_LINUX_H

#include "../../SoftEtherVPN/src/Mayaqua/Mayaqua.h"
#include "../../SoftEtherVPN/src/Cedar/Cedar.h"

// Packet structure for queuing
typedef struct TUN_PACKET {
    void *data;
    UINT size;
} TUN_PACKET;

// Linux TUN context
typedef struct LINUX_TUN_CONTEXT {
    SESSION *session;
    int tun_fd;
    char device_name[64];
    THREAD *read_thread;
    CANCEL *cancel;
    QUEUE *recv_queue;
    LOCK *queue_lock;
    bool halt;
    
    // Statistics
    UINT64 packets_sent;
    UINT64 packets_received;
    UINT64 bytes_sent;
    UINT64 bytes_received;
} LINUX_TUN_CONTEXT;

// Function declarations
PACKET_ADAPTER* NewLinuxTunAdapter();
bool LinuxTunInit(SESSION *s);
CANCEL* LinuxTunGetCancel(SESSION *s);
UINT LinuxTunGetNextPacket(SESSION *s, void **data);
bool LinuxTunPutPacket(SESSION *s, void *data, UINT size);
void LinuxTunFree(SESSION *s);

#endif // PACKET_ADAPTER_LINUX_H
