/*
 * iOS Packet Adapter for SoftEther VPN
 * 
 * This adapter integrates with iOS Network Extension (NEPacketTunnelProvider)
 * Uses NEPacketTunnelFlow for packet I/O via callbacks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>

#include "../../Mayaqua/Mayaqua.h"
#include "../../Cedar/Cedar.h"
#include "../logging.h"

// Forward declaration of iOS flow interface
typedef struct IOSPacketFlow IOSPacketFlow;

// Function pointers for iOS NEPacketTunnelFlow callbacks
typedef void (*IOSWritePacketsCallback)(IOSPacketFlow *flow, const void **packets, 
                                       const int *sizes, int count);
typedef void (*IOSReadPacketsCallback)(IOSPacketFlow *flow, void *context);

// iOS adapter context
typedef struct {
    SESSION *session;
    CANCEL *cancel;
    QUEUE *recv_queue;    // Packets from iOS (to VPN server)
    QUEUE *send_queue;    // Packets to iOS (from VPN server)
    LOCK *queue_lock;
    THREAD *send_thread;
    volatile bool halt;
    
    // iOS flow interface
    IOSPacketFlow *packet_flow;
    IOSWritePacketsCallback write_packets;
    IOSReadPacketsCallback read_packets;
    void *flow_context;
    
    // DHCP state
    UINT32 assigned_ip;
    UINT32 gateway_ip;
    UINT32 subnet_mask;
    UINT32 dns_server1;
    UINT32 dns_server2;
    UCHAR mac_address[6];
    
} IOSTunContext;

// Forward declarations
static void IOSTunSendThread(THREAD *thread, void *param);

/*
 * iOS-side calls this when packets are read from TUN
 * Called from Swift via C bridge
 */
void IOSTunReceivePackets(void *adapter_context, const void **packets, 
                         const int *sizes, int count) {
    if (adapter_context == NULL || packets == NULL || sizes == NULL || count <= 0) {
        return;
    }
    
    IOSTunContext *ctx = (IOSTunContext*)adapter_context;
    
    LOG_TUN_TRACE("iOS: Received %d packets from TUN\n", count);
    
    Lock(ctx->queue_lock);
    {
        for (int i = 0; i < count; i++) {
            if (packets[i] != NULL && sizes[i] > 0) {
                // Copy packet data
                void *packet_data = Malloc(sizes[i]);
                if (packet_data != NULL) {
                    Copy(packet_data, packets[i], sizes[i]);
                    
                    BLOCK *block = NewBlock(packet_data, sizes[i], 0);
                    InsertQueue(ctx->recv_queue, block);
                }
            }
        }
    }
    Unlock(ctx->queue_lock);
    
    Cancel(ctx->cancel);
}

/*
 * Background thread to send packets to iOS
 */
static void IOSTunSendThread(THREAD *thread, void *param) {
    IOSTunContext *ctx = (IOSTunContext*)param;
    
    if (ctx == NULL) {
        return;
    }
    
    NoticeThreadInit(thread);
    LOG_TUN_DEBUG("iOS send thread started\n");
    
    // Buffer for batch sending (up to 32 packets at once)
    const void *packet_ptrs[32];
    int packet_sizes[32];
    
    while (!ctx->halt) {
        int packet_count = 0;
        
        // Collect packets from send queue
        Lock(ctx->queue_lock);
        {
            while (packet_count < 32) {
                BLOCK *block = GetNext(ctx->send_queue);
                if (block == NULL) {
                    break;
                }
                
                packet_ptrs[packet_count] = block->Buf;
                packet_sizes[packet_count] = block->Size;
                packet_count++;
                
                // Keep block for now, will free after sending
            }
        }
        Unlock(ctx->queue_lock);
        
        // Send packets to iOS if we have any
        if (packet_count > 0 && ctx->write_packets != NULL) {
            LOG_TUN_TRACE("iOS: Sending %d packets to TUN\n", packet_count);
            ctx->write_packets(ctx->packet_flow, packet_ptrs, packet_sizes, packet_count);
            
            // Free the blocks now
            Lock(ctx->queue_lock);
            {
                for (int i = 0; i < packet_count; i++) {
                    Free((void*)packet_ptrs[i]);
                }
            }
            Unlock(ctx->queue_lock);
        } else {
            // No packets, wait briefly
            Wait(ctx->cancel, 10);
        }
        
        // Request more packets from iOS
        if (ctx->read_packets != NULL && !ctx->halt) {
            ctx->read_packets(ctx->packet_flow, ctx->flow_context);
        }
    }
    
    LOG_TUN_DEBUG("iOS send thread exiting\n");
}

/*
 * Initialize iOS TUN adapter
 */
bool IOSTunInit(SESSION *s) {
    if (s == NULL) {
        LOG_TUN_ERROR("Session is NULL\n");
        return false;
    }
    
    LOG_TUN_INFO("Initializing iOS TUN adapter\n");
    
    // Allocate context
    IOSTunContext *ctx = (IOSTunContext*)ZeroMalloc(sizeof(IOSTunContext));
    if (ctx == NULL) {
        LOG_TUN_ERROR("Failed to allocate context\n");
        return false;
    }
    
    ctx->session = s;
    ctx->halt = false;
    
    // Generate MAC address
    GenMacAddress(ctx->mac_address);
    ctx->mac_address[0] = 0x02; // Locally administered
    
    LOG_TUN_INFO("Generated MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                 ctx->mac_address[0], ctx->mac_address[1], ctx->mac_address[2],
                 ctx->mac_address[3], ctx->mac_address[4], ctx->mac_address[5]);
    
    // Create synchronization objects
    ctx->cancel = NewCancel();
    ctx->recv_queue = NewQueue();
    ctx->send_queue = NewQueue();
    ctx->queue_lock = NewLock();
    
    // Start send thread
    ctx->send_thread = NewThread(IOSTunSendThread, ctx);
    WaitThreadInit(ctx->send_thread);
    
    // Store context
    s->PacketAdapter->Param = ctx;
    
    LOG_TUN_INFO("iOS TUN adapter initialized successfully\n");
    return true;
}

/*
 * Set iOS packet flow interface (called from Swift)
 */
void IOSTunSetPacketFlow(void *adapter_context, void *packet_flow,
                        IOSWritePacketsCallback write_cb,
                        IOSReadPacketsCallback read_cb,
                        void *flow_context) {
    if (adapter_context == NULL) {
        return;
    }
    
    IOSTunContext *ctx = (IOSTunContext*)adapter_context;
    
    ctx->packet_flow = (IOSPacketFlow*)packet_flow;
    ctx->write_packets = write_cb;
    ctx->read_packets = read_cb;
    ctx->flow_context = flow_context;
    
    LOG_TUN_INFO("iOS packet flow interface set\n");
    
    // Start reading packets
    if (read_cb != NULL) {
        read_cb(packet_flow, flow_context);
    }
}

/*
 * Get next packet to send to VPN server
 */
void* IOSTunGetNextPacket(PACKET_ADAPTER *pa, UINT *size) {
    if (pa == NULL || size == NULL) {
        return NULL;
    }
    
    IOSTunContext *ctx = (IOSTunContext*)pa->Param;
    if (ctx == NULL) {
        return NULL;
    }
    
    *size = 0;
    
    // Check queue for packets from iOS
    Lock(ctx->queue_lock);
    {
        BLOCK *block = GetNext(ctx->recv_queue);
        if (block != NULL) {
            void *data = block->Buf;
            *size = block->Size;
            
            // Free block structure but return data
            block->Buf = NULL;
            FreeBlock(block);
            
            Unlock(ctx->queue_lock);
            return data;
        }
    }
    Unlock(ctx->queue_lock);
    
    // No packets available, wait briefly
    Wait(ctx->cancel, 10);
    return NULL;
}

/*
 * Put packet received from VPN server (to be sent to iOS)
 */
bool IOSTunPutPacket(PACKET_ADAPTER *pa, void *data, UINT size) {
    if (pa == NULL || data == NULL || size == 0) {
        return false;
    }
    
    IOSTunContext *ctx = (IOSTunContext*)pa->Param;
    if (ctx == NULL) {
        return false;
    }
    
    LOG_TUN_TRACE("Queueing %u bytes for iOS\n", size);
    
    // Copy packet and queue for send thread
    void *packet_copy = Malloc(size);
    if (packet_copy == NULL) {
        return false;
    }
    
    Copy(packet_copy, data, size);
    
    Lock(ctx->queue_lock);
    {
        BLOCK *block = NewBlock(packet_copy, size, 0);
        InsertQueue(ctx->send_queue, block);
    }
    Unlock(ctx->queue_lock);
    
    Cancel(ctx->cancel);
    return true;
}

/*
 * Get adapter cancel handle
 */
CANCEL* IOSTunGetCancel(PACKET_ADAPTER *pa) {
    if (pa == NULL) {
        return NULL;
    }
    
    IOSTunContext *ctx = (IOSTunContext*)pa->Param;
    if (ctx == NULL) {
        return NULL;
    }
    
    return ctx->cancel;
}

/*
 * Free iOS TUN adapter
 */
void IOSTunFree(PACKET_ADAPTER *pa) {
    if (pa == NULL) {
        return;
    }
    
    LOG_TUN_INFO("Freeing iOS TUN adapter\n");
    
    IOSTunContext *ctx = (IOSTunContext*)pa->Param;
    if (ctx != NULL) {
        // Stop send thread
        ctx->halt = true;
        Cancel(ctx->cancel);
        
        if (ctx->send_thread != NULL) {
            WaitThread(ctx->send_thread, 5000);
            ReleaseThread(ctx->send_thread);
        }
        
        // Free synchronization objects
        if (ctx->cancel != NULL) {
            ReleaseCancel(ctx->cancel);
        }
        
        // Free queues
        if (ctx->recv_queue != NULL) {
            while (true) {
                BLOCK *block = GetNext(ctx->recv_queue);
                if (block == NULL) break;
                FreeBlock(block);
            }
            ReleaseQueue(ctx->recv_queue);
        }
        
        if (ctx->send_queue != NULL) {
            while (true) {
                BLOCK *block = GetNext(ctx->send_queue);
                if (block == NULL) break;
                FreeBlock(block);
            }
            ReleaseQueue(ctx->send_queue);
        }
        
        if (ctx->queue_lock != NULL) {
            DeleteLock(ctx->queue_lock);
        }
        
        Free(ctx);
    }
    
    Free(pa);
    LOG_TUN_INFO("iOS TUN adapter freed\n");
}

/*
 * Create iOS packet adapter
 */
PACKET_ADAPTER* NewIOSPacketAdapter(SESSION *s) {
    if (s == NULL) {
        return NULL;
    }
    
    PACKET_ADAPTER *pa = (PACKET_ADAPTER*)ZeroMalloc(sizeof(PACKET_ADAPTER));
    if (pa == NULL) {
        return NULL;
    }
    
    pa->Init = IOSTunInit;
    pa->GetNextPacket = IOSTunGetNextPacket;
    pa->PutPacket = IOSTunPutPacket;
    pa->GetCancel = IOSTunGetCancel;
    pa->Free = IOSTunFree;
    pa->Param = NULL;
    
    if (!pa->Init(s)) {
        Free(pa);
        return NULL;
    }
    
    return pa;
}

/*
 * Get adapter context (for iOS to call receive/set functions)
 */
void* IOSTunGetContext(PACKET_ADAPTER *pa) {
    if (pa == NULL) {
        return NULL;
    }
    return pa->Param;
}
