/*
 * Android Packet Adapter for SoftEther VPN
 * 
 * This adapter integrates with Android VpnService TUN interface.
 * Uses file descriptor provided by VpnService.establish()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../../Mayaqua/Mayaqua.h"
#include "../../Cedar/Cedar.h"
#include "../logging.h"

// External TUN fd set by JNI
extern int g_tun_fd;

// Android adapter context
typedef struct {
    int tun_fd;
    SESSION *session;
    CANCEL *cancel;
    QUEUE *recv_queue;
    LOCK *queue_lock;
    THREAD *read_thread;
    volatile bool halt;
    
    // DHCP state
    UINT32 assigned_ip;
    UINT32 gateway_ip;
    UINT32 subnet_mask;
    UINT8 mac_address[6];
    
} AndroidTunContext;

// Forward declarations
static void AndroidTunReadThread(THREAD *thread, void *param);

/*
 * Initialize Android TUN adapter
 */
bool AndroidTunInit(SESSION *s) {
    if (s == NULL) {
        LOG_TUN_ERROR("Session is NULL\n");
        return false;
    }
    
    LOG_TUN_INFO("Initializing Android TUN adapter\n");
    
    if (g_tun_fd < 0) {
        LOG_TUN_ERROR("TUN fd not set (call setTunFd first)\n");
        return false;
    }
    
    // Allocate context
    AndroidTunContext *ctx = (AndroidTunContext*)ZeroMalloc(sizeof(AndroidTunContext));
    if (ctx == NULL) {
        LOG_TUN_ERROR("Failed to allocate context\n");
        return false;
    }
    
    ctx->tun_fd = g_tun_fd;
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
    ctx->queue_lock = NewLock();
    
    // Start read thread
    ctx->read_thread = NewThread(AndroidTunReadThread, ctx);
    WaitThreadInit(ctx->read_thread);
    
    // Store context
    s->PacketAdapter->Param = ctx;
    
    LOG_TUN_INFO("Android TUN adapter initialized successfully (fd=%d)\n", ctx->tun_fd);
    return true;
}

/*
 * Background thread to read from TUN device
 */
static void AndroidTunReadThread(THREAD *thread, void *param) {
    AndroidTunContext *ctx = (AndroidTunContext*)param;
    UCHAR buffer[2048];
    
    if (ctx == NULL) {
        return;
    }
    
    NoticeThreadInit(thread);
    LOG_TUN_DEBUG("Android TUN read thread started\n");
    
    while (!ctx->halt) {
        // Use select with timeout for cancellation
        fd_set readfds;
        struct timeval tv;
        
        FD_ZERO(&readfds);
        FD_SET(ctx->tun_fd, &readfds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000; // 100ms timeout
        
        int ret = select(ctx->tun_fd + 1, &readfds, NULL, NULL, &tv);
        
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_TUN_ERROR("select() error: %s\n", strerror(errno));
            break;
        }
        
        if (ret == 0) {
            // Timeout, check halt flag
            continue;
        }
        
        if (FD_ISSET(ctx->tun_fd, &readfds)) {
            ssize_t n = read(ctx->tun_fd, buffer, sizeof(buffer));
            
            if (n < 0) {
                if (errno == EINTR || errno == EAGAIN) {
                    continue;
                }
                LOG_TUN_ERROR("read() error: %s\n", strerror(errno));
                break;
            }
            
            if (n == 0) {
                LOG_TUN_WARN("TUN device closed\n");
                break;
            }
            
            LOG_TUN_TRACE("Read %zd bytes from TUN\n", n);
            
            // Queue packet for GetNextPacket
            void *packet_data = Malloc(n);
            if (packet_data != NULL) {
                Copy(packet_data, buffer, n);
                
                Lock(ctx->queue_lock);
                {
                    BLOCK *block = NewBlock(packet_data, n, 0);
                    InsertQueue(ctx->recv_queue, block);
                }
                Unlock(ctx->queue_lock);
                
                Cancel(ctx->cancel);
            }
        }
    }
    
    LOG_TUN_DEBUG("Android TUN read thread exiting\n");
}

/*
 * Get next packet to send to VPN server
 */
void* AndroidTunGetNextPacket(PACKET_ADAPTER *pa, UINT *size) {
    if (pa == NULL || size == NULL) {
        return NULL;
    }
    
    AndroidTunContext *ctx = (AndroidTunContext*)pa->Param;
    if (ctx == NULL) {
        return NULL;
    }
    
    *size = 0;
    
    // Check queue for packets
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
 * Put packet received from VPN server
 */
bool AndroidTunPutPacket(PACKET_ADAPTER *pa, void *data, UINT size) {
    if (pa == NULL || data == NULL || size == 0) {
        return false;
    }
    
    AndroidTunContext *ctx = (AndroidTunContext*)pa->Param;
    if (ctx == NULL || ctx->tun_fd < 0) {
        return false;
    }
    
    LOG_TUN_TRACE("Writing %u bytes to TUN\n", size);
    
    // Write to TUN device
    ssize_t n = write(ctx->tun_fd, data, size);
    
    if (n < 0) {
        LOG_TUN_ERROR("write() error: %s\n", strerror(errno));
        return false;
    }
    
    if ((UINT)n != size) {
        LOG_TUN_WARN("Partial write: %zd/%u bytes\n", n, size);
        return false;
    }
    
    return true;
}

/*
 * Get adapter cancel handle
 */
CANCEL* AndroidTunGetCancel(PACKET_ADAPTER *pa) {
    if (pa == NULL) {
        return NULL;
    }
    
    AndroidTunContext *ctx = (AndroidTunContext*)pa->Param;
    if (ctx == NULL) {
        return NULL;
    }
    
    return ctx->cancel;
}

/*
 * Free Android TUN adapter
 */
void AndroidTunFree(PACKET_ADAPTER *pa) {
    if (pa == NULL) {
        return;
    }
    
    LOG_TUN_INFO("Freeing Android TUN adapter\n");
    
    AndroidTunContext *ctx = (AndroidTunContext*)pa->Param;
    if (ctx != NULL) {
        // Stop read thread
        ctx->halt = true;
        Cancel(ctx->cancel);
        
        if (ctx->read_thread != NULL) {
            WaitThread(ctx->read_thread, 5000);
            ReleaseThread(ctx->read_thread);
        }
        
        // Free synchronization objects
        if (ctx->cancel != NULL) {
            ReleaseCancel(ctx->cancel);
        }
        
        if (ctx->recv_queue != NULL) {
            // Free any remaining packets
            while (true) {
                BLOCK *block = GetNext(ctx->recv_queue);
                if (block == NULL) break;
                FreeBlock(block);
            }
            ReleaseQueue(ctx->recv_queue);
        }
        
        if (ctx->queue_lock != NULL) {
            DeleteLock(ctx->queue_lock);
        }
        
        // Note: TUN fd is managed by Java side, don't close it here
        
        Free(ctx);
    }
    
    Free(pa);
    LOG_TUN_INFO("Android TUN adapter freed\n");
}

/*
 * Create Android packet adapter
 */
PACKET_ADAPTER* NewAndroidPacketAdapter(SESSION *s) {
    if (s == NULL) {
        return NULL;
    }
    
    PACKET_ADAPTER *pa = (PACKET_ADAPTER*)ZeroMalloc(sizeof(PACKET_ADAPTER));
    if (pa == NULL) {
        return NULL;
    }
    
    pa->Init = AndroidTunInit;
    pa->GetNextPacket = AndroidTunGetNextPacket;
    pa->PutPacket = AndroidTunPutPacket;
    pa->GetCancel = AndroidTunGetCancel;
    pa->Free = AndroidTunFree;
    pa->Param = NULL;
    
    if (!pa->Init(s)) {
        Free(pa);
        return NULL;
    }
    
    return pa;
}
