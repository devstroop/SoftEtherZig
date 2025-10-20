// SoftEther VPN Zig Client - Linux Packet Adapter Implementation
// Uses Linux TUN/TAP interface for packet forwarding

#include "packet_adapter_linux.h"
#include "../../SoftEtherVPN/src/Mayaqua/Mayaqua.h"
#include "../../SoftEtherVPN/src/Cedar/Cedar.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define TUN_MTU 1500
#define MAX_PACKET_SIZE 2048
#define RECV_QUEUE_MAX 1024

// Background thread for reading packets from TUN device
void LinuxTunReadThread(THREAD *t, void *param) {
    LINUX_TUN_CONTEXT *ctx = (LINUX_TUN_CONTEXT *)param;
    UCHAR buf[MAX_PACKET_SIZE];
    
    printf("[LinuxTunReadThread] === THREAD STARTED === fd=%d\n", ctx->tun_fd);
    fflush(stdout);
    
    NoticeThreadInit(t);
    
    printf("[LinuxTunReadThread] Thread initialized, entering read loop\n");
    fflush(stdout);
    
    while (!ctx->halt) {
        // Read packet from TUN device (blocking)
        int n = read(ctx->tun_fd, buf, sizeof(buf));
        
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            printf("[LinuxTunReadThread] Read error: %s\n", strerror(errno));
            break;
        }
        
        if (n == 0) {
            printf("[LinuxTunReadThread] TUN device closed\n");
            break;
        }
        
        // TUN mode: no protocol header, direct IP packets
        // Allocate packet and copy data
        void *packet_data = Malloc(n);
        Copy(packet_data, buf, n);
        
        TUN_PACKET *pkt = ZeroMalloc(sizeof(TUN_PACKET));
        pkt->data = packet_data;
        pkt->size = n;
        
        // Add to receive queue
        Lock(ctx->queue_lock);
        {
            if (ctx->recv_queue->num_item < RECV_QUEUE_MAX) {
                InsertQueue(ctx->recv_queue, pkt);
                ctx->bytes_received += pkt->size;
                ctx->packets_received++;
            } else {
                // Queue full, drop packet
                Free(pkt->data);
                Free(pkt);
                printf("[LinuxTunReadThread] Queue full, dropping packet\n");
            }
        }
        Unlock(ctx->queue_lock);
        
        // Cancel any blocking waits
        if (ctx->cancel) {
            Cancel(ctx->cancel);
        }
    }
    
    printf("[LinuxTunReadThread] Exiting\n");
}

// Open a Linux TUN device
int OpenLinuxTunDevice(char *device_name, size_t device_name_size) {
    struct ifreq ifr;
    int fd;
    
    // Open /dev/net/tun
    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        printf("[OpenLinuxTunDevice] Failed to open /dev/net/tun: %s\n", strerror(errno));
        return -1;
    }
    
    // Configure TUN device
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN mode, no packet information
    
    // Let kernel assign device name (tun0, tun1, etc.)
    strncpy(ifr.ifr_name, "tun%d", IFNAMSIZ - 1);
    
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        printf("[OpenLinuxTunDevice] ioctl TUNSETIFF failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    // Get the assigned device name
    strncpy(device_name, ifr.ifr_name, device_name_size - 1);
    device_name[device_name_size - 1] = '\0';
    
    // Set non-blocking mode
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    
    printf("[OpenLinuxTunDevice] Created TUN device: %s (fd=%d)\n", device_name, fd);
    return fd;
}

// Close TUN device
void CloseLinuxTunDevice(int fd) {
    if (fd >= 0) {
        printf("[CloseLinuxTunDevice] Closing fd=%d\n", fd);
        close(fd);
    }
}

// PA_INIT callback - Initialize TUN device
bool LinuxTunInit(SESSION *s) {
    LINUX_TUN_CONTEXT *ctx;
    
    printf("[LinuxTunInit] === ENTER === session=%p\n", s);
    fflush(stdout);
    
    if (s == NULL || s->PacketAdapter == NULL) {
        printf("[LinuxTunInit] ERROR: invalid parameters\n");
        return false;
    }
    
    // Allocate context
    ctx = ZeroMalloc(sizeof(LINUX_TUN_CONTEXT));
    ctx->session = s;
    ctx->halt = false;
    
    // Open TUN device
    ctx->tun_fd = OpenLinuxTunDevice(ctx->device_name, sizeof(ctx->device_name));
    if (ctx->tun_fd < 0) {
        printf("[LinuxTunInit] ERROR: Failed to open TUN device\n");
        Free(ctx);
        return false;
    }
    
    printf("[LinuxTunInit] TUN device opened: %s (fd=%d)\n", ctx->device_name, ctx->tun_fd);
    
    // Create synchronization objects
    ctx->cancel = NewCancel();
    ctx->recv_queue = NewQueue();
    ctx->queue_lock = NewLock();
    
    // Start background read thread
    ctx->read_thread = NewThread(LinuxTunReadThread, ctx);
    WaitThreadInit(ctx->read_thread);
    
    // Store context
    s->PacketAdapter->Param = ctx;
    
    printf("[LinuxTunInit] === SUCCESS === TUN device: %s\n", ctx->device_name);
    return true;
}

// PA_GETCANCEL callback
CANCEL* LinuxTunGetCancel(SESSION *s) {
    LINUX_TUN_CONTEXT *ctx;
    
    if (s == NULL || s->PacketAdapter == NULL) {
        return NULL;
    }
    
    ctx = (LINUX_TUN_CONTEXT *)s->PacketAdapter->Param;
    return ctx ? ctx->cancel : NULL;
}

// PA_GETNEXTPACKET callback
UINT LinuxTunGetNextPacket(SESSION *s, void **data) {
    LINUX_TUN_CONTEXT *ctx;
    TUN_PACKET *pkt;
    UINT size = 0;
    
    if (s == NULL || s->PacketAdapter == NULL || data == NULL) {
        return 0;
    }
    
    ctx = (LINUX_TUN_CONTEXT *)s->PacketAdapter->Param;
    if (ctx == NULL) {
        return 0;
    }
    
    Lock(ctx->queue_lock);
    {
        pkt = (TUN_PACKET *)GetNext(ctx->recv_queue);
        if (pkt != NULL) {
            *data = pkt->data;
            size = pkt->size;
            Free(pkt);
        }
    }
    Unlock(ctx->queue_lock);
    
    return size;
}

// PA_PUTPACKET callback
bool LinuxTunPutPacket(SESSION *s, void *data, UINT size) {
    LINUX_TUN_CONTEXT *ctx;
    int n;
    
    if (s == NULL || s->PacketAdapter == NULL || data == NULL || size == 0) {
        return false;
    }
    
    ctx = (LINUX_TUN_CONTEXT *)s->PacketAdapter->Param;
    if (ctx == NULL || ctx->tun_fd < 0) {
        return false;
    }
    
    if (size > TUN_MTU) {
        printf("[LinuxTunPutPacket] Packet too large: %u bytes\n", size);
        return false;
    }
    
    // Write packet directly (no protocol header in TUN mode with IFF_NO_PI)
    n = write(ctx->tun_fd, data, size);
    if (n < 0) {
        if (errno != EINTR && errno != EAGAIN) {
            printf("[LinuxTunPutPacket] Write error: %s\n", strerror(errno));
            return false;
        }
        return true; // Temporary error
    }
    
    ctx->bytes_sent += size;
    ctx->packets_sent++;
    
    return true;
}

// PA_FREE callback
void LinuxTunFree(SESSION *s) {
    LINUX_TUN_CONTEXT *ctx;
    TUN_PACKET *pkt;
    
    printf("[LinuxTunFree] Cleaning up Linux TUN adapter\n");
    
    if (s == NULL || s->PacketAdapter == NULL) {
        return;
    }
    
    ctx = (LINUX_TUN_CONTEXT *)s->PacketAdapter->Param;
    if (ctx == NULL) {
        return;
    }
    
    // Stop read thread
    ctx->halt = true;
    if (ctx->cancel) {
        Cancel(ctx->cancel);
    }
    
    if (ctx->read_thread) {
        WaitThread(ctx->read_thread, 5000);
        ReleaseThread(ctx->read_thread);
    }
    
    // Close TUN device
    CloseLinuxTunDevice(ctx->tun_fd);
    
    // Free queued packets
    if (ctx->recv_queue) {
        Lock(ctx->queue_lock);
        {
            while ((pkt = (TUN_PACKET *)GetNext(ctx->recv_queue)) != NULL) {
                Free(pkt->data);
                Free(pkt);
            }
        }
        Unlock(ctx->queue_lock);
        ReleaseQueue(ctx->recv_queue);
    }
    
    // Free synchronization objects
    if (ctx->queue_lock) {
        DeleteLock(ctx->queue_lock);
    }
    if (ctx->cancel) {
        ReleaseCancel(ctx->cancel);
    }
    
    printf("[LinuxTunFree] Statistics - Sent: %llu packets (%llu bytes), Received: %llu packets (%llu bytes)\n",
           ctx->packets_sent, ctx->bytes_sent, ctx->packets_received, ctx->bytes_received);
    
    Free(ctx);
    s->PacketAdapter->Param = NULL;
}

// Create a new Linux TUN packet adapter
PACKET_ADAPTER* NewLinuxTunAdapter() {
    PACKET_ADAPTER *pa;
    
    printf("[NewLinuxTunAdapter] Creating Linux TUN packet adapter\n");
    
    pa = NewPacketAdapter(
        LinuxTunInit,
        LinuxTunGetCancel,
        LinuxTunGetNextPacket,
        LinuxTunPutPacket,
        LinuxTunFree
    );
    
    if (pa) {
        pa->Id = PACKET_ADAPTER_ID_VLAN_WIN32;
        pa->Param = NULL;
        printf("[NewLinuxTunAdapter] Packet adapter created successfully\n");
    }
    
    return pa;
}
