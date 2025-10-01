// SoftEther VPN Zig Client - macOS Packet Adapter Implementation
// Uses macOS utun kernel interface for packet forwarding

#include "packet_adapter_macos.h"
#include "../../SoftEtherVPN_Stable/src/Mayaqua/Mayaqua.h"
#include "../../SoftEtherVPN_Stable/src/Cedar/Cedar.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#define TUN_MTU 1500
#define MAX_PACKET_SIZE 2048
#define RECV_QUEUE_MAX 1024

// Background thread for reading packets from TUN device
void MacOsTunReadThread(THREAD *t, void *param) {
    MACOS_TUN_CONTEXT *ctx = (MACOS_TUN_CONTEXT *)param;
    UCHAR buf[MAX_PACKET_SIZE];
    
    printf("[MacOsTunReadThread] === THREAD STARTED === fd=%d\n", ctx->tun_fd);
    fflush(stdout);
    
    // Signal thread is initialized
    printf("[MacOsTunReadThread] About to call NoticeThreadInit()...\n");
    fflush(stdout);
    
    NoticeThreadInit(t);
    
    printf("[MacOsTunReadThread] NoticeThreadInit() called, entering read loop\n");
    fflush(stdout);
    
    while (!ctx->halt) {
        // Read packet from TUN device (blocking)
        int n = read(ctx->tun_fd, buf, sizeof(buf));
        
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            printf("[MacOsTunReadThread] Read error: %s\n", strerror(errno));
            break;
        }
        
        if (n == 0) {
            printf("[MacOsTunReadThread] TUN device closed\n");
            break;
        }
        
        // Skip 4-byte protocol header (AF_INET/AF_INET6)
        if (n < 4) {
            continue;
        }
        
        // Allocate packet and copy data
        void *packet_data = Malloc(n - 4);
        Copy(packet_data, buf + 4, n - 4);
        
        TUN_PACKET *pkt = ZeroMalloc(sizeof(TUN_PACKET));
        pkt->data = packet_data;
        pkt->size = n - 4;
        
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
                printf("[MacOsTunReadThread] Queue full, dropping packet\n");
            }
        }
        Unlock(ctx->queue_lock);
        
        // Cancel any blocking waits
        if (ctx->cancel) {
            Cancel(ctx->cancel);
        }
    }
    
    printf("[MacOsTunReadThread] Exiting\n");
}

// Open a macOS TUN device using utun kernel control interface
int OpenMacOsTunDevice(char *device_name, size_t device_name_size) {
    struct sockaddr_ctl addr;
    struct ctl_info info;
    int fd = -1;
    int unit_number;
    
    // Get utun control ID first (only need to do this once)
    int temp_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (temp_fd < 0) {
        printf("[OpenMacOsTunDevice] Failed to create socket: %s\n", strerror(errno));
        return -1;
    }
    
    Zero(&info, sizeof(info));
    StrCpy(info.ctl_name, sizeof(info.ctl_name), UTUN_CONTROL_NAME);
    
    if (ioctl(temp_fd, CTLIOCGINFO, &info) < 0) {
        printf("[OpenMacOsTunDevice] ioctl CTLIOCGINFO failed: %s\n", strerror(errno));
        close(temp_fd);
        return -1;
    }
    close(temp_fd);
    
    // Try to connect to utun devices (0-15)
    // Start from 0 and find the first available one
    for (unit_number = 0; unit_number < 16; unit_number++) {
        // Create socket for kernel control
        fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd < 0) {
            printf("[OpenMacOsTunDevice] Failed to create socket for utun%d: %s\n", 
                   unit_number, strerror(errno));
            continue;
        }
        
        // Connect to utun kernel control
        Zero(&addr, sizeof(addr));
        addr.sc_len = sizeof(addr);
        addr.sc_family = AF_SYSTEM;
        addr.ss_sysaddr = AF_SYS_CONTROL;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = unit_number + 1; // utun0 = 1, utun1 = 2, etc.
        
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            printf("[OpenMacOsTunDevice] utun%d busy (%s), trying next...\n", 
                   unit_number, strerror(errno));
            close(fd);
            fd = -1;
            continue;
        }
        
        // Successfully connected!
        printf("[OpenMacOsTunDevice] Successfully connected to utun%d\n", unit_number);
        break;
    }
    
    if (fd < 0) {
        printf("[OpenMacOsTunDevice] Failed to find available utun device\n");
        return -1;
    }
    
    // Get the device name
    socklen_t optlen = (socklen_t)device_name_size;
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, device_name, &optlen) < 0) {
        printf("[OpenMacOsTunDevice] getsockopt UTUN_OPT_IFNAME failed: %s\n", strerror(errno));
        StrCpy(device_name, device_name_size, "utun?");
    }
    
    // Set non-blocking mode
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    
    printf("[OpenMacOsTunDevice] Created TUN device: %s (fd=%d)\n", device_name, fd);
    return fd;
}

// Close TUN device
void CloseMacOsTunDevice(int fd) {
    if (fd >= 0) {
        printf("[CloseMacOsTunDevice] Closing fd=%d\n", fd);
        close(fd);
    }
}

// PA_INIT callback - Initialize TUN device
bool MacOsTunInit(SESSION *s) {
    MACOS_TUN_CONTEXT *ctx;
    
    printf("[MacOsTunInit] === ENTER === session=%p\n", s);
    fflush(stdout);
    
    if (s == NULL) {
        printf("[MacOsTunInit] ERROR: session is NULL\n");
        fflush(stdout);
        return false;
    }
    
    if (s->PacketAdapter == NULL) {
        printf("[MacOsTunInit] ERROR: PacketAdapter is NULL\n");
        fflush(stdout);
        return false;
    }
    
    if (s->PacketAdapter->Param != NULL) {
        printf("[MacOsTunInit] ERROR: Param already set\n");
        fflush(stdout);
        return false;
    }
    
    printf("[MacOsTunInit] Validation passed, allocating context\n");
    fflush(stdout);
    
    // Allocate context
    printf("[MacOsTunInit] Allocating context structure\n");
    fflush(stdout);
    ctx = ZeroMalloc(sizeof(MACOS_TUN_CONTEXT));
    ctx->session = s;
    ctx->halt = false;
    printf("[MacOsTunInit] Context allocated at %p\n", ctx);
    fflush(stdout);
    
    // Open TUN device
    printf("[MacOsTunInit] Opening TUN device...\n");
    fflush(stdout);
    ctx->tun_fd = OpenMacOsTunDevice(ctx->device_name, sizeof(ctx->device_name));
    if (ctx->tun_fd < 0) {
        printf("[MacOsTunInit] ERROR: Failed to open TUN device\n");
        fflush(stdout);
        Free(ctx);
        return false;
    }
    printf("[MacOsTunInit] TUN device opened: %s (fd=%d)\n", ctx->device_name, ctx->tun_fd);
    fflush(stdout);
    
    // Create synchronization objects
    printf("[MacOsTunInit] Creating synchronization objects...\n");
    fflush(stdout);
    ctx->cancel = NewCancel();
    printf("[MacOsTunInit] Cancel created\n");
    fflush(stdout);
    ctx->recv_queue = NewQueue();
    printf("[MacOsTunInit] Queue created\n");
    fflush(stdout);
    ctx->queue_lock = NewLock();
    printf("[MacOsTunInit] Lock created\n");
    fflush(stdout);
    
    // Start background read thread
    printf("[MacOsTunInit] Starting background read thread...\n");
    fflush(stdout);
    ctx->read_thread = NewThread(MacOsTunReadThread, ctx);
    printf("[MacOsTunInit] NewThread returned, waiting for init...\n");
    fflush(stdout);
    WaitThreadInit(ctx->read_thread);
    printf("[MacOsTunInit] Thread initialized\n");
    fflush(stdout);
    
    // Store context in packet adapter
    s->PacketAdapter->Param = ctx;
    
    printf("[MacOsTunInit] === SUCCESS === TUN device: %s\n", ctx->device_name);
    fflush(stdout);
    return true;
}

// PA_GETCANCEL callback - Get cancellation object
CANCEL* MacOsTunGetCancel(SESSION *s) {
    MACOS_TUN_CONTEXT *ctx;
    
    if (s == NULL || s->PacketAdapter == NULL) {
        return NULL;
    }
    
    ctx = (MACOS_TUN_CONTEXT *)s->PacketAdapter->Param;
    if (ctx == NULL) {
        return NULL;
    }
    
    return ctx->cancel;
}

// PA_GETNEXTPACKET callback - Get next packet from TUN device
UINT MacOsTunGetNextPacket(SESSION *s, void **data) {
    MACOS_TUN_CONTEXT *ctx;
    TUN_PACKET *pkt;
    UINT size = 0;
    
    if (s == NULL || s->PacketAdapter == NULL || data == NULL) {
        return 0;
    }
    
    ctx = (MACOS_TUN_CONTEXT *)s->PacketAdapter->Param;
    if (ctx == NULL) {
        return 0;
    }
    
    // Try to get packet from queue
    Lock(ctx->queue_lock);
    {
        pkt = (TUN_PACKET *)GetNext(ctx->recv_queue);
        if (pkt != NULL) {
            *data = pkt->data;
            size = pkt->size;
            Free(pkt); // Free wrapper, but data is returned to caller
        }
    }
    Unlock(ctx->queue_lock);
    
    return size;
}

// PA_PUTPACKET callback - Send packet to TUN device
bool MacOsTunPutPacket(SESSION *s, void *data, UINT size) {
    MACOS_TUN_CONTEXT *ctx;
    UCHAR buf[MAX_PACKET_SIZE];
    int n;
    
    if (s == NULL || s->PacketAdapter == NULL || data == NULL || size == 0) {
        return false;
    }
    
    ctx = (MACOS_TUN_CONTEXT *)s->PacketAdapter->Param;
    if (ctx == NULL || ctx->tun_fd < 0) {
        return false;
    }
    
    if (size > TUN_MTU) {
        printf("[MacOsTunPutPacket] Packet too large: %u bytes\n", size);
        return false;
    }
    
    // Determine IP version from packet
    UCHAR *pkt = (UCHAR *)data;
    UINT32 proto;
    
    if (size > 0 && (pkt[0] & 0xF0) == 0x40) {
        // IPv4
        proto = htonl(AF_INET);
    } else if (size > 0 && (pkt[0] & 0xF0) == 0x60) {
        // IPv6
        proto = htonl(AF_INET6);
    } else {
        printf("[MacOsTunPutPacket] Unknown protocol version\n");
        return false;
    }
    
    // Write protocol header + packet
    Copy(buf, &proto, 4);
    Copy(buf + 4, data, size);
    
    n = write(ctx->tun_fd, buf, size + 4);
    if (n < 0) {
        if (errno != EINTR && errno != EAGAIN) {
            printf("[MacOsTunPutPacket] Write error: %s\n", strerror(errno));
            return false;
        }
        return true; // Temporary error, consider success
    }
    
    ctx->bytes_sent += size;
    ctx->packets_sent++;
    
    return true;
}

// PA_FREE callback - Cleanup TUN device
void MacOsTunFree(SESSION *s) {
    MACOS_TUN_CONTEXT *ctx;
    TUN_PACKET *pkt;
    
    printf("[MacOsTunFree] Cleaning up macOS TUN adapter\n");
    
    if (s == NULL || s->PacketAdapter == NULL) {
        return;
    }
    
    ctx = (MACOS_TUN_CONTEXT *)s->PacketAdapter->Param;
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
    CloseMacOsTunDevice(ctx->tun_fd);
    
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
    
    printf("[MacOsTunFree] Statistics - Sent: %llu packets (%llu bytes), Received: %llu packets (%llu bytes)\n",
           ctx->packets_sent, ctx->bytes_sent, ctx->packets_received, ctx->bytes_received);
    
    Free(ctx);
    s->PacketAdapter->Param = NULL;
    
    printf("[MacOsTunFree] Cleanup complete\n");
}

// Create a new macOS TUN packet adapter
PACKET_ADAPTER* NewMacOsTunAdapter() {
    PACKET_ADAPTER *pa;
    
    printf("[NewMacOsTunAdapter] Creating macOS TUN packet adapter\n");
    fflush(stdout);
    
    printf("[NewMacOsTunAdapter] Calling NewPacketAdapter with callbacks:\n");
    printf("  Init=%p, GetCancel=%p, GetNext=%p, Put=%p, Free=%p\n",
           MacOsTunInit, MacOsTunGetCancel, MacOsTunGetNextPacket,
           MacOsTunPutPacket, MacOsTunFree);
    fflush(stdout);
    
    pa = NewPacketAdapter(
        MacOsTunInit,
        MacOsTunGetCancel,
        MacOsTunGetNextPacket,
        MacOsTunPutPacket,
        MacOsTunFree
    );
    
    printf("[NewMacOsTunAdapter] NewPacketAdapter returned: %p\n", pa);
    fflush(stdout);
    
    if (pa) {
        pa->Id = PACKET_ADAPTER_ID_VLAN_WIN32; // Reuse ID since it's just for tracking
        pa->Param = NULL; // Will be set in Init callback
        printf("[NewMacOsTunAdapter] Set pa->Id=%u, pa->Param=%p\n", pa->Id, pa->Param);
        printf("[NewMacOsTunAdapter] Packet adapter created successfully\n");
        fflush(stdout);
    } else {
        printf("[NewMacOsTunAdapter] Failed to create packet adapter\n");
        fflush(stdout);
    }
    
    return pa;
}
