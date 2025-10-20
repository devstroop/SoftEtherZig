// SoftEther VPN Zig Client - Windows Packet Adapter Implementation
// Uses Windows TAP-Windows6 adapter for packet forwarding

#ifdef _WIN32

#include "packet_adapter_windows.h"
#include "../../SoftEtherVPN/src/Mayaqua/Mayaqua.h"
#include "../../SoftEtherVPN/src/Cedar/Cedar.h"
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>

#define TUN_MTU 1500
#define MAX_PACKET_SIZE 2048
#define RECV_QUEUE_MAX 1024

// TAP-Windows6 IOCTL codes
#define TAP_WIN_IOCTL_GET_MAC               CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_GET_VERSION           CTL_CODE(FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_GET_MTU               CTL_CODE(FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_GET_INFO              CTL_CODE(FILE_DEVICE_UNKNOWN, 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT CTL_CODE(FILE_DEVICE_UNKNOWN, 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS      CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_CONFIG_DHCP_MASQ      CTL_CODE(FILE_DEVICE_UNKNOWN, 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_GET_LOG_LINE          CTL_CODE(FILE_DEVICE_UNKNOWN, 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT   CTL_CODE(FILE_DEVICE_UNKNOWN, 9, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Background thread for reading packets from TAP device
void WindowsTapReadThread(THREAD *t, void *param) {
    WINDOWS_TAP_CONTEXT *ctx = (WINDOWS_TAP_CONTEXT *)param;
    UCHAR buf[MAX_PACKET_SIZE];
    DWORD bytes_read;
    OVERLAPPED overlapped;
    
    printf("[WindowsTapReadThread] === THREAD STARTED === handle=%p\n", ctx->tap_handle);
    fflush(stdout);
    
    NoticeThreadInit(t);
    
    printf("[WindowsTapReadThread] Thread initialized, entering read loop\n");
    fflush(stdout);
    
    while (!ctx->halt) {
        // Setup overlapped I/O
        ZeroMemory(&overlapped, sizeof(overlapped));
        overlapped.hEvent = ctx->read_event;
        
        // Start async read
        BOOL result = ReadFile(ctx->tap_handle, buf, sizeof(buf), &bytes_read, &overlapped);
        
        if (!result) {
            DWORD error = GetLastError();
            if (error == ERROR_IO_PENDING) {
                // Wait for completion
                DWORD wait_result = WaitForSingleObject(ctx->read_event, 1000);
                if (wait_result == WAIT_TIMEOUT) {
                    continue;
                }
                if (wait_result != WAIT_OBJECT_0) {
                    break;
                }
                
                // Get result
                if (!GetOverlappedResult(ctx->tap_handle, &overlapped, &bytes_read, FALSE)) {
                    printf("[WindowsTapReadThread] Read error: %d\n", GetLastError());
                    break;
                }
            } else {
                printf("[WindowsTapReadThread] Read error: %d\n", error);
                break;
            }
        }
        
        if (bytes_read == 0) {
            continue;
        }
        
        // Allocate packet and copy data
        void *packet_data = Malloc(bytes_read);
        Copy(packet_data, buf, bytes_read);
        
        TUN_PACKET *pkt = ZeroMalloc(sizeof(TUN_PACKET));
        pkt->data = packet_data;
        pkt->size = bytes_read;
        
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
                printf("[WindowsTapReadThread] Queue full, dropping packet\n");
            }
        }
        Unlock(ctx->queue_lock);
        
        // Cancel any blocking waits
        if (ctx->cancel) {
            Cancel(ctx->cancel);
        }
    }
    
    printf("[WindowsTapReadThread] Exiting\n");
}

// Open a Windows TAP device
HANDLE OpenWindowsTapDevice(char *device_name, size_t device_name_size) {
    HANDLE handle = INVALID_HANDLE_VALUE;
    char adapter_id[256];
    char device_path[512];
    
    // TODO: Enumerate TAP adapters from registry
    // For now, use a common TAP device path
    // Registry path: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}
    
    // Try common TAP device name
    snprintf(device_path, sizeof(device_path), "\\\\.\\Global\\{GUID}.tap");
    
    printf("[OpenWindowsTapDevice] Attempting to open TAP device\n");
    
    // Open device
    handle = CreateFileA(
        device_path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
        NULL
    );
    
    if (handle == INVALID_HANDLE_VALUE) {
        printf("[OpenWindowsTapDevice] Failed to open TAP device: %d\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }
    
    // Set media status to connected
    DWORD status = 1;
    DWORD bytes_returned;
    if (!DeviceIoControl(handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                        &status, sizeof(status), &status, sizeof(status),
                        &bytes_returned, NULL)) {
        printf("[OpenWindowsTapDevice] Failed to set media status: %d\n", GetLastError());
        CloseHandle(handle);
        return INVALID_HANDLE_VALUE;
    }
    
    strncpy(device_name, "TAP-Windows6", device_name_size - 1);
    device_name[device_name_size - 1] = '\0';
    
    printf("[OpenWindowsTapDevice] TAP device opened successfully\n");
    return handle;
}

// Close TAP device
void CloseWindowsTapDevice(HANDLE handle) {
    if (handle != INVALID_HANDLE_VALUE) {
        printf("[CloseWindowsTapDevice] Closing TAP device\n");
        CloseHandle(handle);
    }
}

// PA_INIT callback - Initialize TAP device
bool WindowsTapInit(SESSION *s) {
    WINDOWS_TAP_CONTEXT *ctx;
    
    printf("[WindowsTapInit] === ENTER === session=%p\n", s);
    fflush(stdout);
    
    if (s == NULL || s->PacketAdapter == NULL) {
        printf("[WindowsTapInit] ERROR: invalid parameters\n");
        return false;
    }
    
    // Allocate context
    ctx = ZeroMalloc(sizeof(WINDOWS_TAP_CONTEXT));
    ctx->session = s;
    ctx->halt = false;
    
    // Open TAP device
    ctx->tap_handle = OpenWindowsTapDevice(ctx->device_name, sizeof(ctx->device_name));
    if (ctx->tap_handle == INVALID_HANDLE_VALUE) {
        printf("[WindowsTapInit] ERROR: Failed to open TAP device\n");
        Free(ctx);
        return false;
    }
    
    printf("[WindowsTapInit] TAP device opened: %s\n", ctx->device_name);
    
    // Create synchronization objects
    ctx->read_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    ctx->write_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    ctx->cancel = NewCancel();
    ctx->recv_queue = NewQueue();
    ctx->queue_lock = NewLock();
    
    // Start background read thread
    ctx->read_thread = NewThread(WindowsTapReadThread, ctx);
    WaitThreadInit(ctx->read_thread);
    
    // Store context
    s->PacketAdapter->Param = ctx;
    
    printf("[WindowsTapInit] === SUCCESS === TAP device: %s\n", ctx->device_name);
    return true;
}

// PA_GETCANCEL callback
CANCEL* WindowsTapGetCancel(SESSION *s) {
    WINDOWS_TAP_CONTEXT *ctx;
    
    if (s == NULL || s->PacketAdapter == NULL) {
        return NULL;
    }
    
    ctx = (WINDOWS_TAP_CONTEXT *)s->PacketAdapter->Param;
    return ctx ? ctx->cancel : NULL;
}

// PA_GETNEXTPACKET callback
UINT WindowsTapGetNextPacket(SESSION *s, void **data) {
    WINDOWS_TAP_CONTEXT *ctx;
    TUN_PACKET *pkt;
    UINT size = 0;
    
    if (s == NULL || s->PacketAdapter == NULL || data == NULL) {
        return 0;
    }
    
    ctx = (WINDOWS_TAP_CONTEXT *)s->PacketAdapter->Param;
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
bool WindowsTapPutPacket(SESSION *s, void *data, UINT size) {
    WINDOWS_TAP_CONTEXT *ctx;
    OVERLAPPED overlapped;
    DWORD bytes_written;
    
    if (s == NULL || s->PacketAdapter == NULL || data == NULL || size == 0) {
        return false;
    }
    
    ctx = (WINDOWS_TAP_CONTEXT *)s->PacketAdapter->Param;
    if (ctx == NULL || ctx->tap_handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    if (size > TUN_MTU) {
        printf("[WindowsTapPutPacket] Packet too large: %u bytes\n", size);
        return false;
    }
    
    // Setup overlapped I/O
    ZeroMemory(&overlapped, sizeof(overlapped));
    overlapped.hEvent = ctx->write_event;
    
    // Write packet
    BOOL result = WriteFile(ctx->tap_handle, data, size, &bytes_written, &overlapped);
    
    if (!result) {
        DWORD error = GetLastError();
        if (error == ERROR_IO_PENDING) {
            // Wait for completion
            if (WaitForSingleObject(ctx->write_event, 5000) != WAIT_OBJECT_0) {
                printf("[WindowsTapPutPacket] Write timeout\n");
                return false;
            }
            
            if (!GetOverlappedResult(ctx->tap_handle, &overlapped, &bytes_written, FALSE)) {
                printf("[WindowsTapPutPacket] Write error: %d\n", GetLastError());
                return false;
            }
        } else {
            printf("[WindowsTapPutPacket] Write error: %d\n", error);
            return false;
        }
    }
    
    ctx->bytes_sent += size;
    ctx->packets_sent++;
    
    return true;
}

// PA_FREE callback
void WindowsTapFree(SESSION *s) {
    WINDOWS_TAP_CONTEXT *ctx;
    TUN_PACKET *pkt;
    
    printf("[WindowsTapFree] Cleaning up Windows TAP adapter\n");
    
    if (s == NULL || s->PacketAdapter == NULL) {
        return;
    }
    
    ctx = (WINDOWS_TAP_CONTEXT *)s->PacketAdapter->Param;
    if (ctx == NULL) {
        return;
    }
    
    // Stop read thread
    ctx->halt = true;
    if (ctx->read_event) {
        SetEvent(ctx->read_event);
    }
    
    if (ctx->read_thread) {
        WaitThread(ctx->read_thread, 5000);
        ReleaseThread(ctx->read_thread);
    }
    
    // Close TAP device
    CloseWindowsTapDevice(ctx->tap_handle);
    
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
    if (ctx->read_event) {
        CloseHandle(ctx->read_event);
    }
    if (ctx->write_event) {
        CloseHandle(ctx->write_event);
    }
    
    printf("[WindowsTapFree] Statistics - Sent: %llu packets (%llu bytes), Received: %llu packets (%llu bytes)\n",
           ctx->packets_sent, ctx->bytes_sent, ctx->packets_received, ctx->bytes_received);
    
    Free(ctx);
    s->PacketAdapter->Param = NULL;
}

// Create a new Windows TAP packet adapter
PACKET_ADAPTER* NewWindowsTapAdapter() {
    PACKET_ADAPTER *pa;
    
    printf("[NewWindowsTapAdapter] Creating Windows TAP packet adapter\n");
    
    pa = NewPacketAdapter(
        WindowsTapInit,
        WindowsTapGetCancel,
        WindowsTapGetNextPacket,
        WindowsTapPutPacket,
        WindowsTapFree
    );
    
    if (pa) {
        pa->Id = PACKET_ADAPTER_ID_VLAN_WIN32;
        pa->Param = NULL;
        printf("[NewWindowsTapAdapter] Packet adapter created successfully\n");
    }
    
    return pa;
}

#endif // _WIN32
