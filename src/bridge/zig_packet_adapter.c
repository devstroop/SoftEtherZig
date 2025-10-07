// Zig Packet Adapter - C Wrapper Implementation
// Wraps Zig packet adapter to provide SoftEther PACKET_ADAPTER interface

#include "zig_packet_adapter.h"
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Forward declarations of SoftEther callbacks
static bool ZigAdapterInit(SESSION* s);
static CANCEL* ZigAdapterGetCancel(SESSION* s);
static UINT ZigAdapterGetNextPacket(SESSION* s, void** data);
static bool ZigAdapterPutPacket(SESSION* s, void* data, UINT size);
static void ZigAdapterFree(SESSION* s);

// Create new Zig packet adapter
PACKET_ADAPTER* NewZigPacketAdapter(void) {
    printf("[NewZigPacketAdapter] Creating Zig packet adapter\n");
    
    // Allocate PACKET_ADAPTER structure
    PACKET_ADAPTER* pa = ZeroMalloc(sizeof(PACKET_ADAPTER));
    if (!pa) {
        printf("[NewZigPacketAdapter] Failed to allocate PACKET_ADAPTER\n");
        return NULL;
    }
    
    // Set up callbacks
    pa->Init = ZigAdapterInit;
    pa->GetCancel = ZigAdapterGetCancel;
    pa->GetNextPacket = ZigAdapterGetNextPacket;
    pa->PutPacket = ZigAdapterPutPacket;
    pa->Free = ZigAdapterFree;
    
    // Generate unique ID
    static UINT next_id = 1;
    pa->Id = next_id++;
    
    printf("[NewZigPacketAdapter] Created adapter with callbacks, Id=%u\n", pa->Id);
    return pa;
}

// Initialize adapter
static bool ZigAdapterInit(SESSION* s) {
    printf("[ZigAdapterInit] Initializing Zig adapter for session %p\n", s);
    
    if (!s) {
        printf("[ZigAdapterInit] ERROR: Session is NULL\n");
        return false;
    }
    
    // Allocate context
    ZIG_ADAPTER_CONTEXT* ctx = ZeroMalloc(sizeof(ZIG_ADAPTER_CONTEXT));
    if (!ctx) {
        printf("[ZigAdapterInit] Failed to allocate context\n");
        return false;
    }
    
    ctx->session = s;
    ctx->halt = false;
    
    // Create cancel handle
    ctx->cancel = NewCancel();
    if (!ctx->cancel) {
        printf("[ZigAdapterInit] Failed to create cancel handle\n");
        Free(ctx);
        return false;
    }
    
    // Configure Zig adapter
    ZigAdapterConfig config = {
        .recv_queue_size = 512,
        .send_queue_size = 256,
        .packet_pool_size = 2,  // Start with just 2 packets (4KB total)
        .batch_size = 32,
        .device_name = "utun",
        .device_name_len = 4,  // MUST match device_name string length
    };
    
    printf("[ZigAdapterInit] Creating Zig adapter with config: recv_q=%llu, send_q=%llu, pool=%llu, batch=%llu\n",
           config.recv_queue_size, config.send_queue_size, config.packet_pool_size, config.batch_size);
    
    // Create Zig adapter
    ctx->zig_adapter = zig_adapter_create(&config);
    if (!ctx->zig_adapter) {
        printf("[ZigAdapterInit] Failed to create Zig adapter\n");
        ReleaseCancel(ctx->cancel);
        Free(ctx);
        return false;
    }
    
    printf("[ZigAdapterInit] Zig adapter created at %p\n", ctx->zig_adapter);
    
    // Open TUN device
    if (!zig_adapter_open(ctx->zig_adapter)) {
        printf("[ZigAdapterInit] Failed to open TUN device\n");
        zig_adapter_destroy(ctx->zig_adapter);
        ReleaseCancel(ctx->cancel);
        Free(ctx);
        return false;
    }
    
    printf("[ZigAdapterInit] TUN device opened successfully\n");
    
    // Start adapter threads
    if (!zig_adapter_start(ctx->zig_adapter)) {
        printf("[ZigAdapterInit] Failed to start adapter threads\n");
        zig_adapter_destroy(ctx->zig_adapter);
        ReleaseCancel(ctx->cancel);
        Free(ctx);
        return false;
    }
    
    printf("[ZigAdapterInit] Zig adapter started successfully\n");
    
    // Configure interface with static IP from VPN range
    // Use 10.21.0.50 as client IP, 10.21.0.1 as gateway
    // This allows OS to accept broadcast packets and send responses
    printf("[ZigAdapterInit] Configuring interface with static IP from VPN range\n");
    
    // Get device name for ifconfig
    uint8_t dev_name_buf[64];
    uint64_t dev_name_len = zig_adapter_get_device_name(ctx->zig_adapter, dev_name_buf, sizeof(dev_name_buf));
    if (dev_name_len > 0 && dev_name_len < sizeof(dev_name_buf)) {
        dev_name_buf[dev_name_len] = '\0';  // Null terminate
        
        // Configure with VPN network IP: 10.21.0.50 with gateway 10.21.0.1
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ifconfig %s 10.21.0.50 10.21.0.1 netmask 255.255.0.0 up", (char*)dev_name_buf);
        printf("[●] ADAPTER: Executing: %s\n", cmd);
        int ret = system(cmd);
        if (ret != 0) {
            printf("[ZigAdapterInit] Warning: Failed to configure interface (ret=%d)\n", ret);
        } else {
            printf("[●] ADAPTER: Interface %s configured with 10.21.0.50\n", (char*)dev_name_buf);
        }
        
        // Add route to VPN network
        snprintf(cmd, sizeof(cmd), "route add -net 10.21.0.0/16 10.21.0.1 2>/dev/null");
        printf("[●] ADAPTER: Adding route: %s\n", cmd);
        system(cmd);
    }
    
    // Store context in session
    s->PacketAdapter->Param = ctx;
    
    printf("[ZigAdapterInit] ✅ Initialization complete - interface ready!\n");
    return true;
}

// Get cancel handle
static CANCEL* ZigAdapterGetCancel(SESSION* s) {
    if (!s || !s->PacketAdapter || !s->PacketAdapter->Param) {
        return NULL;
    }
    
    ZIG_ADAPTER_CONTEXT* ctx = (ZIG_ADAPTER_CONTEXT*)s->PacketAdapter->Param;
    return ctx->cancel;
}

// Get next packet (single packet mode - for compatibility)
static UINT ZigAdapterGetNextPacket(SESSION* s, void** data) {
    static uint64_t get_count = 0;
    
    if (!s || !s->PacketAdapter || !s->PacketAdapter->Param) {
        return 0;
    }
    
    ZIG_ADAPTER_CONTEXT* ctx = (ZIG_ADAPTER_CONTEXT*)s->PacketAdapter->Param;
    
    if (ctx->halt) {
        return 0;
    }
    
    // Get packet from Zig adapter
    uint8_t* packet_data = NULL;
    uint64_t packet_len = 0;
    
    if (!zig_adapter_get_packet(ctx->zig_adapter, &packet_data, &packet_len)) {
        // No packet available (this is normal - polled frequently)
        return 0;
    }
    
    // Log first few successful gets
    if (get_count < 5) {
        printf("[ZigAdapterGetNextPacket] Got packet #%llu, len=%llu\n", get_count, packet_len);
    } else if (get_count % 100 == 0) {
        printf("[ZigAdapterGetNextPacket] Packet #%llu, len=%llu\n", get_count, packet_len);
    }
    get_count++;
    
    if (packet_len == 0 || packet_len > 2048) {
        // Release the packet buffer even if invalid
        printf("[ZigAdapterGetNextPacket] Invalid packet length %llu, dropping\n", packet_len);
        zig_adapter_release_packet(ctx->zig_adapter, packet_data);
        return 0;
    }
    
    // Allocate buffer for packet
    void* packet_copy = Malloc((UINT)packet_len);
    if (!packet_copy) {
        // Release the packet buffer on allocation failure
        zig_adapter_release_packet(ctx->zig_adapter, packet_data);
        return 0;
    }
    
    // Copy packet data
    Copy(packet_copy, packet_data, (UINT)packet_len);
    *data = packet_copy;
    
    // CRITICAL: Release Zig buffer after copying to prevent leak
    zig_adapter_release_packet(ctx->zig_adapter, packet_data);
    
    return (UINT)packet_len;
}

// Put packet for transmission
static bool ZigAdapterPutPacket(SESSION* s, void* data, UINT size) {
    static uint64_t packet_count = 0;
    
    if (!s || !s->PacketAdapter || !s->PacketAdapter->Param) {
        return false;
    }
    
    ZIG_ADAPTER_CONTEXT* ctx = (ZIG_ADAPTER_CONTEXT*)s->PacketAdapter->Param;
    
    if (ctx->halt) {
        return false;
    }
    
    // NULL packet is a flush operation (SoftEther API design)
    if (!data || size == 0) {
        if (packet_count % 100 == 0) {
            printf("[ZigAdapterPutPacket] Flush operation (count=%llu)\n", packet_count);
        }
        packet_count++;
        return true; // Success: flush acknowledged
    }
    
    // Log first few packets for debugging
    if (packet_count < 5) {
        printf("[ZigAdapterPutPacket] Sending packet #%llu, size=%u\n", packet_count, size);
    } else if (packet_count % 100 == 0) {
        printf("[ZigAdapterPutPacket] Packet #%llu, size=%u\n", packet_count, size);
    }
    packet_count++;
    
    // Send packet to Zig adapter
    return zig_adapter_put_packet(ctx->zig_adapter, (const uint8_t*)data, (uint64_t)size);
}

// Free adapter
static void ZigAdapterFree(SESSION* s) {
    printf("[ZigAdapterFree] Freeing Zig adapter\n");
    
    if (!s || !s->PacketAdapter || !s->PacketAdapter->Param) {
        printf("[ZigAdapterFree] Already freed or NULL\n");
        return;
    }
    
    ZIG_ADAPTER_CONTEXT* ctx = (ZIG_ADAPTER_CONTEXT*)s->PacketAdapter->Param;
    
    printf("[ZigAdapterFree] ctx=%p, zig_adapter=%p, cancel=%p\n", 
           (void*)ctx, (void*)ctx->zig_adapter, (void*)ctx->cancel);
    
    // Clear pointer FIRST to prevent double-free
    s->PacketAdapter->Param = NULL;
    
    ctx->halt = true;
    
    // Print final stats
    printf("[ZigAdapterFree] Final statistics:\n");
    zig_adapter_print_stats(ctx->zig_adapter);
    
    // Stop adapter
    printf("[ZigAdapterFree] Stopping adapter...\n");
    zig_adapter_stop(ctx->zig_adapter);
    
    // Destroy Zig adapter
    printf("[ZigAdapterFree] Destroying adapter...\n");
    zig_adapter_destroy(ctx->zig_adapter);
    ctx->zig_adapter = NULL;
    
    // NOTE: Don't release cancel here - SoftEther manages it via s->Cancel2
    // ReleaseCancel would cause a double-free since SoftEther calls ReleaseCancel(s->Cancel2)
    // in SessionMain cleanup (Session.c line ~772)
    ctx->cancel = NULL;
    
    // Free context
    printf("[ZigAdapterFree] Freeing context at %p...\n", (void*)ctx);
    Free(ctx);
    printf("[ZigAdapterFree] Context freed successfully\n");
    
    printf("[ZigAdapterFree] ✅ Cleanup complete\n");
}
