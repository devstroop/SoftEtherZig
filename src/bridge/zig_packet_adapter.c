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
        .recv_queue_size = 8192,
        .send_queue_size = 4096,
        .packet_pool_size = 16384,
        .batch_size = 32,
        .device_name = "utun",
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
    
    // Store context in session
    s->PacketAdapter->Param = ctx;
    
    printf("[ZigAdapterInit] ✅ Initialization complete\n");
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
        // No packet available
        return 0;
    }
    
    if (packet_len == 0 || packet_len > 2048) {
        return 0;
    }
    
    // Allocate buffer for packet
    void* packet_copy = Malloc((UINT)packet_len);
    if (!packet_copy) {
        return 0;
    }
    
    // Copy packet data
    Copy(packet_copy, packet_data, (UINT)packet_len);
    *data = packet_copy;
    
    return (UINT)packet_len;
}

// Put packet for transmission
static bool ZigAdapterPutPacket(SESSION* s, void* data, UINT size) {
    if (!s || !s->PacketAdapter || !s->PacketAdapter->Param || !data || size == 0) {
        return false;
    }
    
    ZIG_ADAPTER_CONTEXT* ctx = (ZIG_ADAPTER_CONTEXT*)s->PacketAdapter->Param;
    
    if (ctx->halt) {
        return false;
    }
    
    // Send packet to Zig adapter
    return zig_adapter_put_packet(ctx->zig_adapter, (const uint8_t*)data, (uint64_t)size);
}

// Free adapter
static void ZigAdapterFree(SESSION* s) {
    printf("[ZigAdapterFree] Freeing Zig adapter\n");
    
    if (!s || !s->PacketAdapter || !s->PacketAdapter->Param) {
        return;
    }
    
    ZIG_ADAPTER_CONTEXT* ctx = (ZIG_ADAPTER_CONTEXT*)s->PacketAdapter->Param;
    ctx->halt = true;
    
    // Print final stats
    printf("[ZigAdapterFree] Final statistics:\n");
    zig_adapter_print_stats(ctx->zig_adapter);
    
    // Stop adapter
    zig_adapter_stop(ctx->zig_adapter);
    
    // Destroy Zig adapter
    zig_adapter_destroy(ctx->zig_adapter);
    
    // Release cancel
    if (ctx->cancel) {
        ReleaseCancel(ctx->cancel);
    }
    
    // Free context
    Free(ctx);
    
    printf("[ZigAdapterFree] ✅ Cleanup complete\n");
}
