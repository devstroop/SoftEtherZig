// SoftEther VPN - Zig Packet Adapter Bridge
// Integrates high-performance Zig adapter with C SoftEther VPN

#include <GlobalConst.h>

#ifdef BRIDGE_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

// Forward declarations for Zig adapter (defined in adapter.zig)
typedef struct ZigPacketAdapter ZigPacketAdapter;

typedef struct {
    size_t recv_queue_size;
    size_t send_queue_size;
    size_t packet_pool_size;
    size_t batch_size;
    const char *device_name;
} ZigAdapterConfig;

// External Zig functions
extern ZigPacketAdapter* zig_adapter_create(const ZigAdapterConfig *config);
extern void zig_adapter_destroy(ZigPacketAdapter *adapter);
extern bool zig_adapter_open(ZigPacketAdapter *adapter);
extern bool zig_adapter_start(ZigPacketAdapter *adapter);
extern void zig_adapter_stop(ZigPacketAdapter *adapter);
extern bool zig_adapter_get_packet(ZigPacketAdapter *adapter, unsigned char **out_data, size_t *out_len);
extern bool zig_adapter_put_packet(ZigPacketAdapter *adapter, const unsigned char *data, size_t len);
extern void zig_adapter_print_stats(ZigPacketAdapter *adapter);

// Wrapper structure for SoftEther integration
typedef struct ZIG_BRIDGE_SESSION {
    ZigPacketAdapter *adapter;
    CANCEL *cancel;
    volatile bool running;
} ZIG_BRIDGE_SESSION;

// PA_INIT callback - Initialize the adapter
// Signature: typedef bool (PA_INIT)(SESSION *s);
static bool ZigBridgeInit(SESSION *s)
{
    ZIG_BRIDGE_SESSION *zbs = NULL;
    ZigAdapterConfig config;
    
    printf("[ZigBridge] Initializing Zig packet adapter for session %s\n", 
           s->Name ? s->Name : "unknown");
    
    // Allocate session structure
    zbs = ZeroMalloc(sizeof(ZIG_BRIDGE_SESSION));
    if (zbs == NULL) {
        printf("[ZigBridge] ERROR: Failed to allocate session structure\n");
        return false;
    }
    
    // Configure Zig adapter with optimized settings
    config.recv_queue_size = 65536;  // 64K starting (scales to 128K)
    config.send_queue_size = 32768;  // 32K starting (scales to 128K)
    config.packet_pool_size = 131072; // 128K pre-allocated
    config.batch_size = 256;
    config.device_name = "utun";
    
    // Create Zig adapter
    printf("[ZigBridge] Creating Zig adapter with dynamic adaptive scaling...\n");
    zbs->adapter = zig_adapter_create(&config);
    if (zbs->adapter == NULL) {
        printf("[ZigBridge] ERROR: Failed to create Zig adapter\n");
        Free(zbs);
        return false;
    }
    
    // Open TUN device
    printf("[ZigBridge] Opening TUN device...\n");
    if (!zig_adapter_open(zbs->adapter)) {
        printf("[ZigBridge] ERROR: Failed to open TUN device\n");
        zig_adapter_destroy(zbs->adapter);
        Free(zbs);
        return false;
    }
    
    // Start I/O threads (including adaptive monitor thread)
    printf("[ZigBridge] Starting I/O threads...\n");
    if (!zig_adapter_start(zbs->adapter)) {
        printf("[ZigBridge] ERROR: Failed to start I/O threads\n");
        zig_adapter_destroy(zbs->adapter);
        Free(zbs);
        return false;
    }
    
    // Create cancel event
    zbs->cancel = NewCancel();
    zbs->running = true;
    
    // Store in session
    s->PacketAdapter->Param = zbs;
    
    printf("[ZigBridge] ✅ Zig adapter initialized successfully\n");
    printf("[ZigBridge] 🚀 Dynamic adaptive buffer scaling: 1K→128K\n");
    printf("[ZigBridge] 📊 Monitor thread active (1ms polling)\n");
    printf("[ZigBridge] 🔥 Performance optimizations enabled\n");
    
    return true;
}

// PA_GETCANCEL callback - Get cancel event
// Signature: typedef CANCEL *(PA_GETCANCEL)(SESSION *s);
static CANCEL* ZigBridgeGetCancel(SESSION *s)
{
    ZIG_BRIDGE_SESSION *zbs = (ZIG_BRIDGE_SESSION*)s->PacketAdapter->Param;
    if (zbs == NULL) {
        return NULL;
    }
    return zbs->cancel;
}

// PA_GETNEXTPACKET callback - Get next packet from adapter
// Signature: typedef UINT (PA_GETNEXTPACKET)(SESSION *s, void **data);
static UINT ZigBridgeGetNextPacket(SESSION *s, void **data)
{
    ZIG_BRIDGE_SESSION *zbs = (ZIG_BRIDGE_SESSION*)s->PacketAdapter->Param;
    unsigned char *packet_data = NULL;
    size_t packet_len = 0;
    
    if (zbs == NULL || !zbs->running) {
        return INFINITE;
    }
    
    // Try to get packet from Zig adapter
    if (!zig_adapter_get_packet(zbs->adapter, &packet_data, &packet_len)) {
        // No packet available - poll again after short delay
        return 0;
    }
    
    // Allocate memory for SoftEther (it will free this)
    void *copy = Malloc(packet_len);
    if (copy == NULL) {
        return INFINITE;
    }
    
    // Copy packet data
    Copy(copy, packet_data, packet_len);
    *data = copy;
    
    return (UINT)packet_len;
}

// PA_PUTPACKET callback - Put packet to adapter for transmission
// Signature: typedef bool (PA_PUTPACKET)(SESSION *s, void *data, UINT size);
static bool ZigBridgePutPacket(SESSION *s, void *data, UINT size)
{
    ZIG_BRIDGE_SESSION *zbs = (ZIG_BRIDGE_SESSION*)s->PacketAdapter->Param;
    
    if (zbs == NULL || !zbs->running || data == NULL || size == 0) {
        return false;
    }
    
    // Send to Zig adapter
    return zig_adapter_put_packet(zbs->adapter, (const unsigned char*)data, size);
}

// PA_FREE callback - Cleanup
// Signature: typedef void (PA_FREE)(SESSION *s);
static void ZigBridgeFree(SESSION *s)
{
    ZIG_BRIDGE_SESSION *zbs = (ZIG_BRIDGE_SESSION*)s->PacketAdapter->Param;
    
    if (zbs == NULL) {
        return;
    }
    
    printf("[ZigBridge] Cleaning up Zig adapter for session %s\n", 
           s->Name ? s->Name : "unknown");
    
    zbs->running = false;
    
    // Print final statistics
    printf("[ZigBridge] Final statistics:\n");
    zig_adapter_print_stats(zbs->adapter);
    
    // Stop threads
    zig_adapter_stop(zbs->adapter);
    
    // Destroy adapter
    zig_adapter_destroy(zbs->adapter);
    
    // Free cancel
    if (zbs->cancel) {
        ReleaseCancel(zbs->cancel);
    }
    
    // Free session structure
    Free(zbs);
    
    printf("[ZigBridge] ✅ Cleanup complete\n");
}

// Create Zig-based packet adapter for SoftEther
PACKET_ADAPTER* NewZigPacketAdapter()
{
    PACKET_ADAPTER *pa;
    
    printf("[ZigBridge] Creating Zig packet adapter (with adaptive scaling)...\n");
    
    pa = NewPacketAdapter(
        ZigBridgeInit,
        ZigBridgeGetCancel,
        ZigBridgeGetNextPacket,
        ZigBridgePutPacket,
        ZigBridgeFree
    );
    
    if (pa != NULL) {
        printf("[ZigBridge] ✅ Packet adapter created successfully\n");
    } else {
        printf("[ZigBridge] ❌ Failed to create packet adapter\n");
    }
    
    return pa;
}

#endif // BRIDGE_C
