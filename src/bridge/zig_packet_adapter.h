// Zig Packet Adapter - C FFI Header
// Provides C-compatible interface to Zig packet adapter

#ifndef ZIG_PACKET_ADAPTER_H
#define ZIG_PACKET_ADAPTER_H

#ifdef __cplusplus
extern "C" {
#endif

// Include SoftEther headers first (they define bool and other types)
#include "../../SoftEtherVPN_Stable/src/Mayaqua/Mayaqua.h"
#include "../../SoftEtherVPN_Stable/src/Cedar/Cedar.h"

// Standard headers (after SoftEther to avoid bool conflicts)
#include <stdint.h>

// Opaque handle to Zig adapter
typedef struct ZigPacketAdapter ZigPacketAdapter;

// Configuration for Zig adapter
typedef struct {
    uint64_t recv_queue_size;
    uint64_t send_queue_size;
    uint64_t packet_pool_size;
    uint64_t batch_size;
    const char* device_name;
} ZigAdapterConfig;

// Packet buffer structure (matches Zig side)
typedef struct {
    uint8_t* data;
    uint64_t len;
    int64_t timestamp;
} ZigPacketBuffer;

// Zig adapter FFI functions (exported from adapter.zig)
extern ZigPacketAdapter* zig_adapter_create(const ZigAdapterConfig* config);
extern void zig_adapter_destroy(ZigPacketAdapter* adapter);
extern bool zig_adapter_open(ZigPacketAdapter* adapter);
extern bool zig_adapter_start(ZigPacketAdapter* adapter);
extern void zig_adapter_stop(ZigPacketAdapter* adapter);
extern bool zig_adapter_get_packet(ZigPacketAdapter* adapter, uint8_t** out_data, uint64_t* out_len);
extern uint64_t zig_adapter_get_packet_batch(ZigPacketAdapter* adapter, ZigPacketBuffer* out_array, uint64_t max_count);
extern bool zig_adapter_put_packet(ZigPacketAdapter* adapter, const uint8_t* data, uint64_t len);
extern void zig_adapter_print_stats(ZigPacketAdapter* adapter);

// Create SoftEther PACKET_ADAPTER that wraps Zig adapter
PACKET_ADAPTER* NewZigPacketAdapter(void);

// Context for Zig adapter wrapper
typedef struct {
    SESSION* session;
    ZigPacketAdapter* zig_adapter;
    CANCEL* cancel;
    bool halt;
} ZIG_ADAPTER_CONTEXT;

#ifdef __cplusplus
}
#endif

#endif // ZIG_PACKET_ADAPTER_H
