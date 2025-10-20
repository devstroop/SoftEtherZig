// SoftEther VPN Zig Client - iOS Packet Adapter Stub
// For iOS, packet I/O is handled by NEPacketTunnelProvider, not by this layer

#ifdef BUILDING_FOR_IOS

#include "packet_adapter_macos.h"
#include "../../SoftEtherVPN/src/Mayaqua/Mayaqua.h"
#include "../../SoftEtherVPN/src/Cedar/Cedar.h"

// Forward declarations for stub functions
static void IosPaInit(SESSION *s, void *param);
static void IosPaGetNextPacket(SESSION *s, void **buf, UINT *size);
static bool IosPaPutPacket(SESSION *s, void *data, UINT size);
static void IosPaFree(SESSION *s);
static CANCEL *IosPaGetCancel(SESSION *s);

// iOS stub implementation - returns a minimal packet adapter
// The actual packet I/O is handled by the Swift NEPacketTunnelProvider layer
PACKET_ADAPTER* NewMacOsTunAdapter() {
    PACKET_ADAPTER *pa;
    
    printf("[NewMacOsTunAdapter] Creating iOS stub packet adapter\n");
    printf("[NewMacOsTunAdapter] Packet I/O will be handled by NEPacketTunnelProvider\n");
    
    // Create minimal packet adapter structure
    pa = ZeroMalloc(sizeof(PACKET_ADAPTER));
    
    if (pa == NULL) {
        printf("[NewMacOsTunAdapter] Failed to allocate packet adapter\n");
        return NULL;
    }
    
    // Set stub function pointers
    pa->Init = IosPaInit;
    pa->GetNextPacket = IosPaGetNextPacket;
    pa->PutPacket = IosPaPutPacket;
    pa->Free = IosPaFree;
    pa->GetCancel = IosPaGetCancel;
    
    pa->Param = NULL;  // No platform-specific data needed for iOS stub
    pa->Id = 0;
    
    printf("[NewMacOsTunAdapter] iOS stub packet adapter created\n");
    
    return pa;
}

// Stub implementation: Initialize adapter (no-op for iOS)
static void IosPaInit(SESSION *s, void *param) {
    printf("[IosPaInit] iOS stub - initialization (no-op)\n");
    // On iOS, initialization is handled by NEPacketTunnelProvider
}

// Stub implementation: Get next packet to send (returns immediately, no packets)
static void IosPaGetNextPacket(SESSION *s, void **buf, UINT *size) {
    // On iOS, outgoing packets are handled by NEPacketTunnelProvider
    // This will be called by SoftEther but should never return packets
    *buf = NULL;
    *size = 0;
}

// Stub implementation: Put received packet (returns success but does nothing)
static bool IosPaPutPacket(SESSION *s, void *data, UINT size) {
    // On iOS, incoming packets are injected via the FFI layer
    // This stub just acknowledges receipt
    return true;
}

// Stub implementation: Free adapter
static void IosPaFree(SESSION *s) {
    printf("[IosPaFree] iOS stub - cleanup\n");
    PACKET_ADAPTER *pa = s->PacketAdapter;
    if (pa != NULL) {
        Free(pa);
        s->PacketAdapter = NULL;
    }
}

// Stub implementation: Get cancel object (returns NULL - no blocking I/O on iOS)
static CANCEL *IosPaGetCancel(SESSION *s) {
    // On iOS, there's no blocking packet I/O to cancel
    return NULL;
}

#endif // BUILDING_FOR_IOS
