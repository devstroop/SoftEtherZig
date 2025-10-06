// SoftEther VPN - Client Bridge with Zig Adapter Integration
// This is a PATCHED version that integrates the high-performance Zig adapter
// DO NOT modify original SoftEther files - use this bridge instead

#include <GlobalConst.h>

#ifdef BRIDGE_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#include "zig_bridge.h"

// Wrapper function to get packet adapter
// This replaces VLanGetPacketAdapter() when USE_ZIG_ADAPTER is defined
PACKET_ADAPTER* GetClientPacketAdapter(void)
{
#ifdef USE_ZIG_ADAPTER
    printf("[ClientBridge] 🚀 Creating Zig packet adapter (100-200 Mbps expected)\n");
    PACKET_ADAPTER *pa = NewZigPacketAdapter();
    if (pa != NULL) {
        printf("[ClientBridge] ✅ Zig adapter created successfully\n");
        return pa;
    } else {
        printf("[ClientBridge] ⚠️  Zig adapter failed, falling back to VLan\n");
        return VLanGetPacketAdapter();
    }
#else
    printf("[ClientBridge] Using standard VLan adapter\n");
    return VLanGetPacketAdapter();
#endif
}

// Export for linking
PACKET_ADAPTER* BridgeGetPacketAdapter(void)
{
    return GetClientPacketAdapter();
}

#endif // BRIDGE_C
