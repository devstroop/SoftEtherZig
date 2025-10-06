// SoftEther VPN - Client Bridge Header
// Provides packet adapter selection without modifying original sources

#ifndef CLIENT_BRIDGE_H
#define CLIENT_BRIDGE_H

#ifdef BRIDGE_C

#include <Cedar/Cedar.h>

// Get packet adapter - uses Zig adapter if USE_ZIG_ADAPTER is defined
// Otherwise falls back to VLanGetPacketAdapter()
PACKET_ADAPTER* BridgeGetPacketAdapter(void);

// For internal use
PACKET_ADAPTER* GetClientPacketAdapter(void);

#endif // BRIDGE_C

#endif // CLIENT_BRIDGE_H
