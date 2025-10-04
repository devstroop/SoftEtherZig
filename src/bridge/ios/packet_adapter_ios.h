/*
 * iOS Packet Adapter Header
 */

#ifndef PACKET_ADAPTER_IOS_H
#define PACKET_ADAPTER_IOS_H

#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

// Callback types for iOS NEPacketTunnelFlow
typedef void (*IOSWritePacketsCallback)(void *flow, const void **packets, 
                                       const int *sizes, int count);
typedef void (*IOSReadPacketsCallback)(void *flow, void *context);

// Create iOS packet adapter
PACKET_ADAPTER* NewIOSPacketAdapter(SESSION *s);

// Get adapter context for iOS callbacks
void* IOSTunGetContext(PACKET_ADAPTER *pa);

// Set iOS packet flow interface (called from Swift)
void IOSTunSetPacketFlow(void *adapter_context, void *packet_flow,
                        IOSWritePacketsCallback write_cb,
                        IOSReadPacketsCallback read_cb,
                        void *flow_context);

// iOS calls this when packets are received from TUN
void IOSTunReceivePackets(void *adapter_context, const void **packets,
                         const int *sizes, int count);

#endif // PACKET_ADAPTER_IOS_H
