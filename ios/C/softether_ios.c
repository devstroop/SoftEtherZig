/*
 * SoftEther VPN - iOS C Bridge
 * 
 * This provides a C interface for Swift to interact with SoftEther VPN.
 * Used by Network Extension PacketTunnelProvider.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../src/bridge/softether_bridge.h"
#include "../../src/bridge/logging.h"
#include "../../src/bridge/ios/packet_adapter_ios.h"

// Global client handle (iOS only runs one VPN at a time)
static VpnBridgeClient *g_ios_client = NULL;

/*
 * Initialize SoftEther VPN bridge
 */
int softether_ios_init(void) {
    return vpn_bridge_init(0);
}

/*
 * Create VPN client
 */
void* softether_ios_create_client(void) {
    if (g_ios_client != NULL) {
        return g_ios_client; // Already exists
    }
    
    g_ios_client = vpn_bridge_create_client();
    return g_ios_client;
}

/*
 * Connect to VPN server
 */
int softether_ios_connect(void *client,
                         const char *server_name,
                         int server_port,
                         const char *hub_name,
                         const char *username,
                         const char *password) {
    if (client == NULL) {
        return -1;
    }
    
    VpnBridgeClient *vpn_client = (VpnBridgeClient*)client;
    
    VpnConnectionOptions opts = {0};
    strncpy(opts.ServerName, server_name, sizeof(opts.ServerName) - 1);
    opts.ServerPort = server_port;
    strncpy(opts.HubName, hub_name, sizeof(opts.HubName) - 1);
    strncpy(opts.Username, username, sizeof(opts.Username) - 1);
    strncpy(opts.Password, password, sizeof(opts.Password) - 1);
    opts.UseEncrypt = 1;
    opts.UseCompress = 1;
    opts.HalfConnection = 0;
    opts.MaxConnection = 1;
    opts.PortUDP = 0; // TCP only for iOS
    opts.AdditionalConnectionInterval = 1;
    opts.ConnectionDisconnectSpan = 0;
    opts.RequireBridgeRoutingMode = 1;
    opts.RequireMonitorMode = 0;
    opts.DisableQoS = 0;
    opts.FromAdminPack = 0;
    opts.NoRoutingTracking = 1;
    
    return vpn_bridge_connect(vpn_client, &opts);
}

/*
 * Set packet flow callbacks from Swift
 */
void softether_ios_set_packet_flow(void *client,
                                   void *packet_flow,
                                   IOSWritePacketsCallback write_cb,
                                   IOSReadPacketsCallback read_cb,
                                   void *flow_context) {
    if (client == NULL) {
        return;
    }
    
    VpnBridgeClient *vpn_client = (VpnBridgeClient*)client;
    
    if (vpn_client->session != NULL && 
        vpn_client->session->PacketAdapter != NULL) {
        void *adapter_context = IOSTunGetContext(vpn_client->session->PacketAdapter);
        IOSTunSetPacketFlow(adapter_context, packet_flow, write_cb, read_cb, flow_context);
    }
}

/*
 * Called by Swift when packets are read from TUN
 */
void softether_ios_receive_packets(void *client,
                                   const void **packets,
                                   const int *sizes,
                                   int count) {
    if (client == NULL) {
        return;
    }
    
    VpnBridgeClient *vpn_client = (VpnBridgeClient*)client;
    
    if (vpn_client->session != NULL && 
        vpn_client->session->PacketAdapter != NULL) {
        void *adapter_context = IOSTunGetContext(vpn_client->session->PacketAdapter);
        IOSTunReceivePackets(adapter_context, packets, sizes, count);
    }
}

/*
 * Check if connected
 */
int softether_ios_is_connected(void *client) {
    if (client == NULL) {
        return 0;
    }
    
    return vpn_bridge_is_connected((VpnBridgeClient*)client) ? 1 : 0;
}

/*
 * Disconnect from VPN
 */
void softether_ios_disconnect(void *client) {
    if (client != NULL) {
        vpn_bridge_disconnect((VpnBridgeClient*)client);
    }
}

/*
 * Free client
 */
void softether_ios_free_client(void *client) {
    if (client != NULL) {
        vpn_bridge_free_client((VpnBridgeClient*)client);
        if (client == g_ios_client) {
            g_ios_client = NULL;
        }
    }
}

/*
 * Cleanup
 */
void softether_ios_cleanup(void) {
    vpn_bridge_cleanup();
}

/*
 * Set log level
 */
void softether_ios_set_log_level(int level) {
    set_log_level((LogLevel)level);
}
