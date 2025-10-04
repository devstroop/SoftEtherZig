/*
 * SoftEther VPN - iOS C Bridge Header
 * 
 * C interface for Swift PacketTunnelProvider
 */

#ifndef SOFTETHER_IOS_H
#define SOFTETHER_IOS_H

#ifdef __cplusplus
extern "C" {
#endif

// Callback types matching iOS packet adapter
typedef void (*IOSWritePacketsCallback)(void *flow, const void **packets, 
                                       const int *sizes, int count);
typedef void (*IOSReadPacketsCallback)(void *flow, void *context);

// Initialize VPN bridge
int softether_ios_init(void);

// Create VPN client
void* softether_ios_create_client(void);

// Connect to VPN server
int softether_ios_connect(void *client,
                         const char *server_name,
                         int server_port,
                         const char *hub_name,
                         const char *username,
                         const char *password);

// Set packet flow callbacks from Swift
void softether_ios_set_packet_flow(void *client,
                                   void *packet_flow,
                                   IOSWritePacketsCallback write_cb,
                                   IOSReadPacketsCallback read_cb,
                                   void *flow_context);

// Receive packets from TUN (called by Swift)
void softether_ios_receive_packets(void *client,
                                   const void **packets,
                                   const int *sizes,
                                   int count);

// Check connection status
int softether_ios_is_connected(void *client);

// Disconnect
void softether_ios_disconnect(void *client);

// Free client
void softether_ios_free_client(void *client);

// Cleanup
void softether_ios_cleanup(void);

// Set log level (0=silent, 1=error, 2=warn, 3=info, 4=debug, 5=trace)
void softether_ios_set_log_level(int level);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_IOS_H
