// SoftEther VPN Zig Client - macOS Packet Adapter Implementation
// Uses macOS utun kernel interface for packet forwarding

// **CRITICAL FIX**: Undefine TARGET_OS_IPHONE if defined - we're building for macOS, not iOS!
#ifdef TARGET_OS_IPHONE
#undef TARGET_OS_IPHONE
#endif

#include "packet_adapter_macos.h"
#include "../../SoftEtherVPN_Stable/src/Mayaqua/Mayaqua.h"
#include "../../SoftEtherVPN_Stable/src/Cedar/Cedar.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#define TUN_MTU 1500
#define MAX_ETHERNET_FRAME 1518  // 1500 IP + 14 Ethernet header + 4 VLAN tag (if any)
#define MAX_PACKET_SIZE 2048
#define RECV_QUEUE_MAX 1024

// DHCP configuration state
typedef enum {
    DHCP_STATE_INIT = 0,
    DHCP_STATE_ARP_ANNOUNCE_SENT = 1, // **NEW**: Send Gratuitous ARP first to register MAC!
    DHCP_STATE_IPV6_NA_SENT = 2,      // Sent IPv6 Neighbor Advertisement
    DHCP_STATE_IPV6_RS_SENT = 3,      // Sent IPv6 Router Solicitation
    DHCP_STATE_DISCOVER_SENT = 4,
    DHCP_STATE_OFFER_RECEIVED = 5,
    DHCP_STATE_REQUEST_SENT = 6,
    DHCP_STATE_ARP_PROBE_SENT = 7,    // Send ARP Probe after getting DHCP ACK
    DHCP_STATE_CONFIGURED = 8
} DHCP_STATE;

static DHCP_STATE g_dhcp_state = DHCP_STATE_INIT;
static UCHAR g_my_mac[6] = {0};
static UINT32 g_dhcp_xid = 0;
static UINT32 g_dhcp_server_ip = 0;
static UINT64 g_connection_start_time = 0;  // Timestamp when connection established
static UINT32 g_offered_ip = 0;
static UINT32 g_offered_mask = 0;
static UINT32 g_offered_gw = 0;
static UINT64 g_last_dhcp_send_time = 0;    // Last DHCP packet send time
static UINT g_dhcp_retry_count = 0;          // DHCP retry counter
static UINT64 g_last_state_change_time = 0;  // When we last changed g_dhcp_state

// ARP reply state
static bool g_need_arp_reply = false;        // Flag: need to send ARP reply
static UCHAR g_arp_reply_to_mac[6] = {0};   // MAC to send ARP reply to
static UINT32 g_arp_reply_to_ip = 0;         // IP to send ARP reply to

// Gateway ARP resolution (CRITICAL for MAC/IP table population!)
static bool g_need_gateway_arp = false;      // Flag: need to send gateway ARP request
static UINT32 g_gateway_ip = 0;              // Gateway IP to resolve

// Our configured IP (learned from outgoing packets or DHCP)
static UINT32 g_our_ip = 0;                  // Our IP address (0 = not known yet)
static UCHAR g_gateway_mac[6] = {0};         // Gateway MAC address (learned from ARP)

// Keep-alive: Send periodic Gratuitous ARP to maintain MAC/IP table in SoftEther
static UINT64 g_last_keepalive_time = 0;     // Last time we sent keep-alive GARP
#define KEEPALIVE_INTERVAL_MS 10000           // Send GARP every 10 seconds

// Original routing configuration (for restoration on disconnect)
static UINT32 g_original_gateway = 0;        // Original default gateway
static UINT32 g_vpn_server_ip = 0;           // VPN server IP
static UINT32 g_local_network = 0;           // Local network (e.g., 192.168.1.0)
static bool g_routes_configured = false;     // Flag: routes have been modified

// Forward declarations
static UINT32 GetDefaultGateway(void);
static UINT32 GetVpnServerIp(void);

// Configure the TUN interface with IP address
static bool ConfigureTunInterface(const char *device, UINT32 ip, UINT32 netmask, UINT32 gateway) {
#ifdef TARGET_OS_IPHONE
    // On iOS, network configuration is handled by NEPacketTunnelProvider
    // This function is not used - configuration comes from the tunnel settings
    char ip_str[32], mask_str[32], gw_str[32];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    snprintf(mask_str, sizeof(mask_str), "%d.%d.%d.%d",
             (netmask >> 24) & 0xFF, (netmask >> 16) & 0xFF, (netmask >> 8) & 0xFF, netmask & 0xFF);
    snprintf(gw_str, sizeof(gw_str), "%d.%d.%d.%d",
             (gateway >> 24) & 0xFF, (gateway >> 16) & 0xFF, (gateway >> 8) & 0xFF, gateway & 0xFF);
    printf("[ConfigureTunInterface] iOS: IP=%s, Netmask=%s, Gateway=%s\n", ip_str, mask_str, gw_str);
    printf("[ConfigureTunInterface] iOS: Network configuration handled by PacketTunnelProvider\n");
    return true;
#else
    char cmd[512];
    char ip_str[32], mask_str[32], gw_str[32];
    
    // Convert IPs to strings (network byte order)
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    snprintf(mask_str, sizeof(mask_str), "%d.%d.%d.%d",
             (netmask >> 24) & 0xFF, (netmask >> 16) & 0xFF, (netmask >> 8) & 0xFF, netmask & 0xFF);
    snprintf(gw_str, sizeof(gw_str), "%d.%d.%d.%d",
             (gateway >> 24) & 0xFF, (gateway >> 16) & 0xFF, (gateway >> 8) & 0xFF, gateway & 0xFF);
    
    printf("\n");
    printf("╔════════════════════════════════════════════╗\n");
    printf("║     DHCP Configuration Received!           ║\n");
    printf("╠════════════════════════════════════════════╣\n");
    printf("║ Device:    %-32s║\n", device);
    printf("║ IP:        %-32s║\n", ip_str);
    printf("║ Netmask:   %-32s║\n", mask_str);
    printf("║ Gateway:   %-32s║\n", gw_str);
    printf("╚════════════════════════════════════════════╝\n");
    printf("\n");
    
    // Set IP address with peer (gateway) - TUN devices need both local and peer IPs
    // Format: ifconfig DEVICE LOCAL_IP PEER_IP netmask NETMASK up
    // This is required for macOS TUN devices (point-to-point interfaces)
    snprintf(cmd, sizeof(cmd), "ifconfig %s %s %s netmask %s up", device, ip_str, gw_str, mask_str);
    printf("[ConfigureTunInterface] Executing: %s\n", cmd);
    if (system(cmd) != 0) {
        printf("[ConfigureTunInterface] ❌ Failed to configure interface\n");
        return false;
    }
    
    // Full Tunnel Mode - Route ALL traffic through VPN
    // This is the default behavior for maximum security
    if (gateway != 0) {
        // CRITICAL: Get the original default gateway BEFORE any route changes
        UINT32 orig_gateway = GetDefaultGateway();
        UINT32 vpn_server_ip = GetVpnServerIp();
        
        if (vpn_server_ip != 0 && orig_gateway != 0) {
            // Calculate local network (192.168.1.0/24 from 192.168.1.1)
            UINT32 local_network = orig_gateway & 0xFFFFFF00;  // Assume /24
            char local_net_str[32];
            char orig_gw_str[32];
            char server_ip_str[32];
            
            snprintf(local_net_str, sizeof(local_net_str), "%d.%d.%d.0",
                     (local_network >> 24) & 0xFF, (local_network >> 16) & 0xFF,
                     (local_network >> 8) & 0xFF);
            snprintf(orig_gw_str, sizeof(orig_gw_str), "%d.%d.%d.%d",
                     (orig_gateway >> 24) & 0xFF, (orig_gateway >> 16) & 0xFF,
                     (orig_gateway >> 8) & 0xFF, orig_gateway & 0xFF);
            snprintf(server_ip_str, sizeof(server_ip_str), "%d.%d.%d.%d",
                     (vpn_server_ip >> 24) & 0xFF, (vpn_server_ip >> 16) & 0xFF,
                     (vpn_server_ip >> 8) & 0xFF, vpn_server_ip & 0xFF);
            
            printf("\n");
            printf("╔════════════════════════════════════════════╗\n");
            printf("║     Full Tunnel Mode (All Traffic)        ║\n");
            printf("╠════════════════════════════════════════════╣\n");
            printf("║ Local Network:    %-25s║\n", local_net_str);
            printf("║ VPN Gateway:      %-25s║\n", gw_str);
            printf("║ VPN Server IP:    %-25s║\n", server_ip_str);
            printf("║ Original Gateway: %-25s║\n", orig_gw_str);
            printf("╠════════════════════════════════════════════╣\n");
            printf("║ All Internet traffic: Through VPN tunnel  ║\n");
            printf("║ Local network:        Direct access       ║\n");
            printf("╚════════════════════════════════════════════╝\n");
            printf("\n");
            
            // 1. Preserve local network access FIRST
            //    Keep LAN traffic (file sharing, printers, etc.) direct
            snprintf(cmd, sizeof(cmd), "route add -net %s/24 %s", local_net_str, orig_gw_str);
            printf("[ConfigureTunInterface] 🏠 Adding local network route: %s\n", cmd);
            if (system(cmd) != 0) {
                printf("[ConfigureTunInterface] ⚠️  Failed to add local network route (may already exist)\n");
            } else {
                printf("[ConfigureTunInterface] ✅ Local network route preserved\n");
            }
            
            // 2. Add host route for VPN server through original gateway
            //    CRITICAL: Prevents routing loop (VPN traffic going through VPN)
            snprintf(cmd, sizeof(cmd), "route add -host %s %s", server_ip_str, orig_gw_str);
            printf("[ConfigureTunInterface] 🔐 Adding VPN server route: %s\n", cmd);
            if (system(cmd) != 0) {
                printf("[ConfigureTunInterface] ⚠️  Failed to add VPN server route (may already exist)\n");
            } else {
                printf("[ConfigureTunInterface] ✅ VPN server route established\n");
            }
            
            // 3. Delete existing default route (important!)
            system("route delete default >/dev/null 2>&1");
            
            // 4. Add default route through VPN
            //    ALL internet traffic now goes through encrypted tunnel
            snprintf(cmd, sizeof(cmd), "route add default %s", gw_str);
            printf("[ConfigureTunInterface] � Adding default route through VPN: %s\n", cmd);
            if (system(cmd) != 0) {
                printf("[ConfigureTunInterface] ⚠️  Failed to add default route (may already exist)\n");
            } else {
                printf("[ConfigureTunInterface] ✅ Default route through VPN established\n");
            }
            
            printf("\n");
            printf("✅ Full Tunnel Mode active:\n");
            printf("   • All internet traffic encrypted through VPN\n");
            printf("   • Local network (%s/24) direct access preserved\n", local_net_str);
            printf("   • VPN server connection protected from routing loop\n\n");
            
            // Store routing info for restoration on disconnect
            g_original_gateway = orig_gateway;
            g_vpn_server_ip = vpn_server_ip;
            g_local_network = local_network;
            g_routes_configured = true;
        } else {
            printf("[ConfigureTunInterface] ⚠️  Could not determine VPN server IP or original gateway\n");
            printf("[ConfigureTunInterface]     VPN server IP: %u.%u.%u.%u\n",
                   (vpn_server_ip >> 24) & 0xFF, (vpn_server_ip >> 16) & 0xFF,
                   (vpn_server_ip >> 8) & 0xFF, vpn_server_ip & 0xFF);
            printf("[ConfigureTunInterface]     Original gateway: %u.%u.%u.%u\n",
                   (orig_gateway >> 24) & 0xFF, (orig_gateway >> 16) & 0xFF,
                   (orig_gateway >> 8) & 0xFF, orig_gateway & 0xFF);
        }
    }
    
    printf("[ConfigureTunInterface] ✅ Interface configured successfully\n\n");
    return true;
#endif // TARGET_OS_IPHONE
}

// Get the current default gateway IP address
// Returns 0 if no default route found
static UINT32 GetDefaultGateway(void) {
    FILE *fp;
    char line[512];
    UINT32 gateway = 0;
    
    // Run netstat to get routing table
    fp = popen("netstat -rn | grep '^default' | grep -v 'utun' | head -1", "r");
    if (fp == NULL) {
        printf("[GetDefaultGateway] ⚠️  Failed to execute netstat\n");
        return 0;
    }
    
    // Parse output: "default            192.168.1.1        UGScg                 en1"
    if (fgets(line, sizeof(line), fp) != NULL) {
        char *token = strtok(line, " \t");  // Skip "default"
        if (token != NULL) {
            token = strtok(NULL, " \t");     // Get gateway IP
            if (token != NULL) {
                // Parse IP address
                unsigned int a, b, c, d;
                if (sscanf(token, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                    gateway = (a << 24) | (b << 16) | (c << 8) | d;
                    printf("[GetDefaultGateway] 🌐 Found default gateway: %u.%u.%u.%u\n", a, b, c, d);
                }
            }
        }
    }
    
    pclose(fp);
    return gateway;
}

// Get the VPN server IP address from SoftEther's connection info
// Returns 0 if not available
static UINT32 GetVpnServerIp(void) {
    FILE *fp;
    char line[512];
    UINT32 server_ip = 0;
    
    // Try to get connected server IP from netstat
    // Look for ESTABLISHED TCP connections on port 443
    fp = popen("netstat -an | grep ESTABLISHED | grep '\\.443 ' | head -1", "r");
    if (fp == NULL) {
        printf("[GetVpnServerIp] ⚠️  Failed to execute netstat\n");
        return 0;
    }
    
    // Parse output: "tcp4       0      0  192.168.1.8.57816      62.24.65.211.443       ESTABLISHED"
    if (fgets(line, sizeof(line), fp) != NULL) {
        // Find the server IP (after local IP, before .443)
        char *p = strstr(line, ".443 ");
        if (p != NULL) {
            // Backtrack to find start of IP
            while (p > line && *(p-1) != ' ' && *(p-1) != '\t') {
                p--;
            }
            // Parse IP address
            unsigned int a, b, c, d;
            if (sscanf(p, "%u.%u.%u.%u.443", &a, &b, &c, &d) == 4) {
                server_ip = (a << 24) | (b << 16) | (c << 8) | d;
                printf("[GetVpnServerIp] 🔐 Found VPN server IP: %u.%u.%u.%u\n", a, b, c, d);
            }
        }
    }
    
    pclose(fp);
    return server_ip;
}

// Build IPv6 Router Solicitation packet (ICMPv6 type 133)
// This is sent by SSTP Connect alongside DHCP DISCOVER
static UCHAR* BuildRouterSolicitation(UCHAR *my_mac, UINT *out_size) {
    static UCHAR packet[1024];
    UINT pos = 0;
    
    // Ethernet header (14 bytes)
    // Destination MAC: IPv6 all-routers multicast (33:33:00:00:00:02)
    packet[pos++] = 0x33; packet[pos++] = 0x33; packet[pos++] = 0x00;
    packet[pos++] = 0x00; packet[pos++] = 0x00; packet[pos++] = 0x02;
    // Source MAC
    memcpy(packet + pos, my_mac, 6); pos += 6;
    // EtherType: IPv6
    packet[pos++] = 0x86; packet[pos++] = 0xDD;
    
    // IPv6 header (40 bytes)
    packet[pos++] = 0x60; // Version 6
    packet[pos++] = 0x00; packet[pos++] = 0x00; packet[pos++] = 0x00; // Traffic class + flow label
    USHORT payload_len = 8; // ICMPv6 Router Solicitation length
    packet[pos++] = (payload_len >> 8) & 0xFF;
    packet[pos++] = payload_len & 0xFF;
    packet[pos++] = 58; // Next header: ICMPv6
    packet[pos++] = 255; // Hop limit
    
    // Source: IPv6 link-local address generated from MAC (fe80::)
    packet[pos++] = 0xFE; packet[pos++] = 0x80;
    for (int i = 0; i < 6; i++) packet[pos++] = 0x00;
    // Generate EUI-64 from MAC
    packet[pos++] = my_mac[0] ^ 0x02; // Flip universal/local bit
    packet[pos++] = my_mac[1];
    packet[pos++] = my_mac[2];
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFE;
    packet[pos++] = my_mac[3];
    packet[pos++] = my_mac[4];
    packet[pos++] = my_mac[5];
    
    // Destination: ff02::2 (all-routers multicast)
    packet[pos++] = 0xFF; packet[pos++] = 0x02;
    for (int i = 0; i < 12; i++) packet[pos++] = 0x00;
    packet[pos++] = 0x00; packet[pos++] = 0x02;
    
    // ICMPv6 Router Solicitation (8 bytes)
    packet[pos++] = 133; // Type: Router Solicitation
    packet[pos++] = 0; // Code
    packet[pos++] = 0x00; packet[pos++] = 0x00; // Checksum (will calculate)
    packet[pos++] = 0x00; packet[pos++] = 0x00; // Reserved
    packet[pos++] = 0x00; packet[pos++] = 0x00;
    
    // Calculate ICMPv6 checksum (simplified - set to 0 for now)
    packet[54] = 0x00;
    packet[55] = 0x00;
    
    *out_size = pos;
    return packet;
}

// Build IPv6 Neighbor Advertisement packet (ICMPv6 type 136)
// This is sent by SSTP Connect alongside DHCP DISCOVER
static UCHAR* BuildNeighborAdvertisement(UCHAR *my_mac, UINT *out_size) {
    static UCHAR packet[1024];
    UINT pos = 0;
    
    // Ethernet header (14 bytes)
    // Destination MAC: IPv6 all-nodes multicast (33:33:00:00:00:01)
    packet[pos++] = 0x33; packet[pos++] = 0x33; packet[pos++] = 0x00;
    packet[pos++] = 0x00; packet[pos++] = 0x00; packet[pos++] = 0x01;
    // Source MAC
    memcpy(packet + pos, my_mac, 6); pos += 6;
    // EtherType: IPv6
    packet[pos++] = 0x86; packet[pos++] = 0xDD;
    
    // IPv6 header (40 bytes)
    packet[pos++] = 0x60; // Version 6
    packet[pos++] = 0x00; packet[pos++] = 0x00; packet[pos++] = 0x00; // Traffic class + flow label
    USHORT payload_len = 24; // ICMPv6 Neighbor Advertisement length
    packet[pos++] = (payload_len >> 8) & 0xFF;
    packet[pos++] = payload_len & 0xFF;
    packet[pos++] = 58; // Next header: ICMPv6
    packet[pos++] = 255; // Hop limit
    
    // Source: IPv6 link-local address generated from MAC (fe80::)
    packet[pos++] = 0xFE; packet[pos++] = 0x80;
    for (int i = 0; i < 6; i++) packet[pos++] = 0x00;
    // Generate EUI-64 from MAC
    packet[pos++] = my_mac[0] ^ 0x02; // Flip universal/local bit
    packet[pos++] = my_mac[1];
    packet[pos++] = my_mac[2];
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFE;
    packet[pos++] = my_mac[3];
    packet[pos++] = my_mac[4];
    packet[pos++] = my_mac[5];
    
    // Destination: ff02::1 (all-nodes multicast)
    packet[pos++] = 0xFF; packet[pos++] = 0x02;
    for (int i = 0; i < 13; i++) packet[pos++] = 0x00;
    packet[pos++] = 0x01;
    
    // ICMPv6 Neighbor Advertisement (24 bytes)
    packet[pos++] = 136; // Type: Neighbor Advertisement
    packet[pos++] = 0; // Code
    packet[pos++] = 0x00; packet[pos++] = 0x00; // Checksum (will calculate)
    packet[pos++] = 0x00; packet[pos++] = 0x00; // Flags (solicited=0, override=0)
    packet[pos++] = 0x00; packet[pos++] = 0x00;
    
    // Target address (same as source IPv6 link-local)
    packet[pos++] = 0xFE; packet[pos++] = 0x80;
    for (int i = 0; i < 6; i++) packet[pos++] = 0x00;
    packet[pos++] = my_mac[0] ^ 0x02;
    packet[pos++] = my_mac[1];
    packet[pos++] = my_mac[2];
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFE;
    packet[pos++] = my_mac[3];
    packet[pos++] = my_mac[4];
    packet[pos++] = my_mac[5];
    
    // Calculate ICMPv6 checksum (simplified - set to 0 for now)
    packet[56] = 0x00;
    packet[57] = 0x00;
    
    *out_size = pos;
    return packet;
}

// Build Gratuitous ARP packet (ARP Announcement)
// CRITICAL: This registers our MAC address in SoftEther's bridge MAC/IP learning table!
// Without this, the bridge won't forward unicast packets to us (including DHCP responses)
static UCHAR* BuildGratuitousArp(UCHAR *my_mac, UINT32 my_ip, UINT *out_size) {
    static UCHAR packet[1024];
    UINT pos = 0;
    
    // Ethernet header (14 bytes)
    // Destination MAC: broadcast (for gratuitous ARP)
    packet[pos++] = 0xFF; packet[pos++] = 0xFF; packet[pos++] = 0xFF;
    packet[pos++] = 0xFF; packet[pos++] = 0xFF; packet[pos++] = 0xFF;
    // Source MAC
    memcpy(packet + pos, my_mac, 6); pos += 6;
    // EtherType: ARP (0x0806)
    packet[pos++] = 0x08; packet[pos++] = 0x06;
    
    // ARP packet (28 bytes)
    // Hardware type: Ethernet (1)
    packet[pos++] = 0x00; packet[pos++] = 0x01;
    // Protocol type: IPv4 (0x0800)
    packet[pos++] = 0x08; packet[pos++] = 0x00;
    // Hardware size: 6
    packet[pos++] = 0x06;
    // Protocol size: 4
    packet[pos++] = 0x04;
    // Opcode: Request (1) - Gratuitous ARP uses Request
    packet[pos++] = 0x00; packet[pos++] = 0x01;
    
    // Sender MAC address
    memcpy(packet + pos, my_mac, 6); pos += 6;
    
    // Sender IP address
    packet[pos++] = (my_ip >> 24) & 0xFF;
    packet[pos++] = (my_ip >> 16) & 0xFF;
    packet[pos++] = (my_ip >> 8) & 0xFF;
    packet[pos++] = my_ip & 0xFF;
    
    // Target MAC address (00:00:00:00:00:00 for gratuitous ARP)
    for (int i = 0; i < 6; i++) packet[pos++] = 0x00;
    
    // Target IP address (same as sender IP for gratuitous ARP)
    packet[pos++] = (my_ip >> 24) & 0xFF;
    packet[pos++] = (my_ip >> 16) & 0xFF;
    packet[pos++] = (my_ip >> 8) & 0xFF;
    packet[pos++] = my_ip & 0xFF;
    
    *out_size = pos;
    return packet;
}

// Build ARP Reply packet (responds to ARP requests for our IP)
// CRITICAL: When DHCP server or router sends ARP request checking if our IP is alive,
// we MUST respond or they'll think the IP is unused and won't complete DHCP!
static UCHAR* BuildArpReply(UCHAR *my_mac, UINT32 my_ip, UCHAR *target_mac, UINT32 target_ip, UINT *out_size) {
    static UCHAR packet[1024];
    UINT pos = 0;
    
    // Ethernet header (14 bytes)
    // Destination MAC: the requester's MAC
    memcpy(packet + pos, target_mac, 6); pos += 6;
    // Source MAC: our MAC
    memcpy(packet + pos, my_mac, 6); pos += 6;
    // EtherType: ARP (0x0806)
    packet[pos++] = 0x08; packet[pos++] = 0x06;
    
    // ARP packet (28 bytes)
    // Hardware type: Ethernet (1)
    packet[pos++] = 0x00; packet[pos++] = 0x01;
    // Protocol type: IPv4 (0x0800)
    packet[pos++] = 0x08; packet[pos++] = 0x00;
    // Hardware size: 6
    packet[pos++] = 0x06;
    // Protocol size: 4
    packet[pos++] = 0x04;
    // Opcode: Reply (2)
    packet[pos++] = 0x00; packet[pos++] = 0x02;
    
    // Sender MAC address (us)
    memcpy(packet + pos, my_mac, 6); pos += 6;
    
    // Sender IP address (our IP: 10.21.255.100)
    packet[pos++] = (my_ip >> 24) & 0xFF;
    packet[pos++] = (my_ip >> 16) & 0xFF;
    packet[pos++] = (my_ip >> 8) & 0xFF;
    packet[pos++] = my_ip & 0xFF;
    
    // Target MAC address (the requester's MAC)
    memcpy(packet + pos, target_mac, 6); pos += 6;
    
    // Target IP address (the requester's IP)
    packet[pos++] = (target_ip >> 24) & 0xFF;
    packet[pos++] = (target_ip >> 16) & 0xFF;
    packet[pos++] = (target_ip >> 8) & 0xFF;
    packet[pos++] = target_ip & 0xFF;
    
    *out_size = pos;
    return packet;
}

// Build ARP Request packet (asks "who has target_ip?")
// Used to resolve gateway MAC address - CRITICAL for MAC/IP table population!
static UCHAR* BuildArpRequest(UCHAR *my_mac, UINT32 my_ip, UINT32 target_ip, UINT *out_size) {
    static UCHAR packet[1024];
    UINT pos = 0;
    
    // Ethernet header (14 bytes)
    // Destination MAC: broadcast (we don't know target MAC yet)
    packet[pos++] = 0xFF; packet[pos++] = 0xFF; packet[pos++] = 0xFF;
    packet[pos++] = 0xFF; packet[pos++] = 0xFF; packet[pos++] = 0xFF;
    // Source MAC: our MAC
    memcpy(packet + pos, my_mac, 6); pos += 6;
    // EtherType: ARP (0x0806)
    packet[pos++] = 0x08; packet[pos++] = 0x06;
    
    // ARP packet (28 bytes)
    // Hardware type: Ethernet (1)
    packet[pos++] = 0x00; packet[pos++] = 0x01;
    // Protocol type: IPv4 (0x0800)
    packet[pos++] = 0x08; packet[pos++] = 0x00;
    // Hardware size: 6
    packet[pos++] = 0x06;
    // Protocol size: 4
    packet[pos++] = 0x04;
    // Opcode: Request (1)
    packet[pos++] = 0x00; packet[pos++] = 0x01;
    
    // Sender MAC address (us)
    memcpy(packet + pos, my_mac, 6); pos += 6;
    
    // Sender IP address (our IP)
    packet[pos++] = (my_ip >> 24) & 0xFF;
    packet[pos++] = (my_ip >> 16) & 0xFF;
    packet[pos++] = (my_ip >> 8) & 0xFF;
    packet[pos++] = my_ip & 0xFF;
    
    // Target MAC address (00:00:00:00:00:00 - unknown)
    for (int i = 0; i < 6; i++) packet[pos++] = 0x00;
    
    // Target IP address (gateway we want to resolve)
    packet[pos++] = (target_ip >> 24) & 0xFF;
    packet[pos++] = (target_ip >> 16) & 0xFF;
    packet[pos++] = (target_ip >> 8) & 0xFF;
    packet[pos++] = target_ip & 0xFF;
    
    *out_size = pos;
    return packet;
}

// Build ARP Probe packet (checks if IP is already in use)
// Sent BEFORE Gratuitous ARP to detect IP conflicts
static UCHAR* BuildArpProbe(UCHAR *my_mac, UINT32 target_ip, UINT *out_size) {
    static UCHAR packet[1024];
    UINT pos = 0;
    
    // Ethernet header (14 bytes)
    // Destination MAC: broadcast
    packet[pos++] = 0xFF; packet[pos++] = 0xFF; packet[pos++] = 0xFF;
    packet[pos++] = 0xFF; packet[pos++] = 0xFF; packet[pos++] = 0xFF;
    // Source MAC
    memcpy(packet + pos, my_mac, 6); pos += 6;
    // EtherType: ARP (0x0806)
    packet[pos++] = 0x08; packet[pos++] = 0x06;
    
    // ARP packet (28 bytes)
    // Hardware type: Ethernet (1)
    packet[pos++] = 0x00; packet[pos++] = 0x01;
    // Protocol type: IPv4 (0x0800)
    packet[pos++] = 0x08; packet[pos++] = 0x00;
    // Hardware size: 6
    packet[pos++] = 0x06;
    // Protocol size: 4
    packet[pos++] = 0x04;
    // Opcode: Request (1)
    packet[pos++] = 0x00; packet[pos++] = 0x01;
    
    // Sender MAC address
    memcpy(packet + pos, my_mac, 6); pos += 6;
    
    // Sender IP address (0.0.0.0 for ARP Probe - we don't have IP yet)
    packet[pos++] = 0x00; packet[pos++] = 0x00;
    packet[pos++] = 0x00; packet[pos++] = 0x00;
    
    // Target MAC address (00:00:00:00:00:00)
    for (int i = 0; i < 6; i++) packet[pos++] = 0x00;
    
    // Target IP address (the IP we want to claim)
    packet[pos++] = (target_ip >> 24) & 0xFF;
    packet[pos++] = (target_ip >> 16) & 0xFF;
    packet[pos++] = (target_ip >> 8) & 0xFF;
    packet[pos++] = target_ip & 0xFF;
    
    *out_size = pos;
    return packet;
}

// Build DHCP DISCOVER packet
static UCHAR* BuildDhcpDiscover(UCHAR *my_mac, UINT32 xid, UINT *out_size) {
    static UCHAR packet[1024];
    UINT pos = 0;
    
    // Ethernet header (14 bytes)
    // Destination MAC: broadcast
    packet[pos++] = 0xFF; packet[pos++] = 0xFF; packet[pos++] = 0xFF;
    packet[pos++] = 0xFF; packet[pos++] = 0xFF; packet[pos++] = 0xFF;
    // Source MAC
    memcpy(packet + pos, my_mac, 6); pos += 6;
    // EtherType: IPv4
    packet[pos++] = 0x08; packet[pos++] = 0x00;
    
    // IPv4 header (20 bytes)
    packet[pos++] = 0x45; // Version 4, IHL 5
    packet[pos++] = 0x00; // DSCP/ECN
    // Will update total_len later after we know the actual packet size
    UINT ip_total_len_pos = pos;  // Save position for later update
    packet[pos++] = 0x00; packet[pos++] = 0x00; // Placeholder for total length
    packet[pos++] = 0x00; packet[pos++] = 0x00; // ID
    packet[pos++] = 0x00; packet[pos++] = 0x00; // Flags/Fragment
    packet[pos++] = 64; // TTL
    packet[pos++] = 17; // Protocol: UDP
    UINT ip_checksum_pos = pos;  // Save position for checksum
    packet[pos++] = 0x00; packet[pos++] = 0x00; // Checksum (will calculate)
    // Source IP: 0.0.0.0
    packet[pos++] = 0; packet[pos++] = 0; packet[pos++] = 0; packet[pos++] = 0;
    // Dest IP: 255.255.255.255
    packet[pos++] = 255; packet[pos++] = 255; packet[pos++] = 255; packet[pos++] = 255;
    
    // UDP header (8 bytes)
    packet[pos++] = 0x00; packet[pos++] = 68; // Source port: 68 (DHCP client)
    packet[pos++] = 0x00; packet[pos++] = 67; // Dest port: 67 (DHCP server)
    UINT udp_len_pos = pos;  // Save position for length
    packet[pos++] = 0x00; packet[pos++] = 0x00; // Placeholder for UDP length
    packet[pos++] = 0x00; packet[pos++] = 0x00; // Checksum (optional for IPv4)
    
    // DHCP header (240 bytes minimum)
    packet[pos++] = 0x01; // op: BOOTREQUEST
    packet[pos++] = 0x01; // htype: Ethernet
    packet[pos++] = 0x06; // hlen: 6
    packet[pos++] = 0x00; // hops: 0
    // Transaction ID (4 bytes)
    packet[pos++] = (xid >> 24) & 0xFF;
    packet[pos++] = (xid >> 16) & 0xFF;
    packet[pos++] = (xid >> 8) & 0xFF;
    packet[pos++] = xid & 0xFF;
    // secs, flags
    packet[pos++] = 0x00; packet[pos++] = 0x00;
    packet[pos++] = 0x80; packet[pos++] = 0x00; // Broadcast flag
    // ciaddr, yiaddr, siaddr, giaddr (all zeros)
    for (int i = 0; i < 16; i++) packet[pos++] = 0x00;
    // chaddr (client MAC)
    memcpy(packet + pos, my_mac, 6); pos += 6;
    for (int i = 0; i < 10; i++) packet[pos++] = 0x00; // Padding
    // sname, file (zeros)
    for (int i = 0; i < 192; i++) packet[pos++] = 0x00;
    
    // DHCP magic cookie
    packet[pos++] = 0x63; packet[pos++] = 0x82;
    packet[pos++] = 0x53; packet[pos++] = 0x63;
    
    // DHCP options
    // Option 53: DHCP Message Type = DISCOVER (1)
    packet[pos++] = 53; packet[pos++] = 1; packet[pos++] = 1;
    
    // Option 55: Parameter Request List
    packet[pos++] = 55; packet[pos++] = 4;
    packet[pos++] = 1;  // Subnet Mask
    packet[pos++] = 3;  // Router
    packet[pos++] = 6;  // DNS
    packet[pos++] = 15; // Domain Name
    
    // REMOVED Option 50 (Requested IP) - let DHCP server assign any IP
    // The DHCP server seems to be rejecting our requested IP 10.21.255.100
    
    // Option 255: End
    packet[pos++] = 255;
    
    // Now update the lengths with actual packet size
    UINT ip_header_start = 14;
    UINT udp_header_start = ip_header_start + 20;
    UINT dhcp_start = udp_header_start + 8;
    UINT total_packet_size = pos;
    
    // Calculate actual lengths
    USHORT ip_total_len = total_packet_size - ip_header_start;  // IP header + UDP + DHCP
    USHORT udp_len = total_packet_size - udp_header_start;      // UDP header + DHCP
    
    // Update IP total length
    packet[ip_total_len_pos] = (ip_total_len >> 8) & 0xFF;
    packet[ip_total_len_pos + 1] = ip_total_len & 0xFF;
    
    // Update UDP length
    packet[udp_len_pos] = (udp_len >> 8) & 0xFF;
    packet[udp_len_pos + 1] = udp_len & 0xFF;
    
    // Calculate and update IP checksum
    UINT checksum = 0;
    for (int i = 0; i < 20; i += 2) {
        checksum += (packet[ip_header_start + i] << 8) | packet[ip_header_start + i + 1];
    }
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum = ~checksum & 0xFFFF;
    packet[ip_checksum_pos] = (checksum >> 8) & 0xFF;
    packet[ip_checksum_pos + 1] = checksum & 0xFF;
    
    *out_size = pos;
    return packet;
}

// Check if packet is a DHCP ACK and extract configuration
static bool ParseDhcpAck(UCHAR *data, UINT size, UINT32 expected_xid, UINT32 *out_ip, UINT32 *out_mask, UINT32 *out_gw) {
    // Skip Ethernet header (14 bytes)
    if (size < 14) return false;
    USHORT ethertype = (data[12] << 8) | data[13];
    if (ethertype != 0x0800) return false;
    
    data += 14;
    size -= 14;
    
    // Check IPv4 UDP
    if (size < 20) return false;
    UCHAR protocol = data[9];
    if (protocol != 17) return false;
    
    // Get IP header length
    UCHAR ihl = (data[0] & 0x0F) * 4;
    if (size < ihl + 8) return false;
    
    // Check UDP ports
    data += ihl;
    size -= ihl;
    USHORT src_port = (data[0] << 8) | data[1];
    USHORT dst_port = (data[2] << 8) | data[3];
    if (src_port != 67 || dst_port != 68) {
        // Debug: Log UDP port mismatch for potential DHCP ACK packets
        if ((src_port == 67 && dst_port != 68) || (src_port != 67 && dst_port == 68)) {
            printf("[ParseDhcpAck] ⚠️ UDP port mismatch: src=%u, dst=%u (expected 67->68)\n", src_port, dst_port);
        }
        return false;
    }
    
    // Skip UDP header
    data += 8;
    size -= 8;
    
    // Parse DHCP
    if (size < 240) {
        printf("[ParseDhcpAck] ⚠️ DHCP packet too small: %u bytes (expected >= 240)\n", size);
        return false;
    }
    if (data[0] != 2) {
        printf("[ParseDhcpAck] ⚠️ Not BOOTREPLY: op=%u (expected 2)\n", data[0]);
        return false; // BOOTREPLY
    }
    
    // Check transaction ID
    UINT32 xid = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    if (xid != expected_xid) {
        printf("[ParseDhcpAck] ⚠️ Transaction ID mismatch: got 0x%08x, expected 0x%08x\n", xid, expected_xid);
        return false;
    }
    
    printf("[ParseDhcpAck] 🔍 DHCP packet with matching xid! Parsing options...\n");
    
    // Extract yiaddr (your IP address)
    UINT32 yiaddr = (data[16] << 24) | (data[17] << 16) | (data[18] << 8) | data[19];
    if (yiaddr == 0) {
        printf("[ParseDhcpAck] ⚠️ yiaddr is 0\n");
        return false;
    }
    
    *out_ip = yiaddr;
    
    // Parse DHCP options
    if (size < 240) return false;
    UINT32 magic = (data[236] << 24) | (data[237] << 16) | (data[238] << 8) | data[239];
    if (magic != 0x63825363) return false;
    
    UCHAR *options = data + 240;
    UINT options_len = size - 240;
    UINT pos = 0;
    
    *out_mask = 0;
    *out_gw = 0;
    bool is_ack = false;
    
    printf("[ParseDhcpAck] 🔎 Parsing DHCP options (length=%u)...\n", options_len);
    
    while (pos < options_len) {
        UCHAR opt_type = options[pos++];
        if (opt_type == 0xFF) break;
        if (opt_type == 0x00) continue;
        
        if (pos >= options_len) break;
        UCHAR opt_len = options[pos++];
        if (pos + opt_len > options_len) break;
        
        switch (opt_type) {
            case 53: // DHCP Message Type
                if (opt_len >= 1) {
                    UCHAR msg_type = options[pos];
                    printf("[ParseDhcpAck] 📋 DHCP Message Type: %u (5=ACK, 2=OFFER)\n", msg_type);
                    if (msg_type == 5) {
                        is_ack = true; // DHCP ACK
                    }
                }
                break;
            case 1: // Subnet Mask
                if (opt_len >= 4) {
                    *out_mask = (options[pos] << 24) | (options[pos+1] << 16) |
                               (options[pos+2] << 8) | options[pos+3];
                }
                break;
            case 3: // Router/Gateway
                if (opt_len >= 4) {
                    *out_gw = (options[pos] << 24) | (options[pos+1] << 16) |
                             (options[pos+2] << 8) | options[pos+3];
                }
                break;
        }
        
        pos += opt_len;
    }
    
    printf("[ParseDhcpAck] 🏁 Result: is_ack=%d, ip=%u.%u.%u.%u, mask=%u.%u.%u.%u, gw=%u.%u.%u.%u\n",
           is_ack,
           (*out_ip >> 24) & 0xFF, (*out_ip >> 16) & 0xFF, (*out_ip >> 8) & 0xFF, *out_ip & 0xFF,
           (*out_mask >> 24) & 0xFF, (*out_mask >> 16) & 0xFF, (*out_mask >> 8) & 0xFF, *out_mask & 0xFF,
           (*out_gw >> 24) & 0xFF, (*out_gw >> 16) & 0xFF, (*out_gw >> 8) & 0xFF, *out_gw & 0xFF);
    
    return is_ack && (*out_ip != 0);
}

// Parse DHCP OFFER packet
static bool ParseDhcpOffer(UCHAR *data, UINT size, UINT32 expected_xid, UINT32 *out_ip, UINT32 *out_mask, UINT32 *out_gw, UINT32 *out_server) {
    // Skip Ethernet header (14 bytes)
    if (size < 14) return false;
    USHORT ethertype = (data[12] << 8) | data[13];
    if (ethertype != 0x0800) return false;
    
    data += 14;
    size -= 14;
    
    // Check IPv4 UDP
    if (size < 20) return false;
    UCHAR protocol = data[9];
    if (protocol != 17) return false;
    
    // Get IP header length
    UCHAR ihl = (data[0] & 0x0F) * 4;
    if (size < ihl + 8) return false;
    
    // Check UDP ports (server:67 -> client:68)
    data += ihl;
    size -= ihl;
    USHORT src_port = (data[0] << 8) | data[1];
    USHORT dst_port = (data[2] << 8) | data[3];
    if (src_port != 67 || dst_port != 68) return false;
    
    // Skip UDP header
    data += 8;
    size -= 8;
    
    // Parse DHCP
    if (size < 240) return false;
    if (data[0] != 2) return false; // BOOTREPLY
    
    // Check transaction ID
    UINT32 xid = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    if (xid != expected_xid) return false;
    
    // Extract yiaddr (offered IP address)
    UINT32 yiaddr = (data[16] << 24) | (data[17] << 16) | (data[18] << 8) | data[19];
    if (yiaddr == 0) return false;
    *out_ip = yiaddr;
    
    // Extract siaddr (server IP)
    UINT32 siaddr = (data[20] << 24) | (data[21] << 16) | (data[22] << 8) | data[23];
    
    // Parse DHCP options
    if (size < 240) return false;
    UINT32 magic = (data[236] << 24) | (data[237] << 16) | (data[238] << 8) | data[239];
    if (magic != 0x63825363) return false;
    
    UCHAR *options = data + 240;
    UINT options_len = size - 240;
    UINT pos = 0;
    
    *out_mask = 0;
    *out_gw = 0;
    *out_server = 0;
    bool is_offer = false;
    
    while (pos < options_len) {
        UCHAR opt_type = options[pos++];
        if (opt_type == 0xFF) break;
        if (opt_type == 0x00) continue;
        
        if (pos >= options_len) break;
        UCHAR opt_len = options[pos++];
        if (pos + opt_len > options_len) break;
        
        switch (opt_type) {
            case 53: // DHCP Message Type
                if (opt_len >= 1 && options[pos] == 2) {
                    is_offer = true; // DHCP OFFER
                }
                break;
            case 1: // Subnet Mask
                if (opt_len >= 4) {
                    *out_mask = (options[pos] << 24) | (options[pos+1] << 16) |
                               (options[pos+2] << 8) | options[pos+3];
                }
                break;
            case 3: // Router/Gateway
                if (opt_len >= 4) {
                    *out_gw = (options[pos] << 24) | (options[pos+1] << 16) |
                             (options[pos+2] << 8) | options[pos+3];
                }
                break;
            case 54: // DHCP Server Identifier
                if (opt_len >= 4) {
                    *out_server = (options[pos] << 24) | (options[pos+1] << 16) |
                                 (options[pos+2] << 8) | options[pos+3];
                }
                break;
        }
        
        pos += opt_len;
    }
    
    // Use siaddr if server option not found
    if (*out_server == 0 && siaddr != 0) {
        *out_server = siaddr;
    }
    
    return is_offer && (*out_ip != 0);
}

// Build DHCP REQUEST packet
static UCHAR* BuildDhcpRequest(UCHAR *my_mac, UINT32 xid, UINT32 requested_ip, UINT32 server_ip, UINT *out_size) {
    static UCHAR packet[1024];
    UINT pos = 0;
    
    // Ethernet header (14 bytes)
    // Destination MAC: broadcast
    packet[pos++] = 0xFF; packet[pos++] = 0xFF; packet[pos++] = 0xFF;
    packet[pos++] = 0xFF; packet[pos++] = 0xFF; packet[pos++] = 0xFF;
    // Source MAC
    memcpy(packet + pos, my_mac, 6); pos += 6;
    // EtherType: IPv4
    packet[pos++] = 0x08; packet[pos++] = 0x00;
    
    // IPv4 header (20 bytes)
    UINT ip_header_start = 14;
    packet[pos++] = 0x45; // Version 4, IHL 5
    packet[pos++] = 0x00; // DSCP/ECN
    // Save position for IP total length (will update after building packet)
    UINT ip_total_len_pos = pos;
    packet[pos++] = 0x00; packet[pos++] = 0x00; // Placeholder for total length
    packet[pos++] = 0x00; packet[pos++] = 0x00; // ID
    packet[pos++] = 0x00; packet[pos++] = 0x00; // Flags/Fragment
    packet[pos++] = 64; // TTL
    packet[pos++] = 17; // Protocol: UDP
    packet[pos++] = 0x00; packet[pos++] = 0x00; // Checksum (will calculate)
    // Source IP: 0.0.0.0
    packet[pos++] = 0; packet[pos++] = 0; packet[pos++] = 0; packet[pos++] = 0;
    // Dest IP: 255.255.255.255
    packet[pos++] = 255; packet[pos++] = 255; packet[pos++] = 255; packet[pos++] = 255;
    
    // UDP header (8 bytes)
    UINT udp_header_start = pos;
    packet[pos++] = 0x00; packet[pos++] = 68; // Source port: 68 (DHCP client)
    packet[pos++] = 0x00; packet[pos++] = 67; // Dest port: 67 (DHCP server)
    // Save position for UDP length (will update after building packet)
    UINT udp_len_pos = pos;
    packet[pos++] = 0x00; packet[pos++] = 0x00; // Placeholder for UDP length
    packet[pos++] = 0x00; packet[pos++] = 0x00; // Checksum (optional for IPv4)
    
    // DHCP header (240 bytes minimum)
    packet[pos++] = 0x01; // op: BOOTREQUEST
    packet[pos++] = 0x01; // htype: Ethernet
    packet[pos++] = 0x06; // hlen: 6
    packet[pos++] = 0x00; // hops: 0
    // Transaction ID (4 bytes)
    packet[pos++] = (xid >> 24) & 0xFF;
    packet[pos++] = (xid >> 16) & 0xFF;
    packet[pos++] = (xid >> 8) & 0xFF;
    packet[pos++] = xid & 0xFF;
    // secs, flags
    packet[pos++] = 0x00; packet[pos++] = 0x00;
    packet[pos++] = 0x80; packet[pos++] = 0x00; // Broadcast flag
    // ciaddr, yiaddr, siaddr, giaddr (all zeros)
    for (int i = 0; i < 16; i++) packet[pos++] = 0x00;
    // chaddr (client MAC)
    memcpy(packet + pos, my_mac, 6); pos += 6;
    for (int i = 0; i < 10; i++) packet[pos++] = 0x00; // Padding
    // sname, file (zeros)
    for (int i = 0; i < 192; i++) packet[pos++] = 0x00;
    
    // DHCP magic cookie
    packet[pos++] = 0x63; packet[pos++] = 0x82;
    packet[pos++] = 0x53; packet[pos++] = 0x63;
    
    // DHCP options
    // Option 53: DHCP Message Type = REQUEST (3)
    packet[pos++] = 53; packet[pos++] = 1; packet[pos++] = 3;
    
    // Option 50: Requested IP Address
    packet[pos++] = 50; packet[pos++] = 4;
    packet[pos++] = (requested_ip >> 24) & 0xFF;
    packet[pos++] = (requested_ip >> 16) & 0xFF;
    packet[pos++] = (requested_ip >> 8) & 0xFF;
    packet[pos++] = requested_ip & 0xFF;
    
    // Option 54: DHCP Server Identifier
    packet[pos++] = 54; packet[pos++] = 4;
    packet[pos++] = (server_ip >> 24) & 0xFF;
    packet[pos++] = (server_ip >> 16) & 0xFF;
    packet[pos++] = (server_ip >> 8) & 0xFF;
    packet[pos++] = server_ip & 0xFF;
    
    // Option 55: Parameter Request List
    packet[pos++] = 55; packet[pos++] = 4;
    packet[pos++] = 1;  // Subnet Mask
    packet[pos++] = 3;  // Router
    packet[pos++] = 6;  // DNS
    packet[pos++] = 15; // Domain Name
    
    // Option 255: End
    packet[pos++] = 255;
    
    // Now calculate actual lengths based on final packet size
    UINT total_packet_size = pos;
    USHORT ip_total_len = total_packet_size - ip_header_start;
    USHORT udp_len = total_packet_size - udp_header_start;
    
    // Update IP total length
    packet[ip_total_len_pos] = (ip_total_len >> 8) & 0xFF;
    packet[ip_total_len_pos + 1] = ip_total_len & 0xFF;
    
    // Update UDP length
    packet[udp_len_pos] = (udp_len >> 8) & 0xFF;
    packet[udp_len_pos + 1] = udp_len & 0xFF;
    
    // Calculate IP checksum (must be done after length is set)
    packet[ip_header_start + 10] = 0x00;  // Clear checksum field first
    packet[ip_header_start + 11] = 0x00;
    UINT checksum = 0;
    for (int i = 0; i < 20; i += 2) {
        checksum += (packet[ip_header_start + i] << 8) | packet[ip_header_start + i + 1];
    }
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum = ~checksum & 0xFFFF;
    packet[ip_header_start + 10] = (checksum >> 8) & 0xFF;
    packet[ip_header_start + 11] = checksum & 0xFF;
    
    printf("[BuildDhcpRequest] 📏 Calculated lengths: IP=%u bytes, UDP=%u bytes, Total=%u bytes\n",
           ip_total_len, udp_len, total_packet_size);
    
    *out_size = pos;
    return packet;
}

// Background thread for reading packets from TUN device
void MacOsTunReadThread(THREAD *t, void *param) {
    MACOS_TUN_CONTEXT *ctx = (MACOS_TUN_CONTEXT *)param;
    UCHAR buf[MAX_PACKET_SIZE];
    
    printf("[MacOsTunReadThread] === THREAD STARTED === fd=%d\n", ctx->tun_fd);
    fflush(stdout);
    
    // Signal thread is initialized
    printf("[MacOsTunReadThread] About to call NoticeThreadInit()...\n");
    fflush(stdout);
    
    NoticeThreadInit(t);
    
    printf("[MacOsTunReadThread] NoticeThreadInit() called, entering read loop\n");
    fflush(stdout);
    
    while (!ctx->halt) {
        // Read packet from TUN device (blocking)
        int n = read(ctx->tun_fd, buf, sizeof(buf));
        
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            printf("[MacOsTunReadThread] Read error: %s\n", strerror(errno));
            break;
        }
        
        if (n == 0) {
            printf("[MacOsTunReadThread] TUN device closed\n");
            break;
        }
        
        // Skip 4-byte protocol header (AF_INET/AF_INET6)
        if (n < 4) {
            continue;
        }
        
        // **LEARN OUR IP**: Extract source IP from outgoing IPv4 packets
        if (n >= 24) {  // Minimum IPv4 header = 20 bytes + 4 byte protocol header
            UCHAR *ip_packet = buf + 4;
            UCHAR ip_version = (ip_packet[0] >> 4) & 0x0F;
            
            if (ip_version == 4) {
                // Extract source IP (bytes 12-15 of IPv4 header)
                UINT32 src_ip = (ip_packet[12] << 24) | (ip_packet[13] << 16) | 
                               (ip_packet[14] << 8) | ip_packet[15];
                
                // Learn our IP if not already known (ignore 169.254.x.x link-local)
                if (g_our_ip == 0 && (src_ip & 0xFFFF0000) != 0xA9FE0000) {
                    g_our_ip = src_ip;
                    printf("[MacOsTunReadThread] 🎯 LEARNED OUR IP: %u.%u.%u.%u\n",
                           (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                           (src_ip >> 8) & 0xFF, src_ip & 0xFF);
                    fflush(stdout);
                }
            }
        }
        
        // Log outgoing packets only during DHCP setup or periodically
        static UINT64 read_count = 0;
        if (g_dhcp_state != DHCP_STATE_CONFIGURED || (++read_count % 100) == 1) {
            printf("[MacOsTunReadThread] 📤 Read %d bytes from TUN device (outgoing to VPN)\n", n - 4);
        }
        
        // Allocate packet and copy data
        void *packet_data = Malloc(n - 4);
        Copy(packet_data, buf + 4, n - 4);
        
        TUN_PACKET *pkt = ZeroMalloc(sizeof(TUN_PACKET));
        pkt->data = packet_data;
        pkt->size = n - 4;
        
        // Add to receive queue
        Lock(ctx->queue_lock);
        {
            if (ctx->recv_queue->num_item < RECV_QUEUE_MAX) {
                InsertQueue(ctx->recv_queue, pkt);
                ctx->bytes_received += pkt->size;
                ctx->packets_received++;
            } else {
                // Queue full, drop packet
                Free(pkt->data);
                Free(pkt);
                printf("[MacOsTunReadThread] Queue full, dropping packet\n");
            }
        }
        Unlock(ctx->queue_lock);
        
        // Cancel any blocking waits
        if (ctx->cancel) {
            Cancel(ctx->cancel);
        }
    }
    
    printf("[MacOsTunReadThread] Exiting\n");
}

// Open a macOS TUN device using utun kernel control interface
int OpenMacOsTunDevice(char *device_name, size_t device_name_size) {
#ifdef TARGET_OS_IPHONE
    // On iOS, packet I/O goes through NEPacketTunnelFlow, not utun
    // This function should not be called on iOS
    printf("[OpenMacOsTunDevice] ERROR: Running iOS code path on macOS! TARGET_OS_IPHONE is defined!\n");
    if (device_name && device_name_size > 0) {
        StrCpy(device_name, device_name_size, "ios_network_extension");
    }
    return -1; // No fd needed on iOS
#else
    printf("[OpenMacOsTunDevice] Starting utun device search (macOS code path)...\n");
    struct sockaddr_ctl addr;
    struct ctl_info info;
    int fd = -1;
    int unit_number;
    
    // Get utun control ID first (only need to do this once)
    int temp_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (temp_fd < 0) {
        printf("[OpenMacOsTunDevice] Failed to create socket: %s\n", strerror(errno));
        return -1;
    }
    
    Zero(&info, sizeof(info));
    StrCpy(info.ctl_name, sizeof(info.ctl_name), UTUN_CONTROL_NAME);
    
    if (ioctl(temp_fd, CTLIOCGINFO, &info) < 0) {
        printf("[OpenMacOsTunDevice] ioctl CTLIOCGINFO failed: %s\n", strerror(errno));
        close(temp_fd);
        return -1;
    }
    close(temp_fd);
    
    // Try to connect to utun devices (0-15)
    // Start from 0 and find the first available one
    for (unit_number = 0; unit_number < 16; unit_number++) {
        // Create socket for kernel control
        fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd < 0) {
            printf("[OpenMacOsTunDevice] Failed to create socket for utun%d: %s\n", 
                   unit_number, strerror(errno));
            continue;
        }
        
        // Connect to utun kernel control
        Zero(&addr, sizeof(addr));
        addr.sc_len = sizeof(addr);
        addr.sc_family = AF_SYSTEM;
        addr.ss_sysaddr = AF_SYS_CONTROL;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = unit_number + 1; // utun0 = 1, utun1 = 2, etc.
        
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            printf("[OpenMacOsTunDevice] utun%d busy (%s), trying next...\n", 
                   unit_number, strerror(errno));
            close(fd);
            fd = -1;
            continue;
        }
        
        // Successfully connected!
        printf("[OpenMacOsTunDevice] Successfully connected to utun%d\n", unit_number);
        break;
    }
    
    if (fd < 0) {
        printf("[OpenMacOsTunDevice] Failed to find available utun device\n");
        return -1;
    }
    
    // Get the device name
    socklen_t optlen = (socklen_t)device_name_size;
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, device_name, &optlen) < 0) {
        printf("[OpenMacOsTunDevice] getsockopt UTUN_OPT_IFNAME failed: %s\n", strerror(errno));
        StrCpy(device_name, device_name_size, "utun?");
    }
    
    // Set non-blocking mode
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    
    printf("[OpenMacOsTunDevice] Created TUN device: %s (fd=%d)\n", device_name, fd);
    return fd;
#endif // TARGET_OS_IPHONE
}

// Close TUN device
void CloseMacOsTunDevice(int fd) {
    if (fd >= 0) {
        printf("[CloseMacOsTunDevice] Closing fd=%d\n", fd);
        close(fd);
    }
}

// PA_INIT callback - Initialize TUN device
bool MacOsTunInit(SESSION *s) {
    MACOS_TUN_CONTEXT *ctx;
    
    printf("[MacOsTunInit] === ENTER === session=%p\n", s);
    fflush(stdout);
    
    if (s == NULL) {
        printf("[MacOsTunInit] ERROR: session is NULL\n");
        fflush(stdout);
        return false;
    }
    
    if (s->PacketAdapter == NULL) {
        printf("[MacOsTunInit] ERROR: PacketAdapter is NULL\n");
        fflush(stdout);
        return false;
    }
    
    if (s->PacketAdapter->Param != NULL) {
        printf("[MacOsTunInit] ERROR: Param already set\n");
        fflush(stdout);
        return false;
    }
    
    printf("[MacOsTunInit] Validation passed, allocating context\n");
    fflush(stdout);
    
    // Allocate context
    printf("[MacOsTunInit] Allocating context structure\n");
    fflush(stdout);
    ctx = ZeroMalloc(sizeof(MACOS_TUN_CONTEXT));
    ctx->session = s;
    ctx->halt = false;
    printf("[MacOsTunInit] Context allocated at %p\n", ctx);
    fflush(stdout);
    
    // Open TUN device
    printf("[MacOsTunInit] Opening TUN device...\n");
    fflush(stdout);
    ctx->tun_fd = OpenMacOsTunDevice(ctx->device_name, sizeof(ctx->device_name));
    if (ctx->tun_fd < 0) {
        printf("[MacOsTunInit] ERROR: Failed to open TUN device\n");
        fflush(stdout);
        Free(ctx);
        return false;
    }
    printf("[MacOsTunInit] TUN device opened: %s (fd=%d)\n", ctx->device_name, ctx->tun_fd);
    fflush(stdout);
    
    // **CRITICAL FIX**: Configure TUN interface immediately with temporary IP
    // This allows packets to flow through the interface while DHCP is in progress
    // Using 169.254.x.x (link-local) range for initial configuration
    printf("[MacOsTunInit] ⚠️  Configuring TUN interface with temporary link-local IP...\n");
    fflush(stdout);
    
    // Generate unique link-local address based on MAC
    UINT32 temp_ip = 0xA9FE0000 | ((rand() & 0xFF) << 8) | (rand() & 0xFF); // 169.254.x.x
    UINT32 temp_peer = 0xA9FE0001; // 169.254.0.1 as peer (gateway)
    UINT32 temp_mask = 0xFFFF0000; // 255.255.0.0
    
    char temp_ip_str[64];
    sprintf(temp_ip_str, "%u.%u.%u.%u",
            (temp_ip >> 24) & 0xFF, (temp_ip >> 16) & 0xFF,
            (temp_ip >> 8) & 0xFF, temp_ip & 0xFF);
    
    char temp_peer_str[64];
    sprintf(temp_peer_str, "%u.%u.%u.%u",
            (temp_peer >> 24) & 0xFF, (temp_peer >> 16) & 0xFF,
            (temp_peer >> 8) & 0xFF, temp_peer & 0xFF);
    
    char temp_mask_str[64];
    sprintf(temp_mask_str, "%u.%u.%u.%u",
            (temp_mask >> 24) & 0xFF, (temp_mask >> 16) & 0xFF,
            (temp_mask >> 8) & 0xFF, temp_mask & 0xFF);
    
    // Configure interface immediately - this is REQUIRED for TUN devices to pass packets
    char cmd[512];
    sprintf(cmd, "ifconfig %s %s %s netmask %s up 2>&1",
            ctx->device_name, temp_ip_str, temp_peer_str, temp_mask_str);
    printf("[MacOsTunInit] Executing: %s\n", cmd);
    fflush(stdout);
    
    int result = system(cmd);
    if (result != 0) {
        printf("[MacOsTunInit] ⚠️  Warning: Failed to configure interface (result=%d)\n", result);
        printf("[MacOsTunInit] ⚠️  This may cause packet flow issues!\n");
        fflush(stdout);
    } else {
        printf("[MacOsTunInit] ✅ Interface configured with temporary IP: %s -> %s\n", 
               temp_ip_str, temp_peer_str);
        fflush(stdout);
    }
    
    // Initialize DHCP state
    printf("[MacOsTunInit] Initializing DHCP state...\n");
    fflush(stdout);
    g_dhcp_state = DHCP_STATE_INIT;
    g_connection_start_time = Tick64();  // Record when connection was established
    
    // Generate MAC address matching iPhone/iOS app format
    // Format: 02:00:5E:XX:XX:XX (matches iPhone Network Extension implementation)
    // 02 = Locally administered address, 00:5E = SoftEther prefix
    g_my_mac[0] = 0x02;  // Locally administered
    g_my_mac[1] = 0x00;
    g_my_mac[2] = 0x5E;  // SoftEther prefix
    for (int i = 3; i < 6; i++) {
        g_my_mac[i] = (UCHAR)(rand() % 256);
    }
    printf("[MacOsTunInit] Generated MAC: %02x:%02x:%02x:%02x:%02x:%02x (02:00:5E matches iPhone app)\n",
           g_my_mac[0], g_my_mac[1], g_my_mac[2], 
           g_my_mac[3], g_my_mac[4], g_my_mac[5]);
    fflush(stdout);
    
    // Generate random DHCP transaction ID
    g_dhcp_xid = (UINT32)rand();
    printf("[MacOsTunInit] Generated DHCP XID: 0x%08x\n", g_dhcp_xid);
    fflush(stdout);
    
    // Create synchronization objects
    printf("[MacOsTunInit] Creating synchronization objects...\n");
    fflush(stdout);
    ctx->cancel = NewCancel();
    printf("[MacOsTunInit] Cancel created\n");
    fflush(stdout);
    ctx->recv_queue = NewQueue();
    printf("[MacOsTunInit] Queue created\n");
    fflush(stdout);
    ctx->queue_lock = NewLock();
    printf("[MacOsTunInit] Lock created\n");
    fflush(stdout);
    
    // Start background read thread
    printf("[MacOsTunInit] Starting background read thread...\n");
    fflush(stdout);
    ctx->read_thread = NewThread(MacOsTunReadThread, ctx);
    printf("[MacOsTunInit] NewThread returned, waiting for init...\n");
    fflush(stdout);
    WaitThreadInit(ctx->read_thread);
    printf("[MacOsTunInit] Thread initialized\n");
    fflush(stdout);
    
    // Store context in packet adapter
    s->PacketAdapter->Param = ctx;
    
    printf("[MacOsTunInit] === SUCCESS === TUN device: %s\n", ctx->device_name);
    fflush(stdout);
    
    // 🚀 **CRITICAL FIX**: Queue DHCP/IPv6 packets IMMEDIATELY (SSTP Connect style)
    // Don't wait for GetNextPacket delay - send packets right away!
    // **ORDER MATTERS**: SSTP Connect log shows DHCP sent FIRST, then IPv6 NA, then IPv6 RS!
    printf("[MacOsTunInit] 🚀 Pre-queuing initial packets for instant transmission (SSTP Connect order)...\n");
    fflush(stdout);
    
    // **PACKET 1**: DHCP DISCOVER (FIRST! - matching SSTP Connect line 253)
    UINT dhcp_size = 0;
    UCHAR *dhcp_discover = BuildDhcpDiscover(g_my_mac, g_dhcp_xid, &dhcp_size);
    if (dhcp_discover && dhcp_size > 0) {
        TUN_PACKET *pkt_dhcp = Malloc(sizeof(TUN_PACKET));
        pkt_dhcp->data = Malloc(dhcp_size);  // Allocate memory
        Copy(pkt_dhcp->data, dhcp_discover, dhcp_size);  // Copy from static buffer
        pkt_dhcp->size = dhcp_size;
        Lock(ctx->queue_lock);
        InsertQueue(ctx->recv_queue, pkt_dhcp);
        Unlock(ctx->queue_lock);
        g_dhcp_state = DHCP_STATE_DISCOVER_SENT;
        printf("[MacOsTunInit]   1️⃣  DHCP DISCOVER queued (%u bytes) - FIRST PRIORITY\n", dhcp_size);
        
        // **DEBUG**: Print full DHCP packet in hex for analysis
        printf("[MacOsTunInit] 📋 DHCP DISCOVER packet hex dump:\n");
        for (UINT i = 0; i < dhcp_size; i++) {
            printf("%02x ", dhcp_discover[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        if (dhcp_size % 16 != 0) printf("\n");
        fflush(stdout);
    }
    
    // **PACKET 2**: IPv6 Neighbor Advertisement (matching SSTP Connect line 254)
    UINT ipv6_na_size = 0;
    UCHAR *ipv6_na = BuildNeighborAdvertisement(g_my_mac, &ipv6_na_size);
    if (ipv6_na && ipv6_na_size > 0) {
        TUN_PACKET *pkt_na = Malloc(sizeof(TUN_PACKET));
        pkt_na->data = Malloc(ipv6_na_size);  // Allocate memory
        Copy(pkt_na->data, ipv6_na, ipv6_na_size);  // Copy from static buffer
        pkt_na->size = ipv6_na_size;
        Lock(ctx->queue_lock);
        InsertQueue(ctx->recv_queue, pkt_na);
        Unlock(ctx->queue_lock);
        printf("[MacOsTunInit]   2️⃣  IPv6 NA queued (%u bytes)\n", ipv6_na_size);
    }
    
    // **PACKET 3**: IPv6 Router Solicitation (matching SSTP Connect line 255)
    UINT ipv6_rs_size = 0;
    UCHAR *ipv6_rs = BuildRouterSolicitation(g_my_mac, &ipv6_rs_size);
    if (ipv6_rs && ipv6_rs_size > 0) {
        TUN_PACKET *pkt_rs = Malloc(sizeof(TUN_PACKET));
        pkt_rs->data = Malloc(ipv6_rs_size);  // Allocate memory
        Copy(pkt_rs->data, ipv6_rs, ipv6_rs_size);  // Copy from static buffer
        pkt_rs->size = ipv6_rs_size;
        Lock(ctx->queue_lock);
        InsertQueue(ctx->recv_queue, pkt_rs);
        Unlock(ctx->queue_lock);
        printf("[MacOsTunInit]   3️⃣  IPv6 RS queued (%u bytes)\n", ipv6_rs_size);
    }
    
    // **PACKET 4**: Gratuitous ARP (register MAC without claiming IP)
    UINT garp_size = 0;
    UCHAR *garp = BuildGratuitousArp(g_my_mac, 0, &garp_size);  // 0 = 0.0.0.0
    if (garp && garp_size > 0) {
        TUN_PACKET *pkt_garp = Malloc(sizeof(TUN_PACKET));
        pkt_garp->data = Malloc(garp_size);  // Allocate memory
        Copy(pkt_garp->data, garp, garp_size);  // Copy from static buffer
        pkt_garp->size = garp_size;
        Lock(ctx->queue_lock);
        InsertQueue(ctx->recv_queue, pkt_garp);
        Unlock(ctx->queue_lock);
        printf("[MacOsTunInit]   4️⃣  Gratuitous ARP queued (%u bytes)\n", garp_size);
    }
    
    printf("[MacOsTunInit] ✅ Queued 4 packets in SSTP Connect order: DHCP → IPv6 NA → IPv6 RS → GARP\n");
    fflush(stdout);
    
    // Trigger session to send packets IMMEDIATELY
    Cancel(ctx->cancel);
    printf("[MacOsTunInit] ✅ Triggered session - packets will be sent instantly!\n");
    fflush(stdout);
    
    return true;
}

// PA_GETCANCEL callback - Get cancellation object
CANCEL* MacOsTunGetCancel(SESSION *s) {
    MACOS_TUN_CONTEXT *ctx;
    CANCEL *c;
    
    if (s == NULL || s->PacketAdapter == NULL) {
        return NULL;
    }
    
    ctx = (MACOS_TUN_CONTEXT *)s->PacketAdapter->Param;
    if (ctx == NULL || ctx->cancel == NULL) {
        return NULL;
    }
    
    // Important: AddRef before returning because caller will ReleaseCancel
    c = ctx->cancel;
    AddRef(c->ref);
    
    return c;
}

// PA_GETNEXTPACKET callback - Get next packet from TUN device
UINT MacOsTunGetNextPacket(SESSION *s, void **data) {
    MACOS_TUN_CONTEXT *ctx;
    TUN_PACKET *pkt;
    UINT size = 0;
    
    if (s == NULL || s->PacketAdapter == NULL || data == NULL) {
        return 0;
    }
    
    ctx = (MACOS_TUN_CONTEXT *)s->PacketAdapter->Param;
    if (ctx == NULL) {
        return 0;
    }
    
    // CRITICAL FIX: Send IPv6 packets + DHCP matching SSTP Connect's exact sequence
    // SSTP Connect log shows (lines 251-256):
    // Line 251: "TCP #1: Received Keep-Alive"
    // Line 252: "IPv6 link-local fe80::b9ab:46e2:b7c6:c6a9"
    // Line 253: "Send DHCP Discover"  
    // Line 254: "Send Neighbor Advertisement from fe80::... to ff02::1"
    // Line 255: "Send Router Solicitation from fe80::..."
    // Line 256: "Received DHCP Offer"
    // All packets sent with only 1 TCP connection active, additional connections come AFTER DHCP!
    UINT64 now = Tick64();
    UINT64 time_since_start = (g_connection_start_time > 0) ? (now - g_connection_start_time) : 0;
    
    // **CRITICAL FIX**: Send Gratuitous ARP with 0.0.0.0 to register MAC in bridge WITHOUT claiming an IP!
    // Bridge needs to know our MAC exists to forward unicast DHCP responses, but we can't claim
    // a specific IP before DHCP or the DHCP server will think it's already taken.
    // DELAY 2 seconds to give bridge learning table time to propagate and Mikrotik router time to learn our MAC
    if (g_dhcp_state == DHCP_STATE_INIT && time_since_start >= 2000) {
        UINT pkt_size;
        UINT32 zero_ip = 0x00000000; // 0.0.0.0 - no IP claimed yet
        UCHAR *pkt = BuildGratuitousArp(g_my_mac, zero_ip, &pkt_size);
        if (pkt_size > 0 && pkt != NULL) {
            printf("[MacOsTunGetNextPacket] ⏰ Tunnel established for %llu ms\n", time_since_start);
            printf("[MacOsTunGetNextPacket] 📡 Sending Gratuitous ARP with 0.0.0.0 to register MAC in bridge\n");
            printf("[MacOsTunGetNextPacket]    MAC: %02x:%02x:%02x:%02x:%02x:%02x (no IP claimed yet)\n",
                   g_my_mac[0], g_my_mac[1], g_my_mac[2], g_my_mac[3], g_my_mac[4], g_my_mac[5]);
            UCHAR *pkt_copy = Malloc(pkt_size);
            memcpy(pkt_copy, pkt, pkt_size);
            *data = pkt_copy;
            g_dhcp_state = DHCP_STATE_ARP_ANNOUNCE_SENT; // Move to next state: IPv6
            g_last_state_change_time = Tick64(); // Record state change time
            return pkt_size;
        }
    }
    
    // **PRIORITY: Send ARP Reply if requested** (can happen at any time)
    // This is CRITICAL - if DHCP server sends ARP request and we don't reply,
    // it will think the IP is dead and won't send DHCP ACK!
    if (g_need_arp_reply) {
        UINT pkt_size;
        // Reply with: 1) learned IP, 2) DHCP offered IP, or 3) 0.0.0.0 if neither known
        UINT32 our_ip = (g_our_ip != 0) ? g_our_ip : ((g_offered_ip != 0) ? g_offered_ip : 0x00000000);
        UCHAR *pkt = BuildArpReply(g_my_mac, our_ip, g_arp_reply_to_mac, g_arp_reply_to_ip, &pkt_size);
        if (pkt_size > 0 && pkt != NULL) {
            // Only log gateway ARP replies or during setup
            if (g_arp_reply_to_ip == 0x0A150001 || g_dhcp_state != DHCP_STATE_CONFIGURED) {
                printf("[MacOsTunGetNextPacket] ✅ ARP REPLY to %u.%u.%u.%u\n",
                       (g_arp_reply_to_ip >> 24) & 0xFF, (g_arp_reply_to_ip >> 16) & 0xFF,
                       (g_arp_reply_to_ip >> 8) & 0xFF, g_arp_reply_to_ip & 0xFF);
            }
            UCHAR *pkt_copy = Malloc(pkt_size);
            memcpy(pkt_copy, pkt, pkt_size);
            *data = pkt_copy;
            g_need_arp_reply = false; // Reset flag
            return pkt_size;
        }
    }
    
    // Stage 1: Send IPv6 Neighbor Advertisement AFTER Gratuitous ARP (wait 500ms for ARP to propagate)
    if (g_dhcp_state == DHCP_STATE_ARP_ANNOUNCE_SENT && (Tick64() - g_last_state_change_time) >= 500) {
        UINT pkt_size;
        UCHAR *pkt = BuildNeighborAdvertisement(g_my_mac, &pkt_size);
        if (pkt_size > 0 && pkt != NULL) {
            printf("[MacOsTunGetNextPacket] 📡 Sending IPv6 Neighbor Advertisement (size=%u)\n", pkt_size);
            UCHAR *pkt_copy = Malloc(pkt_size);
            memcpy(pkt_copy, pkt, pkt_size);
            *data = pkt_copy;
            g_dhcp_state = DHCP_STATE_IPV6_NA_SENT;
            g_last_state_change_time = Tick64(); // Record state change time
            return pkt_size;
        }
    }
    
    // Stage 2: Send IPv6 Router Solicitation (wait 200ms after IPv6 NA)
    if (g_dhcp_state == DHCP_STATE_IPV6_NA_SENT && (Tick64() - g_last_state_change_time) >= 200) {
        UINT pkt_size;
        UCHAR *pkt = BuildRouterSolicitation(g_my_mac, &pkt_size);
        if (pkt_size > 0 && pkt != NULL) {
            printf("[MacOsTunGetNextPacket] 📡 Sending IPv6 Router Solicitation (size=%u)\n", pkt_size);
            UCHAR *pkt_copy = Malloc(pkt_size);
            memcpy(pkt_copy, pkt, pkt_size);
            *data = pkt_copy;
            g_dhcp_state = DHCP_STATE_IPV6_RS_SENT;
            g_last_state_change_time = Tick64(); // Record state change time
            return pkt_size;
        }
    }
    
    // Stage 3: Send DHCP DISCOVER (wait 300ms after IPv6 RS, then retry every 3s)
    // DHCP standard: Retry every 3-4 seconds, up to 5 attempts (similar to IPC implementation)
    if (g_dhcp_state == DHCP_STATE_IPV6_RS_SENT || g_dhcp_state == DHCP_STATE_DISCOVER_SENT) {
        UINT64 now = Tick64();
        bool should_send = false;
        
        if (g_dhcp_state == DHCP_STATE_IPV6_RS_SENT) {
            // First send after 300ms delay to let IPv6 packets propagate
            if ((now - g_last_state_change_time) >= 300) {
                should_send = true;
                g_dhcp_state = DHCP_STATE_DISCOVER_SENT;
                g_last_dhcp_send_time = now;
                g_dhcp_retry_count = 0;
            }
        } else if (g_dhcp_state == DHCP_STATE_DISCOVER_SENT) {
            // Retry every 3 seconds, up to 5 attempts (15 seconds total)
            if (g_dhcp_retry_count < 5 && (now - g_last_dhcp_send_time) >= 3000) {
                should_send = true;
                g_last_dhcp_send_time = now;
                g_dhcp_retry_count++;
                printf("[MacOsTunGetNextPacket] 🔄 DHCP DISCOVER retry #%u (no response after %llu ms)\n", 
                       g_dhcp_retry_count, now - g_connection_start_time);
            }
        }
        
        if (should_send) {
            UINT dhcp_size;
            UCHAR *dhcp_pkt = BuildDhcpDiscover(g_my_mac, g_dhcp_xid, &dhcp_size);
            if (dhcp_size > 0 && dhcp_pkt != NULL) {
                printf("[MacOsTunGetNextPacket] 📡 Sending DHCP DISCOVER #%u (xid=0x%08x, size=%u)\n", 
                       g_dhcp_retry_count + 1, g_dhcp_xid, dhcp_size);
                if (g_dhcp_retry_count == 0) {
                    printf("[MacOsTunGetNextPacket] First 100 bytes: ");
                    for (UINT i = 0; i < (dhcp_size < 100 ? dhcp_size : 100); i++) {
                        printf("%02x ", dhcp_pkt[i]);
                    }
                    printf("\n");
                }
                UCHAR *pkt_copy = Malloc(dhcp_size);
                memcpy(pkt_copy, dhcp_pkt, dhcp_size);
                *data = pkt_copy;
                return dhcp_size;
            }
        }
    }
    
    // Send DHCP REQUEST after receiving OFFER
    if (g_dhcp_state == DHCP_STATE_OFFER_RECEIVED) {
        UINT dhcp_size;
        UCHAR *dhcp_pkt = BuildDhcpRequest(g_my_mac, g_dhcp_xid, g_offered_ip, g_dhcp_server_ip, &dhcp_size);
        if (dhcp_size > 0 && dhcp_pkt != NULL) {
            printf("[MacOsTunGetNextPacket] 📤 Sending DHCP REQUEST for IP (xid=0x%08x, size=%u)\n", g_dhcp_xid, dhcp_size);
            // Allocate a copy for the session
            UCHAR *pkt_copy = Malloc(dhcp_size);
            memcpy(pkt_copy, dhcp_pkt, dhcp_size);
            *data = pkt_copy;
            g_dhcp_state = DHCP_STATE_REQUEST_SENT;
            return dhcp_size;
        }
    }
    
    // **CRITICAL FOR MAC/IP TABLE**: Send ARP Request to resolve gateway MAC
    // This mimics SSTP Connect behavior and is essential for SoftEther to add us to MAC/IP table!
    // Must be sent BEFORE keep-alive GARP, right after DHCP configuration (just like SSTP Connect)
    if (g_need_gateway_arp && g_our_ip != 0 && g_gateway_ip != 0) {
        UINT pkt_size;
        UCHAR *pkt = BuildArpRequest(g_my_mac, g_our_ip, g_gateway_ip, &pkt_size);
        if (pkt_size > 0 && pkt != NULL) {
            printf("[MacOsTunGetNextPacket] 🔍 Resolving gateway MAC address for %u.%u.%u.%u\n",
                   (g_gateway_ip >> 24) & 0xFF, (g_gateway_ip >> 16) & 0xFF,
                   (g_gateway_ip >> 8) & 0xFF, g_gateway_ip & 0xFF);
            printf("[MacOsTunGetNextPacket]    This ARP Request will populate SoftEther's MAC/IP table!\n");
            UCHAR *pkt_copy = Malloc(pkt_size);
            memcpy(pkt_copy, pkt, pkt_size);
            *data = pkt_copy;
            g_need_gateway_arp = false;  // Send only once
            return pkt_size;
        }
    }
    
    // **CRITICAL FOR LOCAL BRIDGE**: Send periodic Gratuitous ARP keep-alive
    // This maintains our MAC/IP entry in SoftEther's session table, which is required
    // for Local Bridge mode to forward our traffic to the external router (CHR).
    // Without this, SoftEther doesn't know about our MAC/IP and won't bridge traffic!
    if (g_dhcp_state == DHCP_STATE_CONFIGURED && g_our_ip != 0) {
        UINT64 now = Tick64();
        if (g_last_keepalive_time == 0) {
            g_last_keepalive_time = now;  // Initialize on first call
        }
        
        if ((now - g_last_keepalive_time) >= KEEPALIVE_INTERVAL_MS) {
            UINT pkt_size;
            UCHAR *pkt = BuildGratuitousArp(g_my_mac, g_our_ip, &pkt_size);
            if (pkt_size > 0 && pkt != NULL) {
                printf("[MacOsTunGetNextPacket] 💓 Keep-alive GARP (MAC/IP table refresh)\n");
                UCHAR *pkt_copy = Malloc(pkt_size);
                memcpy(pkt_copy, pkt, pkt_size);
                *data = pkt_copy;
                g_last_keepalive_time = now;  // Update timestamp
                return pkt_size;
            }
        }
    }
    
    // Try to get packet from queue
    Lock(ctx->queue_lock);
    {
        pkt = (TUN_PACKET *)GetNext(ctx->recv_queue);
        if (pkt != NULL) {
            UCHAR *packet_data = (UCHAR *)pkt->data;
            size = pkt->size;
            
            // Check if this is already an Ethernet frame (pre-queued packets) or raw IP packet (from TUN device)
            // Ethernet frames are at least 14 bytes and have dest MAC as first 6 bytes
            // Pre-queued packets (DHCP, IPv6, ARP) are already Ethernet frames, just return them as-is
            bool is_ethernet_frame = false;
            
            if (size >= 14) {
                // Check if EtherType field (bytes 12-13) looks valid
                USHORT ethertype = (packet_data[12] << 8) | packet_data[13];
                if (ethertype == 0x0800 || ethertype == 0x0806 || ethertype == 0x86DD) {
                    // Valid EtherType (IPv4, ARP, or IPv6) - this is already an Ethernet frame
                    is_ethernet_frame = true;
                }
            }
            
            if (is_ethernet_frame) {
                // Already an Ethernet frame (pre-queued packet), return as-is
                printf("[MacOsTunGetNextPacket] 📤 Sending pre-queued Ethernet frame to VPN: %u bytes\n", size);
                *data = pkt->data;  // Transfer ownership to session
                Free(pkt);          // Free packet structure (but NOT pkt->data!)
            } else if (size > 0 && (packet_data[0] & 0xF0) == 0x40) {
                // Raw IPv4 packet from TUN device - add Ethernet header
                UCHAR dest_mac[6];
                USHORT ethertype = 0x0800;
                
                // Use learned gateway MAC if available, otherwise broadcast
                if (g_gateway_mac[0] != 0) {
                    memcpy(dest_mac, g_gateway_mac, 6);
                } else {
                    memset(dest_mac, 0xFF, 6);
                }
                
                // Build Ethernet frame
                UINT eth_size = 14 + size;
                UCHAR *eth_frame = Malloc(eth_size);
                
                memcpy(eth_frame, dest_mac, 6);                    // Dest MAC
                memcpy(eth_frame + 6, g_my_mac, 6);               // Src MAC
                eth_frame[12] = (ethertype >> 8) & 0xFF;          // EtherType
                eth_frame[13] = ethertype & 0xFF;
                memcpy(eth_frame + 14, packet_data, size);        // IP packet
                
                // Log periodically to reduce verbosity
                static UINT64 ipv4_count = 0;
                if (g_dhcp_state != DHCP_STATE_CONFIGURED || (++ipv4_count % 100) == 1) {
                    printf("[MacOsTunGetNextPacket] 📤 IPv4: %u bytes\n", eth_size);
                }
                
                Free(pkt->data);
                Free(pkt);
                *data = eth_frame;
                size = eth_size;
            } else if (size > 0 && (packet_data[0] & 0xF0) == 0x60) {
                // Raw IPv6 packet from TUN device - add Ethernet header
                UCHAR dest_mac[6];
                USHORT ethertype = 0x86DD;
                memset(dest_mac, 0xFF, 6);
                
                UINT eth_size = 14 + size;
                UCHAR *eth_frame = Malloc(eth_size);
                
                memcpy(eth_frame, dest_mac, 6);
                memcpy(eth_frame + 6, g_my_mac, 6);
                eth_frame[12] = (ethertype >> 8) & 0xFF;
                eth_frame[13] = ethertype & 0xFF;
                memcpy(eth_frame + 14, packet_data, size);
                
                printf("[MacOsTunGetNextPacket] 📤 Forwarding IPv6 packet to VPN: %u bytes IP → %u bytes Ethernet\n",
                       size, eth_size);
                
                Free(pkt->data);
                Free(pkt);
                *data = eth_frame;
                size = eth_size;
            } else {
                // Unknown protocol, skip it
                printf("[MacOsTunGetNextPacket] ⚠️  Skipping unknown packet type (first byte: 0x%02x, size: %u)\n", 
                       packet_data[0], size);
                Free(pkt->data);
                Free(pkt);
                size = 0;  // Return 0 to indicate no packet
            }
        }
    }
    Unlock(ctx->queue_lock);
    
    return size;
}

// PA_PUTPACKET callback - Send packet to TUN device
bool MacOsTunPutPacket(SESSION *s, void *data, UINT size) {
    MACOS_TUN_CONTEXT *ctx;
    UCHAR buf[MAX_PACKET_SIZE];
    int n;
    
    if (s == NULL || s->PacketAdapter == NULL) {
        return false;
    }
    
    // Handle flush call (data=NULL, size=0) - just return success
    if (data == NULL || size == 0) {
        return true;
    }
    
    ctx = (MACOS_TUN_CONTEXT *)s->PacketAdapter->Param;
    if (ctx == NULL || ctx->tun_fd < 0) {
        return false;
    }
    
    // Debug: Log incoming packets only during DHCP negotiation
    if (size > 14 && g_dhcp_state != DHCP_STATE_CONFIGURED) {
        USHORT ethertype = (((UCHAR*)data)[12] << 8) | ((UCHAR*)data)[13];
        printf("[MacOsTunPutPacket] 📦 Incoming packet: size=%u, ethertype=0x%04x, state=%d\n", size, ethertype, g_dhcp_state);
        
        // Dump first 64 bytes only for DHCP/ARP packets
        if (ethertype == 0x0806 || ethertype == 0x0800) {
            printf("[MacOsTunPutPacket] First 64 bytes: ");
            for (int i = 0; i < (size < 64 ? size : 64); i++) {
                printf("%02x ", ((UCHAR*)data)[i]);
                if ((i + 1) % 16 == 0) printf("\n[MacOsTunPutPacket]                    ");
            }
            printf("\n");
        }
        
        if (ethertype == 0x0800) {
            // Check if it's UDP port 68 (DHCP client port)
            UCHAR *ip_hdr = (UCHAR*)data + 14;
            if (size >= 34 && ip_hdr[9] == 17) { // Protocol = UDP
                // CRITICAL FIX: Calculate IP header length from IHL field (lower 4 bits of first byte)
                UINT ip_hdr_len = (ip_hdr[0] & 0x0F) * 4;
                if (size >= 14 + ip_hdr_len + 8) { // Need room for UDP header
                    UCHAR *udp_hdr = ip_hdr + ip_hdr_len;
                    USHORT src_port = (udp_hdr[0] << 8) | udp_hdr[1];
                    USHORT dest_port = (udp_hdr[2] << 8) | udp_hdr[3];
                    
                    // Extract source and dest IPs
                    UINT32 src_ip = (ip_hdr[12] << 24) | (ip_hdr[13] << 16) | (ip_hdr[14] << 8) | ip_hdr[15];
                    UINT32 dst_ip = (ip_hdr[16] << 24) | (ip_hdr[17] << 16) | (ip_hdr[18] << 8) | ip_hdr[19];
                    
                    printf("[MacOsTunPutPacket] 📩 UDP: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",
                           (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port,
                           (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF, (dst_ip >> 8) & 0xFF, dst_ip & 0xFF, dest_port);
                    
                    if (dest_port == 68 || src_port == 67) {
                        printf("[MacOsTunPutPacket] *** DHCP PACKET DETECTED! ***\n");
                        // Dump first 100 bytes for debugging
                        printf("[MacOsTunPutPacket] First 100 bytes: ");
                        for (int i = 0; i < (size < 100 ? size : 100); i++) {
                            printf("%02x ", ((UCHAR*)data)[i]);
                        }
                        printf("\n");
                    }
                }
            }
        }
    }
    
    // Handle DHCP responses
    if (g_dhcp_state != DHCP_STATE_CONFIGURED && size > 14) {
        // Check if this is a UDP packet on ports 67/68 (DHCP)
        if (size >= 14) {
            UCHAR *pkt = (UCHAR *)data;
            USHORT ethertype = (pkt[12] << 8) | pkt[13];
            if (ethertype == 0x0800 && size >= 34) { // IPv4
                UCHAR protocol = pkt[23];
                if (protocol == 17) { // UDP
                    USHORT src_port = (pkt[34] << 8) | pkt[35];
                    USHORT dst_port = (pkt[36] << 8) | pkt[37];
                    if (src_port == 67 && dst_port == 68) {
                        printf("[MacOsTunPutPacket] 🔍 Received UDP 67->68 packet (DHCP), size=%u, state=%d\n", size, g_dhcp_state);
                    }
                }
            }
        }
        
        // Check for DHCP OFFER
        if (g_dhcp_state == DHCP_STATE_DISCOVER_SENT) {
            UINT32 ip, mask, gw, server;
            if (ParseDhcpOffer(data, size, g_dhcp_xid, &ip, &mask, &gw, &server)) {
                printf("[MacOsTunPutPacket] 📨 DHCP OFFER received!\n");
                printf("  Offered IP: %u.%u.%u.%u\n", 
                       (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
                printf("  Netmask:    %u.%u.%u.%u\n",
                       (mask >> 24) & 0xFF, (mask >> 16) & 0xFF, (mask >> 8) & 0xFF, mask & 0xFF);
                printf("  Gateway:    %u.%u.%u.%u\n",
                       (gw >> 24) & 0xFF, (gw >> 16) & 0xFF, (gw >> 8) & 0xFF, gw & 0xFF);
                printf("  Server:     %u.%u.%u.%u\n",
                       (server >> 24) & 0xFF, (server >> 16) & 0xFF, (server >> 8) & 0xFF, server & 0xFF);
                
                g_offered_ip = ip;
                g_offered_mask = mask;
                g_offered_gw = gw;
                g_dhcp_server_ip = server;
                g_dhcp_state = DHCP_STATE_OFFER_RECEIVED;
                // Don't write DHCP packets to TUN
                return true;
            }
        }
        
        // Check for DHCP ACK
        if (g_dhcp_state == DHCP_STATE_REQUEST_SENT) {
            UINT32 ip, mask, gw;
            if (ParseDhcpAck(data, size, g_dhcp_xid, &ip, &mask, &gw)) {
                printf("[MacOsTunPutPacket] 🎉 DHCP ACK received!\n");
                
                // **CRITICAL**: Store our IP address for keep-alive GARP
                g_our_ip = ip;
                g_gateway_ip = gw;  // Store gateway IP for ARP resolution
                printf("[MacOsTunPutPacket] 📋 Stored our IP: %u.%u.%u.%u (for periodic keep-alive)\n",
                       (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                       (ip >> 8) & 0xFF, ip & 0xFF);
                printf("[MacOsTunPutPacket] 📋 Gateway IP: %u.%u.%u.%u (will resolve MAC)\n",
                       (gw >> 24) & 0xFF, (gw >> 16) & 0xFF,
                       (gw >> 8) & 0xFF, gw & 0xFF);
                
                if (ConfigureTunInterface(ctx->device_name, ip, mask, gw)) {
                    g_dhcp_state = DHCP_STATE_CONFIGURED;
                    
                    // **CRITICAL**: Request gateway MAC resolution
                    // This is what SSTP Connect does, and it's essential for MAC/IP table!
                    g_need_gateway_arp = true;
                    printf("[MacOsTunPutPacket] 🔍 Will send ARP Request to resolve gateway MAC (like SSTP Connect)\n");
                }
                // Don't write DHCP packets to TUN
                return true;
            }
        }
    }
    
    // Check packet size - allow for Ethernet frame (IP + 14-byte Ethernet header)
    if (size > MAX_ETHERNET_FRAME) {
        printf("[MacOsTunPutPacket] ⚠️  Packet too large: %u bytes (max=%u)\n", size, MAX_ETHERNET_FRAME);
        return false;
    }
    
    UCHAR *pkt = (UCHAR *)data;
    
    // **CRITICAL**: Handle incoming ARP packets!
    // After we send Gratuitous ARP, the network will send ARP requests to verify our IP.
    // We MUST respond to these or DHCP server won't believe we own the IP!
    if (size >= 14) {
        USHORT ethertype = (pkt[12] << 8) | pkt[13];
        if (ethertype == 0x0806) {  // ARP packet
            // Parse ARP
            if (size >= 42) {  // Min ARP packet size (14 eth + 28 arp)
                USHORT opcode = (pkt[20] << 8) | pkt[21];
                UINT32 target_ip = (pkt[38] << 24) | (pkt[39] << 16) | (pkt[40] << 8) | pkt[41];
                
                // Only log ARP during DHCP negotiation to reduce verbosity
                if (g_dhcp_state != DHCP_STATE_CONFIGURED) {
                    printf("[MacOsTunPutPacket] 📬 ARP: opcode=%u, target_ip=%u.%u.%u.%u\n",
                           opcode,
                           (target_ip >> 24) & 0xFF, (target_ip >> 16) & 0xFF,
                           (target_ip >> 8) & 0xFF, target_ip & 0xFF);
                }
                
                // Learn gateway MAC from ARP replies (opcode=2)
                if (opcode == 2) {
                    UINT32 sender_ip = (pkt[28] << 24) | (pkt[29] << 16) | (pkt[30] << 8) | pkt[31];
                    // If this is from 10.21.0.1 (gateway), learn its MAC
                    if (sender_ip == 0x0A150001) {
                        bool mac_changed = (memcmp(g_gateway_mac, pkt + 22, 6) != 0);
                        if (mac_changed || g_gateway_mac[0] == 0) {
                            memcpy(g_gateway_mac, pkt + 22, 6);
                            printf("[MacOsTunPutPacket] 🎯 LEARNED GATEWAY MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                                   g_gateway_mac[0], g_gateway_mac[1], g_gateway_mac[2],
                                   g_gateway_mac[3], g_gateway_mac[4], g_gateway_mac[5]);
                        }
                    }
                }
                
                // If it's an ARP request for our IP (learned, offered, or configured), respond!
                if (opcode == 1) {
                    UINT32 sender_ip = (pkt[28] << 24) | (pkt[29] << 16) | (pkt[30] << 8) | pkt[31];
                    
                    if (target_ip == g_our_ip || target_ip == g_offered_ip || target_ip == 0x0A15FF64) {
                        // Only log ARP requests from gateway (10.21.0.1) or during DHCP setup
                        if (sender_ip == 0x0A150001 || g_dhcp_state != DHCP_STATE_CONFIGURED) {
                            printf("[MacOsTunPutPacket] 📬 ARP Request from %u.%u.%u.%u for our IP, replying\n",
                                   (sender_ip >> 24) & 0xFF, (sender_ip >> 16) & 0xFF,
                                   (sender_ip >> 8) & 0xFF, sender_ip & 0xFF);
                        }
                        // Queue ARP reply - we'll send it in GetNextPacket
                        g_need_arp_reply = true;
                        memcpy(g_arp_reply_to_mac, pkt + 6, 6);  // Sender MAC
                        g_arp_reply_to_ip = sender_ip;
                    }
                }
            }
            // Don't write ARP to TUN device (Layer 2 packet, TUN is Layer 3)
            return true;
        }
    }
    
    UCHAR *ip_packet = pkt;
    UINT ip_size = size;
    UINT32 proto;
    
    // Check if this is an Ethernet frame (Layer 2) that needs stripping
    // Ethernet frame: [6 bytes dest MAC][6 bytes src MAC][2 bytes EtherType][payload]
    if (size >= 14) {
        USHORT ethertype = (pkt[12] << 8) | pkt[13];
        
        if (ethertype == 0x0800) {
            // IPv4 in Ethernet frame - strip the 14-byte Ethernet header
            ip_packet = pkt + 14;
            ip_size = size - 14;
            proto = htonl(AF_INET);
        } else if (ethertype == 0x86DD) {
            // IPv6 in Ethernet frame - strip the 14-byte Ethernet header
            ip_packet = pkt + 14;
            ip_size = size - 14;
            proto = htonl(AF_INET6);
        } else if ((pkt[0] & 0xF0) == 0x40) {
            // Raw IPv4 packet (no Ethernet header)
            proto = htonl(AF_INET);
        } else if ((pkt[0] & 0xF0) == 0x60) {
            // Raw IPv6 packet (no Ethernet header)
            proto = htonl(AF_INET6);
        } else {
            // Unknown protocol - skip it
            printf("[MacOsTunPutPacket] Skipping unknown EtherType 0x%04x\n", ethertype);
            return true;
        }
    } else if (size > 0 && (pkt[0] & 0xF0) == 0x40) {
        // Raw IPv4 packet
        proto = htonl(AF_INET);
    } else if (size > 0 && (pkt[0] & 0xF0) == 0x60) {
        // Raw IPv6 packet
        proto = htonl(AF_INET6);
    } else {
        // Too small or unknown - skip it
        return true;
    }
    
    // Write protocol header + packet
    Copy(buf, &proto, 4);
    Copy(buf + 4, ip_packet, ip_size);
    
    n = write(ctx->tun_fd, buf, ip_size + 4);
    if (n < 0) {
        if (errno != EINTR && errno != EAGAIN) {
            printf("[MacOsTunPutPacket] Write error: %s\n", strerror(errno));
            return false;
        }
        return true; // Temporary error, consider success
    }
    
    ctx->bytes_sent += ip_size;
    ctx->packets_sent++;
    
    return true;
}

// PA_FREE callback - Cleanup TUN device
// Restore original routing configuration on disconnect
static void RestoreRouting(void) {
#ifndef TARGET_OS_IPHONE
    if (!g_routes_configured || g_original_gateway == 0) {
        printf("[RestoreRouting] No routes to restore\n");
        return;
    }
    
    char cmd[512];
    char gw_str[32];
    
    snprintf(gw_str, sizeof(gw_str), "%u.%u.%u.%u",
             (g_original_gateway >> 24) & 0xFF, (g_original_gateway >> 16) & 0xFF,
             (g_original_gateway >> 8) & 0xFF, g_original_gateway & 0xFF);
    
    printf("\n");
    printf("╔════════════════════════════════════════════╗\n");
    printf("║     Restoring Original Routing             ║\n");
    printf("╠════════════════════════════════════════════╣\n");
    printf("║ Original Gateway: %-24s ║\n", gw_str);
    printf("╚════════════════════════════════════════════╝\n");
    printf("\n");
    
    // Delete VPN default route
    printf("[RestoreRouting] 🔄 Removing VPN default route...\n");
    snprintf(cmd, sizeof(cmd), "route delete default 2>&1");
    FILE *fp = popen(cmd, "r");
    if (fp) {
        char result[256];
        while (fgets(result, sizeof(result), fp)) {
            printf("%s", result);
        }
        pclose(fp);
    }
    
    // Restore original default route
    printf("[RestoreRouting] ✅ Restoring original default route: %s\n", gw_str);
    snprintf(cmd, sizeof(cmd), "route add default %s 2>&1", gw_str);
    fp = popen(cmd, "r");
    if (fp) {
        char result[256];
        while (fgets(result, sizeof(result), fp)) {
            printf("%s", result);
        }
        pclose(fp);
    }
    
    // Clean up host routes (VPN server and local network)
    if (g_vpn_server_ip != 0) {
        char vpn_str[32];
        snprintf(vpn_str, sizeof(vpn_str), "%u.%u.%u.%u",
                 (g_vpn_server_ip >> 24) & 0xFF, (g_vpn_server_ip >> 16) & 0xFF,
                 (g_vpn_server_ip >> 8) & 0xFF, g_vpn_server_ip & 0xFF);
        printf("[RestoreRouting] 🧹 Cleaning up VPN server route: %s\n", vpn_str);
        snprintf(cmd, sizeof(cmd), "route delete -host %s 2>&1", vpn_str);
        fp = popen(cmd, "r");
        if (fp) pclose(fp);
    }
    
    printf("\n✅ Original routing restored successfully\n");
    printf("   • Internet connectivity through %s\n", gw_str);
    printf("   • VPN routes cleaned up\n\n");
    
    g_routes_configured = false;
#endif
}

void MacOsTunFree(SESSION *s) {
    MACOS_TUN_CONTEXT *ctx;
    TUN_PACKET *pkt;
    
    printf("[MacOsTunFree] Cleaning up macOS TUN adapter\n");
    
    // Restore original routing FIRST (before closing TUN device)
    RestoreRouting();
    
    if (s == NULL || s->PacketAdapter == NULL) {
        return;
    }
    
    ctx = (MACOS_TUN_CONTEXT *)s->PacketAdapter->Param;
    if (ctx == NULL) {
        return;
    }
    
    // Stop read thread
    ctx->halt = true;
    if (ctx->cancel) {
        Cancel(ctx->cancel);
    }
    
    if (ctx->read_thread) {
        WaitThread(ctx->read_thread, 5000);
        ReleaseThread(ctx->read_thread);
    }
    
    // Close TUN device
    CloseMacOsTunDevice(ctx->tun_fd);
    
    // Free queued packets
    if (ctx->recv_queue) {
        Lock(ctx->queue_lock);
        {
            while ((pkt = (TUN_PACKET *)GetNext(ctx->recv_queue)) != NULL) {
                Free(pkt->data);
                Free(pkt);
            }
        }
        Unlock(ctx->queue_lock);
        ReleaseQueue(ctx->recv_queue);
    }
    
    // Free synchronization objects
    if (ctx->queue_lock) {
        DeleteLock(ctx->queue_lock);
    }
    if (ctx->cancel) {
        ReleaseCancel(ctx->cancel);
    }
    
    printf("[MacOsTunFree] Statistics - Sent: %llu packets (%llu bytes), Received: %llu packets (%llu bytes)\n",
           ctx->packets_sent, ctx->bytes_sent, ctx->packets_received, ctx->bytes_received);
    
    Free(ctx);
    s->PacketAdapter->Param = NULL;
    
    printf("[MacOsTunFree] Cleanup complete\n");
}

// Create a new macOS TUN packet adapter
PACKET_ADAPTER* NewMacOsTunAdapter() {
    PACKET_ADAPTER *pa;
    
    printf("[NewMacOsTunAdapter] Creating macOS TUN packet adapter\n");
    fflush(stdout);
    
    printf("[NewMacOsTunAdapter] Calling NewPacketAdapter with callbacks:\n");
    printf("  Init=%p, GetCancel=%p, GetNext=%p, Put=%p, Free=%p\n",
           MacOsTunInit, MacOsTunGetCancel, MacOsTunGetNextPacket,
           MacOsTunPutPacket, MacOsTunFree);
    fflush(stdout);
    
    pa = NewPacketAdapter(
        MacOsTunInit,
        MacOsTunGetCancel,
        MacOsTunGetNextPacket,
        MacOsTunPutPacket,
        MacOsTunFree
    );
    
    printf("[NewMacOsTunAdapter] NewPacketAdapter returned: %p\n", pa);
    fflush(stdout);
    
    if (pa) {
        pa->Id = PACKET_ADAPTER_ID_VLAN_WIN32; // Reuse ID since it's just for tracking
        pa->Param = NULL; // Will be set in Init callback
        printf("[NewMacOsTunAdapter] Set pa->Id=%u, pa->Param=%p\n", pa->Id, pa->Param);
        printf("[NewMacOsTunAdapter] Packet adapter created successfully\n");
        fflush(stdout);
    } else {
        printf("[NewMacOsTunAdapter] Failed to create packet adapter\n");
        fflush(stdout);
    }
    
    return pa;
}
