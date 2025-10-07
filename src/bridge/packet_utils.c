// SoftEther VPN Zig Client - Shared Packet Utilities Implementation
// Common packet building and parsing functions for all platforms
// Extracted from packet_adapter_macos.c to reduce code duplication

#include "packet_utils.h"
#include "logging.h"
#include <string.h>

// ============================================================================
// IPv6 Packet Building Functions
// ============================================================================

UCHAR *BuildRouterSolicitation(UCHAR *my_mac, UINT *out_size)
{
    static UCHAR packet[1024];
    UINT pos = 0;

    // Ethernet header (14 bytes)
    // Destination MAC: IPv6 all-routers multicast (33:33:00:00:00:02)
    packet[pos++] = 0x33;
    packet[pos++] = 0x33;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 0x02;
    // Source MAC
    memcpy(packet + pos, my_mac, 6);
    pos += 6;
    // EtherType: IPv6
    packet[pos++] = 0x86;
    packet[pos++] = 0xDD;

    // IPv6 header (40 bytes)
    packet[pos++] = 0x60; // Version 6
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;   // Traffic class + flow label
    USHORT payload_len = 8; // ICMPv6 Router Solicitation length
    packet[pos++] = (payload_len >> 8) & 0xFF;
    packet[pos++] = payload_len & 0xFF;
    packet[pos++] = 58;  // Next header: ICMPv6
    packet[pos++] = 255; // Hop limit

    // Source: IPv6 link-local address generated from MAC (fe80::)
    packet[pos++] = 0xFE;
    packet[pos++] = 0x80;
    for (int i = 0; i < 6; i++)
        packet[pos++] = 0x00;
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
    packet[pos++] = 0xFF;
    packet[pos++] = 0x02;
    for (int i = 0; i < 12; i++)
        packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 0x02;

    // ICMPv6 Router Solicitation (8 bytes)
    packet[pos++] = 133; // Type: Router Solicitation
    packet[pos++] = 0;   // Code
    packet[pos++] = 0x00;
    packet[pos++] = 0x00; // Checksum (will calculate)
    packet[pos++] = 0x00;
    packet[pos++] = 0x00; // Reserved
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;

    // Calculate ICMPv6 checksum (simplified - set to 0 for now)
    packet[54] = 0x00;
    packet[55] = 0x00;

    *out_size = pos;
    return packet;
}

UCHAR *BuildNeighborAdvertisement(UCHAR *my_mac, UINT *out_size)
{
    static UCHAR packet[1024];
    UINT pos = 0;

    // Ethernet header (14 bytes)
    // Destination MAC: IPv6 all-nodes multicast (33:33:00:00:00:01)
    packet[pos++] = 0x33;
    packet[pos++] = 0x33;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 0x01;
    // Source MAC
    memcpy(packet + pos, my_mac, 6);
    pos += 6;
    // EtherType: IPv6
    packet[pos++] = 0x86;
    packet[pos++] = 0xDD;

    // IPv6 header (40 bytes)
    packet[pos++] = 0x60; // Version 6
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;    // Traffic class + flow label
    USHORT payload_len = 24; // ICMPv6 Neighbor Advertisement length
    packet[pos++] = (payload_len >> 8) & 0xFF;
    packet[pos++] = payload_len & 0xFF;
    packet[pos++] = 58;  // Next header: ICMPv6
    packet[pos++] = 255; // Hop limit

    // Source: IPv6 link-local address generated from MAC (fe80::)
    packet[pos++] = 0xFE;
    packet[pos++] = 0x80;
    for (int i = 0; i < 6; i++)
        packet[pos++] = 0x00;
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
    packet[pos++] = 0xFF;
    packet[pos++] = 0x02;
    for (int i = 0; i < 13; i++)
        packet[pos++] = 0x00;
    packet[pos++] = 0x01;

    // ICMPv6 Neighbor Advertisement (24 bytes)
    packet[pos++] = 136; // Type: Neighbor Advertisement
    packet[pos++] = 0;   // Code
    packet[pos++] = 0x00;
    packet[pos++] = 0x00; // Checksum (will calculate)
    packet[pos++] = 0x00;
    packet[pos++] = 0x00; // Flags (solicited=0, override=0)
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;

    // Target address (same as source IPv6 link-local)
    packet[pos++] = 0xFE;
    packet[pos++] = 0x80;
    for (int i = 0; i < 6; i++)
        packet[pos++] = 0x00;
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

// ============================================================================
// ARP Packet Building Functions
// ============================================================================

UCHAR *BuildGratuitousArp(UCHAR *my_mac, UINT32 my_ip, UINT *out_size)
{
    static UCHAR packet[1024];
    UINT pos = 0;

    // Ethernet header (14 bytes)
    // Destination MAC: broadcast (for gratuitous ARP)
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    // Source MAC
    memcpy(packet + pos, my_mac, 6);
    pos += 6;
    // EtherType: ARP (0x0806)
    packet[pos++] = 0x08;
    packet[pos++] = 0x06;

    // ARP packet (28 bytes)
    // Hardware type: Ethernet (1)
    packet[pos++] = 0x00;
    packet[pos++] = 0x01;
    // Protocol type: IPv4 (0x0800)
    packet[pos++] = 0x08;
    packet[pos++] = 0x00;
    // Hardware size: 6
    packet[pos++] = 0x06;
    // Protocol size: 4
    packet[pos++] = 0x04;
    // Opcode: Request (1) - Gratuitous ARP uses Request
    packet[pos++] = 0x00;
    packet[pos++] = 0x01;

    // Sender MAC address
    memcpy(packet + pos, my_mac, 6);
    pos += 6;

    // Sender IP address
    packet[pos++] = (my_ip >> 24) & 0xFF;
    packet[pos++] = (my_ip >> 16) & 0xFF;
    packet[pos++] = (my_ip >> 8) & 0xFF;
    packet[pos++] = my_ip & 0xFF;

    // Target MAC address (00:00:00:00:00:00 for gratuitous ARP)
    for (int i = 0; i < 6; i++)
        packet[pos++] = 0x00;

    // Target IP address (same as sender IP for gratuitous ARP)
    packet[pos++] = (my_ip >> 24) & 0xFF;
    packet[pos++] = (my_ip >> 16) & 0xFF;
    packet[pos++] = (my_ip >> 8) & 0xFF;
    packet[pos++] = my_ip & 0xFF;

    *out_size = pos;
    return packet;
}

UCHAR *BuildArpReply(UCHAR *my_mac, UINT32 my_ip, UCHAR *target_mac, UINT32 target_ip, UINT *out_size)
{
    static UCHAR packet[1024];
    UINT pos = 0;

    // Ethernet header (14 bytes)
    // Destination MAC: the requester's MAC
    memcpy(packet + pos, target_mac, 6);
    pos += 6;
    // Source MAC: our MAC
    memcpy(packet + pos, my_mac, 6);
    pos += 6;
    // EtherType: ARP (0x0806)
    packet[pos++] = 0x08;
    packet[pos++] = 0x06;

    // ARP packet (28 bytes)
    // Hardware type: Ethernet (1)
    packet[pos++] = 0x00;
    packet[pos++] = 0x01;
    // Protocol type: IPv4 (0x0800)
    packet[pos++] = 0x08;
    packet[pos++] = 0x00;
    // Hardware size: 6
    packet[pos++] = 0x06;
    // Protocol size: 4
    packet[pos++] = 0x04;
    // Opcode: Reply (2)
    packet[pos++] = 0x00;
    packet[pos++] = 0x02;

    // Sender MAC address (us)
    memcpy(packet + pos, my_mac, 6);
    pos += 6;

    // Sender IP address (our IP - learned from DHCP or configuration)
    packet[pos++] = (my_ip >> 24) & 0xFF;
    packet[pos++] = (my_ip >> 16) & 0xFF;
    packet[pos++] = (my_ip >> 8) & 0xFF;
    packet[pos++] = my_ip & 0xFF;

    // Target MAC address (the requester's MAC)
    memcpy(packet + pos, target_mac, 6);
    pos += 6;

    // Target IP address (the requester's IP)
    packet[pos++] = (target_ip >> 24) & 0xFF;
    packet[pos++] = (target_ip >> 16) & 0xFF;
    packet[pos++] = (target_ip >> 8) & 0xFF;
    packet[pos++] = target_ip & 0xFF;

    *out_size = pos;
    return packet;
}

UCHAR *BuildArpRequest(UCHAR *my_mac, UINT32 my_ip, UINT32 target_ip, UINT *out_size)
{
    static UCHAR packet[1024];
    UINT pos = 0;

    // Ethernet header (14 bytes)
    // Destination MAC: broadcast (we don't know target MAC yet)
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    // Source MAC: our MAC
    memcpy(packet + pos, my_mac, 6);
    pos += 6;
    // EtherType: ARP (0x0806)
    packet[pos++] = 0x08;
    packet[pos++] = 0x06;

    // ARP packet (28 bytes)
    // Hardware type: Ethernet (1)
    packet[pos++] = 0x00;
    packet[pos++] = 0x01;
    // Protocol type: IPv4 (0x0800)
    packet[pos++] = 0x08;
    packet[pos++] = 0x00;
    // Hardware size: 6
    packet[pos++] = 0x06;
    // Protocol size: 4
    packet[pos++] = 0x04;
    // Opcode: Request (1)
    packet[pos++] = 0x00;
    packet[pos++] = 0x01;

    // Sender MAC address (us)
    memcpy(packet + pos, my_mac, 6);
    pos += 6;

    // Sender IP address (our IP)
    packet[pos++] = (my_ip >> 24) & 0xFF;
    packet[pos++] = (my_ip >> 16) & 0xFF;
    packet[pos++] = (my_ip >> 8) & 0xFF;
    packet[pos++] = my_ip & 0xFF;

    // Target MAC address (00:00:00:00:00:00 - unknown)
    for (int i = 0; i < 6; i++)
        packet[pos++] = 0x00;

    // Target IP address (gateway we want to resolve)
    packet[pos++] = (target_ip >> 24) & 0xFF;
    packet[pos++] = (target_ip >> 16) & 0xFF;
    packet[pos++] = (target_ip >> 8) & 0xFF;
    packet[pos++] = target_ip & 0xFF;

    *out_size = pos;
    return packet;
}

UCHAR *BuildArpProbe(UCHAR *my_mac, UINT32 target_ip, UINT *out_size)
{
    static UCHAR packet[1024];
    UINT pos = 0;

    // Ethernet header (14 bytes)
    // Destination MAC: broadcast
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    // Source MAC
    memcpy(packet + pos, my_mac, 6);
    pos += 6;
    // EtherType: ARP (0x0806)
    packet[pos++] = 0x08;
    packet[pos++] = 0x06;

    // ARP packet (28 bytes)
    // Hardware type: Ethernet (1)
    packet[pos++] = 0x00;
    packet[pos++] = 0x01;
    // Protocol type: IPv4 (0x0800)
    packet[pos++] = 0x08;
    packet[pos++] = 0x00;
    // Hardware size: 6
    packet[pos++] = 0x06;
    // Protocol size: 4
    packet[pos++] = 0x04;
    // Opcode: Request (1)
    packet[pos++] = 0x00;
    packet[pos++] = 0x01;

    // Sender MAC address
    memcpy(packet + pos, my_mac, 6);
    pos += 6;

    // Sender IP address (0.0.0.0 for ARP Probe)
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;

    // Target MAC address (00:00:00:00:00:00)
    for (int i = 0; i < 6; i++)
        packet[pos++] = 0x00;

    // Target IP address (IP we're probing)
    packet[pos++] = (target_ip >> 24) & 0xFF;
    packet[pos++] = (target_ip >> 16) & 0xFF;
    packet[pos++] = (target_ip >> 8) & 0xFF;
    packet[pos++] = target_ip & 0xFF;

    *out_size = pos;
    return packet;
}

// ============================================================================
// DHCP Packet Building Functions
// ============================================================================

UCHAR *BuildDhcpDiscover(UCHAR *my_mac, UINT32 xid, UINT *out_size)
{
    static UCHAR packet[1024];
    UINT pos = 0;

    // Ethernet header (14 bytes)
    // Destination MAC: broadcast
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    // Source MAC
    memcpy(packet + pos, my_mac, 6);
    pos += 6;
    // EtherType: IPv4
    packet[pos++] = 0x08;
    packet[pos++] = 0x00;

    // IPv4 header (20 bytes)
    packet[pos++] = 0x45; // Version 4, IHL 5
    packet[pos++] = 0x00; // DSCP/ECN
    UINT ip_total_len_pos = pos;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00; // Placeholder for total length
    packet[pos++] = 0x00;
    packet[pos++] = 0x00; // ID
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;       // Flags/Fragment
    packet[pos++] = 64;         // TTL
    packet[pos++] = 17;         // Protocol: UDP
    UINT ip_checksum_pos = pos;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00; // Checksum (will calculate)
    // Source IP: 0.0.0.0
    packet[pos++] = 0;
    packet[pos++] = 0;
    packet[pos++] = 0;
    packet[pos++] = 0;
    // Dest IP: 255.255.255.255
    packet[pos++] = 255;
    packet[pos++] = 255;
    packet[pos++] = 255;
    packet[pos++] = 255;

    // UDP header (8 bytes)
    packet[pos++] = 0x00;
    packet[pos++] = 68; // Source port: 68 (DHCP client)
    packet[pos++] = 0x00;
    packet[pos++] = 67;     // Dest port: 67 (DHCP server)
    UINT udp_len_pos = pos;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00; // Placeholder for UDP length
    packet[pos++] = 0x00;
    packet[pos++] = 0x00; // Checksum (optional for IPv4)

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
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 0x80;
    packet[pos++] = 0x00; // Broadcast flag
    // ciaddr, yiaddr, siaddr, giaddr (all zeros)
    for (int i = 0; i < 16; i++)
        packet[pos++] = 0x00;
    // chaddr (client MAC)
    memcpy(packet + pos, my_mac, 6);
    pos += 6;
    for (int i = 0; i < 10; i++)
        packet[pos++] = 0x00; // Padding
    // sname, file (zeros)
    for (int i = 0; i < 192; i++)
        packet[pos++] = 0x00;

    // DHCP magic cookie
    packet[pos++] = 0x63;
    packet[pos++] = 0x82;
    packet[pos++] = 0x53;
    packet[pos++] = 0x63;

    // DHCP options
    // Option 53: DHCP Message Type = DISCOVER (1)
    packet[pos++] = 53;
    packet[pos++] = 1;
    packet[pos++] = 1;

    // Option 55: Parameter Request List
    packet[pos++] = 55;
    packet[pos++] = 4;
    packet[pos++] = 1;  // Subnet Mask
    packet[pos++] = 3;  // Router
    packet[pos++] = 6;  // DNS
    packet[pos++] = 15; // Domain Name

    // Option 255: End
    packet[pos++] = 255;

    // Update lengths
    UINT ip_header_start = 14;
    UINT udp_header_start = ip_header_start + 20;
    UINT total_packet_size = pos;

    USHORT ip_total_len = total_packet_size - ip_header_start;
    USHORT udp_len = total_packet_size - udp_header_start;

    packet[ip_total_len_pos] = (ip_total_len >> 8) & 0xFF;
    packet[ip_total_len_pos + 1] = ip_total_len & 0xFF;

    packet[udp_len_pos] = (udp_len >> 8) & 0xFF;
    packet[udp_len_pos + 1] = udp_len & 0xFF;

    // Calculate IP checksum
    UINT checksum = 0;
    for (int i = 0; i < 20; i += 2)
    {
        checksum += (packet[ip_header_start + i] << 8) | packet[ip_header_start + i + 1];
    }
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum = ~checksum & 0xFFFF;
    packet[ip_checksum_pos] = (checksum >> 8) & 0xFF;
    packet[ip_checksum_pos + 1] = checksum & 0xFF;

    *out_size = pos;
    return packet;
}

UCHAR *BuildDhcpRequest(UCHAR *my_mac, UINT32 xid, UINT32 requested_ip, UINT32 server_ip, UINT *out_size)
{
    static UCHAR packet[1024];
    UINT pos = 0;

    // Ethernet header (14 bytes)
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    packet[pos++] = 0xFF;
    memcpy(packet + pos, my_mac, 6);
    pos += 6;
    packet[pos++] = 0x08;
    packet[pos++] = 0x00;

    // IPv4 header (20 bytes)
    UINT ip_header_start = 14;
    packet[pos++] = 0x45;
    packet[pos++] = 0x00;
    UINT ip_total_len_pos = pos;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 64;
    packet[pos++] = 17;
    UINT ip_checksum_pos = pos;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 0;
    packet[pos++] = 0;
    packet[pos++] = 0;
    packet[pos++] = 0;
    packet[pos++] = 255;
    packet[pos++] = 255;
    packet[pos++] = 255;
    packet[pos++] = 255;

    // UDP header (8 bytes)
    UINT udp_header_start = pos;
    packet[pos++] = 0x00;
    packet[pos++] = 68;
    packet[pos++] = 0x00;
    packet[pos++] = 67;
    UINT udp_len_pos = pos;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;

    // DHCP header
    packet[pos++] = 0x01;
    packet[pos++] = 0x01;
    packet[pos++] = 0x06;
    packet[pos++] = 0x00;
    packet[pos++] = (xid >> 24) & 0xFF;
    packet[pos++] = (xid >> 16) & 0xFF;
    packet[pos++] = (xid >> 8) & 0xFF;
    packet[pos++] = xid & 0xFF;
    packet[pos++] = 0x00;
    packet[pos++] = 0x00;
    packet[pos++] = 0x80;
    packet[pos++] = 0x00;
    for (int i = 0; i < 16; i++)
        packet[pos++] = 0x00;
    memcpy(packet + pos, my_mac, 6);
    pos += 6;
    for (int i = 0; i < 10; i++)
        packet[pos++] = 0x00;
    for (int i = 0; i < 192; i++)
        packet[pos++] = 0x00;

    // DHCP magic cookie
    packet[pos++] = 0x63;
    packet[pos++] = 0x82;
    packet[pos++] = 0x53;
    packet[pos++] = 0x63;

    // Options
    packet[pos++] = 53;
    packet[pos++] = 1;
    packet[pos++] = 3; // DHCP REQUEST

    packet[pos++] = 50;
    packet[pos++] = 4;
    packet[pos++] = (requested_ip >> 24) & 0xFF;
    packet[pos++] = (requested_ip >> 16) & 0xFF;
    packet[pos++] = (requested_ip >> 8) & 0xFF;
    packet[pos++] = requested_ip & 0xFF;

    packet[pos++] = 54;
    packet[pos++] = 4;
    packet[pos++] = (server_ip >> 24) & 0xFF;
    packet[pos++] = (server_ip >> 16) & 0xFF;
    packet[pos++] = (server_ip >> 8) & 0xFF;
    packet[pos++] = server_ip & 0xFF;

    packet[pos++] = 55;
    packet[pos++] = 4;
    packet[pos++] = 1;
    packet[pos++] = 3;
    packet[pos++] = 6;
    packet[pos++] = 15;

    packet[pos++] = 255;

    // Update lengths
    UINT total_packet_size = pos;
    USHORT ip_total_len = total_packet_size - ip_header_start;
    USHORT udp_len = total_packet_size - udp_header_start;

    packet[ip_total_len_pos] = (ip_total_len >> 8) & 0xFF;
    packet[ip_total_len_pos + 1] = ip_total_len & 0xFF;
    packet[udp_len_pos] = (udp_len >> 8) & 0xFF;
    packet[udp_len_pos + 1] = udp_len & 0xFF;

    // Calculate IP checksum
    UINT checksum = 0;
    for (int i = 0; i < 20; i += 2)
    {
        checksum += (packet[ip_header_start + i] << 8) | packet[ip_header_start + i + 1];
    }
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum = ~checksum & 0xFFFF;
    packet[ip_checksum_pos] = (checksum >> 8) & 0xFF;
    packet[ip_checksum_pos + 1] = checksum & 0xFF;

    *out_size = pos;
    return packet;
}

// ============================================================================
// DHCP Packet Parsing Functions
// ============================================================================

// Temporary globals for DNS (to match macOS adapter behavior)
// These should be passed as parameters in a future refactoring
static UINT32 g_offered_dns1 = 0;
static UINT32 g_offered_dns2 = 0;

bool ParseDhcpOffer(UCHAR *data, UINT size, UINT32 expected_xid,
                    UINT32 *out_ip, UINT32 *out_mask, UINT32 *out_gw, UINT32 *out_server)
{
    if (size < 14) return false;
    USHORT ethertype = (data[12] << 8) | data[13];
    if (ethertype != 0x0800) return false;

    data += 14;
    size -= 14;

    if (size < 20) return false;
    UCHAR protocol = data[9];
    if (protocol != 17) return false;

    UCHAR ihl = (data[0] & 0x0F) * 4;
    if (size < ihl + 8) return false;

    data += ihl;
    size -= ihl;
    USHORT src_port = (data[0] << 8) | data[1];
    USHORT dst_port = (data[2] << 8) | data[3];
    if (src_port != 67 || dst_port != 68) return false;

    data += 8;
    size -= 8;

    if (size < 240) return false;
    if (data[0] != 2) return false;

    UINT32 xid = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    if (xid != expected_xid) return false;

    UINT32 yiaddr = (data[16] << 24) | (data[17] << 16) | (data[18] << 8) | data[19];
    if (yiaddr == 0) return false;
    *out_ip = yiaddr;

    UINT32 siaddr = (data[20] << 24) | (data[21] << 16) | (data[22] << 8) | data[23];

    if (size < 240) return false;
    UINT32 magic = (data[236] << 24) | (data[237] << 16) | (data[238] << 8) | data[239];
    if (magic != 0x63825363) return false;

    UCHAR *options = data + 240;
    UINT options_len = size - 240;
    UINT pos = 0;

    *out_mask = 0;
    *out_gw = 0;
    *out_server = 0;
    g_offered_dns1 = 0;
    g_offered_dns2 = 0;
    bool is_offer = false;

    while (pos < options_len)
    {
        UCHAR opt_type = options[pos++];
        if (opt_type == 0xFF) break;
        if (opt_type == 0x00) continue;

        if (pos >= options_len) break;
        UCHAR opt_len = options[pos++];
        if (pos + opt_len > options_len) break;

        switch (opt_type)
        {
        case 53:
            if (opt_len >= 1 && options[pos] == 2) is_offer = true;
            break;
        case 1:
            if (opt_len >= 4)
                *out_mask = (options[pos] << 24) | (options[pos + 1] << 16) |
                            (options[pos + 2] << 8) | options[pos + 3];
            break;
        case 3:
            if (opt_len >= 4)
                *out_gw = (options[pos] << 24) | (options[pos + 1] << 16) |
                          (options[pos + 2] << 8) | options[pos + 3];
            break;
        case 54:
            if (opt_len >= 4)
                *out_server = (options[pos] << 24) | (options[pos + 1] << 16) |
                              (options[pos + 2] << 8) | options[pos + 3];
            break;
        case 6:
            if (opt_len >= 4)
                g_offered_dns1 = (options[pos] << 24) | (options[pos + 1] << 16) |
                                 (options[pos + 2] << 8) | options[pos + 3];
            if (opt_len >= 8)
                g_offered_dns2 = (options[pos + 4] << 24) | (options[pos + 5] << 16) |
                                 (options[pos + 6] << 8) | options[pos + 7];
            break;
        }

        pos += opt_len;
    }

    if (*out_server == 0 && siaddr != 0)
        *out_server = siaddr;

    return is_offer && (*out_ip != 0);
}

bool ParseDhcpAck(UCHAR *data, UINT size, UINT32 expected_xid,
                  UINT32 *out_ip, UINT32 *out_mask, UINT32 *out_gw)
{
    if (size < 14) return false;
    USHORT ethertype = (data[12] << 8) | data[13];
    if (ethertype != 0x0800) return false;

    data += 14;
    size -= 14;

    if (size < 20) return false;
    UCHAR protocol = data[9];
    if (protocol != 17) return false;

    UCHAR ihl = (data[0] & 0x0F) * 4;
    if (size < ihl + 8) return false;

    data += ihl;
    size -= ihl;
    USHORT src_port = (data[0] << 8) | data[1];
    USHORT dst_port = (data[2] << 8) | data[3];
    if (src_port != 67 || dst_port != 68) return false;

    data += 8;
    size -= 8;

    if (size < 240) return false;
    if (data[0] != 2) return false;

    UINT32 xid = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    if (xid != expected_xid) return false;

    UINT32 yiaddr = (data[16] << 24) | (data[17] << 16) | (data[18] << 8) | data[19];
    if (yiaddr == 0) return false;
    *out_ip = yiaddr;

    if (size < 240) return false;
    UINT32 magic = (data[236] << 24) | (data[237] << 16) | (data[238] << 8) | data[239];
    if (magic != 0x63825363) return false;

    UCHAR *options = data + 240;
    UINT options_len = size - 240;
    UINT pos = 0;

    *out_mask = 0;
    *out_gw = 0;
    bool is_ack = false;

    while (pos < options_len)
    {
        UCHAR opt_type = options[pos++];
        if (opt_type == 0xFF) break;
        if (opt_type == 0x00) continue;

        if (pos >= options_len) break;
        UCHAR opt_len = options[pos++];
        if (pos + opt_len > options_len) break;

        switch (opt_type)
        {
        case 53:
            if (opt_len >= 1 && options[pos] == 5) is_ack = true;
            break;
        case 1:
            if (opt_len >= 4)
                *out_mask = (options[pos] << 24) | (options[pos + 1] << 16) |
                            (options[pos + 2] << 8) | options[pos + 3];
            break;
        case 3:
            if (opt_len >= 4)
                *out_gw = (options[pos] << 24) | (options[pos + 1] << 16) |
                          (options[pos + 2] << 8) | options[pos + 3];
            break;
        }

        pos += opt_len;
    }

    return is_ack && (*out_ip != 0);
}

// ============================================================================
// Utility Functions
// ============================================================================

UINT16 CalculateIPv4Checksum(const UCHAR *data, UINT len)
{
    UINT32 sum = 0;

    for (UINT i = 0; i < len; i += 2)
    {
        if (i + 1 < len)
            sum += (data[i] << 8) | data[i + 1];
        else
            sum += data[i] << 8;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (UINT16)~sum;
}

UINT16 CalculateUDPChecksum(UINT32 src_ip, UINT32 dst_ip, const UCHAR *udp_data, UINT udp_len)
{
    UINT32 sum = 0;

    // Pseudo-header
    sum += (src_ip >> 16) & 0xFFFF;
    sum += src_ip & 0xFFFF;
    sum += (dst_ip >> 16) & 0xFFFF;
    sum += dst_ip & 0xFFFF;
    sum += 17; // UDP protocol
    sum += udp_len;

    // UDP header and data
    for (UINT i = 0; i < udp_len; i += 2)
    {
        if (i + 1 < udp_len)
            sum += (udp_data[i] << 8) | udp_data[i + 1];
        else
            sum += udp_data[i] << 8;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (UINT16)~sum;
}
