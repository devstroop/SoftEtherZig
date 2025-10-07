// SoftEther VPN Zig Client - Shared Packet Utilities
// Common packet building and parsing functions for all platforms
// This reduces code duplication across macOS/Linux/Windows/iOS/Android

#ifndef PACKET_UTILS_H
#define PACKET_UTILS_H

#include "../../SoftEtherVPN_Stable/src/Mayaqua/Mayaqua.h"
#include "../../SoftEtherVPN_Stable/src/Cedar/Cedar.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// ARP Packet Building Functions
// ============================================================================

/**
 * Build a Gratuitous ARP packet (announce our IP/MAC to the network)
 * @param my_mac Our MAC address (6 bytes)
 * @param my_ip Our IP address (network byte order)
 * @param out_size Output: size of the packet
 * @return Pointer to allocated packet data (caller must free)
 */
UCHAR *BuildGratuitousArp(UCHAR *my_mac, UINT32 my_ip, UINT *out_size);

/**
 * Build an ARP Reply packet
 * @param my_mac Our MAC address (6 bytes)
 * @param my_ip Our IP address (network byte order)
 * @param target_mac Target MAC address (6 bytes)
 * @param target_ip Target IP address (network byte order)
 * @param out_size Output: size of the packet
 * @return Pointer to allocated packet data (caller must free)
 */
UCHAR *BuildArpReply(UCHAR *my_mac, UINT32 my_ip, UCHAR *target_mac, UINT32 target_ip, UINT *out_size);

/**
 * Build an ARP Request packet (ask "who has target_ip?")
 * @param my_mac Our MAC address (6 bytes)
 * @param my_ip Our IP address (network byte order)
 * @param target_ip IP address to resolve (network byte order)
 * @param out_size Output: size of the packet
 * @return Pointer to allocated packet data (caller must free)
 */
UCHAR *BuildArpRequest(UCHAR *my_mac, UINT32 my_ip, UINT32 target_ip, UINT *out_size);

/**
 * Build an ARP Probe packet (check if IP is in use)
 * @param my_mac Our MAC address (6 bytes)
 * @param target_ip IP address to probe (network byte order)
 * @param out_size Output: size of the packet
 * @return Pointer to allocated packet data (caller must free)
 */
UCHAR *BuildArpProbe(UCHAR *my_mac, UINT32 target_ip, UINT *out_size);

// ============================================================================
// DHCP Packet Building Functions
// ============================================================================

/**
 * Build a DHCP Discover packet (initial DHCP request)
 * @param my_mac Our MAC address (6 bytes)
 * @param xid DHCP transaction ID
 * @param out_size Output: size of the packet
 * @return Pointer to allocated packet data (caller must free)
 */
UCHAR *BuildDhcpDiscover(UCHAR *my_mac, UINT32 xid, UINT *out_size);

/**
 * Build a DHCP Request packet (request specific IP from server)
 * @param my_mac Our MAC address (6 bytes)
 * @param xid DHCP transaction ID
 * @param requested_ip IP address we want (network byte order)
 * @param server_ip DHCP server IP address (network byte order)
 * @param out_size Output: size of the packet
 * @return Pointer to allocated packet data (caller must free)
 */
UCHAR *BuildDhcpRequest(UCHAR *my_mac, UINT32 xid, UINT32 requested_ip, UINT32 server_ip, UINT *out_size);

// ============================================================================
// DHCP Packet Parsing Functions
// ============================================================================

/**
 * Parse a DHCP Offer packet
 * @param data Packet data
 * @param size Packet size
 * @param expected_xid Expected transaction ID
 * @param out_ip Output: offered IP address
 * @param out_mask Output: subnet mask
 * @param out_gw Output: gateway IP
 * @param out_server Output: DHCP server IP
 * @return true if packet was parsed successfully
 */
bool ParseDhcpOffer(UCHAR *data, UINT size, UINT32 expected_xid, 
                    UINT32 *out_ip, UINT32 *out_mask, UINT32 *out_gw, UINT32 *out_server);

/**
 * Parse a DHCP ACK packet
 * @param data Packet data
 * @param size Packet size
 * @param expected_xid Expected transaction ID
 * @param out_ip Output: assigned IP address
 * @param out_mask Output: subnet mask
 * @param out_gw Output: gateway IP
 * @return true if packet was parsed successfully
 */
bool ParseDhcpAck(UCHAR *data, UINT size, UINT32 expected_xid,
                  UINT32 *out_ip, UINT32 *out_mask, UINT32 *out_gw);

// ============================================================================
// IPv6 Packet Building Functions
// ============================================================================

/**
 * Build an IPv6 Router Solicitation packet
 * @param my_mac Our MAC address (6 bytes)
 * @param out_size Output: size of the packet
 * @return Pointer to allocated packet data (caller must free)
 */
UCHAR *BuildRouterSolicitation(UCHAR *my_mac, UINT *out_size);

/**
 * Build an IPv6 Neighbor Advertisement packet
 * @param my_mac Our MAC address (6 bytes)
 * @param out_size Output: size of the packet
 * @return Pointer to allocated packet data (caller must free)
 */
UCHAR *BuildNeighborAdvertisement(UCHAR *my_mac, UINT *out_size);

// ============================================================================
// Packet Utilities
// ============================================================================

/**
 * Calculate IPv4 checksum
 * @param data Packet data
 * @param len Data length in bytes
 * @return 16-bit checksum
 */
USHORT CalculateIPv4Checksum(const UCHAR *data, UINT len);

/**
 * Calculate UDP checksum
 * @param src_ip Source IP address (network byte order)
 * @param dst_ip Destination IP address (network byte order)
 * @param udp_data UDP header + data
 * @param udp_len Total UDP length
 * @return 16-bit checksum
 */
USHORT CalculateUDPChecksum(UINT32 src_ip, UINT32 dst_ip, const UCHAR *udp_data, UINT udp_len);

#ifdef __cplusplus
}
#endif

#endif // PACKET_UTILS_H
