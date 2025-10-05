# Local Bridge Mode - Quick Reference

## TL;DR

When SoftEther server uses **Local Bridge** instead of **SecureNAT**:
- 📦 Packets come as **Ethernet frames** (Layer 2) not IP packets (Layer 3)
- 🔧 Client must **strip** Ethernet headers before writing to TUN device
- 🔨 Client must **add** Ethernet headers before sending to VPN
- 🎯 Client must **learn gateway MAC** via ARP
- 💓 Client must send **Gratuitous ARP keep-alives** every 30s

---

## Packet Structure Difference

### SecureNAT: Raw IP Packets
```
[IP Header][IP Payload]
    ↓ Write directly to TUN device
```

### Local Bridge: Ethernet Frames
```
[Dest MAC][Src MAC][EtherType][IP Header][IP Payload]
    ↓ Must strip 14 bytes before writing to TUN
```

---

## Code Pattern: Incoming (VPN → TUN)

```c
bool PutPacket(void* data, UINT size) {
    UCHAR* pkt = (UCHAR*)data;
    
    // Check if Ethernet frame
    if (size >= 14) {
        USHORT ethertype = (pkt[12] << 8) | pkt[13];
        
        if (ethertype == 0x0800) {  // IPv4
            // Strip Ethernet header (14 bytes)
            write(tun_fd, pkt + 14, size - 14);
            return true;
            
        } else if (ethertype == 0x0806) {  // ARP
            HandleArp(pkt, size);  // Learn MAC, respond to queries
            return true;  // Don't write to TUN
            
        } else if (ethertype == 0x86DD) {  // IPv6
            write(tun_fd, pkt + 14, size - 14);
            return true;
        }
    }
    
    return false;
}
```

---

## Code Pattern: Outgoing (TUN → VPN)

```c
UINT GetNextPacket(void** data) {
    UCHAR ip_packet[MAX_PACKET_SIZE];
    int ip_size = read(tun_fd, ip_packet, MAX_PACKET_SIZE);
    
    if (ip_size <= 0) return 0;
    
    // Build Ethernet frame
    UINT eth_size = 14 + ip_size;
    UCHAR* eth_frame = malloc(eth_size);
    
    // Add Ethernet header
    memcpy(eth_frame + 0, gateway_mac, 6);   // Dest MAC (learned!)
    memcpy(eth_frame + 6, our_mac, 6);       // Src MAC
    
    // EtherType
    UCHAR version = (ip_packet[0] >> 4) & 0x0F;
    if (version == 4) {
        eth_frame[12] = 0x08; eth_frame[13] = 0x00;  // IPv4
    } else {
        eth_frame[12] = 0x86; eth_frame[13] = 0xDD;  // IPv6
    }
    
    // Copy IP packet
    memcpy(eth_frame + 14, ip_packet, ip_size);
    
    *data = eth_frame;
    return eth_size;
}
```

---

## ARP Handling (Required!)

### 1. Announce Our Presence (Gratuitous ARP)

```c
// Send at connection start and every 30 seconds
void SendGratuitousArp() {
    UCHAR arp[42];
    
    // Ethernet: broadcast destination
    memset(arp, 0xFF, 6);           // Dest: ff:ff:ff:ff:ff:ff
    memcpy(arp + 6, our_mac, 6);    // Src: our MAC
    arp[12] = 0x08; arp[13] = 0x06; // EtherType: ARP
    
    // ARP payload
    arp[14] = 0x00; arp[15] = 0x01; // Hardware: Ethernet
    arp[16] = 0x08; arp[17] = 0x00; // Protocol: IPv4
    arp[18] = 0x06;                 // HW size: 6
    arp[19] = 0x04;                 // Proto size: 4
    arp[20] = 0x00; arp[21] = 0x01; // Opcode: 1 (request)
    
    // Sender
    memcpy(arp + 22, our_mac, 6);   // Sender MAC
    memcpy(arp + 28, &our_ip, 4);   // Sender IP
    
    // Target (same as sender for gratuitous)
    memcpy(arp + 32, our_mac, 6);   // Target MAC
    memcpy(arp + 38, &our_ip, 4);   // Target IP
    
    SendToVpn(arp, 42);
}
```

### 2. Request Gateway MAC

```c
void RequestGatewayMac() {
    UCHAR arp[42];
    
    // Similar to gratuitous, but:
    // - Target MAC: 00:00:00:00:00:00
    // - Target IP: gateway IP (10.21.0.1)
    
    memset(arp, 0xFF, 6);           // Broadcast
    memcpy(arp + 6, our_mac, 6);
    arp[12] = 0x08; arp[13] = 0x06;
    
    // ... (ARP header)
    
    memcpy(arp + 22, our_mac, 6);
    memcpy(arp + 28, &our_ip, 4);
    memset(arp + 32, 0x00, 6);      // Unknown target MAC
    memcpy(arp + 38, &gateway_ip, 4);
    
    SendToVpn(arp, 42);
}
```

### 3. Learn from ARP Replies

```c
void HandleArp(UCHAR* pkt, UINT size) {
    if (size < 42) return;
    
    USHORT opcode = (pkt[20] << 8) | pkt[21];
    
    if (opcode == 2) {  // ARP Reply
        UINT32 sender_ip;
        memcpy(&sender_ip, pkt + 28, 4);
        
        if (sender_ip == gateway_ip) {
            // Learn gateway MAC!
            memcpy(gateway_mac, pkt + 22, 6);
            
            printf("✅ Learned gateway MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   gateway_mac[0], gateway_mac[1], gateway_mac[2],
                   gateway_mac[3], gateway_mac[4], gateway_mac[5]);
        }
    }
}
```

---

## EtherType Values (Quick Reference)

| EtherType | Value  | Meaning |
|-----------|--------|---------|
| IPv4      | 0x0800 | Internet Protocol version 4 |
| ARP       | 0x0806 | Address Resolution Protocol |
| IPv6      | 0x86DD | Internet Protocol version 6 |

---

## Packet Size Calculations

```c
// SecureNAT
IP packet:       20-1500 bytes

// Local Bridge
Ethernet frame:  14 + 20-1500 = 34-1514 bytes
                 ↑
                 14-byte Ethernet header
```

---

## Common Pitfalls

### ❌ Mistake 1: Writing Ethernet frames to TUN device
```c
// WRONG - TUN expects Layer 3
write(tun_fd, ethernet_frame, size);  // Will corrupt packets!
```

```c
// CORRECT
write(tun_fd, ethernet_frame + 14, size - 14);
```

### ❌ Mistake 2: Sending raw IP to Local Bridge server
```c
// WRONG - Server expects Ethernet frames
SendToVpn(ip_packet, size);  // Server won't route it!
```

```c
// CORRECT
UCHAR* eth_frame = AddEthernetHeader(ip_packet, size);
SendToVpn(eth_frame, size + 14);
```

### ❌ Mistake 3: Forgetting to learn gateway MAC
```c
// WRONG - Using broadcast or zero MAC
memset(dest_mac, 0xFF, 6);  // Works but inefficient
```

```c
// CORRECT
memcpy(dest_mac, gateway_mac, 6);  // Use learned MAC
```

### ❌ Mistake 4: Not sending keep-alive
```c
// WRONG - Server will age out our entry after ~5 minutes
// No periodic Gratuitous ARP
```

```c
// CORRECT
if ((now - last_keepalive) > 30000) {
    SendGratuitousArp();
    last_keepalive = now;
}
```

---

## Detection: Which Mode is Server Using?

### Method 1: Configuration Flag
```c
opt->RequireBridgeRoutingMode = true;  // Request Local Bridge mode
// Server will respond with s->IsBridgeMode = true
```

### Method 2: Packet Inspection
```c
bool IsEthernetFrame(UCHAR* data, UINT size) {
    if (size < 14) return false;
    
    USHORT ethertype = (data[12] << 8) | data[13];
    return (ethertype == 0x0800 ||  // IPv4
            ethertype == 0x0806 ||  // ARP
            ethertype == 0x86DD);   // IPv6
}

// First packet from server:
UCHAR* first_packet;
UINT size = ReceiveFromVpn(&first_packet);

if (IsEthernetFrame(first_packet, size)) {
    // Local Bridge mode - enable header stripping
    enable_ethernet_translation = true;
} else {
    // SecureNAT mode - pass through
    enable_ethernet_translation = false;
}
```

---

## Implementation Checklist

For Local Bridge support, you **MUST** implement:

- [ ] Ethernet header detection (check EtherType at bytes 12-13)
- [ ] Strip 14-byte Ethernet header on incoming packets
- [ ] Add 14-byte Ethernet header on outgoing packets
- [ ] Generate our MAC address (random or from device)
- [ ] Send initial Gratuitous ARP
- [ ] Send ARP request for gateway
- [ ] Parse ARP replies and learn gateway MAC
- [ ] Respond to ARP requests for our IP
- [ ] Send Gratuitous ARP keep-alive every 30 seconds
- [ ] Handle ARP packets separately (don't write to TUN)
- [ ] Use learned gateway MAC as destination for IP packets

---

## Files to Study

1. **C Reference Implementation**
   - `src/bridge/packet_adapter_macos.c` (lines 2100-2600)
   - Shows complete ARP handling and header stripping

2. **Zig Working Implementation**
   - `src/packet/packet.zig` - Packet type detection
   - `src/packet/adapter.zig` - High-level adapter

3. **Library Project**
   - `ZigTapTun/` - Reusable Layer 2/3 translation

4. **Documentation**
   - `SECURENAT_VS_LOCALBRIDGE.md` - Full comparison
   - `ARCHITECTURE.md` - Overall design

---

## Quick Test

To verify Local Bridge support works:

```bash
# 1. Check packets are Ethernet frames
tcpdump -i utun3 -n -vv

# Look for:
# - 14-byte Ethernet header
# - MAC addresses in output
# - ARP packets

# 2. Monitor ARP traffic
tcpdump -i utun3 arp

# Should see:
# - Gratuitous ARP on connect
# - ARP request for gateway
# - ARP reply with gateway MAC
# - Periodic Gratuitous ARP (every 30s)

# 3. Check gateway MAC learned
# In your logs, look for:
"🎯 LEARNED GATEWAY MAC: xx:xx:xx:xx:xx:xx"
```

---

**Quick Ref Version**: 1.0  
**Last Updated**: October 5, 2025  
