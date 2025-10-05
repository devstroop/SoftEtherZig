# SecureNAT vs Local Bridge: Key Differences for VPN Client Implementation

## Executive Summary

When implementing a SoftEther VPN client, the **server-side configuration** (SecureNAT vs Local Bridge) fundamentally changes how packets are transmitted between client and server:

- **SecureNAT Mode**: Server sends/receives **Layer 3 IP packets** (no Ethernet headers)
- **Local Bridge Mode**: Server sends/receives **Layer 2 Ethernet frames** (with MAC addresses)

This difference requires the client to perform **Ethernet header stripping/adding** and **MAC address learning through ARP** when connecting to a Local Bridge server.

---

## 1. Packet Format Differences

### SecureNAT Mode (Layer 3)

```
┌─────────────────────────────────────────┐
│        IP Packet (Raw Layer 3)          │
├─────────────────────────────────────────┤
│ Version | IHL | ... | Payload           │
│  (0x45 for IPv4, 0x60 for IPv6)         │
└─────────────────────────────────────────┘

Size: 20+ bytes (IPv4) or 40+ bytes (IPv6)
No MAC addresses, no EtherType
```

**Client receives**: Raw IP packets ready to write to TUN device
**Client sends**: Raw IP packets read from TUN device

### Local Bridge Mode (Layer 2)

```
┌──────────────────────────────────────────────────────┐
│           Ethernet Frame (Layer 2)                   │
├──────────┬───────────┬───────────┬───────────────────┤
│ Dest MAC │  Src MAC  │ EtherType │   IP Packet       │
│ 6 bytes  │  6 bytes  │  2 bytes  │   ...             │
├──────────┴───────────┴───────────┴───────────────────┤
│ 0x0800 = IPv4                                        │
│ 0x0806 = ARP                                         │
│ 0x86DD = IPv6                                        │
└──────────────────────────────────────────────────────┘

Size: 14 bytes header + IP packet payload
Includes full Layer 2 addressing
```

**Client receives**: Ethernet frames that must be **stripped** before writing to TUN
**Client sends**: IP packets that must have Ethernet headers **added** before sending to VPN

---

## 2. Client Implementation Requirements

### For SecureNAT Mode (Simpler)

```c
// ✅ INCOMING: VPN → TUN device
// Packets are already raw IP - just write directly
bool PutPacket(void* data, UINT size) {
    // No processing needed!
    write(tun_fd, data, size);
    return true;
}

// ✅ OUTGOING: TUN device → VPN
// Packets are already raw IP - just send directly
UINT GetNextPacket(void** data) {
    UCHAR* buffer = malloc(MAX_PACKET_SIZE);
    int size = read(tun_fd, buffer, MAX_PACKET_SIZE);
    *data = buffer;
    return size;
}
```

**No MAC learning, no ARP handling, no header manipulation required!**

---

### For Local Bridge Mode (Complex)

#### A. Incoming Packets (VPN → TUN Device)

```c
// 🔧 INCOMING: Must strip Ethernet headers
bool PutPacket(void* data, UINT size) {
    UCHAR* pkt = (UCHAR*)data;
    
    // Check EtherType (bytes 12-13)
    USHORT ethertype = (pkt[12] << 8) | pkt[13];
    
    if (ethertype == 0x0800) {
        // IPv4 Ethernet frame → Strip 14-byte header
        UCHAR* ip_packet = pkt + 14;
        UINT ip_size = size - 14;
        
        // Write raw IP to TUN device
        write(tun_fd, ip_packet, ip_size);
        
    } else if (ethertype == 0x0806) {
        // ARP packet → Handle separately, don't write to TUN
        HandleArpPacket(pkt, size);
        
    } else if (ethertype == 0x86DD) {
        // IPv6 Ethernet frame → Strip 14-byte header
        UCHAR* ip_packet = pkt + 14;
        UINT ip_size = size - 14;
        write(tun_fd, ip_packet, ip_size);
    }
    
    return true;
}
```

**Key: Must detect and strip Ethernet headers before writing to TUN!**

#### B. Outgoing Packets (TUN Device → VPN)

```c
// 🔧 OUTGOING: Must add Ethernet headers
UINT GetNextPacket(void** data) {
    UCHAR buffer[MAX_PACKET_SIZE];
    int ip_size = read(tun_fd, buffer, MAX_PACKET_SIZE);
    
    // Detect IP version
    UCHAR version = (buffer[0] >> 4) & 0x0F;
    USHORT ethertype = (version == 4) ? 0x0800 : 0x86DD;
    
    // Build Ethernet frame
    UINT eth_size = 14 + ip_size;
    UCHAR* eth_frame = malloc(eth_size);
    
    // Add Ethernet header
    memcpy(eth_frame + 0, gateway_mac, 6);      // Dest MAC (learned!)
    memcpy(eth_frame + 6, our_mac, 6);          // Src MAC (our address)
    eth_frame[12] = (ethertype >> 8) & 0xFF;    // EtherType high byte
    eth_frame[13] = ethertype & 0xFF;           // EtherType low byte
    
    // Copy IP packet after header
    memcpy(eth_frame + 14, buffer, ip_size);
    
    *data = eth_frame;
    return eth_size;
}
```

**Key: Must construct proper Ethernet frames with learned MAC addresses!**

---

## 3. MAC Address Learning (Local Bridge Only)

Local Bridge mode requires the client to learn MAC addresses through **ARP (Address Resolution Protocol)**.

### Why MAC Learning is Required

```
┌─────────────────────────────────────────────────────┐
│         SoftEther Server (Local Bridge)             │
│   Maintains MAC/IP table for all clients            │
│   Routes packets based on MAC addresses             │
└──────────────┬──────────────────────────────────────┘
               │
         [MAC/IP Table]
         ┌────────────────────────────┐
         │ MAC              IP        │
         ├────────────────────────────┤
         │ aa:bb:cc:dd:ee:ff → 10.0.1.2 │
         │ 11:22:33:44:55:66 → 10.0.1.1 │  ← Gateway
         └────────────────────────────┘
               │
               ▼
       Our client must:
       1. Announce our MAC/IP (Gratuitous ARP)
       2. Learn gateway MAC (ARP Request/Reply)
       3. Respond to ARP queries (ARP Reply)
```

### Implementation in Code

From `src/bridge/packet_adapter_macos.c`:

```c
// Global state for MAC learning
static UCHAR g_my_mac[6] = {0};           // Our MAC address
static UCHAR g_gateway_mac[6] = {0};      // Learned gateway MAC
static UINT32 g_gateway_ip = 0x0A150001;  // Gateway IP (10.21.0.1)
static UINT32 g_our_ip = 0;               // Our assigned IP

// Step 1: Announce our presence with Gratuitous ARP
// Sends: "This is my MAC address for this IP!"
UCHAR* BuildGratuitousArp(UCHAR* mac, UINT32 ip, UINT* size) {
    UCHAR* arp = malloc(42);  // 14 Ethernet + 28 ARP
    
    // Ethernet header (broadcast)
    memset(arp, 0xFF, 6);           // Dest: broadcast
    memcpy(arp + 6, mac, 6);        // Src: our MAC
    arp[12] = 0x08; arp[13] = 0x06; // EtherType: ARP
    
    // ARP header
    arp[20] = 0x00; arp[21] = 0x01; // Opcode: 1 (request)
    memcpy(arp + 22, mac, 6);       // Sender MAC
    // Sender IP, Target IP, etc.
    
    *size = 42;
    return arp;
}

// Step 2: Request gateway MAC address
UCHAR* BuildArpRequest(UCHAR* mac, UINT32 our_ip, UINT32 target_ip, UINT* size) {
    UCHAR* arp = malloc(42);
    
    // Build ARP request: "Who has target_ip? Tell our_ip"
    // ... (similar structure)
    
    *size = 42;
    return arp;
}

// Step 3: Learn gateway MAC from ARP replies
void HandleArpPacket(UCHAR* pkt, UINT size) {
    if (size >= 42) {
        USHORT opcode = (pkt[20] << 8) | pkt[21];
        
        if (opcode == 2) {  // ARP Reply
            UINT32 sender_ip = (pkt[28] << 24) | (pkt[29] << 16) | 
                               (pkt[30] << 8) | pkt[31];
            
            if (sender_ip == g_gateway_ip) {
                // Learn gateway MAC!
                memcpy(g_gateway_mac, pkt + 22, 6);
                printf("🎯 LEARNED GATEWAY MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       g_gateway_mac[0], g_gateway_mac[1], g_gateway_mac[2],
                       g_gateway_mac[3], g_gateway_mac[4], g_gateway_mac[5]);
            }
        }
    }
}
```

### ARP Sequence Diagram

```
Client                          Server (Bridge)              Gateway Router
  │                                  │                              │
  │ 1. Gratuitous ARP                │                              │
  │  (Announce MAC/IP)               │                              │
  ├─────────────────────────────────>│                              │
  │                                  │ [Updates MAC/IP table]       │
  │                                  │                              │
  │ 2. ARP Request                   │                              │
  │  "Who has 10.21.0.1?"            │                              │
  ├─────────────────────────────────>├─────────────────────────────>│
  │                                  │                              │
  │ 3. ARP Reply                     │                              │
  │  "I'm 11:22:33:44:55:66"         │                              │
  │<─────────────────────────────────┤<─────────────────────────────┤
  │ [Learn gateway MAC]              │                              │
  │                                  │                              │
  │ 4. Send IP packets with          │                              │
  │    proper dest MAC               │                              │
  ├─────────────────────────────────>├─────────────────────────────>│
  │                                  │ [Routes based on MAC]        │
```

---

## 4. Keep-Alive Mechanism (Local Bridge Only)

Local Bridge mode requires **periodic Gratuitous ARP** to maintain the client's entry in the server's MAC/IP table.

```c
#define KEEPALIVE_INTERVAL_MS 30000  // Send every 30 seconds

static UINT64 g_last_keepalive_time = 0;

UINT GetNextPacket(void** data) {
    UINT64 now = Tick64();
    
    // Send periodic keep-alive
    if (g_dhcp_state == DHCP_STATE_CONFIGURED && 
        (now - g_last_keepalive_time) >= KEEPALIVE_INTERVAL_MS) {
        
        UINT pkt_size;
        UCHAR* pkt = BuildGratuitousArp(g_my_mac, g_our_ip, &pkt_size);
        
        *data = pkt;
        g_last_keepalive_time = now;
        return pkt_size;
    }
    
    // ... regular packet processing
}
```

**Without keep-alive**: Server may age out our MAC/IP entry and stop forwarding traffic!

---

## 5. DHCP Handling Differences

### SecureNAT Mode

- **Server has built-in DHCP server** (SecureNAT function)
- Responds directly to DHCP requests
- Client gets IP configuration easily
- Works like a traditional NAT router

### Local Bridge Mode

- **Server bridges to external network**
- DHCP requests forwarded to external DHCP server
- Requires proper Ethernet framing
- Must maintain MAC/IP mappings

```c
// Local Bridge DHCP flow (from packet_adapter_macos.c)

// 1. Send DHCP DISCOVER (as Ethernet frame with our MAC)
UCHAR* BuildDhcpDiscover(UCHAR* mac, UINT32 xid, UINT* size) {
    UCHAR* pkt = malloc(342);  // Ethernet + IP + UDP + DHCP
    
    // Ethernet header
    memset(pkt, 0xFF, 6);       // Dest: broadcast
    memcpy(pkt + 6, mac, 6);    // Src: our MAC
    pkt[12] = 0x08; pkt[13] = 0x00;  // IPv4
    
    // IP + UDP + DHCP options...
    
    *size = 342;
    return pkt;
}

// 2. Receive DHCP OFFER (as Ethernet frame)
// 3. Send DHCP REQUEST (as Ethernet frame)
// 4. Receive DHCP ACK (as Ethernet frame)
// 5. Configure interface and learn gateway MAC
```

---

## 6. Configuration Flag: `RequireBridgeRoutingMode`

From `src/bridge/softether_bridge.c`:

```c
// This flag tells the server we expect Layer 2 frames
opt->RequireBridgeRoutingMode = true;

// Effect on server:
// - s->IsBridgeMode = true
// - Server sends Ethernet frames instead of IP packets
// - Server expects Ethernet frames from client
```

**Critical**: Without this flag, client connected to Local Bridge server will receive malformed packets!

---

## 7. Code Structure Comparison

### SecureNAT Client (Simple)

```
┌──────────────────────────────────┐
│         Client Code              │
├──────────────────────────────────┤
│  TUN Device                      │
│    ↕ Raw IP packets              │
│  SoftEther Session               │
│    ↕ Raw IP packets              │
│  VPN Server (SecureNAT)          │
└──────────────────────────────────┘

Total complexity: ~500 lines
```

### Local Bridge Client (Complex)

```
┌──────────────────────────────────┐
│         Client Code              │
├──────────────────────────────────┤
│  TUN Device (Layer 3)            │
│    ↕ Raw IP packets              │
│  ┌────────────────────────────┐  │
│  │ Ethernet Translation       │  │
│  │ - Strip headers (incoming) │  │
│  │ - Add headers (outgoing)   │  │
│  └────────────────────────────┘  │
│  ┌────────────────────────────┐  │
│  │ ARP Handler                │  │
│  │ - Learn gateway MAC        │  │
│  │ - Respond to ARP queries   │  │
│  │ - Send keep-alives         │  │
│  └────────────────────────────┘  │
│  ┌────────────────────────────┐  │
│  │ MAC Address Table          │  │
│  │ - Our MAC/IP               │  │
│  │ - Gateway MAC/IP           │  │
│  └────────────────────────────┘  │
│  SoftEther Session               │
│    ↕ Ethernet frames             │
│  VPN Server (Local Bridge)       │
└──────────────────────────────────┘

Total complexity: ~2700 lines (packet_adapter_macos.c)
```

---

## 8. Real-World Example from Codebase

### Detection: Is packet Ethernet or IP?

```c
// From packet_adapter_macos.c:2153-2169
bool is_ethernet_frame = false;

if (size >= 14) {
    // Check EtherType field (bytes 12-13)
    USHORT ethertype = (packet_data[12] << 8) | packet_data[13];
    
    if (ethertype == 0x0800 ||  // IPv4
        ethertype == 0x0806 ||  // ARP
        ethertype == 0x86DD) {  // IPv6
        
        is_ethernet_frame = true;
    }
}

if (is_ethernet_frame) {
    // Local Bridge mode - return as-is or strip
    return ProcessEthernetFrame(packet_data, size);
} else {
    // SecureNAT mode or raw IP - process as IP
    return ProcessIpPacket(packet_data, size);
}
```

### Zig Implementation (Working)

From `src/packet/packet.zig`:

```zig
pub const Packet = struct {
    data: []u8,
    len: usize,
    timestamp: i64,
    flags: u8,

    pub const Flags = struct {
        pub const IPV4: u8 = 0x01;
        pub const IPV6: u8 = 0x02;
        pub const ARP: u8 = 0x04;
        pub const ETHERNET: u8 = 0x08;
    };

    /// Detect packet type from first bytes
    fn detectType(data: []const u8) u8 {
        if (data.len == 0) return 0;

        // Check if Ethernet frame (14+ bytes with valid EtherType)
        if (data.len >= 14) {
            const ethertype = (@as(u16, data[12]) << 8) | data[13];
            if (ethertype == 0x0800 or 
                ethertype == 0x0806 or 
                ethertype == 0x86DD) {
                
                var flags = Flags.ETHERNET;
                if (ethertype == 0x0800) flags |= Flags.IPV4;
                if (ethertype == 0x86DD) flags |= Flags.IPV6;
                if (ethertype == 0x0806) flags |= Flags.ARP;
                return flags;
            }
        }

        // Raw IP packet
        const version = (data[0] >> 4) & 0x0F;
        if (version == 4) return Flags.IPV4;
        if (version == 6) return Flags.IPV6;

        return 0;
    }

    pub fn isEthernet(self: Packet) bool {
        return (self.flags & Flags.ETHERNET) != 0;
    }
};
```

---

## 9. Summary Table

| Aspect | SecureNAT Mode | Local Bridge Mode |
|--------|----------------|-------------------|
| **Packet Format** | Layer 3 IP packets | Layer 2 Ethernet frames |
| **Header Size** | 20+ bytes (IP header only) | 14 bytes (Ethernet) + IP header |
| **MAC Addresses** | Not present | Required in every packet |
| **ARP Handling** | Not needed | **Required** for MAC learning |
| **DHCP** | Built-in server | Bridged to external network |
| **Keep-Alive** | Not needed | Gratuitous ARP every 30s |
| **Client Complexity** | Simple (pass-through) | Complex (header manipulation) |
| **Code Lines** | ~500 | ~2700 |
| **TUN Device I/O** | Direct read/write | Strip/add headers |
| **Gateway MAC** | Not needed | **Must be learned via ARP** |

---

## 10. Key Takeaways for Implementation

### When implementing a VPN client:

1. **Detect server mode** via `RequireBridgeRoutingMode` or packet inspection
2. **For Local Bridge**:
   - ✅ Strip Ethernet headers on incoming packets
   - ✅ Add Ethernet headers on outgoing packets
   - ✅ Implement ARP request/reply handling
   - ✅ Learn gateway MAC address
   - ✅ Send Gratuitous ARP keep-alives
   - ✅ Maintain MAC/IP address table

3. **For SecureNAT**:
   - ✅ Pass packets through unchanged
   - ✅ No ARP handling needed
   - ✅ Use built-in DHCP server

### Code Organization:

```
src/packet/
  ├── packet.zig          # Packet type detection (ETHERNET flag)
  ├── adapter.zig         # High-level packet I/O
  └── ethernet.zig        # Header strip/add (for Local Bridge)

src/arp/
  ├── handler.zig         # ARP request/reply
  ├── cache.zig           # MAC address learning
  └── keepalive.zig       # Gratuitous ARP

src/bridge/
  └── packet_adapter_macos.c  # Reference C implementation (2748 lines)
```

---

## 11. References

- `src/packet/packet.zig` - Packet type detection
- `src/packet/adapter.zig` - Zig packet adapter (working)
- `src/bridge/packet_adapter_macos.c` - Full C implementation
- `ZigTapTun/` - Layer 2/3 translation library
- `ARCHITECTURE.md` - Platform architecture
- `src/bridge/Cedar/Session.c` - Server-side mode handling

---

**Document Version**: 1.0  
**Date**: October 5, 2025  
**Status**: Based on working Zig implementation  
