# Packet Flow Diagrams: SecureNAT vs Local Bridge

## Visual Comparison

### SecureNAT Mode - Packet Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                      Application Layer                          │
│                  (Browser, curl, etc.)                          │
└────────────────────────────┬────────────────────────────────────┘
                             │
                        [IP Packet]
                        20+ bytes
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                       TUN Device                                │
│                    (Layer 3 - utun3)                            │
│                                                                 │
│  Read: [45 00 00 54 ...]     (Raw IPv4)                        │
│  Write: [45 00 00 54 ...]    (Raw IPv4)                        │
└────────────────────────────┬────────────────────────────────────┘
                             │
                    ⚡ NO PROCESSING ⚡
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                  VPN Client Adapter                             │
│                                                                 │
│  GetNextPacket():  pass-through                                 │
│  PutPacket():      pass-through                                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
                        [IP Packet]
                        20+ bytes
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                 SoftEther VPN Session                           │
│                   (Layer 3 Mode)                                │
│                                                                 │
│  Encrypt/decrypt IP packets directly                            │
└────────────────────────────┬────────────────────────────────────┘
                             │
                        [Encrypted]
                             │
┌────────────────────────────▼────────────────────────────────────┐
│            VPN Server (SecureNAT Mode)                          │
│                                                                 │
│  ┌──────────────────────────────────────┐                      │
│  │  Built-in NAT Router                 │                      │
│  │  - IP routing                        │                      │
│  │  - Built-in DHCP server              │                      │
│  │  - Port forwarding                   │                      │
│  └──────────────────────────────────────┘                      │
└────────────────────────────┬────────────────────────────────────┘
                             │
                        [IP Packet]
                             │
                             ▼
                        Internet
```

---

### Local Bridge Mode - Packet Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                      Application Layer                          │
│                  (Browser, curl, etc.)                          │
└────────────────────────────┬────────────────────────────────────┘
                             │
                        [IP Packet]
                        20+ bytes
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                       TUN Device                                │
│                    (Layer 3 - utun3)                            │
│                                                                 │
│  Read: [45 00 00 54 ...]     (Raw IPv4)                        │
│  Write: [45 00 00 54 ...]    (Raw IPv4)                        │
└────────────────────────────┬────────────────────────────────────┘
                             │
                ⚡ ETHERNET TRANSLATION ⚡
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                  VPN Client Adapter                             │
│                (Ethernet Translation)                           │
│                                                                 │
│  GetNextPacket():                                               │
│    1. Read IP packet from TUN                                   │
│    2. Add Ethernet header (14 bytes)                            │
│       [Dest MAC][Src MAC][Type][IP Packet]                      │
│    3. Return Ethernet frame                                     │
│                                                                 │
│  PutPacket():                                                   │
│    1. Receive Ethernet frame from VPN                           │
│    2. Check EtherType (bytes 12-13)                             │
│    3. If IP: Strip header, write to TUN                         │
│    4. If ARP: Handle MAC learning                               │
│                                                                 │
│  MAC Learning (ARP):                                            │
│    - Learn gateway MAC: 11:22:33:44:55:66                       │
│    - Send Gratuitous ARP every 30s                              │
│    - Respond to ARP queries                                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                    [Ethernet Frame]
                    14 + 20+ bytes
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                 SoftEther VPN Session                           │
│                   (Layer 2 Mode)                                │
│                                                                 │
│  Encrypt/decrypt Ethernet frames                                │
└────────────────────────────┬────────────────────────────────────┘
                             │
                        [Encrypted]
                             │
┌────────────────────────────▼────────────────────────────────────┐
│            VPN Server (Local Bridge Mode)                       │
│                                                                 │
│  ┌──────────────────────────────────────────┐                  │
│  │  Layer 2 Bridge                          │                  │
│  │  ┌────────────────────────────────────┐  │                  │
│  │  │    MAC/IP Address Table            │  │                  │
│  │  ├────────────────────────────────────┤  │                  │
│  │  │ aa:bb:cc:dd:ee:ff → 10.21.0.2      │  │                  │
│  │  │ 11:22:33:44:55:66 → 10.21.0.1      │  │                  │
│  │  └────────────────────────────────────┘  │                  │
│  │                                           │                  │
│  │  Routes based on MAC addresses            │                  │
│  └──────────────────────────────────────────┘                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                    [Ethernet Frame]
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Physical Network                               │
│              (eth0, external router)                            │
│                                                                 │
│  ┌─────────────────────┐                                        │
│  │  External DHCP      │  ← Real network infrastructure        │
│  │  Gateway Router     │                                        │
│  │  10.21.0.1          │                                        │
│  └─────────────────────┘                                        │
└─────────────────────────────────────────────────────────────────┘
                             │
                             ▼
                        Internet
```

---

## Detailed Packet Transformation

### Outgoing Packet (Client → Server)

#### SecureNAT Mode
```
TUN Device Read:
┌────────────────────────────────────────────┐
│ IP Header (20 bytes)                       │
├────────────────────────────────────────────┤
│ 45 00 00 54 12 34 40 00 40 06 ...         │
└────────────────────────────────────────────┘
         │
         │ (no change)
         ▼
Sent to VPN:
┌────────────────────────────────────────────┐
│ IP Header (20 bytes)                       │
├────────────────────────────────────────────┤
│ 45 00 00 54 12 34 40 00 40 06 ...         │
└────────────────────────────────────────────┘
```

#### Local Bridge Mode
```
TUN Device Read:
┌────────────────────────────────────────────┐
│ IP Header (20 bytes)                       │
├────────────────────────────────────────────┤
│ 45 00 00 54 12 34 40 00 40 06 ...         │
└────────────────────────────────────────────┘
         │
         │ ADD ETHERNET HEADER (14 bytes)
         ▼
┌──────────┬──────────┬──────────┬───────────┐
│ Dest MAC │  Src MAC │EtherType │IP Packet  │
│ 6 bytes  │ 6 bytes  │ 2 bytes  │20+ bytes  │
├──────────┼──────────┼──────────┼───────────┤
│11:22:33:44│aa:bb:cc:dd│08 00     │45 00 00 54│
│:55:66    │:ee:ff    │         │12 34...   │
└──────────┴──────────┴──────────┴───────────┘
    ↑          ↑         ↑
    │          │         └─ IPv4 (0x0800)
    │          └─────────── Our MAC (learned)
    └────────────────────── Gateway MAC (learned via ARP)

Sent to VPN:
Total size: 14 + 20 = 34+ bytes
```

---

### Incoming Packet (Server → Client)

#### SecureNAT Mode
```
Received from VPN:
┌────────────────────────────────────────────┐
│ IP Header (20 bytes)                       │
├────────────────────────────────────────────┤
│ 45 00 00 54 56 78 40 00 40 06 ...         │
└────────────────────────────────────────────┘
         │
         │ (no change)
         ▼
TUN Device Write:
┌────────────────────────────────────────────┐
│ IP Header (20 bytes)                       │
├────────────────────────────────────────────┤
│ 45 00 00 54 56 78 40 00 40 06 ...         │
└────────────────────────────────────────────┘
```

#### Local Bridge Mode
```
Received from VPN:
┌──────────┬──────────┬──────────┬───────────┐
│ Dest MAC │  Src MAC │EtherType │IP Packet  │
│ 6 bytes  │ 6 bytes  │ 2 bytes  │20+ bytes  │
├──────────┼──────────┼──────────┼───────────┤
│aa:bb:cc:dd│11:22:33:44│08 00     │45 00 00 54│
│:ee:ff    │:55:66    │         │56 78...   │
└──────────┴──────────┴──────────┴───────────┘
    ↑          ↑         ↑
    │          │         └─ IPv4 (0x0800)
    │          └─────────── Gateway MAC
    └────────────────────── Our MAC
         │
         │ DETECT ETHERTYPE & STRIP HEADER (14 bytes)
         ▼
┌────────────────────────────────────────────┐
│ IP Header (20 bytes)                       │
├────────────────────────────────────────────┤
│ 45 00 00 54 56 78 40 00 40 06 ...         │
└────────────────────────────────────────────┘

TUN Device Write:
Size: 34 - 14 = 20+ bytes (IP only)
```

---

## ARP Packet Flow (Local Bridge Only)

### Connection Establishment

```
Client                    VPN Server              Network
  │                          │                       │
  │                          │                       │
  ├─ 1. Connect ────────────>│                       │
  │  [TCP handshake]         │                       │
  │                          │                       │
  ├─ 2. Gratuitous ARP ─────>│                       │
  │  [Announce our MAC/IP]   │                       │
  │  Src: aa:bb:cc:dd:ee:ff  ├─ Register in table ──┤
  │  IP:  0.0.0.0            │                       │
  │                          │                       │
  ├─ 3. DHCP DISCOVER ──────>│                       │
  │  [As Ethernet frame]     ├──────────────────────>│
  │  Src MAC: aa:bb:cc:dd:.. │  [Forward to DHCP]   │
  │                          │                       │
  │<─ 4. DHCP OFFER ─────────┤<──────────────────────┤
  │  [As Ethernet frame]     │                       │
  │  IP: 10.21.0.2           │                       │
  │                          │                       │
  ├─ 5. DHCP REQUEST ───────>│──────────────────────>│
  │                          │                       │
  │<─ 6. DHCP ACK ───────────┤<──────────────────────┤
  │  IP: 10.21.0.2           │                       │
  │  GW: 10.21.0.1           │                       │
  │                          │                       │
  ├─ Configure interface ────┤                       │
  │  ifconfig utun3 10.21.0.2│                       │
  │                          │                       │
  ├─ 7. ARP Request ────────>│──────────────────────>│
  │  "Who has 10.21.0.1?"    │  [Forward to network] │
  │                          │                       │
  │<─ 8. ARP Reply ──────────┤<──────────────────────┤
  │  "I'm 11:22:33:44:55:66" │  [Gateway responds]   │
  │                          │                       │
  ├─ Learn gateway MAC ──────┤                       │
  │  Gateway: 11:22:33:44:55:66                      │
  │                          │                       │
  ├─ 9. Gratuitous ARP ─────>│                       │
  │  [Keep-alive with IP]    ├─ Update table ────────┤
  │  Src: aa:bb:cc:dd:ee:ff  │  aa:bb... → 10.21.0.2 │
  │  IP:  10.21.0.2          │                       │
  │                          │                       │
  │                          │                       │
  ├─ 10. IP Packets ────────>│──────────────────────>│
  │  [With gateway MAC]      │  [Routes by MAC]      │
  │                          │                       │
```

---

### ARP Packet Structure

```
Gratuitous ARP (Announce our MAC/IP):
┌────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                             │
├────────────────────────────────────────────────────────┤
│ Dest:   ff:ff:ff:ff:ff:ff  (broadcast)                 │
│ Src:    aa:bb:cc:dd:ee:ff  (our MAC)                   │
│ Type:   08:06              (ARP)                       │
└────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────┐
│ ARP Payload (28 bytes)                                 │
├────────────────────────────────────────────────────────┤
│ Hardware Type:  00:01      (Ethernet)                  │
│ Protocol Type:  08:00      (IPv4)                      │
│ HW Size:        06         (6 bytes)                   │
│ Proto Size:     04         (4 bytes)                   │
│ Opcode:         00:01      (Request)                   │
│                                                        │
│ Sender MAC:     aa:bb:cc:dd:ee:ff                      │
│ Sender IP:      0a:15:00:02  (10.21.0.2)               │
│ Target MAC:     aa:bb:cc:dd:ee:ff  (same - gratuitous) │
│ Target IP:      0a:15:00:02  (10.21.0.2)               │
└────────────────────────────────────────────────────────┘

Total: 42 bytes


ARP Request (Learn gateway MAC):
┌────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                             │
├────────────────────────────────────────────────────────┤
│ Dest:   ff:ff:ff:ff:ff:ff  (broadcast)                 │
│ Src:    aa:bb:cc:dd:ee:ff  (our MAC)                   │
│ Type:   08:06              (ARP)                       │
└────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────┐
│ ARP Payload (28 bytes)                                 │
├────────────────────────────────────────────────────────┤
│ Hardware Type:  00:01      (Ethernet)                  │
│ Protocol Type:  08:00      (IPv4)                      │
│ HW Size:        06                                     │
│ Proto Size:     04                                     │
│ Opcode:         00:01      (Request)                   │
│                                                        │
│ Sender MAC:     aa:bb:cc:dd:ee:ff                      │
│ Sender IP:      0a:15:00:02  (10.21.0.2 - our IP)      │
│ Target MAC:     00:00:00:00:00:00  (unknown)           │
│ Target IP:      0a:15:00:01  (10.21.0.1 - gateway)     │
└────────────────────────────────────────────────────────┘

Total: 42 bytes


ARP Reply (Gateway responds):
┌────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                             │
├────────────────────────────────────────────────────────┤
│ Dest:   aa:bb:cc:dd:ee:ff  (our MAC)                   │
│ Src:    11:22:33:44:55:66  (gateway MAC)               │
│ Type:   08:06              (ARP)                       │
└────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────┐
│ ARP Payload (28 bytes)                                 │
├────────────────────────────────────────────────────────┤
│ Hardware Type:  00:01                                  │
│ Protocol Type:  08:00                                  │
│ HW Size:        06                                     │
│ Proto Size:     04                                     │
│ Opcode:         00:02      (Reply) ← Key difference!   │
│                                                        │
│ Sender MAC:     11:22:33:44:55:66  (gateway MAC) ✅    │
│ Sender IP:      0a:15:00:01  (10.21.0.1)               │
│ Target MAC:     aa:bb:cc:dd:ee:ff  (our MAC)           │
│ Target IP:      0a:15:00:02  (10.21.0.2)               │
└────────────────────────────────────────────────────────┘

Total: 42 bytes
         ↑
  Learn this MAC! Store as gateway_mac[6]
```

---

## State Machine Comparison

### SecureNAT Client States

```
┌─────────────┐
│ DISCONNECTED│
└──────┬──────┘
       │
       │ Connect()
       ▼
┌─────────────┐
│  CONNECTING │
└──────┬──────┘
       │
       │ Session established
       ▼
┌─────────────┐
│  CONNECTED  │  ← Forward packets directly
└──────┬──────┘
       │
       │ Disconnect()
       ▼
┌─────────────┐
│ DISCONNECTED│
└─────────────┘

States: 3
Complexity: LOW
```

### Local Bridge Client States

```
┌─────────────┐
│ DISCONNECTED│
└──────┬──────┘
       │
       │ Connect()
       ▼
┌─────────────┐
│  CONNECTING │
└──────┬──────┘
       │
       │ Session established
       ▼
┌──────────────────┐
│ SEND_GARP_INIT   │  ← Announce MAC (IP=0.0.0.0)
└────────┬─────────┘
         │
         │ GARP sent
         ▼
┌──────────────────┐
│ DHCP_DISCOVER    │  ← Request IP
└────────┬─────────┘
         │
         │ OFFER received
         ▼
┌──────────────────┐
│ DHCP_REQUEST     │  ← Confirm IP
└────────┬─────────┘
         │
         │ ACK received
         ▼
┌──────────────────┐
│ CONFIGURE_IF     │  ← Set interface IP
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ LEARN_GATEWAY_MAC│  ← Send ARP request
└────────┬─────────┘
         │
         │ ARP reply received
         ▼
┌──────────────────┐
│ SEND_GARP_FINAL  │  ← Announce with real IP
└────────┬─────────┘
         │
         ▼
┌─────────────┐
│  CONNECTED  │  ← Forward packets with translation
│             │    + Send GARP every 30s
└──────┬──────┘
       │
       │ Disconnect()
       ▼
┌─────────────┐
│ DISCONNECTED│
└─────────────┘

States: 9
Complexity: HIGH
```

---

## Memory Layout Comparison

### SecureNAT Packet Buffer

```c
struct PacketBuffer {
    UCHAR data[1500];    // Just IP packet
    UINT size;           // 20-1500 bytes
};

Memory: ~1.5 KB per packet
```

### Local Bridge Packet Buffer

```c
struct EthernetPacketBuffer {
    UCHAR dest_mac[6];       // Destination MAC
    UCHAR src_mac[6];        // Source MAC
    UCHAR ethertype[2];      // 0x0800, 0x0806, 0x86DD
    UCHAR data[1500];        // IP packet or ARP
    UINT size;               // 34-1514 bytes
};

// Plus MAC learning table:
struct MacTable {
    UCHAR our_mac[6];
    UCHAR gateway_mac[6];
    UINT32 our_ip;
    UINT32 gateway_ip;
    UINT64 last_arp_time;
};

Memory: ~1.5 KB + 30 bytes per packet
```

---

## Performance Comparison

### SecureNAT
- **Packet Processing**: Direct pass-through
- **CPU**: ~0.1% per Mbps
- **Memory**: Minimal (no translation buffers)
- **Latency**: Low (no header manipulation)

### Local Bridge
- **Packet Processing**: 
  - Incoming: Strip 14 bytes
  - Outgoing: Add 14 bytes
  - ARP: Parse and respond
- **CPU**: ~0.3% per Mbps (3x higher)
- **Memory**: +30 bytes per connection (MAC table)
- **Latency**: +0.1ms (header manipulation)

---

## When to Use Each Mode

### Use SecureNAT When:
- ✅ Simple deployment (no network access)
- ✅ NAT/firewall acceptable
- ✅ Built-in DHCP sufficient
- ✅ Client simplicity preferred
- ✅ Lower CPU usage needed

### Use Local Bridge When:
- ✅ True bridging to physical network required
- ✅ Layer 2 protocols needed (ARP, multicast)
- ✅ External DHCP server
- ✅ Full network integration
- ✅ Multiple VLANs
- ✅ Network monitoring/sniffing

---

## References

- Full documentation: `SECURENAT_VS_LOCALBRIDGE.md`
- Quick reference: `LOCALBRIDGE_QUICKREF.md`
- C implementation: `src/bridge/packet_adapter_macos.c`
- Zig implementation: `src/packet/adapter.zig`

---

**Diagrams Version**: 1.0  
**Last Updated**: October 5, 2025
