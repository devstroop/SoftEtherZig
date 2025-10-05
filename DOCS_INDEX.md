# Documentation Index - SecureNAT vs Local Bridge

This directory contains comprehensive documentation about implementing a SoftEther VPN client that supports both **SecureNAT** (Layer 3) and **Local Bridge** (Layer 2) server modes.

## 📚 Documentation Files

### 1. **SECURENAT_VS_LOCALBRIDGE.md** (Main Reference)
**Purpose**: Complete technical comparison and implementation guide

**Contents**:
- Executive summary of packet format differences
- Detailed code examples for both modes
- MAC address learning via ARP
- DHCP handling differences
- Configuration flags
- Real-world examples from working codebase
- Summary comparison table

**Best for**: Deep understanding, implementation details, reference

**Length**: ~800 lines with extensive code samples

---

### 2. **LOCALBRIDGE_QUICKREF.md** (Quick Reference)
**Purpose**: Fast lookup guide for Local Bridge implementation

**Contents**:
- TL;DR summary
- Code patterns (incoming/outgoing)
- ARP handling snippets
- EtherType reference table
- Common pitfalls and fixes
- Detection methods
- Implementation checklist

**Best for**: Quick lookup during coding, debugging, code review

**Length**: ~400 lines focused on practical patterns

---

### 3. **PACKET_FLOW_DIAGRAMS.md** (Visual Guide)
**Purpose**: Visual understanding of packet flows and transformations

**Contents**:
- Side-by-side flow diagrams
- Packet structure before/after translation
- ARP sequence diagrams
- State machine comparison
- Memory layout comparison
- Performance comparison

**Best for**: Understanding concepts visually, presentations, onboarding

**Length**: ~600 lines with ASCII diagrams

---

## 🎯 Quick Navigation

### I want to understand the basics
→ Start with **PACKET_FLOW_DIAGRAMS.md** (Section 1: Visual Comparison)

### I need to implement Local Bridge support
→ Read **SECURENAT_VS_LOCALBRIDGE.md** (Section 2: Client Implementation Requirements)  
→ Use **LOCALBRIDGE_QUICKREF.md** as you code

### I'm debugging packet issues
→ Check **LOCALBRIDGE_QUICKREF.md** (Section: Common Pitfalls)  
→ Reference **PACKET_FLOW_DIAGRAMS.md** (Packet Transformation)

### I need to explain this to someone
→ Use **PACKET_FLOW_DIAGRAMS.md** (visual diagrams)  
→ Show **SECURENAT_VS_LOCALBRIDGE.md** (Section 9: Summary Table)

### I want code examples
→ **SECURENAT_VS_LOCALBRIDGE.md** (Sections 2, 3, 8)  
→ **LOCALBRIDGE_QUICKREF.md** (Code Pattern sections)

---

## 🔑 Key Concepts Summary

### The Core Difference

```
SecureNAT:  VPN Server ←→ [IP Packets] ←→ Client ←→ [IP Packets] ←→ TUN Device

Local Bridge: VPN Server ←→ [Ethernet Frames] ←→ Client ←→ [IP Packets] ←→ TUN Device
                                                      ↑
                                           Translation happens here!
```

### What You Must Do for Local Bridge

1. **Strip Ethernet headers** when receiving (14 bytes)
2. **Add Ethernet headers** when sending (14 bytes)
3. **Learn gateway MAC** via ARP requests
4. **Respond to ARP** queries for our IP
5. **Send keep-alive** Gratuitous ARP every 30s

### Implementation Complexity

| Mode | Lines of Code | Main Tasks |
|------|---------------|------------|
| SecureNAT | ~500 | Pass-through |
| Local Bridge | ~2700 | Translation + ARP |

---

## 📖 Learning Path

### Beginner (Understanding)
1. Read: **PACKET_FLOW_DIAGRAMS.md** - Visual Comparison
2. Read: **SECURENAT_VS_LOCALBRIDGE.md** - Section 1 (Packet Format Differences)
3. Understand: Why headers need stripping/adding

### Intermediate (Implementation)
1. Read: **SECURENAT_VS_LOCALBRIDGE.md** - Section 2 (Client Implementation)
2. Study: Code examples in Section 3 (MAC Address Learning)
3. Reference: **LOCALBRIDGE_QUICKREF.md** - Code patterns
4. Review: Real implementation in `src/bridge/packet_adapter_macos.c`

### Advanced (Optimization)
1. Study: **SECURENAT_VS_LOCALBRIDGE.md** - Section 7 (Code Structure)
2. Analyze: `src/packet/adapter.zig` (Zig implementation)
3. Optimize: Using `ZigTapTun/` library for reusable translation
4. Review: **PACKET_FLOW_DIAGRAMS.md** - Performance Comparison

---

## 🔍 Code References

### C Implementation (Reference)
```
src/bridge/packet_adapter_macos.c
  Lines 2100-2250: ARP handling and Gratuitous ARP
  Lines 2150-2200: Ethernet header detection and stripping
  Lines 2300-2600: Incoming packet processing
```

### Zig Implementation (Working)
```
src/packet/packet.zig
  Lines 45-67: Packet type detection (isEthernet flag)
  Lines 83-90: Helper methods

src/packet/adapter.zig
  Full high-performance adapter with ring buffers
```

### Reusable Library
```
ZigTapTun/src/translator.zig
  Layer 2/3 translation (cross-platform)
  
ZigTapTun/src/arp.zig
  ARP handling (request/reply/cache)
```

---

## 🧪 Testing

### Verify SecureNAT Mode
```bash
# Should see raw IP packets
tcpdump -i utun3 -n
# Output: IP 10.21.0.2 > 1.1.1.1: ...
```

### Verify Local Bridge Mode
```bash
# Should see Ethernet frames and ARP
tcpdump -i utun3 -e -n
# Output: aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66, ethertype IPv4 ...

# Monitor ARP specifically
tcpdump -i utun3 arp
# Should see periodic Gratuitous ARP every 30s
```

### Test MAC Learning
```bash
# Watch logs for:
grep "LEARNED GATEWAY MAC" your.log
# Should see: 🎯 LEARNED GATEWAY MAC: xx:xx:xx:xx:xx:xx
```

---

## 🐛 Troubleshooting Guide

### Problem: No connectivity after connecting

**Symptoms**: Connected but can't ping anything

**Check**:
1. Is server in Local Bridge mode? → Check for Ethernet headers in packets
2. Did we learn gateway MAC? → Look for "LEARNED GATEWAY MAC" log
3. Are we sending Gratuitous ARP? → Check ARP traffic with tcpdump

**Solution**: See **LOCALBRIDGE_QUICKREF.md** - Common Pitfalls

---

### Problem: Packets corrupted or wrong format

**Symptoms**: TUN device errors, malformed packet warnings

**Check**:
1. Are we stripping Ethernet headers? → Check PutPacket() code
2. Are we adding headers correctly? → Check GetNextPacket() code
3. Is EtherType correct? → Should be 0x0800 (IPv4) or 0x86DD (IPv6)

**Solution**: See **PACKET_FLOW_DIAGRAMS.md** - Packet Transformation

---

### Problem: Connection drops after ~5 minutes

**Symptoms**: Works initially, then stops forwarding

**Check**:
1. Are we sending keep-alive ARP? → Should be every 30 seconds
2. Is server aging out our MAC entry? → Server MAC table timeout

**Solution**: Implement Gratuitous ARP keep-alive (see **SECURENAT_VS_LOCALBRIDGE.md** Section 4)

---

### Problem: ARP replies not received

**Symptoms**: Can't learn gateway MAC, using broadcast

**Check**:
1. Are we sending ARP requests? → Check ARP traffic
2. Are we parsing replies correctly? → Opcode should be 2
3. Is gateway IP correct? → Usually x.x.x.1

**Solution**: See **LOCALBRIDGE_QUICKREF.md** - ARP Handling

---

## 📊 Comparison Matrix

|  | SecureNAT | Local Bridge |
|--|-----------|--------------|
| **Server Config** | Virtual NAT router | Bridge to physical network |
| **Packet Type** | IP (Layer 3) | Ethernet (Layer 2) |
| **DHCP** | Built-in | External network |
| **ARP** | Not needed | Required |
| **MAC Learning** | Not needed | Required |
| **Keep-Alive** | Not needed | Gratuitous ARP |
| **Header Manipulation** | None | Strip/Add |
| **Code Complexity** | Low (~500 LOC) | High (~2700 LOC) |
| **CPU Usage** | Low | Medium (+3x) |
| **Use Case** | Simple VPN | Network integration |

---

## 🎓 Related Documentation

### In This Repository
- `ARCHITECTURE.md` - Overall system architecture
- `PROGRESS.md` - Implementation status
- `ZigTapTun/PROJECT_SUMMARY.md` - Layer 2/3 translation library
- `ZigTapTun/README.md` - TUN/TAP device handling

### SoftEther Source Code
- `src/bridge/Cedar/Session.c` - Server-side mode handling
- `src/bridge/Cedar/Protocol.c` - Protocol implementation
- `src/bridge/Cedar/Client.c` - Client configuration

### External References
- [SoftEther Documentation](https://www.softether.org/4-docs)
- [RFC 826 - ARP](https://tools.ietf.org/html/rfc826)
- [IEEE 802.3 - Ethernet](https://standards.ieee.org/standard/802_3-2018.html)

---

## ✅ Implementation Checklist

Use this when adding Local Bridge support to your client:

### Phase 1: Detection
- [ ] Detect if server is in Local Bridge mode
- [ ] Set `RequireBridgeRoutingMode = true` flag
- [ ] Check first packet for Ethernet headers

### Phase 2: Header Handling
- [ ] Implement Ethernet header detection (check EtherType)
- [ ] Strip 14-byte header on incoming packets
- [ ] Add 14-byte header on outgoing packets
- [ ] Handle IPv4, IPv6, and ARP packet types

### Phase 3: MAC Management
- [ ] Generate or obtain client MAC address
- [ ] Send initial Gratuitous ARP (IP=0.0.0.0)
- [ ] Store gateway IP from DHCP
- [ ] Send ARP request for gateway MAC
- [ ] Parse ARP replies and learn gateway MAC

### Phase 4: Keep-Alive
- [ ] Implement periodic timer (30 seconds)
- [ ] Send Gratuitous ARP with assigned IP
- [ ] Maintain MAC/IP table entries

### Phase 5: ARP Handling
- [ ] Parse incoming ARP requests
- [ ] Respond to ARP queries for our IP
- [ ] Don't write ARP packets to TUN device
- [ ] Log MAC learning events

### Phase 6: Testing
- [ ] Test with tcpdump (verify Ethernet frames)
- [ ] Test with ARP monitoring
- [ ] Verify gateway MAC learned
- [ ] Test long-running connection (>5 minutes)
- [ ] Test DHCP lease renewal

---

## 💡 Tips and Best Practices

1. **Start with SecureNAT**: Get basic connectivity working first
2. **Use packet inspection**: tcpdump is your friend
3. **Log everything initially**: ARP, MAC learning, packet formats
4. **Test incrementally**: Add one feature at a time
5. **Study the C code**: `packet_adapter_macos.c` is battle-tested
6. **Use the library**: Consider `ZigTapTun` for reusable translation

---

## 📞 Support

- GitHub Issues: Report bugs or ask questions
- Code Examples: All three documentation files have working code
- Real Implementation: Study `src/bridge/packet_adapter_macos.c`

---

**Index Version**: 1.0  
**Last Updated**: October 5, 2025  
**Status**: Based on working implementation
