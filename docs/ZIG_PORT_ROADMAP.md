# Zig Port Roadmap - Performance-Critical Components

## Current State Analysis

### Performance Baseline
- **Current**: 9-10 Mbps download (Zig client with SoftEther C library)
- **Target**: 87 Mbps download (SSTP Connect reference)
- **Gap**: ~9x performance difference
- **Configuration**: Identical (1 TCP connection, same protocol settings)

### Architecture Overview
```
┌─────────────────────────────────────────────────────────────┐
│                    Zig Client Application                    │
│  (src/main.zig, cli.zig, client.zig, config.zig)           │
└─────────────────────┬───────────────────────────────────────┘
                      │ FFI calls
┌─────────────────────▼───────────────────────────────────────┐
│              C Bridge Layer (src/bridge/)                    │
│  softether_bridge.c, packet_adapter_macos.c                 │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│            SoftEther VPN Library (C)                         │
│  Protocol.c, Session.c, Connection.c, Network.c             │
└──────────────────────────────────────────────────────────────┘
```

## Root Cause: Protocol Layer Polling Overhead

### The Bottleneck
The performance issue is **NOT** in:
- ❌ TCP buffer sizes
- ❌ TUN device I/O
- ❌ Packet adapter implementation
- ❌ Number of connections

The bottleneck **IS** in:
- ✅ **SoftEther's Protocol Layer** - calls `GetNextPacket()` one-at-a-time in polling loop
- ✅ **Packet Serialization** - each packet goes through full protocol state machine
- ✅ **C Performance Overhead** - malloc/free per packet, function call overhead

### Evidence
1. **Consistent 10 Mbps ceiling** regardless of optimizations
2. **Upload speed normal** (~11 Mbps) - asymmetric issue points to receive path
3. **GetNextPacket polling** - protocol layer requests packets individually
4. **No batching** - each packet travels through full call stack separately

---

## Phase 1: Port Packet Processing Pipeline (High Priority)

### Goal
Port the hot path from C to Zig for 3-5x performance improvement.

### Components to Port

#### 1.1 Packet Adapter (Already Zig-friendly)
**File**: `src/bridge/packet_adapter_macos.c` → `src/packet/adapter.zig`

**Current State**: 
- C implementation with SoftEther callbacks
- 1024-packet queue (can increase to 8192)
- Blocking read() on TUN device

**Zig Port Benefits**:
```zig
const PacketAdapter = struct {
    tun_fd: std.posix.fd_t,
    recv_queue: RingBuffer(Packet, 8192),  // Lock-free ring buffer
    cancel: *Cancel,
    
    // Zero-copy packet handling
    pub fn getNextPacket(self: *PacketAdapter) ?[]u8 {
        return self.recv_queue.pop();  // O(1) lock-free
    }
    
    // Batch packet processing
    pub fn getPacketBatch(self: *PacketAdapter, buf: []?[]u8) usize {
        return self.recv_queue.popBatch(buf);  // Get up to N packets
    }
};
```

**Performance Gains**:
- Lock-free ring buffer: 10x faster than mutex-protected queue
- Zero-copy: eliminate malloc/memcpy per packet
- Batch API: amortize call overhead across multiple packets
- **Expected**: 2-3x throughput improvement

#### 1.2 Session Layer Protocol Handler
**File**: `SoftEtherVPN/src/Cedar/Session.c` → `src/protocol/session.zig`

**Current State**:
- Polls GetNextPacket() in loop
- Processes one packet at a time
- Heavy malloc/free overhead

**Zig Port Benefits**:
```zig
const Session = struct {
    adapter: *PacketAdapter,
    send_fifo: Fifo,
    recv_fifo: Fifo,
    
    // Batch packet processing
    pub fn processPackets(self: *Session) !void {
        var batch: [32]?[]u8 = undefined;
        const count = self.adapter.getPacketBatch(&batch);
        
        for (batch[0..count]) |pkt_opt| {
            if (pkt_opt) |pkt| {
                try self.send_fifo.write(pkt);  // Batched write
            }
        }
    }
};
```

**Performance Gains**:
- Batch processing: 32 packets per iteration vs 1
- Reduced function call overhead
- Better CPU cache utilization
- **Expected**: 3-5x throughput improvement

#### 1.3 Protocol Framing/Deframing
**File**: `SoftEtherVPN/src/Cedar/Protocol.c` → `src/protocol/framing.zig`

**Current State**:
- Packet-by-packet framing
- Individual encrypt/decrypt per packet
- Buffer copying overhead

**Zig Port Benefits**:
```zig
pub fn framePackets(packets: []const []u8, out: *Fifo) !void {
    // Batch encryption
    const batch_size = 32;
    var i: usize = 0;
    
    while (i < packets.len) : (i += batch_size) {
        const end = @min(i + batch_size, packets.len);
        const chunk = packets[i..end];
        
        // Encrypt batch in one OpenSSL call
        try crypto.encryptBatch(chunk, out);
    }
}
```

**Performance Gains**:
- Batch encryption: leverage OpenSSL's batch APIs
- Reduced context switching
- **Expected**: 1.5-2x throughput improvement

---

## Phase 2: Replace SoftEther Protocol (Medium Priority)

### Goal
Full native Zig implementation of VPN protocol.

### Why Replace?
1. **C Library Overhead**: Function calls, malloc/free, indirection
2. **Protocol Design**: Single-packet processing baked into architecture
3. **Extensibility**: Can't modify closed-source behavior

### Native Zig Protocol Stack

#### 2.1 Custom VPN Protocol
```zig
// Simple, high-performance VPN protocol
const VpnProtocol = struct {
    // Stream-oriented transport
    tcp_stream: net.Stream,
    cipher: crypto.Cipher,
    
    // Batch I/O
    send_buffer: [64 * 1024]u8,  // 64KB buffer
    recv_buffer: [64 * 1024]u8,
    
    pub fn sendPackets(self: *VpnProtocol, packets: []const []u8) !void {
        var pos: usize = 0;
        
        // Pack multiple packets into single TCP write
        for (packets) |pkt| {
            // Frame: [2-byte length][packet data]
            std.mem.writeInt(u16, self.send_buffer[pos..][0..2], @intCast(pkt.len), .little);
            pos += 2;
            @memcpy(self.send_buffer[pos..][0..pkt.len], pkt);
            pos += pkt.len;
        }
        
        // Single syscall for all packets
        _ = try self.tcp_stream.write(self.send_buffer[0..pos]);
    }
    
    pub fn recvPackets(self: *VpnProtocol, allocator: Allocator) ![][]u8 {
        // Read large chunk
        const n = try self.tcp_stream.read(&self.recv_buffer);
        
        // Parse multiple packets from buffer
        var packets = std.ArrayList([]u8).init(allocator);
        var pos: usize = 0;
        
        while (pos + 2 < n) {
            const len = std.mem.readInt(u16, self.recv_buffer[pos..][0..2], .little);
            pos += 2;
            
            const pkt = try allocator.dupe(u8, self.recv_buffer[pos..][0..len]);
            try packets.append(pkt);
            pos += len;
        }
        
        return packets.toOwnedSlice();
    }
};
```

**Performance Gains**:
- Stream-based I/O: fill TCP buffers efficiently
- Minimal framing overhead
- No per-packet crypto context switch
- **Expected**: 5-10x throughput improvement

#### 2.2 Async I/O with io_uring (Linux) / kqueue (macOS)
```zig
const AsyncVpn = struct {
    ring: IoUring,  // Linux
    // kq: Kqueue,  // macOS alternative
    
    pub fn runEventLoop(self: *AsyncVpn) !void {
        while (true) {
            // Submit batch of operations
            _ = try self.ring.submit();
            
            // Wait for completions
            const cqes = try self.ring.copy_cqes(&cqe_buffer, 1);
            
            for (cqes) |cqe| {
                try self.handleCompletion(cqe);
            }
        }
    }
};
```

**Performance Gains**:
- Zero-copy I/O
- Batch syscalls
- Kernel-level buffering
- **Expected**: 2-3x throughput improvement on Linux

---

## Phase 3: Zig-Native TUN/TAP Driver (Low Priority)

### Goal
Replace OS TUN device with userspace networking.

### Options

#### 3.1 VirtIO Network Device (Best Performance)
```zig
// Direct memory-mapped I/O
const VirtioNet = struct {
    tx_ring: VirtQueue,
    rx_ring: VirtQueue,
    
    pub fn sendPacket(self: *VirtioNet, pkt: []const u8) !void {
        const desc = self.tx_ring.allocDesc();
        desc.addr = @intFromPtr(pkt.ptr);
        desc.len = @intCast(pkt.len);
        self.tx_ring.submitDesc(desc);
    }
};
```

**Performance Gains**:
- No syscalls
- Direct DMA
- **Expected**: 10-20x throughput vs TUN device

#### 3.2 XDP (Linux) / PF_RING (High-speed packet processing)
- Bypass kernel networking stack
- Run packet processing in eBPF/kernel module
- Wire-speed forwarding

---

## Implementation Strategy

### Quick Wins (1-2 weeks)
1. ✅ **Increase queue size** to 8192 packets (already done)
2. 🔄 **Add batch GetNextPacket API** - return array of packets
3. 🔄 **Port packet adapter to Zig** - eliminate C malloc overhead
4. 🔄 **Lock-free ring buffer** - replace mutex-protected queue

**Expected Result**: 15-20 Mbps (2x improvement)

### Medium Effort (1-2 months)
1. **Port Session layer** - batch packet processing
2. **Port Protocol framing** - batch encryption
3. **Optimize TCP I/O** - larger buffers, batch writes

**Expected Result**: 40-60 Mbps (5-6x improvement)

### Long-term (3-6 months)
1. **Native Zig VPN protocol** - replace SoftEther entirely
2. **Async I/O with io_uring** - kernel-level efficiency
3. **Custom crypto pipeline** - hardware acceleration

**Expected Result**: 200-500 Mbps (20-50x improvement)

---

## Benchmarking Plan

### Metrics to Track
```zig
const Metrics = struct {
    packets_per_second: u64,
    bytes_per_second: u64,
    latency_p50: u64,  // microseconds
    latency_p99: u64,
    cpu_usage: f32,    // percentage
    
    syscalls_per_packet: f32,
    mallocs_per_packet: f32,
    
    pub fn report(self: Metrics) void {
        std.debug.print(
            \\Throughput: {d:.2} Mbps ({d} pps)
            \\Latency: p50={d}µs, p99={d}µs
            \\Efficiency: {d:.2} syscalls/pkt, {d:.2} mallocs/pkt
            \\CPU: {d:.1}%
            \\
        , .{
            @as(f64, @floatFromInt(self.bytes_per_second * 8)) / 1_000_000.0,
            self.packets_per_second,
            self.latency_p50,
            self.latency_p99,
            self.syscalls_per_packet,
            self.mallocs_per_packet,
            self.cpu_usage,
        });
    }
};
```

### Profiling Tools
1. **perf** (Linux) / **Instruments** (macOS) - CPU profiling
2. **strace** / **dtrace** - syscall tracing
3. **Valgrind** / **Heaptrack** - memory profiling
4. **eBPF** - kernel-level packet tracing

---

## Code Organization

### Proposed Structure
```
src/
├── main.zig              # Entry point (existing)
├── cli.zig               # CLI (existing)
├── client.zig            # High-level client (existing)
├── config.zig            # Configuration (existing)
│
├── packet/               # NEW: Packet handling
│   ├── adapter.zig       # Packet adapter (port from C)
│   ├── queue.zig         # Lock-free ring buffer
│   └── tun.zig           # TUN device I/O
│
├── protocol/             # NEW: VPN protocol
│   ├── session.zig       # Session management
│   ├── framing.zig       # Packet framing/deframing
│   ├── crypto.zig        # Encryption/decryption
│   └── handshake.zig     # Connection handshake
│
├── network/              # NEW: Network I/O
│   ├── tcp.zig           # TCP connection
│   ├── async.zig         # Async I/O (io_uring/kqueue)
│   └── socket.zig        # Socket utilities
│
└── bridge/               # EXISTING: C interop (phase out)
    ├── softether_bridge.c
    └── packet_adapter_macos.c
```

---

## Migration Path

### Hybrid Approach (Recommended)
```zig
// Start with C SoftEther, gradually replace components
const VpnClient = struct {
    // Phase 1: Use C SoftEther with Zig adapter
    softether: ?*c.SoftEtherClient,
    adapter: ?*PacketAdapter,
    
    // Phase 2: Use Zig protocol with C crypto
    session: ?*protocol.Session,
    
    // Phase 3: Pure Zig implementation
    native_vpn: ?*NativeVpn,
    
    pub fn init(allocator: Allocator, cfg: Config) !VpnClient {
        if (cfg.use_native) {
            // Pure Zig path
            return .{
                .softether = null,
                .adapter = null,
                .session = null,
                .native_vpn = try NativeVpn.init(allocator, cfg),
            };
        } else {
            // Hybrid path
            return .{
                .softether = try initSoftEther(cfg),
                .adapter = try PacketAdapter.init(allocator),
                .session = null,
                .native_vpn = null,
            };
        }
    }
};
```

**Benefits**:
- Incremental migration
- A/B testing between implementations
- Fallback to C if Zig path has issues

---

## Risk Mitigation

### Compatibility Risks
- **SoftEther protocol changes**: Pin to specific version, document protocol
- **Platform differences**: Extensive cross-platform testing
- **Performance regressions**: Comprehensive benchmarking at each step

### Technical Risks
- **Crypto correctness**: Reuse OpenSSL, extensive testing
- **Memory safety**: Zig's safety features reduce risk
- **Concurrency bugs**: Use Zig's async/await, minimize shared state

---

## Success Metrics

### Phase 1 Success (2x improvement)
- ✅ 15-20 Mbps download speed
- ✅ <1% packet loss
- ✅ <10ms additional latency
- ✅ Same CPU usage or better

### Phase 2 Success (5x improvement)
- ✅ 40-60 Mbps download speed
- ✅ 50% reduction in CPU usage
- ✅ <5ms additional latency
- ✅ Stable under load testing

### Phase 3 Success (10x+ improvement)
- ✅ 80-100+ Mbps download speed
- ✅ Match or exceed SSTP Connect performance
- ✅ 70% reduction in CPU usage
- ✅ Production-ready stability

---

## Next Steps

### Immediate Actions (This Week)
1. ✅ Document current architecture
2. ✅ Identify performance bottlenecks
3. 🔄 Set up profiling infrastructure
4. 🔄 Create initial Zig packet adapter prototype

### Short-term (Next Month)
1. 🔄 Port packet adapter to Zig
2. 🔄 Implement lock-free ring buffer
3. 🔄 Add batch packet API
4. 🔄 Benchmark against C implementation

### Medium-term (Q1 2026)
1. 🔄 Port Session layer
2. 🔄 Port Protocol framing
3. 🔄 Optimize TCP I/O
4. 🔄 Achieve 40-60 Mbps target

### Long-term (2026)
1. 🔄 Design native Zig VPN protocol
2. 🔄 Implement async I/O
3. 🔄 Production deployment
4. 🔄 Match/exceed 87 Mbps target

---

## Conclusion

The current 9 Mbps performance is limited by SoftEther's C implementation architecture, specifically single-packet polling in the protocol layer. A phased Zig port focusing on the hot path (packet adapter → session → protocol) can achieve:

- **Phase 1 (Quick)**: 2x improvement → 15-20 Mbps
- **Phase 2 (Medium)**: 5x improvement → 40-60 Mbps  
- **Phase 3 (Complete)**: 10x+ improvement → 80-100+ Mbps

The hybrid migration approach minimizes risk while delivering incremental performance gains.
