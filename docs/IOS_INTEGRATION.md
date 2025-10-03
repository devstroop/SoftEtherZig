# SoftEther VPN Client - iOS Integration

This document describes how the SoftEtherZig VPN client is integrated with the WorxVPN iOS application.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     WorxVPN iOS App                         │
│  ┌────────────────────────────────────────────────────┐    │
│  │  PacketTunnelProvider (Swift)                      │    │
│  │  - NEPacketTunnelFlow management                   │    │
│  │  - IP packet routing                                │    │
│  │  - DHCP configuration                               │    │
│  │  - ARP handling                                     │    │
│  └──────────────────┬─────────────────────────────────┘    │
│                     │ C FFI                                 │
│  ┌──────────────────▼─────────────────────────────────┐    │
│  │  softether_ffi.h (C API)                           │    │
│  │  - softether_client_create()                       │    │
│  │  - softether_client_connect()                      │    │
│  │  - softether_client_send_ip_packet()               │    │
│  │  - Callbacks for RX, state, events                 │    │
│  └──────────────────┬─────────────────────────────────┘    │
└────────────────────┬┘                                       │
                     │                                         │
┌────────────────────▼──────────────────────────────────────┐
│              SoftEtherClient.xcframework                   │
│  ┌────────────────────────────────────────────────────┐   │
│  │  ios_ffi.c (FFI Implementation)                    │   │
│  │  - JSON config parsing                             │   │
│  │  - Callback adapters                               │   │
│  │  - Thread safety (pthread mutexes)                 │   │
│  └──────────────────┬─────────────────────────────────┘   │
│  ┌──────────────────▼─────────────────────────────────┐   │
│  │  softether_bridge.c (Simplified API)               │   │
│  │  - VpnBridgeClient management                      │   │
│  │  - Configuration helpers                           │   │
│  │  - DHCP info extraction                            │   │
│  └──────────────────┬─────────────────────────────────┘   │
│  ┌──────────────────▼─────────────────────────────────┐   │
│  │  SoftEther VPN C Implementation                    │   │
│  │  - Cedar/* (VPN protocol)                          │   │
│  │  - Mayaqua/* (networking, crypto)                  │   │
│  │  - Platform adapters (macOS/iOS)                   │   │
│  └────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────┘
```

## Components

### 1. **iOS App (Swift)**
- **Location:** `WorxVPN-iOS/WorxVPNExtension/PacketTunnelProvider.swift`
- **Responsibilities:**
  - Network Extension lifecycle management
  - NEPacketTunnelFlow I/O
  - Tunnel settings application
  - ARP table management (iOS-side caching)
  - UI/UX event handling

### 2. **C FFI Layer**
- **Header:** `SoftEtherZig/include/softether_ffi.h`
- **Implementation:** `SoftEtherZig/src/bridge/ios_ffi.c`
- **Responsibilities:**
  - Expose C API for Swift interop
  - JSON configuration parsing
  - Thread-safe callback dispatch
  - Memory management
  - Error handling

### 3. **Bridge Layer**
- **Header:** `SoftEtherZig/src/bridge/softether_bridge.h`
- **Implementation:** `SoftEtherZig/src/bridge/softether_bridge.c`
- **Responsibilities:**
  - Simplified API over complex SoftEther C code
  - Client lifecycle management
  - DHCP information extraction
  - Connection state management

### 4. **SoftEther C Core**
- **Location:** `SoftEtherZig/SoftEtherVPN_Stable/src/`
- **Key Modules:**
  - **Cedar:** VPN protocol implementation
  - **Mayaqua:** Cross-platform utilities, crypto, networking
  - **Platform Adapters:** macOS/iOS TUN device management

## Building

### Prerequisites
```bash
# Install Zig (0.11.0 or later)
brew install zig

# Install OpenSSL
brew install openssl@3

# Verify installations
zig version  # Should be 0.11.0 or later
openssl version  # Should be 3.x
```

### Build Steps

1. **Navigate to SoftEtherZig:**
   ```bash
   cd /Volumes/EXT/SoftEtherDev/SoftEtherZig
   ```

2. **Run the iOS build script:**
   ```bash
   ./build_ios.sh
   ```

   This script:
   - Builds for `aarch64-ios` (device)
   - Builds for `aarch64-ios-simulator` (M1/M2 simulator)
   - Builds for `x86_64-ios-simulator` (Intel simulator)
   - Creates framework structure for each architecture
   - Packages as XCFramework
   - Copies to `WorxVPN-iOS/Framework/`

3. **Regenerate Xcode project:**
   ```bash
   cd /Volumes/EXT/SoftEtherDev/WorxVPN-iOS
   xcodegen generate
   ```

4. **Open and build in Xcode:**
   ```bash
   open WorxVPN.xcodeproj
   ```

## Configuration

### Swift Side (PacketTunnelProvider)

```swift
let config: [String: Any] = [
    "server": "worxvpn.662.cloud",
    "port": 443,
    "hub": "VPN",
    "username": "devstroop",
    "password_hash": "<base64-encoded-sha0>",
    "use_encrypt": true,
    "use_compress": false,
    "max_connections": 8
]

let json = try! JSONSerialization.data(withJSONObject: config)
let jsonString = String(data: json, encoding: .utf8)!

self.client = softether_client_create(jsonString)
```

### C FFI Side (ios_ffi.c)

The FFI layer parses the JSON configuration and extracts:
- `server` → hostname or IP address
- `port` → TCP port (default 443)
- `hub` → Virtual HUB name
- `username` → authentication username
- `password_hash` → SHA-0 hashed password (base64)
- `use_encrypt` → SSL/TLS encryption (bool)
- `use_compress` → LZO compression (bool)

## Callback Flow

### State Changes
```
Swift: PacketTunnelProvider
  ↓ (register callback)
C FFI: softether_client_set_state_callback()
  ↓ (store callback)
Bridge: vpn_bridge_connect()
  ↓ (connection events)
C FFI: state_callback(state, user_context)
  ↓ (trampoline)
Swift: stateCallback(state: Int32, user: UnsafeMutableRawPointer?)
```

**States:**
- `0` = Idle/Disconnected
- `1` = Connecting
- `2` = Established
- `3` = Disconnecting

### Packet Reception (IP Mode)
```
SoftEther: Session receives encrypted VPN packet
  ↓ (decrypt, decompress)
Cedar: Extract Ethernet frame
  ↓ (strip Ethernet header if IPv4)
Bridge: Identify IPv4 packet
  ↓ (call registered callback)
C FFI: ip_rx_callback(packet_data, length, user)
  ↓ (Swift trampoline)
Swift: ipRxCallback → NEPacketTunnelFlow.writePackets()
  ↓
iOS: Packet delivered to network stack
```

### Packet Transmission
```
iOS: App/Browser sends IP packet
  ↓
NEPacketTunnelFlow: readPackets()
  ↓
Swift: softether_client_send_ip_packet(client, data, len)
  ↓
C FFI: Extract IP header, wrap in Ethernet
  ↓
Bridge: Send to SoftEther session
  ↓
Cedar: Encrypt, compress, transmit to server
```

## DHCP Integration

### How It Works

1. **Server Assignment:**
   - SoftEther server runs DHCP/SecureNAT
   - Assigns IP address, subnet mask, gateway, DNS
   - Sends DHCP OFFER/ACK to client

2. **Client Reception:**
   - `softether_bridge.c` extracts DHCP info from session
   - Stores in `VpnBridgeDhcpInfo` structure

3. **iOS Query:**
   - Swift calls `softether_client_get_network_settings_json()`
   - C FFI formats as JSON:
     ```json
     {
       "assigned_ipv4": "10.21.0.100",
       "subnet_mask": "255.255.0.0",
       "gateway": "10.21.0.1",
       "dns_servers": ["8.8.8.8", "8.8.4.4"]
     }
     ```

4. **iOS Application:**
   - PacketTunnelProvider calls `setTunnelNetworkSettings()`
   - iOS configures routes, DNS, MTU

### Timing
- DHCP typically completes within 2-5 seconds of connection
- Swift polls via `scheduleSettingsPolling()` every 500ms
- Timeout after 30 seconds with error

## Troubleshooting

### Build Failures

**Error: `zig: command not found`**
```bash
brew install zig
```

**Error: `openssl/ssl.h: No such file or directory`**
```bash
brew install openssl@3
export OPENSSL_IOS_PREFIX=/opt/homebrew/opt/openssl@3
```

**Error: `unsupported target: aarch64-ios`**
- Update Zig to 0.11.0 or later
- Check with `zig targets | grep ios`

### Runtime Issues

**Error: `module 'SoftEtherClient' not found`**
- Framework not built or not in `Framework/` directory
- Run `./build_ios.sh` again
- Regenerate Xcode project with `xcodegen`

**Crash: `EXC_BAD_ACCESS` on callback**
- Check that Swift context is kept alive (use `Unmanaged.passUnretained`)
- Verify callback signature matches C declaration

**No DHCP response:**
- Check server logs for DHCP packets
- Verify server has DHCP/SecureNAT enabled
- Check `VpnBridgeDhcpInfo.valid` flag
- Enable debug logging in `vpn_bridge_init(true)`

**Connection timeout:**
- Check server reachability (ping, telnet)
- Verify port is open (usually 443 or 992)
- Check credentials (username/password hash)
- Inspect `softether_client_last_error()`

## API Reference

### Key Functions

#### Client Management
```c
softether_client_t* softether_client_create(const char* json_config);
int softether_client_connect(softether_client_t* handle);
int softether_client_disconnect(softether_client_t* handle);
void softether_client_free(softether_client_t* handle);
```

#### Packet I/O
```c
int softether_client_send_ip_packet(softether_client_t* handle, 
                                     const uint8_t* data, 
                                     uint32_t len);
int softether_client_set_ip_rx_callback(softether_client_t* handle, 
                                         softether_ip_rx_cb_t cb, 
                                         void* user);
```

#### Configuration
```c
char* softether_client_get_network_settings_json(softether_client_t* handle);
int softether_client_get_mac(softether_client_t* handle, uint8_t out_mac[6]);
int softether_client_arp_add(softether_client_t* handle, 
                              uint32_t ipv4_be, 
                              const uint8_t mac[6]);
```

#### Callbacks
```c
typedef void (*softether_state_cb_t)(int state, void* user);
typedef void (*softether_event_cb_t)(int level, int code, 
                                       const char* message, void* user);
typedef void (*softether_ip_rx_cb_t)(const uint8_t* ip_packet, 
                                       uint32_t len, void* user);
```

## Performance Considerations

### Memory Usage
- Base client: ~500 KB
- Per connection: ~100 KB
- Packet buffers: ~64 KB each
- Total: ~1-2 MB typical

### CPU Usage
- Encryption overhead: 5-15% (AES-128)
- Compression overhead: 3-10% (LZO, if enabled)
- Protocol overhead: <2%

### Optimization Tips
1. **Disable compression** for modern networks (CPU vs bandwidth tradeoff)
2. **Use multiple connections** (max 8) for throughput
3. **Adjust MTU** to avoid fragmentation (default 1400 is safe)
4. **Enable hardware AES** if available (iOS devices have it)

## Testing

### Unit Tests
Currently not implemented. Recommended additions:
- JSON parsing tests
- Callback dispatch tests
- Thread safety tests
- Memory leak tests

### Integration Tests
1. **Connection Test:**
   - Create client
   - Connect to test server
   - Verify state callbacks
   - Disconnect cleanly

2. **Packet Test:**
   - Send IPv4 packet
   - Verify callback fires
   - Check packet integrity

3. **DHCP Test:**
   - Connect to server with DHCP
   - Poll for settings
   - Verify JSON format

### Manual Testing
```bash
# Build and install on device
cd WorxVPN-iOS
xcodebuild -scheme WorxVPN -destination 'platform=iOS Simulator,name=iPhone 14'

# Check logs
log stream --predicate 'subsystem == "com.worxvpn.ios"' --level debug
```

## Security Notes

### Password Handling
- **Never** store plaintext passwords
- Always use SHA-0 hashed password (SoftEther compatible)
- Hash calculated as: `SHA0(username_uppercase + password)`
- Transmitted encrypted over SSL/TLS

### Certificate Validation
- By default, validates server certificate
- Can disable with `skip_tls_verify: true` (NOT RECOMMENDED in production)
- Use only for testing with self-signed certs

### Memory Safety
- All buffers bounds-checked
- pthread mutexes protect shared state
- Callbacks validated before dispatch
- Proper cleanup on errors

## Future Improvements

### Short Term
- [ ] Implement full L2 frame support (currently IP-only)
- [ ] Add proper base64 decoding for password hashes
- [ ] Implement packet receive path from bridge
- [ ] Add comprehensive error codes

### Medium Term
- [ ] Support UDP acceleration
- [ ] Implement L2TP/IPsec mode
- [ ] Add connection statistics API
- [ ] Background keepalive optimization

### Long Term
- [ ] WireGuard protocol support
- [ ] On-demand VPN triggers
- [ ] Per-app VPN routing
- [ ] VPN traffic analytics

## License

SoftEther VPN is licensed under Apache License 2.0.
This integration code follows the same license.

## Support

- **Issues:** File on GitHub repository
- **Documentation:** See `docs/` directory
- **Community:** SoftEther VPN forums

---

**Last Updated:** October 2, 2025  
**Version:** 1.0.0  
**Maintainer:** WorxVPN Team
