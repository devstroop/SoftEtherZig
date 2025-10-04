# SoftEther VPN iOS Integration

Complete iOS Network Extension implementation for SoftEther VPN client.

## Architecture

```
iOS App Container
    ↓ IPC (Options/Configuration)
Network Extension (PacketTunnelProvider)
    ↓ Swift/ObjC Interop
SoftEther iOS Bridge (C)
    ↓ Callback Interface
iOS Packet Adapter
    ↓ SoftEther API
SoftEther Core (Cedar + Mayaqua)
```

## Components

### Swift Layer
- **PacketTunnelProvider.swift** (230 lines)
  - NEPacketTunnelProvider subclass
  - Handles VPN lifecycle (start/stop/sleep/wake)
  - Manages NEPacketTunnelFlow packet forwarding
  - IPC from container app

- **SoftEtherBridge.swift** (220 lines)
  - Swift-friendly API wrapper
  - Type-safe connection parameters
  - Error handling with Swift Result types
  - Async/await support (iOS 13+)

### C Bridge Layer
- **ios/C/softether_ios.c/h** (210 lines)
  - C interface for Swift interop
  - Functions: init, create_client, connect, disconnect
  - Packet flow management
  - Global client lifecycle

### Packet Adapter
- **src/bridge/ios/packet_adapter_ios.c/h** (415 lines)
  - NEPacketTunnelFlow integration via callbacks
  - Dual queue system (recv/send)
  - Background send thread with batch processing (up to 32 packets)
  - Thread-safe queue management

## Key Differences from Android

| Aspect | Android | iOS |
|--------|---------|-----|
| TUN Interface | File descriptor (ParcelFileDescriptor) | Callback-based (NEPacketTunnelFlow) |
| Packet I/O | Direct read/write on fd | writePackets/readPackets callbacks |
| Threading | Single thread per direction | Background send thread + read loop |
| Batch Processing | Not required | Up to 32 packets per write |
| Permissions | VpnService with user approval | Network Extension + entitlements |

## Build Setup

### Prerequisites
- Xcode 14.0+
- iOS 12.0+ deployment target
- Apple Developer Account (for Network Extension entitlement)
- OpenSSL compiled for iOS (arm64, x86_64 simulator)

### 1. Compile OpenSSL for iOS

```bash
# Download prebuilt OpenSSL or compile from source
cd scripts
./download_openssl_ios.sh

# Or build from source
git clone https://github.com/openssl/openssl.git
cd openssl
./Configure ios64-cross --prefix=/path/to/ios/openssl
make && make install
```

### 2. Create Xcode Project

#### Framework Target (SoftEtherVPN.framework)

```bash
# Create new Xcode project
# File → New → Project → Framework

# Add C sources
- ios/C/softether_ios.c
- ios/C/softether_ios.h
- src/bridge/ios/packet_adapter_ios.c
- src/bridge/ios/packet_adapter_ios.h
- SoftEtherVPN_Stable/src/Cedar/*.c
- SoftEtherVPN_Stable/src/Mayaqua/*.c

# Add Swift sources
- ios/Swift/SoftEtherBridge.swift

# Configure Build Settings
- Header Search Paths: 
  - $(PROJECT_DIR)/ios/C
  - $(PROJECT_DIR)/src/bridge/ios
  - $(PROJECT_DIR)/SoftEtherVPN_Stable/src/Cedar
  - $(PROJECT_DIR)/SoftEtherVPN_Stable/src/Mayaqua
  - /path/to/openssl/include

- Library Search Paths:
  - /path/to/openssl/lib

- Other Linker Flags:
  - -lssl
  - -lcrypto
  - -lz
  - -lpthread

- Defines Module: YES
- Module Map File: $(PROJECT_DIR)/ios/C/module.modulemap
```

#### Network Extension Target (PacketTunnelProvider)

```bash
# Add Network Extension target
# File → New → Target → Network Extension

# Add Swift source
- ios/Swift/PacketTunnelProvider.swift

# Link framework
- Embed SoftEtherVPN.framework

# Entitlements (PacketTunnel.entitlements)
- com.apple.developer.networking.networkextension
- packet-tunnel-provider
```

### 3. Configure Entitlements

**App Entitlements (SoftEtherVPN.entitlements)**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.developer.networking.networkextension</key>
    <array>
        <string>packet-tunnel-provider</string>
    </array>
</dict>
</plist>
```

**Extension Entitlements (PacketTunnelExtension.entitlements)**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.developer.networking.networkextension</key>
    <array>
        <string>packet-tunnel-provider</string>
    </array>
    <key>com.apple.security.application-groups</key>
    <array>
        <string>group.com.softether.vpn</string>
    </array>
</dict>
</plist>
```

### 4. Build Framework

```bash
# Build for device
xcodebuild -project SoftEtherVPN.xcodeproj \
           -scheme SoftEtherVPN \
           -configuration Release \
           -arch arm64 \
           -sdk iphoneos

# Build for simulator
xcodebuild -project SoftEtherVPN.xcodeproj \
           -scheme SoftEtherVPN \
           -configuration Release \
           -arch x86_64 \
           -sdk iphonesimulator

# Create XCFramework (optional, for distribution)
xcodebuild -create-xcframework \
           -framework build/Release-iphoneos/SoftEtherVPN.framework \
           -framework build/Release-iphonesimulator/SoftEtherVPN.framework \
           -output SoftEtherVPN.xcframework
```

## Usage

### Container App Integration

```swift
import NetworkExtension
import SoftEtherVPN

class VPNManager {
    private var tunnelManager: NETunnelProviderManager?
    
    func setupVPN() {
        // Load or create VPN configuration
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            if let error = error {
                print("Error loading VPN: \(error)")
                return
            }
            
            let manager = managers?.first ?? NETunnelProviderManager()
            self?.tunnelManager = manager
            
            // Configure protocol
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "com.softether.vpn.extension"
            proto.serverAddress = "vpn.example.com"
            proto.username = "user@hub"
            proto.providerConfiguration = [
                "HubName": "MyHub"
            ]
            
            manager.protocolConfiguration = proto
            manager.localizedDescription = "SoftEther VPN"
            manager.isEnabled = true
            
            // Save configuration
            manager.saveToPreferences { error in
                if let error = error {
                    print("Error saving VPN: \(error)")
                } else {
                    print("VPN configured successfully")
                }
            }
        }
    }
    
    func connect() {
        guard let manager = tunnelManager else { return }
        
        let options: [String: NSObject] = [
            "ServerName": "vpn.example.com" as NSString,
            "ServerPort": 443 as NSNumber,
            "HubName": "MyHub" as NSString,
            "Username": "user" as NSString,
            "Password": "password" as NSString
        ]
        
        do {
            try manager.connection.startVPNTunnel(options: options)
        } catch {
            print("Failed to start VPN: \(error)")
        }
    }
    
    func disconnect() {
        tunnelManager?.connection.stopVPNTunnel()
    }
    
    func getStatus() -> NEVPNStatus {
        return tunnelManager?.connection.status ?? .invalid
    }
}
```

### Direct Bridge Usage (Advanced)

```swift
import SoftEtherVPN

// Initialize bridge
let bridge = SoftEtherVPNBridge()

do {
    // Initialize library
    try bridge.initialize()
    bridge.setLogLevel(.info)
    
    // Create client
    try bridge.createClient()
    
    // Connect (async/await)
    let params = SoftEtherVPNBridge.ConnectionParameters(
        serverName: "vpn.example.com",
        serverPort: 443,
        hubName: "MyHub",
        username: "user",
        password: "password"
    )
    
    try await bridge.connect(parameters: params)
    print("Connected!")
    
    // Later...
    try await bridge.disconnect()
    print("Disconnected")
    
} catch {
    print("Error: \(error)")
}
```

## Packet Flow

### From TUN to VPN (Outbound)

1. iOS System → NEPacketTunnelFlow.readPackets()
2. Swift: PacketTunnelProvider.readPacketsFromTUN()
3. Swift → C: softether_ios_receive_packets()
4. C → Packet Adapter: IOSTunReceivePackets()
5. Packet Adapter: Enqueue to recv_queue
6. SoftEther: PacketAdapterRead() dequeues from recv_queue
7. SoftEther: Processes packet (encryption, routing)
8. TCP/UDP socket → VPN server

### From VPN to TUN (Inbound)

1. VPN server → TCP/UDP socket
2. SoftEther: Receives encrypted packet
3. SoftEther: Decrypts and processes
4. SoftEther: PacketAdapterWrite() enqueues to send_queue
5. Packet Adapter: Send thread batches up to 32 packets
6. C → Swift: IOSWritePacketsCallback()
7. Swift: NEPacketTunnelFlow.writePackets()
8. iOS System → Network stack

## Threading Model

```
Main Thread (Swift)
    ↓ startTunnel()
Background Queue
    ↓ Connect to VPN
    ├─ Packet Read Loop (Swift)
    │   ↓ readPackets (async)
    │   ↓ softether_ios_receive_packets()
    │   ↓ IOSTunReceivePackets() → recv_queue
    │
    ├─ SoftEther Worker Threads (C)
    │   ↓ Process VPN packets
    │   ↓ PacketAdapterRead() ← recv_queue
    │   ↓ PacketAdapterWrite() → send_queue
    │
    └─ Send Thread (C)
        ↓ IOSTunSendThread()
        ↓ Batch 32 packets from send_queue
        ↓ IOSWritePacketsCallback()
        ↓ writePackets (Swift)
```

## Debugging

### Enable Verbose Logging

```swift
// In PacketTunnelProvider.startTunnel()
softether_ios_set_log_level(5) // TRACE level
```

### Console Logs

```bash
# View extension logs
log stream --predicate 'subsystem == "com.softether.vpn"' --level debug

# Filter by category
log stream --predicate 'subsystem == "com.softether.vpn" AND category == "PacketTunnel"'
```

### Common Issues

**Issue**: Extension crashes on launch
- **Solution**: Check that all frameworks are embedded correctly
- **Solution**: Verify entitlements are configured

**Issue**: Cannot connect to VPN server
- **Solution**: Check network connectivity from extension
- **Solution**: Verify server address and credentials
- **Solution**: Check firewall rules (extension runs in sandbox)

**Issue**: Packets not forwarding
- **Solution**: Verify NEPacketTunnelFlow is set correctly
- **Solution**: Check callback pointers are valid
- **Solution**: Enable TRACE logging to see packet flow

**Issue**: "Missing entitlement" error
- **Solution**: Network Extension requires paid Apple Developer account
- **Solution**: Ensure packet-tunnel-provider entitlement is added

## Performance Tuning

### Batch Size
```c
// In packet_adapter_ios.c
#define MAX_BATCH_SIZE 32  // Increase for higher throughput
```

### Queue Size
```c
#define MAX_QUEUE_SIZE 256  // Increase for bursty traffic
```

### Thread Priority
```swift
// In PacketTunnelProvider
DispatchQueue.global(qos: .userInitiated).async {
    // Packet processing
}
```

## File Summary

| File | Lines | Purpose |
|------|-------|---------|
| ios/Swift/PacketTunnelProvider.swift | 230 | NEPacketTunnelProvider implementation |
| ios/Swift/SoftEtherBridge.swift | 220 | Swift API wrapper |
| ios/C/softether_ios.c | 140 | C bridge functions |
| ios/C/softether_ios.h | 70 | C bridge header |
| ios/C/module.modulemap | 4 | Swift/C interop |
| src/bridge/ios/packet_adapter_ios.c | 380 | Packet adapter implementation |
| src/bridge/ios/packet_adapter_ios.h | 35 | Packet adapter header |
| **Total** | **1,079** | Complete iOS implementation |

## Testing

### Unit Tests
```bash
# Run tests in Xcode
xcodebuild test -scheme SoftEtherVPN -destination 'platform=iOS Simulator,name=iPhone 14'
```

### Manual Testing
1. Build and install app + extension on device
2. Configure VPN in app
3. Connect via Settings → VPN or in-app
4. Test connectivity: ping, web browsing, etc.
5. Check logs for errors
6. Test disconnect and reconnect

## Distribution

### App Store
- Network Extension requires manual entitlement from Apple
- Submit entitlement request: https://developer.apple.com/contact/request/networking-entitlement/
- Wait for approval (typically 1-2 weeks)
- Build with production certificate

### Enterprise/TestFlight
- Same entitlement required
- Can test with development provisioning profile

## License

Same as SoftEther VPN - Apache 2.0 (see LICENSE.TXT)

## References

- [Network Extension Programming Guide](https://developer.apple.com/documentation/networkextension)
- [NEPacketTunnelProvider Reference](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider)
- [NEPacketTunnelFlow Reference](https://developer.apple.com/documentation/networkextension/nepackettunnelflow)
- [SoftEther VPN Documentation](https://www.softether.org/)
