# iOS Integration Guide - SoftEther Mobile Client

This guide shows how to integrate the SoftEther Mobile FFI into your iOS VPN app.

## Overview

The iOS integration consists of:
1. **Mobile FFI Library** (`libsoftether_mobile.a`) - Platform-agnostic C API
2. **Swift Wrapper** (`SoftEtherMobileClient.swift`) - Swift-native API
3. **PacketTunnelProvider** - NetworkExtension integration

## Architecture

```
┌─────────────────────────────────────┐
│  iOS App / PacketTunnelProvider     │
│  (Swift)                            │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  SoftEtherMobileClient.swift        │
│  (Swift wrapper)                    │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  libsoftether_mobile.a              │
│  (Mobile FFI - C API)               │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Zig Packet Adapter                 │
│  (Core VPN logic)                   │
└─────────────────────────────────────┘
```

## Building the Library

### 1. Build Mobile FFI Library

```bash
# From SoftEtherZig root directory
zig build mobile-ffi -Doptimize=ReleaseFast -Dtarget=aarch64-ios

# Output: zig-out/lib/libsoftether_mobile.a
```

### 2. Copy to iOS Project

```bash
# Create framework structure
mkdir -p build_ios/ios-arm64/SoftEtherClient.framework
cp zig-out/lib/libsoftether_mobile.a build_ios/ios-arm64/SoftEtherClient.framework/SoftEtherClient
cp include/mobile_ffi.h build_ios/ios-arm64/SoftEtherClient.framework/Headers/
```

## Xcode Integration

### 1. Add Framework to Project

1. In Xcode, go to your target → **General** → **Frameworks, Libraries, and Embedded Content**
2. Click **+** → **Add Other...** → **Add Files...**
3. Select `SoftEtherClient.framework`
4. Set to **Embed & Sign**

### 2. Add Swift Files

Add these Swift files to your project:
- `ios/Swift/SoftEtherMobileClient.swift`
- `ios/C/module.modulemap`

### 3. Configure Bridging Header

If you don't have a bridging header, create one:

**YourProject-Bridging-Header.h**:
```objc
#import <SoftEtherClient/mobile_ffi.h>
```

Or use a module map (recommended):

**module.modulemap**:
```
module SoftEtherMobile {
    header "mobile_ffi.h"
    export *
}
```

Add to Xcode project and set in Build Settings:
- **Import Paths**: `$(SRCROOT)/ios/C`

## Usage Examples

### Basic Connection

```swift
import Foundation

let client = SoftEtherMobileClient()

// Create configuration
let config = VpnConfig(
    serverName: "vpn.example.com",
    serverPort: 443,
    hubName: "VPN",
    username: "user",
    password: "pass"
)

// Create and connect
Task {
    do {
        try client.create(config: config)
        try await client.connect(timeout: 30)
        
        print("Connected! Status: \(client.getStatus())")
        
        // Get network info
        let networkInfo = try client.getNetworkInfo()
        print("IP: \(networkInfo.ipAddress)")
        print("Gateway: \(networkInfo.gateway)")
        print("DNS: \(networkInfo.dnsServers)")
        
    } catch {
        print("Connection failed: \(error)")
    }
}
```

### PacketTunnelProvider Integration

```swift
import NetworkExtension

class YourPacketTunnelProvider: NEPacketTunnelProvider {
    
    private var client: SoftEtherMobileClient?
    private var isRunning = false
    
    override func startTunnel(options: [String: NSObject]?, 
                            completionHandler: @escaping (Error?) -> Void) {
        
        // Create client
        client = SoftEtherMobileClient()
        
        // Set up callbacks
        client?.onStatusChange { [weak self] status in
            NSLog("VPN Status: \(status.description)")
            
            if status == .connected {
                self?.configureNetworkSettings()
            } else if status == .error {
                self?.cancelTunnelWithError(VpnError.connectFailed(code: -1))
            }
        }
        
        client?.onStatsUpdate { stats in
            NSLog("Stats: \(stats.bytesSent) sent, \(stats.bytesReceived) received")
        }
        
        client?.onNetworkInfo { [weak self] info in
            NSLog("Network config: IP=\(info.ipAddress), Gateway=\(info.gateway)")
            self?.applyNetworkSettings(info)
        }
        
        // Extract config from options
        guard let config = extractConfig(from: options) else {
            completionHandler(VpnError.createFailed)
            return
        }
        
        // Connect
        Task {
            do {
                try client?.create(config: config)
                try await client?.connect(timeout: 30)
                
                isRunning = true
                startPacketFlow()
                
                completionHandler(nil)
            } catch {
                completionHandler(error)
            }
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, 
                           completionHandler: @escaping () -> Void) {
        isRunning = false
        
        Task {
            await client?.disconnect()
            client = nil
            completionHandler()
        }
    }
    
    // MARK: - Network Settings
    
    private func applyNetworkSettings(_ info: NetworkInfo) {
        let settings = NEPacketTunnelNetworkSettings(
            tunnelRemoteAddress: info.gateway
        )
        
        // IPv4 settings
        let ipv4Settings = NEIPv4Settings(
            addresses: [info.ipAddress], 
            subnetMasks: [info.netmask]
        )
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4Settings
        
        // DNS settings
        if !info.dnsServers.isEmpty {
            settings.dnsSettings = NEDNSSettings(servers: info.dnsServers)
        }
        
        // MTU
        settings.mtu = NSNumber(value: info.mtu)
        
        // Apply
        setTunnelNetworkSettings(settings) { error in
            if let error = error {
                NSLog("Failed to apply settings: \(error)")
                self.cancelTunnelWithError(error)
            } else {
                NSLog("Network settings applied successfully")
            }
        }
    }
    
    // MARK: - Packet Flow
    
    private func startPacketFlow() {
        // Read from TUN → Send to VPN
        readPacketsFromTunnel()
        
        // Read from VPN → Write to TUN
        readPacketsFromVPN()
    }
    
    private func readPacketsFromTunnel() {
        guard isRunning else { return }
        
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.isRunning else { return }
            
            // Send each packet to VPN
            Task {
                for packet in packets {
                    do {
                        try await self.client?.writePacket(packet)
                    } catch {
                        NSLog("Failed to write packet: \(error)")
                    }
                }
            }
            
            // Continue reading
            self.readPacketsFromTunnel()
        }
    }
    
    private func readPacketsFromVPN() {
        guard isRunning else { return }
        
        Task {
            while isRunning {
                do {
                    // Read packet from VPN
                    let packet = try await client?.readPacket(timeout: 0.1)
                    
                    if let packet = packet {
                        // Write to TUN device
                        packetFlow.writePackets(
                            [packet], 
                            withProtocols: [NSNumber(value: AF_INET)]
                        )
                    }
                    
                } catch VpnError.noData {
                    // No data available, continue
                    continue
                } catch {
                    NSLog("Failed to read packet: \(error)")
                    try? await Task.sleep(nanoseconds: 100_000_000) // 100ms
                }
            }
        }
    }
    
    private func extractConfig(from options: [String: NSObject]?) -> VpnConfig? {
        // Extract from NETunnelProviderProtocol
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol else {
            return nil
        }
        
        let providerConfig = proto.providerConfiguration ?? [:]
        
        return VpnConfig(
            serverName: proto.serverAddress ?? "",
            serverPort: (providerConfig["port"] as? NSNumber)?.uint16Value ?? 443,
            hubName: providerConfig["hub"] as? String ?? "VPN",
            username: providerConfig["username"] as? String ?? "",
            password: providerConfig["password"] as? String ?? ""
        )
    }
}
```

### Monitoring Stats

```swift
// Set up periodic stats monitoring
client.onStatsUpdate { stats in
    print("""
    VPN Statistics:
    - Sent: \(stats.bytesSent) bytes (\(stats.packetsSent) packets)
    - Received: \(stats.bytesReceived) bytes (\(stats.packetsReceived) packets)
    - Connected: \(stats.connectedDuration) seconds
    - Errors: \(stats.errors)
    - Drops: \(stats.queueDrops)
    """)
}
```

### Manual Packet I/O (Advanced)

```swift
// Synchronous mode (blocking)
do {
    let packet = try client.readPacketSync(timeout: 1.0)
    print("Received \(packet.count) bytes")
    
    try client.writePacketSync(packet)
    print("Sent packet")
} catch VpnError.noData {
    print("No data available")
} catch {
    print("I/O error: \(error)")
}

// Async mode (non-blocking)
Task {
    do {
        let packet = try await client.readPacket(timeout: 1.0)
        print("Received \(packet.count) bytes")
        
        try await client.writePacket(packet)
        print("Sent packet")
    } catch {
        print("I/O error: \(error)")
    }
}
```

## API Reference

### SoftEtherMobileClient

#### Connection Management
- `init()` - Create client instance
- `create(config:)` - Create VPN connection with config
- `connect()` - Connect to VPN server (throws)
- `connect(timeout:)` async - Connect with timeout
- `disconnect()` - Disconnect from VPN
- `disconnect()` async - Async disconnect

#### Status & Stats
- `getStatus() -> VpnStatus` - Get current status
- `getStats() -> VpnStats` - Get statistics (throws)
- `getNetworkInfo() -> NetworkInfo` - Get network config (throws)
- `isConnected() -> Bool` - Check connection status
- `getLastError() -> String?` - Get last error message

#### Packet I/O
- `readPacket(timeout:)` async - Read packet (async)
- `writePacket(_:)` async - Write packet (async)
- `readPacketSync(timeout:)` - Read packet (blocking)
- `writePacketSync(_:)` - Write packet (blocking)

#### Callbacks
- `onStatusChange(_:)` - Set status callback
- `onStatsUpdate(_:)` - Set stats callback
- `onNetworkInfo(_:)` - Set network info callback

#### Version Info
- `SoftEtherMobileClient.version` - Library version
- `SoftEtherMobileClient.buildInfo` - Build info

### Types

#### VpnConfig
```swift
struct VpnConfig {
    let serverName: String
    let serverPort: UInt16
    let hubName: String
    let username: String
    let password: String
    
    var useEncrypt: Bool = true
    var useCompress: Bool = true
    var halfConnection: Bool = false
    var maxConnection: UInt8 = 1
    
    var recvQueueSize: UInt64 = 128
    var sendQueueSize: UInt64 = 128
    var packetPoolSize: UInt64 = 256
    var batchSize: UInt64 = 32
}
```

#### VpnStatus
```swift
enum VpnStatus: Int32 {
    case disconnected = 0
    case connecting = 1
    case connected = 2
    case reconnecting = 3
    case error = 4
}
```

#### VpnStats
```swift
struct VpnStats {
    let bytesSent: UInt64
    let bytesReceived: UInt64
    let packetsSent: UInt64
    let packetsReceived: UInt64
    let connectedDurationMs: UInt64
    let queueDrops: UInt64
    let errors: UInt64
    
    var connectedDuration: TimeInterval // Computed property
}
```

#### NetworkInfo
```swift
struct NetworkInfo {
    let ipAddress: String
    let gateway: String
    let netmask: String
    let dnsServers: [String]
    let mtu: UInt16
}
```

## Troubleshooting

### Library Not Found
```
Error: ld: library not found for -lsoftether_mobile
```

**Solution**: Make sure library is added to **Frameworks, Libraries, and Embedded Content** in target settings.

### Module Not Found
```
Error: No such module 'SoftEtherMobile'
```

**Solution**: 
1. Check `module.modulemap` is in project
2. Verify **Import Paths** in Build Settings includes module directory
3. Clean build folder (Cmd+Shift+K)

### Bridging Header Issues
```
Error: 'mobile_ffi.h' file not found
```

**Solution**: Add header search path to Build Settings:
- **Header Search Paths**: `$(SRCROOT)/../include`

### Memory Leaks

Use Xcode Instruments to check for leaks:
1. Product → Profile → Leaks
2. Run VPN connection test
3. Check for leaked SoftEtherMobileClient instances

**Common causes**:
- Not calling `disconnect()` in `deinit`
- Retain cycles in callbacks (use `[weak self]`)

## Performance Tuning

### Queue Sizes

```swift
var config = VpnConfig(...)
config.recvQueueSize = 256  // Increase for high throughput
config.sendQueueSize = 256
config.packetPoolSize = 512  // Increase for better buffering
config.batchSize = 64        // Increase for better batching
```

### Timeout Values

```swift
// Short timeout for interactive apps (low latency)
let packet = try await client.readPacket(timeout: 0.05) // 50ms

// Longer timeout for background processing
let packet = try await client.readPacket(timeout: 0.5)  // 500ms
```

## Testing

### Unit Tests

```swift
import XCTest

class SoftEtherMobileTests: XCTestCase {
    
    func testClientCreation() throws {
        let client = SoftEtherMobileClient()
        
        let config = VpnConfig(
            serverName: "test.vpn.com",
            serverPort: 443,
            hubName: "TEST",
            username: "test",
            password: "test"
        )
        
        XCTAssertNoThrow(try client.create(config: config))
    }
    
    func testVersionInfo() {
        let version = SoftEtherMobileClient.version
        XCTAssertFalse(version.isEmpty)
        XCTAssertNotEqual(version, "Unknown")
    }
}
```

### Integration Tests

Run on iOS Simulator or device with VPN server access.

## License

MIT License - See LICENSE file for details.
