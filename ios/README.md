# SoftEther VPN iOS Integration

Complete iOS Network Extension implementation for SoftEther VPN client.

## Architecture

**Integration Method:** Pure **C FFI API** (Foreign Function Interface)

```
iOS App Container (Swift)
    ↓ IPC (Options/Configuration)
Network Extension (PacketTunnelProvider - Swift)
    ↓ Swift → C FFI Bridge
SoftEther iOS Bridge (C FFI API)
    ↓ C FFI → Zig callconv(.C)
Zig Implementation Layer
    ↓ Zig → C Bridge
iOS Packet Adapter (C)
    ↓ Callback Interface
SoftEther Core (Cedar + Mayaqua - C)
```

**Why C FFI (Not C++):**
- ✅ Universal ABI compatibility (Swift, Rust, Python, etc.)
- ✅ No C++ name mangling or template complexity
- ✅ Zig has first-class C interop with `callconv(.C)`
- ✅ iOS/Objective-C bridging works seamlessly with pure C
- ✅ SoftEther core is already pure C

## Components

### Swift Layer
- **PacketTunnelProvider.swift** (230 lines)
  - NEPacketTunnelProvider subclass
  - Handles VPN lifecycle (start/stop/sleep/wake)
  - Manages NEPacketTunnelFlow packet forwarding
  - IPC from container app
  - **Calls C FFI functions directly** (no C++ wrapper)

- **SoftEtherBridge.swift** (220 lines)
  - Swift-friendly API wrapper around C FFI
  - Type-safe connection parameters
  - Error handling with Swift Result types
  - Async/await support (iOS 13+)
  - **Bridges Swift → C FFI API**

### C FFI Layer (include/softether_ffi.h)
- **Pure C API with `extern "C"` linkage**
  - `softether_client_create()` - Client initialization
  - `softether_client_connect()` - VPN connection
  - `softether_client_send_frame()` - L2 packet I/O
  - `softether_client_send_ip_packet()` - L3 packet I/O (iOS NEPacketTunnelFlow)
  - Callback typedefs for RX, state, and events
  - **No C++ features** - pure C ABI for maximum compatibility

### Zig Implementation Layer (src/ffi.zig)
- **Zig functions with C calling convention**
  - `export fn softether_vpn_init() callconv(.C)`
  - Implements C FFI API using Zig's C interop
  - Bridges between C FFI and Zig client implementation
  - **Uses `callconv(.C)` for C ABI compatibility**

### C Bridge Layer (ios/C/)
- **ios/C/softether_ios.c/h** (210 lines)
  - iOS-specific C interface for Swift interop
  - Functions: init, create_client, connect, disconnect
  - Packet flow management
  - Global client lifecycle
  - **Pure C, no C++ dependencies**

### Packet Adapter
- **src/bridge/ios/packet_adapter_ios.c/h** (415 lines)
  - NEPacketTunnelFlow integration via callbacks
  - Dual queue system (recv/send)
  - Background send thread with batch processing (up to 32 packets)
  - Thread-safe queue management
  - **Written in C for compatibility with SoftEther core**

## Key Differences from Android

| Aspect | Android | iOS |
|--------|---------|-----|
| **API Type** | C FFI | **C FFI (same)** |
| **Language** | Kotlin/Java → JNI → C | Swift → C FFI → Zig |
| TUN Interface | File descriptor (ParcelFileDescriptor) | Callback-based (NEPacketTunnelFlow) |
| Packet I/O | Direct read/write on fd | writePackets/readPackets callbacks |
| Threading | Single thread per direction | Background send thread + read loop |
| Batch Processing | Not required | Up to 32 packets per write |
| Permissions | VpnService with user approval | Network Extension + entitlements |
| **ABI** | C calling convention | **C calling convention (same)** |

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

## API Documentation

For complete API reference, see [API_REFERENCE.md](./API_REFERENCE.md) which covers:

- **C FFI API** - Core C interface (`softether_ffi.h`)
- **Swift Bridge API** - Swift wrapper (`SoftEtherBridge.swift`)
- **Configuration Formats** - JSON, Swift, NEVPNManager
- **Usage Examples** - Direct C FFI, Swift Bridge, Network Extension
- **API Comparison** - When to use which API

## Quick Start

### Option 1: Direct C FFI API (Maximum Control)

```swift
import SoftEtherClient

let config = """
{"server": "vpn.example.com:443", "hub": "MyHub", 
 "user": "username", "password": "password"}
"""

guard let client = softether_client_create(config) else { return }

// Set callbacks
softether_client_set_state_callback(client, { state, _ in
    print("State: \(state)")  // 0=Idle, 1=Connecting, 2=Established, 3=Disconnecting
}, nil)

// Connect
if softether_client_connect(client) == 0 {
    print("Connected!")
    
    // Send IP packet
    let packet = Data([/* IP packet bytes */])
    packet.withUnsafeBytes { buffer in
        softether_client_send_ip_packet(client, buffer.baseAddress, UInt32(packet.count))
    }
}

softether_client_free(client)
```

### Option 2: Swift Bridge (Recommended for iOS Apps)

```swift
import SoftEtherVPN

let bridge = SoftEtherVPNBridge()

do {
    try bridge.initialize()
    try bridge.createClient()
    
    let params = SoftEtherVPNBridge.ConnectionParameters(
        serverName: "vpn.example.com",
        serverPort: 443,
        hubName: "MyHub",
        username: "user",
        password: "password"
    )
    
    // iOS 13+ async/await
    if #available(iOS 13.0, *) {
        try await bridge.connect(parameters: params)
    } else {
        try bridge.connect(parameters: params)
    }
    
    print("Connected!")
} catch {
    print("Error: \(error)")
}
```

### Option 3: Network Extension Integration

```swift
import NetworkExtension

class MyPacketTunnelProvider: NEPacketTunnelProvider {
    
    private let bridge = SoftEtherVPNBridge()
    
    override func startTunnel(options: [String : NSObject]?, 
                            completionHandler: @escaping (Error?) -> Void) {
        // See API_REFERENCE.md for complete implementation
        do {
            try bridge.initialize()
            try bridge.createClient()
            
            // Extract parameters from options
            let serverName = options?["ServerName"] as? String ?? ""
            let hubName = options?["HubName"] as? String ?? ""
            // ... (see full example in API_REFERENCE.md)
            
            completionHandler(nil)
        } catch {
            completionHandler(error)
        }
    }
}
```

### Container App Integration

```swift
import NetworkExtension

class VPNManager {
    private var tunnelManager: NETunnelProviderManager?
    
    func setupVPN() {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            let manager = managers?.first ?? NETunnelProviderManager()
            
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "com.your.app.extension"
            proto.serverAddress = "vpn.example.com"
            proto.providerConfiguration = [
                "HubName": "MyHub",
                "ServerPort": 443
            ]
            
            manager.protocolConfiguration = proto
            manager.localizedDescription = "SoftEther VPN"
            manager.isEnabled = true
            
            manager.saveToPreferences { error in
                // Handle error
            }
        }
    }
    
    func connect() {
        let options: [String: NSObject] = [
            "ServerName": "vpn.example.com" as NSString,
            "ServerPort": 443 as NSNumber,
            "HubName": "MyHub" as NSString,
            "Username": "user" as NSString,
            "Password": "password" as NSString
        ]
        
        try? tunnelManager?.connection.startVPNTunnel(options: options)
    }
}
```

**For complete examples and API documentation, see [API_REFERENCE.md](./API_REFERENCE.md)**

### Direct C FFI API Usage (Advanced)

Using the native C FFI API directly (from `softether_ffi.h`):

```swift
import SoftEtherClient

// Create JSON configuration
let config = """
{
    "server": "vpn.example.com:443",
    "hub": "MyHub",
    "user": "user",
    "password": "password"
}
"""

// Create client from JSON config
guard let client = softether_client_create(config) else {
    print("Failed to create client")
    return
}

// Set up callbacks
let rxCallback: softether_ip_rx_cb_t = { (packet, len, user) in
    // Handle received IP packet
    let data = Data(bytes: packet!, count: Int(len))
    print("Received packet: \(data.count) bytes")
}

softether_client_set_ip_rx_callback(client, rxCallback, nil)

let stateCallback: softether_state_cb_t = { (state, user) in
    // 0=Idle, 1=Connecting, 2=Established, 3=Disconnecting
    print("State changed to: \(state)")
}

softether_client_set_state_callback(client, stateCallback, nil)

// Connect
let result = softether_client_connect(client)
if result == 0 {
    print("Connected!")
    
    // Get network settings
    if let settingsJson = softether_client_get_network_settings_json(client) {
        let jsonString = String(cString: settingsJson)
        print("Network settings: \(jsonString)")
        softether_string_free(settingsJson)
    }
    
    // Send IP packet
    let packet = Data([/* IP packet bytes */])
    packet.withUnsafeBytes { buffer in
        if let baseAddress = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) {
            _ = softether_client_send_ip_packet(client, baseAddress, UInt32(packet.count))
        }
    }
    
    // Disconnect
    softether_client_disconnect(client)
}

// Cleanup
softether_client_free(client)
```

### Using Swift Bridge Wrapper (Recommended)

Using the Swift wrapper from `SoftEtherBridge.swift`:

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
    
    // Connect (async/await on iOS 13+)
    let params = SoftEtherVPNBridge.ConnectionParameters(
        serverName: "vpn.example.com",
        serverPort: 443,
        hubName: "MyHub",
        username: "user",
        password: "password"
    )
    
    if #available(iOS 13.0, *) {
        try await bridge.connect(parameters: params)
    } else {
        try bridge.connect(parameters: params)
    }
    print("Connected!")
    
    // Later...
    try await bridge.disconnect()
    print("Disconnected")
    
} catch {
    print("Error: \(error)")
}
```

## C FFI API Reference

### Core Client Functions

```c
// Create client from JSON configuration
softether_client_t* softether_client_create(const char* json_config);

// JSON config format:
// {
//   "server": "hostname:port",
//   "hub": "HubName",
//   "user": "username",
//   "password": "password"
// }

// Connect to VPN server (blocking)
int softether_client_connect(softether_client_t* handle);

// Disconnect from VPN server
int softether_client_disconnect(softether_client_t* handle);

// Free client resources
void softether_client_free(softether_client_t* handle);
```

### Packet I/O Functions

```c
// L2 Frame I/O (Full Ethernet frames with MAC headers)
typedef void (*softether_rx_cb_t)(const uint8_t* data, uint32_t len, void* user);
int softether_client_set_rx_callback(softether_client_t* handle, 
                                     softether_rx_cb_t cb, void* user);
int softether_client_send_frame(softether_client_t* handle, 
                                const uint8_t* data, uint32_t len);

// L3 IP Packet I/O (iOS NEPacketTunnelFlow mode - No MAC headers)
typedef void (*softether_ip_rx_cb_t)(const uint8_t* ip_packet, uint32_t len, void* user);
int softether_client_set_ip_rx_callback(softether_client_t* handle, 
                                        softether_ip_rx_cb_t cb, void* user);
int softether_client_send_ip_packet(softether_client_t* handle, 
                                    const uint8_t* data, uint32_t len);
```

### State & Event Callbacks

```c
// State callback: 0=Idle, 1=Connecting, 2=Established, 3=Disconnecting
typedef void (*softether_state_cb_t)(int state, void* user);
int softether_client_set_state_callback(softether_client_t* handle, 
                                       softether_state_cb_t cb, void* user);

// Event callback: level=0(info), 1(warn), 2(error)
typedef void (*softether_event_cb_t)(int level, int code, 
                                     const char* message, void* user);
int softether_client_set_event_callback(softether_client_t* handle, 
                                       softether_event_cb_t cb, void* user);
```

### Utility Functions

```c
// Get VPN network settings as JSON
// Returns: {"assigned_ipv4":"10.0.0.2", "subnet_mask":"255.255.255.0", 
//           "gateway":"10.0.0.1", "dns_servers":["8.8.8.8"]}
char* softether_client_get_network_settings_json(softether_client_t* handle);

// Get client MAC address
int softether_client_get_mac(softether_client_t* handle, uint8_t out_mac[6]);

// Get last error message
char* softether_client_last_error(softether_client_t* handle);

// Free strings returned by API
void softether_string_free(char* str);

// Get library version
char* softether_client_version(void);

// Add static ARP entry (for L3 mode)
int softether_client_arp_add(softether_client_t* handle, 
                             uint32_t ipv4_be, const uint8_t mac[6]);
```

### Logging Functions

```c
typedef enum {
    LOG_LEVEL_SILENT = 0,
    LOG_LEVEL_ERROR = 1,
    LOG_LEVEL_WARN = 2,
    LOG_LEVEL_INFO = 3,
    LOG_LEVEL_DEBUG = 4,
    LOG_LEVEL_TRACE = 5
} LogLevel;

void set_log_level(LogLevel level);
const char* get_log_level_name(LogLevel level);
LogLevel parse_log_level(const char* str);
```

## Swift Bridge API Reference

The `SoftEtherBridge.swift` wrapper provides a Swift-friendly interface:

```swift
public class SoftEtherVPNBridge {
    
    // Connection parameters
    public struct ConnectionParameters {
        public let serverName: String
        public let serverPort: Int32  // Default: 443
        public let hubName: String
        public let username: String
        public let password: String
    }
    
    // Error types
    public enum VPNError: Error {
        case initializationFailed(Int32)
        case clientCreationFailed
        case connectionFailed(Int32)
        case disconnectionFailed(Int32)
        case notConnected
        case invalidParameters
    }
    
    // Log levels
    public enum LogLevel: Int32 {
        case silent = 0
        case error = 1
        case warning = 2
        case info = 3
        case debug = 4
        case trace = 5
    }
    
    // Lifecycle
    public func initialize() throws
    public func createClient() throws
    public func connect(parameters: ConnectionParameters) throws
    public func disconnect() throws
    public func cleanup()
    
    // Configuration
    public func setLogLevel(_ level: LogLevel)
    
    // Packet I/O (for Network Extension)
    public func setPacketFlow(_ flow: AnyObject,
                             writeCallback: @escaping IOSWritePacketsCallback,
                             readCallback: @escaping IOSReadPacketsCallback,
                             context: UnsafeMutableRawPointer?)
    public func receivePackets(_ packets: [Data])
    
    // Status
    public var connectionStatus: Bool { get }
}

// Async/await support (iOS 13+)
@available(iOS 13.0, *)
extension SoftEtherVPNBridge {
    public func connect(parameters: ConnectionParameters) async throws
    public func disconnect() async throws
}
```

## Configuration Format

### JSON Configuration (C FFI API)

```json
{
  "server": "vpn.example.com:443",
  "hub": "MyHub",
  "user": "username",
  "password": "password"
}
```

### Swift Configuration (Bridge API)

```swift
let params = SoftEtherVPNBridge.ConnectionParameters(
    serverName: "vpn.example.com",
    serverPort: 443,
    hubName: "MyHub",
    username: "user",
    password: "password"
)
```

### Network Extension Options (IPC from App)

```swift
// In container app
let options: [String: NSObject] = [
    "ServerName": "vpn.example.com" as NSString,
    "ServerPort": 443 as NSNumber,
    "HubName": "MyHub" as NSString,
    "Username": "user" as NSString,
    "Password": "password" as NSString
]

try manager.connection.startVPNTunnel(options: options)
```

### NETunnelProviderProtocol Configuration

```swift
let proto = NETunnelProviderProtocol()
proto.providerBundleIdentifier = "com.softether.vpn.extension"
proto.serverAddress = "vpn.example.com"
proto.username = "user@MyHub"  // Or separate in providerConfiguration
proto.providerConfiguration = [
    "HubName": "MyHub",
    "ServerPort": 443
]
```

## API Comparison

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
