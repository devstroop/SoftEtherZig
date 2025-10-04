# SoftEtherZig iOS API Reference

Complete API documentation aligned with the C FFI implementation.

## Table of Contents
1. [C FFI API](#c-ffi-api)
2. [Swift Bridge API](#swift-bridge-api)
3. [Configuration Formats](#configuration-formats)
4. [Usage Examples](#usage-examples)
5. [API Comparison](#api-comparison)

---

## C FFI API

The core C FFI API is defined in `include/softether_ffi.h`. This is the native API that all other layers build upon.

### Client Lifecycle

```c
// Create client from JSON configuration
softether_client_t* softether_client_create(const char* json_config);

// Connect to VPN server (blocking call)
int softether_client_connect(softether_client_t* handle);

// Disconnect from VPN server
int softether_client_disconnect(softether_client_t* handle);

// Free client resources (must be called after use)
void softether_client_free(softether_client_t* handle);
```

**Returns:**
- `softether_client_create()`: Client handle or `NULL` on error
- `softether_client_connect()`: `0` on success, negative on error
- `softether_client_disconnect()`: `0` on success, negative on error

### Packet I/O - Layer 2 (Ethernet Frames)

For full L2 frame handling with MAC headers:

```c
// RX callback: Receives Ethernet frames FROM tunnel
typedef void (*softether_rx_cb_t)(const uint8_t* data, uint32_t len, void* user);

// Register callback for received frames
int softether_client_set_rx_callback(softether_client_t* handle, 
                                     softether_rx_cb_t cb, 
                                     void* user);

// Send Ethernet frame TO tunnel
// Returns: 1 if queued, 0 if no link, negative on error
int softether_client_send_frame(softether_client_t* handle, 
                                const uint8_t* data, 
                                uint32_t len);
```

### Packet I/O - Layer 3 (IP Packets)

For iOS NEPacketTunnelFlow integration (no MAC headers):

```c
// RX callback: Receives IP packets FROM tunnel (EtherType 0x0800 stripped)
typedef void (*softether_ip_rx_cb_t)(const uint8_t* ip_packet, uint32_t len, void* user);

// Register callback for received IP packets
int softether_client_set_ip_rx_callback(softether_client_t* handle, 
                                        softether_ip_rx_cb_t cb, 
                                        void* user);

// Send IP packet TO tunnel
// Returns: 1 if queued, 0 if no link, negative on error
int softether_client_send_ip_packet(softether_client_t* handle, 
                                    const uint8_t* data, 
                                    uint32_t len);
```

**Key Differences:**
- **L2 Mode:** Full Ethernet frames with MAC addresses
- **L3 Mode:** Pure IP packets (iOS NEPacketTunnelFlow only handles IP)

### State & Event Callbacks

```c
// State callback: Notifies of connection state changes
// States: 0=Idle, 1=Connecting, 2=Established, 3=Disconnecting
typedef void (*softether_state_cb_t)(int state, void* user);

int softether_client_set_state_callback(softether_client_t* handle, 
                                       softether_state_cb_t cb, 
                                       void* user);

// Event callback: Receives log events and errors
// Levels: 0=info, 1=warn, 2=error
typedef void (*softether_event_cb_t)(int level, int code, 
                                     const char* message, void* user);

int softether_client_set_event_callback(softether_client_t* handle, 
                                       softether_event_cb_t cb, 
                                       void* user);
```

### Network Information

```c
// Get current network settings as JSON string
// Returns: Allocated string (must be freed with softether_string_free)
// Format: {"assigned_ipv4":"10.0.0.2", "subnet_mask":"255.255.255.0",
//          "gateway":"10.0.0.1", "dns_servers":["8.8.8.8","8.8.4.4"]}
char* softether_client_get_network_settings_json(softether_client_t* handle);

// Get client MAC address
// Returns: 0 on success, negative on error
int softether_client_get_mac(softether_client_t* handle, uint8_t out_mac[6]);

// Get last error message
// Returns: Allocated string (must be freed) or NULL if no error
char* softether_client_last_error(softether_client_t* handle);

// Free strings returned by API
void softether_string_free(char* str);

// Get library version
// Returns: Allocated string (must be freed)
char* softether_client_version(void);
```

### ARP Management (L3 Mode)

```c
// Add static ARP entry for L3 mode routing
// ipv4_be: IPv4 address in big-endian (network byte order)
// mac: 6-byte MAC address
// Returns: 0 on success, negative on error
int softether_client_arp_add(softether_client_t* handle, 
                             uint32_t ipv4_be, 
                             const uint8_t mac[6]);
```

### Logging

```c
typedef enum {
    LOG_LEVEL_SILENT = 0,  // No logging
    LOG_LEVEL_ERROR = 1,   // Errors only
    LOG_LEVEL_WARN = 2,    // Warnings and errors
    LOG_LEVEL_INFO = 3,    // Info, warnings, errors
    LOG_LEVEL_DEBUG = 4,   // Debug messages
    LOG_LEVEL_TRACE = 5    // Verbose tracing
} LogLevel;

// Set global log level
void set_log_level(LogLevel level);

// Get log level name
const char* get_log_level_name(LogLevel level);

// Parse log level from string
LogLevel parse_log_level(const char* str);
```

### Utility

```c
// Decode Base64 string
// Returns: Number of decoded bytes, or negative on error
int softether_b64_decode(const char* b64, 
                         unsigned char* out_buf, 
                         unsigned int out_cap);
```

---

## Swift Bridge API

The Swift wrapper (`SoftEtherBridge.swift`) provides a type-safe, Swift-friendly interface.

### Class: SoftEtherVPNBridge

```swift
public class SoftEtherVPNBridge {
    
    // MARK: - Types
    
    public struct ConnectionParameters {
        public let serverName: String
        public let serverPort: Int32   // Default: 443
        public let hubName: String
        public let username: String
        public let password: String
        
        public init(serverName: String, 
                   serverPort: Int32 = 443,
                   hubName: String,
                   username: String,
                   password: String)
    }
    
    public enum VPNError: Error {
        case initializationFailed(Int32)
        case clientCreationFailed
        case connectionFailed(Int32)
        case disconnectionFailed(Int32)
        case notConnected
        case invalidParameters
    }
    
    public enum LogLevel: Int32 {
        case silent = 0
        case error = 1
        case warning = 2
        case info = 3
        case debug = 4
        case trace = 5
    }
    
    // MARK: - Initialization
    
    public init()
    
    // Initialize SoftEther library
    public func initialize() throws
    
    // Create VPN client
    public func createClient() throws
    
    // MARK: - Connection Management
    
    // Connect to VPN server (synchronous)
    public func connect(parameters: ConnectionParameters) throws
    
    // Disconnect from VPN server (synchronous)
    public func disconnect() throws
    
    // MARK: - Configuration
    
    // Set logging level
    public func setLogLevel(_ level: LogLevel)
    
    // MARK: - Packet I/O (Network Extension)
    
    // Set packet flow for NEPacketTunnelFlow integration
    public func setPacketFlow(_ flow: AnyObject,
                             writeCallback: @escaping IOSWritePacketsCallback,
                             readCallback: @escaping IOSReadPacketsCallback,
                             context: UnsafeMutableRawPointer?)
    
    // Receive packets from TUN device (iOS → VPN)
    public func receivePackets(_ packets: [Data])
    
    // MARK: - Status
    
    // Get current connection status
    public var connectionStatus: Bool { get }
    
    // MARK: - Cleanup
    
    // Release all resources
    public func cleanup()
}
```

### Async/Await Support (iOS 13+)

```swift
@available(iOS 13.0, *)
extension SoftEtherVPNBridge {
    
    // Connect asynchronously
    public func connect(parameters: ConnectionParameters) async throws
    
    // Disconnect asynchronously
    public func disconnect() async throws
}
```

---

## Configuration Formats

### JSON Configuration (C FFI)

Used with `softether_client_create()`:

```json
{
  "server": "vpn.example.com:443",
  "hub": "MyHub",
  "user": "username",
  "password": "password"
}
```

**Fields:**
- `server`: Server hostname and port (format: `hostname:port`)
- `hub`: Virtual Hub name on the server
- `user`: Username for authentication
- `password`: Password for authentication

### Swift Configuration (Bridge)

```swift
let params = SoftEtherVPNBridge.ConnectionParameters(
    serverName: "vpn.example.com",
    serverPort: 443,
    hubName: "MyHub",
    username: "user",
    password: "password"
)
```

### NEVPNManager Options (IPC)

Passed from container app to Network Extension:

```swift
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
proto.providerBundleIdentifier = "com.your.app.extension"
proto.serverAddress = "vpn.example.com"
proto.username = "user"
proto.providerConfiguration = [
    "HubName": "MyHub",
    "ServerPort": 443
]
```

---

## Usage Examples

### Example 1: Direct C FFI API Usage

```swift
import SoftEtherClient

func connectUsingCFFI() {
    // 1. Create JSON configuration
    let config = """
    {
        "server": "vpn.example.com:443",
        "hub": "MyHub",
        "user": "myuser",
        "password": "mypassword"
    }
    """
    
    // 2. Create client
    guard let client = softether_client_create(config) else {
        print("Failed to create client")
        return
    }
    
    // 3. Set up state callback
    let stateCallback: softether_state_cb_t = { (state, user) in
        let states = ["Idle", "Connecting", "Established", "Disconnecting"]
        print("State: \(states[Int(state)])")
    }
    softether_client_set_state_callback(client, stateCallback, nil)
    
    // 4. Set up IP packet RX callback (L3 mode for iOS)
    let rxCallback: softether_ip_rx_cb_t = { (packet, len, user) in
        let data = Data(bytes: packet!, count: Int(len))
        print("Received IP packet: \(data.count) bytes")
        
        // Forward to NEPacketTunnelFlow
        // packetFlow.writePackets([data], withProtocols: [AF_INET])
    }
    softether_client_set_ip_rx_callback(client, rxCallback, nil)
    
    // 5. Set up event callback
    let eventCallback: softether_event_cb_t = { (level, code, message, user) in
        let levelNames = ["INFO", "WARN", "ERROR"]
        let msg = String(cString: message!)
        print("[\(levelNames[Int(level)])] \(code): \(msg)")
    }
    softether_client_set_event_callback(client, eventCallback, nil)
    
    // 6. Connect
    let result = softether_client_connect(client)
    if result == 0 {
        print("Connected successfully!")
        
        // 7. Get network settings
        if let settingsJson = softether_client_get_network_settings_json(client) {
            let settings = String(cString: settingsJson)
            print("Network settings: \(settings)")
            softether_string_free(settingsJson)
        }
        
        // 8. Get MAC address
        var mac: [UInt8] = Array(repeating: 0, count: 6)
        if softether_client_get_mac(client, &mac) == 0 {
            let macStr = mac.map { String(format: "%02x", $0) }.joined(separator: ":")
            print("Client MAC: \(macStr)")
        }
        
        // 9. Send IP packet
        let ipPacket = Data([/* IP packet bytes */])
        ipPacket.withUnsafeBytes { buffer in
            if let baseAddress = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                let sent = softether_client_send_ip_packet(client, baseAddress, UInt32(ipPacket.count))
                print("Send result: \(sent)")
            }
        }
        
        // 10. Disconnect when done
        Thread.sleep(forTimeInterval: 10)
        softether_client_disconnect(client)
    } else {
        print("Connection failed: \(result)")
        if let error = softether_client_last_error(client) {
            print("Error: \(String(cString: error))")
            softether_string_free(error)
        }
    }
    
    // 11. Cleanup
    softether_client_free(client)
}
```

### Example 2: Swift Bridge API (Synchronous)

```swift
import SoftEtherVPN

func connectUsingSwiftBridge() {
    let bridge = SoftEtherVPNBridge()
    
    do {
        // 1. Initialize
        try bridge.initialize()
        print("Library initialized")
        
        // 2. Set log level
        bridge.setLogLevel(.info)
        
        // 3. Create client
        try bridge.createClient()
        print("Client created")
        
        // 4. Prepare connection parameters
        let params = SoftEtherVPNBridge.ConnectionParameters(
            serverName: "vpn.example.com",
            serverPort: 443,
            hubName: "MyHub",
            username: "myuser",
            password: "mypassword"
        )
        
        // 5. Connect
        try bridge.connect(parameters: params)
        print("Connected!")
        
        // 6. Check status
        print("Is connected: \(bridge.connectionStatus)")
        
        // 7. Keep connection alive...
        Thread.sleep(forTimeInterval: 30)
        
        // 8. Disconnect
        try bridge.disconnect()
        print("Disconnected")
        
    } catch SoftEtherVPNBridge.VPNError.initializationFailed(let code) {
        print("Initialization failed: \(code)")
    } catch SoftEtherVPNBridge.VPNError.connectionFailed(let code) {
        print("Connection failed: \(code)")
    } catch {
        print("Error: \(error)")
    }
    
    // 9. Cleanup
    bridge.cleanup()
}
```

### Example 3: Swift Bridge API (Async/Await)

```swift
import SoftEtherVPN

@available(iOS 13.0, *)
func connectAsync() async {
    let bridge = SoftEtherVPNBridge()
    
    do {
        // Initialize
        try bridge.initialize()
        bridge.setLogLevel(.debug)
        
        // Create client
        try bridge.createClient()
        
        // Connect asynchronously
        let params = SoftEtherVPNBridge.ConnectionParameters(
            serverName: "vpn.example.com",
            serverPort: 443,
            hubName: "MyHub",
            username: "myuser",
            password: "mypassword"
        )
        
        print("Connecting...")
        try await bridge.connect(parameters: params)
        print("Connected successfully!")
        
        // Keep alive
        try await Task.sleep(nanoseconds: 30_000_000_000) // 30 seconds
        
        // Disconnect asynchronously
        print("Disconnecting...")
        try await bridge.disconnect()
        print("Disconnected")
        
    } catch {
        print("Error: \(error)")
    }
    
    bridge.cleanup()
}
```

### Example 4: Network Extension Integration

```swift
import NetworkExtension

class MyPacketTunnelProvider: NEPacketTunnelProvider {
    
    private let bridge = SoftEtherVPNBridge()
    
    override func startTunnel(options: [String : NSObject]?, 
                            completionHandler: @escaping (Error?) -> Void) {
        do {
            // 1. Initialize
            try bridge.initialize()
            bridge.setLogLevel(.info)
            try bridge.createClient()
            
            // 2. Get parameters
            guard let serverName = options?["ServerName"] as? String,
                  let hubName = options?["HubName"] as? String,
                  let username = options?["Username"] as? String,
                  let password = options?["Password"] as? String else {
                completionHandler(NEVPNError(.configurationInvalid))
                return
            }
            
            let serverPort = options?["ServerPort"] as? Int32 ?? 443
            
            // 3. Set up packet flow callbacks
            let writeCallback: IOSWritePacketsCallback = { (flow, packets, sizes, count) in
                // Convert to Swift arrays
                guard let packetsPtr = packets,
                      let sizesPtr = sizes,
                      let flowObj = flow else { return }
                
                var dataPackets: [Data] = []
                var protocols: [NSNumber] = []
                
                for i in 0..<Int(count) {
                    let ptr = packetsPtr[i]
                    let size = Int(sizesPtr[i])
                    let data = Data(bytes: ptr!, count: size)
                    dataPackets.append(data)
                    protocols.append(NSNumber(value: AF_INET))
                }
                
                // Get NEPacketTunnelFlow
                let packetFlow = Unmanaged<NEPacketTunnelFlow>
                    .fromOpaque(flowObj).takeUnretainedValue()
                packetFlow.writePackets(dataPackets, withProtocols: protocols)
            }
            
            let readCallback: IOSReadPacketsCallback = { (flow, context) in
                // Trigger read on main queue
                DispatchQueue.main.async {
                    // self.readPacketsFromTUN()
                }
            }
            
            bridge.setPacketFlow(self.packetFlow,
                               writeCallback: writeCallback,
                               readCallback: readCallback,
                               context: nil)
            
            // 4. Configure network settings
            let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: serverName)
            settings.ipv4Settings = NEIPv4Settings(
                addresses: ["10.0.0.2"],
                subnetMasks: ["255.255.255.0"]
            )
            settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
            
            setTunnelNetworkSettings(settings) { error in
                if let error = error {
                    completionHandler(error)
                    return
                }
                
                // 5. Connect to VPN
                let params = SoftEtherVPNBridge.ConnectionParameters(
                    serverName: serverName,
                    serverPort: serverPort,
                    hubName: hubName,
                    username: username,
                    password: password
                )
                
                do {
                    try self.bridge.connect(parameters: params)
                    
                    // 6. Start packet read loop
                    self.startReadLoop()
                    
                    completionHandler(nil)
                } catch {
                    completionHandler(error)
                }
            }
            
        } catch {
            completionHandler(error)
        }
    }
    
    private func startReadLoop() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }
            
            // Forward packets to VPN
            self.bridge.receivePackets(packets)
            
            // Continue reading
            self.startReadLoop()
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, 
                            completionHandler: @escaping () -> Void) {
        do {
            try bridge.disconnect()
            bridge.cleanup()
        } catch {
            print("Error disconnecting: \(error)")
        }
        completionHandler()
    }
}
```

---

## API Comparison

| Operation | C FFI API | Swift Bridge | Purpose |
|-----------|-----------|--------------|---------|
| **Initialize** | `softether_client_create(json)` | `initialize()` + `createClient()` | Create VPN client instance |
| **Connect** | `softether_client_connect(handle)` | `connect(parameters:)` | Establish VPN connection |
| **Disconnect** | `softether_client_disconnect(handle)` | `disconnect()` | Close VPN connection |
| **Send Packet (L3)** | `softether_client_send_ip_packet(handle, data, len)` | `receivePackets([Data])` | Send IP packet to VPN |
| **Receive Callback (L3)** | `softether_client_set_ip_rx_callback(handle, cb, user)` | `setPacketFlow(...)` | Receive IP packets from VPN |
| **Send Frame (L2)** | `softether_client_send_frame(handle, data, len)` | N/A | Send Ethernet frame |
| **Receive Callback (L2)** | `softether_client_set_rx_callback(handle, cb, user)` | N/A | Receive Ethernet frames |
| **State Events** | `softether_client_set_state_callback(handle, cb, user)` | N/A | Monitor connection state |
| **Error Events** | `softether_client_set_event_callback(handle, cb, user)` | N/A | Monitor errors/warnings |
| **Get Network Info** | `softether_client_get_network_settings_json(handle)` | N/A | Get IP/gateway/DNS |
| **Get MAC** | `softether_client_get_mac(handle, mac)` | N/A | Get client MAC address |
| **Add ARP** | `softether_client_arp_add(handle, ip, mac)` | N/A | Add static ARP entry |
| **Get Error** | `softether_client_last_error(handle)` | Throws `VPNError` | Get last error message |
| **Set Log Level** | `set_log_level(level)` | `setLogLevel(_:)` | Control logging verbosity |
| **Get Version** | `softether_client_version()` | N/A | Get library version |
| **Cleanup** | `softether_client_free(handle)` | `cleanup()` | Release resources |

### When to Use Which API

**Use C FFI API when:**
- You need maximum control and flexibility
- You're implementing a custom packet handling layer
- You need L2 (Ethernet frame) support
- You want to handle state/event callbacks directly
- You're integrating with C/C++ code

**Use Swift Bridge when:**
- You're building a pure Swift iOS app
- You want type-safe, idiomatic Swift code
- You're using Network Extension (NEPacketTunnelProvider)
- You prefer async/await patterns (iOS 13+)
- You want simplified error handling

---

## Return Codes

### Success Codes
- `0`: Operation successful
- `1`: Packet queued successfully (for send operations)

### Error Codes
- `-1`: Generic error
- `-2`: Invalid parameters
- `-3`: Not connected
- `-4`: Connection failed
- `-5`: Timeout
- Negative values: Check `softether_client_last_error()` for details

---

## Thread Safety

**C FFI API:**
- All callbacks are invoked from internal threads
- Callbacks must be thread-safe and return quickly
- Do not call blocking operations in callbacks
- Client handle can be used from any thread after creation

**Swift Bridge:**
- All public methods are thread-safe
- Callbacks are dispatched to appropriate queues
- Use `@MainActor` for UI updates from callbacks

---

## Memory Management

**C FFI API:**
- Always call `softether_client_free()` when done
- Free strings with `softether_string_free()`
- Client handle must outlive all callbacks

**Swift Bridge:**
- Automatic cleanup in `deinit`
- Call `cleanup()` explicitly for deterministic cleanup
- All resources released when object is deallocated

---

## See Also

- [SoftEtherZig Main Documentation](../README.md)
- [iOS Integration Guide](./README.md)
- [Network Extension Programming Guide](https://developer.apple.com/documentation/networkextension)
- [SoftEther VPN Documentation](https://www.softether.org/)
