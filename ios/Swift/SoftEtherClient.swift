//
//  SoftEtherClient.swift
//  Integration Layer
//
//  Swift wrapper for SoftEtherZig C FFI
//

import Foundation

/// Connection state
public enum ConnectionState: Int {
    case idle = 0
    case connecting = 1
    case established = 2
    case disconnecting = 3
    case error = 4
}

/// Event level
public enum EventLevel: Int {
    case info = 0
    case warning = 1
    case error = 2
}

/// VPN Configuration
public struct VPNConfig: Codable {
    let serverName: String
    let serverPort: UInt16
    let hubName: String
    let username: String
    let password: String
    let useEncrypt: Bool
    let useCompress: Bool
    let ipVersion: String?
    let maxConnection: Int?
    
    enum CodingKeys: String, CodingKey {
        case serverName = "server_name"
        case serverPort = "server_port"
        case hubName = "hub_name"
        case username
        case password
        case useEncrypt = "use_encrypt"
        case useCompress = "use_compress"
        case ipVersion = "ip_version"
        case maxConnection = "max_connection"
    }
    
    public init(
        serverName: String,
        serverPort: UInt16 = 443,
        hubName: String,
        username: String,
        password: String,
        useEncrypt: Bool = true,
        useCompress: Bool = true,
        ipVersion: String? = "auto",
        maxConnection: Int? = 1
    ) {
        self.serverName = serverName
        self.serverPort = serverPort
        self.hubName = hubName
        self.username = username
        self.password = password
        self.useEncrypt = useEncrypt
        self.useCompress = useCompress
        self.ipVersion = ipVersion
        self.maxConnection = maxConnection
    }
}

/// Network settings from VPN server
public struct NetworkSettings: Codable {
    let assignedIPv4: String?
    let subnetMask: String?
    let gateway: String?
    let dnsServers: [String]?
    
    enum CodingKeys: String, CodingKey {
        case assignedIPv4 = "assigned_ipv4"
        case subnetMask = "subnet_mask"
        case gateway
        case dnsServers = "dns_servers"
    }
}

/// Connection statistics
public struct ConnectionStats {
    let bytesSent: UInt64
    let bytesReceived: UInt64
    let packetsSent: UInt64
    let packetsReceived: UInt64
    let connectedSeconds: UInt64
    let currentRttMs: UInt32
}

/// VPN Error types
public enum VPNError: Error {
    case notInitialized
    case initializationFailed
    case connectionFailed(code: Int)
    case disconnectionFailed
    case invalidConfiguration
    case operationFailed(message: String)
    case notConnected
}

/// Main SoftEther client class
public class SoftEtherClient {
    private var handle: OpaquePointer?
    private var stateCallback: ((ConnectionState) -> Void)?
    private var eventCallback: ((EventLevel, Int, String) -> Void)?
    private var ipPacketCallback: ((Data) -> Void)?
    private var logCallback: ((Date, Int, String, String) -> Void)?
    
    // Context pointers for C callbacks
    private var stateContext: UnsafeMutableRawPointer?
    private var eventContext: UnsafeMutableRawPointer?
    private var ipRxContext: UnsafeMutableRawPointer?
    private var logContext: UnsafeMutableRawPointer?
    
    public init() {
        // Set default log level
        set_log_level(LOG_LEVEL_INFO)
    }
    
    deinit {
        disconnect()
        if let handle = handle {
            softether_client_free(handle)
        }
        cleanupContexts()
    }
    
    /// Create client with configuration
    public func create(config: VPNConfig) throws {
        // Encode config to JSON
        let encoder = JSONEncoder()
        let jsonData = try encoder.encode(config)
        guard let jsonString = String(data: jsonData, encoding: .utf8) else {
            throw VPNError.invalidConfiguration
        }
        
        // Create client
        handle = softether_client_create_for_ios(jsonString)
        guard handle != nil else {
            throw VPNError.initializationFailed
        }
    }
    
    /// Connect to VPN server
    public func connect() throws {
        guard let handle = handle else {
            throw VPNError.notInitialized
        }
        
        let result = softether_client_connect(handle)
        if result != 0 {
            let errorMsg = getLastError()
            throw VPNError.connectionFailed(code: Int(result))
        }
    }
    
    /// Disconnect from VPN server
    public func disconnect() {
        guard let handle = handle else { return }
        _ = softether_client_disconnect(handle)
    }
    
    /// Get current connection state
    public func getState() -> ConnectionState {
        guard let handle = handle else {
            return .idle
        }
        let state = softether_client_get_state(handle)
        return ConnectionState(rawValue: Int(state)) ?? .error
    }
    
    /// Check if connected
    public func isConnected() -> Bool {
        guard let handle = handle else { return false }
        return softether_client_is_connected(handle) != 0
    }
    
    /// Get connection statistics
    public func getStats() throws -> ConnectionStats {
        guard let handle = handle else {
            throw VPNError.notInitialized
        }
        
        var stats = softether_connection_stats_t()
        let result = softether_client_get_stats(handle, &stats)
        
        if result != 0 {
            throw VPNError.operationFailed(message: "Failed to get statistics")
        }
        
        return ConnectionStats(
            bytesSent: stats.bytes_sent,
            bytesReceived: stats.bytes_received,
            packetsSent: stats.packets_sent,
            packetsReceived: stats.packets_received,
            connectedSeconds: stats.connected_seconds,
            currentRttMs: stats.current_rtt_ms
        )
    }
    
    /// Get network settings from server
    public func getNetworkSettings() throws -> NetworkSettings {
        guard let handle = handle else {
            throw VPNError.notInitialized
        }
        
        guard let jsonPtr = softether_client_get_network_settings_json(handle) else {
            throw VPNError.operationFailed(message: "Failed to get network settings")
        }
        defer { softether_string_free(jsonPtr) }
        
        let jsonString = String(cString: jsonPtr)
        let jsonData = jsonString.data(using: .utf8)!
        
        let decoder = JSONDecoder()
        return try decoder.decode(NetworkSettings.self, from: jsonData)
    }
    
    /// Get last error message
    public func getLastError() -> String {
        guard let handle = handle else {
            return "Client not initialized"
        }
        
        guard let errorPtr = softether_client_last_error(handle) else {
            return "No error"
        }
        defer { softether_string_free(errorPtr) }
        
        return String(cString: errorPtr)
    }
    
    /// Set state change callback
    public func setStateCallback(_ callback: @escaping (ConnectionState) -> Void) {
        self.stateCallback = callback
        
        guard let handle = handle else { return }
        
        // Create context
        let context = UnsafeMutableRawPointer(Unmanaged.passRetained(self).toOpaque())
        stateContext = context
        
        // C callback wrapper
        let cCallback: @convention(c) (Int32, UnsafeMutableRawPointer?) -> Void = { state, userPtr in
            guard let userPtr = userPtr else { return }
            let client = Unmanaged<SoftEtherClient>.fromOpaque(userPtr).takeUnretainedValue()
            
            if let state = ConnectionState(rawValue: Int(state)) {
                DispatchQueue.main.async {
                    client.stateCallback?(state)
                }
            }
        }
        
        softether_client_set_state_callback(handle, cCallback, context)
    }
    
    /// Set event callback
    public func setEventCallback(_ callback: @escaping (EventLevel, Int, String) -> Void) {
        self.eventCallback = callback
        
        guard let handle = handle else { return }
        
        let context = UnsafeMutableRawPointer(Unmanaged.passRetained(self).toOpaque())
        eventContext = context
        
        let cCallback: @convention(c) (Int32, Int32, UnsafePointer<CChar>?, UnsafeMutableRawPointer?) -> Void = {
            level, code, message, userPtr in
            guard let userPtr = userPtr else { return }
            let client = Unmanaged<SoftEtherClient>.fromOpaque(userPtr).takeUnretainedValue()
            
            let levelEnum = EventLevel(rawValue: Int(level)) ?? .info
            let msg = message != nil ? String(cString: message!) : ""
            
            DispatchQueue.main.async {
                client.eventCallback?(levelEnum, Int(code), msg)
            }
        }
        
        softether_client_set_event_callback(handle, cCallback, context)
    }
    
    /// Set IP packet receive callback (for PacketTunnelProvider)
    public func setIPPacketCallback(_ callback: @escaping (Data) -> Void) {
        self.ipPacketCallback = callback
        
        guard let handle = handle else { return }
        
        let context = UnsafeMutableRawPointer(Unmanaged.passRetained(self).toOpaque())
        ipRxContext = context
        
        let cCallback: @convention(c) (UnsafePointer<UInt8>?, UInt32, UnsafeMutableRawPointer?) -> Void = {
            dataPtr, len, userPtr in
            guard let userPtr = userPtr, let dataPtr = dataPtr else { return }
            let client = Unmanaged<SoftEtherClient>.fromOpaque(userPtr).takeUnretainedValue()
            
            let data = Data(bytes: dataPtr, count: Int(len))
            
            DispatchQueue.main.async {
                client.ipPacketCallback?(data)
            }
        }
        
        softether_client_set_ip_rx_callback(handle, cCallback, context)
    }
    
    /// Send IP packet (for PacketTunnelProvider)
    public func sendIPPacket(_ packet: Data) -> Bool {
        guard let handle = handle else { return false }
        
        let result = packet.withUnsafeBytes { bufferPtr in
            guard let baseAddress = bufferPtr.baseAddress else { return Int32(-1) }
            return softether_client_send_ip_packet(
                handle,
                baseAddress.assumingMemoryBound(to: UInt8.self),
                UInt32(packet.count)
            )
        }
        
        return result > 0
    }
    
    /// Set reconnection enabled
    public func setReconnectEnabled(_ enabled: Bool) {
        guard let handle = handle else { return }
        _ = softether_client_set_reconnect_enabled(handle, enabled ? 1 : 0)
    }
    
    /// Set reconnection parameters
    public func setReconnectParams(maxAttempts: UInt32, initialDelay: UInt32, maxDelay: UInt32) {
        guard let handle = handle else { return }
        _ = softether_client_set_reconnect_params(handle, maxAttempts, initialDelay, maxDelay)
    }
    
    /// Set log level
    public func setLogLevel(_ level: LogLevel) {
        set_log_level(level)
    }
    
    /// Get version string
    public static func getVersion() -> String {
        guard let versionPtr = softether_client_version() else {
            return "Unknown"
        }
        defer { softether_string_free(versionPtr) }
        return String(cString: versionPtr)
    }
    
    // MARK: - Private helpers
    
    private func cleanupContexts() {
        if let ctx = stateContext {
            Unmanaged<SoftEtherClient>.fromOpaque(ctx).release()
        }
        if let ctx = eventContext {
            Unmanaged<SoftEtherClient>.fromOpaque(ctx).release()
        }
        if let ctx = ipRxContext {
            Unmanaged<SoftEtherClient>.fromOpaque(ctx).release()
        }
        if let ctx = logContext {
            Unmanaged<SoftEtherClient>.fromOpaque(ctx).release()
        }
    }
}

// MARK: - Utility Extensions

extension SoftEtherClient {
    /// Test connectivity to a server
    public static func testConnectivity(
        serverName: String,
        serverPort: UInt16 = 443,
        timeoutMs: UInt32 = 5000
    ) -> Bool {
        let result = softether_client_test_connectivity(serverName, serverPort, timeoutMs)
        return result == 0
    }
    
    /// Resolve DNS
    public static func resolveDNS(hostname: String, dnsServer: String? = nil) throws -> [String] {
        let dns = dnsServer ?? "8.8.8.8"
        
        guard let jsonPtr = softether_dns_resolve(hostname, dns) else {
            throw VPNError.operationFailed(message: "DNS resolution failed")
        }
        defer { softether_string_free(jsonPtr) }
        
        let jsonString = String(cString: jsonPtr)
        let jsonData = jsonString.data(using: .utf8)!
        
        struct DNSResult: Codable {
            let addresses: [String]
            let cname: String?
        }
        
        let decoder = JSONDecoder()
        let result = try decoder.decode(DNSResult.self, from: jsonData)
        return result.addresses
    }
}
