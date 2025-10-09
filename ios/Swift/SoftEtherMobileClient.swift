//
//  SoftEtherMobileClient.swift
//  SoftEtherZig iOS Client
//
//  Swift wrapper for mobile FFI layer (libsoftether_mobile.a)
//

import Foundation
import NetworkExtension

// MARK: - Swift Types

/// VPN connection configuration
public struct VpnConfig {
    public let serverName: String
    public let serverPort: UInt16
    public let hubName: String
    public let username: String
    public let password: String
    
    // Connection options
    public var useEncrypt: Bool = true
    public var useCompress: Bool = true
    public var halfConnection: Bool = false
    public var maxConnection: UInt8 = 1
    
    // Performance tuning
    public var recvQueueSize: UInt64 = 128
    public var sendQueueSize: UInt64 = 128
    public var packetPoolSize: UInt64 = 256
    public var batchSize: UInt64 = 32
    
    public init(serverName: String, serverPort: UInt16, hubName: String, username: String, password: String) {
        self.serverName = serverName
        self.serverPort = serverPort
        self.hubName = hubName
        self.username = username
        self.password = password
    }
}

/// VPN connection status
public enum VpnStatus: Int32 {
    case disconnected = 0
    case connecting = 1
    case connected = 2
    case reconnecting = 3
    case error = 4
    
    var description: String {
        switch self {
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting"
        case .connected: return "Connected"
        case .reconnecting: return "Reconnecting"
        case .error: return "Error"
        }
    }
}

/// VPN statistics
public struct VpnStats {
    public let bytesSent: UInt64
    public let bytesReceived: UInt64
    public let packetsSent: UInt64
    public let packetsReceived: UInt64
    public let connectedDurationMs: UInt64
    public let queueDrops: UInt64
    public let errors: UInt64
    
    public var connectedDuration: TimeInterval {
        return TimeInterval(connectedDurationMs) / 1000.0
    }
}

/// Network configuration (from DHCP)
public struct NetworkInfo {
    public let ipAddress: String
    public let gateway: String
    public let netmask: String
    public let dnsServers: [String]
    public let mtu: UInt16
    
    init?(fromCStruct cInfo: MobileNetworkInfo) {
        // Convert IP address
        let ip = cInfo.ip_address
        self.ipAddress = "\(ip.0).\(ip.1).\(ip.2).\(ip.3)"
        
        // Convert gateway
        let gw = cInfo.gateway
        self.gateway = "\(gw.0).\(gw.1).\(gw.2).\(gw.3)"
        
        // Convert netmask
        let nm = cInfo.netmask
        self.netmask = "\(nm.0).\(nm.1).\(nm.2).\(nm.3)"
        
        // Convert DNS servers (filter out zeros)
        var dns: [String] = []
        let dnsArray = withUnsafeBytes(of: cInfo.dns_servers) { ptr in
            Array(ptr.bindMemory(to: (UInt8, UInt8, UInt8, UInt8).self))
        }
        for server in dnsArray {
            if server.0 == 0 && server.1 == 0 && server.2 == 0 && server.3 == 0 {
                break
            }
            dns.append("\(server.0).\(server.1).\(server.2).\(server.3)")
        }
        self.dnsServers = dns
        
        self.mtu = cInfo.mtu
    }
}

// MARK: - Main Client Class

/// Swift wrapper for mobile FFI VPN client
public class SoftEtherMobileClient {
    
    // MARK: - Properties
    
    private var handle: MobileVpnHandle?
    private let queue = DispatchQueue(label: "com.softether.mobile.client", qos: .userInitiated)
    
    // Callbacks
    private var statusCallback: ((VpnStatus) -> Void)?
    private var statsCallback: ((VpnStats) -> Void)?
    private var networkCallback: ((NetworkInfo) -> Void)?
    
    // Keep C callback contexts alive
    private var statusContext: UnsafeMutableRawPointer?
    private var statsContext: UnsafeMutableRawPointer?
    private var networkContext: UnsafeMutableRawPointer?
    
    // MARK: - Initialization
    
    public init() {
        // Initialize mobile VPN library
        let result = mobile_vpn_init()
        if result != 0 {
            NSLog("SoftEtherMobile: Warning - init returned \(result)")
        }
    }
    
    deinit {
        disconnect()
        cleanup()
    }
    
    // MARK: - Connection Management
    
    /// Create VPN connection with configuration
    public func create(config: VpnConfig) throws {
        try queue.sync {
            // Clean up existing connection
            if let existingHandle = handle {
                mobile_vpn_destroy(existingHandle)
                handle = nil
            }
            
            // Convert Swift config to C struct
            var cConfig = MobileVpnConfig()
            
            config.serverName.withCString { serverPtr in
                config.hubName.withCString { hubPtr in
                    config.username.withCString { userPtr in
                        config.password.withCString { passPtr in
                            cConfig.server = serverPtr
                            cConfig.port = config.serverPort
                            cConfig.hub = hubPtr
                            cConfig.username = userPtr
                            cConfig.password_hash = passPtr
                            cConfig.use_encrypt = config.useEncrypt
                            cConfig.use_compress = config.useCompress
                            cConfig.half_connection = config.halfConnection
                            cConfig.max_connection = config.maxConnection
                            cConfig.recv_queue_size = config.recvQueueSize
                            cConfig.send_queue_size = config.sendQueueSize
                            cConfig.packet_pool_size = config.packetPoolSize
                            cConfig.batch_size = config.batchSize
                            
                            // Create handle
                            handle = mobile_vpn_create(&cConfig)
                        }
                    }
                }
            }
            
            guard handle != nil else {
                throw VpnError.createFailed
            }
        }
    }
    
    /// Connect to VPN server
    public func connect() throws {
        try queue.sync {
            guard let handle = handle else {
                throw VpnError.notCreated
            }
            
            let result = mobile_vpn_connect(handle)
            if result != 0 {
                throw VpnError.connectFailed(code: result)
            }
        }
    }
    
    /// Disconnect from VPN server
    public func disconnect() {
        queue.sync {
            guard let handle = handle else { return }
            _ = mobile_vpn_disconnect(handle)
        }
    }
    
    /// Async connect with timeout
    public func connect(timeout: TimeInterval = 30.0) async throws {
        try connect()
        
        // Wait for connection to establish
        let startTime = Date()
        while Date().timeIntervalSince(startTime) < timeout {
            let status = getStatus()
            
            if status == .connected {
                return
            }
            
            if status == .error {
                throw VpnError.connectFailed(code: -1)
            }
            
            try await Task.sleep(nanoseconds: 100_000_000) // 100ms
        }
        
        throw VpnError.timeout
    }
    
    /// Async disconnect
    public func disconnect() async {
        disconnect()
        
        // Wait for disconnection
        for _ in 0..<50 {
            if getStatus() == .disconnected {
                return
            }
            try? await Task.sleep(nanoseconds: 100_000_000) // 100ms
        }
    }
    
    // MARK: - Status & Stats
    
    /// Get current VPN status
    public func getStatus() -> VpnStatus {
        return queue.sync {
            guard let handle = handle else { return .disconnected }
            let cStatus = mobile_vpn_get_status(handle)
            return VpnStatus(rawValue: cStatus.rawValue) ?? .disconnected
        }
    }
    
    /// Get VPN statistics
    public func getStats() throws -> VpnStats {
        return try queue.sync {
            guard let handle = handle else {
                throw VpnError.notCreated
            }
            
            var cStats = MobileVpnStats()
            let result = mobile_vpn_get_stats(handle, &cStats)
            
            if result != 0 {
                throw VpnError.operationFailed(code: result)
            }
            
            return VpnStats(
                bytesSent: cStats.bytes_sent,
                bytesReceived: cStats.bytes_received,
                packetsSent: cStats.packets_sent,
                packetsReceived: cStats.packets_received,
                connectedDurationMs: cStats.connected_duration_ms,
                queueDrops: cStats.queue_drops,
                errors: cStats.errors
            )
        }
    }
    
    /// Get network configuration
    public func getNetworkInfo() throws -> NetworkInfo {
        return try queue.sync {
            guard let handle = handle else {
                throw VpnError.notCreated
            }
            
            var cInfo = MobileNetworkInfo()
            let result = mobile_vpn_get_network_info(handle, &cInfo)
            
            if result != 0 {
                throw VpnError.operationFailed(code: result)
            }
            
            guard let info = NetworkInfo(fromCStruct: cInfo) else {
                throw VpnError.invalidNetworkInfo
            }
            
            return info
        }
    }
    
    /// Check if connected
    public func isConnected() -> Bool {
        guard let handle = handle else { return false }
        return mobile_vpn_is_connected(handle)
    }
    
    /// Get last error message
    public func getLastError() -> String? {
        guard let handle = handle else { return nil }
        if let errorPtr = mobile_vpn_get_error(handle) {
            return String(cString: errorPtr)
        }
        return nil
    }
    
    // MARK: - Packet I/O
    
    /// Read packet from VPN (async)
    public func readPacket(timeout: TimeInterval = 0.1) async throws -> Data {
        return try await withCheckedThrowingContinuation { continuation in
            queue.async { [weak self] in
                guard let self = self, let handle = self.handle else {
                    continuation.resume(throwing: VpnError.notCreated)
                    return
                }
                
                // Allocate buffer
                let bufferSize = 2048
                var buffer = [UInt8](repeating: 0, count: bufferSize)
                
                let timeoutMs = UInt32(timeout * 1000)
                let bytesRead = mobile_vpn_read_packet(handle, &buffer, UInt64(bufferSize), timeoutMs)
                
                if bytesRead < 0 {
                    continuation.resume(throwing: VpnError.readFailed(code: Int(bytesRead)))
                } else if bytesRead == 0 {
                    continuation.resume(throwing: VpnError.noData)
                } else {
                    let data = Data(buffer[..<Int(bytesRead)])
                    continuation.resume(returning: data)
                }
            }
        }
    }
    
    /// Write packet to VPN (async)
    public func writePacket(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [weak self] in
                guard let self = self, let handle = self.handle else {
                    continuation.resume(throwing: VpnError.notCreated)
                    return
                }
                
                let result = data.withUnsafeBytes { ptr in
                    mobile_vpn_write_packet(handle, ptr.baseAddress!, UInt64(data.count))
                }
                
                if result != 0 {
                    continuation.resume(throwing: VpnError.writeFailed(code: Int(result)))
                } else {
                    continuation.resume()
                }
            }
        }
    }
    
    /// Synchronous read packet (for blocking operations)
    public func readPacketSync(timeout: TimeInterval = 0.1) throws -> Data {
        return try queue.sync {
            guard let handle = handle else {
                throw VpnError.notCreated
            }
            
            let bufferSize = 2048
            var buffer = [UInt8](repeating: 0, count: bufferSize)
            
            let timeoutMs = UInt32(timeout * 1000)
            let bytesRead = mobile_vpn_read_packet(handle, &buffer, UInt64(bufferSize), timeoutMs)
            
            if bytesRead < 0 {
                throw VpnError.readFailed(code: Int(bytesRead))
            } else if bytesRead == 0 {
                throw VpnError.noData
            }
            
            return Data(buffer[..<Int(bytesRead)])
        }
    }
    
    /// Synchronous write packet
    public func writePacketSync(_ data: Data) throws {
        try queue.sync {
            guard let handle = handle else {
                throw VpnError.notCreated
            }
            
            let result = data.withUnsafeBytes { ptr in
                mobile_vpn_write_packet(handle, ptr.baseAddress!, UInt64(data.count))
            }
            
            if result != 0 {
                throw VpnError.writeFailed(code: Int(result))
            }
        }
    }
    
    // MARK: - Callbacks
    
    /// Set status change callback
    public func onStatusChange(_ callback: @escaping (VpnStatus) -> Void) {
        statusCallback = callback
        
        guard let handle = handle else { return }
        
        // Create context that captures self
        let context = UnsafeMutableRawPointer(Unmanaged.passRetained(self).toOpaque())
        statusContext = context
        
        // Set C callback
        mobile_vpn_set_status_callback(handle, { cStatus, userData in
            guard let userData = userData else { return }
            let client = Unmanaged<SoftEtherMobileClient>.fromOpaque(userData).takeUnretainedValue()
            
            if let status = VpnStatus(rawValue: cStatus.rawValue) {
                client.statusCallback?(status)
            }
        }, context)
    }
    
    /// Set stats update callback
    public func onStatsUpdate(_ callback: @escaping (VpnStats) -> Void) {
        statsCallback = callback
        
        guard let handle = handle else { return }
        
        let context = UnsafeMutableRawPointer(Unmanaged.passRetained(self).toOpaque())
        statsContext = context
        
        mobile_vpn_set_stats_callback(handle, { cStatsPtr, userData in
            guard let userData = userData, let cStatsPtr = cStatsPtr else { return }
            let client = Unmanaged<SoftEtherMobileClient>.fromOpaque(userData).takeUnretainedValue()
            
            let cStats = cStatsPtr.pointee
            let stats = VpnStats(
                bytesSent: cStats.bytes_sent,
                bytesReceived: cStats.bytes_received,
                packetsSent: cStats.packets_sent,
                packetsReceived: cStats.packets_received,
                connectedDurationMs: cStats.connected_duration_ms,
                queueDrops: cStats.queue_drops,
                errors: cStats.errors
            )
            
            client.statsCallback?(stats)
        }, context)
    }
    
    /// Set network info callback
    public func onNetworkInfo(_ callback: @escaping (NetworkInfo) -> Void) {
        networkCallback = callback
        
        guard let handle = handle else { return }
        
        let context = UnsafeMutableRawPointer(Unmanaged.passRetained(self).toOpaque())
        networkContext = context
        
        mobile_vpn_set_network_callback(handle, { cInfoPtr, userData in
            guard let userData = userData, let cInfoPtr = cInfoPtr else { return }
            let client = Unmanaged<SoftEtherMobileClient>.fromOpaque(userData).takeUnretainedValue()
            
            if let info = NetworkInfo(fromCStruct: cInfoPtr.pointee) {
                client.networkCallback?(info)
            }
        }, context)
    }
    
    // MARK: - Cleanup
    
    private func cleanup() {
        if let handle = handle {
            mobile_vpn_destroy(handle)
            self.handle = nil
        }
        
        // Release callback contexts
        if let ctx = statusContext {
            Unmanaged<SoftEtherMobileClient>.fromOpaque(ctx).release()
            statusContext = nil
        }
        if let ctx = statsContext {
            Unmanaged<SoftEtherMobileClient>.fromOpaque(ctx).release()
            statsContext = nil
        }
        if let ctx = networkContext {
            Unmanaged<SoftEtherMobileClient>.fromOpaque(ctx).release()
            networkContext = nil
        }
        
        mobile_vpn_cleanup()
    }
}

// MARK: - Error Types

public enum VpnError: Error, LocalizedError {
    case notCreated
    case createFailed
    case connectFailed(code: Int)
    case operationFailed(code: Int)
    case readFailed(code: Int)
    case writeFailed(code: Int)
    case noData
    case timeout
    case invalidNetworkInfo
    
    public var errorDescription: String? {
        switch self {
        case .notCreated:
            return "VPN client not created"
        case .createFailed:
            return "Failed to create VPN client"
        case .connectFailed(let code):
            return "Connection failed with code \(code)"
        case .operationFailed(let code):
            return "Operation failed with code \(code)"
        case .readFailed(let code):
            return "Read failed with code \(code)"
        case .writeFailed(let code):
            return "Write failed with code \(code)"
        case .noData:
            return "No data available"
        case .timeout:
            return "Operation timed out"
        case .invalidNetworkInfo:
            return "Invalid network information"
        }
    }
}

// MARK: - Version Info

extension SoftEtherMobileClient {
    /// Get library version
    public static var version: String {
        if let versionPtr = mobile_vpn_get_version() {
            return String(cString: versionPtr)
        }
        return "Unknown"
    }
    
    /// Get build info
    public static var buildInfo: String {
        if let buildPtr = mobile_vpn_get_build_info() {
            return String(cString: buildPtr)
        }
        return "Unknown"
    }
}
