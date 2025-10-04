import Foundation

/**
 * Swift-friendly bridge to SoftEther VPN C API
 * 
 * This class provides a clean Swift interface to the underlying C functions.
 */
public class SoftEtherVPNBridge {
    
    // MARK: - Types
    
    public struct ConnectionParameters {
        public let serverName: String
        public let serverPort: Int32
        public let hubName: String
        public let username: String
        public let password: String
        
        public init(serverName: String, 
                   serverPort: Int32 = 443,
                   hubName: String,
                   username: String,
                   password: String) {
            self.serverName = serverName
            self.serverPort = serverPort
            self.hubName = hubName
            self.username = username
            self.password = password
        }
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
    
    // MARK: - Properties
    
    private var client: OpaquePointer?
    private var isInitialized = false
    private var isConnected = false
    
    // MARK: - Initialization
    
    public init() {}
    
    deinit {
        cleanup()
    }
    
    /**
     * Initialize SoftEther VPN library
     */
    public func initialize() throws {
        guard !isInitialized else { return }
        
        let result = softether_ios_init()
        guard result == 0 else {
            throw VPNError.initializationFailed(result)
        }
        
        isInitialized = true
    }
    
    /**
     * Set log level
     */
    public func setLogLevel(_ level: LogLevel) {
        softether_ios_set_log_level(level.rawValue)
    }
    
    /**
     * Create VPN client
     */
    public func createClient() throws {
        guard isInitialized else {
            throw VPNError.initializationFailed(-1)
        }
        
        guard client == nil else { return }
        
        client = softether_ios_create_client()
        guard client != nil else {
            throw VPNError.clientCreationFailed
        }
    }
    
    /**
     * Connect to VPN server
     */
    public func connect(parameters: ConnectionParameters) throws {
        guard let client = client else {
            throw VPNError.clientCreationFailed
        }
        
        guard !parameters.serverName.isEmpty,
              !parameters.hubName.isEmpty,
              !parameters.username.isEmpty else {
            throw VPNError.invalidParameters
        }
        
        let result = softether_ios_connect(
            client,
            parameters.serverName,
            parameters.serverPort,
            parameters.hubName,
            parameters.username,
            parameters.password
        )
        
        guard result == 0 else {
            throw VPNError.connectionFailed(result)
        }
        
        isConnected = true
    }
    
    /**
     * Disconnect from VPN server
     */
    public func disconnect() throws {
        guard let client = client else {
            throw VPNError.notConnected
        }
        
        let result = softether_ios_disconnect(client)
        guard result == 0 else {
            throw VPNError.disconnectionFailed(result)
        }
        
        isConnected = false
    }
    
    /**
     * Set packet flow (for Network Extension use)
     */
    public func setPacketFlow(_ flow: AnyObject,
                             writeCallback: @escaping IOSWritePacketsCallback,
                             readCallback: @escaping IOSReadPacketsCallback,
                             context: UnsafeMutableRawPointer?) {
        guard let client = client else { return }
        
        let flowPtr = Unmanaged.passUnretained(flow).toOpaque()
        softether_ios_set_packet_flow(client, flowPtr, writeCallback, readCallback, context)
    }
    
    /**
     * Receive packets from TUN device
     */
    public func receivePackets(_ packets: [Data]) {
        guard let client = client else { return }
        guard !packets.isEmpty else { return }
        
        var packetPtrs: [UnsafeRawPointer?] = []
        var packetSizes: [Int32] = []
        
        packets.forEach { packet in
            packet.withUnsafeBytes { buffer in
                if let baseAddress = buffer.baseAddress {
                    packetPtrs.append(baseAddress)
                    packetSizes.append(Int32(packet.count))
                }
            }
        }
        
        packetPtrs.withUnsafeBufferPointer { ptrBuffer in
            packetSizes.withUnsafeBufferPointer { sizeBuffer in
                softether_ios_receive_packets(
                    client,
                    ptrBuffer.baseAddress,
                    sizeBuffer.baseAddress,
                    Int32(packets.count)
                )
            }
        }
    }
    
    /**
     * Cleanup resources
     */
    public func cleanup() {
        if let client = client {
            if isConnected {
                _ = try? disconnect()
            }
            softether_ios_free_client(client)
            self.client = nil
        }
        
        if isInitialized {
            softether_ios_cleanup()
            isInitialized = false
        }
    }
    
    // MARK: - Status
    
    public var connectionStatus: Bool {
        return isConnected
    }
}

// MARK: - Async/Await Support (iOS 13+)

@available(iOS 13.0, *)
extension SoftEtherVPNBridge {
    
    /**
     * Connect to VPN server (async)
     */
    public func connect(parameters: ConnectionParameters) async throws {
        try await withCheckedThrowingContinuation { continuation in
            do {
                try connect(parameters: parameters)
                continuation.resume()
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
    
    /**
     * Disconnect from VPN server (async)
     */
    public func disconnect() async throws {
        try await withCheckedThrowingContinuation { continuation in
            do {
                try disconnect()
                continuation.resume()
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}
