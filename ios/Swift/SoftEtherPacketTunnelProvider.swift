//
//  SoftEtherPacketTunnelProvider.swift
//  Packet Tunnel Provider
//
//  NetworkExtension integration for SoftEtherZig
//

import NetworkExtension
import Foundation

class SoftEtherPacketTunnelProvider: NEPacketTunnelProvider {
    
    private var client: SoftEtherClient?
    private var isRunning = false
    private var pendingCompletion: ((Error?) -> Void)?
    
    // MARK: - Tunnel Lifecycle
    
    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        NSLog("SoftEther: Starting tunnel...")
        
        self.pendingCompletion = completionHandler
        
        // Extract configuration from options or protocol configuration
        guard let config = extractConfiguration(from: options) else {
            NSLog("SoftEther: Failed to extract configuration")
            completionHandler(NSError(domain: "SoftEtherVPN", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Invalid configuration"
            ]))
            return
        }
        
        // Create SoftEther client
        do {
            client = SoftEtherClient()
            try client?.create(config: config)
            NSLog("SoftEther: Client created successfully")
        } catch {
            NSLog("SoftEther: Failed to create client: \(error)")
            completionHandler(error)
            return
        }
        
        // Set up callbacks
        setupCallbacks()
        
        // Configure reconnection
        client?.setReconnectEnabled(true)
        client?.setReconnectParams(maxAttempts: 0, initialDelay: 5, maxDelay: 60)
        
        // Connect to VPN
        do {
            try client?.connect()
            NSLog("SoftEther: Connection initiated")
        } catch {
            NSLog("SoftEther: Failed to connect: \(error)")
            completionHandler(error)
            return
        }
        
        // Note: completionHandler will be called in state callback when connected
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        NSLog("SoftEther: Stopping tunnel (reason: \(reason.rawValue))")
        
        isRunning = false
        client?.disconnect()
        client = nil
        
        completionHandler()
    }
    
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // Handle messages from the main app
        guard let message = try? JSONDecoder().decode([String: String].self, from: messageData) else {
            completionHandler?(nil)
            return
        }
        
        NSLog("SoftEther: Received app message: \(message)")
        
        // Handle different message types
        switch message["action"] {
        case "get_stats":
            if let stats = try? client?.getStats() {
                let response: [String: Any] = [
                    "bytes_sent": stats.bytesSent,
                    "bytes_received": stats.bytesReceived,
                    "connected_seconds": stats.connectedSeconds,
                    "rtt_ms": stats.currentRttMs
                ]
                if let responseData = try? JSONSerialization.data(withJSONObject: response) {
                    completionHandler?(responseData)
                    return
                }
            }
            
        case "get_state":
            let state = client?.getState() ?? .idle
            let response = ["state": "\(state.rawValue)"]
            if let responseData = try? JSONEncoder().encode(response) {
                completionHandler?(responseData)
                return
            }
            
        default:
            break
        }
        
        completionHandler?(nil)
    }
    
    // MARK: - Configuration
    
    private func extractConfiguration(from options: [String: NSObject]?) -> VPNConfig? {
        // Try to get config from options first
        if let configStr = options?["config"] as? String,
           let configData = configStr.data(using: .utf8),
           let config = try? JSONDecoder().decode(VPNConfig.self, from: configData) {
            return config
        }
        
        // Fall back to protocol configuration
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let serverAddress = proto.serverAddress else {
            return nil
        }
        
        // Extract from providerConfiguration dictionary
        let providerConfig = proto.providerConfiguration ?? [:]
        
        let serverName = serverAddress
        let serverPort = (providerConfig["server_port"] as? NSNumber)?.uint16Value ?? 443
        let hubName = providerConfig["hub_name"] as? String ?? "VPN"
        let username = providerConfig["username"] as? String ?? ""
        let password = providerConfig["password"] as? String ?? ""
        
        return VPNConfig(
            serverName: serverName,
            serverPort: serverPort,
            hubName: hubName,
            username: username,
            password: password
        )
    }
    
    // MARK: - Callbacks Setup
    
    private func setupCallbacks() {
        // State callback
        client?.setStateCallback { [weak self] state in
            self?.handleStateChange(state)
        }
        
        // Event callback (for logging and errors)
        client?.setEventCallback { [weak self] level, code, message in
            self?.handleEvent(level: level, code: code, message: message)
        }
        
        // IP packet callback
        client?.setIPPacketCallback { [weak self] packet in
            self?.handleIncomingPacket(packet)
        }
        
        // Start reading from tunnel
        readPacketsFromTunnel()
    }
    
    // MARK: - State Management
    
    private func handleStateChange(_ state: ConnectionState) {
        NSLog("SoftEther: State changed to \(state)")
        
        switch state {
        case .established:
            // Connection established - configure network settings
            configureNetworkSettings()
            
        case .error:
            // Connection error
            if let completion = pendingCompletion {
                let error = NSError(domain: "SoftEtherVPN", code: 2, userInfo: [
                    NSLocalizedDescriptionKey: client?.getLastError() ?? "Connection failed"
                ])
                completion(error)
                pendingCompletion = nil
            }
            
        default:
            break
        }
    }
    
    private func handleEvent(level: EventLevel, code: Int, message: String) {
        let levelStr = ["INFO", "WARN", "ERROR"][level.rawValue]
        NSLog("SoftEther: [\(levelStr)] Code \(code): \(message)")
        
        // Handle specific error codes
        if level == .error {
            switch code {
            case 401: // Auth failed
                cancelTunnelWithError(NSError(domain: "SoftEtherVPN", code: 401, userInfo: [
                    NSLocalizedDescriptionKey: "Authentication failed"
                ]))
                
            case 503: // Network down
                // Will attempt reconnection automatically if enabled
                break
                
            case 504: // Server unreachable
                // Will attempt reconnection automatically if enabled
                break
                
            default:
                break
            }
        }
    }
    
    // MARK: - Network Settings
    
    private func configureNetworkSettings() {
        guard let client = client else { return }
        
        do {
            let settings = try client.getNetworkSettings()
            
            // Create tunnel network settings
            let tunnelSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: settings.assignedIPv4 ?? "10.0.0.1")
            
            // IPv4 settings
            if let ipv4Address = settings.assignedIPv4,
               let subnetMask = settings.subnetMask {
                let ipv4Settings = NEIPv4Settings(addresses: [ipv4Address], subnetMasks: [subnetMask])
                ipv4Settings.includedRoutes = [NEIPv4Route.default()]
                tunnelSettings.ipv4Settings = ipv4Settings
            }
            
            // DNS settings
            if let dnsServers = settings.dnsServers, !dnsServers.isEmpty {
                let dnsSettings = NEDNSSettings(servers: dnsServers)
                tunnelSettings.dnsSettings = dnsSettings
            }
            
            // Apply settings
            setTunnelNetworkSettings(tunnelSettings) { [weak self] error in
                if let error = error {
                    NSLog("SoftEther: Failed to apply network settings: \(error)")
                    self?.cancelTunnelWithError(error)
                    return
                }
                
                NSLog("SoftEther: Network settings applied successfully")
                self?.isRunning = true
                
                // Call pending completion handler
                if let completion = self?.pendingCompletion {
                    completion(nil)
                    self?.pendingCompletion = nil
                }
            }
            
        } catch {
            NSLog("SoftEther: Failed to get network settings: \(error)")
            cancelTunnelWithError(error)
        }
    }
    
    // MARK: - Packet I/O
    
    private func readPacketsFromTunnel() {
        guard isRunning else { return }
        
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.isRunning else { return }
            
            // Send each packet to SoftEther
            for packet in packets {
                let sent = self.client?.sendIPPacket(packet) ?? false
                if !sent {
                    NSLog("SoftEther: Warning - failed to send packet")
                }
            }
            
            // Continue reading
            self.readPacketsFromTunnel()
        }
    }
    
    private func handleIncomingPacket(_ packet: Data) {
        guard isRunning else { return }
        
        // Write packet to tunnel
        packetFlow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
    }
}

// MARK: - Extensions

extension NEProviderStopReason {
    var description: String {
        switch self {
        case .none: return "None"
        case .userInitiated: return "User initiated"
        case .providerFailed: return "Provider failed"
        case .noNetworkAvailable: return "No network available"
        case .unrecoverableNetworkChange: return "Unrecoverable network change"
        case .providerDisabled: return "Provider disabled"
        case .authenticationCanceled: return "Authentication canceled"
        case .configurationFailed: return "Configuration failed"
        case .idleTimeout: return "Idle timeout"
        case .configurationDisabled: return "Configuration disabled"
        case .configurationRemoved: return "Configuration removed"
        case .superceded: return "Superceded"
        case .userLogout: return "User logout"
        case .userSwitch: return "User switch"
        case .connectionFailed: return "Connection failed"
        case .sleep: return "Sleep"
        case .appUpdate: return "App update"
        @unknown default: return "Unknown"
        }
    }
}
