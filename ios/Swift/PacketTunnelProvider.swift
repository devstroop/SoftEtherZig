import NetworkExtension
import os.log

/**
 * SoftEther VPN PacketTunnelProvider
 * 
 * This class implements the iOS Network Extension for SoftEther VPN.
 * It manages the VPN tunnel lifecycle and packet forwarding.
 */
class SoftEtherPacketTunnelProvider: NEPacketTunnelProvider {
    
    private let logger = OSLog(subsystem: "com.softether.vpn", category: "PacketTunnel")
    
    private var vpnClient: OpaquePointer?
    private var isConnected = false
    private var packetFlow: NEPacketTunnelFlow?
    
    // Connection parameters (set by container app via IPC)
    private var serverName: String = ""
    private var serverPort: Int32 = 443
    private var hubName: String = ""
    private var username: String = ""
    private var password: String = ""
    
    /**
     * Start VPN tunnel
     */
    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        os_log("Starting SoftEther VPN tunnel", log: logger, type: .info)
        
        // Extract connection parameters from options or protocol configuration
        if let options = options {
            serverName = options["ServerName"] as? String ?? ""
            serverPort = options["ServerPort"] as? Int32 ?? 443
            hubName = options["HubName"] as? String ?? ""
            username = options["Username"] as? String ?? ""
            password = options["Password"] as? String ?? ""
        } else if let proto = protocolConfiguration as? NETunnelProviderProtocol {
            serverName = proto.serverAddress ?? ""
            hubName = (proto.providerConfiguration?["HubName"] as? String) ?? ""
            username = proto.username ?? ""
            password = proto.passwordReference != nil ? 
                       loadPasswordFromKeychain(proto.passwordReference!) : ""
        }
        
        guard !serverName.isEmpty && !username.isEmpty else {
            os_log("Missing connection parameters", log: logger, type: .error)
            completionHandler(NEVPNError(.configurationInvalid))
            return
        }
        
        // Initialize SoftEther VPN
        let initResult = softether_ios_init()
        guard initResult == 0 else {
            os_log("Failed to initialize SoftEther: %d", log: logger, type: .error, initResult)
            completionHandler(NEVPNError(.connectionFailed))
            return
        }
        
        // Set log level
        softether_ios_set_log_level(3) // INFO level
        
        // Create VPN client
        vpnClient = softether_ios_create_client()
        guard vpnClient != nil else {
            os_log("Failed to create VPN client", log: logger, type: .error)
            completionHandler(NEVPNError(.connectionFailed))
            return
        }
        
        // Configure network settings first
        configureNetworkSettings { [weak self] error in
            guard let self = self else { return }
            
            if let error = error {
                os_log("Failed to configure network: %{public}@", 
                      log: self.logger, type: .error, error.localizedDescription)
                completionHandler(error)
                return
            }
            
            // Connect to VPN server
            let connectResult = softether_ios_connect(
                self.vpnClient,
                self.serverName,
                self.serverPort,
                self.hubName,
                self.username,
                self.password
            )
            
            if connectResult != 0 {
                os_log("Failed to connect: %d", log: self.logger, type: .error, connectResult)
                completionHandler(NEVPNError(.connectionFailed))
                return
            }
            
            // Set up packet flow callbacks
            self.packetFlow = self.packetFlow
            self.setupPacketFlow()
            
            self.isConnected = true
            os_log("VPN tunnel started successfully", log: self.logger, type: .info)
            completionHandler(nil)
        }
    }
    
    /**
     * Stop VPN tunnel
     */
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("Stopping VPN tunnel, reason: %d", log: logger, type: .info, reason.rawValue)
        
        isConnected = false
        
        // Disconnect VPN
        if let client = vpnClient {
            softether_ios_disconnect(client)
            softether_ios_free_client(client)
            vpnClient = nil
        }
        
        // Cleanup
        softether_ios_cleanup()
        
        os_log("VPN tunnel stopped", log: logger, type: .info)
        completionHandler()
    }
    
    /**
     * Handle app message (IPC from container app)
     */
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // Parse message and update connection parameters if needed
        if let message = try? JSONDecoder().decode([String: String].self, from: messageData) {
            os_log("Received app message: %{public}@", log: logger, type: .debug, message.description)
            
            // Update parameters
            if let server = message["ServerName"] { serverName = server }
            if let hub = message["HubName"] { hubName = hub }
            if let user = message["Username"] { username = user }
            if let pass = message["Password"] { password = pass }
        }
        
        completionHandler?(nil)
    }
    
    /**
     * Configure network settings
     */
    private func configureNetworkSettings(completionHandler: @escaping (Error?) -> Void) {
        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: serverName)
        
        // IPv4 settings
        let ipv4Settings = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        networkSettings.ipv4Settings = ipv4Settings
        
        // DNS settings
        let dnsSettings = NEDNSSettings(servers: ["8.8.8.8", "8.8.4.4"])
        networkSettings.dnsSettings = dnsSettings
        
        // MTU
        networkSettings.mtu = 1500
        
        os_log("Applying network settings", log: logger, type: .debug)
        setTunnelNetworkSettings(networkSettings, completionHandler: completionHandler)
    }
    
    /**
     * Setup packet flow between iOS and VPN
     */
    private func setupPacketFlow() {
        guard let client = vpnClient else { return }
        
        // Create context for callbacks
        let flowContext = Unmanaged.passUnretained(self).toOpaque()
        
        // Set packet flow in native code
        softether_ios_set_packet_flow(
            client,
            Unmanaged.passUnretained(packetFlow!).toOpaque(),
            { flow, packets, sizes, count in
                // Write packets callback (C → Swift)
                guard let flow = flow else { return }
                let packetFlow = Unmanaged<NEPacketTunnelFlow>.fromOpaque(flow).takeUnretainedValue()
                
                var swiftPackets: [Data] = []
                for i in 0..<count {
                    if let packet = packets?[i], sizes?[i] ?? 0 > 0 {
                        let data = Data(bytes: packet, count: Int(sizes![i]))
                        swiftPackets.append(data)
                    }
                }
                
                if !swiftPackets.isEmpty {
                    packetFlow.writePackets(swiftPackets, withProtocols: Array(repeating: NSNumber(value: AF_INET), count: swiftPackets.count))
                }
            },
            { flow, context in
                // Read packets callback (C → Swift)
                guard let context = context else { return }
                let provider = Unmanaged<SoftEtherPacketTunnelProvider>.fromOpaque(context).takeUnretainedValue()
                provider.readPacketsFromTUN()
            },
            flowContext
        )
        
        // Start reading packets
        readPacketsFromTUN()
    }
    
    /**
     * Read packets from TUN device
     */
    private func readPacketsFromTUN() {
        guard isConnected, let client = vpnClient else { return }
        
        packetFlow?.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }
            
            if !packets.isEmpty {
                // Convert Swift Data to C pointers
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
                
                // Send to native code
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
            
            // Continue reading (this creates the packet read loop)
            self.readPacketsFromTUN()
        }
    }
    
    /**
     * Load password from keychain
     */
    private func loadPasswordFromKeychain(_ reference: Data) -> String {
        // Implement keychain loading
        // For now, return empty string
        return ""
    }
    
    /**
     * Sleep (override to prevent iOS from sleeping the tunnel)
     */
    override func sleep(completionHandler: @escaping () -> Void) {
        os_log("Network extension entering sleep mode", log: logger, type: .info)
        completionHandler()
    }
    
    /**
     * Wake (override to handle wake from sleep)
     */
    override func wake() {
        os_log("Network extension waking up", log: logger, type: .info)
    }
}
