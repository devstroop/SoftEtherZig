package com.softether.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.softether.vpn.bridge.*
import java.io.IOException
import java.net.InetAddress

/**
 * SoftEther VPN Service for Android
 * Integrates SoftEtherZig with Android VpnService
 */
class SoftEtherVpnService : VpnService() {
    
    private var client: SoftEtherClient? = null
    private var tunInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    
    companion object {
        const val TAG = "SoftEtherVpnService"
        const val ACTION_CONNECT = "com.softether.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.softether.vpn.DISCONNECT"
        const val ACTION_GET_STATUS = "com.softether.vpn.GET_STATUS"
        
        const val EXTRA_SERVER_NAME = "server_name"
        const val EXTRA_SERVER_PORT = "server_port"
        const val EXTRA_HUB_NAME = "hub_name"
        const val EXTRA_USERNAME = "username"
        const val EXTRA_PASSWORD = "password"
    }
    
    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "SoftEther VPN Service created")
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            return START_NOT_STICKY
        }
        
        when (intent.action) {
            ACTION_CONNECT -> handleConnect(intent)
            ACTION_DISCONNECT -> handleDisconnect()
            ACTION_GET_STATUS -> handleGetStatus()
        }
        
        return START_STICKY
    }
    
    override fun onDestroy() {
        Log.i(TAG, "SoftEther VPN Service destroyed")
        disconnect()
        super.onDestroy()
    }
    
    /**
     * Handle connect request
     */
    private fun handleConnect(intent: Intent) {
        if (isRunning) {
            Log.w(TAG, "VPN already running")
            return
        }
        
        try {
            // Extract configuration from intent
            val config = VPNConfig(
                serverName = intent.getStringExtra(EXTRA_SERVER_NAME) ?: "",
                serverPort = intent.getIntExtra(EXTRA_SERVER_PORT, 443),
                hubName = intent.getStringExtra(EXTRA_HUB_NAME) ?: "VPN",
                username = intent.getStringExtra(EXTRA_USERNAME) ?: "",
                password = intent.getStringExtra(EXTRA_PASSWORD) ?: ""
            )
            
            connect(config)
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VPN", e)
            sendBroadcast(Intent("com.softether.vpn.CONNECTION_FAILED").apply {
                putExtra("error", e.message)
            })
        }
    }
    
    /**
     * Handle disconnect request
     */
    private fun handleDisconnect() {
        disconnect()
    }
    
    /**
     * Handle get status request
     */
    private fun handleGetStatus() {
        val state = client?.getState() ?: ConnectionState.IDLE
        val isConnected = client?.isConnected() ?: false
        
        sendBroadcast(Intent("com.softether.vpn.STATUS_UPDATE").apply {
            putExtra("state", state.value)
            putExtra("connected", isConnected)
        })
    }
    
    /**
     * Connect to VPN
     */
    private fun connect(config: VPNConfig) {
        Log.i(TAG, "Connecting to ${config.serverName}:${config.serverPort}")
        
        // Create SoftEther client
        client = SoftEtherClient().apply {
            create(config)
            
            // Set callbacks
            setStateCallback { state ->
                handleStateChange(state)
            }
            
            setEventCallback { level, code, message ->
                handleEvent(level, code, message)
            }
            
            // Enable reconnection
            setReconnectEnabled(true)
            setReconnectParams(
                maxAttempts = 0, // Infinite
                initialDelay = 5,
                maxDelay = 60
            )
        }
        
        // Connect
        try {
            client?.connect()
            Log.i(TAG, "Connection initiated")
            
        } catch (e: VPNException) {
            Log.e(TAG, "Connection failed", e)
            sendBroadcast(Intent("com.softether.vpn.CONNECTION_FAILED").apply {
                putExtra("error", e.message)
            })
        }
    }
    
    /**
     * Disconnect from VPN
     */
    private fun disconnect() {
        Log.i(TAG, "Disconnecting")
        
        isRunning = false
        
        client?.disconnect()
        client?.destroy()
        client = null
        
        tunInterface?.close()
        tunInterface = null
        
        sendBroadcast(Intent("com.softether.vpn.DISCONNECTED"))
    }
    
    /**
     * Handle state change
     */
    private fun handleStateChange(state: ConnectionState) {
        Log.i(TAG, "State changed: $state")
        
        when (state) {
            ConnectionState.ESTABLISHED -> {
                // Connection established - setup tunnel
                setupTunnel()
            }
            
            ConnectionState.ERROR -> {
                // Connection error
                val error = client?.getLastError() ?: "Unknown error"
                Log.e(TAG, "Connection error: $error")
                
                sendBroadcast(Intent("com.softether.vpn.CONNECTION_FAILED").apply {
                    putExtra("error", error)
                })
            }
            
            else -> {
                // Other states - just broadcast
                sendBroadcast(Intent("com.softether.vpn.STATE_CHANGED").apply {
                    putExtra("state", state.value)
                })
            }
        }
    }
    
    /**
     * Handle event
     */
    private fun handleEvent(level: EventLevel, code: Int, message: String) {
        val levelStr = when (level) {
            EventLevel.INFO -> "INFO"
            EventLevel.WARNING -> "WARN"
            EventLevel.ERROR -> "ERROR"
        }
        
        Log.i(TAG, "[$levelStr] Code $code: $message")
        
        // Broadcast event to UI
        sendBroadcast(Intent("com.softether.vpn.EVENT").apply {
            putExtra("level", level.value)
            putExtra("code", code)
            putExtra("message", message)
        })
        
        // Handle specific error codes
        if (level == EventLevel.ERROR) {
            when (code) {
                401 -> { // Auth failed
                    sendBroadcast(Intent("com.softether.vpn.AUTH_FAILED"))
                }
                503 -> { // Network down
                    sendBroadcast(Intent("com.softether.vpn.NETWORK_DOWN"))
                }
                504 -> { // Server unreachable
                    sendBroadcast(Intent("com.softether.vpn.SERVER_UNREACHABLE"))
                }
            }
        }
    }
    
    /**
     * Setup VPN tunnel
     */
    private fun setupTunnel() {
        try {
            // Get network settings from SoftEther
            val settings = client?.getNetworkSettings()
                ?: throw IOException("Failed to get network settings")
            
            Log.i(TAG, "Network settings: $settings")
            
            // Build VPN interface
            val builder = Builder()
                .setSession("SoftEther VPN")
                .setMtu(1500)
            
            // Add addresses
            settings.assignedIPv4?.let { ipv4 ->
                builder.addAddress(ipv4, 24)
                Log.i(TAG, "Added address: $ipv4/24")
            }
            
            // Add routes
            builder.addRoute("0.0.0.0", 0)
            
            // Add DNS servers
            settings.dnsServers?.forEach { dns ->
                builder.addDnsServer(dns)
                Log.i(TAG, "Added DNS server: $dns")
            }
            
            // Configure apps (allow all by default)
            // builder.addAllowedApplication("com.example.vpnapp")
            
            // Establish VPN
            tunInterface = builder.establish()
            if (tunInterface == null) {
                throw IOException("Failed to establish VPN interface")
            }
            
            Log.i(TAG, "VPN interface established")
            
            // Pass tunnel FD to SoftEther client
            val fd = tunInterface!!.fd
            client?.setTunFd(fd)
            
            isRunning = true
            
            // Notify connection success
            sendBroadcast(Intent("com.softether.vpn.CONNECTED").apply {
                putExtra("ipv4", settings.assignedIPv4)
                settings.dnsServers?.let {
                    putExtra("dns_servers", it.toTypedArray())
                }
            })
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to setup tunnel", e)
            sendBroadcast(Intent("com.softether.vpn.CONNECTION_FAILED").apply {
                putExtra("error", e.message)
            })
            disconnect()
        }
    }
    
    /**
     * Protect socket from VPN routing
     */
    fun protectSocket(socket: Int): Boolean {
        return protect(socket)
    }
}
