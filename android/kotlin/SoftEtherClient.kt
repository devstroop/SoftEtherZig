package com.softether.vpn

import android.util.Log
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Connection state enum matching C API
 */
enum class ConnectionState(val value: Int) {
    IDLE(0),
    CONNECTING(1),
    ESTABLISHED(2),
    DISCONNECTING(3),
    ERROR(4);
    
    companion object {
        fun fromInt(value: Int) = values().firstOrNull { it.value == value } ?: ERROR
    }
}

/**
 * Event level enum
 */
enum class EventLevel(val value: Int) {
    INFO(0),
    WARNING(1),
    ERROR(2);
    
    companion object {
        fun fromInt(value: Int) = values().firstOrNull { it.value == value } ?: INFO
    }
}

/**
 * VPN Configuration data class
 */
data class VPNConfig(
    val serverName: String,
    val serverPort: Int = 443,
    val hubName: String,
    val username: String,
    val password: String,
    val useEncrypt: Boolean = true,
    val useCompress: Boolean = true,
    val ipVersion: String = "auto",
    val maxConnection: Int = 1
) {
    fun toJson(): String {
        return JSONObject().apply {
            put("server_name", serverName)
            put("server_port", serverPort)
            put("hub_name", hubName)
            put("username", username)
            put("password", password)
            put("use_encrypt", useEncrypt)
            put("use_compress", useCompress)
            put("ip_version", ipVersion)
            put("max_connection", maxConnection)
        }.toString()
    }
}

/**
 * Network settings from VPN server
 */
data class NetworkSettings(
    val assignedIPv4: String?,
    val subnetMask: String?,
    val gateway: String?,
    val dnsServers: List<String>?
)

/**
 * Connection statistics
 */
data class ConnectionStats(
    val bytesSent: Long,
    val bytesReceived: Long,
    val packetsSent: Long,
    val packetsReceived: Long,
    val connectedSeconds: Long,
    val currentRttMs: Int
)

/**
 * VPN Error exceptions
 */
sealed class VPNException(message: String) : Exception(message) {
    class NotInitialized : VPNException("Client not initialized")
    class InitializationFailed : VPNException("Failed to initialize client")
    class ConnectionFailed(val code: Int) : VPNException("Connection failed with code $code")
    class DisconnectionFailed : VPNException("Disconnection failed")
    class InvalidConfiguration : VPNException("Invalid configuration")
    class OperationFailed(message: String) : VPNException(message)
    class NotConnected : VPNException("Not connected to VPN")
}

/**
 * Main SoftEther Client class for Android
 */
class SoftEtherClient {
    
    private var handle: Long = 0
    private val initialized = AtomicBoolean(false)
    
    // Callbacks
    private var stateCallback: ((ConnectionState) -> Unit)? = null
    private var eventCallback: ((EventLevel, Int, String) -> Unit)? = null
    private var logCallback: ((Long, Int, String, String) -> Unit)? = null
    
    companion object {
        private const val TAG = "SoftEtherClient"
        
        init {
            try {
                System.loadLibrary("softether")
                Log.i(TAG, "SoftEther native library loaded")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Failed to load SoftEther library", e)
                throw e
            }
        }
        
        /**
         * Get library version
         */
        @JvmStatic
        external fun getVersion(): String
        
        /**
         * Test connectivity to a server
         */
        @JvmStatic
        external fun testConnectivity(
            serverName: String,
            serverPort: Int,
            timeoutMs: Int
        ): Boolean
        
        /**
         * Resolve DNS
         */
        @JvmStatic
        external fun resolveDNS(hostname: String, dnsServer: String): List<String>?
    }
    
    // Native methods
    private external fun nativeCreate(jsonConfig: String): Long
    private external fun nativeFree(handle: Long)
    private external fun nativeConnect(handle: Long): Int
    private external fun nativeDisconnect(handle: Long): Int
    private external fun nativeGetState(handle: Long): Int
    private external fun nativeIsConnected(handle: Long): Boolean
    private external fun nativeGetStats(handle: Long): LongArray?
    private external fun nativeGetNetworkSettings(handle: Long): String?
    private external fun nativeGetLastError(handle: Long): String
    private external fun nativeSetStateCallback(handle: Long)
    private external fun nativeSetEventCallback(handle: Long)
    private external fun nativeSetReconnectEnabled(handle: Long, enabled: Boolean)
    private external fun nativeSetReconnectParams(
        handle: Long,
        maxAttempts: Int,
        initialDelay: Int,
        maxDelay: Int
    )
    private external fun nativeSetLogLevel(level: Int)
    private external fun nativeGetTunFd(handle: Long): Int
    private external fun nativeSetTunFd(handle: Long, fd: Int): Int
    
    /**
     * Create client with configuration
     */
    fun create(config: VPNConfig) {
        if (initialized.get()) {
            throw VPNException.OperationFailed("Client already initialized")
        }
        
        val jsonConfig = config.toJson()
        handle = nativeCreate(jsonConfig)
        
        if (handle == 0L) {
            throw VPNException.InitializationFailed()
        }
        
        initialized.set(true)
        Log.i(TAG, "Client created successfully")
    }
    
    /**
     * Clean up resources
     */
    fun destroy() {
        if (!initialized.get()) return
        
        disconnect()
        
        if (handle != 0L) {
            nativeFree(handle)
            handle = 0
        }
        
        initialized.set(false)
        Log.i(TAG, "Client destroyed")
    }
    
    /**
     * Connect to VPN server
     */
    fun connect() {
        if (!initialized.get()) {
            throw VPNException.NotInitialized()
        }
        
        val result = nativeConnect(handle)
        if (result != 0) {
            val error = getLastError()
            Log.e(TAG, "Connection failed: $error")
            throw VPNException.ConnectionFailed(result)
        }
        
        Log.i(TAG, "Connection initiated")
    }
    
    /**
     * Disconnect from VPN server
     */
    fun disconnect() {
        if (!initialized.get()) return
        
        val result = nativeDisconnect(handle)
        if (result != 0) {
            Log.w(TAG, "Disconnection returned code $result")
        }
        
        Log.i(TAG, "Disconnected")
    }
    
    /**
     * Get current connection state
     */
    fun getState(): ConnectionState {
        if (!initialized.get()) {
            return ConnectionState.IDLE
        }
        
        val state = nativeGetState(handle)
        return ConnectionState.fromInt(state)
    }
    
    /**
     * Check if connected
     */
    fun isConnected(): Boolean {
        if (!initialized.get()) return false
        return nativeIsConnected(handle)
    }
    
    /**
     * Get connection statistics
     */
    fun getStats(): ConnectionStats {
        if (!initialized.get()) {
            throw VPNException.NotInitialized()
        }
        
        val stats = nativeGetStats(handle)
            ?: throw VPNException.OperationFailed("Failed to get statistics")
        
        return ConnectionStats(
            bytesSent = stats[0],
            bytesReceived = stats[1],
            packetsSent = stats[2],
            packetsReceived = stats[3],
            connectedSeconds = stats[4],
            currentRttMs = stats[5].toInt()
        )
    }
    
    /**
     * Get network settings from server
     */
    fun getNetworkSettings(): NetworkSettings {
        if (!initialized.get()) {
            throw VPNException.NotInitialized()
        }
        
        val jsonStr = nativeGetNetworkSettings(handle)
            ?: throw VPNException.OperationFailed("Failed to get network settings")
        
        val json = JSONObject(jsonStr)
        return NetworkSettings(
            assignedIPv4 = json.optString("assigned_ipv4", null),
            subnetMask = json.optString("subnet_mask", null),
            gateway = json.optString("gateway", null),
            dnsServers = json.optJSONArray("dns_servers")?.let { array ->
                (0 until array.length()).map { array.getString(it) }
            }
        )
    }
    
    /**
     * Get last error message
     */
    fun getLastError(): String {
        if (!initialized.get()) {
            return "Client not initialized"
        }
        return nativeGetLastError(handle)
    }
    
    /**
     * Set state change callback
     */
    fun setStateCallback(callback: (ConnectionState) -> Unit) {
        stateCallback = callback
        if (initialized.get()) {
            nativeSetStateCallback(handle)
        }
    }
    
    /**
     * Set event callback
     */
    fun setEventCallback(callback: (EventLevel, Int, String) -> Unit) {
        eventCallback = callback
        if (initialized.get()) {
            nativeSetEventCallback(handle)
        }
    }
    
    /**
     * Set reconnection enabled
     */
    fun setReconnectEnabled(enabled: Boolean) {
        if (initialized.get()) {
            nativeSetReconnectEnabled(handle, enabled)
        }
    }
    
    /**
     * Set reconnection parameters
     */
    fun setReconnectParams(maxAttempts: Int, initialDelay: Int, maxDelay: Int) {
        if (initialized.get()) {
            nativeSetReconnectParams(handle, maxAttempts, initialDelay, maxDelay)
        }
    }
    
    /**
     * Set log level
     */
    fun setLogLevel(level: Int) {
        nativeSetLogLevel(level)
    }
    
    /**
     * Get tunnel file descriptor (for VpnService)
     */
    fun getTunFd(): Int {
        if (!initialized.get()) {
            throw VPNException.NotInitialized()
        }
        return nativeGetTunFd(handle)
    }
    
    /**
     * Set tunnel file descriptor (for VpnService)
     */
    fun setTunFd(fd: Int) {
        if (!initialized.get()) {
            throw VPNException.NotInitialized()
        }
        val result = nativeSetTunFd(handle, fd)
        if (result != 0) {
            throw VPNException.OperationFailed("Failed to set tunnel FD")
        }
    }
    
    // Called from JNI
    @Suppress("unused")
    private fun onStateChanged(state: Int) {
        val connState = ConnectionState.fromInt(state)
        Log.d(TAG, "State changed: $connState")
        stateCallback?.invoke(connState)
    }
    
    // Called from JNI
    @Suppress("unused")
    private fun onEvent(level: Int, code: Int, message: String) {
        val eventLevel = EventLevel.fromInt(level)
        Log.d(TAG, "Event [$eventLevel] code=$code: $message")
        eventCallback?.invoke(eventLevel, code, message)
    }
    
    // Called from JNI
    @Suppress("unused")
    private fun onLog(timestamp: Long, level: Int, source: String, message: String) {
        logCallback?.invoke(timestamp, level, source, message)
    }
}
