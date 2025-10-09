package com.softether.mobile

import kotlinx.coroutines.*
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * SoftEther Mobile Client - Kotlin Bridge for Android
 * 
 * Type-safe Kotlin API wrapping the mobile FFI (libsoftether_mobile.so)
 * 
 * Architecture:
 *   Android VpnService (Kotlin) → SoftEtherMobileClient (this file) →
 *   mobile_jni.c (JNI wrapper) → libsoftether_mobile.so (mobile FFI) →
 *   Zig Packet Adapter
 */

// ============================================================================
// Data Classes
// ============================================================================

/**
 * VPN connection configuration
 */
data class VpnConfig(
    val serverName: String,
    val serverPort: Int = 443,
    val hubName: String = "VPN",
    val username: String,
    val password: String,
    
    // Connection options
    val useEncrypt: Boolean = true,
    val useCompress: Boolean = true,
    val halfConnection: Boolean = false,
    val maxConnection: Int = 1,
    
    // Performance tuning
    val recvQueueSize: Long = 128,
    val sendQueueSize: Long = 128,
    val packetPoolSize: Long = 256,
    val batchSize: Long = 32
)

/**
 * VPN connection status
 */
enum class VpnStatus(val value: Int) {
    DISCONNECTED(0),
    CONNECTING(1),
    CONNECTED(2),
    RECONNECTING(3),
    ERROR(4);
    
    companion object {
        fun fromInt(value: Int) = values().firstOrNull { it.value == value } ?: DISCONNECTED
    }
}

/**
 * VPN statistics
 */
data class VpnStats(
    val bytesSent: Long,
    val bytesReceived: Long,
    val packetsSent: Long,
    val packetsReceived: Long,
    val connectedDurationMs: Long,
    val queueDrops: Long,
    val errors: Long
) {
    val connectedDuration: Double
        get() = connectedDurationMs / 1000.0
}

/**
 * Network configuration (from DHCP)
 */
data class NetworkInfo(
    val ipAddress: String,
    val gateway: String,
    val netmask: String,
    val dnsServers: Array<String>,
    val mtu: Int
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        
        other as NetworkInfo
        
        if (ipAddress != other.ipAddress) return false
        if (gateway != other.gateway) return false
        if (netmask != other.netmask) return false
        if (!dnsServers.contentEquals(other.dnsServers)) return false
        if (mtu != other.mtu) return false
        
        return true
    }
    
    override fun hashCode(): Int {
        var result = ipAddress.hashCode()
        result = 31 * result + gateway.hashCode()
        result = 31 * result + netmask.hashCode()
        result = 31 * result + dnsServers.contentHashCode()
        result = 31 * result + mtu
        return result
    }
}

/**
 * VPN exception types
 */
sealed class VpnException(message: String) : Exception(message) {
    class NotCreated : VpnException("VPN client not created")
    class CreateFailed : VpnException("Failed to create VPN client")
    class ConnectFailed(code: Int) : VpnException("Connection failed with code $code")
    class OperationFailed(code: Int) : VpnException("Operation failed with code $code")
    class ReadFailed(code: Int) : VpnException("Read failed with code $code")
    class WriteFailed(code: Int) : VpnException("Write failed with code $code")
    class NoData : VpnException("No data available")
    class Timeout : VpnException("Operation timed out")
    class InvalidNetworkInfo : VpnException("Invalid network information")
}

// ============================================================================
// Main Client Class
// ============================================================================

/**
 * SoftEther Mobile VPN Client
 * 
 * Thread-safe Kotlin wrapper for mobile FFI layer
 */
class SoftEtherMobileClient {
    
    // Native handle
    private val handle = AtomicLong(0)
    
    // State tracking
    private val isInitialized = AtomicBoolean(false)
    
    // Coroutine scope for async operations
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    // Callbacks
    private var statusCallback: ((VpnStatus) -> Unit)? = null
    private var statsCallback: ((VpnStats) -> Unit)? = null
    private var networkCallback: ((NetworkInfo) -> Unit)? = null
    
    companion object {
        private const val TAG = "SoftEtherMobile"
        
        // Load native library
        init {
            try {
                System.loadLibrary("softether_mobile")
            } catch (e: UnsatisfiedLinkError) {
                android.util.Log.e(TAG, "Failed to load native library", e)
                throw e
            }
        }
        
        // Native library info
        external fun nativeGetVersion(): String
        external fun nativeGetBuildInfo(): String
        
        // Library initialization
        private external fun nativeInit(): Int
        private external fun nativeCleanup()
        
        // Initialize library once
        private val initialized = AtomicBoolean(false)
        
        fun ensureInitialized() {
            if (initialized.compareAndSet(false, true)) {
                val result = nativeInit()
                if (result != 0) {
                    throw VpnException.CreateFailed()
                }
            }
        }
        
        /**
         * Get library version
         */
        val version: String
            get() = try {
                nativeGetVersion()
            } catch (e: Exception) {
                "Unknown"
            }
        
        /**
         * Get build info
         */
        val buildInfo: String
            get() = try {
                nativeGetBuildInfo()
            } catch (e: Exception) {
                "Unknown"
            }
    }
    
    // ========================================================================
    // Native Methods
    // ========================================================================
    
    private external fun nativeCreate(
        server: String, port: Int, hub: String, username: String, passwordHash: String,
        useEncrypt: Boolean, useCompress: Boolean, halfConnection: Boolean, maxConnection: Int,
        recvQueueSize: Long, sendQueueSize: Long, packetPoolSize: Long, batchSize: Long
    ): Long
    
    private external fun nativeDestroy(handle: Long)
    private external fun nativeConnect(handle: Long): Int
    private external fun nativeDisconnect(handle: Long): Int
    private external fun nativeGetStatus(handle: Long): Int
    private external fun nativeIsConnected(handle: Long): Boolean
    private external fun nativeReadPacket(handle: Long, buffer: ByteArray, timeoutMs: Int): Int
    private external fun nativeWritePacket(handle: Long, data: ByteArray, length: Int): Int
    private external fun nativeGetStats(handle: Long): VpnStats?
    private external fun nativeGetNetworkInfo(handle: Long): NetworkInfo?
    private external fun nativeGetError(handle: Long): String?
    
    // ========================================================================
    // Public API
    // ========================================================================
    
    /**
     * Create VPN connection with configuration
     */
    fun create(config: VpnConfig) {
        ensureInitialized()
        
        // Clean up existing connection
        destroy()
        
        val h = nativeCreate(
            config.serverName, config.serverPort, config.hubName, 
            config.username, config.password,
            config.useEncrypt, config.useCompress, config.halfConnection, config.maxConnection,
            config.recvQueueSize, config.sendQueueSize, config.packetPoolSize, config.batchSize
        )
        
        if (h == 0L) {
            throw VpnException.CreateFailed()
        }
        
        handle.set(h)
        isInitialized.set(true)
        
        android.util.Log.i(TAG, "VPN client created: handle=$h")
    }
    
    /**
     * Connect to VPN server (blocking)
     */
    fun connect() {
        val h = handle.get()
        if (h == 0L) throw VpnException.NotCreated()
        
        val result = nativeConnect(h)
        if (result != 0) {
            throw VpnException.ConnectFailed(result)
        }
        
        android.util.Log.i(TAG, "VPN connection initiated")
    }
    
    /**
     * Connect to VPN server (async with timeout)
     */
    suspend fun connectAsync(timeoutMs: Long = 30000): Unit = withContext(Dispatchers.IO) {
        connect()
        
        // Wait for connection to establish
        val startTime = System.currentTimeMillis()
        while (System.currentTimeMillis() - startTime < timeoutMs) {
            val status = getStatus()
            
            when (status) {
                VpnStatus.CONNECTED -> {
                    android.util.Log.i(TAG, "VPN connected")
                    return@withContext
                }
                VpnStatus.ERROR -> {
                    throw VpnException.ConnectFailed(-1)
                }
                else -> {
                    delay(100) // Check every 100ms
                }
            }
        }
        
        throw VpnException.Timeout()
    }
    
    /**
     * Disconnect from VPN server (blocking)
     */
    fun disconnect() {
        val h = handle.get()
        if (h == 0L) return
        
        val result = nativeDisconnect(h)
        if (result != 0) {
            android.util.Log.w(TAG, "Disconnect returned: $result")
        }
        
        android.util.Log.i(TAG, "VPN disconnected")
    }
    
    /**
     * Disconnect from VPN server (async)
     */
    suspend fun disconnectAsync(): Unit = withContext(Dispatchers.IO) {
        disconnect()
        
        // Wait for disconnection
        repeat(50) {
            if (getStatus() == VpnStatus.DISCONNECTED) {
                return@withContext
            }
            delay(100)
        }
    }
    
    /**
     * Get current VPN status
     */
    fun getStatus(): VpnStatus {
        val h = handle.get()
        if (h == 0L) return VpnStatus.DISCONNECTED
        
        val statusInt = nativeGetStatus(h)
        return VpnStatus.fromInt(statusInt)
    }
    
    /**
     * Check if connected
     */
    fun isConnected(): Boolean {
        val h = handle.get()
        if (h == 0L) return false
        return nativeIsConnected(h)
    }
    
    /**
     * Get VPN statistics
     */
    fun getStats(): VpnStats {
        val h = handle.get()
        if (h == 0L) throw VpnException.NotCreated()
        
        return nativeGetStats(h) ?: throw VpnException.OperationFailed(-1)
    }
    
    /**
     * Get network configuration
     */
    fun getNetworkInfo(): NetworkInfo {
        val h = handle.get()
        if (h == 0L) throw VpnException.NotCreated()
        
        return nativeGetNetworkInfo(h) ?: throw VpnException.InvalidNetworkInfo()
    }
    
    /**
     * Get last error message
     */
    fun getLastError(): String? {
        val h = handle.get()
        if (h == 0L) return null
        return nativeGetError(h)
    }
    
    // ========================================================================
    // Packet I/O
    // ========================================================================
    
    /**
     * Read packet from VPN (blocking)
     * 
     * @param timeoutMs Timeout in milliseconds (0 = non-blocking)
     * @return Packet data as ByteArray
     * @throws VpnException.NoData if no packet available
     * @throws VpnException.ReadFailed on error
     */
    fun readPacket(timeoutMs: Int = 100): ByteArray {
        val h = handle.get()
        if (h == 0L) throw VpnException.NotCreated()
        
        val buffer = ByteArray(2048)
        val bytesRead = nativeReadPacket(h, buffer, timeoutMs)
        
        return when {
            bytesRead < 0 -> throw VpnException.ReadFailed(bytesRead)
            bytesRead == 0 -> throw VpnException.NoData()
            else -> buffer.copyOf(bytesRead)
        }
    }
    
    /**
     * Read packet from VPN (async)
     */
    suspend fun readPacketAsync(timeoutMs: Int = 100): ByteArray = withContext(Dispatchers.IO) {
        readPacket(timeoutMs)
    }
    
    /**
     * Write packet to VPN (blocking)
     * 
     * @param data Packet data to write
     * @throws VpnException.WriteFailed on error
     */
    fun writePacket(data: ByteArray) {
        val h = handle.get()
        if (h == 0L) throw VpnException.NotCreated()
        
        val result = nativeWritePacket(h, data, data.size)
        if (result != 0) {
            throw VpnException.WriteFailed(result)
        }
    }
    
    /**
     * Write packet to VPN (async)
     */
    suspend fun writePacketAsync(data: ByteArray): Unit = withContext(Dispatchers.IO) {
        writePacket(data)
    }
    
    // ========================================================================
    // Callbacks (Polling-based for now)
    // ========================================================================
    
    /**
     * Set status change callback
     * 
     * Note: Currently uses polling. Native callback support can be added later.
     */
    fun setStatusCallback(callback: (VpnStatus) -> Unit) {
        statusCallback = callback
        
        // Start polling for status changes
        scope.launch {
            var lastStatus = VpnStatus.DISCONNECTED
            while (isInitialized.get()) {
                try {
                    val currentStatus = getStatus()
                    if (currentStatus != lastStatus) {
                        callback(currentStatus)
                        lastStatus = currentStatus
                    }
                } catch (e: Exception) {
                    android.util.Log.e(TAG, "Error in status callback", e)
                }
                delay(500) // Poll every 500ms
            }
        }
    }
    
    /**
     * Set stats update callback
     */
    fun setStatsCallback(callback: (VpnStats) -> Unit) {
        statsCallback = callback
        
        // Start polling for stats
        scope.launch {
            while (isInitialized.get()) {
                try {
                    if (isConnected()) {
                        val stats = getStats()
                        callback(stats)
                    }
                } catch (e: Exception) {
                    android.util.Log.e(TAG, "Error in stats callback", e)
                }
                delay(5000) // Poll every 5 seconds
            }
        }
    }
    
    /**
     * Set network info callback
     */
    fun setNetworkCallback(callback: (NetworkInfo) -> Unit) {
        networkCallback = callback
        
        // Start polling for network info
        scope.launch {
            var lastInfo: NetworkInfo? = null
            while (isInitialized.get()) {
                try {
                    if (isConnected()) {
                        val info = getNetworkInfo()
                        if (info != lastInfo) {
                            callback(info)
                            lastInfo = info
                        }
                    }
                } catch (e: Exception) {
                    // Network info might not be available yet
                }
                delay(2000) // Poll every 2 seconds
            }
        }
    }
    
    // ========================================================================
    // Cleanup
    // ========================================================================
    
    /**
     * Destroy VPN client and free resources
     */
    fun destroy() {
        val h = handle.getAndSet(0)
        if (h != 0L) {
            try {
                disconnect()
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Error disconnecting", e)
            }
            
            nativeDestroy(h)
            android.util.Log.i(TAG, "VPN client destroyed")
        }
        
        isInitialized.set(false)
        
        // Cancel all coroutines
        scope.cancel()
    }
    
    /**
     * Finalize - ensure cleanup
     */
    protected fun finalize() {
        destroy()
    }
}
