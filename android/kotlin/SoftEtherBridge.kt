package com.softether.vpnclient

import android.util.Log

/**
 * JNI Bridge to SoftEther VPN native library
 * 
 * This class provides Kotlin/Java interface to the native SoftEther VPN client.
 */
class SoftEtherBridge private constructor() {
    
    companion object {
        private const val TAG = "SoftEtherBridge"
        
        // Log levels (must match logging.h)
        const val LOG_LEVEL_SILENT = 0
        const val LOG_LEVEL_ERROR = 1
        const val LOG_LEVEL_WARN = 2
        const val LOG_LEVEL_INFO = 3
        const val LOG_LEVEL_DEBUG = 4
        const val LOG_LEVEL_TRACE = 5
        
        private var instance: SoftEtherBridge? = null
        
        /**
         * Get singleton instance
         */
        @Synchronized
        fun getInstance(): SoftEtherBridge {
            if (instance == null) {
                instance = SoftEtherBridge()
            }
            return instance!!
        }
        
        init {
            try {
                System.loadLibrary("softether-vpn")
                Log.i(TAG, "Native library loaded successfully")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Failed to load native library", e)
                throw e
            }
        }
    }
    
    // Native method declarations
    private external fun nativeInit(): Int
    private external fun nativeCreateClient(): Long
    private external fun nativeConnect(
        serverName: String,
        serverPort: Int,
        hubName: String,
        username: String,
        password: String
    ): Int
    private external fun nativeSetTunFd(tunFd: Int)
    private external fun nativeGetNextPacket(buffer: ByteArray): Int
    private external fun nativePutPacket(packet: ByteArray, size: Int): Boolean
    private external fun nativeIsConnected(): Boolean
    private external fun nativeDisconnect()
    private external fun nativeFreeClient()
    private external fun nativeCleanup()
    private external fun nativeSetLogLevel(level: Int)
    private external fun nativeGetStats(): String
    
    private var clientHandle: Long = 0
    private var isInitialized = false
    
    /**
     * Initialize the VPN bridge
     */
    fun initialize(): Boolean {
        if (isInitialized) {
            Log.w(TAG, "Already initialized")
            return true
        }
        
        val result = nativeInit()
        if (result != 0) {
            Log.e(TAG, "Native init failed: $result")
            return false
        }
        
        clientHandle = nativeCreateClient()
        if (clientHandle == 0L) {
            Log.e(TAG, "Failed to create client")
            return false
        }
        
        isInitialized = true
        Log.i(TAG, "SoftEther bridge initialized successfully")
        return true
    }
    
    /**
     * Connect to VPN server
     */
    fun connect(
        serverName: String,
        serverPort: Int,
        hubName: String,
        username: String,
        password: String
    ): Boolean {
        if (!isInitialized) {
            Log.e(TAG, "Not initialized")
            return false
        }
        
        Log.i(TAG, "Connecting to $serverName:$serverPort")
        val result = nativeConnect(serverName, serverPort, hubName, username, password)
        
        if (result != 0) {
            Log.e(TAG, "Connection failed: $result")
            return false
        }
        
        Log.i(TAG, "Connected successfully")
        return true
    }
    
    /**
     * Set TUN file descriptor from VpnService
     */
    fun setTunFd(tunFd: Int) {
        Log.i(TAG, "Setting TUN fd: $tunFd")
        nativeSetTunFd(tunFd)
    }
    
    /**
     * Get next packet from VPN (to write to TUN)
     * @param buffer Buffer to receive packet data
     * @return Number of bytes read, or -1 if no packet available
     */
    fun getNextPacket(buffer: ByteArray): Int {
        return nativeGetNextPacket(buffer)
    }
    
    /**
     * Put packet into VPN (read from TUN)
     * @param packet Packet data
     * @param size Packet size
     * @return true if successful
     */
    fun putPacket(packet: ByteArray, size: Int): Boolean {
        return nativePutPacket(packet, size)
    }
    
    /**
     * Check if connected to VPN
     */
    fun isConnected(): Boolean {
        if (!isInitialized) {
            return false
        }
        return nativeIsConnected()
    }
    
    /**
     * Disconnect from VPN
     */
    fun disconnect() {
        if (!isInitialized) {
            return
        }
        
        Log.i(TAG, "Disconnecting...")
        nativeDisconnect()
        Log.i(TAG, "Disconnected")
    }
    
    /**
     * Set log level
     */
    fun setLogLevel(level: Int) {
        nativeSetLogLevel(level)
        Log.i(TAG, "Log level set to: $level")
    }
    
    /**
     * Get connection statistics
     */
    fun getStats(): String {
        return if (isInitialized) {
            nativeGetStats()
        } else {
            "Not initialized"
        }
    }
    
    /**
     * Cleanup and free resources
     */
    fun cleanup() {
        if (!isInitialized) {
            return
        }
        
        Log.i(TAG, "Cleaning up...")
        nativeFreeClient()
        nativeCleanup()
        isInitialized = false
        clientHandle = 0
        Log.i(TAG, "Cleanup complete")
    }
}
