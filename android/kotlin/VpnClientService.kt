package com.softether.vpnclient

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import kotlin.concurrent.thread

/**
 * Android VpnService implementation for SoftEther VPN
 * 
 * This service manages the VPN connection lifecycle and packet forwarding
 * between the TUN interface and SoftEther VPN client.
 */
class VpnClientService : VpnService() {
    
    companion object {
        private const val TAG = "VpnClientService"
        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "SoftEtherVPN"
        private const val MTU = 1500
        
        // Connection parameters (set these before starting service)
        var serverName: String = ""
        var serverPort: Int = 443
        var hubName: String = ""
        var username: String = ""
        var password: String = ""
    }
    
    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private var tunToVpnThread: Thread? = null
    private var vpnToTunThread: Thread? = null
    
    private val softEtherBridge = SoftEtherBridge.getInstance()
    
    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "VpnClientService created")
        createNotificationChannel()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "onStartCommand called")
        
        if (intent?.action == "STOP") {
            stopVpn()
            return START_NOT_STICKY
        }
        
        // Start VPN in background
        thread {
            startVpn()
        }
        
        return START_STICKY
    }
    
    private fun startVpn() {
        if (isRunning) {
            Log.w(TAG, "VPN already running")
            return
        }
        
        try {
            Log.i(TAG, "Starting VPN connection...")
            
            // Show notification
            startForeground(NOTIFICATION_ID, createNotification("Connecting..."))
            
            // Initialize SoftEther bridge
            if (!softEtherBridge.initialize()) {
                Log.e(TAG, "Failed to initialize SoftEther bridge")
                stopSelf()
                return
            }
            
            // Set log level
            softEtherBridge.setLogLevel(SoftEtherBridge.LOG_LEVEL_INFO)
            
            // Establish VPN interface
            vpnInterface = establishVpnInterface()
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                stopSelf()
                return
            }
            
            // Get TUN file descriptor and pass to native code
            val tunFd = vpnInterface!!.fd
            softEtherBridge.setTunFd(tunFd)
            Log.i(TAG, "TUN interface established, fd=$tunFd")
            
            // Connect to VPN server
            if (!softEtherBridge.connect(serverName, serverPort, hubName, username, password)) {
                Log.e(TAG, "Failed to connect to VPN server")
                stopVpn()
                return
            }
            
            Log.i(TAG, "Connected to VPN server")
            updateNotification("Connected")
            
            isRunning = true
            
            // Start packet forwarding threads
            startPacketForwarding()
            
        } catch (e: Exception) {
            Log.e(TAG, "Error starting VPN", e)
            stopVpn()
        }
    }
    
    private fun establishVpnInterface(): ParcelFileDescriptor? {
        return try {
            Builder()
                .setSession("SoftEther VPN")
                .addAddress("10.0.0.2", 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("8.8.4.4")
                .setMtu(MTU)
                .setBlocking(true)
                .establish()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish VPN interface", e)
            null
        }
    }
    
    private fun startPacketForwarding() {
        // Thread 1: Read from TUN, send to VPN (outgoing packets)
        tunToVpnThread = thread(name = "TUN→VPN") {
            Log.i(TAG, "TUN→VPN thread started")
            val inputStream = FileInputStream(vpnInterface!!.fileDescriptor)
            val packet = ByteArray(32767) // Max IP packet size
            
            try {
                while (isRunning && !Thread.currentThread().isInterrupted) {
                    val length = inputStream.read(packet)
                    if (length > 0) {
                        // Send packet to VPN
                        if (!softEtherBridge.putPacket(packet, length)) {
                            Log.w(TAG, "Failed to send packet to VPN")
                        }
                    }
                }
            } catch (e: Exception) {
                if (isRunning) {
                    Log.e(TAG, "Error in TUN→VPN thread", e)
                }
            }
            Log.i(TAG, "TUN→VPN thread stopped")
        }
        
        // Thread 2: Read from VPN, write to TUN (incoming packets)
        vpnToTunThread = thread(name = "VPN→TUN") {
            Log.i(TAG, "VPN→TUN thread started")
            val outputStream = FileOutputStream(vpnInterface!!.fileDescriptor)
            val packet = ByteArray(32767)
            
            try {
                while (isRunning && !Thread.currentThread().isInterrupted) {
                    // Get packet from VPN
                    val length = softEtherBridge.getNextPacket(packet)
                    if (length > 0) {
                        // Write to TUN
                        outputStream.write(packet, 0, length)
                    } else {
                        // No packet available, sleep briefly
                        Thread.sleep(10)
                    }
                }
            } catch (e: Exception) {
                if (isRunning) {
                    Log.e(TAG, "Error in VPN→TUN thread", e)
                }
            }
            Log.i(TAG, "VPN→TUN thread stopped")
        }
    }
    
    private fun stopVpn() {
        Log.i(TAG, "Stopping VPN...")
        isRunning = false
        
        // Stop packet forwarding threads
        tunToVpnThread?.interrupt()
        vpnToTunThread?.interrupt()
        
        try {
            tunToVpnThread?.join(1000)
            vpnToTunThread?.join(1000)
        } catch (e: InterruptedException) {
            Log.w(TAG, "Thread join interrupted", e)
        }
        
        // Disconnect VPN
        softEtherBridge.disconnect()
        
        // Close TUN interface
        vpnInterface?.close()
        vpnInterface = null
        
        // Cleanup SoftEther bridge
        softEtherBridge.cleanup()
        
        stopForeground(true)
        stopSelf()
        
        Log.i(TAG, "VPN stopped")
    }
    
    override fun onDestroy() {
        super.onDestroy()
        Log.i(TAG, "VpnClientService destroyed")
        stopVpn()
    }
    
    override fun onRevoke() {
        super.onRevoke()
        Log.i(TAG, "VPN permission revoked")
        stopVpn()
    }
    
    // Notification helpers
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "SoftEther VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "SoftEther VPN connection status"
            }
            
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(status: String): Notification {
        val stopIntent = Intent(this, VpnClientService::class.java).apply {
            action = "STOP"
        }
        val stopPendingIntent = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        
        return builder
            .setContentTitle("SoftEther VPN")
            .setContentText(status)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .addAction(android.R.drawable.ic_delete, "Disconnect", stopPendingIntent)
            .setOngoing(true)
            .build()
    }
    
    private fun updateNotification(status: String) {
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NOTIFICATION_ID, createNotification(status))
    }
}
