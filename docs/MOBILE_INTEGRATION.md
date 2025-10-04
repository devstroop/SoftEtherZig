# SoftEther VPN Mobile Integration Guide

## Overview

This document provides comprehensive integration guides for SoftEther VPN on mobile platforms:
- **Android**: Using JNI (Java Native Interface)
- **iOS**: Using PacketTunnelProvider (Network Extension)

Both platforms can share the same C/C++ core codebase with platform-specific adapters.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Mobile Application Layer                 │
│  ┌──────────────────────┐      ┌──────────────────────────┐ │
│  │   Android (Kotlin)   │      │    iOS (Swift)           │ │
│  │   VpnService         │      │ PacketTunnelProvider     │ │
│  └──────────┬───────────┘      └────────────┬─────────────┘ │
└─────────────┼───────────────────────────────┼───────────────┘
              │                               │
              │ JNI                           │ Obj-C Bridge
              │                               │
┌─────────────┴───────────────────────────────┴───────────────┐
│              Platform Adapter Layer (C/C++)                 │
│  ┌──────────────────────┐      ┌──────────────────────────┐ │
│  │ packet_adapter_      │      │ packet_adapter_          │ │
│  │ android.c            │      │ ios.c                    │ │
│  └──────────┬───────────┘      └────────────┬─────────────┘ │
└─────────────┼───────────────────────────────┼───────────────┘
              │                                │
              └────────────────┬───────────────┘
                               │
┌──────────────────────────────┴───────────────────────────────┐
│              SoftEther VPN Core (C/C++)                      │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  softether_bridge.c, Cedar/Client.c, Protocol.c, etc.  │  │
│  │  (Platform-independent VPN protocol implementation)    │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

---

## Part 1: Android Integration (JNI)

### 1.1 Overview

Android VPN apps use `VpnService` to establish a TUN interface and intercept device traffic. We integrate SoftEther via JNI to handle the VPN protocol while Android manages the TUN device.

### 1.2 Project Structure

```
android/
├── app/
│   └── src/
│       └── main/
│           ├── java/com/softether/vpnclient/
│           │   ├── VpnClientService.kt       # VpnService implementation
│           │   ├── VpnClientActivity.kt      # UI
│           │   └── SoftEtherBridge.kt        # JNI interface
│           ├── cpp/
│           │   ├── CMakeLists.txt
│           │   ├── softether_jni.c           # JNI bindings
│           │   ├── packet_adapter_android.c  # Android packet adapter
│           │   └── softether_bridge.c        # Core bridge (symlink)
│           └── AndroidManifest.xml
├── gradle/
└── build.gradle
```

### 1.3 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.softether.vpnclient">

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    
    <application
        android:label="SoftEther VPN"
        android:icon="@mipmap/ic_launcher"
        android:theme="@style/AppTheme">
        
        <service
            android:name=".VpnClientService"
            android:permission="android.permission.BIND_VPN_SERVICE">
            <intent-filter>
                <action android:name="android.net.VpnService" />
            </intent-filter>
        </service>
        
        <activity
            android:name=".VpnClientActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

### 1.4 SoftEtherBridge.kt (JNI Interface)

```kotlin
package com.softether.vpnclient

class SoftEtherBridge {
    
    companion object {
        init {
            System.loadLibrary("softether-jni")
        }
    }
    
    // Native methods
    external fun init(): Int
    external fun cleanup(): Int
    external fun createClient(
        serverName: String,
        serverPort: Int,
        hubName: String,
        username: String,
        passwordHash: String
    ): Long
    
    external fun connect(clientHandle: Long): Int
    external fun disconnect(clientHandle: Long): Int
    external fun freeClient(clientHandle: Long)
    
    // Packet I/O
    external fun sendPacket(clientHandle: Long, data: ByteArray): Int
    external fun receivePacket(clientHandle: Long): ByteArray?
    
    // Status
    external fun isConnected(clientHandle: Long): Boolean
    external fun getStatus(clientHandle: Long): Int
    external fun getDeviceName(clientHandle: Long): String?
    external fun getLearnedIp(clientHandle: Long): Int
    
    // Callbacks (called from native)
    private var packetCallback: ((ByteArray) -> Unit)? = null
    
    fun setPacketCallback(callback: (ByteArray) -> Unit) {
        packetCallback = callback
    }
    
    // Called from JNI when packet received from VPN
    @Suppress("unused")
    private fun onPacketReceived(data: ByteArray) {
        packetCallback?.invoke(data)
    }
}
```

### 1.5 VpnClientService.kt (VpnService Implementation)

```kotlin
package com.softether.vpnclient

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import kotlin.concurrent.thread

class VpnClientService : VpnService() {
    
    private var tunInterface: ParcelFileDescriptor? = null
    private var softEther: SoftEtherBridge? = null
    private var clientHandle: Long = 0
    private var running = false
    
    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "VpnClientService created")
        softEther = SoftEtherBridge()
        softEther?.init()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStartCommand")
        
        val serverName = intent?.getStringExtra("server") ?: return START_NOT_STICKY
        val serverPort = intent.getIntExtra("port", 443)
        val hubName = intent.getStringExtra("hub") ?: return START_NOT_STICKY
        val username = intent.getStringExtra("username") ?: return START_NOT_STICKY
        val passwordHash = intent.getStringExtra("passwordHash") ?: return START_NOT_STICKY
        
        // Start as foreground service
        startForeground(NOTIFICATION_ID, createNotification("Connecting..."))
        
        thread {
            connectVpn(serverName, serverPort, hubName, username, passwordHash)
        }
        
        return START_STICKY
    }
    
    private fun connectVpn(
        serverName: String,
        serverPort: Int,
        hubName: String,
        username: String,
        passwordHash: String
    ) {
        try {
            // Create SoftEther client
            clientHandle = softEther?.createClient(
                serverName, serverPort, hubName, username, passwordHash
            ) ?: 0
            
            if (clientHandle == 0L) {
                Log.e(TAG, "Failed to create client")
                stopSelf()
                return
            }
            
            // Establish VPN session
            val result = softEther?.connect(clientHandle) ?: -1
            if (result != 0) {
                Log.e(TAG, "Connection failed: $result")
                stopSelf()
                return
            }
            
            // Wait for IP assignment (DHCP)
            Thread.sleep(2000)
            
            val learnedIp = softEther?.getLearnedIp(clientHandle) ?: 0
            if (learnedIp == 0) {
                Log.w(TAG, "No IP learned yet, using default config")
            }
            
            // Configure Android TUN interface
            val builder = Builder()
                .setSession("SoftEther VPN")
                .setMtu(1500)
                .addAddress("10.21.0.2", 24)  // Temporary, will be updated by DHCP
                .addRoute("0.0.0.0", 0)       // Route all traffic
                .addDnsServer("8.8.8.8")
            
            // Protect the VPN server socket from routing loop
            val vpnServerSocket = InetSocketAddress(serverName, serverPort)
            protect(java.net.Socket().also { 
                it.connect(vpnServerSocket, 5000)
            }.fileDescriptor)
            
            tunInterface = builder.establish()
            
            if (tunInterface == null) {
                Log.e(TAG, "Failed to establish TUN interface")
                stopSelf()
                return
            }
            
            // Update notification
            updateNotification("Connected to $serverName")
            
            // Start packet forwarding threads
            running = true
            startPacketForwarding()
            
        } catch (e: Exception) {
            Log.e(TAG, "Connection error", e)
            stopSelf()
        }
    }
    
    private fun startPacketForwarding() {
        val tun = tunInterface ?: return
        val inputStream = FileInputStream(tun.fileDescriptor)
        val outputStream = FileOutputStream(tun.fileDescriptor)
        
        // TUN -> VPN thread
        thread {
            val buffer = ByteArray(4096)
            while (running) {
                try {
                    val n = inputStream.read(buffer)
                    if (n > 0) {
                        softEther?.sendPacket(clientHandle, buffer.copyOf(n))
                    }
                } catch (e: Exception) {
                    if (running) {
                        Log.e(TAG, "TUN read error", e)
                        break
                    }
                }
            }
        }
        
        // VPN -> TUN thread (using callback)
        softEther?.setPacketCallback { packet ->
            try {
                outputStream.write(packet)
            } catch (e: Exception) {
                Log.e(TAG, "TUN write error", e)
            }
        }
    }
    
    override fun onDestroy() {
        Log.d(TAG, "onDestroy")
        running = false
        
        softEther?.disconnect(clientHandle)
        softEther?.freeClient(clientHandle)
        softEther?.cleanup()
        
        tunInterface?.close()
        tunInterface = null
        
        super.onDestroy()
    }
    
    private fun createNotification(message: String): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "VPN Service",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
        
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("SoftEther VPN")
            .setContentText(message)
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .build()
    }
    
    private fun updateNotification(message: String) {
        val notification = createNotification(message)
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, notification)
    }
    
    companion object {
        private const val TAG = "VpnClientService"
        private const val CHANNEL_ID = "vpn_channel"
        private const val NOTIFICATION_ID = 1
    }
}
```

### 1.6 softether_jni.c (JNI Bindings)

```c
#include <jni.h>
#include <android/log.h>
#include "softether_bridge.h"
#include "packet_adapter_android.h"

#define LOG_TAG "SoftEtherJNI"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Global reference to SoftEtherBridge Java class for callbacks
static JavaVM *g_jvm = NULL;
static jobject g_bridge_obj = NULL;

// JNI_OnLoad - Called when library is loaded
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    g_jvm = vm;
    return JNI_VERSION_1_6;
}

// Initialize SoftEther library
JNIEXPORT jint JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_init(JNIEnv *env, jobject thiz) {
    LOGD("Initializing SoftEther VPN library");
    
    // Store global reference for callbacks
    g_bridge_obj = (*env)->NewGlobalRef(env, thiz);
    
    return vpn_bridge_init(0); // 0 = no debug
}

// Cleanup
JNIEXPORT jint JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_cleanup(JNIEnv *env, jobject thiz) {
    LOGD("Cleaning up SoftEther VPN library");
    
    if (g_bridge_obj) {
        (*env)->DeleteGlobalRef(env, g_bridge_obj);
        g_bridge_obj = NULL;
    }
    
    return vpn_bridge_cleanup();
}

// Create client
JNIEXPORT jlong JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_createClient(
    JNIEnv *env, jobject thiz,
    jstring serverName, jint serverPort,
    jstring hubName, jstring username, jstring passwordHash)
{
    const char *server = (*env)->GetStringUTFChars(env, serverName, NULL);
    const char *hub = (*env)->GetStringUTFChars(env, hubName, NULL);
    const char *user = (*env)->GetStringUTFChars(env, username, NULL);
    const char *hash = (*env)->GetStringUTFChars(env, passwordHash, NULL);
    
    LOGD("Creating client: %s:%d hub=%s user=%s", server, serverPort, hub, user);
    
    VpnBridgeClient *client = vpn_bridge_create_client(
        server, (unsigned int)serverPort,
        hub, user, hash, 1  // 1 = is_hashed
    );
    
    (*env)->ReleaseStringUTFChars(env, serverName, server);
    (*env)->ReleaseStringUTFChars(env, hubName, hub);
    (*env)->ReleaseStringUTFChars(env, username, user);
    (*env)->ReleaseStringUTFChars(env, passwordHash, hash);
    
    return (jlong)client;
}

// Connect
JNIEXPORT jint JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_connect(
    JNIEnv *env, jobject thiz, jlong clientHandle)
{
    VpnBridgeClient *client = (VpnBridgeClient *)clientHandle;
    if (!client) return -1;
    
    LOGD("Connecting VPN session");
    return vpn_bridge_connect(client);
}

// Disconnect
JNIEXPORT jint JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_disconnect(
    JNIEnv *env, jobject thiz, jlong clientHandle)
{
    VpnBridgeClient *client = (VpnBridgeClient *)clientHandle;
    if (!client) return -1;
    
    LOGD("Disconnecting VPN session");
    return vpn_bridge_disconnect(client);
}

// Free client
JNIEXPORT void JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_freeClient(
    JNIEnv *env, jobject thiz, jlong clientHandle)
{
    VpnBridgeClient *client = (VpnBridgeClient *)clientHandle;
    if (!client) return;
    
    LOGD("Freeing client");
    vpn_bridge_free_client(client);
}

// Send packet (from Android TUN to VPN)
JNIEXPORT jint JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_sendPacket(
    JNIEnv *env, jobject thiz, jlong clientHandle, jbyteArray data)
{
    VpnBridgeClient *client = (VpnBridgeClient *)clientHandle;
    if (!client) return -1;
    
    jsize len = (*env)->GetArrayLength(env, data);
    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
    
    int result = android_send_packet_to_vpn(client, (unsigned char *)bytes, len);
    
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
    
    return result;
}

// Receive packet (from VPN to Android TUN) - called by polling
JNIEXPORT jbyteArray JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_receivePacket(
    JNIEnv *env, jobject thiz, jlong clientHandle)
{
    VpnBridgeClient *client = (VpnBridgeClient *)clientHandle;
    if (!client) return NULL;
    
    unsigned char buffer[2048];
    unsigned int size = sizeof(buffer);
    
    int result = android_receive_packet_from_vpn(client, buffer, &size);
    if (result <= 0 || size == 0) {
        return NULL;  // No packet available
    }
    
    jbyteArray packet = (*env)->NewByteArray(env, size);
    (*env)->SetByteArrayRegion(env, packet, 0, size, (jbyte *)buffer);
    
    return packet;
}

// Callback from C code to Java (when packet received)
void android_packet_callback(unsigned char *data, unsigned int size) {
    if (!g_jvm || !g_bridge_obj) return;
    
    JNIEnv *env;
    int attached = 0;
    
    // Attach current thread if needed
    if ((*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        if ((*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL) != 0) {
            LOGE("Failed to attach thread");
            return;
        }
        attached = 1;
    }
    
    // Create byte array
    jbyteArray packet = (*env)->NewByteArray(env, size);
    (*env)->SetByteArrayRegion(env, packet, 0, size, (jbyte *)data);
    
    // Call Java callback
    jclass cls = (*env)->GetObjectClass(env, g_bridge_obj);
    jmethodID mid = (*env)->GetMethodID(env, cls, "onPacketReceived", "([B)V");
    
    if (mid) {
        (*env)->CallVoidMethod(env, g_bridge_obj, mid, packet);
    }
    
    (*env)->DeleteLocalRef(env, packet);
    (*env)->DeleteLocalRef(env, cls);
    
    if (attached) {
        (*g_jvm)->DetachCurrentThread(g_jvm);
    }
}

// Status queries
JNIEXPORT jboolean JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_isConnected(
    JNIEnv *env, jobject thiz, jlong clientHandle)
{
    VpnBridgeClient *client = (VpnBridgeClient *)clientHandle;
    if (!client) return JNI_FALSE;
    
    return vpn_bridge_is_connected(client) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_softether_vpnclient_SoftEtherBridge_getStatus(
    JNIEnv *env, jobject thiz, jlong clientHandle)
{
    VpnBridgeClient *client = (VpnBridgeClient *)clientHandle;
    if (!client) return 0;
    
    return vpn_bridge_get_status(client);
}
```

### 1.7 packet_adapter_android.c

```c
// Android-specific packet adapter
#include "packet_adapter_android.h"
#include "softether_bridge.h"

// Queue for packets from VPN to Android
static PacketQueue *g_vpn_to_android_queue = NULL;

// Initialize Android adapter
int android_adapter_init(SESSION *s) {
    g_vpn_to_android_queue = NewQueue();
    return 1;
}

// Send packet from Android TUN to VPN session
int android_send_packet_to_vpn(VpnBridgeClient *client, unsigned char *data, unsigned int size) {
    if (!client || !client->session) return -1;
    
    // Create packet and add to session's send queue
    BLOCK *block = NewBlock(data, size, 0);
    InsertQueue(client->session->PacketAdapter->PacketQueue, block);
    
    // Wake up session
    Cancel(client->session->Cancel1);
    
    return size;
}

// Receive packet from VPN to Android TUN (polling)
int android_receive_packet_from_vpn(VpnBridgeClient *client, unsigned char *buffer, unsigned int *size) {
    if (!g_vpn_to_android_queue) return -1;
    
    BLOCK *block = GetNext(g_vpn_to_android_queue);
    if (!block) {
        *size = 0;
        return 0;
    }
    
    if (block->Size > *size) {
        FreeBlock(block);
        return -1;  // Buffer too small
    }
    
    Copy(buffer, block->Buf, block->Size);
    *size = block->Size;
    FreeBlock(block);
    
    return *size;
}

// Called by SoftEther when packet ready for Android
void android_packet_put(SESSION *s, void *data, unsigned int size) {
    if (!g_vpn_to_android_queue) return;
    
    BLOCK *block = NewBlock(data, size, 0);
    InsertQueue(g_vpn_to_android_queue, block);
    
    // Trigger callback to Java
    extern void android_packet_callback(unsigned char *, unsigned int);
    android_packet_callback(data, size);
}
```

### 1.8 CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.4.1)

project(softether-jni)

# Add SoftEther source paths
set(SOFTETHER_ROOT ../../../../../SoftEtherVPN_Stable/src)

include_directories(
    ${SOFTETHER_ROOT}
    ${SOFTETHER_ROOT}/Mayaqua
    ${SOFTETHER_ROOT}/Cedar
    ../include
)

# Add all required SoftEther sources
add_library(softether-jni SHARED
    softether_jni.c
    packet_adapter_android.c
    ../../../bridge/softether_bridge.c
    ../../../bridge/logging.c
    
    # Mayaqua sources
    ${SOFTETHER_ROOT}/Mayaqua/Mayaqua.c
    ${SOFTETHER_ROOT}/Mayaqua/Memory.c
    ${SOFTETHER_ROOT}/Mayaqua/Str.c
    # ... (add all required sources)
)

# Link OpenSSL and other dependencies
find_library(log-lib log)
find_package(OpenSSL REQUIRED)

target_link_libraries(softether-jni
    ${log-lib}
    OpenSSL::SSL
    OpenSSL::Crypto
    z
)
```

---

## Part 2: iOS Integration (PacketTunnelProvider)

### 2.1 Overview

iOS VPN apps use the Network Extension framework with `PacketTunnelProvider` (NEPacketTunnelProvider) to handle VPN connections. This requires:
- Main app (Swift/Obj-C)
- Network Extension target (PacketTunnelProvider)
- Shared framework for C/C++ code

### 2.2 Project Structure

```
ios/
├── SoftEtherVPN/
│   ├── SoftEtherVPN.xcodeproj
│   ├── SoftEtherVPN/              # Main app
│   │   ├── AppDelegate.swift
│   │   ├── ViewController.swift
│   │   └── Info.plist
│   ├── SoftEtherTunnel/           # Network Extension
│   │   ├── PacketTunnelProvider.swift
│   │   ├── SoftEtherBridge.swift
│   │   └── Info.plist
│   └── SoftEtherCore/             # Shared C/C++ framework
│       ├── softether_ios.c
│       ├── packet_adapter_ios.c
│       ├── softether_bridge.c
│       └── bridging-header.h
└── Podfile (for OpenSSL)
```

### 2.3 Entitlements

**SoftEtherVPN.entitlements:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.developer.networking.networkextension</key>
    <array>
        <string>packet-tunnel-provider</string>
    </array>
</dict>
</plist>
```

### 2.4 PacketTunnelProvider.swift

```swift
import NetworkExtension
import Foundation

class PacketTunnelProvider: NEPacketTunnelProvider {
    
    private var clientHandle: UnsafeMutableRawPointer?
    private var running = false
    
    override func startTunnel(options: [String : NSObject]?, 
                              completionHandler: @escaping (Error?) -> Void) {
        
        NSLog("Starting SoftEther VPN tunnel")
        
        // Get configuration from options
        guard let serverName = protocolConfiguration.serverAddress,
              let username = (protocolConfiguration as? NETunnelProviderProtocol)?.username,
              let passwordRef = (protocolConfiguration as? NETunnelProviderProtocol)?.passwordReference else {
            completionHandler(NEVPNError(.configurationInvalid))
            return
        }
        
        // Retrieve password from keychain
        let password = retrievePassword(from: passwordRef)
        
        // Initialize SoftEther
        let initResult = softether_init()
        guard initResult == 0 else {
            completionHandler(NEVPNError(.configurationDisabled))
            return
        }
        
        // Create client
        clientHandle = softether_create_client(
            serverName,
            443,  // port
            "VPN", // hub
            username,
            password,
            true  // is_hashed
        )
        
        guard clientHandle != nil else {
            completionHandler(NEVPNError(.configurationInvalid))
            return
        }
        
        // Connect
        let connectResult = softether_connect(clientHandle)
        guard connectResult == 0 else {
            completionHandler(NEVPNError(.connectionFailed))
            return
        }
        
        // Wait for DHCP (with timeout)
        var attempts = 0
        var learnedIp: UInt32 = 0
        
        while attempts < 20 && learnedIp == 0 {
            Thread.sleep(forTimeInterval: 0.5)
            learnedIp = softether_get_learned_ip(clientHandle)
            attempts += 1
        }
        
        if learnedIp == 0 {
            NSLog("Warning: No IP learned from DHCP, using defaults")
            learnedIp = inet_addr("10.21.0.2")  // Fallback
        }
        
        // Configure iOS network settings
        let tunnelNetworkSettings = createNetworkSettings(learnedIp: learnedIp)
        
        setTunnelNetworkSettings(tunnelNetworkSettings) { error in
            if let error = error {
                NSLog("Failed to set network settings: \(error)")
                completionHandler(error)
                return
            }
            
            NSLog("Tunnel network settings applied successfully")
            
            // Start packet forwarding
            self.running = true
            self.startPacketForwarding()
            
            completionHandler(nil)
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, 
                             completionHandler: @escaping () -> Void) {
        
        NSLog("Stopping tunnel, reason: \(reason)")
        
        running = false
        
        if let handle = clientHandle {
            softether_disconnect(handle)
            softether_free_client(handle)
            clientHandle = nil
        }
        
        softether_cleanup()
        
        completionHandler()
    }
    
    private func createNetworkSettings(learnedIp: UInt32) -> NEPacketTunnelNetworkSettings {
        
        // Convert IP to string
        let ipString = String(format: "%d.%d.%d.%d",
                              (learnedIp >> 24) & 0xFF,
                              (learnedIp >> 16) & 0xFF,
                              (learnedIp >> 8) & 0xFF,
                              learnedIp & 0xFF)
        
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: ipString)
        
        // IPv4 settings
        let ipv4Settings = NEIPv4Settings(
            addresses: [ipString],
            subnetMasks: ["255.255.0.0"]
        )
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4Settings
        
        // DNS settings
        let dnsSettings = NEDNSSettings(servers: ["8.8.8.8", "8.8.4.4"])
        settings.dnsSettings = dnsSettings
        
        // MTU
        settings.mtu = 1500
        
        return settings
    }
    
    private func startPacketForwarding() {
        
        // iOS -> VPN (outgoing packets)
        packetFlow.readPackets { [weak self] (packets, protocols) in
            guard let self = self, self.running else { return }
            
            for (index, packet) in packets.enumerated() {
                let proto = protocols[index]
                
                // Send to SoftEther
                packet.withUnsafeBytes { ptr in
                    if let baseAddress = ptr.baseAddress {
                        _ = softether_send_packet(
                            self.clientHandle,
                            baseAddress,
                            UInt32(packet.count)
                        )
                    }
                }
            }
            
            // Continue reading
            if self.running {
                self.startPacketForwarding()
            }
        }
        
        // VPN -> iOS (incoming packets) - polling thread
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            
            var buffer = [UInt8](repeating: 0, count: 2048)
            
            while self.running {
                var size: UInt32 = UInt32(buffer.count)
                
                buffer.withUnsafeMutableBytes { ptr in
                    if let baseAddress = ptr.baseAddress {
                        let result = softether_receive_packet(
                            self.clientHandle,
                            baseAddress,
                            &size
                        )
                        
                        if result > 0 && size > 0 {
                            let packet = Data(bytes: baseAddress, count: Int(size))
                            
                            // Write to iOS packet flow
                            self.packetFlow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
                        }
                    }
                }
                
                Thread.sleep(forTimeInterval: 0.001) // 1ms polling
            }
        }
    }
    
    private func retrievePassword(from reference: Data) -> String {
        // Implement keychain retrieval
        return ""
    }
}
```

### 2.5 softether_ios.c (C Bridge for iOS)

```c
#include "softether_bridge.h"
#include "packet_adapter_ios.h"
#include <stdint.h>

// iOS-specific initialization
int softether_init(void) {
    return vpn_bridge_init(0);
}

int softether_cleanup(void) {
    return vpn_bridge_cleanup();
}

void* softether_create_client(
    const char *server, uint32_t port,
    const char *hub, const char *username,
    const char *password_hash, int is_hashed)
{
    return vpn_bridge_create_client(server, port, hub, username, password_hash, is_hashed);
}

int softether_connect(void *client) {
    return vpn_bridge_connect((VpnBridgeClient *)client);
}

int softether_disconnect(void *client) {
    return vpn_bridge_disconnect((VpnBridgeClient *)client);
}

void softether_free_client(void *client) {
    vpn_bridge_free_client((VpnBridgeClient *)client);
}

// Packet I/O for iOS
int softether_send_packet(void *client, const void *data, uint32_t size) {
    return ios_send_packet_to_vpn((VpnBridgeClient *)client, (unsigned char *)data, size);
}

int softether_receive_packet(void *client, void *buffer, uint32_t *size) {
    return ios_receive_packet_from_vpn((VpnBridgeClient *)client, (unsigned char *)buffer, size);
}

uint32_t softether_get_learned_ip(void *client) {
    VpnBridgeClient *c = (VpnBridgeClient *)client;
    return vpn_bridge_get_learned_ip(c);
}
```

### 2.6 packet_adapter_ios.c

```c
// iOS-specific packet adapter using NEPacketTunnelFlow
#include "packet_adapter_ios.h"
#include "../../SoftEtherVPN_Stable/src/Cedar/Cedar.h"

static QUEUE *g_vpn_to_ios_queue = NULL;
static LOCK *g_queue_lock = NULL;

// Initialize iOS adapter
bool ios_adapter_init(SESSION *s) {
    g_vpn_to_ios_queue = NewQueue();
    g_queue_lock = NewLock();
    return true;
}

// Cleanup
void ios_adapter_free(SESSION *s) {
    if (g_vpn_to_ios_queue) {
        // Drain queue
        while (true) {
            BLOCK *block = GetNext(g_vpn_to_ios_queue);
            if (!block) break;
            FreeBlock(block);
        }
        ReleaseQueue(g_vpn_to_ios_queue);
        g_vpn_to_ios_queue = NULL;
    }
    
    if (g_queue_lock) {
        DeleteLock(g_queue_lock);
        g_queue_lock = NULL;
    }
}

// Send packet from iOS to VPN
int ios_send_packet_to_vpn(VpnBridgeClient *client, unsigned char *data, unsigned int size) {
    if (!client || !client->session) return -1;
    
    // Create ethernet frame (add dummy MAC header)
    unsigned char frame[2048];
    if (size + 14 > sizeof(frame)) return -1;
    
    // Destination MAC: ff:ff:ff:ff:ff:ff (broadcast)
    memset(frame, 0xff, 6);
    // Source MAC: 02:00:5e:XX:XX:XX (locally administered)
    frame[6] = 0x02;
    frame[7] = 0x00;
    frame[8] = 0x5e;
    frame[9] = 0x00;
    frame[10] = 0x00;
    frame[11] = 0x01;
    
    // EtherType: 0x0800 (IPv4)
    frame[12] = 0x08;
    frame[13] = 0x00;
    
    // Copy IP packet
    memcpy(frame + 14, data, size);
    
    // Add to session queue
    BLOCK *block = NewBlock(frame, size + 14, 0);
    InsertQueue(client->session->PacketAdapter->PacketQueue, block);
    
    // Wake up session
    Cancel(client->session->Cancel1);
    
    return size;
}

// Receive packet from VPN to iOS
int ios_receive_packet_from_vpn(VpnBridgeClient *client, unsigned char *buffer, unsigned int *size) {
    if (!g_vpn_to_ios_queue || !g_queue_lock) return -1;
    
    Lock(g_queue_lock);
    BLOCK *block = GetNext(g_vpn_to_ios_queue);
    Unlock(g_queue_lock);
    
    if (!block) {
        *size = 0;
        return 0;  // No packet available
    }
    
    // Strip ethernet header (14 bytes) to get IP packet
    if (block->Size > 14) {
        unsigned int ip_size = block->Size - 14;
        if (ip_size > *size) {
            FreeBlock(block);
            return -1;  // Buffer too small
        }
        
        memcpy(buffer, block->Buf + 14, ip_size);
        *size = ip_size;
    } else {
        *size = 0;
    }
    
    FreeBlock(block);
    return *size;
}

// Called by SoftEther when packet ready for iOS
void ios_packet_put(SESSION *s, void *data, unsigned int size) {
    if (!g_vpn_to_ios_queue || !g_queue_lock) return;
    
    BLOCK *block = NewBlock(data, size, 0);
    
    Lock(g_queue_lock);
    InsertQueue(g_vpn_to_ios_queue, block);
    Unlock(g_queue_lock);
}
```

---

## Testing and Deployment

### Android Testing
```bash
# Build APK
./gradlew assembleDebug

# Install on device
adb install app/build/outputs/apk/debug/app-debug.apk

# View logs
adb logcat | grep -E "SoftEther|VpnClient"
```

### iOS Testing
```bash
# Build with Xcode
xcodebuild -workspace SoftEtherVPN.xcworkspace \
           -scheme SoftEtherVPN \
           -configuration Debug \
           -destination 'platform=iOS Simulator,name=iPhone 14'

# View logs
log stream --predicate 'process == "SoftEtherTunnel"' --level debug
```

---

## Security Considerations

1. **Certificate Pinning**: Implement server certificate validation
2. **Keychain Storage**: Store credentials securely
3. **App Transport Security**: Configure ATS properly
4. **Network Extension Entitlements**: Required for both platforms
5. **Code Signing**: Both platforms require proper signing

---

## Performance Optimization

1. **Buffer Sizes**: Tune for mobile networks (typically 1500 MTU)
2. **Thread Pools**: Limit concurrent threads on mobile
3. **Memory Usage**: Monitor and optimize for constrained environments
4. **Battery Life**: Minimize wake locks and CPU usage
5. **Network Transitions**: Handle WiFi ↔ Cellular transitions gracefully

---

## Troubleshooting

### Android
- **VpnService Permission Denied**: User must approve VPN connection
- **JNI Crash**: Check native library loading and thread attachment
- **No Internet**: Verify route configuration and DNS settings

### iOS
- **Network Extension Not Loading**: Check entitlements and provisioning profile
- **Packet Loss**: Verify packet flow read/write loop timing
- **Connection Timeout**: Check server reachability and firewall rules

---

## References

- Android VpnService: https://developer.android.com/reference/android/net/VpnService
- iOS Network Extension: https://developer.apple.com/documentation/networkextension
- JNI Specification: https://docs.oracle.com/javase/8/docs/technotes/guides/jni/
- SoftEther VPN Protocol: https://github.com/SoftEtherVPN/SoftEtherVPN

---

*Document version: 1.0*  
*Last updated: October 4, 2025*
