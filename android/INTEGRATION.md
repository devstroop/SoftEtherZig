# SoftEther Mobile FFI - Android Integration Guide

Complete guide to integrate SoftEther Mobile FFI into your Android VPN application.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Building the Mobile FFI Library](#building-the-mobile-ffi-library)
4. [Android Project Setup](#android-project-setup)
5. [Basic Usage](#basic-usage)
6. [VpnService Integration](#vpnservice-integration)
7. [Advanced Features](#advanced-features)
8. [API Reference](#api-reference)
9. [Troubleshooting](#troubleshooting)
10. [Performance Tuning](#performance-tuning)

---

## Overview

The SoftEther Mobile FFI provides a clean, type-safe Kotlin API for Android VPN applications.

### Architecture

```
Android VpnService (Kotlin)
    ↓
SoftEtherMobileClient (Kotlin API)
    ↓
mobile_jni.c (JNI Wrapper)
    ↓
libsoftether_mobile.so (Mobile FFI - platform-agnostic C API)
    ↓
Zig Packet Adapter (Core VPN logic)
```

### Features

- ✅ Type-safe Kotlin API with data classes
- ✅ Coroutine-based async/await operations
- ✅ Thread-safe concurrent access
- ✅ Native memory management (no leaks)
- ✅ VpnService integration
- ✅ Efficient packet I/O
- ✅ Real-time stats and network info
- ✅ Reconnection support

---

## Prerequisites

### Required Tools

1. **Zig 0.15.1 or later**
   ```bash
   # Install Zig
   brew install zig  # macOS
   # Or download from https://ziglang.org/download/
   ```

2. **Android Studio Arctic Fox or later**
   - Android SDK 24+ (Android 7.0)
   - NDK 25.0 or later

3. **OpenSSL for Android**
   ```bash
   # Install via vcpkg or build from source
   ```

### Project Structure

```
your-vpn-app/
├── app/
│   ├── src/main/
│   │   ├── java/com/yourapp/
│   │   │   └── VpnService.kt
│   │   └── jniLibs/
│   │       ├── arm64-v8a/
│   │       │   └── libsoftether-vpn.so
│   │       └── armeabi-v7a/
│   │           └── libsoftether-vpn.so
│   └── build.gradle
├── softether/                    # Add this submodule
│   ├── android/
│   │   ├── jni/mobile_jni.c
│   │   ├── kotlin/SoftEtherMobileClient.kt
│   │   └── CMakeLists.txt
│   ├── include/mobile_ffi.h
│   └── zig-out/lib/
│       └── libsoftether_mobile.a
└── build.gradle
```

---

## Building the Mobile FFI Library

### Step 1: Build the Zig Mobile FFI

```bash
cd /path/to/SoftEtherZig

# Build for Android ARM64
zig build mobile-ffi -Dtarget=aarch64-linux-android

# Build for Android ARM32
zig build mobile-ffi -Dtarget=arm-linux-android

# Output: zig-out/lib/libsoftether_mobile.a
```

### Step 2: Configure Android NDK Build

Create or update `app/build.gradle`:

```groovy
android {
    compileSdk 34
    ndkVersion "25.0.8775105"
    
    defaultConfig {
        applicationId "com.yourapp.vpn"
        minSdk 24
        targetSdk 34
        
        ndk {
            abiFilters 'arm64-v8a', 'armeabi-v7a'
        }
        
        externalNativeBuild {
            cmake {
                cppFlags "-std=c++17"
                arguments "-DANDROID_STL=c++_shared"
            }
        }
    }
    
    externalNativeBuild {
        cmake {
            path file('src/main/cpp/CMakeLists.txt')
            version '3.18.1'
        }
    }
}

dependencies {
    implementation 'org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3'
}
```

### Step 3: Configure CMake

Update `app/src/main/cpp/CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.18.1)
project(softether-vpn)

set(CMAKE_C_STANDARD 99)

# Include mobile FFI headers
include_directories(
    ${CMAKE_SOURCE_DIR}/../../../../softether/include
)

# JNI wrapper
add_library(softether-vpn SHARED
    ${CMAKE_SOURCE_DIR}/../../../../softether/android/jni/mobile_jni.c
)

# Link pre-built mobile FFI library
add_library(softether_mobile STATIC IMPORTED)
set_target_properties(softether_mobile PROPERTIES
    IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/../../../../softether/zig-out/lib/libsoftether_mobile.a
)

# Link libraries
find_library(log-lib log)
target_link_libraries(softether-vpn
    softether_mobile
    ${log-lib}
)
```

### Step 4: Copy Kotlin Bridge

Copy `SoftEtherMobileClient.kt` to your project:

```bash
cp softether/android/kotlin/SoftEtherMobileClient.kt \
   app/src/main/java/com/yourapp/vpn/
```

Update package name in the file:

```kotlin
package com.yourapp.vpn  // Change from com.softether.mobile
```

---

## Basic Usage

### Simple Connection Example

```kotlin
import com.yourapp.vpn.SoftEtherMobileClient
import com.yourapp.vpn.VpnConfig
import kotlinx.coroutines.*

class VpnManager {
    private val client = SoftEtherMobileClient()
    
    suspend fun connect() {
        // Create configuration
        val config = VpnConfig(
            serverName = "vpn.example.com",
            serverPort = 443,
            hubName = "VPN",
            username = "user@example.com",
            password = "your_password"
        )
        
        // Create VPN client
        client.create(config)
        
        // Connect (async with timeout)
        try {
            client.connectAsync(timeoutMs = 30000)
            println("Connected! Status: ${client.getStatus()}")
            
            // Get network info
            val netInfo = client.getNetworkInfo()
            println("IP: ${netInfo.ipAddress}")
            println("Gateway: ${netInfo.gateway}")
            println("DNS: ${netInfo.dnsServers.joinToString()}")
            
        } catch (e: Exception) {
            println("Connection failed: ${e.message}")
            client.destroy()
        }
    }
    
    suspend fun disconnect() {
        client.disconnectAsync()
        client.destroy()
    }
}
```

### Configuration Options

```kotlin
val config = VpnConfig(
    // Required
    serverName = "vpn.example.com",
    serverPort = 443,
    hubName = "VPN",
    username = "user@example.com",
    password = "your_password",
    
    // Optional - Connection settings
    useEncrypt = true,           // Enable SSL/TLS encryption
    useCompress = true,          // Enable data compression
    halfConnection = false,      // Use half-duplex (saves battery)
    maxConnection = 1,           // Number of TCP connections (1-8)
    
    // Optional - Performance tuning
    recvQueueSize = 128,         // Receive queue size (packets)
    sendQueueSize = 128,         // Send queue size (packets)
    packetPoolSize = 256,        // Packet pool size
    batchSize = 32               // Batch processing size
)
```

---

## VpnService Integration

### Complete VpnService Implementation

```kotlin
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.yourapp.vpn.*
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

class SoftEtherVpnService : VpnService() {
    
    private val client = SoftEtherMobileClient()
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var vpnInterface: ParcelFileDescriptor? = null
    
    companion object {
        const val ACTION_CONNECT = "com.yourapp.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.yourapp.vpn.DISCONNECT"
        const val EXTRA_SERVER = "server"
        const val EXTRA_PORT = "port"
        const val EXTRA_HUB = "hub"
        const val EXTRA_USERNAME = "username"
        const val EXTRA_PASSWORD = "password"
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val server = intent.getStringExtra(EXTRA_SERVER) ?: return START_NOT_STICKY
                val port = intent.getIntExtra(EXTRA_PORT, 443)
                val hub = intent.getStringExtra(EXTRA_HUB) ?: "VPN"
                val username = intent.getStringExtra(EXTRA_USERNAME) ?: return START_NOT_STICKY
                val password = intent.getStringExtra(EXTRA_PASSWORD) ?: return START_NOT_STICKY
                
                val config = VpnConfig(server, port, hub, username, password)
                scope.launch { connect(config) }
            }
            ACTION_DISCONNECT -> {
                scope.launch { disconnect() }
                stopSelf()
            }
        }
        return START_STICKY
    }
    
    private suspend fun connect(config: VpnConfig) {
        try {
            // Initialize SoftEther client
            client.create(config)
            client.connectAsync(timeoutMs = 30000)
            
            // Get network configuration
            val netInfo = client.getNetworkInfo()
            
            // Establish VPN interface
            vpnInterface = Builder()
                .setSession("SoftEther VPN")
                .addAddress(netInfo.ipAddress, 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(netInfo.dnsServers[0])
                .setMtu(netInfo.mtu)
                .establish()
            
            // Start packet forwarding
            startPacketForwarding()
            
            // Setup callbacks
            setupCallbacks()
            
        } catch (e: Exception) {
            android.util.Log.e("VpnService", "Connection failed", e)
            disconnect()
        }
    }
    
    private fun startPacketForwarding() {
        val vpnFd = vpnInterface ?: return
        
        // VPN → SoftEther (upload)
        scope.launch {
            val inputStream = FileInputStream(vpnFd.fileDescriptor)
            val buffer = ByteArray(2048)
            
            try {
                while (isActive && client.isConnected()) {
                    val bytesRead = inputStream.read(buffer)
                    if (bytesRead > 0) {
                        val packet = buffer.copyOf(bytesRead)
                        client.writePacketAsync(packet)
                    }
                }
            } catch (e: Exception) {
                android.util.Log.e("VpnService", "Upload error", e)
            }
        }
        
        // SoftEther → VPN (download)
        scope.launch {
            val outputStream = FileOutputStream(vpnFd.fileDescriptor)
            
            try {
                while (isActive && client.isConnected()) {
                    try {
                        val packet = client.readPacketAsync(timeoutMs = 100)
                        outputStream.write(packet)
                    } catch (e: VpnException.NoData) {
                        // No packet available, continue
                        delay(10)
                    }
                }
            } catch (e: Exception) {
                android.util.Log.e("VpnService", "Download error", e)
            }
        }
    }
    
    private fun setupCallbacks() {
        // Status monitoring
        client.setStatusCallback { status ->
            android.util.Log.i("VpnService", "Status changed: $status")
            when (status) {
                VpnStatus.ERROR -> {
                    scope.launch { disconnect() }
                }
                VpnStatus.DISCONNECTED -> {
                    stopSelf()
                }
                else -> { }
            }
        }
        
        // Stats logging
        client.setStatsCallback { stats ->
            android.util.Log.d("VpnService", 
                "Stats: ↑${stats.bytesSent} ↓${stats.bytesReceived} " +
                "duration=${stats.connectedDuration}s")
        }
    }
    
    private suspend fun disconnect() {
        try {
            client.disconnectAsync()
        } catch (e: Exception) {
            android.util.Log.e("VpnService", "Disconnect error", e)
        } finally {
            client.destroy()
            vpnInterface?.close()
            vpnInterface = null
        }
    }
    
    override fun onDestroy() {
        scope.cancel()
        runBlocking { disconnect() }
        super.onDestroy()
    }
}
```

### Activity to Start VPN

```kotlin
class MainActivity : AppCompatActivity() {
    
    private val VPN_REQUEST_CODE = 100
    
    private fun startVpn() {
        // Request VPN permission
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null)
        }
    }
    
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            val intent = Intent(this, SoftEtherVpnService::class.java).apply {
                action = SoftEtherVpnService.ACTION_CONNECT
                putExtra(SoftEtherVpnService.EXTRA_SERVER, "vpn.example.com")
                putExtra(SoftEtherVpnService.EXTRA_PORT, 443)
                putExtra(SoftEtherVpnService.EXTRA_HUB, "VPN")
                putExtra(SoftEtherVpnService.EXTRA_USERNAME, "user@example.com")
                putExtra(SoftEtherVpnService.EXTRA_PASSWORD, "password")
            }
            startService(intent)
        }
    }
    
    private fun stopVpn() {
        val intent = Intent(this, SoftEtherVpnService::class.java).apply {
            action = SoftEtherVpnService.ACTION_DISCONNECT
        }
        startService(intent)
    }
}
```

### AndroidManifest.xml

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.yourapp.vpn">
    
    <!-- Required permissions -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.BIND_VPN_SERVICE" />
    
    <application>
        <service
            android:name=".SoftEtherVpnService"
            android:permission="android.permission.BIND_VPN_SERVICE"
            android:exported="true">
            <intent-filter>
                <action android:name="android.net.VpnService" />
            </intent-filter>
        </service>
    </application>
</manifest>
```

---

## Advanced Features

### Statistics Monitoring

```kotlin
// Get real-time statistics
val stats = client.getStats()
println("Uploaded: ${stats.bytesSent / 1024} KB")
println("Downloaded: ${stats.bytesReceived / 1024} KB")
println("Packets: ${stats.packetsSent}↑ ${stats.packetsReceived}↓")
println("Duration: ${stats.connectedDuration}s")
println("Drops: ${stats.queueDrops}")
println("Errors: ${stats.errors}")

// Continuous monitoring with callback
client.setStatsCallback { stats ->
    updateUI(stats)
}
```

### Network Information

```kotlin
val netInfo = client.getNetworkInfo()

println("IP Address: ${netInfo.ipAddress}")
println("Gateway: ${netInfo.gateway}")
println("Netmask: ${netInfo.netmask}")
println("DNS Servers: ${netInfo.dnsServers.joinToString(", ")}")
println("MTU: ${netInfo.mtu}")
```

### Connection Status

```kotlin
// Get current status
when (client.getStatus()) {
    VpnStatus.DISCONNECTED -> println("Not connected")
    VpnStatus.CONNECTING -> println("Establishing connection...")
    VpnStatus.CONNECTED -> println("Connected!")
    VpnStatus.RECONNECTING -> println("Reconnecting...")
    VpnStatus.ERROR -> {
        println("Error: ${client.getLastError()}")
    }
}

// Monitor status changes
client.setStatusCallback { status ->
    when (status) {
        VpnStatus.CONNECTED -> showNotification("VPN Connected")
        VpnStatus.ERROR -> showNotification("VPN Error")
        else -> { }
    }
}
```

### Error Handling

```kotlin
try {
    client.connectAsync()
} catch (e: VpnException) {
    when (e) {
        is VpnException.NotCreated -> {
            println("Client not initialized")
        }
        is VpnException.ConnectFailed -> {
            println("Connection failed: code ${e.message}")
        }
        is VpnException.Timeout -> {
            println("Connection timed out")
        }
        is VpnException.OperationFailed -> {
            println("Operation failed: ${e.message}")
            println("Details: ${client.getLastError()}")
        }
        else -> {
            println("Unknown error: ${e.message}")
        }
    }
}
```

### Packet I/O

```kotlin
// Read packet (non-blocking)
try {
    val packet = client.readPacket(timeoutMs = 0)
    processPacket(packet)
} catch (e: VpnException.NoData) {
    // No packet available
}

// Read packet (blocking with timeout)
try {
    val packet = client.readPacket(timeoutMs = 100)
    processPacket(packet)
} catch (e: VpnException.Timeout) {
    // Timeout
}

// Write packet
try {
    val packet = buildIpPacket()
    client.writePacket(packet)
} catch (e: VpnException.WriteFailed) {
    println("Write failed")
}
```

---

## API Reference

### VpnConfig

```kotlin
data class VpnConfig(
    val serverName: String,          // VPN server hostname/IP
    val serverPort: Int = 443,       // Server port (default: 443)
    val hubName: String = "VPN",     // Virtual Hub name
    val username: String,            // Username
    val password: String,            // Password
    val useEncrypt: Boolean = true,  // Enable encryption
    val useCompress: Boolean = true, // Enable compression
    val halfConnection: Boolean = false,  // Half-duplex mode
    val maxConnection: Int = 1,      // Number of TCP connections
    val recvQueueSize: Long = 128,   // RX queue size
    val sendQueueSize: Long = 128,   // TX queue size
    val packetPoolSize: Long = 256,  // Packet pool size
    val batchSize: Long = 32         // Batch size
)
```

### VpnStatus

```kotlin
enum class VpnStatus {
    DISCONNECTED,  // Not connected
    CONNECTING,    // Establishing connection
    CONNECTED,     // Connected and operational
    RECONNECTING,  // Reconnecting after error
    ERROR          // Error state
}
```

### VpnStats

```kotlin
data class VpnStats(
    val bytesSent: Long,            // Total bytes uploaded
    val bytesReceived: Long,        // Total bytes downloaded
    val packetsSent: Long,          // Total packets uploaded
    val packetsReceived: Long,      // Total packets downloaded
    val connectedDurationMs: Long,  // Connected time (ms)
    val queueDrops: Long,           // Packets dropped
    val errors: Long                // Error count
)
```

### NetworkInfo

```kotlin
data class NetworkInfo(
    val ipAddress: String,        // VPN IP address
    val gateway: String,          // Gateway IP
    val netmask: String,          // Subnet mask
    val dnsServers: Array<String>,// DNS servers
    val mtu: Int                  // MTU size
)
```

### SoftEtherMobileClient Methods

```kotlin
// Lifecycle
fun create(config: VpnConfig)
fun destroy()

// Connection
fun connect()
suspend fun connectAsync(timeoutMs: Long = 30000)
fun disconnect()
suspend fun disconnectAsync()

// Status
fun getStatus(): VpnStatus
fun isConnected(): Boolean

// Info
fun getStats(): VpnStats
fun getNetworkInfo(): NetworkInfo
fun getLastError(): String?

// Packet I/O
fun readPacket(timeoutMs: Int = 100): ByteArray
suspend fun readPacketAsync(timeoutMs: Int = 100): ByteArray
fun writePacket(data: ByteArray)
suspend fun writePacketAsync(data: ByteArray)

// Callbacks
fun setStatusCallback(callback: (VpnStatus) -> Unit)
fun setStatsCallback(callback: (VpnStats) -> Unit)
fun setNetworkCallback(callback: (NetworkInfo) -> Unit)

// Static
companion object {
    val version: String
    val buildInfo: String
    fun ensureInitialized()
}
```

---

## Troubleshooting

### Build Issues

**Problem**: `libsoftether_mobile.a not found`

```bash
# Solution: Build the mobile FFI first
cd /path/to/SoftEtherZig
zig build mobile-ffi -Dtarget=aarch64-linux-android
```

**Problem**: NDK not found

```bash
# Solution: Install NDK in Android Studio
# Tools → SDK Manager → SDK Tools → NDK (Side by side)
```

**Problem**: OpenSSL linking errors

```bash
# Solution: Build OpenSSL for Android or use vcpkg
vcpkg install openssl:arm64-android
```

### Runtime Issues

**Problem**: `UnsatisfiedLinkError: couldn't find libsoftether-vpn.so`

```kotlin
// Solution: Check ABI filters in build.gradle
ndk {
    abiFilters 'arm64-v8a'  // Match device architecture
}
```

**Problem**: Connection fails with error code -1

```kotlin
// Solution: Check server credentials and network
val error = client.getLastError()
println("Error details: $error")

// Common causes:
// - Wrong username/password
// - Server unreachable
// - Firewall blocking
// - Certificate validation failed
```

**Problem**: VPN interface not established

```kotlin
// Solution: Ensure VPN permission granted
val intent = VpnService.prepare(context)
if (intent != null) {
    // Permission not granted
    startActivityForResult(intent, VPN_REQUEST_CODE)
}
```

### Performance Issues

**Problem**: High CPU usage

```kotlin
// Solution: Increase batch size and queue sizes
val config = VpnConfig(
    // ...
    recvQueueSize = 256,    // Increase from 128
    sendQueueSize = 256,
    batchSize = 64          // Increase from 32
)
```

**Problem**: Packet drops

```kotlin
// Solution: Monitor stats and increase pool size
val stats = client.getStats()
if (stats.queueDrops > 100) {
    val config = VpnConfig(
        // ...
        packetPoolSize = 512  // Increase from 256
    )
}
```

### Memory Issues

**Problem**: Memory leaks

```kotlin
// Solution: Always call destroy()
override fun onDestroy() {
    client.destroy()  // Essential!
    super.onDestroy()
}
```

---

## Performance Tuning

### Network Configuration

```kotlin
// Low latency (gaming, VoIP)
val config = VpnConfig(
    serverName = "vpn.example.com",
    username = "user",
    password = "pass",
    useCompress = false,      // Disable compression
    maxConnection = 4,        // Multiple connections
    batchSize = 16            // Smaller batches
)

// High throughput (downloads, streaming)
val config = VpnConfig(
    serverName = "vpn.example.com",
    username = "user",
    password = "pass",
    useCompress = true,       // Enable compression
    maxConnection = 8,        // Max connections
    batchSize = 64,           // Larger batches
    packetPoolSize = 512      // More buffering
)

// Battery saving (background sync)
val config = VpnConfig(
    serverName = "vpn.example.com",
    username = "user",
    password = "pass",
    useCompress = true,
    halfConnection = true,    // Half-duplex
    maxConnection = 1,        // Single connection
    batchSize = 32
)
```

### Monitoring Performance

```kotlin
// Log stats periodically
client.setStatsCallback { stats ->
    val throughput = stats.bytesReceived / (stats.connectedDuration + 1)
    val dropRate = stats.queueDrops.toDouble() / (stats.packetsReceived + 1)
    
    android.util.Log.d("Performance",
        "Throughput: ${throughput / 1024} KB/s, " +
        "Drop rate: ${dropRate * 100}%")
    
    // Adjust if needed
    if (dropRate > 0.01) {
        android.util.Log.w("Performance", "High drop rate detected!")
    }
}
```

---

## Next Steps

1. **Testing**: Test on real devices with different Android versions
2. **Optimization**: Profile and optimize packet forwarding performance
3. **UI**: Build user-friendly configuration UI
4. **Persistence**: Save VPN profiles to preferences
5. **Notifications**: Show connection status in notification bar
6. **Analytics**: Track connection metrics
7. **Security**: Implement certificate pinning

---

## Support

- **Documentation**: See `docs/` directory for more details
- **Issues**: Report bugs on GitHub
- **API Reference**: See `ios/API_REFERENCE.md` (similar API)

---

## License

See LICENSE.TXT for details.
