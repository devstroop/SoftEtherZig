# SoftEther VPN - Android Implementation

This directory contains the Android implementation of SoftEther VPN client using JNI and VpnService.

## Architecture

```
┌─────────────────────────────────────────┐
│         Android Application             │
│  (Kotlin/Java UI, VPN Management)       │
└─────────────┬───────────────────────────┘
              │
              ├─ VpnClientService.kt
              │  (VpnService implementation)
              │
              ├─ SoftEtherBridge.kt
              │  (JNI wrapper)
              │
              ▼
┌─────────────────────────────────────────┐
│         JNI Layer (C)                   │
│  softether_jni.c                        │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│    Android Packet Adapter (C)           │
│  packet_adapter_android.c               │
│  - TUN device I/O via fd                │
│  - Packet queue management              │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│      SoftEther VPN Core (C)             │
│  (Cedar + Mayaqua libraries)            │
└─────────────────────────────────────────┘
```

## Directory Structure

```
android/
├── CMakeLists.txt           # Native build configuration
├── jni/
│   └── softether_jni.c      # JNI bindings
├── kotlin/
│   ├── SoftEtherBridge.kt   # Kotlin JNI wrapper
│   └── VpnClientService.kt  # VpnService implementation
└── README.md                # This file

src/bridge/android/
├── packet_adapter_android.c # Android TUN adapter
└── packet_adapter_android.h # Header
```

## Prerequisites

1. **Android NDK** (r21 or later)
2. **Android SDK** (API 21+, target API 33+)
3. **CMake** (3.18.1 or later)
4. **OpenSSL for Android** (prebuilt or build from source)

## Building

### Step 1: Build OpenSSL for Android

```bash
# Download and build OpenSSL for Android
# Or use prebuilt binaries from:
# https://github.com/openssl/openssl/releases

# Set OPENSSL_ROOT_DIR in build.gradle or CMakeLists.txt
export OPENSSL_ROOT_DIR=/path/to/openssl-android
```

### Step 2: Build Native Library

```bash
cd android
mkdir build && cd build

# Configure for Android (arm64-v8a example)
cmake .. \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-21 \
  -DOPENSSL_ROOT_DIR=/path/to/openssl-android

# Build
cmake --build .
```

### Step 3: Integrate with Android Project

1. **Copy native library** to your Android project:
   ```
   app/src/main/jniLibs/
   ├── arm64-v8a/
   │   └── libsoftether-vpn.so
   ├── armeabi-v7a/
   │   └── libsoftether-vpn.so
   └── x86_64/
       └── libsoftether-vpn.so
   ```

2. **Copy Kotlin files** to your project:
   ```
   app/src/main/java/com/softether/vpnclient/
   ├── SoftEtherBridge.kt
   └── VpnClientService.kt
   ```

3. **Update AndroidManifest.xml**:
   ```xml
   <manifest>
       <!-- VPN permission -->
       <uses-permission android:name="android.permission.INTERNET" />
       <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
       
       <application>
           <!-- VPN Service -->
           <service
               android:name=".VpnClientService"
               android:permission="android.permission.BIND_VPN_SERVICE"
               android:exported="false">
               <intent-filter>
                   <action android:name="android.net.VpnService" />
               </intent-filter>
           </service>
       </application>
   </manifest>
   ```

## Usage Example

### Kotlin Activity

```kotlin
import android.content.Intent
import android.net.VpnService
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    
    companion object {
        const val VPN_REQUEST_CODE = 1
    }
    
    fun connectVpn() {
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
            // Set connection parameters
            VpnClientService.serverName = "vpn.example.com"
            VpnClientService.serverPort = 443
            VpnClientService.hubName = "VPN"
            VpnClientService.username = "user"
            VpnClientService.password = "password"
            
            // Start VPN service
            val serviceIntent = Intent(this, VpnClientService::class.java)
            startService(serviceIntent)
        }
    }
    
    fun disconnectVpn() {
        val intent = Intent(this, VpnClientService::class.java).apply {
            action = "STOP"
        }
        startService(intent)
    }
}
```

## Key Features

- ✅ **Full VPN Protocol Support**: SSTP, L2TP, OpenVPN compatible
- ✅ **Native Performance**: C-based packet processing
- ✅ **Foreground Service**: Persistent VPN connection
- ✅ **Notification**: Connection status display
- ✅ **Logging System**: Configurable log levels
- ✅ **Thread-Safe**: Proper synchronization
- ✅ **Error Handling**: Graceful failure recovery

## API Reference

### SoftEtherBridge

```kotlin
// Initialize
val bridge = SoftEtherBridge.getInstance()
bridge.initialize()

// Set log level
bridge.setLogLevel(SoftEtherBridge.LOG_LEVEL_INFO)

// Connect
bridge.connect(
    serverName = "vpn.example.com",
    serverPort = 443,
    hubName = "VPN",
    username = "user",
    password = "password"
)

// Set TUN fd (from VpnService.establish())
bridge.setTunFd(tunFd)

// Packet I/O
val packet = ByteArray(2048)
val length = bridge.getNextPacket(packet)  // VPN → TUN
bridge.putPacket(packet, length)            // TUN → VPN

// Status
val connected = bridge.isConnected()
val stats = bridge.getStats()

// Disconnect
bridge.disconnect()
bridge.cleanup()
```

## Testing

### Run on Android Emulator

```bash
# Start emulator
emulator -avd Pixel_5_API_33 -netdelay none -netspeed full

# Install APK
adb install app/build/outputs/apk/debug/app-debug.apk

# Monitor logs
adb logcat | grep -E "(SoftEther|VpnClient)"
```

### Test on Physical Device

1. Enable Developer Options
2. Enable USB Debugging
3. Connect device via USB
4. Run: `adb devices`
5. Install and test

## Troubleshooting

### Issue: Native library not found

**Solution**: Ensure `libsoftether-vpn.so` is in correct `jniLibs/` directory for your ABI.

```bash
# Check library location
unzip -l app-debug.apk | grep libsoftether
```

### Issue: VpnService not starting

**Solution**: Check VPN permission was granted and service is declared in manifest.

### Issue: Connection fails

**Solution**: Check logs for detailed error:
```bash
adb logcat -s SoftEtherVPN-JNI:V SoftEtherBridge:V VpnClientService:V
```

## Performance Optimization

- Packet pool pre-allocation
- Zero-copy where possible
- Efficient thread synchronization
- Minimal logging in release builds

## Security Considerations

- Store credentials securely (Android Keystore)
- Use encrypted connections (TLS/SSL)
- Validate server certificates
- Clear sensitive data on disconnect
- Use ProGuard/R8 for code obfuscation

## Future Enhancements

- [ ] Always-on VPN support
- [ ] Per-app VPN routing
- [ ] IPv6 support
- [ ] Connection statistics UI
- [ ] Multiple server profiles
- [ ] Auto-reconnect on network change
- [ ] Split tunneling

## License

Same as SoftEther VPN (Apache License 2.0)

## Contact

For issues and support, see main project README.
