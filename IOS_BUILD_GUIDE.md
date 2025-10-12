# iOS Framework Build Guide

## Problem: OpenSSL-Zig iOS Build Issues

OpenSSL-Zig cannot find iOS SDK headers (`stdio.h`, `stdlib.h`) when building for iOS targets. This is expected since iOS SDK paths require special configuration.

## Solution: Use OpenSSL-Universal CocoaPod

The WorxVPN project already has OpenSSL-Universal in Podfile:
```ruby
pod 'OpenSSL-Universal', '3.3.2000'
```

This provides prebuilt OpenSSL frameworks for iOS with proper architecture support.

## Build Strategy

### Option 1: Swift Package with C Bridge (RECOMMENDED)

Create a Swift package that wraps the VPN client:

1. **Build Zig Core** (no OpenSSL dependency):
```bash
cd SoftEtherZig
# Build core VPN logic without OpenSSL directly
zig build-lib \
  -target aarch64-ios \
  -frelease-fast \
  src/protocol.zig \
  -femit-bin=zig-out/lib/libsoftether_core_ios.a
```

2. **Create Swift Wrapper** (`SoftEtherClient.swift`):
```swift
import Foundation
import OpenSSL  // From CocoaPods

@objc public class SoftEtherVPNClient: NSObject {
    private var configPtr: OpaquePointer?
    
    @objc public init(
        server: String,
        port: UInt16,
        hub: String,
        username: String,
        password: String
    ) {
        super.init()
        // Initialize Zig client
        // Use OpenSSL from CocoaPods for TLS
    }
    
    @objc public func connect() async throws {
        // Call Zig FFI functions
        // Wrap errors in Swift Error types
    }
    
    @objc public func disconnect() async {
        // Clean disconnect
    }
}
```

3. **Link in Xcode**:
   - Add `libsoftether_core_ios.a` to "Link Binary With Libraries"
   - Add OpenSSL-Universal via CocoaPods
   - Configure header search paths

### Option 2: Use Pre-compiled OpenSSL Framework

Build against OpenSSL-Universal's XCFramework:

```bash
# Extract OpenSSL paths from CocoaPods
OPENSSL_PATH="Pods/OpenSSL-Universal/OpenSSL.xcframework/ios-arm64"

# Build with system-style linking
zig build \
  -Dtarget=aarch64-ios \
  -Drelease=true \
  -Dsystem-ssl=true \
  --sysroot $OPENSSL_PATH
```

Then manually link against OpenSSL.xcframework in Xcode.

### Option 3: Build Separate iOS Framework

Create an iOS framework target in WorxVPN.xcodeproj:

1. Add new Framework target "SoftEtherVPN"
2. Include Zig compiled `.a` files
3. Link with OpenSSL-Universal
4. Export public Swift/Objective-C API
5. Import in WorxVPN app target

## Recommended Next Steps

1. **Create C Bridge Header** (`SoftEther-Bridging-Header.h`):
```c
#ifndef SoftEther_Bridging_Header_h
#define SoftEther_Bridging_Header_h

#include <stdint.h>
#include <stdbool.h>

// Zig FFI functions
typedef struct VPNConfig {
    const char* server;
    uint16_t port;
    const char* hub;
    const char* username;
    const char* password_hash;
    bool use_compress;
    uint8_t max_connection;
} VPNConfig;

// Exported from Zig
extern int vpn_connect(const VPNConfig* config);
extern int vpn_disconnect(void);
extern bool vpn_is_connected(void);

#endif
```

2. **Update Zig mobile_ffi.zig**:
```zig
export fn vpn_connect(config: *const VPNConfig) callconv(.C) c_int {
    // Use OpenSSL from Swift side (passed as callbacks)
    // Or link statically with OpenSSL-Universal
    return 0; // success
}

export fn vpn_disconnect() callconv(.C) c_int {
    // Clean shutdown
    return 0;
}

export fn vpn_is_connected() callconv(.C) bool {
    // Check connection state
    return false;
}
```

3. **Integrate in WorxVPN**:
```swift
// In WorxVPNApp.swift or ConnectionViewModel.swift
import SoftEtherVPN

class VPNManager: ObservableObject {
    private var client: SoftEtherVPNClient?
    
    func connect(to server: String, credentials: Credentials) async throws {
        client = SoftEtherVPNClient(
            server: server,
            port: 443,
            hub: "VPN",
            username: credentials.username,
            password: credentials.password
        )
        
        try await client?.connect()
    }
}
```

## Build Commands Reference

```bash
# macOS CLI (current working build)
zig build -Dsystem-ssl=true

# iOS Device (ARM64)
zig build -Dtarget=aarch64-ios -Drelease=true

# iOS Simulator (ARM64 for M1+ Macs)
zig build -Dtarget=aarch64-ios-simulator -Drelease=true

# iOS Simulator (x86_64 for Intel Macs)
zig build -Dtarget=x86_64-ios-simulator -Drelease=true

# Create XCFramework
xcodebuild -create-xcframework \
  -library zig-out/lib/libsoftether_ios.a \
  -headers include/ \
  -library zig-out/lib/libsoftether_sim.a \
  -headers include/ \
  -output SoftEtherClient.xcframework
```

## Known Issues & Workarounds

**Issue**: OpenSSL-Zig can't find iOS SDK headers  
**Workaround**: Use OpenSSL-Universal from CocoaPods instead

**Issue**: Cross-compilation requires proper SDK paths  
**Workaround**: Build core Zig logic separately, link with OpenSSL in Xcode

**Issue**: Zig doesn't know about iOS frameworks  
**Workaround**: Use `-framework` flags or link in Xcode project settings

## Testing on Device

```bash
# 1. Build iOS framework
cd SoftEtherZig
zig build -Dtarget=aarch64-ios -Drelease=true

# 2. Copy to WorxVPN
cp zig-out/lib/libsoftether_mobile.a ../Frameworks/

# 3. Open Xcode
cd ..
open WorxVPN.xcworkspace

# 4. Add to WorxVPN target:
# - Link Binary With Libraries: libsoftether_mobile.a
# - Link Binary With Libraries: OpenSSL (from CocoaPods)

# 5. Deploy to device
# Product → Destination → Your iPhone
# Product → Run (⌘R)
```

## Next Session Action Plan

Since OpenSSL-Zig needs iOS SDK configuration, we should:

1. **Short-term**: Build core VPN protocol in Zig without direct OpenSSL dependency
2. **Medium-term**: Create Swift wrapper that uses OpenSSL-Universal for TLS
3. **Long-term**: Configure OpenSSL-Zig build system for proper iOS SDK paths

The fastest path to working iOS integration is using Swift as the glue layer between Zig VPN logic and OpenSSL-Universal's prebuilt frameworks.
