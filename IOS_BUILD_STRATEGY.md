# Building for iOS - Current Status & Strategy

## Problem Analysis

OpenSSL-Zig has deep dependencies on macOS-specific frameworks (`CoreServices`) that don't exist in iOS.  Even with SDK paths configured, OpenSSL-Zig's build system tries to link frameworks that aren't available on iOS.

## Solution: Use Prebuilt OpenSSL for iOS

Since WorxVPN already has OpenSSL-Universal via CocoaPods, we should leverage that instead of fighting with OpenSSL-Zig's cross-compilation issues.

### Strategy

**1. Build Zig Core Without OpenSSL Dependency**

Create a "core" library that contains all VPN logic EXCEPT the OpenSSL calls:

```bash
zig build-lib \
  -target aarch64-ios \
  -frelease-fast \
  src/protocol.zig \
  src/client.zig \
  -femit-bin=zig-out/lib/libsoftether_core_ios.a
```

**2. Create C Bridge Layer**

The C bridge (`src/bridge/ios_ffi.c`) will:
- Call into Zig core for VPN protocol logic
- Call into OpenSSL-Universal for TLS/crypto operations
- Expose simple C API for Swift

**3. Link in Xcode Project**

In WorxVPN target:
```
Link Binary With Libraries:
  - libsoftether_core_ios.a (from Zig)
  - OpenSSL.framework (from CocoaPods)
```

## Alternative: Minimal OpenSSL Wrapper

Create a minimal OpenSSL wrapper that iOS can link against:

```zig
// src/crypto_ios.zig - Minimal crypto wrapper
pub const CryptoBackend = struct {
    // These will call into OpenSSL.framework at link time
    extern "c" fn SSL_library_init() void;
    extern "c" fn SSL_CTX_new() ?*anyopaque;
    // ... other OpenSSL functions we need
    
    pub fn init() !void {
        SSL_library_init();
    }
};
```

Then in build.zig for iOS:
```zig
if (is_ios) {
    // Don't use OpenSSL-Zig, just declare external functions
    lib.linkFramework("Security");  // iOS crypto framework
    // OpenSSL functions will be resolved from OpenSSL-Universal at link time
}
```

## Recommended Approach

**Short-term (Get iOS Working Now)**:
1. Remove OpenSSL-Zig dependency for iOS builds
2. Declare OpenSSL functions as `extern "c"` in Zig
3. Link against OpenSSL-Universal's framework in Xcode
4. Profit! 🎉

**Long-term (Pure Zig Solution)**:
1. Continue C→Zig migration
2. Replace OpenSSL calls with pure Zig crypto (std.crypto)
3. Eventually remove OpenSSL dependency entirely
4. Maximum Zig! 🚀

## Implementation Plan

### Step 1: Modify build.zig for iOS

```zig
if (is_ios) {
    // For iOS, don't link OpenSSL-Zig
    // Just link libc and declare OpenSSL functions as extern
    lib.linkLibC();
    // OpenSSL will be provided by OpenSSL-Universal framework
} else if (use_system_ssl) {
    lib.linkSystemLibrary("ssl");
    lib.linkSystemLibrary("crypto");
} else {
    lib.linkLibrary(crypto.?);
    lib.linkLibrary(openssl.?);
}
```

### Step 2: Create iOS-specific SSL declarations

```zig
// src/ssl_ios.zig
// Declare OpenSSL functions that will be linked from OpenSSL.framework
pub extern "c" fn SSL_library_init() c_int;
pub extern "c" fn SSL_CTX_new(method: *anyopaque) ?*anyopaque;
pub extern "c" fn TLS_client_method() *anyopaque;
// ... etc
```

### Step 3: Build command

```bash
# Build for iOS device
zig build -Dtarget=aarch64-ios -Drelease=true

# Build for iOS simulator  
zig build -Dtarget=aarch64-ios-simulator -Drelease=true

# The .a files will link against OpenSSL-Universal in Xcode
```

### Step 4: Xcode integration

1. Add `libsoftether_mobile.a` to WorxVPN target
2. OpenSSL-Universal already linked via CocoaPods
3. Add bridging header for C API
4. Call from Swift!

## Next Action

Let me modify build.zig to skip OpenSSL-Zig for iOS and rely on external OpenSSL framework linkage.
