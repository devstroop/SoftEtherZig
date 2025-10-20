# iOS Build Compatibility Layer

## Overview
This directory contains compatibility headers and stubs that allow building SoftEther VPN for iOS without modifying the original `SoftEtherVPN` source code.

## Problem
iOS lacks certain headers and functions that are present on macOS and Linux:
- `net/if_arp.h` - ARP definitions (not available on iOS)
- `readline/readline.h` and `readline/history.h` - CLI libraries (not needed on iOS)
- `sys/kern_control.h` - Kernel control definitions (iOS has these but for kernel extensions)
- `system()` function - Not available on iOS for security reasons

## Solution
Instead of modifying `SoftEtherVPN` code, we provide stub headers in this directory that get included BEFORE system headers during compilation.

## Directory Structure
```
src/bridge/ios_include/
├── net/
│   └── if_arp.h          - ARP structure definitions
├── readline/
│   ├── readline.h        - Stub readline functions
│   └── history.h         - Stub history functions
└── sys/
    └── kern_control.h    - Kernel control stubs
```

## How It Works

### 1. Include Path Priority
The `build.zig` adds this directory to the include path BEFORE system includes:
```zig
if (is_ios) {
    // Add our iOS stub headers FIRST (before system includes)
    lib.addIncludePath(b.path("src/bridge/ios_include"));
    
    // Then add iOS SDK includes
    lib.addSystemIncludePath(.{ .cwd_relative = ios_include });
}
```

### 2. Header Guards
Each stub header uses the same header guard as the real header, so if the code includes `<net/if_arp.h>`, it gets our stub instead.

### 3. Minimal Definitions
The stubs provide only the minimal definitions needed for compilation:
- `net/if_arp.h`: Basic ARP constants and structures (not actually used in iOS client mode)
- `readline/*.h`: Empty stub functions (CLI not used on iOS)
- `sys/kern_control.h`: Basic structures (for packet_adapter_macos.c compatibility)

### 4. Platform-Specific Code
For code that can't be stubbed (like `system()` calls), we exclude those source files:
```zig
// NativeStack.c uses system() which is unavailable on iOS
const native_stack_sources = &[_][]const u8{
    "SoftEtherVPN/src/Cedar/NativeStack.c",
};

// Only compile for non-iOS platforms
if (!is_ios) {
    lib.addCSourceFiles(.{
        .files = native_stack_sources,
        .flags = c_flags,
    });
}
```

## iOS-Specific Files

### Packet Adapter
iOS uses a dedicated packet adapter:
- `src/bridge/ios/packet_adapter_ios.c` - Uses NEPacketTunnelFlow callbacks
- Different from macOS which uses utun file descriptors

### Build Configuration
- **Target**: `aarch64-ios` (device), `aarch64-ios-simulator` or `x86_64-ios-simulator`
- **SDK Path**: Automatically detected from Xcode
- **Defines**: `-DUNIX_IOS -DTARGET_OS_IPHONE=1`

## Files NOT Modified
✅ **No changes to `SoftEtherVPN/`** - Original source code remains untouched  
✅ All compatibility is in `src/bridge/ios_include/` and `build.zig`  
✅ Clean separation between original code and iOS-specific compatibility

## What Gets Built
For iOS, we build:
- All Mayaqua library functions
- All Cedar VPN protocol code  
- iOS-specific packet adapter
- **Excluded**: NativeStack.c (server-side routing)
- **Excluded**: All server-side components

## Usage in Xcode
The built `libSoftEtherClient.a` can be linked into iOS apps. The Xcode build uses the framework created by `scripts/build_ios.sh`.

## Maintenance
When updating SoftEtherVPN:
1. ✅ No need to patch the original source
2. ✅ Stub headers continue to work
3. ⚠️ Check if new files use unavailable APIs
4. ⚠️ Update exclude list if needed

## Testing
Build for iOS:
```bash
cd /Volumes/EXT/SoftEtherDev/SoftEtherZig
zig build lib -Dtarget=aarch64-ios -Doptimize=ReleaseSafe
```

Verify output:
```bash
ls -lh zig-out/lib/libSoftEtherClient.a
file zig-out/lib/libSoftEtherClient.a
```

## Related Files
- `build.zig` - Build configuration with iOS-specific logic
- `src/bridge/ios/` - iOS-specific packet adapter
- `scripts/build_ios.sh` - Creates XCFramework for all iOS architectures
- `ios/` - Swift/Objective-C integration layer

## References
- iOS SDK: `/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk`
- Network Extension: iOS VPN framework using NEPacketTunnelProvider
- Cross-compilation: Zig's native iOS target support
