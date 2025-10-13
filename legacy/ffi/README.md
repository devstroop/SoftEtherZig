# Legacy FFI Archive

**Archived Date**: October 13, 2025

This directory contains the archived legacy iOS FFI implementation that has been superseded by the platform-agnostic Mobile FFI.

## Contents

- `ios_ffi.c.archived` - C implementation of legacy iOS FFI (deprecated Oct 2025)
- `softether_ffi.h.archived` - Header file for legacy iOS FFI (deprecated Oct 2025)
- `ffi.zig.archived` - Incomplete Zig FFI stubs (deprecated Oct 2025)

## Why Archived?

These files were part of the original iOS-only FFI implementation that has been superseded by the platform-agnostic **Mobile FFI** (`mobile_ffi.h` / `src/ffi/mobile.zig`).

### Problems with Legacy FFI

- ❌ **iOS-only design** - Not portable to Android
- ❌ **C implementation** - `ios_ffi.c` instead of pure Zig
- ❌ **JSON-based config** - Type safety issues, parsing overhead
- ❌ **Incomplete** - `ffi.zig` contained mostly TODO stubs
- ❌ **Mixed concerns** - WorxVPN-specific extensions mixed with core API

### Mobile FFI Benefits

- ✅ **Platform-agnostic** - Works on both iOS and Android
- ✅ **Pure Zig implementation** - Better type safety and maintainability
- ✅ **Struct-based config** - No JSON parsing overhead
- ✅ **Clean, minimal API** - Only essential functions
- ✅ **Fully implemented** - No stubs or TODOs

## Migration Guide

See [`docs/FFI_MIGRATION_GUIDE.md`](../../docs/FFI_MIGRATION_GUIDE.md) for complete migration instructions.

## Deprecation Timeline

- **Created**: Early 2024 (iOS port)
- **Deprecated**: October 2025
- **Removed**: October 13, 2025 (archived for reference)

## Current Status

- **Android**: Already using Mobile FFI ✅
- **WorxVPN-iOS**: Migration in progress 🔄
- **New projects**: Must use Mobile FFI ✅

## Restoration (Emergency Only)

⚠️ **Not Recommended** - These files are archived for historical reference only. If you absolutely must restore them:

```bash
cd /Volumes/EXT/SoftEtherDev/SoftEtherZig
cp legacy/ffi/ios_ffi.c.archived src/bridge/ios_ffi.c
cp legacy/ffi/softether_ffi.h.archived include/softether_ffi.h
cp legacy/ffi/ffi.zig.archived src/ffi.zig
```

Then manually update `build.zig` to re-add the legacy library target (lines 397-458 in the old version).

**Important**: This is NOT recommended. Please migrate to `mobile_ffi.h` instead.

## Related Files

Other files that reference the legacy FFI and should be updated:

### iOS Project (WorxVPN)
- `WorxVPN-iOS/WorxVPN/Bridging/WorxVPN-Bridging-Header.h` - Change to `#include "mobile_ffi.h"`
- `WorxVPN-iOS/WorxVPNExtension/WorxVPNExtension-Bridging-Header.h` - Change to `#include "mobile_ffi.h"`
- `WorxVPN-iOS/WorxVPNExtension/PacketTunnelProvider.swift` - Refactor to use Mobile FFI API

### Documentation
- Migration guide: `docs/FFI_MIGRATION_GUIDE.md`
- iOS integration: `ios/README.md`
- Android integration: `android/README.md`

---

For questions or issues, file an issue at: https://github.com/SoftEtherUnofficial/SoftEtherZig/issues
