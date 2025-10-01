# Patched SoftEther Headers

This directory contains patched versions of SoftEther VPN headers that fix compatibility issues with modern C compilers (Clang/Zig).

## Unix.h

**Status**: ✅ Fixed

**Issue**: The original `Unix.h` uses K&R-style function declarations (e.g., `func()` instead of `func(void)`) for functions with no parameters. This causes "conflicting types" errors when compiled with modern C compilers that enforce strict ANSI C prototypes.

**Changes Made**:
- Changed 29+ function declarations from `func()` to `func(void)`
- Fixed typo: `UnixFlush` → `UnixFileFlush`

**Functions Patched**:
- `UnixInit()` → `UnixInit(void)`
- `UnixFree()` → `UnixFree(void)`
- `UnixGetTick()` → `UnixGetTick(void)`
- `UnixThreadId()` → `UnixThreadId(void)`
- `UnixIsSupportedOs()` → `UnixIsSupportedOs(void)`
- ... and 24 more functions

## Unix.c

**Status**: ⚠️ Patched but Not Used (bool type conflict)

**Issue**: The original `Unix.c` has K&R-style function definitions for 3 functions that conflict with the patched header declarations.

**Changes Made**:
- Line 364: `UnixIsInVmMain()` → `UnixIsInVmMain(void)`
- Line 399: `UnixIsInVm()` → `UnixIsInVm(void)`
- Line 1189: `UnixIsSupportedOs()` → `UnixIsSupportedOs(void)`

**Remaining Issue**:
Even though both the header and implementation now use `(void)`, there's a deeper `bool` type conflict. SoftEther defines `bool` as `unsigned int` in MayaType.h, but when Unix.c is compiled, the preprocessor sometimes expands `bool` to C99's `_Bool` type. This causes "conflicting types" errors because:
- Header declaration: `bool UnixIsInVmMain(void);` → expands to `unsigned int UnixIsInVmMain(void);`
- C definition: `bool UnixIsInVmMain(void) {` → expands to `_Bool UnixIsInVmMain(void) {`

The C99 `<stdbool.h>` header is being included somewhere before SoftEther's bool typedef, causing the type mismatch. Attempts to prevent stdbool.h with `-D__bool_true_false_are_defined=1` did not resolve the issue.

**Current Workaround**:
Using `unix_stubs.c` which provides stub implementations with proper ANSI C signatures and SoftEther's bool type. The patched Unix.c remains in the repository for reference but is not currently used in the build.

**Files Status**:
1. ✅ `Unix.h` - Patched and working (29 function declarations fixed)
2. ⚠️ `Unix.c` - Patched but not used (3 function definitions fixed, but bool type conflicts prevent usage)

## How the Patched Header is Used

The build system (`build.zig`) adds `src/bridge` to the include path **before** `../src`, so when code includes `<Mayaqua/Unix.h>`, it finds this patched version first.

```zig
// In build.zig:
demo.addIncludePath(b.path("src/bridge"));  // Patched headers here
demo.addIncludePath(b.path("../src"));       // Original SoftEther source
```

## License

This patched file is derived from SoftEther VPN source code and is subject to the same Apache License 2.0. See the file header for full license text.
