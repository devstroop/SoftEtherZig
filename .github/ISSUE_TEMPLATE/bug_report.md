---
name: Bug Report
about: Report a bug in libsoftether (build, runtime, protocol, FFI)
labels: ["bug"]
---

## Description

A clear and concise description of the bug.

## Steps to Reproduce

1. Build with: `zig build shared-lib -Dtarget=...`
2. Run: `...`
3. Observe: `...`

## Expected Behavior

What you expected to happen.

## Actual Behavior

What actually happened. Include full error output if applicable.

## Environment

| Field | Value |
|-------|-------|
| OS / Arch | e.g. `macOS 14.5 ARM64`, `Windows x64`, `Ubuntu 22.04 x86_64` |
| Zig version | e.g. `0.15.2` (`zig version`) |
| OpenSSL version | e.g. `3.3.1` (`openssl version`) |
| Build command | e.g. `zig build shared-lib -Dtarget=aarch64-linux-android` |
| Build mode | `Debug` / `ReleaseFast` |
| Client type | CLI (`vpnclient`) / FFI (Flutter / Dart) |

## Logs / Backtrace

If the bug involves a crash or unexpected error, include relevant logs:

```
# CLI: run with verbose output
# FFI: check host app logs (Logcat, Console.app, flutter run output)
```

## Server Info (if connection bug)

| Field | Value |
|-------|-------|
| Server version | e.g. `SoftEther VPN Server 4.43 build 9799` |
| Server OS | |
| Auth type | Password / Certificate / Anonymous |
| Connection mode | Full / Half-duplex |

## Additional Context

Any other context, screenshots, or packet captures.
