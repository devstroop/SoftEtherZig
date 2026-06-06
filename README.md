# SoftEtherZig

A SoftEther VPN client written in Zig — standalone CLI + embeddable C library for mobile/desktop apps.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Zig](https://img.shields.io/badge/Zig-0.15+-orange)](https://ziglang.org/)

## Overview

- **CLI** (`vpnclient`) — connect to any SoftEther VPN server
- **Shared lib** (`libsoftether.dylib/.so/.dll`) — embed via FFI in Flutter, Swift, Kotlin
- **Static lib** (`libsoftether.a`) — iOS/Android static linking

Implements the full SoftEther VPN protocol: HTTPS tunnel, AES-256 encryption, DHCP, ARP, keepalive, auto-reconnect.

## Why Zig?

This is a real-world rewrite of a production VPN client. Before landing on Zig we tried four other approaches in earnest. Each one hit a wall specific to this problem — embedding a TLS + protocol stack as a shared library across macOS / Linux / Windows / iOS / Android, callable from Flutter / Swift / Kotlin.

### The original C (SoftEther's own codebase)

500K+ lines, written for a Visual Studio + Cedar build system that pre-dates the modern cross-compilation story. Building for iOS arm64 + Android arm64 + Windows from the same machine meant maintaining three separate toolchains, three sets of OpenSSL static libs, and three flavours of preprocessor flags. Most of the file is `#ifdef WIN32 / #ifdef UNIX / #ifdef OS_MACOS` triplets. Adding a feature meant editing in three places and hoping CI caught the one you missed.

### Rust

C FFI works, but every `extern "C"` export needs a hand-maintained header (`cbindgen` is close but drifts), an `unsafe` block, and a `repr(C)` mirror of any struct that crosses the boundary. For a project with 20+ exports and several callback signatures, that's real overhead. Cross-compiling to Android NDK + iOS + Windows from one host requires `cargo-cross` + per-target sysroots; it works but is materially more fragile than `zig build -Dtarget=...`. Linking OpenSSL statically into a `.a` for iOS is solvable but painful. The borrow checker also fought the protocol's natural shape: long-lived sessions, raw byte buffers shared between an I/O thread and a state machine, host-supplied tunnel fds. Workable, but every fight cost time.

### Native Swift

Swift on Linux exists; Swift on Windows and Android does not, in any practical sense. Producing a `libfoo.so` that Dart FFI can `dlopen` on Android arm64 is not Swift's path. We hit the same wall every Apple-first stack hits: the moment one target is non-Apple, you're back to writing the real implementation in C-ish code and wrapping it in Swift on iOS only — at which point Swift is a UI layer, not the core.

### Go

A Go `c-shared` library is technically possible, but:
- The Go runtime ships in every binary — a ~5 MB minimum for what should be a ~500 KB component embedded in a Flutter app.
- The GC's stop-the-world pauses are visible in packet I/O timing on slower mobile hardware.
- `cgo` calls are not signal-safe; the protocol code calls OpenSSL on every packet, so the cgo boundary is hot.
- Cross-compiling cgo to Android NDK is exactly the workflow cgo was designed to make hard — you need a C toolchain *and* the Go toolchain configured for the same target. Some mobile linkers reject the generated archives.

### What Zig delivered for this specific project

- **One toolchain, every target.** `zig build -Dtarget=aarch64-ios`, `aarch64-linux-android`, `x86_64-windows-gnu`, `aarch64-macos`, all from the same Mac, no extra installs. `zig cc` is a drop-in C cross-compiler that solved our OpenSSL build pipeline too (`scripts/build_openssl_ios.sh`).
- **C interop is symmetric and zero-overhead.** Calling OpenSSL is `@cImport({ @cInclude("openssl/ssl.h"); })` and then `ssl.SSL_read(...)`. Exporting to C is one line per function: `export fn softether_connect(...) c_int`. No bindings layer, no codegen step, no drift.
- **No hidden allocator.** Every allocation in this codebase goes through an explicit `Allocator` parameter. For a long-lived background process that runs for days inside a mobile VPN extension, that predictability matters — we audited every alloc path during the iOS NetworkExtension memory-cap work.
- **Comptime replaced macros.** The original C uses preprocessor macros for endianness, packing, and protocol field tables. In Zig the same logic is `comptime` Zig — type-checked, debuggable, no separate language.
- **Binary size.** `ReleaseSmall` produces a ~500 KB `libsoftether.so` for arm64-android — small enough that Flutter app bundles don't notice it.
- **No runtime.** No GC pauses, no async scheduler, no surprise threads. Predictable enough to ship inside an iOS Network Extension where the kernel will SIGKILL the process if it crosses memory or CPU limits.

The kicker: Zig is pre-1.0 and we still found it the *most* stable foundation for this particular problem shape. Andrew Kelley's [2026 interview on Zig's "worse is better" philosophy](https://youtu.be/iqddnwKF8HQ) explains why that's not the contradiction it looks like.

## Platform Support

| Platform | Build Target | Output | Status |
|----------|-------------|--------|--------|
| macOS (arm64) | `zig build` | CLI | ✅ |
| macOS (x86_64) | `zig build` | CLI | ✅ |
| macOS (arm64) | `zig build shared-lib` | .dylib | ✅ |
| macOS (x86_64) | `zig build shared-lib` | .dylib | ✅ |
| iOS (arm64) | `zig build static-lib -Dtarget=aarch64-ios` | .a | ✅ |
| Linux (x86_64) | `zig build` | CLI | ✅ |
| Linux (x86_64) | `zig build shared-lib` | .so | ✅ |
| Windows (x64) | `zig build` | CLI | ✅ |
| Windows (x64) | `zig build shared-lib` | .dll | ✅ |
| Android (arm64-v8a) | `zig build shared-lib -Dtarget=aarch64-linux-android` | .so | ✅ |
| Android (armeabi-v7a) | `zig build shared-lib -Dtarget=arm-linux-androideabi` | .so | ✅ |

## Prerequisites

- **Zig 0.15+** — [ziglang.org/download](https://ziglang.org/download/)
- **OpenSSL 3.x**:
  - macOS: `brew install openssl@3`
  - Linux: `apt install libssl-dev` / `dnf install openssl-devel`
  - iOS/Android: Pre-built in `deps/` (committed)

## Quick Start

### CLI

```bash
zig build --release=fast
sudo ./zig-out/bin/vpnclient \
  --server vpn.example.com --hub VPN \
  --user myuser --password mypassword
```

Or with a config file: `sudo ./zig-out/bin/vpnclient --config config.json`

### macOS — Shared Library

```bash
zig build shared-lib
# zig-out/lib/libsoftether.dylib
```

### Linux — Shared Library

```bash
zig build shared-lib
# zig-out/lib/libsoftether.so
```

### iOS — Static Library

```bash
zig build static-lib -Dtarget=aarch64-ios
# zig-out/lib/libsoftether.a
```

### Android — Shared Library

```bash
# arm64-v8a
zig build shared-lib \
  -Dtarget=aarch64-linux-android \
  --libc android-libc-aarch64-linux-android.conf
# zig-out/lib/libsoftether.so

# armeabi-v7a
zig build shared-lib \
  -Dtarget=arm-linux-androideabi \
  --libc android-libc-arm-linux-androideabi.conf
# zig-out/lib/libsoftether.so
```

### Windows — Shared Library

```bash
zig build shared-lib -Dtarget=x86_64-windows
# zig-out/bin/libsoftether.dll
```

### C API Usage

```c
#include "softether.h"

softether_client_t client = softether_create(
    "vpn.example.com", 443, "VPN", "user", "pass");
softether_set_encryption(client, true);
softether_connect(client);
softether_run_data_loop(client);  // blocking, dedicated thread
softether_disconnect(client);
softether_destroy(client);
```

Full header: [`include/softether.h`](include/softether.h)

## CLI Options

```
USAGE:
  vpnclient [OPTIONS]

CONNECTION:
  -s, --server <HOST>      VPN server hostname
  -p, --port <PORT>        Port (default: 443)
  -H, --hub <HUB>          Virtual hub name
  -u, --user <USER>        Username
  -P, --password <PASS>    Password

OPTIONS:
  -c, --config <FILE>      Load JSON config
  -f, --full-tunnel        Route all traffic through VPN
  -d, --daemon             Run in background
  -h, --help               Show help
  -v, --version            Show version
```

Priority: CLI args > env vars > config file.

## Configuration

```json
{
  "server": "vpn.example.com",
  "port": 443,
  "hub": "VPN",
  "username": "myuser",
  "password": "mypassword",
  "default_route": true,
  "use_encrypt": true,
  "use_compress": false,
  "mtu": 1400,
  "reconnect": { "enabled": true, "max_attempts": 10 }
}
```

Schema: [`config.schema.json`](config.schema.json)

### Environment Variables

```bash
export SOFTETHER_SERVER="vpn.example.com"
export SOFTETHER_HUB="VPN"
export SOFTETHER_USER="myuser"
export SOFTETHER_PASSWORD="mypassword"
sudo -E ./zig-out/bin/vpnclient
```

## C API Reference

### Lifecycle

| Function | Description |
|----------|-------------|
| `softether_create()` | Password auth client |
| `softether_create_anonymous()` | Anonymous auth client |
| `softether_create_certificate()` | Certificate auth client |
| `softether_destroy()` | Free client + resources |

### Connection

| Function | Description |
|----------|-------------|
| `softether_connect()` | Connect to server (blocking) |
| `softether_disconnect()` | Disconnect |
| `softether_run_data_loop()` | Packet I/O loop (blocking, dedicated thread) |
| `softether_request_stop()` | Signal data loop to exit |

### State & Stats

| Function | Description |
|----------|-------------|
| `softether_get_state()` | Current connection state |
| `softether_is_connected()` | Connected? |
| `softether_get_stats()` | Bytes, packets, uptime |
| `softether_get_assigned_ip()` | DHCP-assigned VPN IP |
| `softether_get_gateway_ip()` | VPN gateway IP |

### Configuration (call before connect)

| Function | Description |
|----------|-------------|
| `softether_set_encryption()` | Enable/disable payload encryption |
| `softether_set_compression()` | Enable/disable compression |
| `softether_set_verify_certificate()` | TLS cert verification |
| `softether_set_default_route()` | Route all traffic through VPN |
| `softether_set_mtu()` | Set MTU |
| `softether_set_reconnect()` | Configure auto-reconnect |

### Mobile Integration

| Function | Description |
|----------|-------------|
| `softether_set_tunnel_fd()` | Pass TUN fd from OS (iOS/Android) |
| `softether_set_event_callback()` | Register state change callback |
| `softether_version()` | Version string |

## Architecture

```
┌──────────────────────────────────────┐
│  CLI (src/main.zig)                  │
│  FFI (src/ffi.zig)                   │
├──────────────────────────────────────┤
│  VPN Client (src/client/)            │
│  • State machine · Reconnect logic   │
│  • DHCP/ARP · Packet processing      │
├──────────────────────────────────────┤
│  SoftEther Protocol (src/protocol/)  │
│  • HTTPS auth (RPC)                  │
│  • Block tunnel framing · Keepalive  │
├──────────────────────────────────────┤
│  TLS/TCP Transport (src/net/)        │
│  • OpenSSL TLS 1.2/1.3               │
│  • TCP NODELAY · Non-blocking I/O    │
├──────────────────────────────────────┤
│  TUN Adapter (src/adapter/)          │
│  • macOS utun · Linux TUN            │
│  • Android/iOS fd passthru           │
└──────────────────────────────────────┘
```

## Project Structure

```
SoftEtherZig/
├── src/
│   ├── main.zig            CLI entry point
│   ├── lib.zig             Library root
│   ├── ffi.zig             22 C ABI exports
│   ├── config.zig          JSON config parser
│   ├── client/             VPN client, connection, state, events
│   ├── protocol/           Auth, RPC, tunnel, pack, watermark
│   ├── adapter/            utun, TUN, TAP, DHCP, routing
│   ├── net/                TLS, TCP, HTTP, UDP acceleration
│   ├── tunnel/             Data loop, ARP, DHCP
│   ├── crypto/             AES, SHA, HMAC, SHA-0
│   ├── session/            Session management
│   ├── app/                Daemon, signals, lifecycle
│   ├── cli/                Arg parsing, display
│   └── core/               Types, errors, IP utils
├── include/softether.h     C API header
├── deps/                   Pre-built OpenSSL for iOS/Android
├── scripts/                Build helpers
├── build.zig               Build system
├── build.zig.zon           Package manifest
└── config.*.json           Example configs + schema
```

## Building

```bash
zig build                                              # CLI (debug)
zig build --release=fast                                # CLI (release)
zig build shared-lib                                    # Shared lib
zig build static-lib -Dtarget=aarch64-ios               # iOS static lib
zig build shared-lib -Dtarget=aarch64-linux-android --libc android-libc-aarch64-linux-android.conf  # Android
zig build shared-lib -Dtarget=x86_64-windows            # Windows DLL
zig build utun-helper --release=fast                    # macOS privilege helper
zig build test                                          # Run tests
```

## Cross-Compilation

**iOS**: OpenSSL pre-built in `deps/openssl-ios/`. Rebuild with `./scripts/build_openssl_ios.sh`.

**Android**: OpenSSL pre-built in `deps/openssl-android/`. Update `android-libc.conf` with your NDK paths. Requires NDK 25+.

## Troubleshooting

### macOS Permission Denied

```bash
# Option 1: sudo
sudo ./zig-out/bin/vpnclient ...

# Option 2: privilege helper
zig build utun-helper --release=fast
sudo chown root:wheel zig-out/bin/softether-utun-helper
sudo chmod u+s zig-out/bin/softether-utun-helper
./zig-out/bin/vpnclient ...
```

### Connection Timeout

Verify reachability: `ping vpn.example.com && nc -zv vpn.example.com 443`

### Auth Failed

Check username, password, hub name, and that the account is enabled on server.

## Security

- TLS 1.2+ with OpenSSL 3.x
- Prefer environment variables over CLI args for credentials
- Certificate authentication supported

## License

**Apache License 2.0.**
Copyright © Devstroop Technologies. 
See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Library-level issues, security disclosures, and protocol questions: see [CONTRIBUTING.md](CONTRIBUTING.md).

## Maintainer

Maintained by **[Devstroop Technologies](https://devstroop.com)** 

Contact: `info@devstroop.com`.

## Credits

- [SoftEther VPN Project](https://www.softether.org/) — protocol specification
- [Zig](https://ziglang.org/) — programming language
- [OpenSSL](https://www.openssl.org/) — TLS implementation
