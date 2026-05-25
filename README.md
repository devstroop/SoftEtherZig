# SoftEtherZig

A SoftEther VPN client written in Zig — standalone CLI + embeddable C library for mobile/desktop apps.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Zig](https://img.shields.io/badge/Zig-0.15+-orange)](https://ziglang.org/)

## Overview

- **CLI** (`vpnclient`) — connect to any SoftEther VPN server
- **Shared lib** (`libsoftether.dylib/.so/.dll`) — embed via FFI in Flutter, Swift, Kotlin
- **Static lib** (`libsoftether.a`) — iOS/Android static linking

Implements the full SoftEther VPN protocol: HTTPS tunnel, AES-256 encryption, DHCP, ARP, keepalive, auto-reconnect.

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
  --libc android-libc.conf
# zig-out/lib/libsoftether.so

# armeabi-v7a
zig build shared-lib \
  -Dtarget=arm-linux-androideabi \
  --libc android-libc.conf
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
  "encryption": true,
  "compression": false,
  "mtu": 1486,
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
| `softether_set_full_tunnel()` | Route all traffic through VPN |
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
zig build shared-lib -Dtarget=aarch64-linux-android --libc android-libc.conf  # Android
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

Apache License 2.0

## Credits

- [SoftEther VPN Project](https://www.softether.org/) — protocol specification
- [Zig](https://ziglang.org/) — programming language
- [OpenSSL](https://www.openssl.org/) — TLS implementation
