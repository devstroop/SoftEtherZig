# SoftEtherZig

A SoftEther VPN client written in Zig — standalone CLI + embeddable C library for mobile/desktop apps.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Zig](https://img.shields.io/badge/Zig-0.15+-orange)](https://ziglang.org/)

## What This Is

- **CLI VPN client** (`vpnclient`) — connect to any SoftEther VPN server from the terminal
- **Shared library** (`libsoftether.dylib/.so/.dll`) — embed in Flutter, Swift, Kotlin, or any FFI-capable app
- **Static library** (`libsoftether.a`) — for iOS/Android where dynamic linking isn't available

Implements the SoftEther VPN protocol: HTTPS-based tunnel with AES-256 encryption, DHCP, ARP, keepalive, and auto-reconnect.

## Platform Support

| Platform | Build Target | Output | Status |
|----------|-------------|--------|--------|
| **macOS** arm64/x64 | `zig build` | CLI + .dylib | ✅ Working |
| **iOS** arm64 | `zig build static-lib -Dtarget=aarch64-ios` | .a | ✅ Working |
| **Android** arm64 | `zig build shared-lib -Dtarget=aarch64-linux-android` | .so | ✅ Working |
| **Linux** x64/arm64 | `zig build` | CLI + .so | ✅ Working |
| **Windows** x64 | `zig build -Dtarget=x86_64-windows` | CLI + .dll | 🚧 Planned |

## Prerequisites

- **Zig 0.15+**: [ziglang.org/download](https://ziglang.org/download/)
- **OpenSSL 3.x**:
  - macOS: `brew install openssl@3`
  - Linux: `apt install libssl-dev` / `dnf install openssl-devel`
  - iOS/Android: Pre-built in `deps/` (committed to repo)

## Quick Start — CLI

```bash
# Build
zig build --release=fast

# Connect
sudo ./zig-out/bin/vpnclient \
  --server vpn.example.com \
  --hub VPN \
  --user myuser \
  --password mypassword

# Or use a config file
sudo ./zig-out/bin/vpnclient --config config.json
```

See [CLI Options](#cli-options) and [Configuration](#configuration) below.

## Quick Start — Library (FFI)

### macOS (shared lib)

```bash
zig build shared-lib
# Output: zig-out/lib/libsoftether.dylib
```

### iOS (static lib)

```bash
zig build static-lib -Dtarget=aarch64-ios
# Output: zig-out/lib/libsoftether.a
```

### Android (shared lib)

```bash
zig build shared-lib \
  -Dtarget=aarch64-linux-android \
  --libc android-libc.conf
# Output: zig-out/lib/libsoftether.so
```

### C API Usage

```c
#include "softether.h"

// Create client
softether_client_t client = softether_create(
    "vpn.example.com", 443, "VPN", "user", "pass");

// Configure
softether_set_encryption(client, true);
softether_set_mtu(client, 1400);
softether_set_event_callback(client, my_callback, NULL);

// Connect (blocking)
int err = softether_connect(client);

// Run data loop in separate thread
softether_run_data_loop(client);

// Cleanup
softether_disconnect(client);
softether_destroy(client);
```

Full C header: [`include/softether.h`](include/softether.h)

## CLI Options

```
USAGE:
  vpnclient [OPTIONS]

CONNECTION:
  -s, --server <HOST>      VPN server hostname (required)
  -p, --port <PORT>        VPN server port (default: 443)
  -H, --hub <HUB>          Virtual hub name (required)
  -u, --user <USER>        Username (required)
  -P, --password <PASS>    Password (required)

OPTIONS:
  -c, --config <FILE>      Load configuration from JSON file
  -f, --full-tunnel        Route all traffic through VPN
  -d, --daemon             Run in background
  -h, --help               Show this help
  -v, --version            Show version
```

**Priority:** CLI args > Environment variables > Config file

## Configuration

### Minimal Config

```json
{
  "server": "vpn.example.com",
  "hub": "VPN",
  "username": "myuser",
  "password": "mypassword"
}
```

### Full Config

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

Schema: [`config.schema.json`](config.schema.json) · Examples: [`config.example.json`](config.example.json), [`config.minimal.json`](config.minimal.json)

### Environment Variables

```bash
export SOFTETHER_SERVER="vpn.example.com"
export SOFTETHER_HUB="VPN"
export SOFTETHER_USER="myuser"
export SOFTETHER_PASSWORD="mypassword"
sudo -E ./zig-out/bin/vpnclient
```

## C API Reference

22 exported symbols. See [`include/softether.h`](include/softether.h) for full documentation.

### Lifecycle

| Function | Description |
|----------|-------------|
| `softether_create()` | Create client with password auth |
| `softether_create_anonymous()` | Create client with anonymous auth |
| `softether_create_certificate()` | Create client with certificate auth |
| `softether_destroy()` | Free client and all resources |

### Connection

| Function | Description |
|----------|-------------|
| `softether_connect()` | Connect to server (blocking) |
| `softether_disconnect()` | Disconnect from server |
| `softether_run_data_loop()` | Run packet I/O loop (blocking, call from dedicated thread) |
| `softether_request_stop()` | Signal data loop to exit (thread-safe) |

### State & Stats

| Function | Description |
|----------|-------------|
| `softether_get_state()` | Get current state enum |
| `softether_is_connected()` | Check if connected |
| `softether_get_stats()` | Fill stats struct (bytes, packets, uptime) |
| `softether_get_assigned_ip()` | Get DHCP-assigned VPN IP |
| `softether_get_gateway_ip()` | Get VPN gateway IP |

### Configuration (call before connect)

| Function | Description |
|----------|-------------|
| `softether_set_encryption()` | Enable/disable payload encryption |
| `softether_set_compression()` | Enable/disable compression |
| `softether_set_verify_certificate()` | Enable/disable TLS cert verification |
| `softether_set_full_tunnel()` | Route all traffic through VPN |
| `softether_set_mtu()` | Set MTU size |
| `softether_set_reconnect()` | Configure auto-reconnect |

### Mobile Integration

| Function | Description |
|----------|-------------|
| `softether_set_tunnel_fd()` | Pass TUN file descriptor from OS (iOS/Android) |
| `softether_set_event_callback()` | Register state change callback |
| `softether_version()` | Get version string |

## Architecture

```
┌─────────────────────────────────────────┐
│      CLI (src/main.zig)                 │
│      FFI (src/ffi.zig)                  │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│       VPN Client (src/client/)          │
│  • State machine · Reconnect logic      │
│  • DHCP/ARP · Packet processing         │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│     SoftEther Protocol (src/protocol/)  │
│  • HTTPS auth (RPC)                     │
│  • Block-based tunnel framing           │
│  • Keepalive · Watermark                │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│     TLS / TCP Transport (src/net/)      │
│  • OpenSSL TLS 1.2/1.3                  │
│  • TCP NODELAY · Non-blocking I/O       │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│     TUN Adapter (src/adapter/)          │
│  • macOS utun (with privilege helper)   │
│  • Linux TUN · Android/iOS fd passthru  │
│  • Windows TAP (planned)                │
└─────────────────────────────────────────┘
```

## Project Structure

```
SoftEtherZig/
├── src/
│   ├── main.zig                 # CLI entry point
│   ├── lib.zig                  # Library root
│   ├── ffi.zig                  # C ABI exports (22 symbols)
│   ├── config.zig               # JSON config parsing
│   ├── client/
│   │   ├── vpn_client.zig       # Main VPN client
│   │   ├── connection.zig       # Connection management
│   │   ├── packet_processor.zig # Ethernet frame handling
│   │   ├── state.zig            # State machine
│   │   ├── stats.zig            # Connection statistics
│   │   └── events.zig           # Event system
│   ├── protocol/
│   │   ├── auth.zig             # HTTPS authentication
│   │   ├── rpc.zig              # RPC message encoding
│   │   ├── tunnel.zig           # Data tunnel framing
│   │   ├── pack.zig             # Binary pack/unpack
│   │   ├── softether_protocol.zig
│   │   └── watermark.zig        # Protocol watermark
│   ├── adapter/
│   │   ├── utun.zig             # macOS utun device
│   │   ├── utun_escalate.zig    # macOS privilege escalation
│   │   ├── utun_helper_main.zig # Privileged helper binary
│   │   ├── tun_linux.zig        # Linux TUN device
│   │   ├── fd_adapter.zig       # FD-based adapter (mobile)
│   │   ├── tap_windows.zig      # Windows TAP (planned)
│   │   ├── dhcp.zig             # DHCP client
│   │   ├── route.zig            # Route management
│   │   └── wrapper.zig          # Platform adapter wrapper
│   ├── net/
│   │   ├── tls.zig              # OpenSSL TLS wrapper
│   │   ├── socket.zig           # TCP socket
│   │   ├── http.zig             # HTTP for auth
│   │   ├── net.zig              # Network utilities
│   │   └── udp_accel.zig        # UDP acceleration
│   ├── tunnel/
│   │   ├── data_loop.zig        # Packet I/O loop
│   │   ├── arp.zig              # ARP responder
│   │   └── dhcp.zig             # DHCP handling
│   ├── crypto/
│   │   ├── cipher.zig           # AES encryption
│   │   ├── hash.zig             # SHA/HMAC
│   │   ├── sha0.zig             # SHA-0 (SoftEther compat)
│   │   └── crypto.zig           # Crypto utilities
│   ├── session/                 # Session management
│   ├── app/                     # App lifecycle, daemon, signals
│   ├── cli/                     # CLI arg parsing, display, shell
│   └── core/                    # Shared types, errors, IP utils
├── include/
│   └── softether.h              # C API header
├── deps/
│   ├── openssl-ios/             # Pre-built OpenSSL 3.6.0 for iOS arm64
│   └── openssl-android/         # Pre-built OpenSSL 3.6.0 for Android arm64
├── scripts/
│   └── build_openssl_ios.sh     # Rebuild OpenSSL for iOS
├── build.zig                    # Build system
├── build.zig.zon                # Package manifest
├── android-libc.conf            # NDK sysroot paths for Android cross-compilation
├── config.example.json          # Full config example
├── config.minimal.json          # Minimal config
└── config.schema.json           # JSON schema for config validation
```

## Building

```bash
# Debug
zig build

# Release (recommended for production)
zig build --release=fast

# Shared library (macOS/Linux/Windows)
zig build shared-lib

# Static library (iOS)
zig build static-lib -Dtarget=aarch64-ios

# Android shared library (requires NDK)
zig build shared-lib -Dtarget=aarch64-linux-android --libc android-libc.conf

# macOS privilege helper (for utun without sudo)
zig build utun-helper --release=fast

# Run tests
zig build test
```

## Cross-Compilation

### iOS

OpenSSL is pre-built in `deps/openssl-ios/`. To rebuild:

```bash
./scripts/build_openssl_ios.sh
```

### Android

OpenSSL is pre-built in `deps/openssl-android/`. The `android-libc.conf` file points to NDK sysroot paths — update paths if your NDK location differs.

Required: Android NDK 25+ installed at `~/Library/Android/sdk/ndk/`.

## Troubleshooting

### Permission Denied (macOS)

TUN devices require root. Either use sudo or the privilege helper:

```bash
# Option 1: sudo
sudo ./zig-out/bin/vpnclient ...

# Option 2: privilege escalation helper
zig build utun-helper --release=fast
sudo chown root:wheel zig-out/bin/softether-utun-helper
sudo chmod u+s zig-out/bin/softether-utun-helper
./zig-out/bin/vpnclient ...
```

### Connection Timeout

1. Verify server is reachable: `ping vpn.example.com`
2. Check port is open: `nc -zv vpn.example.com 443`
3. Confirm hub name matches server config

### Authentication Failed

- Verify username/password and hub name
- Ensure the account is enabled on the SoftEther server

### Android: App Feels Slow

If using the library in a Flutter app, avoid calling FFI functions on the main thread. The `softether_get_stats()`, `softether_get_state()`, etc. are fast but can cause jank if polled too frequently with full UI rebuilds in between.

## Security

- TLS 1.2+ with OpenSSL 3.x
- Passwords can be passed via environment variables (recommended over CLI args)
- Certificate authentication supported (`softether_create_certificate()`)

## License

Apache License 2.0

## Credits

- [SoftEther VPN Project](https://www.softether.org/) — protocol specification
- [Zig](https://ziglang.org/) — programming language
- [OpenSSL](https://www.openssl.org/) — TLS implementation
