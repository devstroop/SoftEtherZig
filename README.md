# SoftEtherZig

A SoftEther VPN client written in Zig — standalone CLI + embeddable C library for mobile/desktop apps.

[![CI](https://github.com/devstroop/SoftEtherZig/actions/workflows/ci.yml/badge.svg)](https://github.com/devstroop/SoftEtherZig/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/devstroop/SoftEtherZig)](https://github.com/devstroop/SoftEtherZig/releases/latest)
[![Zig](https://img.shields.io/badge/Zig-0.15+-orange)](https://ziglang.org/)
[![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows%20%7C%20iOS%20%7C%20Android-informational)](#platforms)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Overview

- **CLI** (`vpnclient`) — connect to any SoftEther VPN server
- **Shared lib** (`libsoftether.dylib/.so/.dll`) — embed via FFI in Flutter, Swift, Kotlin
- **Static lib** (`libsoftether.a`) — iOS/Android static linking

Implements the full SoftEther VPN protocol: HTTPS tunnel, AES-256-CBC session encryption, block compression (zlib), keepalive, multi-TCP connections, half-connection mode, UDP acceleration, cluster redirect support, DHCP/ARP, DHCPv6, route management.

## Features

| Feature | Status |
|---------|--------|
| Password / anonymous / X.509 certificate auth | ✅ |
| TLS 1.2/1.3 via OpenSSL 3.x | ✅ |
| AES-256-CBC session encryption | ✅ |
| zlib block compression | ✅ |
| Multi-TCP connections (1–32 parallel sockets) | ✅ |
| Half-connection mode (split TX/RX) | ✅ |
| UDP acceleration (RUDP) | ✅ |
| Cluster redirect (server farm transparent failover) | ✅ |
| SOCKS5 / HTTP proxy tunnel | ✅ |
| DHCPv4 + DHCPv6 client | ✅ |
| ARP handling | ✅ |
| Full-tunnel / split-tunnel / custom routes | ✅ |
| Static IP assignment (bypass DHCP) | ✅ |
| Route self-healing (stale route cleanup) | ✅ |
| Data-plane health check | ✅ |
| Interactive CLI shell | ✅ |
| Daemon mode | ✅ |

## Output Targets

| Platform | Build Target | Output | Status |
|----------|-------------|--------|--------|
| macOS (aarch64) | `zig build` | CLI | ✅ |
| macOS (x86_64) | `zig build` | CLI | ✅ |
| macOS (aarch64) | `zig build shared-lib` | .dylib | ✅ |
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
sudo ./zig-out/bin/vpnclient connect \
  --server vpn.example.com --hub VPN \
  --user myuser --password mypassword
```

Or with a config file: `sudo ./zig-out/bin/vpnclient connect --config config.json`

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

## CLI

### Subcommands

```text
USAGE:
  vpnclient <subcommand> [OPTIONS]

SUBCOMMANDS:
  help                    Show help message
  version                 Show version information
  passhash                Generate a SoftEther password hash
  cleanup                 Clean up stale VPN routes left by crashes
  connect                 Connect to a VPN server
```

### Connect Options

```text
CONNECTION:
  -c, --config <FILE>      Load JSON config file
  -s, --server <HOST>      VPN server hostname
  -p, --port <PORT>        Port (default: 443)
  -H, --hub <HUB>          Virtual hub name
  -u, --user <USER>        Username
  -P, --password <PASS>    Password
  --password-hash <HASH>   Pre-hashed password (base64)

ENCRYPTION / COMPRESSION:
  --use-encrypt / --no-encrypt    AES-256-CBC (default: on)
  --use-compress / --no-compress   zlib (default: off)

ADVANCED:
  --half-connection        Split TX/RX onto separate TCP connections
  --no-half-connection     Single bidirectional connection (default)
  --qos / --no-qos         QoS traffic shaping (default: on)
  --udp-accel              Enable UDP acceleration (RUDP)
  --max-connections <N>    Parallel TCP connections 1–32 (default: 1)
  --mtu <BYTES>            MTU size (default: 1400)
  --ip-version <4|6>       IP protocol version preference (default: both)
  --verbose                Emit diagnostic throughput / queue stats
  --profile                Emit profiling data
  -k, --skip-tls-verify    Skip TLS certificate verification (INSECURE)

TIMEOUTS:
  --connect-timeout <MS>   Connection timeout (default: 30000)
  --read-timeout <MS>      Read timeout (default: 60000)
  --keepalive-interval <MS> Keepalive interval (default: 10000)

RECONNECTION:
  --reconnect / --no-reconnect  Auto-reconnect (default: off)
  --max-retries <N>        Max attempts, 0 = infinite (default: 0)

PROXY:
  --proxy <URL>            HTTP/SOCKS proxy (e.g. socks5://127.0.0.1:1080)

ROUTING:
  --ipv4-include <CIDR>     Networks to route through VPN (split-tunnel)
  --ipv4-exclude <CIDR>     Networks to exclude from VPN tunnel
  --ipv6-include <CIDR>     IPv6 networks to include
  --ipv6-exclude <CIDR>     IPv6 networks to exclude
  --dns-server <IP>         DNS server (repeatable)
  (Use config file or FFI for: default_route, accept_pushed_routes, custom_routes)

STATIC IP (bypass DHCP):
  --static-ipv4 <ADDR>      Static IPv4 address
  --static-ipv4-netmask     Static IPv4 netmask
  --static-ipv4-gateway     Static IPv4 gateway
  --static-ipv6 <ADDR>      Static IPv6 address
  --static-ipv6-prefix      Static IPv6 prefix length
  --static-ipv6-gateway     Static IPv6 gateway

RUNTIME:
  -d, --daemon             Run in background
  -i, --interactive        Run in interactive shell mode
  --log-level <LEVEL>      silent|error|warn|info|debug|trace
```

Priority: CLI args > env vars > config file.

### Passhash

```bash
vpnclient passhash --user myuser --password mypassword
# Output: base64-encoded SHA-1 hash
```

### Cleanup

Remove stale routing state left by a killed or crashed session:

```bash
sudo vpnclient cleanup
```

## Configuration

```json
{
  "server": "vpn.example.com",
  "port": 443,
  "hub": "VPN",
  "username": "myuser",
  "password": "mypassword",
  "use_encrypt": true,
  "use_compress": false,
  "half_connection": false,
  "qos": true,
  "udp_accel": false,
  "max_connections": 1,
  "mtu": 1400,
  "ip_version": null,
  "routing": {
    "default_route": true,
    "accept_pushed_routes": true,
    "enable_custom_routes": false,
    "ipv4_include": null,
    "ipv4_exclude": null,
    "ipv6_include": null,
    "ipv6_exclude": null
  },
  "static_ip": {
    "ipv4_address": null,
    "ipv4_netmask": null,
    "ipv4_gateway": null,
    "ipv6_address": null,
    "ipv6_prefix": null,
    "ipv6_gateway": null,
    "dns_servers": ["8.8.8.8", "8.8.4.4"]
  },
  "reconnect": {
    "enabled": false,
    "max_attempts": 0
  },
  "proxy": null,
  "connect_timeout_ms": 30000,
  "read_timeout_ms": 60000,
  "keepalive_interval_ms": 10000,
  "log_level": "info"
}
```

Schema: [`config.schema.json`](config.schema.json)

### Environment Variables

```bash
export SOFTETHER_SERVER="vpn.example.com"
export SOFTETHER_HUB="VPN"
export SOFTETHER_USER="myuser"
export SOFTETHER_PASSWORD="mypassword"
sudo -E ./zig-out/bin/vpnclient connect
```

Full env var list: see [CONFIG.md](CONFIG.md#env-vars-reference).

## C API Reference

### Lifecycle

| Function | Description |
|----------|-------------|
| `softether_create()` | Password auth client |
| `softether_create_anonymous()` | Anonymous auth client |
| `softether_create_certificate()` | Certificate (X.509) auth client |
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
| `softether_get_assigned_mask()` | DHCP-assigned subnet mask |
| `softether_get_gateway_ip()` | VPN gateway IP |
| `softether_get_effective_server_ip()` | Actual server IP (post-cluster-redirect) |

### Configuration (call before connect)

| Function | Description |
|----------|-------------|
| `softether_set_encryption()` | Enable/disable AES-256-CBC |
| `softether_set_compression()` | Enable/disable zlib compression |
| `softether_set_verify_certificate()` | TLS cert verification |
| `softether_set_default_route()` | Full-tunnel or split-tunnel |
| `softether_set_mtu()` | Set MTU |
| `softether_set_reconnect()` | Configure auto-reconnect |
| `softether_set_max_connections()` | Parallel TCP connections (1–32) |
| `softether_set_half_connection()` | Split TX/RX connections |
| `softether_set_qos()` | QoS prioritization |
| `softether_set_udp_acceleration()` | UDP acceleration (RUDP) |
| `softether_set_connect_timeout()` | Connection timeout (ms) |
| `softether_set_read_timeout()` | Read timeout (ms) |
| `softether_set_keepalive_interval()` | TCP keepalive (ms) |
| `softether_set_ip_version()` | 0=both, 4=IPv4, 6=IPv6 |
| `softether_set_proxy()` | HTTP / SOCKS5 proxy |

### Routing (call before connect)

| Function | Description |
|----------|-------------|
| `softether_set_accept_pushed_routes()` | Accept server-pushed routes |
| `softether_set_enable_custom_routes()` | Enable split-tunnel includes |
| `softether_set_ipv4_include()` | CIDR networks to include |
| `softether_set_ipv4_exclude()` | CIDR networks to exclude |
| `softether_set_ipv6_include()` | IPv6 CIDR includes |
| `softether_set_ipv6_exclude()` | IPv6 CIDR excludes |

### Mobile Integration

| Function | Description |
|----------|-------------|
| `softether_set_tunnel_fd()` | Pass TUN fd from OS (iOS/Android) |
| `softether_replace_tun_fd()` | Replace TUN fd at runtime (Android VpnService recreation) |
| `softether_set_event_callback()` | Register state change callback |
| `softether_set_log_callback()` | Host-provided log sink |
| `softether_set_bind_interface()` | Bind TLS to physical interface (iOS NE) |
| `softether_set_tcp_dial_callback()` | Host-provided TCP dial (iOS NE bypass) |

### Diagnostics

| Function | Description |
|----------|-------------|
| `softether_version()` | Library version string |
| `softether_set_log_callback()` | External log sink (iOS NE, custom routing) |

## Architecture

```
┌──────────────────────────────────────────┐
│  CLI (src/main.zig)                      │
│  FFI (src/ffi.zig)                       │
├──────────────────────────────────────────┤
│  Cedar — VPN Protocol Layer              │
│  ┌────────────────────────────────────┐  │
│  │  client/   Auth, state machine,    │  │
│  │            multi-conn, reconnect   │  │
│  │  protocol/ SoftEther wire protocol │  │
│  │  session/  Encryption keys, state  │  │
│  │  tunnel/   Data loop, ARP, DHCPv4  │  │
│  │            DHCPv6                  │  │
│  └────────────────────────────────────┘  │
├──────────────────────────────────────────┤
│  Mayaqua — Platform Abstraction Layer    │
│  ┌────────────────────────────────────┐  │
│  │  encrypt/   AES, SHA, HMAC, SHA-0 │  │
│  │  kernel/    IP utils, types, errs  │  │
│  │  network/   TLS, TCP, HTTP, DNS   │  │
│  │             cache, SOCKS, UDP accel│  │
│  └────────────────────────────────────┘  │
├──────────────────────────────────────────┤
│  TUN Adapter (src/adapter/)              │
│  • macOS utun · Linux TUN · Windows TAP  │
│  • Android/iOS fd passthrough            │
│  • Route management · Self-healing       │
└──────────────────────────────────────────┘
```

## Project Structure

```
SoftEtherZig/
├── src/
│   ├── main.zig              CLI entry point
│   ├── lib.zig               Library root / public Zig API
│   ├── ffi.zig               43 C ABI exports
│   ├── config.zig            JSON config parser
│   ├── cedar/                VPN protocol layer
│   │   ├── main.zig          Module root
│   │   ├── client/           Auth, state machine, multi-conn
│   │   ├── protocol/         SoftEther wire protocol, auth, pack, RPC
│   │   ├── session/          Encryption keys, session state
│   │   └── tunnel/           Data loop, ARP, DHCPv4, DHCPv6
│   ├── mayaqua/              Platform abstraction layer
│   │   ├── main.zig          Module root
│   │   ├── encrypt/          AES, SHA-1, SHA-256, HMAC, SHA-0
│   │   ├── kernel/           IP utils, protocol types, errors
│   │   └── network/          TLS, TCP, HTTP, DNS cache, SOCKS, UDP accel
│   ├── adapter/              TUN/TAP, routing, DHCP, route healing
│   ├── app/                  Daemon, signals, lifecycle, events
│   └── cli/                  Arg parsing, display, config, shell
├── include/softether.h       C API header (366 lines, 43 exports)
├── deps/                     Pre-built OpenSSL for iOS/Android + zlib
├── scripts/                  Build helpers + Python diagnostics
├── docs/
│   ├── rca/                  Root Cause Analysis documents
│   └── CODEBASE_REORGANIZATION.md
├── test/
│   ├── integration/          Handshake fixture, DHCPv6 wire tests
│   └── live/                 Live test placeholder
├── config.*.json             Example configs + schema (17 files)
├── build.zig                 Build system
├── build.zig.zon             Package manifest (v0.2.0)
├── CHANGELOG.md              Changelog
├── CONFIG.md                 Config field reference
├── CONTRIBUTING.md           Contribution guide
└── QUICKSTART.md             Platform build guide
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

**Android**: OpenSSL pre-built in `deps/openssl-android/`. Update `android-libc-*.conf` with your NDK paths. Requires NDK 25+.

## iOS NetworkExtension

Use with `NEPacketTunnelProvider`:

1. Build `libsoftether.a` and link it in your extension target
2. Call `softether_set_bind_interface("en0")` before `softether_connect()` — without this, the kernel NECP layer routes the extension's own VPN-server connection through the tunnel about to be established, causing ECONNREFUSED.
3. Register a TCP dial callback via `softether_set_tcp_dial_callback()` — the host calls `NEProvider.createTCPConnection()` (bypassing the tunnel) and bridges bytes through a socketpair.
4. Pass the utun fd from `NEPacketTunnelProvider` via `softether_set_tunnel_fd()`.
5. Register a log callback via `softether_set_log_callback()` — stderr capture races with extension teardown; use `os_log` instead.

## Troubleshooting

### macOS Permission Denied

```bash
# Option 1: sudo
sudo ./zig-out/bin/vpnclient connect ...

# Option 2: privilege helper
zig build utun-helper --release=fast
sudo chown root:wheel zig-out/bin/softether-utun-helper
sudo chmod u+s zig-out/bin/softether-utun-helper
./zig-out/bin/vpnclient connect ...
```

### Stale Routes After Crash

If the VPN process is killed without a clean disconnect, stale routes may remain:

```bash
sudo vpnclient cleanup
```

This purges routes through dead utun interfaces and restores the default route if the host was left with no internet access.

### Connection Timeout

Verify reachability: `ping vpn.example.com && nc -zv vpn.example.com 443`

### Auth Failed

Check username, password, hub name, and that the account is enabled on server. Generate a proper password hash:

```bash
vpnclient passhash --user myuser --password mypassword
```

## Security

- TLS 1.2+ with OpenSSL 3.x
- AES-256-CBC session encryption
- Prefer environment variables over CLI args for credentials
- Certificate (X.509) authentication supported
- Custom external log sink available for log security

## Why Zig?

This is a real-world rewrite of a production VPN client. Before landing on Zig we tried C (SoftEther's own codebase), Rust, native Swift, and Go. Each hit a wall specific to embedding a TLS + protocol stack as a shared library across macOS / Linux / Windows / iOS / Android, callable from Flutter / Swift / Kotlin.

What Zig delivered:

- **One toolchain, every target.** `zig build -Dtarget=aarch64-ios`, `aarch64-linux-android`, `x86_64-windows-gnu`, all from the same Mac.
- **C interop is symmetric and zero-overhead.** Calling OpenSSL is `@cImport`; exporting to C is one line per function. No bindings layer, no drift.
- **No hidden allocator.** Every allocation goes through an explicit `Allocator` parameter — critical for iOS NE memory caps.
- **Comptime replaced macros.** Same logic, type-checked, debuggable.
- **Binary size.** `ReleaseSmall` produces ~500 KB `libsoftether.so` for arm64-android.
- **No runtime.** No GC pauses, no async scheduler, no surprise threads.

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
