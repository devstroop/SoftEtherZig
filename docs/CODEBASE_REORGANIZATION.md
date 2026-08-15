# Codebase Reorganization Proposal

> **Date:** 2026-06-18  
> **Based on:** SoftEtherVPN C source structure, Ghostty Zig best practices, current codebase analysis  
> **Target:** Zig 0.15.2 (no 0.16.0 migration)

---

## 1. Current State Analysis

### 1.1 Current Zig Project Layout (`libsoftether/src/`)

```
src/
├── adapter/       (11 files, ~3,200 lines) — Platform TUN/TAP + routing
├── app/           (8 files)               — App lifecycle, signals, daemon
├── cli/           (5 files, ~2,000 lines) — CLI interface
├── client/        (10 files, ~5,800 lines) — Client orchestration ← TOO LARGE
├── core/          (4 files)               — IP utils, types, errors
├── crypto/        (4 files, ~900 lines)   — SHA-0, hash, AES-CBC
├── net/           (7 files, ~3,500 lines) — Socket, TLS, HTTP, DNS, UDP
├── protocol/      (7 files, ~4,800 lines) — SoftEther protocol tunnel/auth/pack
├── session/       (4 files, ~2,000 lines) — Session state + encryption
├── tunnel/        (5 files, ~1,500 lines) — ARP, DHCP, data loop
├── config.zig     (436 lines)             — Config parsing
├── errors.zig     (60 lines)              — Error types
├── ffi.zig        (982 lines)             — C ABI exports
├── lib.zig        (118 lines)             — Module exports
├── main.zig      (190 lines)              — Entry point
└── types.zig      (82 lines)              — Type definitions
```

**Total:** ~67 files, ~28,000-30,000 lines Zig

### 1.2 Problem Files (Need Splitting)

| File | Lines | Problem |
|------|-------|---------|
| `client/vpn_client.zig` | 2,787 | Single file does: config, state machine, data loop, diagnostics, reconnect, routing |
| `protocol/tunnel.zig` | 1,542 | Tunnel framing + compression + keepalive blended together |
| `protocol/softether_protocol.zig` | 1,548 | 4-step handshake + auth + protocol negotiation in one file |
| `adapter/utun.zig` | 1,211 | utun device + packet builders + packet queue mixed |
| `adapter/route.zig` | 994 | IPv4 + IPv6 + heal + sync in one file |
| `net/tls.zig` | 949 | TLS connect + socket options + config in one file |
| `session/session.zig` | 1,156 | Session state + key derivation + encryption + queue |
| `ffi.zig` | 982 | C ABI for everything — no separation |

### 1.3 Reference: SoftEtherVPN C Source Organization

```
SoftEtherVPN/src/
├── Mayaqua/        (20 .c files, ~93,000 lines) — PLATFORM ABSTRACTION LAYER
│   ├── Network.c   (25,448 lines) — Socket I/O, DNS, HTTP, RUDP, TCP/UDP
│   ├── Microsoft.c (15,763 lines) — Windows OS abstraction
│   ├── Encrypt.c   (7,360 lines) — All crypto: SHA-0/1, AES, RC4, RSA, DH
│   ├── Pack.c      (2,573 lines) — Pack/Value serialization
│   ├── Kernel.c    (2,450 lines) — Threading, timers, process
│   ├── Memory.c    (5,219 lines) — Custom allocators, buffers
│   └── TcpIp.c     (4,734 lines) — Protocol header parsing
│
├── Cedar/          (61 .c files, ~216,000 lines) — VPN PROTOCOL LAYER
│   ├── Connection.c  (3,682 lines) — TCP/TLS connection lifecycle
│   ├── Session.c     (2,500 lines) — Session state machine
│   ├── Protocol.c    (10,103 lines) — Wire protocol negotiation
│   ├── Virtual.c     (10,317 lines) — Virtual hub L2 switch
│   ├── Client.c      (11,172 lines) — Client core
│   ├── Server.c      (11,127 lines) — Server core
│   ├── Hub.c         (7,550 lines) — Hub management
│   ├── Admin.c       (15,113 lines) — RPC admin protocol
│   ├── Command.c     (23,955 lines) — CLI command handler
│   ├── Encrypt.c     — Session-layer encryption (RC4)
│   └── UdpAccel.c    — UDP acceleration
│
├── vpnclient/      — Client executable entry point
├── vpnserver/      — Server executable entry point
└── vpncmd/         — CLI entry point
```

**Key architectural insight:** The C code has a strict two-layer separation:
- **Mayaqua** = OS abstraction + low-level library (no VPN logic)
- **Cedar** = VPN protocol + business logic (no OS-specific code)
- **Executables** = thin entry points that link both

### 1.4 Reference: Ghostty Zig Structure (for best practices)

```
ghostty/src/
├── main.zig               (dispatcher) — Routes to entrypoint based on build config
├── Surface.zig            (6,036 lines) — Largest file, but single concern
├── terminal/              (55+ files)   — Terminal emulation
│   ├── main.zig                          — Module facade (re-exports)
│   ├── Terminal.zig / Screen.zig         — Core types
│   ├── Parser.zig / ansi.zig / csi.zig   — Protocol parsers (separated by concern)
│   └── kitty/ / tmux/ / osc/ / apc/     — Sub-protocol directories
├── renderer/              (3 backends)  — Metal, OpenGL, WebGL
├── apprt/                 (3 runtimes)  — GTK, embedded, browser
├── os/                    (30+ files)   — Platform-specific, selected via comptime
├── config/                (20+ files)   — Config parsing split by concern
├── termio/                (9 files)     — Terminal I/O, exec, threading
├── cli/                   (25+ files)   — Command implementations, one per command
└── lib/ / datastruct/ / unicode/ / simd/ — Pure utility libraries
```

**Key Ghostty patterns to adopt:**

1. **`main.zig` facade in every module** — `pub const Foo = @import("Foo.zig");` — clean API surface
2. **One concern per file** — max 500-800 lines per file; 6,036 lines is their outlier
3. **backend/pattern for platform-specific** — separate subdirectory per platform backend
4. **`build_config.zig`** — central comptime build options, prevents `@import("build_options")` scattering
5. **Tests co-located** — `test { refAllDecls(@This()); }` in every module facade
6. **Module naming** — `PascalCase.zig` for types, `snake_case.zig` for utilities, `main.zig` for facades

---

## 2. Proposed Reorganization Map

### 2.1 Mayaqua-equivalent Foundation Layer

Create a Mayaqua equivalent as the bottom layer: pure utilities, no VPN logic.

| Current File(s) | Proposed Module | Splits Into | C Equivalent |
|-----------------|----------------|-------------|-------------|
| `net/socket.zig` | `mayaqua/network.zig` | Keep as-is, plus extract | `Network.c` |
| `net/tls.zig` | `mayaqua/network/` | `socket.zig`, `tls.zig`, `dns.zig` | Part of `Network.c` |
| `crypto/*` | `mayaqua/encrypt/` | `hash.zig`, `cipher.zig`, `sha0.zig`, `aes.zig` | `Encrypt.c` |
| `protocol/pack.zig` | `mayaqua/pack.zig` | Keep as-is | `Pack.c` |
| `core/` | `mayaqua/kernel/` | `ip.zig`, `memory.zig`, `time.zig`, `thread.zig` | `Kernel.c` |
| `adapter/route.zig` | `mayaqua/tcp_ip.zig` | Route logic + IP utils | `TcpIp.c` |
| `errors.zig`, `types.zig` | `mayaqua/types.zig` | Merge into one | `MayaquaType.h` |
| `-` | `mayaqua/secure.zig` | OpenSSL wrapper, certificates | `Secure.c` |
| `-` | `mayaqua/file.zig` | File I/O, config file parsing | `FileIO.c` |

**Result:** `mayaqua/` module with no VPN logic — pure OS abstraction + crypto + utilities.

### 2.2 Cedar-equivalent VPN Protocol Layer

| Current File(s) | Proposed Module | Splits Into | C Equivalent |
|-----------------|----------------|-------------|-------------|
| `client/vpn_client.zig` (2,787) | `cedar/client/` | `connect.zig`, `disconnect.zig`, `data_loop.zig`, `config.zig`, `state.zig`, `diagnostics.zig` | `Client.c` |
| `client/connection_manager.zig` | `cedar/connection.zig` | Combine with session connection mgmt | `Connection.c` |
| `session/session.zig` (1,156) | `cedar/session.zig` | Split into `session.zig` + `encrypt.zig` | `Session.c` |
| `protocol/softether_protocol.zig` (1,548) | `cedar/protocol.zig` | Split into `auth.zig`, `handshake.zig`, `pack.zig` | `Protocol.c` |
| `protocol/tunnel.zig` (1,542) | `cedar/layer2/` | `tunnel.zig`, `compression.zig`, `keepalive.zig` | Part of `Virtual.c` |
| `protocol/auth.zig` (718) | `cedar/auth.zig` | Keep (already reasonable) | `Sam.c` |
| `protocol/watermark.zig` | `cedar/watermark.zig` | Keep | `WaterMark.c` |
| `net/udp_accel.zig` | `cedar/udp_accel.zig` | Keep + fix to match C cipher | `UdpAccel.c` |
| `adapter/*` | `cedar/adapter.zig` | Platform adapter interface | Bridge/VLan |
| `tunnel/arp.zig` | `cedar/arp.zig` | Keep | Part of `Virtual.c` |
| `tunnel/dhcp.zig` | `cedar/dhcp.zig` | Keep | Part of `Virtual.c` |

**Result:** `cedar/` module with all VPN business logic, no platform-specific code.

### 2.3 Thin Entry Points

| Current File(s) | Proposed | C Equivalent |
|-----------------|----------|-------------|
| `main.zig` + `cli/` | `exec/vpnclient/main.zig` | `vpnclient/` |
| `ffi.zig` | `exec/libsoftether/main.zig` | C library build |
| `cli/args.zig` → config | `exec/vpnclient/config.zig` | CLI-specific config |
| `app/` | `exec/vpnclient/app.zig` | App lifecycle |

---

## 3. Detailed File Split Plan

### 3.1 Priority 1: Split `client/vpn_client.zig` (2,787 → ~350 facade)

**Current content breakdown (estimated):**

| Lines | Section | New File |
|-------|---------|----------|
| 1-150 | Imports + `ClientConfig` | `cedar/client/config.zig` |
| 150-210 | Config fields | `cedar/client/config.zig` |
| 210-260 | `VpnClient` struct decl | `cedar/client/vpn_client.zig` (facade) |
| 260-400 | Thread lifecycle | `cedar/client/thread.zig` |
| 400-600 | `connect()` method | `cedar/client/connect.zig` |
| 600-800 | Auth + session setup | `cedar/client/connect.zig` |
| 800-900 | `disconnect()` | `cedar/client/disconnect.zig` |
| 900-1060 | Packet I/O helpers | `cedar/client/io.zig` |
| 1060-1100 | `sendPacket()`, `receivePacket()` | `cedar/client/io.zig` |
| 1100-1210 | `processInboundBlock()` | `cedar/client/process.zig` |
| 1210-1700 | DHCP, ARP, routing | `cedar/client/routing.zig` |
| 1700-2320 | Data loop (`runDataLoop`) | `cedar/client/data_loop/` |
| 2320-2370 | Health check (disabled) | `cedar/client/diagnostics.zig` |
| 2370-2550 | DIAG stats | `cedar/client/diagnostics.zig` |
| 2550-2710 | `ClientConfigBuilder` | `cedar/client/config.zig` |
| 2710-2787 | `parseIpv6Address` | `cedar/client/routing.zig` |

### 3.2 Priority 2: Split `protocol/` modules

**`protocol/tunnel.zig` (1,542 → 3 files):**

| Lines | Content | New File |
|-------|---------|----------|
| 1-60 | TunnelConnection struct | `cedar/tunnel.zig` |
| 60-250 | Read/Write state machine | `cedar/tunnel.zig` |
| 250-430 | `receiveBlocksBatch` | `cedar/tunnel.zig` |
| 430-470 | `sendBlocksZeroCopy` | `cedar/tunnel.zig` |
| 470-550 | Compression (zlib) | `cedar/tunnel/compression.zig` |
| 550-660 | Keepalive send | `cedar/tunnel/keepalive.zig` |
| 660-end | Tests | Kept at file bottoms |

**`protocol/softether_protocol.zig` (1,548 → 4 files):**

| Lines | Content | New File |
|-------|---------|----------|
| 1-450 | Pack building helpers | `cedar/protocol/pack.zig` |
| 450-600 | Auth structs + builders | `cedar/protocol/auth.zig` |
| 600-1300 | `performHandshake` (4 auth methods) | `cedar/protocol/handshake.zig` |
| 1300-end | Server response parsing | `cedar/protocol/response.zig` |

### 3.3 Priority 3: Split `adapter/utun.zig` (1,211 → 2 files)

| Lines | Content | New File |
|-------|---------|----------|
| 1-540 | utun device (open/close/read/write) | `adapter/utun.zig` |
| 540-end | Packet builders (ARP, ND, Router Solicitation) | `adapter/packets.zig` |

### 3.4 Priority 4: Split `session/session.zig` (1,156 → 2 files)

| Lines | Content | New File |
|-------|---------|----------|
| 1-360 | Session struct, key derivation | `cedar/session.zig` |
| 360-660 | Packet queue, encrypt/decrypt | `cedar/session/encrypt.zig` |
| 660-end | Tests | Kept |

---

## 4. Consolidated Module Map (Final State)

```
src/
├── mayaqua/                        # OS abstraction + utilities (NO VPN logic)
│   ├── main.zig                    # Module facade, re-exports
│   ├── network.zig                 # Socket I/O (from net/socket.zig)
│   ├── network/
│   │   ├── tls.zig                 # TLS wrapper (from net/tls.zig)
│   │   ├── dns.zig                 # DNS cache (from net/dns_cache.zig)
│   │   └── http.zig                # HTTP client (from net/http.zig)
│   ├── encrypt.zig                 # All crypto facade
│   ├── encrypt/
│   │   ├── hash.zig                # SHA-0, SHA-1, SHA-256
│   │   ├── cipher.zig              # AES-CBC, RC4 (for session)
│   │   └── aes.zig                 # AES-128/256 GCM
│   ├── pack.zig                    # Pack/Value serialization
│   ├── kernel.zig                  # Thread, time, memory
│   ├── kernel/
│   │   ├── thread.zig              # Thread spawning
│   │   ├── time.zig                # Timers, tick
│   │   └── memory.zig              # Allocators, buffers
│   ├── tcp_ip.zig                  # IP header parsing, route utils
│   ├── file.zig                    # File I/O, config file
│   ├── types.zig                   # Shared types (from core/)
│   └── secure.zig                  # OpenSSL wrapper, certs
│
├── cedar/                          # VPN protocol logic (NO platform code)
│   ├── main.zig                    # Module facade
│   ├── client.zig                  # Client config facade
│   ├── client/
│   │   ├── config.zig              # ClientConfig + builder (~200 lines)
│   │   ├── connect.zig             # connect(), auth flow (~300 lines)
│   │   ├── disconnect.zig          # disconnect(), cleanup (~150 lines)
│   │   ├── thread.zig              # Thread lifecycle (~150 lines)
│   │   ├── io.zig                  # sendPacket, receivePacket (~200 lines)
│   │   ├── process.zig             # processInboundBlock (~200 lines)
│   │   ├── routing.zig             # DHCP+route config (~300 lines)
│   │   ├── diagnostics.zig         # DIAG, health check (~250 lines)
│   │   └── data_loop.zig           # runDataLoop (~600 lines)
│   ├── connection.zig              # TCP connection lifecycle (~500 lines)
│   ├── connection/
│   │   ├── manager.zig             # Multi-conn manager (from connection_manager.zig, ~400 lines)
│   │   └── keepalive.zig           # Keep-alive send/recv (~150 lines)
│   ├── session.zig                 # Session state, keys (~400 lines)
│   ├── session/
│   │   ├── encrypt.zig             # Session encrypt/decrypt queue (~300 lines)
│   │   └── setup.zig               # Session initialization (~200 lines)
│   ├── auth.zig                    # Auth protocol (from protocol/auth.zig, ~720 lines)
│   ├── auth/
│   │   ├── handler.zig             # Auth handler (from client/auth_handler.zig, ~520 lines)
│   │   └── password.zig            # SecurePassword, password hash (~150 lines)
│   ├── protocol.zig                # Wire protocol facade
│   ├── protocol/
│   │   ├── handshake.zig           # 4-step handshake (~600 lines)
│   │   ├── response.zig            # Server response parsing (~400 lines)
│   │   └── negotiation.zig         # Version negotiation (~200 lines)
│   ├── tunnel.zig                  # Tunnel connection (~600 lines)
│   ├── tunnel/
│   │   ├── compression.zig         # zlib compress/decompress (~150 lines)
│   │   └── keepalive.zig           # Keepalive messages (~100 lines)
│   ├── layer2.zig                  # L2 switch facade
│   ├── layer2/
│   │   ├── arp.zig                 # ARP handling (from tunnel/arp.zig, ~210 lines)
│   │   └── dhcp.zig                # DHCP client (from tunnel/dhcp.zig, ~180 lines)
│   ├── watermark.zig               # Anti-DPI watermark (from protocol/watermark.zig, ~90 lines)
│   ├── udp_accel.zig               # UDP acceleration (from net/udp_accel.zig, ~650 lines)
│   └── adapter.zig                 # Platform adapter interface
│
├── exec/                           # Entry points (thin)
│   ├── vpnclient/
│   │   ├── main.zig                # Entry point (~50 lines)
│   │   ├── config.zig              # CLI config parsing (~100 lines)
│   │   └── args.zig                # CLI arguments (from cli/args.zig, ~560 lines)
│   └── libsoftether/
│       ├── main.zig                # C library entry point (~50 lines)
│       └── ffi.zig                 # C ABI exports (from ffi.zig, ~980 lines)
│
├── cli/                            # CLI commands (if needed standalone)
│   ├── display.zig                 # Terminal display helpers (~530 lines)
│   └── shell.zig                   # Interactive shell (~500 lines)
│
└── app/                            # App lifecycle (daemon, signals)
    ├── daemon.zig                  # Daemon mode
    └── signals.zig                 # Signal handling
```

---

## 5. Adoption Strategy

### Phase 1: Structural Only (1-2 days)
No logic changes — just move files and update imports.

1. Create `mayaqua/` directory structure
2. Move `crypto/*`, `core/*`, `net/*` into `mayaqua/`
3. Create `cedar/` directory structure
4. Split `client/vpn_client.zig` into `cedar/client/` (7 files)
5. Split `protocol/tunnel.zig` into `cedar/tunnel/` (3 files)
6. Split `protocol/softether_protocol.zig` into `cedar/protocol/` (3 files)
7. Update `main.zig` in each module for re-exports
8. Update `build.zig` to include new paths
9. Verify build passes

### Phase 2: Rename and Clean (1 day)
1. Rename structs/functions to match new module names
2. Clean up dead code identified by RCAs
3. Add `test { refAllDecls(@This()); }` to each `main.zig`
4. Add `build_config.zig` for comptime build options

### Phase 3: Fix Known Issues (2-3 days)
1. Fix AES-256-CBC dead code path
2. Fix UDP acceleration cipher (RC4/ChaCha20) to match C
3. Fix password hash (SHA-0 vs SHA-256) if server compatibility needed
4. Add connection replenishment to multi-conn manager

---

## 6. Targeted File Sizes After Reorganization

| Current File | Lines | After Split | Lines |
|-------------|-------|-------------|-------|
| `client/vpn_client.zig` | 2,787 | 9 files @ 150-600 each | ~2,200 total |
| `protocol/tunnel.zig` | 1,542 | 3 files @ 100-600 each | ~1,200 total |
| `protocol/softether_protocol.zig` | 1,548 | 3 files @ 200-600 each | ~1,200 total |
| `adapter/utun.zig` | 1,211 | 2 files @ 500-700 each | ~1,200 total |
| `adapter/route.zig` | 994 | Keep | 994 (monitor) |
| `net/tls.zig` | 949 | 2 files | 949 (monitor) |
| `session/session.zig` | 1,156 | 2 files @ 400-600 each | ~1,000 total |
| `ffi.zig` | 982 | Keep | 982 (C API is large) |

**Final file count:** ~85 files (up from 67), but largest file < 1,000 lines (except `ffi.zig`).

---

## 7. Key Principles Applied

| Principle | From | How |
|-----------|------|-----|
| **Two-layer separation** | SoftEtherVPN C | `mayaqua/` (abstraction) vs `cedar/` (business logic) |
| **One concern per file** | Zig best practice | No file > 1,000 lines; target < 600 |
| **`main.zig` facade** | Ghostty | Every module has `main.zig` with `pub const` re-exports |
| **Tests co-located** | Ghostty, Zig std | `test { refAllDecls(@This()); }` in every `main.zig` |
| **Comptime build config** | Ghostty `build_config.zig` | Central comptime options, no `@import("build_options")` scattering |
| **Platform backends** | Ghostty `apprt/`, `renderer/` | Separate subdirectory per platform for complex adapters |
| **Thin entry points** | C `vpnclient/`, `vpnserver/`, `vpncmd/` | `exec/vpnclient/main.zig` is ~50 lines |
