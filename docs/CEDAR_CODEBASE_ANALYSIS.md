# SoftEtherVPN C Codebase Analysis

## Summary

This document analyzes the SoftEtherVPN C codebase to understand what's required for a client-only build and future Zig porting.

## Current State

- **Total Cedar C files**: 40+ files
- **Lines of code**: ~216K in Cedar/, ~76K in server-only files
- **Release binary size**: 2.1MB (macOS ARM64)
- **Debug binary size**: 5.1MB (macOS ARM64)

## File Categories

### Client Core (REQUIRED) - ~60K lines
- `Cedar.c` - Core initialization
- `Client.c` - Client implementation
- `Protocol.c` - Protocol handling (includes ServerAccept - 2,747 lines)
- `Connection.c` - Connection management
- `Session.c` - Session management (includes NewServerSession)
- `Account.c` - Account configuration
- `Logging.c` - Logging system
- `Virtual.c` - Virtual network interface
- `NullLan.c` - Null LAN adapter
- `UdpAccel.c` - UDP acceleration
- `WaterMark.c` - Watermark handling

### Shared Infrastructure - ~40K lines
- `Command.c` - CLI commands (both Pc* client and Ps* server commands)
- `Console.c` - Console I/O
- `Remote.c` - Remote administration

### Server-Only Files - ~76K lines (24 files)
- `Server.c`, `Hub.c`, `Listener.c`, `Admin.c`, `Sam.c`
- `Link.c`, `SecureNAT.c`, `Bridge.c`, `BridgeUnix.c`, `Nat.c`
- `Database.c`, `DDNS.c`, `AzureClient.c`, `AzureServer.c`
- `Radius.c`, `Layer3.c`, `EtherLog.c`, `WebUI.c`
- `NativeStack.c`, `Interop_OpenVPN.c`, `Interop_SSTP.c`
- `IPsec*.c` (7 files)

### Mayaqua Core Library - ~40K lines
Required by all builds.

## Separation Challenges

### Why file-level separation fails (296 undefined symbols)

The Cedar codebase has **tight coupling** between client and server code:

1. **Protocol.c**
   - `ServerAccept()` (2,747 lines) calls functions from 10+ server files
   - `ClientConnect()` shares infrastructure with server code
   
2. **Session.c**
   - `SessionMain()` handles both client and server sessions
   - `is_server_session` flag routes to server-specific code
   - Calls `IncrementUserTraffic()`, `IncrementHubTraffic()`, etc.

3. **Command.c**
   - Contains both `Pc*` (client) and `Ps*` (server) command handlers
   - Uses `FreeRpc*`, `AdminConnect*` server admin functions

4. **Cedar.c**
   - `NewCedar()` initializes server components (Layer3, LocalBridge, etc.)
   - `CleanupCedar()` frees server resources

### Why stubbing fails (typedef conflicts)

```c
// Cedar headers forward-declare types:
typedef struct HUB HUB;
typedef struct SERVER SERVER;

// Stub files can't include headers without pulling in full definitions
// Defining stubs causes "typedef redefinition" errors
```

## Recommended Zig Porting Strategy

### Key Insight: Bridge API Pattern

The Zig code **only uses 30 functions** from `softether_bridge.h`:

```c
// Core lifecycle
vpn_bridge_init()
vpn_bridge_cleanup()
vpn_bridge_create_client()
vpn_bridge_free_client()

// Connection
vpn_bridge_configure()
vpn_bridge_connect()
vpn_bridge_disconnect()
vpn_bridge_get_status()

// Information
vpn_bridge_get_connection_info()
vpn_bridge_get_dhcp_info()
vpn_bridge_get_device_name()
vpn_bridge_get_learned_ip()
vpn_bridge_get_gateway_mac()

// Configuration
vpn_bridge_set_ip_version()
vpn_bridge_set_max_connection()
vpn_bridge_set_static_ipv4()
vpn_bridge_set_static_ipv6()
vpn_bridge_set_dns_servers()
```

### Porting Phases

**Phase 1: Packet Adapter (DONE)**
- macOS TUN implementation in `packet_adapter_macos.c`
- L2↔L3 translation done in C

**Phase 2: Bridge Layer**
- Reimplement `vpn_bridge_*` functions in Zig
- Still use C for Cedar internals

**Phase 3: Protocol Layer**
- Port VPN protocol handling to Zig
- Focus on client-side only (`ClientConnect`, not `ServerAccept`)

**Phase 4: Core Reduction**
- Remove unused Mayaqua functions
- Replace with Zig equivalents

## Build Configuration

Current `build.zig` includes all files for maximum compatibility:

```zig
// Cedar - Client core (REQUIRED)
"SoftEtherVPN/src/Cedar/Cedar.c",
"SoftEtherVPN/src/Cedar/Client.c",
// ... 11 more files

// Cedar - Server files (included due to tight coupling)
"SoftEtherVPN/src/Cedar/Admin.c",
"SoftEtherVPN/src/Cedar/Hub.c",
// ... 26 more files
```

**LTO (Link-Time Optimization)** removes unused code in release builds, resulting in a 2.1MB binary despite including all source files.

## Metrics

| Metric | Value |
|--------|-------|
| Total C source files | 58 |
| Server-only files | 24 |
| Lines in Cedar/ | ~216K |
| Lines in server-only | ~76K |
| Lines in Mayaqua/ | ~40K |
| Bridge API functions | ~30 |
| Release binary | 2.1MB |
| Debug binary | 5.1MB |

## Conclusion

The Cedar codebase cannot be easily separated at the file level due to tight coupling. The recommended approach is:

1. **Keep all C files** for now (LTO handles dead code)
2. **Port incrementally** through the bridge API layer
3. **Focus on client code paths** only
4. **Replace C internals** with Zig equivalents over time

This provides a working VPN client today while enabling gradual migration to Zig.
