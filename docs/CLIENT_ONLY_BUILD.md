# Client-Only Build Documentation

## Overview

This document describes the client-only build of SoftEtherZig, which removes all server-related code from the SoftEtherVPN Cedar library to create a lightweight VPN client.

## Why Client-Only?

1. **Smaller Binary Size**: ~3.5MB client-only vs larger full build
2. **Cleaner Code Base**: Easier to understand and maintain
3. **Zig Porting**: Simplified migration path to pure Zig
4. **Security**: Reduced attack surface (no server code)
5. **Mobile Deployment**: Better suited for iOS/Android

## Files Removed from Build (32 Cedar files)

### Server Core
- `Admin.c` - Server admin RPC (1031 RPC functions)
- `Server.c` - VPN server core
- `Hub.c` - Virtual hub management
- `Sam.c` - Server authentication module
- `Listener.c` - Connection listeners

### Bridge/Link
- `Bridge.c` - Bridge adapter
- `BridgeUnix.c` - Unix bridge implementation
- `Link.c` - Cascade/Link connections

### Protocols (Server-side)
- `Interop_OpenVPN.c` - OpenVPN protocol support
- `Interop_SSTP.c` - SSTP protocol support

### IPsec Stack
- `IPsec.c` - IPsec core
- `IPsec_EtherIP.c` - EtherIP protocol
- `IPsec_IKE.c` - IKE key exchange
- `IPsec_IkePacket.c` - IKE packet handling
- `IPsec_IPC.c` - IPsec IPC
- `IPsec_L2TP.c` - L2TP protocol
- `IPsec_PPP.c` - PPP protocol
- `IPsec_Win7.c` - Windows 7 IPsec

### NAT/Routing
- `Nat.c` - NAT tables
- `SecureNAT.c` - Secure NAT
- `Layer3.c` - Layer 3 routing
- `NativeStack.c` - Native IP stack

### Other Server Features
- `Database.c` - Server database
- `DDNS.c` - Dynamic DNS client
- `AzureClient.c` - Azure VPN relay client
- `AzureServer.c` - Azure VPN relay server
- `Radius.c` - RADIUS authentication
- `EtherLog.c` - Ethernet logging
- `WebUI.c` - Web administration interface

### Command/Admin Interface
- `Command.c` - CLI (202 Ps* server commands removed)
- `Console.c` - Console interface
- `Remote.c` - Remote administration

## Code Removed from Source Files

### Protocol.c
- Deleted `ServerAccept()` function (~2741 lines)
- This was the main server-side connection handler
- Replaced with stub that returns `false`

### Session.c
- Deleted `NewServerSession()` function
- Deleted `NewServerSessionEx()` function (~155 lines)
- These created server-side session objects
- Replaced with stubs that return `NULL`

## Files Retained (Client Core)

### Mayaqua (Core Library) - 18 files
- `Mayaqua.c` - Main library
- `Memory.c` - Memory management
- `Str.c` - String operations
- `Object.c` - Object system
- `OS.c` - OS abstraction
- `FileIO.c` - File I/O
- `Kernel.c` - Thread/sync primitives
- `Network.c` - Network stack
- `TcpIp.c` - TCP/IP utilities
- `Encrypt.c` - Encryption (OpenSSL wrapper)
- `Secure.c` - Security utilities
- `Pack.c` - Data serialization
- `Cfg.c` - Configuration
- `Table.c` - Table management
- `Tracking.c` - Debug tracking
- `Microsoft.c` - Windows compatibility (stubs on Unix)
- `Internat.c` - Internationalization
- `Unix.c` - Unix-specific code

### Cedar (Client Core) - 11 files
- `Cedar.c` - Cedar initialization
- `Client.c` - VPN client core
- `Protocol.c` - VPN protocol (client-side only)
- `Connection.c` - Connection management
- `Session.c` - Session management (client-side only)
- `Account.c` - Account management
- `Logging.c` - Logging (client-side only)
- `Virtual.c` - Virtual LAN
- `NullLan.c` - Null LAN adapter
- `UdpAccel.c` - UDP acceleration
- `WaterMark.c` - Watermark data

## Stub Implementation

The file `src/c/client_stubs.c` (~281 lines) provides stub implementations for:

1. **Hub/Server stubs**: `GetHub`, `ReleaseHub`, etc.
2. **RPC stubs**: `RpcCall`, `StartRpcServer`, etc.
3. **Listener stubs**: `NewListenerEx2`, `StopListener`, etc.
4. **IPC stubs**: `NewIPCByParam`, `IPCSendIPv4`, etc.
5. **Bridge stubs**: `OpenEth`, `EthGetCancel`, etc.
6. **Authentication stubs**: `SamAuthUserByPassword`, etc.
7. **Layer3 stubs**: `L3GetNextPacket`, etc.

These stubs either return `NULL`/`0`/`false` or are empty void functions.
They should never be called at runtime in a properly functioning client.

## Build Configuration

```zig
// build.zig - Client-only C sources
const c_sources = &[_][]const u8{
    // Integration layer
    "src/c/softether_bridge.c",
    "src/c/stubs.c",
    "src/c/macos/tick64_macos.c",
    "src/c/macos/packet_adapter_macos.c",
    "src/c/util/logging.c",
    "src/c/util/security_utils.c",

    // Mayaqua - 18 core files
    "SoftEtherVPN/src/Mayaqua/Mayaqua.c",
    // ... (see full list above)

    // Cedar - 11 client files
    "SoftEtherVPN/src/Cedar/Cedar.c",
    "SoftEtherVPN/src/Cedar/Client.c",
    // ... (see full list above)

    // Stubs for removed server functions
    "src/c/client_stubs.c",
};
```

## Verification

```bash
# Build client-only binary
zig build

# Check binary
ls -lh zig-out/bin/vpnclient  # ~3.5MB

# Test functionality
./zig-out/bin/vpnclient --help
```

## Impact on Zig Porting

With server code removed:

1. **Reduced Surface**: ~30K lines to port instead of ~70K
2. **Cleaner Dependencies**: No server-only type references
3. **Simpler Testing**: Can test client functions in isolation
4. **Incremental Migration**: Can replace one function at a time

## Warning

⚠️ **This build breaks the original SoftEtherVPN repository.**

The modified files (`Protocol.c`, `Session.c`) are incompatible with the
upstream SoftEtherVPN server. This is intentional - we are creating a
client-only fork for Zig porting purposes.

Do not submit these changes back to the SoftEtherVPN project.

## Next Steps

1. Continue removing server references from remaining client code
2. Replace stubs with Zig implementations
3. Eventually remove Mayaqua dependency entirely
