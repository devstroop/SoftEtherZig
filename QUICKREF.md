# Quick Reference - SoftEther VPN Zig Wrapper

## Build Commands

```bash
# Build everything
zig build

# Run demo
zig build run

# Clean build artifacts
rm -rf zig-out .zig-cache
```

## Project Structure

```
SoftEtherZig/
├── build.zig              # Build configuration
├── src/
│   ├── main.zig           # Library entry point
│   ├── cli.zig            # CLI client
│   ├── client.zig         # VPN client logic
│   ├── config.zig         # Configuration types
│   ├── errors.zig         # Error handling
│   ├── types.zig          # Common types
│   ├── ffi.zig            # C FFI interface
│   ├── c.zig              # C imports
│   └── bridge/
│       ├── softether_bridge.c     # Main C bridge layer
│       ├── unix_bridge.c          # POSIX OS abstraction
│       ├── packet_adapter_*.c     # Platform-specific TUN/TAP
│       └── tick64_*.c             # Platform-specific timing
├── SoftEtherVPN_Stable/   # Git submodule (SoftEther C source)
│   └── src/               # SoftEther VPN core
├── zig-out/bin/
│   └── vpnclient          # Compiled executable
├── README.md
└── docs/                  # Documentation
```

## C Shim API

### Initialization
```c
VpnErrorCode vpn_init(void);
void vpn_cleanup(void);
const char* vpn_get_version(void);
```

### Client Management
```c
VpnClientHandle vpn_client_create(void);
void vpn_client_destroy(VpnClientHandle handle);
```

### Connection
```c
VpnErrorCode vpn_connect(VpnClientHandle handle, const VpnConnectionParams* params);
void vpn_disconnect(VpnClientHandle handle);
VpnStatus vpn_get_status(VpnClientHandle handle);
```

### Statistics
```c
VpnErrorCode vpn_get_stats(VpnClientHandle handle, VpnSessionStats* stats);
const char* vpn_get_last_error(VpnClientHandle handle);
```

## Zig FFI Wrapper API

### Types
```zig
const shim = @import("shim_client.zig");

// Status enum
shim.VpnShim.Status: .disconnected, .connecting, .connected, .err

// Error codes
shim.VpnShim.ErrorCode: .ok, .init_failed, .connect_failed, etc.

// Auth types
shim.VpnShim.AuthType: .anonymous, .password, .cert
```

### Functions
```zig
// Initialize
_ = shim.VpnShim.init();
defer shim.VpnShim.cleanup();

// Create client
const client = shim.VpnShim.clientCreate();
defer shim.VpnShim.clientDestroy(client);

// Connect
const params = shim.VpnShim.ConnectionParams{ /* ... */ };
const result = shim.VpnShim.connect(client, &params);

// Status & Stats
const status = shim.VpnShim.getStatus(client);
var stats: shim.VpnShim.SessionStats = undefined;
_ = shim.VpnShim.getStats(client, &stats);

// Error message
const err_msg = shim.VpnShim.getLastError(client);
```

## Complete Example

```zig
const std = @import("std");
const shim = @import("shim_client.zig");

pub fn main() !void {
    // Init
    if (shim.VpnShim.init() != .ok) return error.InitFailed;
    defer shim.VpnShim.cleanup();
    
    // Create
    const client = shim.VpnShim.clientCreate() orelse return error.CreateFailed;
    defer shim.VpnShim.clientDestroy(client);
    
    // Connect
    const params = shim.VpnShim.ConnectionParams{
        .server_name = "vpn.example.com".ptr,
        .server_port = 443,
        .hub_name = "DEFAULT".ptr,
        .account_name = "user".ptr,
        .auth_type = .password,
        .username = "user".ptr,
        .password = "pass".ptr,
        .cert_path = "".ptr,
        .key_path = "".ptr,
        .use_encrypt = true,
        .use_compress = true,
    };
    
    if (shim.VpnShim.connect(client, &params) != .ok) {
        std.debug.print("Failed: {s}\n", .{shim.VpnShim.getLastError(client)});
        return error.ConnectFailed;
    }
    
    // Use connection
    std.debug.print("Connected! Status: {s}\n", 
        .{@tagName(shim.VpnShim.getStatus(client))});
    
    // Disconnect
    shim.VpnShim.disconnect(client);
}
```

## Next Development Steps

### Add Real SoftEther Integration
1. Edit `src/shim/vpn_shim.c`
2. Add SoftEther includes at top
3. Replace stub implementations with actual calls:
   - `vpn_init()` → call `InitMayaqua()`, `InitCedar()`
   - `vpn_client_create()` → call `CiNewClient()`
   - `vpn_connect()` → call SoftEther connection functions
4. Test incrementally

### Extend Shim API
Add to `vpn_shim.h`:
```c
// Certificate management
VpnErrorCode vpn_load_certificate(const char* cert_path, const char* key_path);

// Connection callbacks
typedef void (*VpnEventCallback)(VpnClientHandle, VpnEventType, void* data);
void vpn_set_event_callback(VpnClientHandle, VpnEventCallback);

// Advanced stats
VpnErrorCode vpn_get_detailed_stats(VpnClientHandle, VpnDetailedStats*);
```

## Troubleshooting

### Build Errors
```bash
# Clean everything
rm -rf zig-out .zig-cache

# Rebuild
zig build
```

### Zig Version Issues
```bash
# Check version (requires 0.15.x)
zig version

# Update if needed
brew upgrade zig
```

### C Compilation Issues
The shim layer is deliberately minimal to avoid C compilation problems.
If you add SoftEther includes and get errors, consider:
1. Compile with `-Wno-error` flags
2. Wrap problematic includes in `#ifdef` guards
3. Use forward declarations instead of full includes

## Resources

- **Full Documentation**: See `SUCCESS.md`
- **Technical Decisions**: See `STATUS_UPDATE.md`
- **Progress Tracking**: See `PHASE1_PROGRESS.md`
- **Architecture Details**: See `.vscode/ZIG_ARCHITECTURE.md`

## Performance Notes

Current implementation is a **stub** for demonstration:
- Connection is simulated (no network I/O)
- Stats are generated (not real)
- All operations succeed

Real implementation will:
- Make actual network connections
- Report real statistics
- Handle errors properly
- Support all SoftEther VPN features
