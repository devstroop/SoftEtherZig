# SoftEtherZig - Codebase Reorganization Issues

> Status: **In Progress** | Created: 2025-12-21 | Target: Long-term maintainability

## Overview

The VPN client is **working** ✅ - this reorganization is about improving structure for long-term maintainability, not fixing bugs.

**Current Stats:**
- ~20,000 lines of pure Zig
- 173+ passing tests (added 29 new tests in refactoring)
- Working SoftEther VPN client with DHCP, full-tunnel, TLS

**Progress:**
- ✅ Phase 1 complete - core module and client type extraction
- ✅ Phase 2 complete - app layer extraction
- ✅ Phase 3 complete - tunnel module with data loop helpers
- ✅ Phase 5 complete - wrapper migration
- ✅ Phase 6 complete - library API

**Summary of Changes:**
| File | Before | After | Notes |
|------|--------|-------|-------|
| `main.zig` | ~350 lines | 117 lines | -67% |
| `vpn_client.zig` | 1718 | 1363 lines | -21% reduction |
| `src/core/` | (new) | 381 lines | ip.zig, types.zig, errors.zig, mod.zig |
| `src/app/` | (new) | 593 lines | state, signals, daemon, events, config, etc |
| `src/client/` | +3 files | +397 lines | state.zig, stats.zig, events.zig |
| `src/tunnel/` | (new) | 847 lines | dhcp.zig, arp.zig, data_loop.zig, mod.zig |
| `src/lib.zig` | (new) | 122 lines | Public library API |
| `src/session/wrapper.zig` | (new) | 150 lines | SessionWrapper extracted |
| `src/adapter/wrapper.zig` | (new) | 198 lines | AdapterWrapper extracted |

---

## Issues

### Issue #1: `vpn_client.zig` is a God Object
**Priority:** High | **Effort:** 3-4 hours

**Problem:** 
[src/client/vpn_client.zig](src/client/vpn_client.zig) is ~1300+ lines containing:
- `SessionWrapper` and `AdapterWrapper` classes
- DNS resolution
- Authentication flow
- Session establishment
- Adapter configuration
- DHCP state machine
- ARP handling
- `runDataLoop()` (~400 lines)
- IP parsing/formatting utilities

**Solution:**
1. Extract `SessionWrapper` → `src/session/wrapper.zig`
2. Extract `AdapterWrapper` → `src/adapter/wrapper.zig`
3. Create `src/tunnel/` module:
   - `data_loop.zig` - main packet loop
   - `dhcp_handler.zig` - DHCP state machine
   - `arp_handler.zig` - ARP resolution
4. Extract client events → `src/client/events.zig`
5. Extract state machine → `src/client/state.zig`
6. Extract statistics → `src/client/stats.zig`

---

### Issue #2: `main.zig` Mixes Application Concerns
**Priority:** Medium | **Effort:** 2-3 hours

**Problem:**
[src/main.zig](src/main.zig) contains:
- `AppState` struct
- Signal handling
- Event handling
- Config building
- Daemon run loop
- Interactive mode
- Password hash generation

**Solution:**
Create `src/app/` directory:
```
src/app/
├── mod.zig
├── state.zig          # AppState
├── signals.zig        # Signal handling
├── daemon.zig         # Daemon mode loop
├── interactive.zig    # Interactive shell mode
└── password_hash.zig  # Hash generation utility
```

Reduce `main.zig` to:
```zig
const app = @import("app/mod.zig");
pub fn main() !void {
    try app.run();
}
```

---

### Issue #3: Configuration Scattered Across Files
**Priority:** Medium | **Effort:** 2 hours

**Problem:**
- [src/config.zig](src/config.zig) - ConnectionConfig, JsonConfig, file loading, merging
- [src/cli/config_manager.zig](src/cli/config_manager.zig) - ConfigManager, ConfigFile
- Overlap and duplication between them

**Solution:**
Create consolidated `src/config/` module:
```
src/config/
├── mod.zig
├── types.zig       # All config structs
├── builder.zig     # ConfigBuilder pattern
├── loader.zig      # JSON file loading
├── merger.zig      # Priority merging (CLI > env > file)
└── validation.zig  # Config validation
```

---

### Issue #4: IP Utilities Duplicated
**Priority:** Low | **Effort:** 1 hour

**Problem:**
IP parsing/formatting exists in multiple places:
- `vpn_client.zig`: `parseIpv4()`, `formatIpv4Buf()`
- `adapter/route.zig`: `parseIpv4()`, `formatIpv4()`
- `client/mod.zig`: `formatIp()`

**Solution:**
Create `src/core/ip.zig` with single implementations:
```zig
pub fn parseIpv4(str: []const u8) ?u32
pub fn formatIpv4(ip: u32, buffer: []u8) []const u8
pub fn ipToBytes(ip: u32) [4]u8
pub fn bytesToIp(bytes: [4]u8) u32
```

---

### Issue #5: Missing Shared Core Module
**Priority:** Low | **Effort:** 1-2 hours

**Problem:**
Common types and utilities scattered:
- [src/types.zig](src/types.zig) - minimal (IpAddress, SessionStats)
- [src/errors.zig](src/errors.zig) - VpnError only
- No central place for shared constants

**Solution:**
Create `src/core/` module:
```
src/core/
├── mod.zig
├── types.zig      # IpAddress, MacAddress, etc.
├── errors.zig     # All error types
├── ip.zig         # IP utilities
└── constants.zig  # Protocol constants, magic numbers
```

---

### Issue #6: No Library vs Application Separation
**Priority:** Low | **Effort:** 1 hour

**Problem:**
No clear public API for library consumers. Everything is mixed together.

**Solution:**
Create `src/lib.zig` as library root:
```zig
// Public API for library users
pub const VpnClient = @import("client/mod.zig").VpnClient;
pub const ClientConfig = @import("config/mod.zig").ClientConfig;
pub const ConfigBuilder = @import("config/mod.zig").ConfigBuilder;
pub const ClientState = @import("client/mod.zig").ClientState;
pub const ClientEvent = @import("client/mod.zig").ClientEvent;
```

---

## Implementation Plan

### Phase 1: Quick Wins (1-2 hours) ✅ COMPLETE
- [x] Create `src/core/` with `ip.zig`, `types.zig`, `errors.zig`
- [x] Create `src/client/events.zig`
- [x] Create `src/client/state.zig`
- [x] Create `src/client/stats.zig`
- [x] Update `vpn_client.zig` to import from new modules
- [x] All tests passing, release build verified

### Phase 2: App Layer (2-3 hours) ✅ COMPLETE
- [x] Create `src/app/` directory
- [x] Extract `AppState` → `app/state.zig`
- [x] Extract signals → `app/signals.zig`
- [x] Extract daemon loop → `app/daemon.zig`
- [x] Extract interactive mode → `app/interactive.zig`
- [x] Extract password hash → `app/password_hash.zig`
- [x] Create `app/events.zig` for VPN event handling
- [x] Create `app/config.zig` for config building
- [x] Simplify `main.zig` (now ~100 lines vs ~350)

### Phase 3: Tunnel Extraction (3-4 hours) ✅ COMPLETE
- [x] Create `src/tunnel/` directory
- [x] Create `tunnel/dhcp.zig` - DhcpState, DhcpConfig, DhcpHandler
- [x] Create `tunnel/arp.zig` - ArpHandler with MAC learning
- [x] Create `tunnel/mod.zig` - Module exports
- [x] Create `tunnel/data_loop.zig` - DataLoopState, helpers, packet utilities
- [x] Integrate tunnel helpers into vpn_client.zig runDataLoop()
- [x] Use formatIpForLog, parseIpv4Header, wrapIpInEthernet, processArpReply/Request
- [x] vpn_client.zig reduced from 1481 → 1363 lines (-8%)

### Phase 4: Config Consolidation (2 hours)
- [ ] Create `src/config/` directory
- [ ] Consolidate config types
- [ ] Merge loaders

### Phase 5: Wrapper Migration (1 hour) ✅ COMPLETE
- [x] Move `SessionWrapper` → `session/wrapper.zig` (150 lines)
- [x] Move `AdapterWrapper` → `adapter/wrapper.zig` (198 lines)
- [x] Update imports in vpn_client.zig
- [x] vpn_client.zig reduced from 1718 → 1481 lines (-14%)

### Phase 6: Library API ✅ COMPLETE
- [x] Create `src/lib.zig` with public API exports
- [x] Document library usage with example code

---

## Target Structure

```
src/
├── lib.zig                    # Library public API
├── main.zig                   # Entry point only
├── app/                       # Application layer
│   ├── mod.zig
│   ├── state.zig
│   ├── signals.zig
│   ├── daemon.zig
│   ├── interactive.zig
│   └── password_hash.zig
├── cli/                       # CLI (unchanged)
├── client/                    # Client facade (simplified)
│   ├── mod.zig
│   ├── vpn_client.zig         # Simplified facade
│   ├── events.zig
│   ├── state.zig
│   └── stats.zig
├── config/                    # Configuration (consolidated)
│   ├── mod.zig
│   ├── types.zig
│   ├── builder.zig
│   ├── loader.zig
│   └── validation.zig
├── tunnel/                    # Data channel (new)
│   ├── mod.zig
│   ├── data_loop.zig
│   ├── dhcp_handler.zig
│   └── arp_handler.zig
├── protocol/                  # Protocol (unchanged)
├── session/                   # Session (+ wrapper)
├── adapter/                   # Adapter (+ wrapper)
├── net/                       # Network (unchanged)
├── crypto/                    # Crypto (unchanged)
└── core/                      # Shared utilities (new)
    ├── mod.zig
    ├── types.zig
    ├── errors.zig
    ├── ip.zig
    └── constants.zig
```

---

## Success Criteria

- [x] All tests still pass (verified)
- [x] VPN client still works (release build verified)
- [ ] No file > 500 lines - `vpn_client.zig` now 1363 lines (needs further decomposition)
- [x] Clear module boundaries (core, app, tunnel, client, session, adapter)
- [ ] `vpn_client.zig` < 300 lines - deferred (currently 1363, down from ~1757)
- [x] `main.zig` < 150 lines (currently 117)

---

## Notes

- **Don't break what works** - refactor incrementally
- **Run tests after each change** - `zig build test`
- **Test VPN connection** after major changes
- Keep backward compatibility for any public APIs
