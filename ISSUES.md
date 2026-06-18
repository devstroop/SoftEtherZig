# Issue Tracker

This document tracks minor gaps in the client implementation that are non-blocking but would improve completeness.

---

## Issue #1: Windows Build Support

**Status**: 🚧 Planned (build.zig has stubs)  
**Priority**: Medium  
**Effort**: 2-3 days  
**Labels**: `platform`, `windows`, `build-system`

### Description
Windows build is listed as "Planned" in README.md but build.zig contains only stub paths for OpenSSL detection. The TAP adapter (tap_windows.zig) is implemented but the build system doesn't properly link OpenSSL for Windows.

### Current State
```zig
// build.zig (lines ~40-50)
const win_openssl_lib: []const u8 = if (target_os == .windows) blk: {
    const candidates = [_][]const u8{
        "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD",
        "C:/Program Files/OpenSSL-Win64/lib",
    };
    // ... only checks existence, doesn't verify libssl/libcrypto
    break :blk "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD";
} else "";
```

### Tasks
- [ ] Detect OpenSSL installation path on Windows (check registry, common paths)
- [ ] Add OpenSSL library linking for Windows targets in build.zig
- [ ] Test build with `zig build -Dtarget=x86_64-windows`
- [ ] Document Windows build prerequisites in README.md
- [ ] Add CI workflow for Windows builds (optional)

### Acceptance Criteria
- `zig build -Dtarget=x86_64-windows` succeeds
- Generated `vpnclient.exe` runs on Windows 10/11
- TAP adapter properly installs and configures

### References
- `build.zig` - Windows OpenSSL detection
- `src/adapter/tap_windows.zig` - TAP adapter implementation
- `README.md` - Platform support table

---

## Issue #2: softether_app_version Not Implemented

**Status**: ❌ Not Implemented  
**Priority**: Low  
**Effort**: 30 minutes  
**Labels**: `ffi`, `c-api`

### Description
`softether_app_version()` is declared in `include/softether.h` (line 360) but never implemented in `src/ffi.zig`. Any C consumer calling this function will get a linker error. The app version string is commonly needed by Flutter/mobile hosts to display the library version alongside the app version.

### Fix
Add an `export fn softether_app_version` in `src/ffi.zig` that returns `@import("build_options").app_version` or a static `"0.2.0"` string. The header already has the declaration.

### References
- `include/softether.h` — line 360 (declaration)
- `src/ffi.zig` — where export should be added

---

## Issue #3: SOCKS Proxy Support

**Status**: ✅ Implemented  
**Priority**: Low  
**Effort**: Complete  
**Labels**: `network`, `proxy`, `feature`

### Description
SOCKS4/SOCKS5 and HTTP CONNECT proxy support has been implemented and is fully wired through the CLI (`--proxy`), config file (`"proxy"`), env var (`SOFTETHER_PROXY`), and FFI (`softether_set_proxy`).

### Implementation
- Full SOCKS4/SOCKS5 client in `src/mayaqua/network/socks.zig` (358 lines)
- Proxy URL parsing in `src/app/config.zig` (`parseProxyUrl`)
- TLS socket integration via `ProxyConfig` in `src/mayaqua/network/tls.zig`
- Auth support (username/password) for both HTTP and SOCKS5 proxies

### References
- `src/app/config.zig` - Proxy URL parser
- `src/mayaqua/network/socks.zig` - SOCKS4/5 implementation
- `src/mayaqua/network/tls.zig` - Proxy TlsSocket
- `src/ffi.zig` - `softether_set_proxy()`

---

## Issue #4: Certificate Pinning

**Status**: ❌ Not Implemented  
**Priority**: Medium  
**Effort**: 1 day  
**Labels**: `security`, `tls`, `certificate`

### Description
Currently uses OpenSSL's built-in certificate verification. Certificate pinning would allow users to specify a known server certificate fingerprint, improving security against MITM attacks (even with compromised CAs).

### Current State
```zig
// src/mayaqua/network/tls.zig
pub const TlsConfig = struct {
    verify_certificate: bool = true,
    allow_self_signed: bool = false, // Only option for self-signed certs
    // No pinning support
};
```

### Tasks
- [ ] Add `pinned_cert_hash: ?[20]u8` field to `TlsConfig`
- [ ] Implement certificate hash verification in `TlsSocket.connect()`
- [ ] Support SHA-1 and SHA-256 fingerprint formats
- [ ] Add `--pin-cert` CLI argument
- [ ] Document certificate pinning in README.md
- [ ] Add unit tests for pinning logic

### Acceptance Criteria
- User can specify pinned certificate hash
- Connection fails if server cert doesn't match pin
- Works with both DER and PEM encoded certs
- Clear error message on pin mismatch

### References
- `src/mayaqua/network/tls.zig` - TlsConfig and TlsSocket
- OpenSSL documentation: `SSL_get_peer_certificate()`, `X509_digest()`
- OWASP Certificate Pinning Guide

---

## Issue #5: IPv6 Support

**Status**: 🚧 Partial  
**Priority**: Low  
**Effort**: 2-3 days remaining  
**Labels**: `network`, `ipv6`, `feature`

### Description
DHCPv6 client (`src/cedar/tunnel/dhcpv6.zig`, 448 lines, RFC 8415) is implemented with full Solicit/Advertise/Request/Reply cycle, IA_NA/IA_TA, and RDNSS option parsing. IPv6 routing CLI flags (`--ipv6-include`, `--ipv6-exclude`, `--static-ipv6`) and FFI setters (`softether_set_ipv6_include`, `softether_set_ipv6_exclude`, `softether_set_ip_version`) exist.

Remaining gaps: IPv6 address assignment to TUN/TAP adapters (utun, tun_linux, tap_windows) not yet wired, and IPv6 default route setup not implemented.

### Remaining Tasks
- [ ] Wire IPv6 address configuration to utun on macOS/iOS
- [ ] Wire IPv6 address configuration to tun_linux
- [ ] Wire IPv6 address configuration to tap_windows
- [ ] Add IPv6 default route via VPN gateway
- [ ] Test with IPv6-only and dual-stack servers

### References
- `src/cedar/tunnel/dhcpv6.zig` - DHCPv6 client (RFC 8415)
- `src/adapter/utun.zig` - macOS/iOS utun device
- `src/adapter/tun_linux.zig` - Linux TUN device
- `src/adapter/tap_windows.zig` - Windows TAP device
- RFC 8415 - DHCPv6

---

## Issue #6: Bridge Mode (Layer 2)

**Status**: ❌ Not Implemented  
**Priority**: Low  
**Effort**: 5-10 days  
**Labels**: `feature`, `layer2`, `bridge`

### Description
Bridge mode would allow the VPN client to act as a Layer 2 bridge, forwarding Ethernet frames between the virtual adapter and the VPN tunnel. This requires implementing a virtual switch (learning bridge) in the client.

### Current State
Client operates in Layer 3 mode (IP routing only). No Layer 2 bridging support.

### Tasks
- [ ] Implement virtual switch (MAC learning table)
- [ ] Add bridge mode configuration option
- [ ] Support STP (Spanning Tree Protocol) to prevent loops (optional)
- [ ] Handle VLAN tagging/untagging in bridge mode
- [ ] Update TUN/TAP device to accept all Ethernet frames (not just IP)
- [ ] Add bridge status to `ConnectionStats`
- [ ] Test with multiple clients in bridge mode

### Acceptance Criteria
- Client can operate in Layer 2 bridge mode
- Ethernet frames are properly forwarded
- MAC address table is maintained (learning bridge)
- Multiple VMs/containers can bridge through client

### References
- C reference: `Cedar/Bridge.c`, `Cedar/VLan.c`
- `src/cedar/tunnel/data_loop.zig` - Would need modification for L2 mode
- IEEE 802.1Q - VLAN tagging
- IEEE 802.1D - Spanning Tree Protocol

---

## Summary Table

| Issue | Priority | Effort | Status | Labels |
|-------|----------|--------|--------|--------|
| #1 Windows Build | Medium | 2-3 days | 🚧 Planned | `platform`, `windows` |
| #2 app_version | Low | 30 min | ❌ Missing | `ffi`, `c-api` |
| #3 SOCKS Proxy | Low | Complete | ✅ Implemented | `network`, `proxy` |
| #4 Cert Pinning | Medium | 1 day | ❌ Missing | `security`, `tls` |
| #5 IPv6 Tunnel | Low | 2-3 days | 🚧 Partial | `network`, `ipv6` |
| #6 Bridge Mode | Low | 5-10 days | ❌ Missing | `feature`, `layer2` |

---

## Contribution Guidelines

If you'd like to work on any of these issues:

1. Comment on the issue to claim it
2. Fork the repository
3. Create a feature branch (`git checkout -b fix/issue-#1-windows-build`)
4. Implement the changes
5. Add tests for new functionality
6. Update documentation
7. Submit a pull request

### Testing Requirements
- All existing tests must pass (`zig build test`)
- New functionality must have unit tests
- Manual testing on target platform (if applicable)

### Code Style
- Follow existing code style in the project
- Use Zig naming conventions (snake_case for functions/variables)
- Add inline documentation for public functions
- Keep functions small and focused
