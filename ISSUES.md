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
- `build.zig` - Windows OpenSSL detection (lines ~40-60)
- `src/adapter/tap_windows.zig` - TAP adapter implementation
- `README.md` - Platform support table

---

## Issue #2: SOCKS Proxy Support

**Status**: ❌ Not Fully Wired  
**Priority**: Low  
**Effort**: 1-2 days  
**Labels**: `network`, `proxy`, `feature`

### Description
Proxy configuration exists in `src/client/connection.zig` (`ProxyConfig` struct) and `src/cli/args.zig`, but the actual proxy connection logic is not fully implemented in the connection establishment path.

### Current State
```zig
// src/client/connection.zig
pub const ProxyConfig = struct {
    host: []const u8,
    port: u16,
    auth_username: ?[]const u8 = null,
    auth_password: ?[]const u8 = null,
    proxy_type: ProxyType = .http,
    // ... but no actual HTTP CONNECT implementation wired to TlsSocket.connect()
};
```

CLI supports `--proxy` argument but it's not passed to the connection layer.

### Tasks
- [ ] Implement HTTP CONNECT method in `src/net/tls.zig` or `src/net/socket.zig`
- [ ] Add SOCKS4/SOCKS5 proxy support
- [ ] Wire proxy config from `ClientConfig` to `TlsSocket.connect()`
- [ ] Add proxy authentication (username/password)
- [ ] Test with actual proxy servers (Burp, mitmproxy, etc.)
- [ ] Add unit tests for proxy connection logic

### Acceptance Criteria
- Client can connect through HTTP CONNECT proxy
- Client can connect through SOCKS5 proxy
- Proxy authentication works (if configured)
- Connection falls back to direct if proxy fails (optional)

### References
- `src/client/connection.zig` - ProxyConfig struct (lines ~25-35)
- `src/cli/args.zig` - CLI proxy argument
- `src/net/tls.zig` - TlsSocket.connect() (needs proxy support)
- C reference: `Cedar/Connection.c` - Proxy connection logic

---

## Issue #3: Certificate Pinning

**Status**: ❌ Not Implemented  
**Priority**: Medium  
**Effort**: 1 day  
**Labels**: `security`, `tls`, `certificate`

### Description
Currently uses OpenSSL's built-in certificate verification. Certificate pinning would allow users to specify a known server certificate fingerprint, improving security against MITM attacks (even with compromised CAs).

### Current State
```zig
// src/net/tls.zig
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
- `src/net/tls.zig` - TlsConfig and TlsSocket
- OpenSSL documentation: `SSL_get_peer_certificate()`, `X509_digest()`
- OWASP Certificate Pinning Guide

---

## Issue #4: IPv6 Support

**Status**: ❌ Not Implemented  
**Priority**: Low  
**Effort**: 3-5 days  
**Labels**: `network`, `ipv6`, `feature`

### Description
Client currently only supports IPv4. DHCPv6, IPv6 routing, and IPv6 tunnel support are missing.

### Current State
```zig
// src/adapter/tun_linux.zig
// Only handles IPv4 configuration:
pub const TunLinuxDevice = struct {
    ipv4_address: u32,
    ipv4_netmask: u32,
    ipv4_gateway: u32,
    // No IPv6 fields
};
```

```zig
// src/adapter/dhcp.zig
// Only DHCPv4, no DHCPv6
pub fn buildDhcpDiscover(...) !usize { ... }  // Only v4
```

### Tasks
- [ ] Add IPv6 address support to TUN/TAP devices
  - Linux: `in6_addr` configuration
  - macOS/iOS: `utun` IPv6 support
  - Windows: TAP IPv6 support
- [ ] Implement DHCPv6 client (IA_NA, IA_TA options)
- [ ] Add IPv6 routing table management
- [ ] Support IPv6 DNS servers (RDNSS option)
- [ ] Update CLI to accept IPv6 config (`--ipv6`, `--ipv6-gateway`)
- [ ] Test with IPv6-only networks

### Acceptance Criteria
- Client can receive IPv6 address via DHCPv6
- IPv6 routes are properly configured
- IPv6 traffic passes through tunnel
- Dual-stack (IPv4 + IPv6) works simultaneously

### References
- `src/adapter/tun_linux.zig` - Linux TUN device
- `src/adapter/utun.zig` - macOS/iOS utun device
- RFC 3315 - DHCPv6
- RFC 4861 - Neighbor Discovery for IPv6

---

## Issue #5: Bridge Mode (Layer 2)

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
- `src/tunnel/data_loop.zig` - Would need modification for L2 mode
- IEEE 802.1Q - VLAN tagging
- IEEE 802.1D - Spanning Tree Protocol

---

## Summary Table

| Issue | Priority | Effort | Status | Labels |
|-------|----------|--------|--------|--------|
| #1 Windows Build | Medium | 2-3 days | 🚧 Planned | `platform`, `windows` |
| #2 SOCKS Proxy | Low | 1-2 days | ❌ Not Wired | `network`, `proxy` |
| #3 Cert Pinning | Medium | 1 day | ❌ Missing | `security`, `tls` |
| #4 IPv6 Support | Low | 3-5 days | ❌ Missing | `network`, `ipv6` |
| #5 Bridge Mode | Low | 5-10 days | ❌ Missing | `feature`, `layer2` |

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
