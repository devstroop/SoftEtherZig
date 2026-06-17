# RCA Scope — Candidates Identified Across Codebase

> **Date:** 2026-06-18  
> **Status:** Proposed — not yet written  
> **Total candidates:** 25  
> **Priority breakdown:** HIGH=10, MEDIUM=9, LOW=6  

---

## How to Use This Document

Each candidate describes a subsystem or pattern that has caused regressions, contains fragile logic, or has a high risk of future issues. When a bug or regression is encountered in one of these areas, the corresponding RCA should be written following the template in `docs/rca/TEMPLATE.md` (to be created).

**Priority tiers:**
- **HIGH:** Has caused regressions before, involves complex cross-platform state machines, or has non-obvious failure modes
- **MEDIUM:** Fragile patterns with potential for future issues; would benefit from documentation
- **LOW:** Well-understood but worth recording for completeness

---

## HIGH Priority

### RCA-01: AES-256-CBC Session Encryption

| Field | Value |
|-------|-------|
| **Files** | `src/session/wrapper.zig`, `src/session/session.zig`, `src/crypto/cipher.zig`, `src/crypto/crypto.zig` |
| **Lines** | `wrapper.zig:45-120` (encrypt/decrypt), `cipher.zig:30-95` (AES-CBC impl), `session.zig:1-80` (key derivation) |
| **Risk** | Data integrity — incorrect encryption produces silent corruption |
| **Past issues** | 3 git commits adjusting encryption setup; `wrapper.zig` encrypt/decrypt methods are called 0 times in the codebase — the data path may use them or bypass them |

**Why it needs an RCA:** There are TWO AES-256-CBC implementations (`wrapper.zig` and `cipher.zig`) with incompatible APIs. The session wrapper's `encrypt()`/`decrypt()` methods are never called from the data path (confirmed by grep — 0 callers). The actual encryption may be handled differently (possibly by OpenSSL or a different code path), meaning the wrapper is dead code that would be broken if ever enabled. A regression here would cause total data corruption or connection failure.

**Key questions:**
- Which AES-256-CBC path actually encrypts tunnel data?
- Are the wrapper encrypt/decrypt functions dead code or speculatively reserved?
- What happens when session key rotation occurs (if implemented)?
- Is HMAC applied correctly per packet?

---

### RCA-02: Multi-TCP Connection Manager

| Field | Value |
|-------|-------|
| **Files** | `src/client/connection_manager.zig` |
| **Lines** | Full file (~300 lines) |
| **Risk** | Throughput, packet ordering, connection leaks |
| **Past issues** | Commit `2ad52780` removed duplicate data loop thread; half-connection direction management added in `b457f79d` |

**Why it needs an RCA:** Multi-TCP connections split upload and download across multiple TCP streams. This creates packet reordering challenges (the receiver must reassemble in-order), load balancing decisions (how to distribute packets across connections), and connection lifecycle management (what happens when one connection dies). The half-connection mode (separate TCP connections for TX and RX) adds directional routing complexity. A bug here could cause out-of-order delivery, throughput asymmetry, or silent connection drops.

**Key questions:**
- How are packets distributed across connections for upload?
- How is in-order delivery maintained on the receive side?
- What happens when one connection in a multi-conn set drops?
- How does half-connection mode interact with the keep-alive mechanism?

---

### RCA-03: UDP Acceleration (RUDP)

| Field | Value |
|-------|-------|
| **Files** | `src/net/udp_accel.zig`, `src/protocol/softether_protocol.zig` (UdpBulkKeys) |
| **Lines** | `udp_accel.zig` full file |
| **Risk** | Throughput, NAT traversal failure, security (AES key exchange over UDP) |
| **Past issues** | NAT-T probe flow; `support_bulk_on_rudp` and `support_hmac_on_bulk_of_rudp` handshake flags |

**Why it needs an RCA:** UDP acceleration provides a faster data path than TCP for the tunnel, but involves NAT traversal probing (hole-punching), AES bulk key exchange, and running a separate UDP-based data protocol alongside the TCP control connection. Failure modes include: NAT-T probe failing silently (falling back to TCP without notification), AES key mismatch, UDP packet loss/reordering affecting tunnel performance, and the interaction between the UDP acceleration state and the main TCP connection state.

**Key questions:**
- What happens when the NAT-T probe fails?
- How does the client fall back from UDP to TCP?
- Are RUDP recovery/retransmission mechanisms implemented?
- How are UDP bulk keys exchanged and rotated?

---

### RCA-04: Authentication Protocol

| Field | Value |
|-------|-------|
| **Files** | `src/protocol/auth.zig`, `src/client/auth_handler.zig`, `src/protocol/rpc.zig` |
| **Lines** | `auth.zig` full file, `auth_handler.zig` full file |
| **Risk** | Connection failure, security bypass, cluster redirect failure |
| **Past issues** | Multiple commits fixing auth: `78e802a9` (ServerIpAddress), `d5c18770` (ticket auth), `c354c0a9` (cluster probe) |

**Why it needs an RCA:** The authentication protocol supports multiple methods (password, certificate, anonymous, ticket-based) and a cluster redirect flow. The auth state machine involves HTTP POST over TLS, Pack serialization, server hello/random exchange, and session ticket validation. The cluster redirect adds a secondary connection to a different server. Past issues show subtle bugs in IP address encoding, ticket data handling, and cluster probe failures.

**Key questions:**
- What happens when ticket auth succeeds but cluster redirect fails?
- How are auth timeouts handled?
- Are all 4 auth methods (password, cert, anonymous, ticket) tested?
- What is the interaction between auth retry and the reconnection mechanism?

---

### RCA-05: DHCP Client State Machine

| Field | Value |
|-------|-------|
| **Files** | `src/adapter/dhcp.zig`, `src/adapter/wrapper.zig` (DHCP config), `src/client/vpn_client.zig` (DHCP handling) |
| **Lines** | `dhcp.zig` full file, `vpn_client.zig:1100-1210` |
| **Risk** | No network connectivity, IP conflict, DNS failure |
| **Past issues** | DHCP request/ACK cycle; `DHCPForce=1` server policy; retry logic |

**Why it needs an RCA:** The DHCP client implements the full DISCOVER/OFFER/REQUEST/ACK state machine with timeout/retry. The server enforces `DHCPForce=1` (blocks traffic from un-leased IPs), so DHCP MUST complete before any data flows. A regression here means total connectivity loss. The DHCPv6 client exists but may not be fully functional (the log shows "DHCPv6: no Reply — server does not support IPv6").

**Key questions:**
- What happens when all DHCP retries are exhausted?
- Is DHCP renewal (REBINDING state) implemented?
- How does DHCP interact with the routing configuration?
- Is the DHCPv6 client production-ready?

---

### RCA-06: ARP Handling and Gateway MAC Learning

| Field | Value |
|-------|-------|
| **Files** | `src/client/packet_processor.zig` (ARP), `src/client/vpn_client.zig:2150-2190` |
| **Lines** | `packet_processor.zig` full file |
| **Risk** | Gateway unreachable, ARP spoofing, broadcast storms |
| **Past issues** | ARP request/reply processing; gratuitous ARP; gateway MAC learning |

**Why it needs an RCA:** The client sends gratuitous ARP on connect and learns the gateway MAC via ARP. ARP handling at the tunnel level is different from physical network ARP — packets are tunneled, so ARP resolution must happen through the VPN server. If ARP resolution fails, the gateway appears unreachable and no traffic flows. Gratuitous ARP is sent to announce the client's MAC to the Virtual Hub.

**Key questions:**
- What happens when gateway ARP resolution fails?
- How are ARP broadcasts handled (forwarded vs filtered)?
- Is there any ARP spoofing protection at the tunnel level?
- How does gratuitous ARP interact with the Virtual Hub's MAC table?

---

### RCA-07: Routing Configuration (Full-Tunnel vs Split-Tunnel)

| Field | Value |
|-------|-------|
| **Files** | `src/client/vpn_client.zig` (routing), `src/adapter/wrapper.zig` (adapter routing) |
| **Lines** | `vpn_client.zig:1185-1210`, `wrapper.zig` routing methods |
| **Risk** | Traffic leaks, DNS leaks, no connectivity |
| **Past issues** | Full-tunnel default route; split-tunnel custom routes; IPv6 leak prevention |

**Why it needs an RCA:** The routing subsystem configures the system's network stack to direct traffic through the TUN adapter. Full-tunnel mode replaces the default route; split-tunnel adds specific routes. Misconfiguration can cause traffic leaks (non-VPN traffic bypasses the tunnel), DNS leaks (DNS queries sent outside the tunnel), or no connectivity (wrong gateway, missing routes). IPv6 leak prevention involves disabling IPv6 on the physical interface.

**Key questions:**
- What happens when route configuration fails? Is the connection torn down or does traffic leak?
- Are routes properly cleaned up on disconnect?
- How is DNS configured for the tunnel (DHCP-provided DNS)?
- Is there a race between DHCP completing and route configuration?

---

### RCA-08: Data Loop Thread Lifecycle

| Field | Value |
|-------|-------|
| **Files** | `src/client/vpn_client.zig:260-270, 470-490` |
| **Lines** | Thread spawn, join, state transitions |
| **Risk** | Double-close, memory corruption, crash |
| **Past issues** | Commit `1e42a003` fixed FFI corruption; `2ad52780` removed duplicate data loop |

**Why it needs an RCA:** The data loop runs in a separate thread spawned by `runDataLoopThread`. The `should_stop` flag is `@atomicStore` with `.release` ordering, but shared state (sockets, buffers, flags) is accessed from both the data loop thread and the main thread without synchronization (mutex usage is minimal). This creates potential race conditions on disconnect/reconnect: the health check or error handler may set `should_stop` while the main thread tries to read `data_loop_running`.

**Key questions:**
- What thread safety guarantees exist for `tun_write_blocked`, `should_stop`, `data_loop_running`?
- Can `finishDisconnect()` run concurrently with the data loop?
- Are all shared variables accessed with proper atomic ordering?
- What happens if `disconnect()` is called while the data loop is starting?

---

### RCA-09: Session Key / Encryption Setup

| Field | Value |
|-------|-------|
| **Files** | `src/session/session.zig`, `src/client/auth_handler.zig`, `src/protocol/auth.zig` |
| **Lines** | `session.zig:1-80`, `auth_handler.zig` full file |
| **Risk** | Unencrypted data channel, wrong cipher, security bypass |
| **Past issues** | `encrypt.flag` vs `use_encrypt`; session key probe; `use_fast_rc4` flag |

**Why it needs an RCA:** After authentication, a session key is derived and used to encrypt tunnel data with AES-256-CBC. The session key is 20 bytes (`session_key_32` is actually checked). The `use_encrypt` flag controls whether encryption is enabled. If session key derivation has a bug, tunnel data flows unencrypted or with wrong key material. The `use_fast_rc4` flag (for legacy RC4) may interact with the AES key setup.

**Key questions:**
- Is the session key correctly derived from the auth exchange?
- What happens when `use_encrypt=0` (encryption disabled)?
- Is there a test vector for the AES-256-CBC encryption/decryption?
- How does the session key relate to the TLS session (double encryption)?

---

### RCA-10: Build System / Platform Cross-Compilation

| Field | Value |
|-------|-------|
| **Files** | `build.zig`, `build.zig.zon` |
| **Lines** | Full files |
| **Risk** | Build failure, wrong OpenSSL linkage, platform-specific code not compiled |
| **Past issues** | OpenSSL path detection; iOS vs macOS libc; Android cross-compilation config |

**Why it needs an RCA:** The build system handles compilation for macOS, iOS, Android (aarch64/arm), Linux, and Windows (planned). Each platform has different libc files, OpenSSL linkage paths, and capabilities. A build regression can silently drop platform support (e.g., OpenSSL linking fails but build succeeds with stubs, producing a non-functional binary). The `.gitmodules` brings in zlib from a fork, and the `deps/zlib` directory is compiled with C flags.

**Key questions:**
- Are all 5 target platforms regularly build-tested?
- What happens when OpenSSL is not found on a platform?
- Are the Android libc configs maintained?
- Does the iOS build produce a working static library?

---

## MEDIUM Priority

### RCA-11: DNS Cache

| Field | Value |
|-------|-------|
| **Files** | `src/net/dns_cache.zig` |
| **Lines** | Full file |
| **Risk** | Connection to wrong server, stale DNS, connection failure |
| **Past issues** | Cache hit/miss logic; TTL handling; IPv6 vs IPv4 resolution |

**Why it needs an RCA:** DNS caching stores resolved server IPs with TTL. Stale cache entries can cause connections to wrong servers (especially problematic for cluster deployments where IPs change). Cache growth is unbounded (no eviction policy). Thread safety of cache reads/writes during the connection phase.

---

### RCA-12: HTTP/RPC Protocol

| Field | Value |
|-------|-------|
| **Files** | `src/net/http.zig`, `src/protocol/rpc.zig` |
| **Lines** | Full files |
| **Risk** | Auth failure, connection drop, misinterpreted responses |
| **Past issues** | Content-Length parsing; Keep-Alive header handling; response body chunking |

**Why it needs an RCA:** The HTTP/RPC layer carries authentication exchanges over HTTP POST. Content-Length parsing, header parsing, connection keep-alive, and response body handling all have corner cases. A malformed server response (extra headers, chunked encoding, different Content-Length) could crash the parser or cause authentication to hang.

---

### RCA-13: Pack Serialization

| Field | Value |
|-------|-------|
| **Files** | `src/protocol/pack.zig` |
| **Lines** | Full file |
| **Risk** | Auth failure, protocol mismatch, data corruption |
| **Past issues** | Endianness; type encoding; nested pack elements |

**Why it needs an RCA:** The Pack/Value format is a SoftEther-specific binary serialization used for all RPC messages (auth, config, keepalive). Field ordering, endianness (big-endian), type tags (int, str, data), and nesting are all explicitly encoded. A bug in pack serialization/deserialization causes protocol-level miscommunication with the server — hard to diagnose because both sides see valid-but-wrong data.

---

### RCA-14: Keep-Alive Mechanism

| Field | Value |
|-------|-------|
| **Files** | `src/client/connection.zig:370-400`, `src/client/vpn_client.zig:2100-2150` (keepalive section) |
| **Lines** | `connection.zig` keepalive methods, vpn_client data loop keepalive interval |
| **Risk** | Connection timeout, false disconnect detection |
| **Past issues** | Keepalive send/recv timing; missed keepalive detection; TCP_KEEPALIVE vs application-level keepalive |

**Why it needs an RCA:** Application-level keepalives prevent the VPN server from timing out idle connections. The timing (send interval, missed threshold) must match the server's IdleSessionTimeout. Too frequent: bandwidth waste. Too infrequent: connection drops. The interaction between TCP keepalive (SO_KEEPALIVE) and application keepalives can cause false disconnects.

---

### RCA-15: Socket Option Configuration

| Field | Value |
|-------|-------|
| **Files** | `src/net/tls.zig:870-925` (clearTimeouts) |
| **Lines** | Full function |
| **Risk** | Performance degradation, connection failure, unexpected OS behavior |
| **Past issues** | SO_SNDBUF, SO_RCVBUF sizing; TCP_NODELAY; TCP_NOTSENT_LOWAT; read/write timeouts |

**Why it needs an RCA:** The `clearTimeouts()` function sets multiple socket options after connection establishment. Options interact in non-obvious ways (e.g., SO_SNDBUF affects the send buffer but TCP_NOTSENT_LOWAT changes when data is considered "sent"). OS-specific behavior (macOS vs iOS vs Linux) for each option matters. The read/write timeout settings (0 = disabled) must be correct for the data loop's non-blocking I/O to work properly.

---

### RCA-16: Watermark / Anti-DPI

| Field | Value |
|-------|-------|
| **Files** | `src/protocol/watermark.zig` |
| **Lines** | Full file |
| **Risk** | Traffic pattern detection, connection blocking by firewalls |
| **Past issues** | Unknown (feature may be incomplete) |

**Why it needs an RCA:** Watermark/anti-DPI adds padding to tunnel packets to resist Deep Packet Inspection by firewalls. If implemented incorrectly, it either fails to prevent DPI (security gap) or adds significant bandwidth overhead (performance gap). The interaction with compression and encryption matters.

---

### RCA-17: Configuration File Handling

| Field | Value |
|-------|-------|
| **Files** | `src/cli/config_manager.zig`, `config.schema.json`, `config.example.json` |
| **Lines** | `config_manager.zig` full file |
| **Risk** | Wrong config applied, silent defaults used, migration failure |
| **Past issues** | JSON parsing edge cases; schema vs code synchronization; config key naming |

**Why it needs an RCA:** Configuration files contain ~50+ parameters governing connection, routing, encryption, reconnect behavior, and more. If the config file is malformed, the client might silently use defaults (different from user intent). Schema validation (`config.schema.json`) exists but may not be enforced at runtime. Config version migration between schema versions could cause incompatible configs.

---

### RCA-18: Route Healing

| Field | Value |
|-------|-------|
| **Files** | `src/tunnel/route_heal.zig` (if exists), `src/client/vpn_client.zig` routing code |
| **Lines** | Route add/remove/cleanup |
| **Risk** | Stale routes, routing loops, traffic leaks |
| **Past issues** | Stale route detection; cleanup on disconnect; race with new connection |

**Why it needs an RCA:** Route healing detects and cleans up stale routes from previous sessions that were not properly removed. If stale routes remain, they can interfere with new connections (wrong gateway, overlapping routes). The route healing logic must be careful not to remove routes from OTHER VPN sessions or system routes.

---

### RCA-19: Configuration Migration

| Field | Value |
|-------|-------|
| **Files** | `config.schema.json` (version field), `config.example.json` |
| **Lines** | Schema version tracking |
| **Risk** | Config file incompatibility between versions |

**Why it needs an RCA:** As configuration evolves, fields are added, removed, or renamed. Without a migration strategy, old config files may silently use wrong defaults or fail to parse. A version field in the schema allows backward-compatible migration.

---

## LOW Priority

### RCA-20: CLI Argument Parsing

| Field | Value |
|-------|-------|
| **Files** | `src/cli/args.zig` |
| **Lines** | Full file |
| **Risk** | Wrong configuration applied, confusing error messages |

**Why it needs an RCA:** CLI arguments override config file values. If argument parsing has bugs (wrong type parsing, missing validation, overlapping flags), the user may get unexpected behavior. Boolean flags (`--compress`, `--qos`, `--no-reconnect`) interact with config file defaults.

---

### RCA-21: DIAG Instrumentation Overhead

| Field | Value |
|-------|-------|
| **Files** | `src/client/vpn_client.zig` DIAG section |
| **Lines** | ~2350-2450 |
| **Risk** | Performance impact from excessive logging/metrics |

**Why it needs an RCA:** DIAG collects ~20 metrics per second (throughput, drain stats, poll stats, etc.). The instrumentation itself adds overhead (atomic reads, syscalls for kernelRecvQueue/kernelSendQueue). In verbose mode, additional per-connection RX diagnostics add more overhead. An RCA would document the performance cost of DIAG and suggest sampling strategies.

---

### RCA-22: Connection Stats Collection

| Field | Value |
|-------|-------|
| **Files** | `src/client/stats.zig` |
| **Lines** | Full file |
| **Risk** | Overflow, thread safety, accuracy |

**Why it needs an RCA:** Connection statistics (bytes sent/received, packets, errors) are collected from the data loop and exposed via the API. Counter overflow at high throughput (u64 wraps after ~500TB), thread safety on reads from API thread while data loop writes, and accuracy over long-running connections.

---

### RCA-23: Error Types and Handling

| Field | Value |
|-------|-------|
| **Files** | `src/errors.zig`, `src/types.zig` |
| **Lines** | Full files |
| **Risk** | Missed errors, wrong disconnect reason, confusing user messages |

**Why it needs an RCA:** Error types (`ClientError`, `DisconnectReason`) define how failures are categorized and reported. If error handling is inconsistent (some errors caught silently, some propagated), debugging becomes difficult. The `broken_data_plane` reason is now dead code (health check disabled) — an RCA would identify all unreachable error paths.

---

### RCA-24: SHA-0 Implementation

| Field | Value |
|-------|-------|
| **Files** | `src/crypto/sha0.zig` |
| **Lines** | Full file |
| **Risk** | Auth failure, security compromise (SHA-0 is broken) |

**Why it needs an RCA:** SHA-0 is used for legacy authentication compatibility with older SoftEther servers. SHA-0 is cryptographically broken (collision attacks published in 2005). The implementation is custom (not OpenSSL) and may have correctness bugs. If used in modern setups, it could be a security risk. If never used (modern servers use SHA-1/SHA-256), the code is dead.

---

### RCA-25: Windows TAP Adapter

| Field | Value |
|-------|-------|
| **Files** | `src/adapter/tap_windows.zig` |
| **Lines** | Full file |
| **Risk** | Platform support gap, build breakage |

**Why it needs an RCA:** Windows support is planned but not fully implemented. The TAP adapter code exists but the build system may not link it correctly. When Windows support is activated, this code may have bitrotted. An RCA would document the current state and what's needed for completion.

---

## Multi-Subsystem Themes

The following patterns appear across multiple subsystems and deserve their own RCA documents:

| Theme | Description | Affected RCAs |
|-------|-------------|---------------|
| **Non-blocking I/O correctness** | OpenSSL non-blocking state machine, WouldBlock propagation, event loop integration | 01, 02, 03, 08, 15 |
| **Thread safety** | Shared state between data loop thread and main/API thread without synchronization | 08, 11, 14, 22 |
| **Silent error swallowing** | `catch {}` patterns that lose error information and hide bugs | 01, 02, 06, 07, 08, 14 |
| **Configuration inconsistency** | CLI args vs config file vs schema defaults — which wins? | 17, 19, 20 |
| **Platform-specific behavior** | macOS vs iOS vs Linux vs Android — different TUN, route, DNS, crypto APIs | 01, 02, 05, 07, 15, 25 |

---

## Writing an RCA

When writing an RCA document:

1. Create `docs/rca/TOPIC_NAME.md`
2. Follow the structure from the existing `PERFORMANCE_REGRESSION.md`:
   - Executive Summary
   - Architecture Context
   - Root Cause description
   - Why it regressed
   - Fix applied
   - Lesson learned
   - Prevention Checklist items

3. Reference the specific files and line numbers
4. Include DIAG metrics or log patterns that help diagnose the issue
5. Add to the prevention checklist in the root RCA document if the lesson applies broadly

---

## Prioritization for Next Sprint

| Priority | RCA | Effort | Impact |
|----------|-----|--------|--------|
| 1 | RCA-01 (AES-256-CBC) | 2 days | Data integrity |
| 2 | RCA-09 (Session Key) | 1 day | Security |
| 3 | RCA-08 (Thread Lifecycle) | 1 day | Stability |
| 4 | RCA-04 (Auth Protocol) | 1 day | Connection reliability |
| 5 | RCA-05 (DHCP) | 1 day | Connectivity |
| 6 | RCA-07 (Routing) | 1 day | Traffic leaks |
