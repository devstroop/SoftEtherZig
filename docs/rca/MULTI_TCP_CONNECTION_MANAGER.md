# RCA-02: Multi-TCP Connection Manager

> **Date:** 2026-06-18  
> **Status:** Final  
> **Supersedes:** N/A  
> **Covered in SCOPE.md:** RCA-02 (HIGH)

---

## Executive Summary

The Multi-TCP Connection Manager provides parallel TCP connections between client and server for increased throughput. It has 10 confirmed historical bugs, ranging from throughput collapse (S2C deadlock) to total connectivity loss (DHCP direction deadlock). The design also has a fundamental gap: **connections that die are removed but never replaced**, causing permanent throughput degradation. Despite this, the single-connection path (which is the default and the only tested configuration in recent sessions) works correctly.

---

## Architecture Context

```
┌────────────────────────────┐
│     ConnectionManager       │
│  max_connections = 1..32   │
│  half_connection = bool    │
├────────────────────────────┤
│  ┌─ ManagedConnection[0] ──┐│
│  │ direction: bidirectional││  ← Primary (established first)
│  │ pending_bytes: 12345    ││
│  │ established: true       ││
│  └─────────────────────────┘│
│  ┌─ ManagedConnection[1] ──┐│
│  │ direction: C2S          ││  ← Upload-only (half-conn mode)
│  │ pending_bytes: 6789     ││
│  │ established: true       ││
│  └─────────────────────────┘│
│  ┌─ ManagedConnection[2] ──┐│
│  │ direction: S2C          ││  ← Download-only (half-conn mode)
│  │ pending_bytes: 0        ││
│  │ established: true       ││
│  └─────────────────────────┘│
└────────────────────────────┘
     │
     ▼
┌────────────────────────────┐
│   SendTunnelHelper.get()    │
│   selectSendConnection()    │  ← least-loaded by pending_bytes
│   → returns best connection │
└────────────────────────────┘
     │
     ▼
┌────────────────────────────┐
│   poll() fd set built by    │
│   buildPollFds()            │  ← all recv-capable connections
│   forEachReadable()         │  ← iterates ready connections
└────────────────────────────┘
```

---

## Root Causes

### Bug #1: Half-Connection S2C Deadlock (skip_poll + kernelRecvQueue)

**File:** `src/client/connection_manager.zig:262-274`  
**Severity:** Critical (total throughput collapse)

In half-connection mode, the primary connection is `C2S` (upload-only, `canRecv=false`). The `forEachReadable()` iterator initially only checked `poll_fds[].revents & POLLIN` for readability. When the `skip_poll` optimization was active (poll was skipped because SSL had pending data), the fd's `revents` stayed at 0 (not refreshed), and `hasPending()` returned false because OpenSSL's internal buffer was empty. But `kernelRecvQueue() > 0` — data was in the kernel recv buffer, waiting to be read by SSL_read.

The S2C download-only connection never had this check, causing a deadlock where unread data sat in the kernel buffer forever. The connection was established but never drained.

**Fix:** Added `conn.tls_socket.kernelRecvQueue() > 0` to the readability test.

---

### Bug #2: DHCP Direction Deadlock

**File:** `src/client/connection_manager.zig:297-315`  
**Severity:** Critical (no connectivity)

In half-connection mode, the primary connection is `client_to_server` (upload-only). DHCP responses from the server need to be RECEIVED, but the primary can't receive. Additional S2C (download-only) connections haven't been established yet during the DHCP phase (they're created after the session is active).

The client never receives DHCP OFFER/ACK → no IP address → no connectivity.

**Fix:** `enableDhcpBidirectional()` temporarily overrides the primary's direction to `bidirectional` during DHCP. `restoreDhcpDirections()` restores it after DHCP completes.

**Residual risk:** If DHCP doesn't complete within the grace period and the override is reverted by a timer, the client loses receive capability while still waiting for DHCP responses — a permanent deadlock.

---

### Bug #3: Inbound Drain Premature Stop (macOS 10ms)

**File:** `src/client/vpn_client.zig:1904-1909`  
**Severity:** High (throughput collapse)

The drain loop's exit condition was:
```zig
if (!conn.tls_socket.hasPending()) break;
```

This only checked OpenSSL's internal buffer (already-decrypted data). If data had arrived in the kernel recv buffer but hadn't been decrypted yet, `hasPending()` returned false and the drain exited. The loop went back to `poll()`, which on macOS can sleep 10ms even with `poll(timeout=0)`. During that 10ms, the server's send window closed → throughput collapse.

**Fix:** Added kernel check:
```zig
if (!conn.tls_socket.hasPending() and conn.tls_socket.kernelRecvQueue() == 0) break;
```

---

### Bug #4: Outbound Starvation During Download (skip_poll)

**File:** `src/client/vpn_client.zig:2054-2061`  
**Severity:** High (DL ACK starvation → throughput drop)

When `skip_poll = true` (OpenSSL has pending decrypted data), the poll didn't run, so `tun_readable` was always false (poll revents are stale). The outbound section guarded on `tun_readable`, which meant no outbound processing during heavy download → DL ACKs never sent → server's congestion window collapsed.

**Fix:** Changed the guard to `if (is_configured and (tun_readable or skip_poll))`.

---

### Bug #5: Non-Primary Connection Death Degrades Throughput

**File:** `src/client/connection_manager.zig:330-343`  
**Severity:** Medium (gradual throughput loss)

When a secondary connection dies, `cleanupDead()` removes it silently. The session continues on remaining connections, but aggregate throughput is permanently reduced. `needsMoreConnections()` returns true after a death, but **nothing in the data loop actually establishes new connections**. The session never recovers its original capacity.

**Design limitation:** Connection replenishment is not implemented. A long-running session with intermittent connection failures will degrade to single-connection throughput.

---

### Bug #6: `last_iter_had_work` Sticky-True (iOS CPU Limit)

**File:** `src/client/vpn_client.zig:1804-1815`  
**Severity:** High (process killed on iOS)

The `last_iter_had_work` flag was set true but never cleared on idle iterations. This forced `poll(timeout=0)` on every iteration, causing a 50k iters/sec busy-spin. iOS's CPU-wakeup-limit killed the process after 45001 wakes in 18 seconds.

**Fix:** Clear `last_iter_had_work = false` at the top of each iteration; OR-set it true only when real work is observed.

---

### Bug #7: Sendq Throttle Using MAX Instead of AVERAGE

**File:** `src/client/vpn_client.zig:2070-2086`  
**Severity:** Medium (unfair throttling in multi-conn)

The send queue throttle used `MAX` of kernelSendQueue across all connections. One connection with a full buffer (e.g., slow path) would throttle ALL connections to minimum batch size, including the fast ones.

**Fix:** Changed to `AVERAGE` sendq across established connections for multi-conn mode. Only the aggregate queue depth matters — a single slow connection doesn't penalize the others.

---

### Bug #8: Connection Replenishment Gap

**File:** `src/client/session_setup.zig`, `src/client/connection_manager.zig`  
**Severity:** Medium (permanent throughput degradation)

`establishAdditionalConnections()` runs once during initial setup. After connections die (detected by `cleanupDead()`), `needsMoreConnections()` returns true, but no code path ever calls the establishment function again. The session permanently loses capacity until the next full reconnect.

---

### Bug #9: TUN Write Backpressure Not Applied in ProcessInboundBlock

**File:** `src/client/vpn_client.zig:1135`  
**Severity:** Medium (packet drops during TUN backpressure)

`dev.write()` can return `EAGAIN` when the TUN kernel buffer is full (application not reading). The error is caught and `tun_write_blocked = true` is set, but the drain loop's check for this flag may exit the multi-conn drain as well. The write itself already lost the packet.

---

## Detection

Multi-connection issues manifest as:
- **Throughput drop over time** as connections die without replacement
- **Upload works but download doesn't** in half-connection mode (S2C direction issues)
- **DHCP never completes** in half-connection mode
- **DL collapses during UL** (single-TCP head-of-line blocking — inherent to single connection, mitigated by multi-conn but not eliminated)

DIAG metrics for diagnosis:
```
Compare multi-conn vs single-conn throughput stability
Look for established=false in connection log
Monitor sendq AVG vs MAX divergence
Check for "Connection lost (multi-conn)" warnings
```

---

## Lessons Learned

### 1. Direction-aware I/O requires careful lifecycle management
Half-connection directions create deadlock windows (DHCP phase, poll skip). Any code that temporarily modifies directions must have restoration guarantees, even in error paths.

### 2. Connection replenishment must be part of the data loop
If the data loop can lose connections, it must also be able to create new ones. A `needsMoreConnections()` check without a corresponding establishment path is a bug waiting to happen.

### 3. Least-loaded scheduling needs proper decay tuning
The `pending_bytes` decay rate (10,000 bytes/iteration) was chosen empirically. If the decay rate doesn't match the actual drain rate, the scheduler becomes either round-robin (too fast) or static (too slow).

---

## Prevention Checklist

- [ ] Direction overrides have guaranteed restoration (even on error paths)
- [ ] Connection death triggers either replacement or explicit degradation notification
- [ ] The `last_iter_had_work` flag is cleared at the top of each iteration
- [ ] Multi-conn throttle uses AVERAGE sendq, not MAX
- [ ] Readability checks include both `hasPending()` and `kernelRecvQueue() > 0`
- [ ] Outbound guard checks both `tun_readable` and `skip_poll`
- [ ] `needsMoreConnections()` either triggers connection establishment or is removed
- [ ] Send queue decay rate is verified against actual throughput measurements

---

## References

- `src/client/connection_manager.zig` — Full file (387 lines)
- `src/client/connection.zig` — Individual connection state (661 lines)
- `src/client/session_setup.zig` — Additional connection establishment (52-127)
- `src/tunnel/data_loop.zig` — Data loop state (422 lines)
- `src/client/vpn_client.zig` — Multi-conn data path integration (scattered)
- `src/protocol/softether_protocol.zig` — Auth negotiation for max_connection/half_connection
- `SoftEtherVPN/src/Cedar/Session.c` — C reference: `ClientAdditionalConnectChance()` (lines 950-1007)
- `SoftEtherVPN/src/Cedar/Connection.c` — C reference: `LateCount`-based send selection (lines 1101-1147)
- SCOPE.md RCA-02

---

## Cross-Validation Against C Source

After writing this RCA, the Zig implementation was validated against the reference C source at `SoftEtherVPN/src/Cedar/`. Two significant discrepancies were found:

### Discrepancy #1: Connection Replenishment

**RCA Claim:** "Connections that die are removed but never replaced."

**Actual C behavior:** `Session.c:950-1007` `ClientAdditionalConnectChance()` actively monitors `CurrentNumConnection < MaxConnection` and spawns new connection threads when needed:

```c
void ClientAdditionalConnectChance(SESSION *s)
{
    if (s->CurrentNumConnection >= s->MaxConnection) return;
    if (s->ClientAdditionalConnectionCheckNextTick == 0 || s->ClientAdditionalConnectionCheckNextTick <= s->H->Tick)
    {
        s->ClientAdditionalConnectionCheckNextTick = s->H->Tick + (UINT)GenRandInterval(500, 1500);
        ClientAddAdditionalConnection(s);
    }
}
```

`ClientAddAdditionalConnection()` creates a new TCP/TLS connection, authenticates it with the session ticket/key, and adds it to the connection pool. The Zig implementation lacks this replenishment entirely.

### Discrepancy #2: Load Balancing Metric

**RCA Claim:** Selection is "least-loaded based on `pending_bytes`" with a decay function.

**Actual C behavior:** The C source uses `LateCount` (a packet-delay counter) as the selection metric for TCP connections, and `LastRecvTime` for R-UDP connections:

```c
// Connection.c:1101-1147
if (ts->UdpAccel == NULL)  // TCP connection
{
    result = ts->LateCount;  // ← KEY: delay count, NOT pending_bytes
}
else  // R-UDP connection
{
    result = (UINT)(s->Now - ts->UdpAccel->LastRecvTime);  // recency-based
}
```

`LateCount` is incremented whenever a `Send` call returns `SOCK_LATER` (write would block), and decayed over time. This directly measures **connection congestion** — a connection whose send buffer is full accumulates `LateCount` and gets skipped. The `pending_bytes` mechanism in Zig approximates this but uses a different decay model (10,000 bytes/iteration uniform decay vs the C's event-driven `LateCount`).

### Implications for Zig Implementation

| Aspect | Zig | C Reference | Action Needed |
|--------|-----|-------------|---------------|
| Connection replenishment | ❌ None | ✅ `ClientAdditionalConnectChance()` | Add replenishment monitor to data loop |
| Load balancing metric | `pending_bytes` decay | `LateCount` (send delay counter) | Consider switching to event-driven congestion signal |
| Non-primary death handling | Silent removal | Silent removal (same) | ✅ No change needed |
| In-order delivery | No inter-connection ordering | No inter-connection ordering (same) | ✅ Correct |


