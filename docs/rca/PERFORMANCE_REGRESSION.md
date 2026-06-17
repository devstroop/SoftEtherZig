# Performance Regression (RCA)

> **Date:** 2026-06-18  
> **Versions examined:** v0.1.0–v0.1.11 (past ~2 months)  
> **Target:** 50+ Mbps bidirectional through a SoftEther VPN tunnel over a single TLS 1.3 connection

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Regression Timeline](#3-regression-timeline)
4. [Root Causes](#4-root-causes)
   - [RC1: 4MB SO_SNDBUF Bufferbloat](#rc1-4mb-so_sndbuf-bufferbloat)
   - [RC2: Blocking Process Spawn in Data Loop (logRoutingDiag)](#rc2-blocking-process-spawn-in-data-loop-logroutingdiag)
   - [RC3: SSL Non-Blocking Violation from writeAll](#rc3-ssl-non-blocking-violation-from-writeall)
   - [RC4: Stale Auth Response Data Consumed by recv_buf Optimization](#rc4-stale-auth-response-data-consumed-by-recv_buf-optimization)
   - [RC5: Health Check False Positive During Download-Only Tests](#rc5-health-check-false-positive-during-download-only-tests)
   - [RC6: Non-Blocking TUN Write Causes Silent Packet Drops](#rc6-non-blocking-tun-write-causes-silent-packet-drops)
   - [RC7: macOS poll(timeout=0) Scheduler Tick Granularity](#rc7-macos-polltimeout0-scheduler-tick-granularity)
   - [RC8: Auto-Reconnect Default Masked Transient Issues](#rc8-auto-reconnect-default-masked-transient-issues)
   - [RC9: sendq Throttle Thresholds Unchanged After Buffer Size Changes](#rc9-sendq-throttle-thresholds-unchanged-after-buffer-size-changes)
5. [Diagnostic Methodology](#5-diagnostic-methodology)
6. [Lessons Learned](#6-lessons-learned)
7. [Prevention Checklist](#7-prevention-checklist)

---

## 1. Executive Summary

Two months of iterative "Cycle" optimizations introduced **nine distinct root causes** of performance regression. Every single one follows the same pattern: a well-intentioned optimization that interacted destructively with the single-threaded, non-blocking I/O event loop at the core of the VPN client.

The single-threaded data loop has three critical constraints:
1. **It can only do one thing at a time** — if it blocks on a write, it can't read; if it spawns a child process, it can't do I/O.
2. **OpenSSL non-blocking mode has strict state machine requirements** — `WANT_READ`/`WANT_WRITE` must be retried with the **exact same buffer pointer**.
3. **macOS has coarse poll/select granularity** (~10ms scheduler tick) that requires proactive workarounds.

Every fix that worked removed complexity rather than adding it.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Data Loop (single thread)                 │
│                                                              │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐ │
│  │   INBOUND    │ ──▶ │   OUTBOUND   │ ──▶ │   CONTROL    │ │
│  │ (TLS → TUN)  │     │ (TUN → TLS)  │     │ (ARP/DHCP/KA)│ │
│  └──────────────┘     └──────────────┘     └──────────────┘ │
│         │                                 ▲                 │
│         ▼                                 │                 │
│  ┌──────────────┐     ┌──────────────┐     │                 │
│  │ SSL_read     │     │ SSL_write    │─────┘                 │
│  │ → parse      │     │ ← batch(64)  │                       │
│  │ → TUN write  │     │ ← TUN read   │                       │
│  └──────────────┘     └──────────────┘                       │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐    │
│  │  poll(TLS_fd | TUN_fd, timeout=0|1)                  │    │
│  └──────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Key properties
- **Single thread**: all I/O (TLS, TUN, control) multiplexed in one poll loop
- **Non-blocking TLS**: OpenSSL set to non-blocking mode, requires WANT_READ/WANT_WRITE retry with same buffer
- **Non-blocking TUN**: `O_NONBLOCK` on utun fd; writes return EAGAIN when kernel buffer full
- **1ms idle poll**: `poll(timeout=1)` when last iteration had no work; `poll(timeout=0)` when busy

---

## 3. Regression Timeline

```
v0.1.0 - v0.1.8   Stable 50+ Mbps DL/UL, no health checks, simple blocking I/O
        │
        ├─ Cycle 5:  batch=32 for outbound
        ├─ Cycle 6:  drain cap 8→64, adaptive poll
        ├─ Cycle 7:  SO_SNDBUF=256KB, SO_RCVBUF=1MB
        ├─ Cycle 8:  DIAG instrumentation added
        ├─ Cycle 9:  skip_poll optimization
        ├─ Cycle 10: SO_SNDBUF=512KB
        ├─ Cycle 11: SO_SNDBUF=4MB ← MAJOR REGRESSION START
        ├─ Health check added (data-plane monitor)
        ├─ logRoutingDiag added (blocking spawn)
        └─ recv_buf optimization (64KB intermediate buffer)
                │
v0.1.11          20-50 DL / 50-70 UL with 3s latency spikes
                │
                └─ After fixes: 61 DL / 50 UL (target met)
```

---

## 4. Root Causes

### RC1: 4MB SO_SNDBUF Bufferbloat

**Severity:** Critical  
**File:** `src/net/tls.zig` → `clearTimeouts()`  
**Introduced in:** Cycle 11 (`17cc21b`) — changed from 512KB to 4MB  
**Fixed by:** Reducing to 2MB

**Mechanism:**
The TCP socket send buffer was set to `4 * 1024 * 1024` bytes. At 70 Mbps upload, the kernel send queue could accumulate 4MB of data (~450ms worth). When the buffer hit the ceiling, `SSL_write` returned `SSL_ERROR_WANT_WRITE`, and `writeAllNonBlocking` entered a 1ms `poll(POLLOUT)` loop. With 884 write_blocked events per second, the event loop spent ~884ms/s stalled — unable to process inbound data (DL collapses) or outbound TUN reads (UL stalls).

**Why it regressed:**
The code comment claimed "Sndbuf never fills in steady state" and "kernel doubles to ~8MB." Both were false on macOS — `SO_NWRITE` consistently reported the send queue at exactly the 4MB `SO_SNDBUF` value. The kernel did NOT double the buffer to 8MB, and the send queue DID fill in steady state during upload tests.

**Fix:**
```zig
const snd_cap: u32 = 2 * 1024 * 1024;  // 2MB
```
Enough for BDP at ~90 Mbps / 180ms RTT without the bufferbloat cascade. At 50 Mbps, 2MB = ~320ms of data — the send queue drains before causing prolonged stalls.

**Lesson:** Never assume OS buffer doubling behavior. Measure actual `SO_NWRITE` values. Match buffer size to BDP, not to "bigger is better."

---

### RC2: Blocking Process Spawn in Data Loop (logRoutingDiag)

**Severity:** Critical  
**File:** `src/client/vpn_client.zig` → `logRoutingDiag()` + DIAG section  
**Fixed by:** Removing the `logRoutingDiag()` call from the data loop

**Mechanism:**
Every second during download (when `mbps_in > 1.0 and mbps_out < 0.5`), the DIAG section called `logRoutingDiag()`, which:

1. `fork()` + `exec()` for `netstat -rn -f inet`
2. **BLOCKING** `read()` from child's stdout
3. `wait()` for child
4. `fork()` + `exec()` for `ifconfig utunN`
5. **BLOCKING** `read()` from child's stdout
6. `wait()` for child

Each fork/exec/read cycle takes **50-100ms** during which the ENTIRE data loop is blocked:
- No TLS reads → recv buffer fills with download data
- No ACKs sent → server's congestion window closes
- After 50-100ms stall, the server needs multiple RTTs to recover its send rate
- The 48 Mbps → 7 Mbps collapse in consecutive DIAG intervals was caused by this

**Why it regressed:**
The diagnostic was added during Cycle 8 (DIAG instrumentation) as a debugging aid, but was left in the hot path. The condition `mbps_in > 1.0 and mbps_out < 0.5` is true during ANY download speed test, so it fired every second.

**Fix:**
Remove the `logRoutingDiag()` call from the data loop. Diagnostics that require process spawning must NOT run in the I/O path.

**Lesson:** Never fork/exec synchronously inside an event loop. Any operation that takes >1ms must be async or offloaded to a separate thread.

---

### RC3: SSL Non-Blocking Violation from writeAll

**Severity:** Critical  
**File:** `src/client/vpn_client.zig` → `write_fn`  
**Fixed by:** Reverting to `writeAllNonBlocking`

**Mechanism:**
The original code used `writeAllNonBlocking()` which correctly handles OpenSSL non-blocking mode: when `SSL_write` returns `SSL_ERROR_WANT_WRITE`, it polls `POLLOUT` and retries with the **same buffer pointer** (required by OpenSSL).

Changing to `writeAll()` (blocking `write` loop) broke this contract:
1. `SSL_write` returns `WANT_WRITE` → `TlsSocket.write()` returns `error.WouldBlock`
2. `writeAll` propagates `WouldBlock` to the caller
3. Caller drops the batch (non-fatal error → `tls_send_ok = false`)
4. Next data loop iteration: **calls `SSL_read`** (inbound processing) on the corrupted SSL state machine
5. OpenSSL detects violation → `SSL_R_BAD_WRITE_RETRY` → connection drops with `BrokenPipe`

**Why it regressed:**
`writeAll` appears simpler and "more correct" (guarantees full write or error). But OpenSSL's non-blocking mode is NOT compatible with abort-and-retry-later semantics. Once `SSL_write` returns `WANT_WRITE`, you MUST retry with the same buffer on the same SSL object before calling any other OpenSSL function.

**Fix:**
```zig
try s.writeAllNonBlocking(data);  // retries WANT_WRITE with same buffer
```

**Lesson:** OpenSSL non-blocking mode is a state machine, not a stream. `WANT_READ` and `WANT_WRITE` require immediate retry with IDENTICAL arguments. Never switch between read and write without completing the pending operation.

---

### RC4: Stale Auth Response Data Consumed by recv_buf Optimization

**Severity:** High  
**File:** `src/protocol/tunnel.zig` → `readFromBuf()`, `recv_buf` field  
**Fixed by:** Reverting the entire `recv_buf` optimization

**Mechanism:**
An intermediate 64KB receive buffer was added to reduce SSL_read calls:
```zig
recv_buf: [65536]u8 = undefined,
```
The first SSL_read after the data loop starts would fill this buffer with data from OpenSSL's internal decryption queue. However, this data could include **leftover HTTP auth response data** (not tunnel protocol batches). The state machine would parse this as `num_blocks` → garbage values → `TooManyBlocks` error.

The error triggered a reset to `.read_num_blocks` state, but the 4-byte u32 was already consumed from `recv_buf`. The next read would consume the NEXT 4 bytes from `recv_buf` (still garbage). This created a tight loop of `TooManyBlocks` errors that never resolved because the same stale buffer was never drained.

Additionally, a bug in the WouldBlock handler left `recv_buf_fill` with a stale non-zero value when `recv_buf_read` was reset to 0, causing the stale data to be re-read infinitely.

**Fix:**
Remove the intermediate buffer entirely. The original approach of reading directly from `read_fn` (SSL_read) for each u32 and block data is correct — each small read consumes the correct amount of data from OpenSSL's buffer.

**Lesson:** Intermediate buffering between an event-driven state machine and a streaming data source (SSL_read) requires careful handling of partial reads, state resets, and error recovery. The complexity often outweighs the performance benefit.

---

### RC5: Health Check False Positive During Download-Only Tests

**Severity:** High  
**File:** `src/client/vpn_client.zig` → DIAG section  
**Fixed by:** Disabled with `if (false)`

**Mechanism:**
The data-plane health check measured the UL/DL byte ratio:
```zig
const HEALTH_RATIO_THRESHOLD = 0.015; // 1.5%
```
During a download-only speed test, UL traffic is just TCP ACKs (~0.5% of DL volume). The ratio drops below 1.5% for 5 consecutive seconds → health check fires → `disconnect_reason = .broken_data_plane` → `should_stop = true` → connection killed.

**False positive rate:** 100% during any download-only test.

**Fix:**
Disabled the health check. It needs a fundamentally different algorithm (e.g., monitoring `TLS_READY` timeout or explicit keepalive response) rather than traffic ratio heuristics.

**Lesson:** Traffic ratio-based health checks cannot distinguish between "server is broken" and "user is running a download-only test." Any threshold low enough to catch real stalls will false-positive on asymmetric traffic patterns.

---

### RC6: Non-Blocking TUN Write Causes Silent Packet Drops

**Severity:** High  
**File:** `src/adapter/utun.zig` → O_NONBLOCK on TUN fd  
**Mitigated by:** `tun_write_blocked` + drain loop break (does not prevent the first drop)

**Mechanism:**
The utun fd is opened with `O_NONBLOCK`. When the application (browser) doesn't read from TUN fast enough, the kernel TUN buffer fills and `posix.write()` returns `EAGAIN`. The utun write function catches this as `UtunError.WriteFailed`. The caller at `vpn_client.zig:1117` silently discards it:

```zig
_ = dev.write(block_data[14..]) catch { self.tun_write_blocked = true; };
```

The packet is **irreversibly dropped**. The TCP connection inside the VPN sees packet loss → RTO (200ms) → retransmit → exponential backoff (400ms → 800ms → 1600ms) → **3 second latency spike**. At 48 Mbps, a 50ms application pause causes ~300KB of queued data → dropping even one packet triggers the full retransmission cascade.

**Mitigation:**
Setting `tun_write_blocked = true` stops the drain loop after the first drop, preventing subsequent drops. The single dropped packet still triggers TCP retransmission but limits the damage.

**Proper fix (future):** Keep a small write buffer for TUN. When write fails, enqueue the packet and wait for POLL.OUT on the TUN fd. This requires adding a TUN write queue and polling TUN for writability.

**Lesson:** Silent packet drops in a VPN tunnel are catastrophic — they trigger TCP retransmission storms with exponential backoff inside the tunnel. A 1% drop rate can collapse throughput by 90%. Always provide backpressure, never drop silently.

---

### RC7: macOS poll(timeout=0) Scheduler Tick Granularity

**Severity:** Medium  
**File:** `src/client/vpn_client.zig` → poll timeout selection  
**Fixed by:** Reducing idle timeout from 10ms to 1ms

**Mechanism:**
On macOS, `poll(timeout=0)` can unpredictably sleep for one scheduler tick (~10ms). When the data loop is between data bursts (draining all available data, then polling for more), this 10ms gap causes:
- 10ms of unprocessed data accumulation in the kernel recv buffer
- ~62KB of data at 50 Mbps (42 packets)
- Bursty processing pattern: 10ms idle → 42-packet burst → 10ms idle

The user-visible effect is latency spikes: a ping packet that arrives during the 10ms gap waits 10ms to be processed.

**Fix:**
```zig
const poll_timeout_ms: i32 = if (last_iter_had_work) @as(i32, 0) else @as(i32, 1);
```
Reducing idle timeout from 10ms to 1ms reduces the maximum data-wait gap by 10x. Using `poll(timeout=1)` instead of `poll(timeout=0)` also avoids the macOS `poll(0)` bug more reliably.

**Lesson:** macOS poll/select has a ~10ms minimum granularity due to the scheduler tick. `poll(0)` is unreliable — it may sleep for 1 tick. Use `poll(1)` for idle mode to guarantee at most 1ms behavior.

---

### RC8: Auto-Reconnect Default Masked Transient Issues

**Severity:** Low (operational)  
**File:** `src/cli/args.zig`, `src/cli/config_manager.zig`  
**Fixed by:** Changing default from `true` to `false`

**Mechanism:**
Auto-reconnect was enabled by default. When the data loop encountered a connection drop (from RC3, RC5, or network issues), it would silently reconnect. The user wouldn't see the failure, and the underlying bug was masked. During performance testing, the auto-reconnect would establish a new session on a different cluster node, making before/after comparisons unreliable.

**Fix:**
```zig
reconnect: bool = false,
```

**Lesson:** Auto-reconnect defaults should be `false` during development and testing. It should only be enabled in production deployments where the user has explicitly opted in.

---

### RC9: sendq Throttle Thresholds Unchanged After Buffer Size Changes

**Severity:** Low  
**File:** `src/client/vpn_client.zig` → outbound section  
**Fixed by:** Aligning throttle thresholds with SO_SNDBUF

**Mechanism:**
The sendq throttle thresholds (`sendq_throttle_med = 256KB`, `sendq_throttle_high = 512KB`) were designed when SO_SNDBUF was 4MB. When SO_SNDBUF was reduced to 2MB (or absent), these thresholds consumed 12-25% of the buffer at the high end, leaving too little headroom. At the med threshold (256KB), the batch was already halved when the buffer was only 12% full of a 2MB buffer.

**Fix:**
Adjust throttle thresholds proportionally to SO_SNDBUF:
- `med` = 12.5% of SO_SNDBUF (256KB for 2MB)
- `high` = 25% of SO_SNDBUF (512KB for 2MB)

**Lesson:** Throttle thresholds must be expressed as percentages of the buffer size, not absolute values. If the buffer size changes, the thresholds must be updated too.

---

## 5. Diagnostic Methodology

### DIAG Metrics Reference

```
DIAG dl=XX.X ul=YY.Y drain[avg=Z.ZZ max=N caps=M]
     ssl_pend_max=K nread_max=R nwrite_max=W pollout_skip=P
     tcp_drop=D fda_drop=F iters=I slow[10ms=A 50ms=B 100ms=C]
     poll_us[max=Q] sendq[max=S avg=A] write_blocked=B

Legend:
  dl/ul       : Throughput in Mbps
  drain avg   : Average batches drained per iter (0.00-1.00)
  drain max   : Max batches drained in one iter
  drain caps  : Times drain hit MAX_INBOUND_DRAIN limit
  ssl_pend_max: Max decrypted bytes pending in OpenSSL buffer
  nread_max   : Max kernel recv queue depth (bytes)
  nwrite_max  : Max kernel send queue depth (bytes)
  pollout_skip: Times poll() was skipped (data was pending)
  tcp_drop    : TLS send drops (WouldBlock)
  fda_drop    : TUN write drops (EAGAIN)
  iters       : Data loop iterations per second
  iter_us     : Iteration time in microseconds (avg / max)
  slow[10ms]  : Iterations that took >10ms
  poll_us[max]: Maximum poll() time in microseconds
  sendq       : Kernel send buffer occupancy (max / avg)
  write_blocked: Times writeAllNonBlocking polled POLLOUT
```

### How to Diagnose Each Root Cause

| Symptom | Check this metric | Probable RC |
|---------|------------------|-------------|
| UL drops after burst, DL collapses during UL | `write_blocked` > 100, `sendq[max]` = SO_SNDBUF | RC1 (buffer too large) |
| DL starts strong then collapses (48→7 Mbps) | `iters` drops between consecutive DIAG lines, ROUTE-ROGUE warnings appear | RC2 (logRoutingDiag) |
| Connection drops with BrokenPipe during UL | DIAG shows no preceding tcp_drops, then disconnect | RC3 (writeAll) |
| TooManyBlocks flood, no DIAG lines between | Non-tunnel data being parsed as batches | RC4 (recv_buf) |
| Connection kills itself during DL test | Health check error in log, `disconnect_reason = broken_data_plane` | RC5 (health check) |
| Latency spikes 3s+ during download, fda_drop=0 | TUN write failures masked by catch{} | RC6 (TUN EAGAIN) |
| Latency spikes ~10ms during idle periods | `slow[10ms]` > 0, `pollout_skip` low | RC7 (macOS poll) |
| Silent reconnection between tests | No disconnect visible, different server IP in next session | RC8 (auto-reconnect) |
| UL stalls even with moderate sendq | `sendq` at throttle threshold, batch count stagnant | RC9 (throttle alignment) |

---

## 6. Lessons Learned

### Principle 1: Never block in the event loop
The data loop is a single-threaded I/O multiplexer. Any synchronous operation that takes >100μs degrades throughput. Process spawning (RC2), blocking reads (RC2), or even `poll(timeout=10)` on a busy connection (RC7) all cause observable performance drops.

**Checklist:**
- [ ] No `fork()`/`exec()` in the hot path
- [ ] No `sleep()` in the hot path  
- [ ] No synchronous file I/O in the hot path
- [ ] All blocking operations use the poll() multiplexer

### Principle 2: OpenSSL non-blocking mode is a state machine
`SSL_read()` and `SSL_write()` in non-blocking mode have strict sequencing requirements:
- `WANT_READ` → must retry `SSL_read` with same buffer
- `WANT_WRITE` → must retry `SSL_write` with same buffer
- Never call the other operation (e.g., `SSL_read` after `SSL_write` returned `WANT_WRITE`)

**Checklist:**
- [ ] `writeAllNonBlocking` or equivalent (never `writeAll` on non-blocking SSL)
- [ ] `tryReadU32`/`tryReadInto` properly returns WouldBlock without consuming data
- [ ] State machine preserves partial read state across WouldBlock

### Principle 3: Buffer sizing must be validated empirically
Every buffer size decision must be verified with actual sendq/nread measurements. The `SO_NWRITE` / `SO_NREAD` values tell the true story, not kernel documentation.

**Checklist:**
- [ ] Measure actual `sendq` during max throughput test
- [ ] Confirm the buffer doesn't fill during steady state
- [ ] If it does fill, ensure drain time is < 200ms
- [ ] Throttle thresholds proportional to actual buffer capacity

### Principle 4: Drop nothing silently
In a VPN tunnel, dropped packets trigger TCP retransmission storms inside the tunnel. Silent drops (caught by `catch {}` without logging or backpressure) are indistinguishable from network packet loss.

**Checklist:**
- [ ] Every `catch {}` either logs, counts, or backpressures
- [ ] TUN write failures set a flag to pause inbound processing
- [ ] TLS write WouldBlock is counted and reported
- [ ] No `_ = expr catch {};` in the data path without tracking

### Principle 5: Health checks must understand the traffic pattern
A health check that triggers on asymmetric traffic will false-positive during download-only tests. Ratio-based checks (UL/DL) are fundamentally flawed for a VPN carrying bidirectional user traffic.

**Checklist:**
- [ ] Health checks measure liveness, not traffic ratio
- [ ] Use explicit keepalives with expected responses
- [ ] Grace period accounts for all traffic patterns
- [ ] False positive rate is zero under all normal traffic patterns

---

## 7. Prevention Checklist

Before merging any change to the data loop, verify:

### Structural
- [ ] No synchronous process spawn
- [ ] No blocking I/O (unless preceded by poll confirmation)
- [ ] No `catch {}` that silently discards errors
- [ ] All error paths either: log + count, or provide backpressure

### SSL / OpenSSL
- [ ] All SSL operations use non-blocking-aware wrappers
- [ ] `WANT_READ` / `WANT_WRITE` are retried with same buffer
- [ ] No operation-switching between SSL_read and SSL_write without completing pending operation

### Buffer Management
- [ ] SO_SNDBUF explicit (not kernel default)
- [ ] SO_SNDBUF measured via sendq to confirm it doesn't fill
- [ ] Throttle thresholds proportional to buffer size
- [ ] SO_RCVBUF explicit (enforced for advertised window)

### macOS-Specific
- [ ] `poll(timeout=0)` not used — use `poll(timeout=1)` as minimum
- [ ] No assumption about poll granularity — measure via `slow[10ms]`

### Diagnostics
- [ ] DIAG metrics cover all potential bottleneck points
- [ ] DIAG-TX trace triggered by traffic ratio, not absolute thresholds
- [ ] No diagnostic code in the hot path that blocks

---

## Appendix A: Final Config Values

| Setting | Value | Rationale |
|---------|-------|-----------|
| `SO_SNDBUF` | 2MB | BDP headroom at ~90 Mbps / 180ms RTT, no bufferbloat |
| `SO_RCVBUF` | 4MB (desktop), 1MB (iOS) | Advertised window for up to 178 Mbps / 180ms RTT |
| `poll_timeout_ms` (idle) | 1ms | Bounds macOS scheduler tick latency |
| `poll_timeout_ms` (active) | 0ms | Maximum responsiveness during data flow |
| `MAX_INBOUND_DRAIN` | 256 | Handles large server bursts without cap hits |
| `OUTBOUND_BATCH` | 64 | Matches sendBlocksZeroCopy batching |
| `sendq_throttle_med` | 256KB | 12.5% of SO_SNDBUF |
| `sendq_throttle_high` | 512KB | 25% of SO_SNDBUF |
| `auto_reconnect` | false | Debug transparency |
| `Health check` | disabled | False positive on asymmetric traffic |

## Appendix B: Key Code Locations

| Component | File | Lines |
|-----------|------|-------|
| Data loop main poll | `src/client/vpn_client.zig` | 1790-1800 |
| Poll timeout selection | `src/client/vpn_client.zig` | 1794 |
| Inbound drain | `src/client/vpn_client.zig` | 1850-1990 |
| Outbound section | `src/client/vpn_client.zig` | 2050-2150 |
| Sendq throttle | `src/client/vpn_client.zig` | 2050-2055 |
| write_fn (single) | `src/client/vpn_client.zig` | 1434-1437 |
| write_fn (multi) | `src/client/connection_manager.zig` | 132-135 |
| writeAllNonBlocking | `src/net/tls.zig` | 795-818 |
| clearTimeouts (socket opts) | `src/net/tls.zig` | 870-925 |
| TUN write (utun) | `src/adapter/utun.zig` | 496-534 |
| processInboundBlock | `src/client/vpn_client.zig` | 1091-1289 |
| receiveBlocksBatch | `src/protocol/tunnel.zig` | 260-420 |
| sendBlocksZeroCopy | `src/protocol/tunnel.zig` | 428-464 |
| DIAG logging | `src/client/vpn_client.zig` | 2370-2420 |
