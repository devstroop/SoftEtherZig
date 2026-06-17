# RCA-03: UDP Acceleration (RUDP)

> **Date:** 2026-06-18  
> **Status:** Final  
> **Supersedes:** N/A  
> **Covered in SCOPE.md:** RCA-03 (HIGH)

---

## Executive Summary

The UDP Acceleration (RUDP) subsystem provides an alternative data path over UDP for reduced latency and improved throughput. The implementation has 10 identified gaps, including a critical sequencing bug where the high-level `performHandshake()` convenience function passes `null` for the bulk key exchange, making the feature silently non-functional for any code path using it. The NAT traversal mechanism is minimal (no actual hole-punching), HMAC key derivation is weak (SHA1 of AES key), and there is no re-probing after failure. Despite these issues, the feature gracefully degrades to TCP on failure and does not impact the primary data path.

---

## Architecture Context

```
Auth negotation:
  Client → Server: support_bulk_on_rudp=true, bulk keys
  Server → Client: use_udp_acceleration=true, port, echo keys

If enabled:
┌─────────────────────┐
│  UdpAccelEngine      │
│  State: idle→probing │
│         →established │
│         →failed      │
├─────────────────────┤
│  AES-128-CBC +       │
│  HMAC-SHA1           │
│  Per-packet:         │
│  [flags|IV|ct|HMAC]  │
└─────────┬───────────┘
          │
┌─────────▼───────────┐
│  Data Loop:          │
│  Outbound: try UDP   │
│           → TCP on fail │
│  Inbound: UDP recv   │
│           → eth frame   │
└─────────────────────┘
```

The UDP acceleration uses **AES-128-CBC** (not the session's AES-256-CBC) with HMAC-SHA1 integrity checks. Packets have a fixed overhead: 1 byte flags + 16 bytes IV + ciphertext + 20 bytes HMAC = 37 bytes per packet.

---

## Root Causes

### Bug #1: `performHandshake()` passes `null` for bulk_keys

**File:** `src/protocol/softether_protocol.zig:1359`  
**Severity:** High (feature non-functional for some callers)

```zig
try buildPasswordAuth(allocator, username, pwd, hub_name, &hello.random,
    0, "", udp_accel, null, default_opts); // ← null for bulk_keys
```

The high-level `performHandshake()` function always passes `null` for the `bulk_keys` parameter, even when `udp_accel=true`. The `buildPasswordAuth()` function (and all other auth builders) only add the bulk key exchange fields when `bulk_keys != null`:

```zig
if (opts.bulk_keys) |keys| {
    try auth_pack.addUdpAccelFields(pack_ref, keys);
}
```

Since bulk_keys is null, the bulk key fields (`use_udp_acceleration`, `bulk_on_rudp_send_key`, `bulk_on_rudp_recv_key`) are NEVER sent in the auth pack when using `performHandshake()`. The server sees no keys, cannot enable UDP acceleration, and responds with `use_udp_acceleration=false`.

**Impact:** Any code path that uses `performHandshake()` for authentication will never establish UDP acceleration, even when explicitly requested. The feature silently doesn't work.

**Contrast:** The `auth_handler.run()` path (used by `VpnClient`) correctly generates `UdpBulkKeys`, stores them in `client.bulk_keys`, and the auth builders include them. So the main `VpnClient` path IS functional, but the convenience helper is broken for any external consumer.

---

### Bug #2: Minimal NAT Traversal (no actual hole-punching)

**File:** `src/net/udp_accel.zig` — `sendProbe()`  
**Severity:** Medium (fails on symmetric NATs)

The NAT-T probe is minimal:

```zig
fn sendProbe(self: *UdpAccelEngine) !void {
    var buf: [16]u8 = undefined;
    buf[0] = FLAG_NATT_PROBE; // 0x04
    std.crypto.random.bytes(buf[1..]);
    _ = try self.socket.sendTo(self.server_addr, &buf);
}
```

There is no:
- **STUN-style address discovery** (no `xor-mapped-address` to learn public IP:port)
- **Port prediction** (no sequence of probes to predict NAT port allocation)
- **Differential behavior** for Full Cone vs Restricted vs Symmetric NATs
- **Retry with different ports** on probe failure

The implementation simply sends a probe and waits for any response. This works for Full Cone NATs (any response accepted) and may work for Restricted Cone, but will fail for Symmetric NATs where the server's source port changes and doesn't match what the NAT expects.

---

### Bug #3: Weak HMAC Key Derivation

**File:** `src/client/auth_handler.zig:491-492`  
**Severity:** Medium (security)

```zig
std.crypto.hash.Sha1.hash(&send_key, &send_hmac, .{});
std.crypto.hash.Sha1.hash(&recv_key, &recv_hmac, .{});
```

HMAC keys are derived by SHA-1 hashing the AES bulk keys. If an attacker recovers the AES key (e.g., through a side channel), the HMAC key is immediately known and forged packets can be injected into the UDP stream.

A proper construction would use independent random HMAC keys or a KDF (HKDF-Expand with separate labels).

---

### Bug #4: No Re-Probing After Failure

**File:** `src/net/udp_accel.zig` — `tick()`  
**Severity:** Medium (permanent UDP loss)

Once the engine transitions to `.failed` state, it never returns to `.probing`. There is no mechanism to re-probe and re-establish the UDP path if the network recovers (e.g., after a temporary NAT timeout). The only way to re-enable UDP acceleration is to tear down and re-establish the entire VPN connection.

---

### Bug #5: No Congestion Control or Packet Recovery

**File:** `src/net/udp_accel.zig` — `checkSeq()`  
**Severity:** Medium (packet loss sensitivity)

```zig
fn checkSeq(self: *UdpAccelEngine, seq: u32) bool {
    const gap = seq -| self.last_seq;
    if (gap > MAX_SEQ_GAP) return false; // MAX_SEQ_GAP = 16384
    self.last_seq = seq;
    return true;
}
```

The only packet handling is a sequence gap check (rejects packets > 16384 seq numbers out of order). There is no:
- **Retransmission** (lost packets are never re-sent)
- **ACK mechanism** (no feedback about what was received)
- **Congestion control** (sends at application's pace, no rate limiting)
- **FEC** (no forward error correction)
- **Reorder buffer** (out-of-order packets within 16384 window are passed through, potentially causing higher-level reordering)

The UDP channel is effectively "best effort" with simple integrity checks. The SoftEther protocol relies on the TCP-on-VPN layer to handle retransmission, which creates an outer TCP-over-UDP-over-TCP stack with potentially pathological interactions.

---

### Bug #6: No UDP in Standalone Test Sources

**File:** `build.zig:469-490`  
**Severity:** Low (test coverage gap)

```
test_sources = .{
    "src/net/tls.zig",
    ...
    "src/net/udp_accel.zig", ← NOT listed
    ...
};
```

The `udp_accel.zig` unit tests are NOT in the standalone `test_sources` list. They only run through the `all_test` step (if imported transitively). This means running `zig build test -- udp` won't find them, reducing the likelihood that regressions are caught.

---

### Bug #7: AES-128 vs AES-256 Confusion

**File:** `src/net/udp_accel.zig`, `src/crypto/cipher.zig`  
**Severity:** Low (works correctly but worth documenting)

| Layer | Cipher | Key size |
|-------|--------|----------|
| TCP session | AES-256-CBC | 32 bytes |
| UDP acceleration | AES-128-CBC | 16 bytes |
| TLS transport | AES-128/256-GCM | negotiated |

The UDP accel uses AES-128-CBC while the TCP session uses AES-256-CBC. This is consistent with the SoftEther protocol specification but creates potential confusion for maintainers. Both use different key material:
- UDP bulk keys: randomly generated 16-byte keys exchanged during auth
- TCP session keys: derived via SHA-256 from password hash + server challenge

---

### Bug #8: Fixed Buffer Size for UDP Payload

**File:** `src/net/udp_accel.zig` — `MAX_UDP_PAYLOAD`  
**Severity:** Low (packets > 1472 bytes silently dropped)

```
const MAX_UDP_PAYLOAD = 1472; // 1500 - 28 (IP+UDP headers)
```

The encrypt and decrypt buffers are fixed at this size. Any Ethernet frame larger than 1472 bytes (the tunnel's MTU minus IP+UDP headers) will overflow and be silently dropped. The TCP fallback in the data loop handles these packets, so no data is lost, but the UDP offload ratio decreases with larger packets.

---

## Detection

UDP acceleration issues manifest as:
- **No UDP traffic** even when `udp_acceleration=true` is configured
- **Diagnostic:** Check if `use_udp_acceleration=true` appears in server auth response
- **Latency spikes** when a NAT binding times out and the engine transitions to `.failed`
- **Static `probing` state** never transitions — NAT is likely symmetric

DIAG metrics:
```
Look for udp_accel.enabled or udp_readable in log
Check bulk_on_rudp fields in auth exchange
Monitor engine state transitions if logged
```

---

## Lessons Learned

### 1. Convenience functions must not silently omit critical features
`performHandshake()` should either:
- Accept and forward `bulk_keys` parameter
- Or document that UDP acceleration is not supported through this path

### 2. NAT traversal requires proper hole-punching
Minimal "send and wait" probing only works for Full Cone NATs. A production-quality implementation needs STUN-style address discovery or at least port prediction.

### 3. Independent key material for separate security layers
HMAC keys derived from AES keys provide no defense-in-depth. If the AES key is compromised, both confidentiality and integrity are lost.

---

## Prevention Checklist

- [ ] Auth helper functions pass through all optional features (bulk_keys, etc.)
- [ ] NAT-T probing includes address discovery for symmetric NAT detection
- [ ] HMAC keys are independent random values, not derived from encryption keys
- [ ] Engine supports re-probing after failure (periodic retry)
- [ ] Test sources include all modules with unit tests
- [ ] Fixed buffer limits are documented and enforced with clear drop counters
- [ ] No reordering of UDP packets without sequence-number-based reorder buffer

---

## References

- `src/net/udp_accel.zig` — Full engine (646 lines, 10 unit tests)
- `src/protocol/softether_protocol.zig` — Auth negotiation fields
- `src/client/auth_handler.zig` — `startUdpAcceleration()` (lines 483-517)
- `src/crypto/cipher.zig` — AES-CBC implementation
- `build.zig:469-490` — Test sources
- `SoftEtherVPN/src/Cedar/UdpAccel.c` — Reference C implementation (full file)
- `SoftEtherVPN/src/Mayaqua/Network.c` — RUDP retransmission + NAT-T (full file)
- `SoftEtherVPN/src/Mayaqua/Network.h` — RUDP constants (`RUDP_RESEND_TIMER`, `UDP_NAT_T_*`)
- `SoftEtherVPN/src/Cedar/Protocol.c` — Bulk key exchange in Welcome pack (lines 6529-6551)
- SCOPE.md RCA-03

---

## Cross-Validation Against C Source

After writing this RCA, the Zig implementation was validated against the reference C source at `SoftEtherVPN/src/Cedar/` and `SoftEtherVPN/src/Mayaqua/`. Five significant discrepancies were found:

### Discrepancy #1: Cipher Algorithm (RC4/ChaCha20 vs AES-128-CBC)

**RCA Claim:** Uses AES-128-CBC for UDP bulk data.

**Actual C behavior:**

| Version | C Cipher | C Key Size | Zig Cipher | Impact |
|---------|----------|------------|------------|--------|
| V1 | **RC4** (NewCrypt/Encrypt) | 20 bytes (SHA1_SIZE) | AES-128-CBC | ⚠️ WRONG — incompatible cipher |
| V2 | **ChaCha20-Poly1305** (AEAD) | 128 bytes | Not implemented | ❌ MISSING — no V2 support |

V1 RC4 (`UdpAccel.c:588-591`):
```c
c = NewCrypt(key, UDP_ACCELERATION_PACKET_KEY_SIZE_V1);  // RC4 key (20 bytes)
Encrypt(c, tmp + ..., tmp + ..., size - ...);              // RC4 encrypt
FreeCrypt(c);
```

V2 ChaCha20-Poly1305 (`UdpAccel.c:547-556`):
```c
Aead_ChaCha20Poly1305_Ietf_Encrypt(tmp + UDP_ACCELERATION_PACKET_IV_SIZE_V2,
    tmp + ..., size - ..., a->MyKey_V2, a->NextIv_V2, NULL, 0);
```

The Zig implementation uses AES-128-CBC (16 bytes key) which is neither the V1 RC4 (20 bytes key) nor the V2 ChaCha20-Poly1305 (128 bytes key) used by the C source. This means the Zig UDP acceleration is **wire-incompatible** with a standard SoftEther server.

### Discrepancy #2: NAT-T Re-Probing

**RCA Claim:** "No re-probing after failure."

**Actual C behavior:** The C source has exponential backoff re-probing (`UdpAccel.c:289-333`):
```c
a->CommToNatT_NumFail++;
rand_interval = UDP_NAT_T_INTERVAL_INITIAL * MIN(a->CommToNatT_NumFail, UDP_NAT_T_INTERVAL_FAIL_MAX);
// 3s initial, 3s*60=180s max exponential backoff
a->NextPerformNatTTick = a->Now + (UINT64)rand_interval;
```

After success, periodic re-probing at 5-10 minute intervals:
```c
// UDP_NAT_T_INTERVAL_MIN = 5 min, UDP_NAT_T_INTERVAL_MAX = 10 min
rand_interval = GenRandInterval(UDP_NAT_T_INTERVAL_MIN, UDP_NAT_T_INTERVAL_MAX);
```

The Zig implementation has no re-probing after the initial probe fails or after establishment.

### Discrepancy #3: RUDP Retransmission and Congestion Control

**RCA Claim:** "No congestion control or retransmission."

**Actual C behavior:** The C source has a FULL retransmission engine in `Network.c:2667-2698`:
- Segment-based send list with sequence numbers
- RTT measurement (`CurrentRtt = Now - LatestRecvMyTick`)
- Exponential backoff: `next_interval = RTT * 120% * 2^NumSent`, capped at 4792ms
- ACK processing: cumulative ACK removes acknowledged segments
- Window: `RUDP_MAX_NUM_ACK = 64` segments

The Zig implementation has none of this — UDP packets are fire-and-forget with only sequence gap detection.

### Discrepancy #4: Bulk Key Exchange

**RCA Claim:** `performHandshake()` passes null bulk_keys (feature is silently non-functional).

**Actual C behavior:** The C source ALWAYS exchanges bulk keys through the Welcome pack if both sides support it (`Protocol.c:6529-6551`):
```c
if (s->EnableBulkOnRUDP)
{
    PackAddBool(p, "enable_bulk_on_rudp", true);
    PackAddData(p, "bulk_on_rudp_send_key", ..., size);
    PackAddData(p, "bulk_on_rudp_recv_key", ..., size);
}
```

There is no code path where bulk keys are null when bulk is enabled. The Zig `performHandshake()` function that passes `null` for bulk_keys has NO equivalent in C — the C auth path always includes keys.

### Discrepancy #5: `rudp_bulk_version` Negotiation

**RCA Claim:** Not mentioned — the RCA missed version negotiation entirely.

**Actual C behavior:** The protocol negotiates RUDP bulk version:
- Client sends `rudp_bulk_max_version` (2 if supported)
- Server responds with `rudp_bulk_version` (clamped to min of both)
- V1: 20-byte keys, RC4 per-packet encryption, SHA-1 HMAC
- V2: 32-byte keys, ChaCha20-Poly1305 AEAD (no separate HMAC), 12-byte IV, 16-byte MAC

The Zig implementation doesn't implement V2 at all and uses the wrong cipher (AES-128-CBC vs RC4) for V1.

### Implications for Zig Implementation

| Aspect | Zig | C Reference | Action Needed |
|--------|-----|-------------|---------------|
| V1 cipher | AES-128-CBC (16B key) | **RC4** (20B key) | Fix cipher to match C for server compatibility |
| V2 support | ❌ None | ✅ ChaCha20-Poly1305 | Implement V2 for security + performance |
| NAT-T re-probing | ❌ None | ✅ Exponential backoff + periodic refresh | Add re-probing with backoff |
| RUDP retransmission | ❌ None | ✅ Full segment ACK + RTT-based backoff | Implement RUDP reliability layer |
| Bulk key exchange | `performHandshake()` passes null | ✅ Always included in Welcome pack | Fix key exchange path |
| Version negotiation | Partial (sends max_version) | ✅ Full clamping and capability detection | Verify server response handling |


