# RCA-01: AES-256-CBC Session Encryption

> **Date:** 2026-06-18  
> **Status:** Final  
> **Supersedes:** N/A  
> **Covered in SCOPE.md:** RCA-01 (HIGH)

---

## Executive Summary

The AES-256-CBC session encryption layer — designed to provide per-packet encryption on top of TLS — is **completely dead code**. The `encrypt()` / `decrypt()` methods are never called from the actual data path. Tunnel data flows as raw Ethernet frames over TLS without any application-layer encryption. Additionally, even if the encryption were wired up, two independent bugs would cause either immediate data corruption (key derivation uses SHA-256 instead of SHA-0, producing wrong AES keys) or silent data loss (the encrypted output is freed without being transmitted).

The net effect is that the tunnel relies solely on TLS for confidentiality — despite `use_encrypt=true` being set and "Session established with AES-256-CBC encryption" being logged.

---

## Architecture Context

```
┌───────────────────┐
│  TLS 1.3 Tunnel   │  ← provides transport security (AES-128/256-GCM)
│  (SSL_read/write) │
└────────┬──────────┘
         │
┌────────▼──────────┐
│ Application Layer │  ← was supposed to add AES-256-CBC per-packet encryption
│ SoftEther blocks  │    on TOP of TLS (defense-in-depth)
└────────┬──────────┘
         │
┌────────▼──────────┐
│ TUN Adapter       │  ← raw IP packets
└───────────────────┘
```

The SoftEther protocol specification calls for **double encryption**: TLS protects the transport, and AES-256-CBC protects each individual tunnel block. This follows the original C implementation at `SoftEtherVPN/src/Cedar/Encrypt.c`. The Zig implementation has the structure but the encryption calls were never wired into the data loop.

---

## Root Cause

### Bug #1: Dead code — encrypt/decrypt never called from data path

**Files:** `src/client/vpn_client.zig`, `src/session/wrapper.zig`  
**Call chain that should exist** (but doesn't):

```
Data loop (read from TLS)
  → receiveBlocksBatch
  → processInboundBlock
  → SessionWrapper.decrypt()  ← NOT CALLED
  → TUN write

Data loop (read from TUN)
  → wrapIpInEthernet
  → SessionWrapper.encrypt()  ← NOT CALLED
  → sendBlocksZeroCopy
  → TLS write
```

The actual call chain:

```
Data loop (read from TLS)
  → receiveBlocksBatch          ← reads raw, encrypted blocks
  → processInboundBlock         ← processes AS-IS, no decryption
  → TUN write                   ← writes raw encrypted data to TUN!

Data loop (read from TUN)
  → wrapIpInEthernet
  → sendBlocksZeroCopy          ← sends raw, unencrypted blocks
  → TLS write
```

**Grep proof:**

```
$ grep -rn "client.sendPacket\|self\.sendPacket\|client\.receivePacket\|self\.receivePacket\|\.encrypt(" src/client/ | grep -v test
→ No results found
```

The `VpnClient` struct has `sendPacket()` and `receivePacket()` methods, but they are **defined, never called** — no caller exists anywhere in the codebase.

### Bug #2: Encrypted output freed without transmission

**File:** `src/client/vpn_client.zig` — hypothetical `sendPacket()`  
**Lines:** 1072-1075

Even if `sendPacket()` were called, it contains a critical bug:

```zig
if (self.config.use_encrypt) {
    const encrypted = sess.encrypt(self.allocator, data) catch |err| {
        std.log.err("Failed to encrypt packet: {}", .{err});
        return;
    };
    defer self.allocator.free(encrypted);
    // ← encrypted is freed here but NEVER TRANSMITTED
    // ← the original `data` is also never transmitted
}
// ← nothing is ever written to any output
```

The encrypted result is stored in a local variable, `defer`-freed at function exit, and **never passed to any send function**. The function returns without transmitting anything in either branch.

### Bug #3: Wrong key derivation algorithm

**File:** `src/session/session.zig` — `SessionKeys.deriveFromAuth()`  
**Lines:** 316-347

The original SoftEther protocol specifies **SHA-0** for session key derivation:

```
send_key = SHA-0(session_key || server_challenge || 0x01)
recv_key = SHA-0(session_key || server_challenge || 0x02)
```

The Zig implementation uses **SHA-256**:

```
send_key = SHA-256(session_key || server_challenge || 0x01)  ← WRONG
recv_key = SHA-256(session_key || server_challenge || 0x02)  ← WRONG
```

Even if encryption were wired up, the derived AES keys would NOT match what the server computes, causing immediate decryption failure and connection drop.

### Bug #4: Orphaned session queue path

**File:** `src/session/session.zig` — `getNextSendPacket()`, `receivePacket()`  
**Lines:** ~400-500

The `Session` struct has a complete internal queue-based encryption path:
- `getNextSendPacket()` → dequeues a raw block, encrypts it, returns encrypted block
- `receivePacket()` → takes encrypted block, decrypts it, enqueues raw data

These functions are never called from ANYWHERE in the codebase (confirmed by grep). The entire session queue mechanism is orphaned dead code that exists only to pass unit tests.

### Bug #5: `use_encrypt=true` has no effect

**File:** `src/client/vpn_client.zig` — `connect()`  
**Lines:** ~880-890

```zig
if (!self.config.use_encrypt) {
    std.log.warn("Encryption disabled — tunnel data will NOT be encrypted at application layer", .{});
}
```

This warning is logged and `use_encrypt` is set to `true`. But since nothing in the data path checks `use_encrypt`, the flag is cosmetic. The log message "Session established with AES-256-CBC encryption" is misleading.

---

## Detection

This RCA was discovered during a systematic code review of encryption code paths, triggered by:

1. **Grep for `encrypt` callers** — found zero callers of `SessionWrapper.encrypt()` in the actual data path
2. **Tracing `sendPacket`** — found it's never called; grep for `sendPacket` across entire `src/` returned only the definition
3. **Code review of `sendPacket()`** — noticed the encrypted result is freed without being transmitted
4. **Reviewing `session.zig` key derivation** — discovered SHA-256 used instead of SHA-0 (protocol specification)

---

## Impact Assessment

| Impact | Severity | Description |
|--------|----------|-------------|
| Confidentiality | **NONE** | TLS 1.3 provides AES-128/256-GCM encryption. The application-layer AES-CBC was additive defense-in-depth. Without it, the tunnel is still secure against passive interception. |
| Server compatibility | **MINIMAL** | The SoftEther server's `use_encrypt` flag controls whether the server applies AES-CBC to tunnel blocks. If the server sends encrypted blocks (because it set `use_encrypt=true`), our client would receive raw ciphertext as "Ethernet frames" and write garbage to TUN. This would break all connectivity immediately on connection. Since no such breakage is reported, the server likely does NOT encrypt either (or uses a different negotiation path). |
| Code correctness | **CRITICAL** | The dead code represents 1156 lines of untested, unexercised session logic. If someone later tries to wire it up, they'll hit: (a) the `sendPacket()` free-before-transmit bug, (b) the SHA-256 vs SHA-0 mismatch, and (c) potential API incompatibilities between the two `Aes256Cbc` implementations. |

---

## Fix Required

The subsystem needs one of two approaches:

**Option A: Remove dead code** (recommended if no plan to wire up encryption)

```
- Remove SessionWrapper.encrypt() and decrypt()
- Remove VpnClient.sendPacket() and receivePacket()
- Remove Session.getNextSendPacket() and receivePacket()
- Remove the session.cipher internal queue logic
- Keep SessionKeys.deriveFromAuth() for the UDP acceleration path (if used)
- Change the "AES-256-CBC" log message to reflect actual encryption status
```

**Option B: Wire up encryption correctly** (recommended for protocol compliance)

```
- Fix VpnClient.sendPacket() to actually transmit the encrypted data
- Fix key derivation to use SHA-0 (or SHA-1 for modern compatibility)
- Insert encrypt/decrypt calls in the data path:
  receiveBlocksBatch → decrypt → processInboundBlock
  wrapIpInEthernet → encrypt → sendBlocksZeroCopy
- Add unit tests with known test vectors from the C implementation
- Verify against an actual server with use_encrypt=true
```

---

## Key Discovery

The investigation uncovered a deeper finding: **the `wrapper.zig` encrypt/decrypt functions are a SECOND, incompatible AES-256-CBC implementation**. There are now TWO separate `Aes256Cbc` structs in the codebase:

| File | API | Used by | Status |
|------|-----|---------|--------|
| `session/session.zig:50-152` | `encrypt(alloc, []u8) → []u8` (allocating, PKCS7 padding) | Session wrapper → dead code | Orphaned |
| `crypto/cipher.zig:107-168` | `encrypt(data: []u8) → void` (in-place, block-aligned) | UDP acceleration (`udp_accel.zig`) | ACTIVE |

Both are correct implementations sharing the same core AES engine (`std.crypto.core.aes.Aes256`). The API difference exists because they serve different use cases (allocating vs in-place). However, having two implementations with different APIs creates maintenance risk — changes to one won't be reflected in the other.

---

## Lesson Learned

### 1. Dead code must be tagged or removed
Any function defined but never called in the data path will inevitably drift out of sync with the actual protocol. If kept for future use, it must have:
- Explicit dead-code annotations in the file header
- Tests that validate against the live protocol (not just unit tests)
- A tracking issue linking to the feature that will call it

### 2. Log messages must reflect actual behavior
"Session established with AES-256-CBC encryption" implies a security property that does not exist. Log messages that describe security states must be verified against the actual code path, not just configuration flags.

### 3. Encryption code must be tested against known vectors
Key derivation, encryption, and decryption must have test vectors from the reference implementation (C source). A SHA-0 vs SHA-256 mismatch would be caught immediately by a test vector comparison.

---

## Prevention Checklist

- [ ] Every non-trivial function has at least one caller in the live code path
- [ ] Dead code is annotated with `// UNUSED` or removed
- [ ] Security-sensitive log messages are verified against the actual code path, not config flags
- [ ] Key derivation has test vectors from the reference implementation
- [ ] All encryption/decryption paths are exercised in integration tests
- [ ] Two implementations of the same algorithm share a test harness that runs both against known vectors

---

---

## Cross-Validation Against C Source

After writing this RCA, the Zig implementation was validated against the reference C source at `SoftEtherVPN/src/`. The following corrections and clarifications apply:

### Finding #1: C source uses RC4, not AES-256-CBC, for per-packet encryption

**Claim in RCA:** The C source applies AES-256-CBC per-packet encryption on top of TLS.

**Actual C behavior:** The C source has two **mutually exclusive** encryption modes:

```c
// Protocol.c:4188-4195
if (s->UseEncrypt && s->UseFastRC4 == false)
    s->UseSSLDataEncryption = true;   // Mode 1: TLS encryption via SSL socket
else
    s->UseSSLDataEncryption = false;  // Mode 2: RC4 per-packet or no encryption
```

**Mode 1 (TLS):** `UseSSLDataEncryption=true` → `Recv()`/`Send()` call `SSL_read()`/`SSL_write()` through OpenSSL. No application-layer encryption on top.

**Mode 2 (Fast RC4):** When `UseFastRC4=true`, TLS is NOT used for data. Instead, the raw TCP socket is used and per-packet RC4 encryption is applied in `WriteSendFifo`/`WriteRecvFifo` (`Connection.c:644-676`):

```c
void WriteSendFifo(SESSION *s, TCPSOCK *ts, void *data, UINT size)
{
    if (s->UseFastRC4) { Encrypt(ts->SendKey, data, data, size); }  // RC4
    WriteFifo(ts->SendFifo, data, size);
}
```

The `Encrypt()` function is an RC4 wrapper (`Encrypt.c:5316-5319`), using `NewCrypt()` which calls `RC4_set_key()` (`Encrypt.c:5290-5299`). RC4 keys are 128-bit random values from `Rand()` (`Protocol.c:8480-8490`).

**AES-256-CBC** exists in the C codebase but is used ONLY in the IPsec IKE code (`IPsec_IkePacket.c:2869`), NOT in the VPN session data path.

### Finding #2: SHA-0 is used for password hashing, not for key derivation

**Claim in RCA:** Key derivation uses SHA-0 (not SHA-256).

**Actual C behavior:** SHA-0 is used in `SecurePassword()` (`Sam.c:108-123`):
```c
void SecurePassword(void *secure_password, void *password, void *random)
{
    Hash(secure_password, b->Buf, b->Size, true);  // sha=true → SHA-0
}
```

Where `Hash(..., true)` calls `Internal_SHA0()` (`Encrypt.c:5232`). The SHA-0 implementation is confirmed by the missing rotation in the message schedule:
```c
W[t] = (1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);  // SHA-0: NO rotation
// SHA-1 would be: W[t] = rol(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
```

The Zig implementation uses SHA-256 for password hashing, which is a protocol deviation but actually SECURITY-IMPROVING (SHA-0 is cryptographically broken).

### Finding #3: The mutual exclusivity of TLS vs application encryption

The Zig codebase has TLS encryption (SSL_read/SSL_write in the data path) AND unused AES-256-CBC functions. The C source shows these are meant to be alternatives, not layers. The Zig implementation chose TLS-only (Mode 1) which is the modern, secure default.

### Implications for RCA Findings

| RCA Finding | C Source Confirmation | Impact |
|-------------|----------------------|--------|
| Dead AES-256-CBC code | ✅ C also has dead AES-CBC (only in IPsec code) | No change — both codebases have unused AES-CBC |
| Key derivation uses SHA-256 vs SHA-0 | ⚠️ C uses SHA-0, Zig uses SHA-256 | Zig is actually MORE secure (SHA-0 broken) but INCOMPATIBLE with standard SoftEther servers expecting SHA-0 hashing |
| Modes are mutually exclusive | ✅ TLS and per-packet encryption are never both active | The Zig `use_encrypt=true` + TLS is correct behavior per C spec |
| Two AES-256-CBC implementations | Not applicable to C | Both Zig implementations share same core AES engine |

---

## References

- `src/session/wrapper.zig` — Dead encrypt/decrypt (full file, 150 lines)
- `src/session/session.zig` — Session key derivation (lines 316-347), two Aes256Cbc implementations (lines 50-152)
- `src/client/vpn_client.zig` — `sendPacket()`/`receivePacket()` (lines ~1060-1100, never called)
- `src/crypto/cipher.zig` — Second Aes256Cbc implementation (lines 107-168), used by UDP acceleration
- `src/protocol/auth.zig` — Auth exchange (session key passing)
- `SoftEtherVPN/src/Cedar/Encrypt.c` — Reference C RC4 encryption + SHA-0 implementation
- `SoftEtherVPN/src/Cedar/Connection.c — WriteSendFifo/WriteRecvFifo (lines 644-676)
- `SoftEtherVPN/src/Cedar/Protocol.c` — Encryption mode selection (lines 4188-4195)
- `SoftEtherVPN/src/Cedar/Ipsec_IkePacket.c` — Only caller of AES-256-CBC in C (lines 2869, 2906)
- SCOPE.md RCA-01
