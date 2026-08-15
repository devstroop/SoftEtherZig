# Server Admin RPC Transport Design — Native RPC Session (issue #87)

> **Date:** 2026-08-15
> **Author:** @devstroop
> **Status:** Final (implemented in PR #134, commit `b6e00a4`)
> **Plan ref:** SERVER_PLAN.md §6.5 (rpc.zig), Phase 1 step 2, milestone S17

---

## Executive Summary

The native admin RPC transport (`src/cedar/server/admin/rpc.zig`) is the
server-side session that carries SoftEther admin API calls. It is a TLS
connection on which each request is one Pack frame — `[u32 size][Pack bytes]`,
the size big-endian — dispatched on the Pack's `function_name` string to a
dispatcher table, and answered with a response Pack carrying `error` /
`error_code` fields. This module is a C-faithful port of `Remote.c`'s
server-side session (`StartRpcServer` / `RpcServer` / `RpcRecvNextCall` /
`CallRpcDispatcher`) plus the Pack error helpers from `Network.c`. It is
transport-only: the dispatcher table (issue #88) and the `RPC_*` structs
(issue #89) live in sibling modules and plug in through a single function
pointer.

---

## Architecture Context

```
vpncmd / SoftEther admin client           this Zig server
──────────────────────                    ─────────────────
TCP connect
  │  TLS handshake (SNI = host)             TLS accept (tls.zig accept path)
  ▼                                        ▼
Pack frame ──────┐                   acceptAdminConnection (listener AcceptHandler)
 [u32 size][Pack]│                   └─ startRpcServer(sock, dispatch, param)
                  │                        └─ runServer() loop
                  │                             └─ recvNextCall()
                  │                                  │ recvFrame → Pack
                  │                                  ├─ callDispatcher(function_name)
                  │                                  │    dispatch: *anyopaque → ?*Pack
                  │                                  └─ sendFrame(response Pack)
Pack frame ◄──────┘                                     (error / error_code on failure)
```

Layer ownership (per plan §10): `mayaqua` stays a platform abstraction — the
TLS primitives live in `tls.zig`. The frame format, session loop, and dispatch
plumbing are Cedar's business and live under `cedar/server/admin/`.

---

## Wire Format (fixed, must match C exactly)

One frame is:

```
offset  size   field
0       4      u32 size, big-endian   (number of following Pack bytes)
4       size   serialized Pack bytes  (pack.zig format)
```

- The size prefix is **big-endian on the wire**. C writes `Endian32(b->Size)`
  (`Remote.c:383-384`); `Endian32` only swaps on little-endian hosts
  (`Memory.c:4301`), so the wire is always network order. Zig mirrors this with
  `std.mem.writeInt(u32, …, .big)` / `readInt(…, .big)`.
- Inside the Pack, string/int element values follow pack.zig's own `.big`
  convention (the client already speaks this format, so it is the
  interoperability source of truth).
- Upper bound: `MAX_PACK_SIZE` (128 MB), same constant as pack.zig. A size of
  `0` or above the bound is an `InvalidFrameSize` and ends the session.
- A graceful close *between* calls (zero bytes on the 4-byte size read) is a
  normal session end — the loop returns quietly.

---

## Module Map (`src/cedar/server/admin/rpc.zig`)

### `Rpc` session struct (C `struct RPC`, Remote.h:112-127, server subset)

| Field | Meaning |
|-------|---------|
| `allocator` | Session allocator |
| `sock` | `*tls.TlsSocket`, the accepted TLS connection |
| `server_mode` | Always `true` (server side) |
| `dispatch` | `Rpc.Dispatcher` — the single function-pointer hook |
| `param` | `*anyopaque` context handed to the dispatcher |
| `server_admin_mode`, `hub_name`, `name`, `is_vpn_server` | Carried for the dispatcher (issue #88 uses these for permission scoping); transport does not interpret them |

### `Rpc.Dispatcher` — the extension point

```zig
pub const Dispatcher = *const fn (
    rpc: *anyopaque,       // owning *Rpc, @ptrCast'd by the caller
    function_name: []const u8,
    request: *Pack,
) ?*Pack;                  // null → transport replies ERR_NOT_SUPPORTED
```

- Mirrors C `RPC_DISPATCHER` (Remote.h:109).
- `rpc` is `*anyopaque` (not `*Rpc`) **to break a Zig type dependency loop**:
  the struct field's function-pointer type would otherwise reference the very
  struct that holds it. Same trick as listener.zig's `AcceptHandler`. Callers
  recover the real pointer with `@ptrCast(@alignCast(rpc))`.
- Return contract: heap-allocated response Pack owned by the transport (freed
  after the reply is sent), or `null` for "function not supported".
- Issue #88 (`admin/dispatch.zig`) supplies the real table with this signature.

### Session lifecycle

- `startRpcServer(allocator, sock, dispatch, param) Rpc` — C `StartRpcServer`
  (Remote.c:429). Returns a **value**, not a pointer (C returns `RPC *`; Zig
  keeps it a value; the accept handler owns it on the stack).
- `runServer(self) void` — C `RpcServer` (Remote.c:277): `while (recvNextCall()) {}`.
- `recvNextCall(self) bool` — C `RpcRecvNextCall` (Remote.c:201): read one
  request frame → `callDispatcher` → reply frame. Returns false (ending the
  session) on close, invalid frame, or send failure.
- `callDispatcher` — C `CallRpcDispatcher` (Remote.c:183). Missing
  `function_name` is treated as "not supported" (null), same as C.

### Frame I/O

- `sendFrame(sock, allocator, p)` — serialize Pack, write BE size then bytes.
- `recvFrame(allocator, sock) !?Pack` — read size, validate, read payload,
  parse. Returns `null` on graceful close before a frame.
- `recvAll(sock, buf)` — blocking exact read. The accepted TLS socket stays
  blocking with **no SO_RCVTIMEO** after the handshake (tls.zig drops it), so a
  read that returns `WouldBlock` spins a `poll(-1)` until data arrives —
  mirroring C's blocking `RecvAll` on the admin control connection. No
  keep-alive or idle timeout.

### Error helpers (C `Remote.c` / `Network.c`)

| Zig | C | Behavior |
|-----|---|----------|
| `packError(alloc, code)` | `PackError` (Network.c:22792) | Pack with only `error = code` |
| `rpcError(p, err)` | `RpcError` (Remote.c:170) | `error = 1` + `error_code = err` |
| `rpcIsOk(p)` | `RpcIsOk` (Remote.c:151) | success iff `error == 0` (absent counts as 0) |
| `rpcGetError(p)` | `RpcGetError` (Remote.c:139) | the `error_code` field |
| `getErrorFromPack(p)` | `GetErrorFromPack` (Network.c:22803) | raw `error` field |

Constants: `max_pack_size = MAX_PACK_SIZE`, `err_not_supported = 33`
(`ERR_NOT_SUPPORTED`, Cedar.h).

### Accept handler

`AdminRpcContext` (allocator + cert/key PEMs + `dispatch` + `param`) is the
bootstrap-owned context. `acceptAdminConnection(ctx, sock, peer_ip, peer_port)`
is a listener.zig `AcceptHandler`: it TLS-accepts (15 s `CONNECTING_TIMEOUT`
handshake timeout), then runs the RPC loop for the connection's lifetime.
Mirrors accept.zig's `acceptConnection` structure.

---

## Key Decisions

1. **`*anyopaque` dispatcher param instead of `*Rpc`** — avoids the Zig
   "dependency loop detected" compile error between a struct and the function
   pointer type stored in it. Cast cost is a single `@ptrCast(@alignCast)` at
   the call sites; the dispatcher signature stays self-documenting.
2. **Frame size is big-endian on the wire** — verified against C `Endian32`
   (Memory.c:4301: on LE hosts the function returns `Swap32`, i.e. it writes
   network order). Do not "fix" this to native-endian; it would break interop.
3. **Blocking session with indefinite reads** — no timeout on the read loop,
   matching C semantics for the control connection. The 15 s timeout applies
   only to the TLS handshake.
4. **Transport does not interpret `hub_name` / `server_admin_mode`** — those
   are dispatcher inputs (permission scoping) owned by issue #88.
5. **`startRpcServer` returns a value** — the accept handler places the `Rpc`
   on its stack; nothing heap-allocates the session itself.

---

## Testing Strategy

- **`server.admin_rpc` filter** (build.zig `all_test`, trailing-space form —
  the #85 substring-filter bug means `"server.admin_rpc."` must never be used):
  - `dispatch round-trip over TLS` — AF_UNIX `socketpair`, server thread calls
    `acceptAdminConnection`, client does `TlsSocket.connect(..., .{
    allow_self_signed = true, external_tcp_dial = testDial })` (Linux-only,
    mirrors accept.zig tests). Asserts ok response, `value = 42`, dispatcher
    call count.
  - `unknown function replies ERR_NOT_SUPPORTED` — asserts `error = 33`.
  - `error helpers` — pure-Pack assertions for `rpcError`/`rpcIsOk`/
    `rpcGetError`/`getErrorFromPack`, including absent-`error` == success.
- **Leak discipline**: `EndToEnd.deinit` destroys thread ctx, admin ctx, and
  the dispatcher `param` (the last one was the fix that took the run from 2
  leaked allocations to 0).
- Full suite: 367/367 tests pass, 0 leaks; `zig build` succeeds.

---

## Follow-ups (plug into this transport)

- Issue #88 `admin/dispatch.zig` — the ~35-endpoint dispatcher table with this
  `Dispatcher` signature; sets `server_admin_mode` / `hub_name` on the Rpc.
- Issue #89 `admin/structs.zig` — `RPC_*` structs + Pack (de)serialization
  that endpoint handlers use.
- Issue #90 — vpncmd-style admin CLI on top of the same frame format.
- Issue #91 — multi-hub: the `hub_name` field starts being interpreted.

---

## References

- `src/cedar/server/admin/rpc.zig` — this module (PR #134, commit `b6e00a4`)
- `src/cedar/server/mod.zig`, `src/lib.zig`, `build.zig` — wiring (test filter
  `"server.admin_rpc "`)
- `src/mayaqua/network/tls.zig` — `TlsSocket.accept` / `connect`,
  `generateSelfSignedCert`, `test_dial_fd` dial hook
- `src/mayaqua/network/socket.zig` — `TcpSocket`, AF_UNIX socketpair tests
- `src/cedar/protocol/pack.zig` — Pack (`addInt`/`addStr`/`toBytes`/
  `fromBytes`, `MAX_PACK_SIZE`)
- C refs: `SoftEtherVPN/src/Cedar/Remote.c` (183, 201, 277, 383-384, 429),
  `Remote.h` (109, 112-127), `Mayaqua/Network.c` (22792, 22803),
  `Mayaqua/Memory.c` (4301), `Cedar/Cedar.h` (`ERR_NOT_SUPPORTED = 33`)
- SERVER_PLAN.md §6.5, Phase 1 step 2, S17
