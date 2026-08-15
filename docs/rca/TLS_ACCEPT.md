# Server Phase 0 Design — TLS Accept + HTTP Server Envelope

> **Date:** 2026-08-15
> **Author:** @devstroop
> **Status:** Final (both parts implemented — part 1 in #112, part 2 in the #76 PR)
> **Plan ref:** SERVER_PLAN.md §11 #4, S5/S6

---

## Executive Summary

This is the Phase 0 design for the two foundational server-side changes that
unblock the rest of Server M1:

1. **TLS accept** (#75, this PR): `src/mayaqua/network/tls.zig` is
   connect-only today (single `pub fn connect`). It gains a server `accept`
   path (`TLS_server_method` + `SSL_accept`), server certificate/key loading,
   SNI capture, and a C-parity first-run self-signed certificate generator with
   a `--gen-cert` CLI flag.
2. **HTTP server envelope** (#76, next): `HttpServerRecvEx`/`HttpServerSend`
   equivalents so the RPC layer (`Remote.c`-style `rpc.zig`) can read a POST
   body and write a 200 response over the accepted TLS socket.

Both changes stay inside `mayaqua/network/` and do not introduce any server
session/hub logic — that arrives with S7 (listener) and S9/S14 (handshake/auth).

---

## Architecture Context

```
C client                          this Zig server
─────────                          ─────────────
TCP connect
  │  TLS handshake (SNI = host)      TLS accept (tls.zig accept path, S5)
  ▼                                  ▼
HTTP POST / (Pack body)  ──────►   HTTP server envelope (http.zig, S6)
                                    │  read POST → Pack body (rpc.zig, RPC dispatch)
                                    ▼
                                  200 + Pack body (http.zig server send)
                                    │
                                    ▼
                              session/hub logic (S7+, later milestones)
```

Layer ownership (per plan §10): `mayaqua` stays a platform abstraction. The
`TlsSocket`/`TlsListener` primitives and the HTTP read/write envelope belong in
`mayaqua/network/`. What a POST means (RPC, handshake, auth) is Cedar's
business and is deliberately out of scope for this design.

---

## Part 1 — TLS accept (`tls.zig`)

### Reference (C)

- `StartSSLWithSettings`/`StartSSLEx2` (Network.c:13888-14100): the server
  takes a connected TCP socket and runs `SSL_accept`. Server mode uses
  `TLS_server_method`; the cert/key come from `CERTS_AND_KEY` lists populated
  at startup from `server_cert`/`server_key`.
- SNI: C reads the client's SNI via `SSL_get_servername(ssl,
  TLSEXT_NAMETYPE_host_name)` for the `Hostname` used in session bookkeeping.
- First-run certs: `SiGenerateDefaultCertEx` (Server.c:2180-2218) builds a
  RSA-2048 keypair, CN = `"server.softether.vpn"` + machine name (unless an
  explicit common name is given), `NewName(cn, cn, cn, L"US", NULL, NULL)`,
  `NewRootX(...)` → `NewRootX509` (Encrypt.c:2908-3034):
  - X.509 v3, serial = single byte `0`
  - subject = issuer = the NAME above
  - `basicConstraints` = `critical,CA:TRUE`
  - `keyUsage` bits {0,1,2,3,5,6} (digitalSignature, nonRepudiation,
    keyEncipherment, dataEncipherment, keyCertSign, cRLSign)
  - EKU: serverAuth, clientAuth, codeSigning, emailProtection, ipsecEndSystem,
    ipsecTunnel, ipsecUser, timeStamping, OCSPSigning
  - notBefore = now, notAfter = now + `GetDaysUntil2038Ex()` days (target
    2038-01-01, or 2049-12-30 once the year is ≥2030)
  - signed SHA-256 with the private key

### API shape

```zig
pub const TlsServerConfig = struct {
    cert_pem: []const u8,          // server certificate, PEM
    key_pem: []const u8,           // private key, PEM
    min_version: TlsVersion = .tls_1_2,
    timeout_ms: u32 = 30000,
    tcp_nodelay: bool = true,
};

pub const TlsSocket = struct {
    // existing connect() ...
    pub fn accept(allocator: Allocator, tcp_fd: std.posix.socket_t, config: TlsServerConfig) !TlsSocket;
    pub fn peerSni(self: *const TlsSocket) []const u8;   // server mode only
};

pub const SelfSignedCert = struct { cert_pem: []u8, key_pem: []u8 }; // caller frees both
pub fn generateSelfSignedCert(allocator: Allocator, common_name: ?[]const u8) !SelfSignedCert;
```

### Design decisions

- **`accept` reuses `TlsSocket`.** The read/write/read-ahead/pending-write
  machinery is identical for both roles; only the handshake direction and the
  SSL_CTX construction differ. No parallel server socket type is created.
- **`TlsServerConfig` vs `TlsConfig`.** The client `TlsConfig` carries verify
  policy, SNI override, proxy, bind-interface and dial callbacks — none of
  which apply server-side. A lean struct keeps server defaults honest (e.g.
  verification is always off server-side; the client's cert IS the auth).
- **SNI is captured, not verified.** `SSL_get_servername` returns the raw
  hostname the client sent. C uses it as bookkeeping (`CONNECTION->Hostname`)
  and as a first hint before falling back to the certificate; it never
  validates against the accepted socket's address. We mirror that: store up to
  255 bytes on the accepted socket, expose `peerSni()`.
- **Keygen via `EVP_PKEY_CTX`, not `RSA_generate_key`.** The latter is
  deprecated in OpenSSL 3 and pulls in `openssl/rsa.h`. `EVP_PKEY_CTX_new_id(
  EVP_PKEY_RSA)` + `EVP_PKEY_keygen` is the supported path and is already
  reachable through the shared `c_imports.zig` (`openssl/evp.h`).
- **Shared cImport block.** `openssl/x509v3.h` is added to the single shared
  `c_imports.zig` block (both Windows and non-Windows) so `X509V3_EXT_conf_nid`
  etc. are available without creating a second translate-c unit (aarch64-windows
  symbol-collision rule).
- **`SSL_OP_BIT`-derived constants are unusable.** This OpenSSL's
  `SSL_OP_NO_SSLv3 = SSL_OP_BIT(25)` fails translate-c ("expected type u6,
  found u64"). Server code sets the `SSL_OP_NO_SSLV3` bit (0x02000000) via a
  literal to stay on a single TLS context path without fighting the translator.
- **`--gen-cert [common-name]`.** Parsed as a special mode like `--gen-hash`;
  writes `server_cert.pem` + `server_key.pem` (PEM) to the current directory
  and exits. A null/empty common name produces the C default CN
  `server.softether.vpn<hostname>` (gethostname).

---

## Part 2 — HTTP server envelope (`http.zig`, #76)

### Reference (C)

- `HttpServerRecvEx` (Network.c:12561-12693): reads the request head until
  `\r\n\r\n`, parses `Content-Length`, then reads exactly that many body bytes
  from the socket. No chunked encoding (SoftEther clients never use it).
- `HttpServerSend` (Network.c:12695-12707): writes `HTTP/1.1 200 OK\r\n` +
  `Content-Length` + body with zero allocation.

### API shape (as implemented)

```zig
pub const vpn_content_type   = "application/octet-stream";   // HTTP_CONTENT_TYPE2
pub const vpn_target         = "/vpnsvc/vpn.cgi";            // HTTP_VPN_TARGET
pub const vpn_keep_alive     = "timeout=15; max=19";         // HTTP_KEEP_ALIVE
pub const max_pack_body_len: usize  = 65536;                 // HTTP_PACK_MAX_SIZE
pub const max_request_head_len: usize = 32 * 1024;           // whole-head cap

pub const HttpRequest = struct {
    method: []const u8,        // "POST" (validated)
    uri: []const u8,           // canonical target (static literal)
    version: []const u8,       // "HTTP/1.1" (validated)
    content_length: usize,
    body: []u8,                // exactly Content-Length bytes in caller's buf
};

pub fn readHttpRequest(tls: *TlsSocket, buf: []u8) !HttpRequest;  // head + body, cap enforced
pub fn sendHttpResponse(tls: *TlsSocket, body: []const u8) !void;  // 200 + keep-alive + Content-Length
```

### Design decisions (part 2, as implemented)

- **Bounded reads.** A `max_request_head_len` (32KB) cap on the header scan
  and the C `HTTP_PACK_MAX_SIZE` cap on Content-Length keep a misbehaving
  client from forcing unbounded buffering.
- **Reuse the read-ahead buffer.** `TlsSocket.read` already serves from a
  64KB batch buffer; `readHttpRequest` scans through the same read-ahead
  machinery so `\r\n\r\n` spanning TLS record boundaries is handled for free.
- **Validation happens inside the envelope.** `readHttpRequest` mirrors C's
  `HttpServerRecvEx` exactly: POST / HTTP/1.1, target `/vpnsvc/vpn.cgi`
  (only), `Content-Type: application/octet-stream`, and `0 < Content-Length
  <= HTTP_PACK_MAX_SIZE`. The `connect.cgi` POSTs (signature upload with
  `image/jpeg`, the empty client hello) are plaintext-HTTP handshakes the
  server handles *before* TLS (C: `ServerDownloadSignature`, Protocol.c:
  7077) — they are deliberately outside this envelope, so accepting them here
  would reject their real content types/lengths.
- **Byte-exact reads keep keep-alive aligned.** The head is scanned
  byte-by-byte and the body read to the exact Content-Length, so bytes beyond
  the current request (the start of the next pipelined POST) stay in the
  socket's read-ahead buffer and are served by the next `readHttpRequest`.
  This mirrors C's `RecvLine`/`RecvAll`, which likewise never over-read into
  the caller.
- **Returned strings are canonical literals.** The head is validated and then
  overwritten by the body, so `method`/`uri`/`version` are the static values
  that passed validation, never slices into the (overwritten) buffer.
- **Reply carries the C keep-alive headers.** `sendHttpResponse` emits
  `HTTP/1.1 200 OK` + `Date` (RFC 1123) + `Keep-Alive: timeout=15; max=19`
  + `Connection: Keep-Alive` + `Content-Type` + `Content-Length` + body
  with zero allocation (stack-buffered head). The client's `HttpClientRecv`
  requires Content-Type to echo `application/octet-stream`.
- **NOOP/Pack semantics are Cedar's business** (per the architecture
  boundary): the pencore padding (`CreateDummyValue`) and the `noop` loop
  stay out of `mayaqua` and arrive with the RPC layer.

---

## Testing strategy

- **Cert generator**: parse the returned PEMs back with OpenSSL, assert subject
  CN, v3, serial 0, `CA:TRUE`, the 9 EKUs, and that notAfter is in the future;
  verify the self-signature. Cross-check the CN composition (`server.softether
  .vpn<hostname>`).
- **Accept path**: `socketpair(AF_UNIX)`; `accept` on one end and `connect`
  (self-signed, verify off) on the other; assert an echo round-trip and that
  `peerSni()` equals the client's SNI.
- Wired into the whole-package test via a `mayaqua_tls.` filter so
  OpenSSL-linked sibling imports (`socket.zig`, `dns_cache.zig`, `http.zig`)
  resolve.

---

## References

- `src/mayaqua/network/tls.zig` — connect-only TLS wrapper (part 1 adds accept)
- `src/mayaqua/network/http.zig` — client-only HTTP module (part 2 adds the
  server envelope: `readHttpRequest` / `sendHttpResponse`)
- `src/cedar/protocol/c_imports.zig` — shared OpenSSL cImport block (+x509v3.h)
- `src/cli/args.zig`, `src/main.zig` — `--gen-cert` wiring
- C refs: `SoftEtherVPN/src/Cedar/Server.c:2180-2218`, `Mayaqua/Encrypt.c:
  2568-2600, 2679-2750, 2908-3034`, `Mayaqua/Network.c:12561-12707,
  13888-14100`
- SERVER_PLAN.md §11 #4, S5/S6
