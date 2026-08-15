# Changelog

All notable changes to SoftEtherZig are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once
1.0 ships. Pre-1.0, breaking changes may occur between minor versions —
they are called out under **Breaking** in each entry.

## [Unreleased]

### Added

- **AF_PACKET L2 port** (`adapter/af_packet.zig`, L2 Network Bridge proposal
  §4.1; issues H-3/H-5/H-8). Linux-only `NetPort` implementation over
  AF_PACKET (SOCK_RAW, ETH_P_ALL): `afPacketPort(&impl, ifname)` mirrors the
  `l3Port` ownership pattern, `open()` binds to the named interface.
  CAP_NET_RAW detected at open (`error.NoCapability` on EPERM — never a
  crash or silent passthrough); MTU > 1500 warns and frames > 1514 are
  dropped into `PortStats.drops` (`SESSION_FRAME_BUDGET`); host-IP address
  on the ingress NIC logs an H-5 warning; `setPromiscuous(bool)` toggles
  PACKET_MR_PROMISC membership. PACKET_MMAP ring deferred (documented).
  Linux-gated tests; all non-Linux targets compile unchanged.
- **L2 bridge core** (`src/bridge/`, proposal §4.3). Pure logic, no I/O:
  - `fdb.zig` — hash-based MAC → port table (`FdbTable`): FNV-1a probing,
    aging (default 300 s), overflow → `error.TableFull` after FIFO eviction
    (engine floods), re-learn on move. Injected clock keeps tests
    deterministic (`age(now)` — no timing flakiness).
  - `engine.zig` — `BridgeEngine` over N ports sharing one FDB: learns src
    MAC; unicast lookup → single port; broadcast/multicast/unknown →
    flood to all other ports (**no-echo loop guard** — frames never return
    to the source port); per-port `forwarded`/`blocked`/`flooded` counters.
    Multi-ingress ready; STP deferred (documented, proposal §11 Q2).
  - Wired into `lib.zig` (`softether.bridge`) and standalone test sources.
    15 new tests (learn/age/refresh/overflow-flood/re-learn/move/bcast/
    unknown-unicast/counters/no-echo/single-port): 265/265 total.
- **Bridge data pump** (`src/bridge/loop.zig`, proposal §4.3; #56). Runtime
  half of the L2 bridge: `BridgeLoop` owns the shared forwarding engine and
  aggregates per-port + session counters into `BridgeStats`; `SessionSink`
  delivers LAN → VPN frames into the session tunnel; `dispatchSessionBlock`
  floods/unicasts session frames to the LAN ports (no-echo guard);
  5 deterministic tests (flood/unicast/no-echo/sink counters/stats).
- **Bridge mode dispatch in VpnClient** (#56). `connect()` spawns
  `runBridgeLoopThread` in bridge mode (monitor warns and falls back to the
  client loop): single TLS socket + `TunnelConnection` (I-14 —
  `max_connections` coerced to 1), AF_PACKET ingress ports opened from
  `config.bridge.ingress_ifs` into stable heap storage, poll over TLS fd +
  port fds, 1 Hz FDB aging + keepalive; `performConnection` skips adapter
  setup for non-client modes; UDP acceleration gated to client mode.
  Linux-gated; non-Linux targets fail cleanly (`error.AdapterConfigurationFailed`).
- **`softether_get_bridge_stats` FFI** (71st export). `CBridgeStats` C
  layout mirrors `BridgeStats`; `VpnClient.bridge_stats` snapshot updated at
  1 Hz by the bridge pump; zeroed when bridge mode is inactive.
  `softether_bridge_stats_t` added to `include/softether.h`.

### Added

### Added

- **Session network-mode flag + mode-aware connect path** (#52). `VpnClient`
  now snapshots `config.mode` into a `network_mode` session flag at init
  (`getNetworkMode()` getter), and `softether_set_network_mode` writes both
  config and session flag. The connect path branches on the flag: `bridge`/
  `monitor` log a warning and fall back to the client data loop (runtime not
  implemented yet — zero behavior change for the default `client` mode;
  250/250 tests). `include/softether.h` documents the storage-only semantics.
- **Session-side I/O helpers shared with the future bridge pump** (#50).
  New `src/cedar/tunnel/session_io.zig` extracting, byte-identical from
  `runDataLoop`'s hotspots: `SendTunnelHelper` (multi-connection fanout +
  single fallback), `drainReceived` + `DrainSink` (fuses the three inline
  drain copies: multi-connection fanout, single-connection, and the iOS
  post-drain re-check), and `maybeSendKeepalive`. `MAX_INBOUND_DRAIN`
  now lives in `session_io.zig`; drain diagnostics hoisted to file scope
  (`DiagStats`, `singleDead`, `mergeDrainDiag`) so the bridge loop can
  reuse them without copying. Zero behavior change: 250/250 tests.

### Added

- **`softether_list_interfaces(out, cap)` FFI export** (#48). C-ABI
  `softether_nic_info {name[64], mac[6], index}` entries with loopback
  exclusion; snprintf-style negative return on truncation. Windows path
  (GetAdaptersAddresses, GUID as stable id) lands in `nic_enumerate.zig`,
  completing the enumeration primitive for all supported platforms.
  `include/softether.h` documents stable-id semantics (MAC or Windows GUID
  is stable; POSIX names/indices are not). Export count 67 → 68.
- **Network operating mode plumbing** (`NetworkMode` client|bridge|monitor,
  L2 bridge proposal §5.1). New `mode`/`bridge`/`monitor` section threaded
  through all six config layers: CLI flags `--mode`/`--ingress`/`--pcap`,
  env `SOFTETHER_MODE`/`SOFTETHER_INGRESS` (comma-split)/`SOFTETHER_PCAP`,
  JSON config (`config.schema.json`/`config.example.json` updated), app
  bridge mapping, FFI setters, and `ClientConfig` fields. `BridgeConfig`
  carries `ingress_ifs`/`fdb_max`(4096)/`fdb_aging_s`(300);
  `MonitorConfig` carries `pcap_file`. `--mode bridge` without `--ingress`
  is rejected at parse time. Storage-only: the connect path stays in client
  mode until bridge/monitor runtime lands in later milestones.
- **FFI setters** `softether_set_network_mode` (0|1|2, invalid ignored),
  `softether_add_ingress_interface` (dedup, owned copy, `-1` on
  invalid/OOM), `softether_remove_ingress_interface` (`0` if absent).
  Mutating setters replace the ingress list with fully-owned entries so
  borrowed `VpnClient.init` configs are never freed; `VpnClient.deinit`
  releases setter-owned bridge/monitor lists. FFI export count 67 → 70.

### Changed

- **`NetPort` interface** (`adapter/port.zig`, L2 Network Bridge proposal §4.1).
  First-class port abstraction: `open/close/read/write/getFd/getName/getMac/
  getMtu/getLayer/setPromiscuous/getStats`, plus `PortLayer`/`PortStats`.
  Existing L3 devices (utun, tun_linux, Wintun, fd_adapter) are wrapped behind
  it via `l3Port()` with unchanged behavior. `VirtualAdapter` is now composed
  over a port; the data pump no longer reaches into device internals
  (previously `runDataLoop` called `adapter.real_adapter.device.getFd()`).
- **NIC enumeration primitive** (`adapter/nic_enumerate.zig`). Host interface
  gathering via getifaddrs (AF_LINK / AF_PACKET) returning
  `{name, mac, index}`; FFI surface lands in a follow-up.

### Changed

- `VirtualAdapter.device` replaced by `VirtualAdapter.port: ?NetPort`;
  device-level l3 configuration operations (configure/configureIpv6/replaceFd)
  route through the port's impl pointer. Client-mode behavior is unchanged
  (byte-identical data path; FFI export count unchanged at 67).

## [0.3.10] - 2026-08-14

### Added

- **Per-client FFI callback isolation.** `softether_set_event_callback` now
  stores the C callback and `user_data` pointer in a heap-allocated per-client
  context. Previously, the FFI used module-level statics, making the library
  effectively single-client (a second client would silently overwrite the
  first's callback). Multiple simultaneous `softether_client_t` instances now
  each route events to their own host objects.
  Covered by two new tests in `src/ffi.zig`.
- **Protocol-level integration test harness.**
  `test/integration/handshake_fixture_test.zig` drives the full
  signature → hello → auth flow against an in-memory `ScriptedTransport`
  (no TLS, no sockets, deterministic). Eight fixtures cover happy path,
  malformed Hello, server error, auth rejection, cluster redirect, full
  `performHandshake`, certificate-auth pack building, and cert-auth
  end-to-end against scripted responses.
- **Header symbols synced.** `include/softether.h` now declares the five
  exports it was missing: `softether_create_certificate`,
  `softether_set_max_connections`, `softether_set_half_connection`,
  `softether_set_qos`, `softether_replace_tun_fd`. Cert auth and multi-TCP
  throughput are reachable from FFI consumers again.
- **`auth_handler.zig` module.** Full SoftEther handshake — including
  cluster-redirect handling, ticket re-auth, server-overrides apply, and
  UDP-acceleration setup — extracted from `vpn_client.zig` into a sibling
  module. `vpn_client.zig` is now ~367 lines shorter.
- **`NOTICE` file** at the library root, per Apache-2.0 Section 4(d).
  Devstroop Technologies copyright + third-party attributions (OpenSSL,
  zlib).
- **`CONTRIBUTING.md`** with reporting requirements, PR rules, and the
  security disclosure channel (`info@devstroop.com`).

### Changed

- **Protocol-layer log levels: `err` → `warn`** for four server-side
  rejection paths in `protocol/softether_protocol.zig`:
  - Non-200 HTTP status from server during Hello
  - Server returning a non-zero `error` field in Hello
  - Malformed Hello with wrong `random` field size
  - Auth response with a non-zero `error` code

  **Rationale:** these are normal protocol outcomes the caller handles via
  return value, not internal library failures. Reserving `err` for things
  the library was unable to handle improves signal/noise for operators.

  **Mitigation for operators grepping `(err)` in logs:** the client
  orchestration layer (`vpn_client.zig`) now emits an `err`-level log when
  `auth_handler.run` fails — application-level failures still surface at
  `err` even though the protocol-layer messages they were caused by are at
  `warn`. If you were filtering specifically on the protocol-layer
  messages, update your filters to include `warn` or to grep on the
  application-level message instead.

### Fixed

- **Release workflow built a spurious `vpnclient` exe on iOS/Android.**
  The merged release matrix's build loop word-split target specs, so
  `static-lib -Dtarget=aarch64-ios` became two invocations — the second
  (`zig build -Dtarget=…` with no step) ran the default `install` step,
  which builds the `vpnclient` executable for the mobile target. The CLI
  had no Android/iOS OpenSSL linkage branch (only macOS/Windows/Linux
  dynamic), so it failed with `unable to find dynamic system library
  'ssl'`. `release.yml` now treats each `matrix.targets` line as one full
  command, and the `vpnclient` linkage in `build.zig` uses the same
  `linkOpenSsl` helper as the shared/static libraries (bundled static
  OpenSSL on Android/iOS, system dynamic elsewhere) so a stray default
  build works on every target.
- **All C header imports unified into one translation unit
  (`src/cedar/protocol/c_imports.zig`).** `tls.zig`, `auth.zig`, and the
  Wintun adapter used three separate `@cImport` blocks (OpenSSL-TLS,
  OpenSSL-auth, `windows.h`), each independently translated. Any two of them
  in one compilation produced the `exported symbol collision:
  __mingw_current_teb` failure on `aarch64-windows` (mingw). They now share a
  single module-level block, selected per-OS in one place.
- **Windows arm64 (native mingw) build failure — `exported symbol collision:
  __mingw_current_teb`.** On `aarch64-windows` translate-c emits an exported
  `__mingw_current_teb` global (the x18-register TEB pointer from the bundled
  mingw `winnt.h`) in every `@cImport` block that reaches `winnt.h` — and on
  Windows, OpenSSL headers reach it too (via `e_os2.h` → `windows.h`), as does
  `windows.h` itself. The library had several such blocks (two OpenSSL imports
  in `tls.zig`/`auth.zig` plus the Wintun adapter's `windows.h` import), so
  the build aborted. All consumers that may reach `winnt.h` now share a single
  import block in the new `src/cedar/protocol/c_imports.zig` (all OpenSSL
  headers + `windows.h` in one `@cImport` on Windows; OpenSSL only elsewhere).
  `zlib.h` never reaches `winnt.h` and stays separate. (`-Dtarget=
  aarch64-windows-msvc` builds, as used by the app consumers, were unaffected
  because the Windows SDK headers don't declare that symbol.)
- **Memory leak in `uploadAuth` debug-logging path.** Each call to the auth
  response field dump leaked one `allocPrint` allocation per int/int64
  field. Caught by the new integration test on its first run. Replaced
  with stack-buffered `bufPrint`. No user-visible behaviour change.
- **Stale unit test in `vpn_client.zig`.** `test "ClientConfig defaults"`
  referenced `config.default_route` after the field had moved to
  `config.routing.default_route` in an earlier refactor. The test never
  ran (file wasn't in `test_sources`); it now does, and the assertion is
  correct.

### Notes

- Test count: **143 passing** (up from 122 before this set of changes).
- No public C ABI changes; `softether.h` only gained declarations.
- No breaking changes to the Zig API.
