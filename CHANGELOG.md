# Changelog

All notable changes to SoftEtherZig are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once
1.0 ships. Pre-1.0, breaking changes may occur between minor versions —
they are called out under **Breaking** in each entry.

## [Unreleased]

## [0.3.13] - 2026-08-18

### Fixed

- **Release assets crash on older CPUs (`SIGILL`).** Native release builds
  defaulted to the GitHub runner's CPU, baking AVX/AVX2 instructions into
  the distributed binaries. `release.yml` now builds with `-Dcpu=baseline`,
  so assets run on any x86_64/arm64 host. (Verified: v0.3.12 linux-x86_64
  asset fails at startup on a pre-AVX machine; baseline build runs fine.)

## [0.3.12] - 2026-08-18

### Fixed

- **Native Linux builds on newer system glibc (2.44+, gcc 16).** zig 0.15.x
  bundles lld 18, which cannot handle the `.sframe` section relocations
  emitted by the new `crt1.o`/`libc_nonshared.a` and fails with
  `unhandled relocation type R_X86_64_PC64` at link time. `build.zig` now
  auto-detects a local `.sframe`-stripped CRT directory via a libc paths
  file (`/usr/local/etc/zig-glibc-0152.conf`) on native Linux builds only;
  other platforms and machines are unaffected. `scripts/setup_zig_0152.sh`
  installs everything (stripped CRT copies, linker scripts, libc file,
  pinned `zig` symlink) and is idempotent with timestamped backups.
- **Linux build failure on non-Debian distros.** The multiarch library
  directory (`/usr/lib/x86_64-linux-gnu`) was always added to the link
  path; on distros without that layout (e.g. Arch) the missing `-L` dir is
  a hard error on zig 0.15.x. It is now only added when it exists.

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
