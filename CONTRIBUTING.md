# Contributing to SoftEtherZig

Thanks for your interest. This document is short on purpose — read it before opening an issue or pull request.

## What this repo is

SoftEtherZig is a from-scratch reimplementation of the SoftEther VPN client protocol in Zig. It ships as a CLI (`vpnclient`) and as an embeddable C library (`libsoftether.{dylib,so,dll,a}`) used by Flutter, Swift, and Kotlin apps on macOS, Linux, Windows, iOS, and Android.

## What this repo is not

- **Not a SoftEther server.** Only the client side is in scope.
- **Not the WorxVPN application.** WorxVPN is a separate, proprietary product that embeds this library. Bugs in the WorxVPN UI, account system, or server infrastructure are not handled here — they belong on WorxVPN's own support channels.
- **Not a general VPN framework.** It implements the SoftEther protocol specifically. We don't accept patches that add OpenVPN, WireGuard, or IKEv2 support.

If your issue or PR is outside this scope, please redirect rather than open it here.

## Reporting issues

Issues without the information below get closed with a label, not a discussion. This is not personal — it's how a solo-maintained project survives.

**Required for every bug report:**

1. **Zig version** (`zig version`)
2. **Target platform** (e.g. macOS 14 arm64, Android arm64-v8a NDK 26)
3. **Build command** you used (`zig build`, `zig build shared-lib -Dtarget=...`)
4. **Server software** (SoftEther 5.x, etc.) and protocol options enabled (multi-TCP, half-connection, UDP acceleration)
5. **Steps to reproduce.** If it requires a specific server config, say so explicitly. Logs help.
6. **What you expected vs. what happened**

**Bug reports that won't be triaged:**

- "Doesn't connect to my server" with no logs, no protocol details, and no `--verbose` output
- "Crashes on my phone" with no stack trace
- Anything that doesn't include a reproduction path
- Feature requests filed as bugs

**Feature requests** are welcome but please open a discussion or a clearly-labelled `enhancement` issue *first* — don't write a 500-line PR and hope it lands. Most large patches that arrive without a prior conversation get closed.

## Security

**Do not file security issues on the public tracker.**

Email security issues to Devstroop Technologies directly:

- **Email:** `info@devstroop.com`
- **Subject prefix:** `[SECURITY] SoftEtherZig`
- **Include:** affected version, platform, reproduction, your suggested fix if you have one

Expected response: acknowledgement within 7 days, fix or "won't fix with rationale" within 30 days for high-severity. Lower-severity issues may take longer. No bug bounty is offered.

Public disclosure: 90 days from initial report, or upon release of a fix, whichever is earlier.

## Pull requests

**Talk first, code second.** Open an issue describing the change before writing more than ~50 lines of code. PRs without a prior discussion are reviewed last and may be closed with "should have been an issue."

**What we accept:**

- Bug fixes with a regression test
- Platform support fixes (especially for the mobile / cross-compile path)
- New tests for existing untested code paths
- Documentation improvements
- Protocol-correctness fixes against real-server behaviour (include a packet capture or server software version)

**What we don't accept without prior agreement:**

- Refactors for the sake of refactoring
- New abstractions ("I added a `Transport` trait/interface")
- Style-only changes
- Adding dependencies (Zig std + OpenSSL + zlib is the stack; that's it)
- Changes that break the C ABI in `softether.h` without a migration plan

**PR requirements:**

- `zig build test` passes locally
- New code has tests (unit or integration — see `test/integration/` for the fixture pattern)
- No `unreachable` or `unwrap`-style panics on user input — return errors
- Commits are signed (`git commit -S`) if possible
- No AI-generated commit messages or PR descriptions

**Review process:**

- Solo maintainer, best-effort, no SLA. Plan on weeks, not days.
- Review may include "please split this PR into N smaller PRs"
- The maintainer reserves the right to say no without elaborate justification. If the project's direction and your patch don't align, a polite no is the answer.

**Contributor licensing:** By opening a PR you agree your contribution is licensed under Apache-2.0, per Section 5 of the license. No separate CLA is required.

## Development

### Prerequisites

- **Zig 0.15.1+** — install via [ziglang.org/download](https://ziglang.org/download/)
- **OpenSSL 3.x**:
  - macOS: `brew install openssl@3`
  - Linux: `apt install libssl-dev` (or distro equivalent)
  - iOS/Android: pre-built libraries in `deps/` are used automatically

### Build

```bash
zig build                                        # CLI (debug)
zig build --release=fast                         # CLI (release)
zig build shared-lib                             # libsoftether.dylib/.so
zig build static-lib -Dtarget=aarch64-ios        # iOS static lib
zig build shared-lib -Dtarget=aarch64-linux-android --libc android-libc-aarch64-linux-android.conf
```

### Tests

```bash
zig build test                                   # full suite
zig build test --summary all                     # with per-test breakdown
```

Current state: 141 tests across unit, FFI, and integration suites. New work should keep or grow that count.

**Test patterns by type:**

- **Unit tests** — co-located in the source file, listed in `build.zig`'s `test_sources` array. Add your file there if it stands alone.
- **FFI tests** — live in `src/ffi.zig`; filtered to `"ffi"` in `build.zig` because the FFI test pulls the full client module tree.
- **Integration tests** — live in `test/integration/`. Use the `ScriptedTransport` pattern in `handshake_fixture_test.zig` for protocol-level tests; no real sockets, no TLS, deterministic.

### Code style

- Follow `zig fmt` (no formatter wars)
- Prefer `defer` / `errdefer` over manual cleanup
- Allocators are passed explicitly, never hidden
- No `unreachable` for user-reachable paths — return an error
- Comments: explain *why*, not *what*. Don't restate the code.
- One reasonable rule of thumb: if a comment would be obvious to a future reader who knows Zig, delete it

### Platform testing

The maintainer can verify changes on macOS arm64 directly. For changes affecting other platforms:

- **Linux / Windows:** include CI output or describe your local test setup
- **iOS / Android:** the maintainer cannot test arbitrary device combinations; for mobile-only changes, include device specifics and (ideally) recordings of the working behaviour

## What we won't do

To save everyone time, the following are out of scope and will be closed quickly if filed:

- Adding non-SoftEther protocols (OpenVPN, WireGuard, IKEv2)
- Reimplementing OpenSSL in pure Zig (we use the system library deliberately)
- Removing OpenSSL in favour of `std.crypto` (the SoftEther protocol requires MD4, DES, SHA-0 — `std.crypto` does not provide some of these)
- AGPL / GPL relicensing (Apache-2.0 stays)
- Build system rewrites (`build.zig` stays; no Makefile, no CMake, no `bazel`)
- A Rust port

## Releases

Tags follow `vMAJOR.MINOR.PATCH`. Pre-1.0; expect breaking changes between minor versions, documented in `CHANGELOG.md`. The C ABI in `softether.h` is stable within a minor version.

## Maintainer

Maintained by **[Devstroop Technologies](https://devstroop.com)** 

Contact: `info@devstroop.com`.

Decisions are not made by committee; if you need a governance model with multiple core maintainers, this is not currently that project.

Thanks for reading. If you got this far and still want to contribute, you're exactly the kind of contributor this project benefits from.
