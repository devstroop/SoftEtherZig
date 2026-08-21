# Config Layer Reference — M21 (vpnclient 12-field connect matrix)

> **M21 #261 breaking:** `vpnclient` no longer auto-loads host `config.json`
> (`./config.json` / `~/.config/softether-zig/config.json`). The file is
> ignored even if present; `vpnclient --help` no longer lists `--config` as
> primary. Profiles are owned by `vpncmd` (XDG `vpn_client.config` Cfg binary,
> no external JSON import/export) — see `docs/ACCOUNT.md`. Host JSON remains
> only for `vpnserver` `vpn_server.config` (Cedar Cfg) parity. Use CLI flags
> or env vars for `vpnclient connect`.

Every **vpnclient connect** property flows through **3 layers** (was 6):
**CLI flag → env var → ClientConfig struct** (via `src/app/config.zig` bridge
→ `src/cedar/client/vpn_client.zig` → FFI setters). `vpncmd` store
(`src/cedar/server/config/cfg.zig` declare tree) is consumed in M21-2/3.

## Legend

| Layer | File | Symbol |
|---|---|---|
| CLI flag | `src/cli/args.zig` | `--flag` |
| CLI env | `src/cli/args.zig :: loadFromEnv()` | `SOFTETHER_*` |
| Bridge | `src/app/config.zig` | CliArgs → ClientConfig |
| FFI setter | `src/ffi.zig` | `softether_set_*()` |
| ClientConfig | `src/cedar/client/vpn_client.zig` | struct field |

## Field Matrix — vpnclient connect (12-field)

| # | Property | CLI flag | CLI env | Bridge | FFI setter | ClientConfig | Wire proto |
|---|---|---|---|---|---|---|---|
| 1 | server address | `--address` / `-a` | `SOFTETHER_ADDRESS` | ✅ | `softether_create` arg | `server_address` | — |
| 2 | server hostname (TLS/SNI) | `--hostname` | — | ✅ | `softether_set_hostname` | `server_hostname` | — |
| 3 | port | `--port` / `-p` | `SOFTETHER_PORT` | ✅ | `softether_create` arg | `server_port` | — |
| 4 | hub | `--hub` / `-H` | `SOFTETHER_HUB` | ✅ | `softether_create` arg | `hub_name` | — |
| 5 | username | `--user` / `-u` | `SOFTETHER_USER` | ✅ | `softether_create` arg | auth | — |
| 6 | password / password_hash | `--password` / `--password-hash` | `SOFTETHER_PASSWORD` / `SOFTETHER_PASSWORD_HASH` | ✅ | `softether_create` arg | auth | — |
| 7 | skip_tls_verify | `--skip-tls-verify` | `SOFTETHER_SKIP_TLS_VERIFY` | ✅ (inverted) | `softether_set_verify_certificate` | `verify_certificate` | — |
| 8 | use_compress | `--use-compress` / `--no-compress` | `SOFTETHER_COMPRESS` | ✅ | `softether_set_compression` | `use_compress` | `"use_compress"` |
| 9 | use_encrypt | `--use-encrypt` / `--no-encrypt` | `SOFTETHER_ENCRYPT` | ✅ | `softether_set_encryption` | `use_encrypt` | `"use_encrypt"` |
| 10 | max_connections | `--max-connections` | `SOFTETHER_MAX_CONNECTIONS` | ✅ | `softether_set_max_connections` | `max_connections` | `"max_connection"` |
| 11 | mtu | `--mtu` | `SOFTETHER_MTU` | ✅ | `softether_set_mtu` | `mtu` | — |
| 12 | reconnect | `--reconnect` / `--no-reconnect` + `--max-retries` | — | ✅ | `softether_set_reconnect` | `reconnect` | — |

All other former host-file properties (proxy, static IP, routing, DNS,
timeouts, modes, fingerprint, etc.) are **not part of the vpnclient 12-field
matrix** — they are either FFI-only, vpncmd-owned, or vpnserver Cfg.
`config.json` / `config.example.json` / `config.minimal.json` host exposure
for vpnclient is removed (M21); `vpn_server.config` example is retained for
vpnserver.

## Env Vars Reference (vpnclient)

All env vars defined in `src/cli/args.zig :: loadFromEnv()` (SOFTETHER_CONFIG removed in M21):

```
SOFTETHER_ADDRESS
SOFTETHER_PORT
SOFTETHER_HUB
SOFTETHER_USER
SOFTETHER_PASSWORD
SOFTETHER_PASSWORD_HASH
SOFTETHER_SKIP_TLS_VERIFY    → isTrue(1|true|yes)
SOFTETHER_COMPRESS           → isTrue(1|true|yes)
SOFTETHER_ENCRYPT            → isTrue(1|true|yes)
SOFTETHER_MAX_CONNECTIONS    → parseInt
SOFTETHER_MTU                → parseInt
Priority: CLI flag > env var > code default (> vpncmd store from M21-2).
```

`SOFTETHER_CONFIG` is removed for vpnclient (M21 #261); `vpnclient --config`
is hidden deprecated and ignored. `vpnserver` Cfg path (`vpn_server.config`)
is unchanged.

## Wire Protocol Names

The SoftEther VPN server uses these field names in the auth handshake
(`src/cedar/protocol/softether_protocol.zig`):

| Server-sent field | Mapped to |
|---|---|
| `"max_connection"` | `AuthResult.server_max_connection` |
| `"half_connection"` | `AuthResult.server_half_connection` |
| `"use_compress"` | `AuthResult.server_use_compress` |
| `"use_encrypt"` | `AuthResult.server_use_encrypt` |
| `"qos"` | `AuthResult.server_qos` |
| `"timeout"` | `AuthResult.server_timeout` |
| `"use_udp_acceleration"` | `AuthResult.udp_accel_enabled` |
| `"udp_acceleration_client_port"` | `AuthResult.udp_accel_port` |
| `"udp_acceleration_use_encryption"` | `AuthResult.udp_accel_use_encrypt` |
| `"rudp_bulk_version"` | `AuthResult.rudp_bulk_version` |

## Gaps (not equally placed)

M21 narrows the vpnclient contract to the 12-field connect matrix above.
All 12 have complete CLI → env → bridge → FFI → ClientConfig coverage.
The former 45-field host-file matrix is retained for vpnserver Cfg parity
but not for vpnclient.

## Bridge & Monitor Modes

Operating semantics (security boundary, MTU rules, FFI behavior, errata) for
`mode: bridge` and `mode: monitor` are documented in
[docs/bridge_monitor_ops.md](docs/bridge_monitor_ops.md) (issue #57).
These modes are `vpnclient connect --mode` flags, not part of the 12-field
host matrix.
