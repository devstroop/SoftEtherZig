# Config Layer Reference

Every config property must be present in **all six layers** to be maintainable.

## Legend

| Layer | File | Symbol |
|---|---|---|
| CLI flag | `src/cli/args.zig` | `--flag` |
| CLI env | `src/cli/args.zig :: loadFromEnv()` | `SOFTETHER_*` |
| Config file | `src/cli/config_manager.zig` | `"json_key"` |
| Bridge | `src/app/config.zig` | CliArgs → ClientConfig |
| FFI setter | `src/ffi.zig` | `softether_set_*()` |
| ClientConfig | `src/client/vpn_client.zig` | struct field |

## Field Matrix

| # | Property | CLI flag | CLI env | Config file | Bridge | FFI setter | ClientConfig | Wire proto |
|---|---|---|---|---|---|---|---|---|
| 1 | server | `--server` | `SOFTETHER_SERVER` | `"server"` | ✅ | `softether_create` arg | `server_host` | — |
| 2 | port | `--port` | `SOFTETHER_PORT` | `"port"` | ✅ | `softether_create` arg | `server_port` | — |
| 3 | hub | `--hub` | `SOFTETHER_HUB` | `"hub"` | ✅ | `softether_create` arg | `hub_name` | — |
| 4 | username | `--user` | `SOFTETHER_USER` | `"username"` | ✅ | `softether_create` arg | auth | — |
| 5 | password | `--password` | `SOFTETHER_PASSWORD` | `"password"` | ✅ | `softether_create` arg | auth | — |
| 6 | password_hash | `--password-hash` | `SOFTETHER_PASSWORD_HASH` | `"password_hash"` | ✅ | — | auth | — |
| 7 | use_compress | `--use-compress` / `--no-compress` | `SOFTETHER_COMPRESS` | `"use_compress"` | ✅ | `softether_set_compression` | `use_compress` | `"use_compress"` |
| 8 | use_encrypt | `--use-encrypt` / `--no-encrypt` | `SOFTETHER_ENCRYPT` | `"use_encrypt"` | ✅ | `softether_set_encryption` | `use_encrypt` | `"use_encrypt"` |
| 9 | half_connection | `--half-connection` / `--no-half-connection` | `SOFTETHER_HALF_CONNECTION` | `"half_connection"` | ✅ | `softether_set_half_connection` | `half_connection` | `"half_connection"` |
| 10 | qos | `--qos` / `--no-qos` | `SOFTETHER_QOS` | `"qos"` | ✅ | `softether_set_qos` | `qos` | `"qos"` |
| 11 | udp_acceleration | `--udp-accel` | `SOFTETHER_UDP_ACCEL` | `"udp_accel"` | ✅ | **❌ missing** | `udp_acceleration` | `"use_udp_acceleration"` |
| 12 | max_connections | `--max-connections` | `SOFTETHER_MAX_CONNECTIONS` | `"max_connections"` | ✅ | `softether_set_max_connections` | `max_connections` | `"max_connection"` |
| 13 | mtu | `--mtu` | `SOFTETHER_MTU` | `"mtu"` | ✅ | `softether_set_mtu` | `mtu` | — |
| 14 | ip_version | `--ip-version` | — | `"ip_version"` | **❌ unused** | **❌ missing** | **❌ field doesn't exist** | — |
| 15 | skip_tls_verify | `--skip-tls-verify` | `SOFTETHER_SKIP_TLS_VERIFY` | `"skip_tls_verify"` | ✅ (inverted) | `softether_set_verify_certificate` | `verify_certificate` | — |
| 16 | default_route | `--full-tunnel` | — | `"routing.default_route"` | ✅ | `softether_set_full_tunnel` | `routing.default_route` | — |
| 17 | accept_pushed_routes | — | — | `"routing.accept_pushed_routes"` | ✅ | **❌ missing** | `routing.accept_pushed_routes` | — |
| 18 | enable_custom_routes | — | — | `"routing.enable_custom_routes"` | ✅ | **❌ missing** | `routing.enable_custom_routes` | — |
| 19 | ipv4_include | `--ipv4-include` | — | `"routing.ipv4_include"` | ✅ | **❌ missing** | `routing.ipv4_include` | — |
| 20 | ipv4_exclude | `--ipv4-exclude` | — | `"routing.ipv4_exclude"` | ✅ | **❌ missing** | `routing.ipv4_exclude` | — |
| 21 | ipv6_include | `--ipv6-include` | — | `"routing.ipv6_include"` | ✅ | **❌ missing** | `routing.ipv6_include` | — |
| 22 | ipv6_exclude | `--ipv6-exclude` | — | `"routing.ipv6_exclude"` | ✅ | **❌ missing** | `routing.ipv6_exclude` | — |
| 23 | static_ipv4 | `--static-ipv4` | — | `"static_ip.ipv4_address"` | ✅ | **❌ missing** | `static_ip.ipv4_address` | — |
| 24 | static_ipv4_netmask | `--static-ipv4-netmask` | — | `"static_ip.ipv4_netmask"` | ✅ | **❌ missing** | `static_ip.ipv4_netmask` | — |
| 25 | static_ipv4_gateway | `--static-ipv4-gateway` | — | `"static_ip.ipv4_gateway"` | ✅ | **❌ missing** | `static_ip.ipv4_gateway` | — |
| 26 | static_ipv6 | `--static-ipv6` | — | `"static_ip.ipv6_address"` | ✅ | **❌ missing** | `static_ip.ipv6_address` | — |
| 27 | static_ipv6_prefix | `--static-ipv6-prefix` | — | `"static_ip.ipv6_prefix"` | ✅ | **❌ missing** | `static_ip.ipv6_prefix_len` | — |
| 28 | static_ipv6_gateway | `--static-ipv6-gateway` | — | `"static_ip.ipv6_gateway"` | ✅ | **❌ missing** | `static_ip.ipv6_gateway` | — |
| 29 | dns_servers | `--dns-server` (multi) | — | `"static_ip.dns_servers"` | ✅ | **❌ missing** | `static_ip.dns_servers` | — |
| 30 | reconnect | `--reconnect` / `--no-reconnect` | — | `"reconnect.enabled"` | ✅ | `softether_set_reconnect` | `reconnect.enabled` | — |
| 31 | max_retries | `--max-retries` | — | `"reconnect.max_attempts"` | ✅ | `softether_set_reconnect` arg | `reconnect.max_attempts` | — |
| 32 | proxy | `--proxy` | `SOFTETHER_PROXY` | **❌ missing** | ✅ | `softether_set_proxy` | `proxy` | — |
| 33 | connect_timeout_ms | **❌ missing** | **❌ missing** | **❌ missing** | hardcoded 30000 | **❌ missing** | `connect_timeout_ms` | — |
| 34 | read_timeout_ms | **❌ missing** | **❌ missing** | **❌ missing** | hardcoded 60000 | **❌ missing** | `read_timeout_ms` | — |
| 35 | keepalive_interval_ms | **❌ missing** | **❌ missing** | **❌ missing** | hardcoded 10000 | **❌ missing** | `keepalive_interval_ms` | — |
| 36 | log_level | `--log-level` | `SOFTETHER_LOG_LEVEL` | `"log_level"` | runtime only | **❌ missing** | **❌ (runtime)** | — |
| 37 | tunnel_fd | — | — | — | — | `softether_set_tunnel_fd` | `tunnel_fd` | — |

## Env Vars Reference

All env vars defined in `src/cli/args.zig :: loadFromEnv()`:

```
SOFTETHER_SERVER
SOFTETHER_PORT
SOFTETHER_HUB
SOFTETHER_USER
SOFTETHER_PASSWORD
SOFTETHER_PASSWORD_HASH
SOFTETHER_CONFIG
SOFTETHER_COMPRESS           → isTrue(1|true|yes)
SOFTETHER_ENCRYPT            → isTrue(1|true|yes)
SOFTETHER_HALF_CONNECTION    → isTrue(1|true|yes)
SOFTETHER_QOS                → isTrue(1|true|yes)
SOFTETHER_SKIP_TLS_VERIFY    → isTrue(1|true|yes)
SOFTETHER_UDP_ACCEL          → isTrue(1|true|yes)
SOFTETHER_MAX_CONNECTIONS    → parseInt
SOFTETHER_MTU                → parseInt
SOFTETHER_LOG_LEVEL          → silent|error|warn|info|debug|trace
SOFTETHER_PROXY
```

Priority: CLI flag > env var > config file > code default.

## Wire Protocol Names

The SoftEther VPN server uses these field names in the auth handshake
(`src/protocol/softether_protocol.zig`):

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

Priority order for filling:

1. **udp_acceleration** — no FFI setter. Add `softether_set_udp_acceleration()`.
2. **proxy** — no config file field. Add `"proxy"` to `ConfigFile`.
3. **connect_timeout_ms** — missing from CLI, env, config file, FFI. Hardcoded 30s in bridge.
4. **read_timeout_ms** — same as above. Hardcoded 60s.
5. **keepalive_interval_ms** — same as above. Hardcoded 10s.
6. **ip_version** — parsed in CLI, goes nowhere. Dead field. Either wire to DNS resolution or remove.
7. **Routing sub-fields** — no FFI setters for accept_pushed_routes, custom_routes, include/exclude.
8. **Static IP sub-fields** — no FFI setters.
9. **log_level** — no FFI setter.
