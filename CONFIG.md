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
| ClientConfig | `src/cedar/client/vpn_client.zig` | struct field |

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
| 11 | udp_acceleration | `--udp-accel` | `SOFTETHER_UDP_ACCEL` | `"udp_accel"` | ✅ | `softether_set_udp_acceleration` | `udp_acceleration` | `"use_udp_acceleration"` |
| 12 | max_connections | `--max-connections` | `SOFTETHER_MAX_CONNECTIONS` | `"max_connections"` | ✅ | `softether_set_max_connections` | `max_connections` | `"max_connection"` |
| 13 | mtu | `--mtu` | `SOFTETHER_MTU` | `"mtu"` | ✅ | `softether_set_mtu` | `mtu` | — |
| 14 | ip_version | `--ip-version` | `SOFTETHER_IP_VERSION` | `"ip_version"` | ✅ | `softether_set_ip_version` | `ip_version` | — |
| 15 | skip_tls_verify | `--skip-tls-verify` | `SOFTETHER_SKIP_TLS_VERIFY` | `"skip_tls_verify"` | ✅ (inverted) | `softether_set_verify_certificate` | `verify_certificate` | — |
| 16 | default_route | `--full-tunnel` / `--no-full-tunnel` | `SOFTETHER_FULL_TUNNEL` | `"routing.default_route"` | ✅ | `softether_set_default_route` | `routing.default_route` | — |
| 17 | accept_pushed_routes | `--accept-pushed-routes` / `--no-accept-pushed-routes` | `SOFTETHER_ACCEPT_PUSHED_ROUTES` | `"routing.accept_pushed_routes"` | ✅ | `softether_set_accept_pushed_routes` | `routing.accept_pushed_routes` | — |
| 18 | enable_custom_routes | `--enable-custom-routes` / `--no-enable-custom-routes` | `SOFTETHER_ENABLE_CUSTOM_ROUTES` | `"routing.enable_custom_routes"` | ✅ | `softether_set_enable_custom_routes` | `routing.enable_custom_routes` | — |
| 19 | ipv4_include | `--ipv4-include` | — | `"routing.ipv4_include"` | ✅ | `softether_set_ipv4_include` | `routing.ipv4_include` | — |
| 20 | ipv4_exclude | `--ipv4-exclude` | — | `"routing.ipv4_exclude"` | ✅ | `softether_set_ipv4_exclude` | `routing.ipv4_exclude` | — |
| 21 | ipv6_include | `--ipv6-include` | — | `"routing.ipv6_include"` | ✅ | `softether_set_ipv6_include` | `routing.ipv6_include` | — |
| 22 | ipv6_exclude | `--ipv6-exclude` | — | `"routing.ipv6_exclude"` | ✅ | `softether_set_ipv6_exclude` | `routing.ipv6_exclude` | — |
| 23 | static_ipv4 | `--static-ipv4` | — | `"static_ip.ipv4_address"` | ✅ | `softether_set_static_ipv4` | `static_ip.ipv4_address` | — |
| 24 | static_ipv4_netmask | `--static-ipv4-netmask` | — | `"static_ip.ipv4_netmask"` | ✅ | `softether_set_static_ipv4_netmask` | `static_ip.ipv4_netmask` | — |
| 25 | static_ipv4_gateway | `--static-ipv4-gateway` | — | `"static_ip.ipv4_gateway"` | ✅ | `softether_set_static_ipv4_gateway` | `static_ip.ipv4_gateway` | — |
| 26 | static_ipv6 | `--static-ipv6` | — | `"static_ip.ipv6_address"` | ✅ | `softether_set_static_ipv6` | `static_ip.ipv6_address` | — |
| 27 | static_ipv6_prefix | `--static-ipv6-prefix` | — | `"static_ip.ipv6_prefix"` | ✅ | `softether_set_static_ipv6_prefix` | `static_ip.ipv6_prefix_len` | — |
| 28 | static_ipv6_gateway | `--static-ipv6-gateway` | — | `"static_ip.ipv6_gateway"` | ✅ | `softether_set_static_ipv6_gateway` | `static_ip.ipv6_gateway` | — |
| 29 | dns_servers | `--dns-server` (multi) | — | `"static_ip.dns_servers"` | ✅ | `softether_set_dns_servers` | `static_ip.dns_servers` | — |
| 30 | reconnect | `--reconnect` / `--no-reconnect` | — | `"reconnect.enabled"` | ✅ | `softether_set_reconnect` | `reconnect.enabled` | — |
| 31 | max_retries | `--max-retries` | — | `"reconnect.max_attempts"` | ✅ | `softether_set_reconnect` arg | `reconnect.max_attempts` | — |
| 32 | proxy | `--proxy` | `SOFTETHER_PROXY` | `"proxy"` | ✅ | `softether_set_proxy` | `proxy` | — |
| 33 | connect_timeout_ms | `--connect-timeout` | `SOFTETHER_CONNECT_TIMEOUT` | `"connect_timeout_ms"` | ✅ | `softether_set_connect_timeout` | `connect_timeout_ms` | — |
| 34 | read_timeout_ms | `--read-timeout` | `SOFTETHER_READ_TIMEOUT` | `"read_timeout_ms"` | ✅ | `softether_set_read_timeout` | `read_timeout_ms` | — |
| 35 | keepalive_interval_ms | `--keepalive-interval` | `SOFTETHER_KEEPALIVE_INTERVAL` | `"keepalive_interval_ms"` | ✅ | `softether_set_keepalive_interval` | `keepalive_interval_ms` | — |
| 36 | log_level | `--log-level` | `SOFTETHER_LOG_LEVEL` | `"log_level"` | runtime only | `softether_set_log_level` | **❌ (runtime)** | — |
| 37 | tunnel_fd | — | — | — | — | `softether_set_tunnel_fd` | `tunnel_fd` | — |
| 38 | tcp_nodelay | `--tcp-nodelay` / `--no-tcp-nodelay` | `SOFTETHER_TCP_NODELAY` | `"tcp_nodelay"` | ✅ | `softether_set_tcp_nodelay` | `tcp_nodelay` | — |
| 38 | client_str | — | — | `"fingerprint.client_str"` | ✅ | `softether_set_client_str` | `fingerprint.client_str` | — |
| 39 | client_ver | — | — | `"fingerprint.client_ver"` | ✅ | `softether_set_client_ver` | `fingerprint.client_ver` | — |
| 40 | client_build | — | — | `"fingerprint.client_build"` | ✅ | `softether_set_client_build` | `fingerprint.client_build` | — |
| 41 | os_name | — | — | `"fingerprint.os_name"` | ✅ | `softether_set_os_info` | `fingerprint.os_name` | — |
| 42 | os_version | — | — | `"fingerprint.os_version"` | ✅ | `softether_set_os_info` | `fingerprint.os_version` | — |
| 43 | os_title | — | — | `"fingerprint.os_title"` | ✅ | `softether_set_os_info` | `fingerprint.os_title` | — |
| 44 | watermark | — | — | `"fingerprint.watermark_b64"` | ✅ | — | `fingerprint.watermark` | — |
| 45 | client_hostname | — | — | `"fingerprint.client_hostname"` | ✅ | — | `fingerprint.client_hostname` | — |
| 46 | mode | `--mode` | `SOFTETHER_MODE` | `"mode"` | ✅ | `softether_set_network_mode` | `mode` | — |
| 47 | ingress_ifs | `--ingress` (multi) | `SOFTETHER_INGRESS` | `"bridge.ingress"` | ✅ | `softether_add_ingress_interface` / `softether_remove_ingress_interface` | `bridge.ingress_ifs` | — |
| 48 | fdb_max | — (config-only) | — | `"bridge.fdb_max"` | ✅ | — | `bridge.fdb_max` | — |
| 49 | fdb_aging_s | — (config-only) | — | `"bridge.fdb_aging_s"` | ✅ | — | `bridge.fdb_aging_s` | — |
| 50 | pcap_file | `--pcap` | `SOFTETHER_PCAP` | `"monitor.pcap_file"` | ✅ | `softether_set_monitor_pcap` | `monitor.pcap_file` | — |

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
SOFTETHER_IP_VERSION         → 4|6
SOFTETHER_SKIP_TLS_VERIFY    → isTrue(1|true|yes)
SOFTETHER_UDP_ACCEL          → isTrue(1|true|yes)
SOFTETHER_MAX_CONNECTIONS    → parseInt
SOFTETHER_MTU                → parseInt
SOFTETHER_LOG_LEVEL          → silent|error|warn|info|debug|trace
SOFTETHER_CONNECT_TIMEOUT    → parseInt (ms)
SOFTETHER_READ_TIMEOUT       → parseInt (ms)
SOFTETHER_KEEPALIVE_INTERVAL → parseInt (ms)
SOFTETHER_PROXY
SOFTETHER_TCP_NODELAY         → isTrue(1|true|yes)
SOFTETHER_FULL_TUNNEL            → isTrue(1|true|yes)
SOFTETHER_ACCEPT_PUSHED_ROUTES   → isTrue(1|true|yes)
SOFTETHER_ENABLE_CUSTOM_ROUTES   → isTrue(1|true|yes)
SOFTETHER_MODE                   → client|bridge|monitor
SOFTETHER_INGRESS                → comma-separated interface names (--mode bridge)
SOFTETHER_PCAP                   → pcap output path (--mode monitor)

Priority: CLI flag > env var > config file > code default.

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

All gaps resolved — every property has complete coverage across all six layers.
