# libsoftether (SoftEtherZig)

Pure Zig implementation of the SoftEther VPN **client + server** protocol — standalone CLIs (`vpnclient`/`vpnserver`/`vpncmd`/`vpnbridge`) + embeddable C library (92 exports).

## Stack

| Layer | Location | Technology |
|-------|----------|------------|
| **Platform abstraction** | `src/mayaqua/` | Zig — OS, crypto, network (mirrors Mayaqua, TLS accept+connect, HTTP server, UDP) |
| **VPN protocol** | `src/cedar/` | Zig — pack, RPC, auth, handshake, session, tunnel + server (mirrors Cedar/) |
| **Server** | `src/cedar/server/` | Zig — hub, listener, accept, session, DHCP/NAT/SecureNAT, farm, admin RPC/WPC (24 modules) |
| **Bridge/STP** | `src/bridge/` | Zig — FDB, engine, loop, STP 802.1D |
| **Adapters** | `src/adapter/` | Zig — NetPort, TUN/TAP/BPF/AF_PACKET/Npcap, DHCP, ARP, routing |
| **CLI** | `src/cli/` | Zig — 9-verb `vpnclient` (`connect`/`list`/`install`/`start`/`stop`/...) + `config file` (deprecated, `vpncmd` store), interactive shell |
| **Executables** | `src/exec/` | Zig — vpnserver, vpnclient, vpncmd, vpnbridge |
| **App lifecycle** | `src/app/` | Zig — state, signals, daemon, interactive mode |
| **FFI bridge** | `src/ffi.zig` | Zig → C ABI (92 exports) for Flutter, Swift, Kotlin (client + server) |
| **Public API** | `src/lib.zig` | Zig module root — re-exports VpnClient, Server, ClientConfig, etc. |

## Architecture

```
src/
├── cedar/                ← VPN Protocol Layer (SoftEtherVPN Cedar/)
│   ├── client/           ← VpnClient, state machine, connection manager, auth handler
│   │   ├── vpn_client.zig    (~2,800 lines) Main client facade + data loop
│   │   ├── connection.zig      Multi-TCP connection pool
│   │   ├── connection_manager.zig
│   │   ├── auth_handler.zig    Full handshake (hello → auth → session → redirect)
│   │   ├── state.zig           ClientState enum + transitions
│   │   ├── stats.zig           ConnectionStats + DisconnectReason
│   │   ├── events.zig          ClientEvent, EventCallback
│   │   ├── packet_processor.zig
│   │   └── session_setup.zig
│   ├── server/           ← VPN server (mirrors Server.c / Hub.c / Admin.c)
│   │   ├── accept.zig        TLS accept + HTTP server envelope + handshake
│   │   ├── listener.zig      TCP/UDP listener, thread-per-conn
│   │   ├── hub.zig           Virtual Hub L2 switch (StorePacket, MAC/IP, ACL)
│   │   ├── session.zig / session_main.zig  SessionMain loop
│   │   ├── auth.zig / userdb.zig  Auth verification + user/group DB
│   │   ├── dhcp_server.zig / nat.zig / securenat.zig / virtual_host.zig
│   │   ├── farm.zig / farm_rpc.zig  Cluster controller/member
│   │   ├── admin/  rpc.zig, wpc.zig, dispatch.zig, structs.zig (~200 endpoints)
│   │   ├── config/ cfg.zig, vpn_server_config.zig (autosave, Cfg text format)
│   │   ├── logging.zig       Syslog, traffic accounting, EnumLog
│   │   ├── runtime.zig       Shared server runtime (FFI + vpnserver exe)
│   │   └── layer3.zig / bridge / udp_accel_server.zig / ra.zig
│   ├── protocol/         ← Wire protocol (shared)
│   │   ├── pack.zig             Pack serialization/deserialization
│   │   ├── rpc.zig              Remote Procedure Call layer
│   │   ├── auth.zig             Authentication (password, cert, anonymous)
│   │   ├── tunnel.zig           Tunnel framing + compression + keepalive
│   │   ├── softether_protocol.zig  SoftEther protocol constants/helpers
│   │   └── watermark.zig        Connection watermarking
│   ├── session/          ← Session encryption (AES-256-CBC, key derivation, RC4, MD4)
│   │   ├── session.zig
│   │   └── wrapper.zig
│   └── tunnel/           ← Data plane (ARP, DHCP, data loop, session_io)
│       ├── arp.zig
│       ├── dhcp.zig
│       ├── dhcpv6.zig
│       ├── data_loop.zig
│       └── session_io.zig
│
├── mayaqua/              ← Platform Abstraction Layer (SoftEtherVPN Mayaqua/)
│   ├── encrypt/          ← Pure Zig crypto (no OpenSSL dependency for session crypto)
│   │   ├── sha0.zig       SHA-0 (required by SoftEther protocol)
│   │   ├── hash.zig       SHA-1, SHA-256
│   │   ├── cipher.zig     AES-256-CBC + RC4
│   │   ├── md4.zig        MD4 (NTLM)
│   │   └── crypto.zig     Re-exports + utilities
│   ├── kernel/           ← Core types, IP utilities, errors
│   │   ├── types.zig      IpAddress, MacAddress, etc.
│   │   ├── ip.zig         IP parsing/formatting
│   │   └── errors.zig     Error definitions
│   └── network/          ← Networking (system OpenSSL for TLS)
│       ├── net.zig         Socket I/O, connection management
│       ├── tls.zig         OpenSSL 3.x TLS wrapper (connect + accept, cert bootstrap)
│       ├── http.zig        HTTP CONNECT proxy + HTTP server envelope
│       ├── socks.zig       SOCKS5 proxy tunnel
│       ├── dns_cache.zig   DNS cache
│       ├── udp_accel.zig   UDP acceleration (RUDP client + server role)
│       └── socket.zig      TcpListener / UdpListener
│
├── adapter/              ← TUN/TAP device management + routing
│   ├── utun.zig             macOS utun + BPF L2
│   ├── tun_linux.zig        Linux /dev/net/tun + AF_PACKET L2
│   ├── tap_windows.zig      Windows Wintun + Npcap L2
│   ├── fd_adapter.zig       Android/iOS fd-based adapter (from VpnService/NE)
│   ├── wrapper.zig          AdapterWrapper — unified interface
│   ├── port.zig             NetPort abstraction (L2/L3)
│   ├── utun_escalate.zig    macOS privilege escalation helper
│   ├── utun_helper_main.zig SUID helper binary entry point
│   ├── route.zig            Route management
│   ├── route_heal.zig       Stale route self-healing
│   └── dhcp.zig             DHCP client
│
├── bridge/               ← L2 bridge + STP (802.1D)
│   ├── fdb.zig, engine.zig, loop.zig, stp.zig
│
├── cli/                  ← Command-line interface
│   ├── args.zig            CLI arg parsing + env vars
│   ├── config_manager.zig  JSON config file management
│   ├── shell.zig           Interactive VPN shell
│   └── display.zig         Terminal display (colors, status, progress)
│
├── app/                  ← Application lifecycle
│   ├── state.zig           AppState
│   ├── config.zig          CliArgs → ClientConfig bridge
│   ├── events.zig          App-level event handling
│   ├── daemon.zig          Daemon mode
│   ├── interactive.zig     Interactive CLI mode
│   ├── signals.zig         Signal handling
│   └── password_hash.zig   Password hashing
│
├── exec/                 ← Executables
│   ├── vpnserver/main.zig  Server executable + runtime wiring
│   ├── vpnclient/main.zig  Client executable
│   ├── vpncmd/main.zig     Admin CLI (RPC/WPC)
│   └── vpnbridge/main.zig  Bridge executable
│
├── ffi.zig               ← C ABI exports (92 functions: client + server + bridge)
├── lib.zig               ← Zig module root (public API)
├── main.zig              ← Entry point (log config + dispatch)
├── config.zig            ← ConnectionConfig, StaticIpConfig, RoutingConfig, AuthMethod
├── types.zig             ← Common types (IpAddress, MacAddress)
└── errors.zig            ← VpnError union
```

### Responsibility Boundary

| Concern | Location | Notes |
|---------|----------|-------|
| Wire protocol (Pack, RPC, auth) | `cedar/protocol/` | Consumer-agnostic protocol impl |
| Session encryption (AES-256-CBC, RC4, MD4) | `cedar/session/` + `mayaqua/encrypt/` | Direction-aware key derivation, legacy RC4, NTLM MD4 |
| Client state machine | `cedar/client/` | VpnClient + ConnectionManager + auth_handler |
| Server (hub, listener, accept, session, farm, admin) | `cedar/server/` | 24 modules, ~20k LOC, thread-per-connection |
| Data plane (ARP, DHCP, DHCPv6, session_io) | `cedar/tunnel/` | Tunnel framing + compression + data loop |
| TUN/TAP + L2 bridge adapters | `adapter/` + `bridge/` | NetPort, BPF/AF_PACKET/Npcap, STP 802.1D |
| Routing + route self-heal | `adapter/` | route.zig + route_heal.zig |
| TLS/TCP networking (accept+connect) | `mayaqua/network/` | System OpenSSL 3.x, TcpListener, HTTP server envelope |
| UDP acceleration (RUDP server role) | `mayaqua/network/` + `cedar/server/udp_accel_server.zig` | Client + server RUDP |
| Proxy tunnels (HTTP, SOCKS5) | `mayaqua/network/` | HTTP CONNECT + SOCKS5 |
| Cryptography (SHA-0, AES, MD4, RC4) | `mayaqua/encrypt/` | Pure Zig, no OpenSSL dep for session crypto |
| CLI + interactive shell | `cli/` | args, config_manager, shell, display |
| Executables | `exec/` | vpnserver, vpnclient, vpncmd, vpnbridge |
| C ABI exports | `ffi.zig` | 92 `softether_*` functions (client + server + bridge/monitor) |
| Zig public API | `lib.zig` | VpnClient, Server, ClientConfig, etc. |

## Output Targets

| Platform | Build Command | Output | TUN Device |
|----------|--------------|--------|------------|
| macOS (arm64/x64) | `zig build` | CLIs (`vpnclient`/`vpnserver`/`vpncmd`/`vpnbridge`) | utun/BPF |
| macOS (arm64/x64) | `zig build shared-lib` | `libsoftether.dylib` (+ `softether-utun-helper` SUID binary) | utun/BPF |
| iOS (arm64) | `zig build static-lib -Dtarget=aarch64-ios` | `libsoftether.a` | NE fd |
| Linux (x86_64) | `zig build` | CLIs | `/dev/net/tun`/AF_PACKET |
| Linux (x86_64) | `zig build shared-lib` | `libsoftether.so` | `/dev/net/tun`/AF_PACKET |
| Windows (x64) | `zig build` | CLIs | Wintun/Npcap |
| Windows (x64) | `zig build shared-lib` | `softether.dll` | Wintun/Npcap |
| Android (arm64) | `zig build shared-lib -Dtarget=aarch64-linux-android` | `libsoftether.so` | VpnService fd |
| Android (arm32) | `zig build shared-lib -Dtarget=arm-linux-androideabi` | `libsoftether.so` | VpnService fd |

## Commands

```bash
# === Build ===
zig build                              # CLI (debug)
zig build --release=fast               # CLI (release)
zig build shared-lib                   # Shared library (.dylib/.so/.dll)
zig build static-lib -Dtarget=aarch64-ios  # iOS static library
zig build shared-lib -Dtarget=aarch64-linux-android  # Android arm64

# === Run CLI ===
sudo ./zig-out/bin/vpnclient connect \
  -s vpn.example.com -H VPN -u myuser -P mypassword
# vpnclient list  — alias to vpncmd client AccountList (XDG vpn_client.config)
# vpncmd tools generatehashedpassword -u myuser -p mypass  # replaces vpnclient passhash
sudo ./zig-out/bin/vpnclient connect --config config.json  # deprecated, use vpncmd

# === macOS privilege helper — built as part of shared-lib ===
# softether-utun-helper is automatically built by `zig build shared-lib`.
# After building, locate it in zig-out/bin/ and set SUID:
sudo chown root:wheel zig-out/bin/softether-utun-helper
sudo chmod u+s zig-out/bin/softether-utun-helper
./zig-out/bin/vpnclient connect ...

# === Test ===
zig build test                         # Unit tests (src/ + test/)
zig build test -- --test-filter "ffi"   # FFI-specific tests
bash test.sh                           # Functional test suite (10 config scenarios)
bash test.sh 120                       # Custom timeout per scenario (default 60s)

# === Diagnostics ===
python3 scripts/diag_data_plane.py     # Data-plane health check
python3 scripts/diag_tcp_upload.py     # TCP upload diagnostics
```

## Key Patterns

### Config system — 6 layers

Every property flows through: **CLI flag → env var → vpncmd store (XDG `vpn_client.config`) → app bridge → FFI setter → ClientConfig struct**. See `CONFIG.md` for the 12-field `connect` matrix (45-field legacy deprecated, see `docs/ACCOUNT.md`).

```zig
// Layer 1: CLI args (src/cli/args.zig)
//   --server, --port, --hub, --user, --password, ...

// Layer 2: Environment variables
//   SOFTETHER_SERVER, SOFTETHER_PORT, SOFTETHER_HUB, ...

// Layer 3: Config file (JSON)
//   { "address": "...", "hostname": "...", "port": 443, ... }

// Layer 4: Bridge (src/app/config.zig)
//   pub fn buildClientConfig(cli_args: CliArgs) !ClientConfig

// Layer 5: FFI setters (src/ffi.zig)
//   softether_set_encryption(client, true)
//   softether_set_compression(client, true)
//   softether_set_max_connections(client, 4)

// Layer 6: ClientConfig (src/cedar/client/vpn_client.zig)
//   pub const ClientConfig = struct { ... }
```

### C ABI — FFI interface (`ffi.zig`, 92 exports)

```c
// ====================================================================
// Lifecycle (call in order: create → set* → connect → run_data_loop)
// ====================================================================
softether_client_t softether_create(server, port, hub, username, password);
softether_client_t softether_create_anonymous(server, port, hub);
softether_client_t softether_create_certificate(server, port, hub, cert_pem, key_pem);
void softether_destroy(client);
int  softether_connect(client);
int  softether_disconnect(client);
int  softether_run_data_loop(client);
void softether_request_stop(client);

// ====================================================================
// State & stats
// ====================================================================
int  softether_get_state(client);
bool softether_is_connected(client);
int  softether_get_stats(client, &stats);
u32  softether_get_assigned_ip(client);
u32  softether_get_assigned_mask(client);
u32  softether_get_assigned_dns1(client);
u32  softether_get_assigned_dns2(client);
u32  softether_get_gateway_ip(client);
u32  softether_get_effective_server_ip(client);
const char* softether_version();

// ====================================================================
// Setters — call BEFORE connect, on the same client handle
// ====================================================================

// Connection parameters
void softether_set_encryption(client, bool);
void softether_set_compression(client, bool);
void softether_set_verify_certificate(client, bool);
void softether_set_max_connections(client, count);
void softether_set_half_connection(client, bool);
void softether_set_qos(client, bool);
void softether_set_udp_acceleration(client, bool);
void softether_set_mtu(client, mtu);
void softether_set_tcp_nodelay(client, bool);
void softether_set_ip_version(client, version);           // 0=any, 4=v4, 6=v6
void softether_set_connect_timeout(client, ms);
void softether_set_read_timeout(client, ms);
void softether_set_keepalive_interval(client, ms);
void softether_set_garp_interval(client, ms);
void softether_set_plain_password(client);                 // send plaintext (not hashed)
void softether_set_proxy(client, type, server, port, username, password);
void softether_set_hostname(client, hostname);
void softether_set_bind_interface(name);                   // global: bind to NIC
void softether_set_tcp_dial_callback(callback_fn);          // global: custom dial

// Reconnection
void softether_set_reconnect(client, enabled, max_attempts);

// Tunnel fd injection (mobile platforms)
void softether_set_tunnel_fd(client, fd);
void softether_set_tunnel_fds(client, dl_fd, ul_fd);
int  softether_replace_tun_fd(client, fd);

// Event callback (per-client)
void softether_set_event_callback(client, callback_fn, user_data);

// Logging
void softether_set_log_callback(callback_fn);              // global: external log sink
void softether_set_log_level_global(level);                // global: 0=err,1=warn,2=info,3=debug
void softether_set_log_level(client, level);               // compat shim (legacy, ignores client)
void softether_set_log_level_client(client, level);        // per-client: delegates to global

// Routing overrides
void softether_set_default_route(client, bool);
void softether_set_accept_pushed_routes(client, bool);
void softether_set_enable_custom_routes(client, bool);
void softether_set_ipv4_include(client, cidr);
void softether_set_ipv4_exclude(client, cidr);
void softether_set_ipv6_include(client, cidr);
void softether_set_ipv6_exclude(client, cidr);

// Static IP
void softether_set_static_ipv4(client, addr);
void softether_set_static_ipv4_netmask(client, mask);
void softether_set_static_ipv4_gateway(client, gw);
void softether_set_static_ipv6(client, addr);
void softether_set_static_ipv6_prefix(client, prefix);
void softether_set_static_ipv6_gateway(client, gw);
void softether_set_dns_servers(client, servers);

// Client fingerprint (spoof SoftEther VPN Client identity)
void softether_set_client_str(client, str);
void softether_set_client_ver(client, ver);
void softether_set_client_build(client, build);
void softether_set_os_info(client, name, version, title);

// Server FFI (embeddable server)
softether_server_t softether_server_create(hub, user, pass);
int  softether_server_start(server);
void softether_server_stop(server);
void softether_server_destroy(server);
int  softether_server_is_running(server);
int  softether_server_wait_for_listening(server, timeout_ms);
int  softether_server_get_hub_name(server, out_buf, len);
int  softether_server_get_admin_user(server, out_buf, len);
int  softether_server_set_syslog(server, hostname, port);

// Session enumeration (server)
int  softether_enum_sessions(server, hub, out_buf, max);
int  softether_get_session_status(server, hub, session, out);
int  softether_disconnect_session(server, hub, session);
```

### Zig public API (`lib.zig`)

```zig
const softether = @import("softether");
const client = softether.VpnClient.init(allocator, config);
defer client.deinit();
try client.connect();

// Builder pattern for config:
var builder = softether.ClientConfigBuilder.init("vpn.example.com", "VPN");
_ = builder.setPasswordAuth("user", "pass").setDefaultRoute(true);
const config = builder.build();
```

### VpnClient state machine

```
disconnected → connecting_tcp → ssl_handshake → authenticating
  → establishing_session → configuring_adapter → connected
  → (loop) → reconnecting → connecting_tcp → ...
  → disconnecting → disconnected
  → error_state → disconnected
```

### Build system highlights (`build.zig`)

- Version parsed from `build.zig.zon` at comptime (single source of truth)
- OpenSSL auto-detection: Homebrew paths on macOS, bundled `deps/openssl-ios/` for iOS, standard system paths on Linux
- Android builds require `--libc` config file (auto-generated by `scripts/build_android.sh` in consuming Flutter projects)
- `build_options` module injects version string into `lib.zig`

## Dependencies

| Dependency | Purpose | When Used | Location |
|-----------|---------|-----------|----------|
| **OpenSSL 3.x** | TLS 1.2/1.3 | macOS, Linux, Windows | System library |
| **zlib** | Block compression | All platforms | `deps/zlib/` (bundled) |
| **OpenSSL (iOS)** | TLS | iOS | `deps/openssl-ios/` (pre-built) |
| **OpenSSL (Android)** | TLS | Android | `deps/openssl-android/` (pre-built) |

No other external dependencies. All crypto (SHA-0, AES, HMAC) is pure Zig in `mayaqua/encrypt/`.

## Danger Zones

| Pitfall | Symptom | Fix |
|---------|---------|-----|
| **OpenSSL not found** | Build fails linking TLS symbols | `brew install openssl@3` (macOS), `apt install libssl-dev` (Linux) |
| **Wrong OpenSSL arch** | Linker errors on macOS ARM64 | Homebrew installs to `/opt/homebrew/opt/openssl@3` (ARM) vs `/usr/local/` (Intel) |
| **Android ABI mismatch** | `SIGSEGV` on `DynamicLibrary.open()` | Match target triple to device arch (`aarch64` vs `arm`) |
| **iOS simulator** | Network Extension unavailable | Must use physical device + release build |
| **TUN permission denied** | Adapter init failure on Linux | Run with `sudo` or set `CAP_NET_ADMIN` capability |
| **Stale `zig-out/`** | CLI/shared lib mismatch after code change | `zig build` recompiles but old artifacts may linger — `rm -rf zig-out` if suspect |
| **WorxVPN vs SE submodule drift** | Same library, different commits | SE at `7c798c39`, WX at `442d7656` — confirm FFI ABI compatible |
| **utun_escalate SUID** | macOS TUN permission error | `chown root:wheel` + `chmod u+s` the helper binary |

## Testing

```bash
# Unit tests (in-source + test/ directory)
zig build test
zig build test -- --test-filter "ffi"     # FFI-specific tests
zig build test -- --test-filter "handshake"  # Integration handshake tests

# Functional integration tests (requires running VPN server + config files)
bash test.sh                      # 10 config scenarios, 60s default timeout
bash test.sh 120                  # Custom timeout
```

### Test structure
- **Unit tests**: Embedded in each Zig source file with `test { ... }` blocks
- **Integration tests**: `test/integration/` — uses `ScriptedTransport` (in-memory, no sockets, deterministic)
  - `handshake_fixture_test.zig` — 8 fixtures: happy path, malformed hello, server error, auth rejection, cluster redirect, cert auth
- **Functional tests**: `test.sh` — Runs CLI against real VPN server with 10 config permutations (baseline, static IP, compression, half-conn, encrypt-off, UDP accel, multi-conn, stress, raw password)
- **Diagnostic scripts**: `scripts/diag_data_plane.py`, `scripts/diag_tcp_upload.py`

## Key Files Reference

| File | Purpose |
|------|---------|
| `build.zig` | Build system — CLI, shared-lib, static-lib, utun-helper targets |
| `build.zig.zon` | Package manifest (version v0.3.11) |
| `include/softether.h` | C API header (770 lines, 92 exports, auto-synced with ffi.zig) |
| `src/ffi.zig` | C ABI exports (92 `softether_*` functions, ~2,500 lines) |
| `src/lib.zig` | Zig module root (VpnClient, Server, ClientConfig, etc.) |
| `src/main.zig` | CLI entry point + scoped log level configuration |
| `src/cedar/client/vpn_client.zig` | Main client facade (~2,800 lines) |
| `src/cedar/server/` | Server (24 modules, ~20k LOC: hub, listener, accept, session, farm, admin) |
| `src/exec/` | Executables (vpnserver, vpnclient, vpncmd, vpnbridge) |
| `src/bridge/` | L2 bridge + STP (4 modules) |
| `config.example.json` | Example config file (all fields documented) |
| `config.schema.json` | JSON Schema for config file validation |
| `CONFIG.md` | Full 45-field config matrix across all 6 layers |
| `QUICKSTART.md` | Platform-specific build + run instructions |
| `docs/CODEBASE_REORGANIZATION.md` | Planned future codebase restructuring |
| `CHANGELOG.md` | Keep a Changelog format, pre-1.0 SemVer |

## Errors

- **Build error: OpenSSL headers not found**: Install OpenSSL 3.x development package
- **Runtime: TUN device creation failed**: Run as root / add `CAP_NET_ADMIN` capability
- **Runtime: TLS handshake failed**: Server certificate self-signed? Set `skip_tls_verify: true` in config
- **Runtime: Connection reset**: Server incompatible protocol version — SoftEther 4.x required
- **Runtime: Address already in use**: Another VPN instance or stale TUN interface — `sudo ifconfig utun0 destroy`
- **Linking: undefined symbol `SSL_*`**: OpenSSL lib not in linker path — check `build.zig` OpenSSL detection
- **SIGSEGV on Android**: Wrong ABI target — ensure `.so` matches `ro.product.cpu.abi`
