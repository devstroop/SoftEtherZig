# Account Store — `vpncmd` Profile Ownership

> **Status:** M19 contract — `vpnclient` 9-verb minimal surface (`connect` + `install`/`uninstall`/`start`/`stop`/`restart`/`status`/`enable`/`disable`/`list` + `help`/`version`/`cleanup`) with `bridge`/`monitor` as `--mode` flags. `config.json`/`--config`/`SOFTETHER_CONFIG` is deprecated (M19 #254) and will be removed in M21 P2. Profiles are owned by `vpncmd`, not hand-edited JSON.

## Store Location

`vpnclient` host file `config.json` is **deprecated**. The canonical store is the `vpncmd`-managed `vpn_client.config` binary `Cfg` tree (parity to `SoftEtherVPN` `vpn_client.config` `Cfg.c` `declare`):

- **Linux/macOS (XDG):** `$XDG_CONFIG_HOME/softether-zig/vpn_client.config` (`~/.config/softether-zig/vpn_client.config` when `XDG_CONFIG_HOME` unset)
- **Linux system service (`--system`):** `/etc/softether-zig/vpn_client.config` (when `install --system`)
- **Windows:** `%APPDATA%\softether-zig\vpn_client.config` (`FOLDERID_RoamingAppData`)
- **Format:** Binary `Cfg` (`declare` tree, `src/cedar/server/config/cfg.zig:32` `Cfg.c` parity), not hand-edited JSON. Hand editing is unsupported.

No JSON `import`/`export` — `vpncmd` manages the store internally (your #1). One-shot `docker`/`CLI` without `install` uses ephemeral flag/env without touching the store.

## `vpncmd` Client Account Verbs (M21 P3)

```
vpncmd client AccountCreate <name> /SERVER:host:port /HUB:hub /USERNAME:user [/PASSWORD:pass]
vpncmd client AccountPasswordSet <name> /PASSWORD:pass
vpncmd client AccountList
vpncmd client AccountDelete <name>
vpncmd client NicCreate <name>          # virtual NIC (macOS utun helper / Wintun)
vpncmd tools generatehashedpassword [-u user -p pass]  # SHA-0(password + UPPER(user)), MD4 NTLM parity
vpncmd tools makeCert ...               # X.509 (when needed)
```

Transport: native RPC (`src/cedar/server/admin/rpc.zig:373` `adminThread`) + WPC/HTTPS (`src/cedar/server/wpc.zig`) to `vpnclient`/`vpnserver` `127.0.0.1:5555` (or `vpnserver` remote).

**Examples:**

```bash
# Create and list (persists to XDG vpn_client.config)
vpncmd client AccountCreate vpn1 /SERVER:worxvpn.662.cloud:443 /HUB:VPN /USERNAME:devstroop1
vpncmd client AccountPasswordSet vpn1 /PASSWORD:devstroop111222
vpncmd client AccountList
# vpn1  worxvpn.662.cloud:443  VPN  devstroop1

# Hash generation (for scripts, no store write)
vpncmd tools generatehashedpassword -u devstroop1 -p devstroop111222
# CS9ZXBrvt9GFvoHSvNuUfhP4rmw=

# vpnclient consumes store when no flags (flag/env overrides store for docker -e)
vpnclient connect                      # uses vpn1 account from XDG store
vpnclient connect -a 62.24.65.211 --hostname worxvpn.662.cloud -H VPN -u devstroop1 -P devstroop111222  # ephemeral, no store

# Bridge/monitor are --mode flags, not verbs
vpnclient connect --mode bridge --ingress eth0
vpnclient connect --mode monitor --pcap /tmp/cap.pcap
```

## `vpnclient` 9-Verb Contract (M19 #255)

```
vpnclient help
vpnclient version
vpnclient connect [OPTIONS]          # one-shot, foreground for docker (no install)
vpnclient list                       # alias to vpncmd client AccountList
vpnclient cleanup                    # stale routes
vpnclient passhash                   # deprecated — use vpncmd tools
vpnclient install [--user|--system]  # planned M20
vpnclient start|stop|restart|status|enable|disable  # planned M20
```

`install` (`systemd` `Type=simple` `Restart=on-failure` `WantedBy=multi-user.target` `AmbientCapabilities=CAP_NET_ADMIN`, `launchd` `KeepAlive`, `SCM`) and `vpncmd`-owned profiles follow community standards (`systemd`/`launchd`/`SCM`, XDG/FHS, 12-factor env-over-file).

## Migration from `config.json`

One-shot `vpncmd client import --from config.json` (hidden, P2) or manual `AccountCreate` mapping:

```bash
# Old config.json with password_hash CS9... → new store
vpncmd client AccountCreate vpn1 /SERVER:worxvpn.662.cloud:443 /HUB:VPN /USERNAME:devstroop1
# Enter hash when prompted or via AccountPasswordSet with --password-hash
```

After M21 P2, `config.json` for `vpnclient` is removed (`git ls-files | grep -E "config\.(json|example\.json)"` empty except `vpn_server.config`).

## References

- `SoftEtherVPN` `src/vpnclient/vpnclient.c:CtStartClient`, `src/vpncmd/Client.c:AccountCreate`, `src/vpncmd/Tools.c:GenerateHashedPassword` (`Mayaqua/Encrypt.c:GenerateNtPasswordHash` `MD4`)
- `Mayaqua/Unix.c:Daemon` `InitDaemon` `Lock`/`PID` file fallback when `PID 1 != systemd`
- `CONFIG.md` 12-field `connect` matrix (M21) vs 50-field legacy
