# IPv6 Data-Plane Validation Guide

## Prerequisites

- SoftEther VPN Server with IPv6 enabled (SecureNAT + IPv6 listener)
- macOS or Linux client with root/sudo
- Zig 0.15.1 + OpenSSL 3

## Server Setup (Docker)

```bash
docker run --cap-add=NET_ADMIN \
    -e USERS="testuser:testpass" \
    -e HUB="VPN" \
    -p 443:443/tcp \
    siomiz/softethervpn
```

Then on the server via `vpncmd`:
1. Enable SecureNAT with IPv6
2. Configure DHCPv6 scope (IA_NA address pool, DNS servers)
3. Enable IPv6 routing on the hub

## Build

```bash
cd libsoftether
zig build --release=fast
```

## Acceptance Tests

### 1. Static IPv6 (manual config)

```bash
sudo ./zig-out/bin/vpnclient \
    --server <server> --hub VPN \
    --user <user> --password <pass> \
    --static-ipv6 2001:db8::100 \
    --static-ipv6-prefix 64
```

Verify: `ifconfig utunX inet6` shows the address.

### 2. Dynamic IPv6 (DHCPv6 from server)

The client sends a DHCPv6 Solicit shortly after connecting. A DHCPv6 Reply from the server will automatically:

1. Assign an IPv6 address to the utun interface
2. Install an IPv6 default route via `fe80::1%utunX`
3. Log: `DHCPv6 REPLY received — configuring IPv6 address`

Verify:

```bash
# Check IPv6 address on tunnel
ifconfig utunX | grep inet6

# Check IPv6 default route
netstat -rn -f inet6 | grep utun

# Test connectivity
ping6 -c 3 2001:4860:4860::8888

# Test HTTP/HTTPS
curl -6 -v https://ipv6.google.com/
```

### 3. Route Cleanup (dirty disconnect)

```bash
# Kill the client without clean disconnect
sudo kill -9 <vpnclient-pid>

# Reconnect — client should purge stale IPv6 routes
sudo ./zig-out/bin/vpnclient ...
```

### 4. Dual-Stack

Both IPv4 and IPv6 traffic works simultaneously:

```bash
ping -c 3 8.8.8.8        # IPv4
ping6 -c 3 2001:4860:4860::8888  # IPv6
```

### 5. Static IPv6 via CLI

```bash
sudo ./zig-out/bin/vpnclient \
    --server <server> --hub VPN \
    --user <user> --password <pass> \
    --static-ipv6 2001:db8::42 \
    --static-ipv6-prefix 64 \
    --static-ipv6-gateway fe80::1
```

## Troubleshooting

| Symptom | Likely Cause |
|---|---|
| No DHCPv6 Reply | Server needs `EnableIPv6Listener` + SecureNAT with DHCPv6 scope |
| `ping6` fails with "no route to host" | IPv6 default route not installed — check `netstat -rn -f inet6` |
| Two IPv6 addresses on utun | RA/SLAAC race — kernel auto-configd before DHCPv6 Reply |
| `ifconfig inet6 add` fails | macOS SIP — run with `sudo` or disable SIP for ifconfig |
| Build fails on Linux | Add `pub fn configureIpv6(...)` to `src/adapter/tun_linux.zig` |
