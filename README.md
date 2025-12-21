# SoftEtherZig

A high-performance SoftEther VPN client written in pure Zig.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Zig](https://img.shields.io/badge/Zig-0.15+-orange)](https://ziglang.org/)

## Features
- A pure Zig SoftEther VPN client
- Fast, low-latency tunnel implementation
- macOS native (Linux/Windows planned)

## Quick Start

### Prerequisites

- **Zig 0.15+**: [Download](https://ziglang.org/download/)
- **OpenSSL 3.0+**: `brew install openssl@3` (macOS)

### Build & Run

```bash
# Clone
git clone https://github.com/user/SoftEtherZig.git
cd SoftEtherZig

# Build (release for best performance)
zig build --release=fast

# Connect to VPN server
sudo ./zig-out/bin/vpnclient \
  --server vpn.example.com \
  --hub VPN \
  --user myuser \
  --password mypassword
```

### Using Config File

Create `config.json`:

```json
{
  "server": "vpn.example.com",
  "port": 443,
  "hub": "VPN",
  "username": "myuser",
  "password": "mypassword"
}
```

Then run:

```bash
sudo ./zig-out/bin/vpnclient --config config.json
```

## CLI Options

```
USAGE:
  vpnclient [OPTIONS]

CONNECTION:
  -s, --server <HOST>      VPN server hostname (required)
  -p, --port <PORT>        VPN server port (default: 443)
  -H, --hub <HUB>          Virtual hub name (required)
  -u, --user <USER>        Username (required)
  -P, --password <PASS>    Password (required)

OPTIONS:
  -c, --config <FILE>      Load configuration from JSON file
  -f, --full-tunnel        Route all traffic through VPN
  -d, --daemon             Run in background
  -h, --help               Show this help
  -v, --version            Show version
```

## Configuration

### Config File (`config.json`)

```json
{
  "server": "vpn.example.com",
  "port": 443,
  "hub": "VPN",
  "username": "myuser",
  "password": "mypassword",
  "full_tunnel": true
}
```

### Environment Variables

```bash
export SOFTETHER_SERVER="vpn.example.com"
export SOFTETHER_PORT="443"
export SOFTETHER_HUB="VPN"
export SOFTETHER_USER="myuser"
export SOFTETHER_PASSWORD="mypassword"

sudo -E ./zig-out/bin/vpnclient
```

**Priority:** CLI args > Environment variables > Config file

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| **macOS** (ARM64/x64) | ✅ Working | Primary development platform |
| **Linux** | 🚧 Planned | TUN device support in progress |
| **Windows** | 🚧 Planned | TAP adapter support planned |

## Architecture

```
┌─────────────────────────────────────┐
│         CLI / Config                │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│         VPN Client                  │
│  • Connection management            │
│  • DHCP/ARP handling                │
│  • Reconnection logic               │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│     SoftEther Protocol              │
│  • Authentication (RPC)             │
│  • Block-based tunnel format        │
│  • Keepalive                        │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      TLS / TCP Transport            │
│  • OpenSSL TLS 1.2/1.3              │
│  • TCP with NODELAY                 │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│       TUN Device (utun)             │
│  • IP packet injection              │
│  • Non-blocking I/O                 │
└─────────────────────────────────────┘
```

## Project Structure

```
SoftEtherZig/
├── src/
│   ├── main.zig           # Entry point
│   ├── config.zig         # Configuration parsing
│   ├── client/
│   │   └── vpn_client.zig # Main VPN client
│   ├── protocol/
│   │   ├── auth.zig       # Authentication
│   │   ├── rpc.zig        # RPC protocol
│   │   └── tunnel.zig     # Data tunnel
│   ├── adapter/
│   │   ├── utun.zig       # macOS TUN device
│   │   └── dhcp.zig       # DHCP client
│   ├── net/
│   │   ├── tls.zig        # TLS wrapper
│   │   └── socket.zig     # TCP socket
│   └── crypto/
│       └── ...            # Cryptographic utilities
├── build.zig
├── config.json
└── README.md
```

## Building

```bash
# Debug build
zig build

# Release build (recommended)
zig build --release=fast

# Run tests
zig build test
```

## Troubleshooting

### Permission Denied

TUN devices require root privileges:

```bash
sudo ./zig-out/bin/vpnclient ...
```

### Connection Timeout

1. Verify server is reachable: `ping vpn.example.com`
2. Check port is open: `nc -zv vpn.example.com 443`
3. Confirm hub name is correct

### Authentication Failed

- Double-check username/password
- Verify hub name matches server configuration
- Ensure account is enabled on server

### High Latency

Build with release optimizations:

```bash
zig build --release=fast
```

## Security

- Passwords can be passed via environment variables (preferred over CLI)
- TLS 1.2+ with certificate verification
- See [SECURITY.md](SECURITY.md) for security best practices

## License

Apache License 2.0

## Credits

- [SoftEther VPN Project](https://www.softether.org/) - Protocol specification
- [Zig](https://ziglang.org/) - Programming language
- [OpenSSL](https://www.openssl.org/) - TLS implementation
