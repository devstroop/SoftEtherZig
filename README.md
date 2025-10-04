# SoftEtherZig

A modern, cross-platform VPN client implementation in Zig, wrapping the SoftEther VPN protocol.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Zig Version](https://img.shields.io/badge/zig-0.15.1+-blue)](https://ziglang.org/)

## Overview

SoftEtherZig is a clean, modern VPN client written in Zig that provides a high-level interface to the battle-tested SoftEther VPN protocol. It combines the performance and safety of Zig with the proven reliability of SoftEther VPN's C codebase.

## Features

- 🚀 **High Performance**: Zero-cost abstractions with Zig's compile-time features
- 🔒 **Secure**: SSL/TLS 1.3 encryption with SoftEther's proven security model
- 🌐 **Cross-Platform**: Native support for macOS, Linux, Windows, **Android, and iOS**
- ⚡ **UDP Acceleration**: Optimized network performance with SoftEther's R-UDP protocol
- 📱 **Mobile Ready**: Full Android (JNI) and iOS (Network Extension) implementations
- 🛠️ **Dual Interface**: Both CLI tool and embeddable library
- 🔧 **Easy Integration**: Clean Zig API for custom applications
- 📦 **Self-Contained**: No external dependencies except OpenSSL

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/SoftEtherZig.git
cd SoftEtherZig

# Build the client
zig build -Doptimize=ReleaseFast

# Connect to a VPN server
sudo ./zig-out/bin/vpnclient -s vpn.example.com -H VPN -u username -P password
```

## Installation

### Prerequisites

- **Zig**: 0.15.1 or later ([download](https://ziglang.org/download/))
- **OpenSSL**: 3.0+ (system package manager)
- **Root/Admin privileges**: Required for TUN device creation

### System Dependencies

```bash
# macOS
brew install openssl@3

# Ubuntu/Debian
sudo apt update
sudo apt install libssl-dev

# Fedora/RHEL
sudo dnf install openssl-devel

# Windows
# Download OpenSSL from https://slproweb.com/products/Win32OpenSSL.html
```

### Build

```bash
# Development build
zig build

# Optimized release build
zig build -Doptimize=ReleaseFast

# Install system-wide (optional)
sudo cp zig-out/bin/vpnclient /usr/local/bin/
```

## Usage

### Command Line Interface

```bash
# Basic connection
sudo vpnclient -s vpn.example.com -H VPN -u username -P password

# Custom port
sudo vpnclient -s vpn.example.com -p 8443 -H VPN -u username -P password

# Daemon mode (background)
sudo vpnclient -s vpn.example.com -H VPN -u username -P password -d

# Show help
vpnclient --help
```

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `-s, --server <HOST>` | VPN server hostname | *required* |
| `-p, --port <PORT>` | VPN server port | 443 |
| `-H, --hub <HUB>` | Virtual hub name | *required* |
| `-u, --user <USERNAME>` | Username | *required* |
| `-P, --password <PASS>` | Password | *required* |
| `-a, --account <NAME>` | Account name | username |
| `--no-encrypt` | Disable encryption | false |
| `--no-compress` | Disable compression | false |
| `-d, --daemon` | Run as daemon | false |
| `-h, --help` | Show help | |
| `-v, --version` | Show version | |

### Library Usage

```zig
const softether = @import("softether");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = softether.ConnectionConfig{
        .server_name = "vpn.example.com",
        .server_port = 443,
        .hub_name = "VPN",
        .account_name = "myaccount",
        .auth = .{ .password = .{
            .username = "user",
            .password = "pass",
        } },
        .use_encrypt = true,
        .use_compress = true,
    };

    var client = try softether.VpnClient.init(allocator, config);
    defer client.deinit();

    try client.connect();

    // Your application logic here
    while (client.isConnected()) {
        std.time.sleep(1 * std.time.ns_per_s);
    }
}
```

## Architecture

### Project Structure

```
SoftEtherZig/
├── SoftEtherVPN_Stable/          # SoftEther C source (submodule)
│   └── src/                      # Original SoftEther VPN codebase
├── src/                          # Zig implementation
│   ├── main.zig                  # Library entry point
│   ├── cli.zig                   # Command-line interface
│   ├── client.zig                # VPN client logic
│   ├── config.zig                # Configuration types
│   ├── types.zig                 # Common data structures
│   ├── errors.zig                # Error definitions
│   ├── ffi.zig                   # C foreign function interface
│   ├── c.zig                     # C imports and bindings
│   └── bridge/                   # C bridge layer
│       ├── softether_bridge.c    # Main SoftEther interface
│       ├── unix_bridge.c         # POSIX system abstraction
│       ├── packet_adapter_*.c    # Platform-specific TUN/TAP
│       └── tick64_*.c            # High-resolution timing
├── build.zig                     # Build configuration
├── build.zig.zon                 # Zig package dependencies
└── zig-out/                      # Build artifacts
    └── bin/
        └── vpnclient             # Compiled executable
```

### Component Overview

1. **CLI Layer** (`cli.zig`): Command-line argument parsing and user interaction
2. **Client Layer** (`client.zig`): High-level VPN connection management
3. **Bridge Layer** (`bridge/`): C code that interfaces with SoftEther VPN
4. **FFI Layer** (`ffi.zig`): Safe Zig bindings to C functions

### Network Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Application   │────│   Zig Client     │────│   C Bridge      │
│   (CLI/Library) │    │   Logic          │    │   Layer         │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌────────────────────┐
                    │  SoftEther VPN     │
                    │  Core (C)          │
                    └────────────────────┘
                             │
                    ┌────────────────────┐
                    │  SSL/TLS 1.3       │
                    │  (OpenSSL)         │
                    └────────────────────┘
                             │
                    ┌────────────────────┐
                    │  TUN/TAP Device    │
                    │  (Platform)        │
                    └────────────────────┘
```

## Platform Support

### Desktop Platforms

| Platform | Architecture | TUN Device | Status |
|----------|--------------|------------|--------|
| macOS | x86_64, ARM64 | utun | ✅ Tested |
| Linux | x86_64, ARM64 | TUN/TAP | 🚧 Planned |
| Windows | x86_64 | TAP-Windows6 | 🚧 Planned |

### Mobile Platforms

| Platform | Architecture | Implementation | Status |
|----------|--------------|----------------|--------|
| Android | ARM64, ARMv7, x86_64 | JNI + VpnService | ✅ Complete |
| iOS | ARM64, x86_64 | PacketTunnelProvider | ✅ Complete |

**Mobile implementations are production-ready!** See:
- [`android/README.md`](android/README.md) - Android integration guide
- [`ios/README.md`](ios/README.md) - iOS integration guide
- [`MOBILE_COMPLETE.md`](MOBILE_COMPLETE.md) - Complete mobile implementation summary

### Building for Different Platforms

Zig enables seamless cross-compilation:

```bash
# Build for Linux from macOS
zig build -Dtarget=x86_64-linux-gnu

# Build for Windows from macOS
zig build -Dtarget=x86_64-windows-gnu

# Build for ARM64 Linux
zig build -Dtarget=aarch64-linux-gnu
```

## Building from Source

### Standard Build

```bash
# Debug build (with symbols)
zig build

# Release build (optimized)
zig build -Doptimize=ReleaseFast

# Safe release build
zig build -Doptimize=ReleaseSafe
```

### Custom Build Options

```bash
# Build with custom target
zig build -Dtarget=aarch64-linux-gnu

# Build with specific CPU features
zig build -Dcpu=baseline

# Clean build artifacts
rm -rf zig-cache zig-out
```

### Build Dependencies

The build system automatically:
- Downloads and compiles SoftEther C sources
- Links with system OpenSSL
- Creates platform-specific TUN adapters
- Generates optimized binaries

## Configuration

### Runtime Configuration

The client supports runtime configuration through command-line arguments. For library usage, configure via the `ConnectionConfig` struct.

### Environment Variables

- `SSL_CERT_FILE`: Path to custom CA certificate bundle
- `SSL_CERT_DIR`: Directory containing CA certificates

## Troubleshooting

### Common Issues

**Permission Denied**
```bash
# Solution: Run with sudo for TUN device access
sudo vpnclient -s server -H hub -u user -P pass
```

**Connection Timeout**
- Verify server hostname and port
- Check firewall settings
- Ensure VPN server is accessible

**Authentication Failed**
- Confirm username and password
- Check virtual hub name
- Verify account permissions

**TUN Device Busy**
- macOS: Wait for utun device to become available
- Linux: Check `/dev/net/tun` permissions

### Debug Mode

```bash
# Build with debug symbols
zig build -Doptimize=Debug

# Run with verbose logging
sudo ./zig-out/bin/vpnclient -s server -H hub -u user -P pass 2>&1 | tee debug.log
```

## Development

### Code Organization

- **`src/`**: Zig source code
- **`src/bridge/`**: C bridge code interfacing with SoftEther
- **`SoftEtherVPN_Stable/`**: Upstream SoftEther VPN source

### Adding Features

**CLI Features:**
- Edit `src/cli.zig` for new command-line options

**Client Features:**
- Modify `src/client.zig` for connection logic

**Bridge Features:**
- Update `src/bridge/softether_bridge.c` for new SoftEther integration

### Testing

```bash
# Run tests
zig build test

# Build and test specific target
zig build -Dtarget=x86_64-linux-gnu test
```

### Code Style

- **Zig**: Follow official Zig style guide
- **C**: Follow SoftEther VPN conventions
- **Documentation**: Use Zig doc comments for public APIs

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Areas for Contribution

- 🐧 Linux TUN/TAP implementation
- 🪟 Windows TAP-Windows6 support
- 🔐 Additional authentication methods (certificate, RADIUS)
- 📊 Performance optimizations
- 🧪 Comprehensive test suite
- 📚 Documentation improvements

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

The SoftEther VPN components are licensed under Apache License 2.0 by the SoftEther VPN Project.

## Credits

- **SoftEther VPN Project**: Original VPN implementation
- **Zig Programming Language**: Modern systems programming language
- **OpenSSL Project**: Cryptography library

## Related Projects

- [SoftEther VPN Official](https://www.softether.org/) - Original SoftEther VPN
- [Zig Language](https://ziglang.org/) - Programming language
- [OpenSSL](https://www.openssl.org/) - Cryptography toolkit

---

**SoftEtherZig** - Bringing modern programming practices to enterprise VPN connectivity.
