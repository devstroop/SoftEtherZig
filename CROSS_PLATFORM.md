# Cross-Platform Build Guide

This document provides detailed instructions for building the SoftEther VPN Zig client on different platforms.

## Platform Support Matrix

| Platform | Architecture | Status | TUN Device | Build Tested |
|----------|-------------|--------|------------|--------------|
| macOS | x86_64 | ✅ Complete | utun | ✅ Yes |
| macOS | arm64 | ✅ Complete | utun | ✅ Yes |
| Linux | x86_64 | ✅ Complete | /dev/net/tun | ⚠️ Needs testing |
| Linux | arm64 | ✅ Complete | /dev/net/tun | ⚠️ Needs testing |
| Windows | x64 | ✅ Complete | TAP-Windows6 | ⚠️ Needs testing |

## Prerequisites by Platform

### macOS

```bash
# Install Zig
brew install zig

# Install OpenSSL
brew install openssl@3

# Verify installation
zig version  # Should be 0.15.1 or later
openssl version  # Should be OpenSSL 3.x
```

### Linux (Debian/Ubuntu)

```bash
# Install Zig (download from ziglang.org or use package manager)
wget https://ziglang.org/download/0.15.1/zig-linux-x86_64-0.15.1.tar.xz
tar xf zig-linux-x86_64-0.15.1.tar.xz
sudo mv zig-linux-x86_64-0.15.1 /opt/zig
export PATH=$PATH:/opt/zig

# Install OpenSSL development libraries
sudo apt update
sudo apt install libssl-dev build-essential

# Install TUN/TAP support
sudo apt install uml-utilities
```

### Linux (Fedora/RHEL/CentOS)

```bash
# Install Zig
wget https://ziglang.org/download/0.15.1/zig-linux-x86_64-0.15.1.tar.xz
tar xf zig-linux-x86_64-0.15.1.tar.xz
sudo mv zig-linux-x86_64-0.15.1 /opt/zig
export PATH=$PATH:/opt/zig

# Install OpenSSL development libraries
sudo dnf install openssl-devel gcc make

# TUN/TAP is built into the kernel (no extra package needed)
```

### Windows

```powershell
# Install Zig (download from ziglang.org)
# Extract to C:\zig and add to PATH

# Install OpenSSL
# Download from: https://slproweb.com/products/Win32OpenSSL.html
# Install "Win64 OpenSSL v3.x.x" to C:\OpenSSL-Win64

# Install TAP-Windows6 adapter
# Download OpenVPN: https://openvpn.net/community-downloads/
# This includes the TAP-Windows6 driver

# Or install just the TAP adapter:
# https://build.openvpn.net/downloads/releases/tap-windows-9.24.7-I601-Win10.exe
```

## Building

### Native Build (Current Platform)

```bash
# Clone repository
cd /path/to/SoftEtherVPN/zig

# Build (release mode)
zig build -Doptimize=ReleaseFast

# Build (debug mode with symbols)
zig build -Doptimize=Debug

# Output binary location
./zig-out/bin/vpnclient
```

### Cross-Compilation

Zig's native cross-compilation makes it easy to build for other platforms:

#### Build for Linux from macOS

```bash
# x86_64 Linux
zig build -Dtarget=x86_64-linux-gnu -Doptimize=ReleaseFast

# ARM64 Linux (Raspberry Pi, AWS Graviton, etc.)
zig build -Dtarget=aarch64-linux-gnu -Doptimize=ReleaseFast
```

#### Build for Windows from macOS/Linux

```bash
# x64 Windows
zig build -Dtarget=x86_64-windows-gnu -Doptimize=ReleaseFast
```

#### Build for macOS from Linux

```bash
# Intel Mac
zig build -Dtarget=x86_64-macos -Doptimize=ReleaseFast

# Apple Silicon Mac
zig build -Dtarget=aarch64-macos -Doptimize=ReleaseFast
```

### Notes on Cross-Compilation

1. **OpenSSL Dependencies**: Cross-compilation requires OpenSSL libraries for the target platform. You may need to:
   - Use static linking: Add `-Dtarget-static` flag
   - Provide target-specific libraries: Set paths in build.zig
   - Use zig-provided libs when available

2. **System Libraries**: Platform-specific libraries (pthread, ws2_32, etc.) are handled automatically by build.zig

3. **Testing**: Cross-compiled binaries must be tested on the target platform

## Platform-Specific Configuration

### macOS TUN Device

The macOS implementation uses `utun` kernel control interfaces (utun0-utun15). No additional configuration needed.

```bash
# Check available utun devices
ifconfig | grep utun

# The VPN client will automatically allocate the first available device
```

### Linux TUN/TAP Device

The Linux implementation uses `/dev/net/tun`. Ensure your user has permission:

```bash
# Check TUN/TAP support
lsmod | grep tun

# If not loaded, load the module
sudo modprobe tun

# Grant user permission (option 1 - add to netdev group)
sudo usermod -a -G netdev $USER

# Grant user permission (option 2 - set device permissions)
sudo chmod 666 /dev/net/tun

# Verify
ls -l /dev/net/tun
```

### Windows TAP Adapter

The Windows implementation uses TAP-Windows6 adapter from OpenVPN:

```powershell
# Install TAP adapter (if not already installed)
# Download and run: tap-windows-9.24.7-I601-Win10.exe

# Verify installation
Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*TAP-Windows*"}

# Rename adapter for easier identification (optional)
Rename-NetAdapter -Name "Ethernet 2" -NewName "VPN TAP"
```

## Troubleshooting

### macOS

**Issue**: "Operation not permitted" when opening TUN device
```bash
# Run with sudo
sudo ./zig-out/bin/vpnclient -s server.com -H HUB -u user -P pass
```

**Issue**: "No available utun devices"
```bash
# Check existing utun devices
ifconfig | grep utun

# Kill processes holding utun devices
sudo killall -9 vpnclient
```

### Linux

**Issue**: "Cannot open /dev/net/tun"
```bash
# Check TUN module
sudo modprobe tun

# Check permissions
ls -l /dev/net/tun

# Fix permissions
sudo chmod 666 /dev/net/tun
```

**Issue**: "Operation not permitted"
```bash
# Run with sudo or add CAP_NET_ADMIN capability
sudo ./zig-out/bin/vpnclient ...

# Or grant capability
sudo setcap cap_net_admin+ep ./zig-out/bin/vpnclient
```

### Windows

**Issue**: "Cannot find TAP adapter"
```powershell
# List network adapters
Get-NetAdapter

# Install TAP-Windows6 driver
# Download from OpenVPN website
```

**Issue**: "Access denied"
```powershell
# Run as Administrator
# Right-click → Run as Administrator
```

## Performance Optimization

### Release Builds

For production use, always build with optimizations:

```bash
zig build -Doptimize=ReleaseFast
```

Build modes comparison:
- `Debug`: Full debug symbols, no optimizations (~5 MB)
- `ReleaseSafe`: Optimizations + safety checks (~3 MB)
- `ReleaseFast`: Maximum speed, minimal safety (~2.5 MB)
- `ReleaseSmall`: Smallest size (~2 MB)

### Static Linking

To create a standalone binary without runtime dependencies:

```bash
# Linux
zig build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseFast

# This creates a fully static binary that runs anywhere
```

## Automated CI/CD

Example GitHub Actions workflow for multi-platform builds:

```yaml
name: Build

on: [push, pull_request]

jobs:
  build:
    strategy:
      matrix:
        os: [macos-latest, ubuntu-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Zig
        uses: goto-bus-stop/setup-zig@v2
        with:
          version: 0.15.1
      
      - name: Install OpenSSL (macOS)
        if: runner.os == 'macOS'
        run: brew install openssl@3
      
      - name: Install OpenSSL (Linux)
        if: runner.os == 'Linux'
        run: sudo apt install libssl-dev
      
      - name: Install OpenSSL (Windows)
        if: runner.os == 'Windows'
        run: choco install openssl
      
      - name: Build
        run: zig build -Doptimize=ReleaseFast
      
      - name: Upload artifact
        uses: actions/upload-artifact@v3
        with:
          name: vpnclient-${{ runner.os }}
          path: zig-out/bin/vpnclient*
```

## Next Steps

After building:

1. **Test Connection**: See [README.md](README.md) for usage examples
2. **Configure Network**: Set up routing and DNS (see docs/networking.md)
3. **Production Deployment**: See docs/deployment.md for systemd/launchd setup
4. **FFI Integration**: See docs/ffi-guide.md for using from other languages
