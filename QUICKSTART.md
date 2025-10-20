# Quick Start - Cross-Platform Usage

This guide shows how to quickly get started with the VPN client on each platform.

## macOS (Intel & Apple Silicon)

### Installation

```bash
# Install dependencies
brew install zig openssl@3

# Clone and build
cd /path/to/SoftEtherVPN/zig
zig build -Doptimize=ReleaseFast

# Optional: Install system-wide
sudo cp zig-out/bin/vpnclient /usr/local/bin/
```

### Usage

```bash
# Connect to VPN
sudo vpnclient -s vpn.example.com -H VPN -u myuser -P mypassword

# Run as daemon (background)
sudo vpnclient -s vpn.example.com -H VPN -u myuser -P mypassword -d

# Check connection
ifconfig | grep utun
```

### Troubleshooting

```bash
# Check available utun devices
ifconfig | grep utun

# Kill existing connections
sudo killall vpnclient

# Run with debug output
sudo vpnclient -s vpn.example.com -H VPN -u user -P pass 2>&1 | tee debug.log
```

---

## Linux (Debian/Ubuntu)

### Installation

```bash
# Install Zig (if not available via apt)
wget https://ziglang.org/download/0.15.1/zig-linux-x86_64-0.15.1.tar.xz
tar xf zig-linux-x86_64-0.15.1.tar.xz
sudo mv zig-linux-x86_64-0.15.1 /opt/zig
export PATH=$PATH:/opt/zig

# Install dependencies
sudo apt update
sudo apt install libssl-dev build-essential

# Enable TUN/TAP
sudo modprobe tun

# Clone and build
cd /path/to/SoftEtherVPN/zig
zig build -Doptimize=ReleaseFast

# Optional: Install system-wide
sudo cp zig-out/bin/vpnclient /usr/local/bin/
```

### Usage

```bash
# Connect to VPN
sudo vpnclient -s vpn.example.com -H VPN -u myuser -P mypassword

# Run as daemon
sudo vpnclient -s vpn.example.com -H VPN -u myuser -P mypassword -d

# Check connection
ip tuntap show
ip addr show | grep tun
```

### Troubleshooting

```bash
# Check TUN module
lsmod | grep tun

# Load TUN module if needed
sudo modprobe tun

# Fix permissions
sudo chmod 666 /dev/net/tun

# Grant capability (alternative to sudo)
sudo setcap cap_net_admin+ep /usr/local/bin/vpnclient

# Check logs
journalctl -f | grep vpn
```

---

## Linux (Fedora/RHEL/CentOS)

### Installation

```bash
# Install Zig
wget https://ziglang.org/download/0.15.1/zig-linux-x86_64-0.15.1.tar.xz
tar xf zig-linux-x86_64-0.15.1.tar.xz
sudo mv zig-linux-x86_64-0.15.1 /opt/zig
export PATH=$PATH:/opt/zig

# Install dependencies
sudo dnf install openssl-devel gcc make

# TUN/TAP is built into kernel (no module needed)

# Clone and build
cd /path/to/SoftEtherVPN/zig
zig build -Doptimize=ReleaseFast

# Optional: Install system-wide
sudo cp zig-out/bin/vpnclient /usr/local/bin/
```

### Usage

Same as Debian/Ubuntu (see above).

---

## Windows (x64)

### Installation

**Step 1: Install Zig**

1. Download Zig 0.15.1 from https://ziglang.org/download/
2. Extract to `C:\zig`
3. Add `C:\zig` to system PATH

**Step 2: Install OpenSSL**

1. Download from https://slproweb.com/products/Win32OpenSSL.html
2. Install "Win64 OpenSSL v3.x.x" to `C:\OpenSSL-Win64`

**Step 3: Install TAP-Windows6 Driver**

Option A - Install full OpenVPN (includes TAP driver):
1. Download from https://openvpn.net/community-downloads/
2. Run installer
3. Select "TAP Virtual Ethernet Adapter" component

Option B - Install TAP driver only:
1. Download from https://build.openvpn.net/downloads/releases/
2. Install `tap-windows-9.24.7-I601-Win10.exe`

**Step 4: Build**

```powershell
# Open PowerShell or Command Prompt
cd C:\path\to\SoftEtherVPN\zig
zig build -Doptimize=ReleaseFast

# Optional: Copy to system directory
copy zig-out\bin\vpnclient.exe C:\Windows\System32\
```

### Usage

```powershell
# Open PowerShell or Command Prompt AS ADMINISTRATOR

# Connect to VPN
vpnclient.exe -s vpn.example.com -H VPN -u myuser -P mypassword

# Run as daemon (background)
Start-Process vpnclient.exe -ArgumentList "-s","vpn.example.com","-H","VPN","-u","myuser","-P","mypassword","-d" -NoNewWindow

# Check connection
Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*TAP*"}
```

### Troubleshooting

```powershell
# List network adapters
Get-NetAdapter

# Check for TAP adapter
Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*TAP*"}

# Reinstall TAP driver if not found
# Download and run tap-windows installer again

# Check OpenSSL installation
Test-Path C:\OpenSSL-Win64\bin\openssl.exe

# Run with debug output
vpnclient.exe -s vpn.example.com -H VPN -u user -P pass 2>&1 | Tee-Object debug.log
```

---

## Cross-Compilation

Build for any platform from any platform using Zig's cross-compilation:

### From macOS

```bash
# Build for Linux x64
zig build -Dtarget=x86_64-linux-gnu -Doptimize=ReleaseFast

# Build for Linux ARM64 (Raspberry Pi, AWS Graviton)
zig build -Dtarget=aarch64-linux-gnu -Doptimize=ReleaseFast

# Build for Windows x64
zig build -Dtarget=x86_64-windows-gnu -Doptimize=ReleaseFast
```

### From Linux

```bash
# Build for macOS Intel
zig build -Dtarget=x86_64-macos -Doptimize=ReleaseFast

# Build for macOS Apple Silicon
zig build -Dtarget=aarch64-macos -Doptimize=ReleaseFast

# Build for Windows x64
zig build -Dtarget=x86_64-windows-gnu -Doptimize=ReleaseFast
```

### From Windows

```powershell
# Build for Linux x64
zig build -Dtarget=x86_64-linux-gnu -Doptimize=ReleaseFast

# Build for macOS Intel
zig build -Dtarget=x86_64-macos -Doptimize=ReleaseFast

# Build for macOS ARM64
zig build -Dtarget=aarch64-macos -Doptimize=ReleaseFast
```

**Note**: Cross-compiled binaries must be tested on the target platform. Some platform-specific features may require native compilation.

---

## Common Command-Line Options

```bash
# Basic connection
vpnclient -s SERVER -H HUB -u USER -P PASSWORD

# Options:
-s, --server <HOST>     VPN server hostname (required)
-p, --port <PORT>       VPN server port (default: 443)
-H, --hub <HUB>         Virtual hub name (required)
-u, --user <USERNAME>   Username for authentication (required)
-P, --password <PASS>   Password for authentication (required)
-d, --daemon            Run as daemon (background)
-h, --help              Show help message
-v, --version           Show version information
```

---

## Configuration Files

For persistent configurations, you can create config files:

### Unix/Linux/macOS

Create `~/.vpnconfig` or `/etc/vpn/config`:

```ini
[connection]
server = vpn.example.com
port = 443
hub = VPN
username = myuser
password = mypassword
daemon = true
```

### Windows

Create `%USERPROFILE%\.vpnconfig`:

```ini
[connection]
server = vpn.example.com
port = 443
hub = VPN
username = myuser
password = mypassword
daemon = true
```

Then run: `vpnclient --config ~/.vpnconfig` (or `%USERPROFILE%\.vpnconfig` on Windows)

---

## Systemd Service (Linux)

Create `/etc/systemd/system/vpnclient.service`:

```ini
[Unit]
Description=SoftEther VPN Client
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/vpnclient -s vpn.example.com -H VPN -u myuser -P mypassword -d
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable vpnclient
sudo systemctl start vpnclient
sudo systemctl status vpnclient
```

---

## Launchd Service (macOS)

Create `/Library/LaunchDaemons/com.softether.vpnclient.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.softether.vpnclient</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/vpnclient</string>
        <string>-s</string>
        <string>vpn.example.com</string>
        <string>-H</string>
        <string>VPN</string>
        <string>-u</string>
        <string>myuser</string>
        <string>-P</string>
        <string>mypassword</string>
        <string>-d</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

Load and start:

```bash
sudo launchctl load /Library/LaunchDaemons/com.softether.vpnclient.plist
sudo launchctl start com.softether.vpnclient
```

---

## Windows Service

Create a Windows Service wrapper (requires additional code) or use Task Scheduler:

1. Open Task Scheduler
2. Create Basic Task
3. Trigger: At startup
4. Action: Start a program
5. Program: `C:\Windows\System32\vpnclient.exe`
6. Arguments: `-s vpn.example.com -H VPN -u myuser -P mypassword -d`
7. Run whether user is logged in or not
8. Run with highest privileges

---

## Getting Help

- **Documentation**: See [README.md](README.md), [CROSS_PLATFORM.md](CROSS_PLATFORM.md), [ARCHITECTURE.md](ARCHITECTURE.md)
- **Build Issues**: Check [CROSS_PLATFORM.md](CROSS_PLATFORM.md) troubleshooting section
- **SoftEther VPN**: https://www.softether.org/
- **Zig Language**: https://ziglang.org/

---

**Quick Reference Card**

| Platform | Build | Run | Check |
|----------|-------|-----|-------|
| macOS | `zig build -Doptimize=ReleaseFast` | `sudo vpnclient -s SERVER -H HUB -u USER -P PASS` | `ifconfig \| grep utun` |
| Linux | `zig build -Doptimize=ReleaseFast` | `sudo vpnclient -s SERVER -H HUB -u USER -P PASS` | `ip tuntap show` |
| Windows | `zig build -Doptimize=ReleaseFast` | `vpnclient.exe -s SERVER -H HUB -u USER -P PASS` | `Get-NetAdapter` |
