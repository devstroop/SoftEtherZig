# Quick Start — Platform Build Guide

Platform-specific build and run instructions. For overview, C API, and project structure, see [README.md](README.md).

## macOS

```bash
brew install zig openssl@3
zig build --release=fast
sudo ./zig-out/bin/vpnclient connect -s vpn.example.com -H VPN -u myuser -P mypassword
```

Check connection: `ifconfig | grep utun`

### Without sudo (privilege helper)

```bash
zig build utun-helper --release=fast
sudo chown root:wheel zig-out/bin/softether-utun-helper
sudo chmod u+s zig-out/bin/softether-utun-helper
./zig-out/bin/vpnclient connect -s vpn.example.com -H VPN -u myuser -P mypassword
```

### Shared library for Flutter/macOS

```bash
zig build shared-lib
# Output: zig-out/lib/libsoftether.dylib
# Copy to: softether_app/macos/Runner/Frameworks/ or link via Xcode
```

---

## iOS

OpenSSL is pre-built in `deps/openssl-ios/`.

```bash
zig build static-lib -Dtarget=aarch64-ios
# Output: zig-out/lib/libsoftether.a (22 FFI symbols)
```

Link into your Xcode project or Flutter iOS runner. The static lib includes OpenSSL statically.
The PacketTunnelProvider receives the utun fd from NetworkExtension; pass it via `softether_set_tunnel_fd()`.

To rebuild OpenSSL for iOS:
```bash
./scripts/build_openssl_ios.sh
```

---

## Android

OpenSSL is pre-built in `deps/openssl-android/`.

```bash
zig build shared-lib \
  -Dtarget=aarch64-linux-android \
  --libc android-libc-aarch64-linux-android.conf
# Output: zig-out/lib/libsoftether.so (~11MB debug, ~3MB release)
```

Place the .so for Flutter:
```bash
mkdir -p ../android/app/src/main/jniLibs/arm64-v8a
cp zig-out/lib/libsoftether.so ../android/app/src/main/jniLibs/arm64-v8a/
```

The `android-libc.conf` file points to NDK sysroot. Update paths if your NDK is at a different location.

The Android VpnService creates the TUN fd; pass it to the library via `softether_set_tunnel_fd()`.

---

## Linux

```bash
# Debian/Ubuntu
sudo apt install libssl-dev
zig build --release=fast
sudo ./zig-out/bin/vpnclient connect -s vpn.example.com -H VPN -u myuser -P mypassword

# Fedora/RHEL
sudo dnf install openssl-devel
zig build --release=fast
sudo ./zig-out/bin/vpnclient connect -s vpn.example.com -H VPN -u myuser -P mypassword
```

Check connection: `ip addr show | grep tun`

Grant capability instead of sudo:
```bash
sudo setcap cap_net_admin+ep zig-out/bin/vpnclient
./zig-out/bin/vpnclient ...
```

### Shared library for Flutter/Linux

```bash
zig build shared-lib
# Output: zig-out/lib/libsoftether.so
# Bundle in: softether_app/linux/runner/
```

---

## Windows (planned)

Requires TAP-Windows6 driver (from OpenVPN) and OpenSSL for Windows.

```powershell
zig build -Dtarget=x86_64-windows --release=fast
.\zig-out\bin\vpnclient.exe connect -s vpn.example.com -H VPN -u myuser -P mypassword
```

---

## Config File

Any platform, instead of CLI args:

```bash
sudo ./zig-out/bin/vpnclient connect --config config.json
```

See [config.minimal.json](config.minimal.json) and [config.example.json](config.example.json).
