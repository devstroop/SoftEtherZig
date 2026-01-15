#!/bin/bash
# SoftEtherC iOS Build Script
# Builds the original SoftEtherVPN C library for iOS using Clang
#
# Usage:
#   ./build-ios-clang.sh           # Build for arm64 iOS device
#   ./build-ios-clang.sh simulator # Build for arm64 iOS simulator

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Target configuration
if [ "$1" = "simulator" ]; then
    TARGET="arm64-apple-ios15.0-simulator"
    SDK="iphonesimulator"
    OUTPUT_DIR="$PROJECT_ROOT/build/ios-simulator"
else
    TARGET="arm64-apple-ios15.0"
    SDK="iphoneos"
    OUTPUT_DIR="$PROJECT_ROOT/build/ios-device"
fi

SDK_PATH=$(xcrun --sdk $SDK --show-sdk-path)
CLANG=$(xcrun --sdk $SDK --find clang)

echo "================================================"
echo "SoftEtherC iOS Build (Clang)"
echo "================================================"
echo "Target: $TARGET"
echo "SDK: $SDK_PATH"
echo "Output: $OUTPUT_DIR"
echo ""

mkdir -p "$OUTPUT_DIR/obj"

# Common C flags
CFLAGS=(
    -target $TARGET
    -isysroot "$SDK_PATH"
    -std=c99
    -O2
    -fPIC
    -D_REENTRANT
    -D_THREAD_SAFE
    -DCPU_64
    -D_FILE_OFFSET_BITS=64
    -DVPN_SPEED
    -DUNIX
    -DUNIX_MACOS
    -DUNIX_IOS
    -DBUILDING_FOR_IOS=1
    -D__bool_true_false_are_defined=1
    -Wno-deprecated-declarations
    -Wno-unused-parameter
    -Wno-unused-variable
    -Wno-sign-compare
    -Wno-incompatible-function-pointer-types
    -Wno-int-conversion
    -Wno-incompatible-pointer-types-discards-qualifiers
    -Wno-implicit-function-declaration
    -Wno-strict-prototypes
    -fno-strict-aliasing
    -fsigned-char
    -I"$PROJECT_ROOT/include"
    -I"$PROJECT_ROOT/src"
    -I"$PROJECT_ROOT/src/bridge"
    -I"$PROJECT_ROOT/SoftEtherVPN/src"
    -I"$PROJECT_ROOT/SoftEtherVPN/src/Mayaqua"
    -I"$PROJECT_ROOT/SoftEtherVPN/src/Cedar"
)

# Source files to compile
SOURCES=(
    # Bridge layer
    "src/bridge/softether_bridge.c"
    "src/bridge/unix_bridge.c"
    "src/bridge/tick64_macos.c"
    "src/bridge/logging.c"
    "src/bridge/security_utils.c"
    "src/bridge/client_bridge.c"
    "src/bridge/zig_bridge.c"
    "src/bridge/zig_packet_adapter.c"
    "src/bridge/ios_stubs.c"
    
    # Mayaqua (modified for iOS)
    "src/bridge/Mayaqua/Mayaqua.c"
    "src/bridge/Mayaqua/Memory.c"
    "src/bridge/Mayaqua/Object.c"
    "src/bridge/Mayaqua/Kernel.c"
    "SoftEtherVPN/src/Mayaqua/Str.c"
    "SoftEtherVPN/src/Mayaqua/OS.c"
    "SoftEtherVPN/src/Mayaqua/FileIO.c"
    "SoftEtherVPN/src/Mayaqua/Network.c"
    "SoftEtherVPN/src/Mayaqua/TcpIp.c"
    "SoftEtherVPN/src/Mayaqua/Encrypt.c"
    "SoftEtherVPN/src/Mayaqua/Secure.c"
    "SoftEtherVPN/src/Mayaqua/Pack.c"
    "SoftEtherVPN/src/Mayaqua/Cfg.c"
    "SoftEtherVPN/src/Mayaqua/Table.c"
    "SoftEtherVPN/src/Mayaqua/Tracking.c"
    "SoftEtherVPN/src/Mayaqua/Microsoft.c"
    "SoftEtherVPN/src/Mayaqua/Internat.c"
    
    # Cedar (modified for iOS)
    "SoftEtherVPN/src/Cedar/Cedar.c"
    "src/bridge/Cedar/Client.c"
    "src/bridge/Cedar/Protocol.c"
    "src/bridge/Cedar/Session.c"
    "SoftEtherVPN/src/Cedar/Connection.c"
    "SoftEtherVPN/src/Cedar/Account.c"
    "SoftEtherVPN/src/Cedar/Admin.c"
    "SoftEtherVPN/src/Cedar/Command.c"
    "SoftEtherVPN/src/Cedar/Hub.c"
    "SoftEtherVPN/src/Cedar/Listener.c"
    "SoftEtherVPN/src/Cedar/Logging.c"
    "SoftEtherVPN/src/Cedar/Sam.c"
    "SoftEtherVPN/src/Cedar/Server.c"
    "SoftEtherVPN/src/Cedar/Virtual.c"
    "SoftEtherVPN/src/Cedar/Link.c"
    "SoftEtherVPN/src/Cedar/SecureNAT.c"
    "SoftEtherVPN/src/Cedar/NullLan.c"
    "SoftEtherVPN/src/Cedar/Bridge.c"
    "SoftEtherVPN/src/Cedar/BridgeUnix.c"
    "SoftEtherVPN/src/Cedar/Nat.c"
    "SoftEtherVPN/src/Cedar/UdpAccel.c"
    "SoftEtherVPN/src/Cedar/Database.c"
    "SoftEtherVPN/src/Cedar/Remote.c"
    "SoftEtherVPN/src/Cedar/DDNS.c"
    "SoftEtherVPN/src/Cedar/AzureClient.c"
    "SoftEtherVPN/src/Cedar/AzureServer.c"
    "SoftEtherVPN/src/Cedar/Radius.c"
    "SoftEtherVPN/src/Cedar/Console.c"
    "SoftEtherVPN/src/Cedar/Layer3.c"
    "SoftEtherVPN/src/Cedar/Interop_OpenVPN.c"
    "SoftEtherVPN/src/Cedar/Interop_SSTP.c"
    "SoftEtherVPN/src/Cedar/IPsec.c"
    "SoftEtherVPN/src/Cedar/IPsec_IKE.c"
    "SoftEtherVPN/src/Cedar/IPsec_IkePacket.c"
    "SoftEtherVPN/src/Cedar/IPsec_L2TP.c"
    "SoftEtherVPN/src/Cedar/IPsec_PPP.c"
    "SoftEtherVPN/src/Cedar/IPsec_EtherIP.c"
    "SoftEtherVPN/src/Cedar/IPsec_IPC.c"
    "SoftEtherVPN/src/Cedar/EtherLog.c"
    "SoftEtherVPN/src/Cedar/WebUI.c"
    "SoftEtherVPN/src/Cedar/WaterMark.c"
)

# Compile each source file
OBJECTS=()
for src in "${SOURCES[@]}"; do
    if [ -f "$PROJECT_ROOT/$src" ]; then
        obj_name=$(basename "$src" .c).o
        obj_path="$OUTPUT_DIR/obj/$obj_name"
        
        echo "Compiling: $src"
        "$CLANG" "${CFLAGS[@]}" -c "$PROJECT_ROOT/$src" -o "$obj_path"
        OBJECTS+=("$obj_path")
    else
        echo "Warning: Source not found: $src"
    fi
done

# Create static library
echo ""
echo "Creating static library..."
ar rcs "$OUTPUT_DIR/libsoftether_c.a" "${OBJECTS[@]}"

# Copy headers
mkdir -p "$OUTPUT_DIR/include"
cp "$PROJECT_ROOT/include/softether_c.h" "$OUTPUT_DIR/include/"
cp "$PROJECT_ROOT/include/ffi.h" "$OUTPUT_DIR/include/"

echo ""
echo "================================================"
echo "Build complete!"
echo "================================================"
echo "Library: $OUTPUT_DIR/libsoftether_c.a"
echo "Headers: $OUTPUT_DIR/include/"
echo ""
echo "To use in Xcode:"
echo "  1. Add libsoftether_c.a to Link Binary with Libraries"
echo "  2. Add $OUTPUT_DIR/include to Header Search Paths"
echo "  3. Add C_BACKEND_ENABLED to Swift Active Compilation Conditions"
echo ""
