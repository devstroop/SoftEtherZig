#!/bin/bash
# Build SoftEther VPN Client as XCFramework for iOS using Xcode
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
BUILD_DIR="$PROJECT_ROOT/build_ios"
XCFRAMEWORK_DIR="$PROJECT_ROOT/xcframework"

echo "🔨 Building SoftEther VPN Client XCFramework for iOS using Xcode..."
echo ""

# Clean previous builds
rm -rf "$BUILD_DIR"
rm -rf "$XCFRAMEWORK_DIR"
mkdir -p "$BUILD_DIR"
mkdir -p "$XCFRAMEWORK_DIR"

# Collect all C source files
C_SOURCES=(
    "src/bridge/softether_bridge.c"
    "src/bridge/unix_bridge.c"
    "src/bridge/tick64_macos.c"
    # NOTE: packet_adapter_macos.c is NOT included for iOS builds
    # iOS uses NEPacketTunnelProvider instead of utun directly
    "src/bridge/packet_adapter_ios_stub.c"
    "src/bridge/ios_stubs.c"
    "src/bridge/Mayaqua/Mayaqua.c"
    "src/bridge/Mayaqua/Memory.c"
    "SoftEtherVPN_Stable/src/Mayaqua/Str.c"
    "src/bridge/Mayaqua/Object.c"
    "SoftEtherVPN_Stable/src/Mayaqua/OS.c"
    "SoftEtherVPN_Stable/src/Mayaqua/FileIO.c"
    "src/bridge/Mayaqua/Kernel.c"
    "SoftEtherVPN_Stable/src/Mayaqua/Network.c"
    "SoftEtherVPN_Stable/src/Mayaqua/TcpIp.c"
    "SoftEtherVPN_Stable/src/Mayaqua/Encrypt.c"
    "SoftEtherVPN_Stable/src/Mayaqua/Secure.c"
    "SoftEtherVPN_Stable/src/Mayaqua/Pack.c"
    "SoftEtherVPN_Stable/src/Mayaqua/Cfg.c"
    "SoftEtherVPN_Stable/src/Mayaqua/Table.c"
    "SoftEtherVPN_Stable/src/Mayaqua/Tracking.c"
    "SoftEtherVPN_Stable/src/Mayaqua/Microsoft.c"
    "SoftEtherVPN_Stable/src/Mayaqua/Internat.c"
    "SoftEtherVPN_Stable/src/Cedar/Cedar.c"
    "src/bridge/Cedar/Client.c"
    "src/bridge/Cedar/Protocol.c"
    "SoftEtherVPN_Stable/src/Cedar/Connection.c"
    "src/bridge/Cedar/Session.c"
    "SoftEtherVPN_Stable/src/Cedar/Account.c"
    "SoftEtherVPN_Stable/src/Cedar/Admin.c"
    "SoftEtherVPN_Stable/src/Cedar/Command.c"
    "SoftEtherVPN_Stable/src/Cedar/Hub.c"
    "SoftEtherVPN_Stable/src/Cedar/Listener.c"
    "SoftEtherVPN_Stable/src/Cedar/Logging.c"
    "SoftEtherVPN_Stable/src/Cedar/Sam.c"
    "SoftEtherVPN_Stable/src/Cedar/Server.c"
    "SoftEtherVPN_Stable/src/Cedar/Virtual.c"
    "SoftEtherVPN_Stable/src/Cedar/Link.c"
    "SoftEtherVPN_Stable/src/Cedar/SecureNAT.c"
    "SoftEtherVPN_Stable/src/Cedar/NullLan.c"
    "SoftEtherVPN_Stable/src/Cedar/Bridge.c"
    "SoftEtherVPN_Stable/src/Cedar/BridgeUnix.c"
    "SoftEtherVPN_Stable/src/Cedar/Nat.c"
    "SoftEtherVPN_Stable/src/Cedar/UdpAccel.c"
    "SoftEtherVPN_Stable/src/Cedar/Database.c"
    "SoftEtherVPN_Stable/src/Cedar/Remote.c"
    "SoftEtherVPN_Stable/src/Cedar/DDNS.c"
    "SoftEtherVPN_Stable/src/Cedar/AzureClient.c"
    "SoftEtherVPN_Stable/src/Cedar/AzureServer.c"
    "SoftEtherVPN_Stable/src/Cedar/Radius.c"
    "SoftEtherVPN_Stable/src/Cedar/Console.c"
    "SoftEtherVPN_Stable/src/Cedar/Layer3.c"
    "SoftEtherVPN_Stable/src/Cedar/Interop_OpenVPN.c"
    "SoftEtherVPN_Stable/src/Cedar/Interop_SSTP.c"
    "SoftEtherVPN_Stable/src/Cedar/IPsec.c"
    "SoftEtherVPN_Stable/src/Cedar/IPsec_IKE.c"
    "SoftEtherVPN_Stable/src/Cedar/IPsec_IkePacket.c"
    "SoftEtherVPN_Stable/src/Cedar/IPsec_L2TP.c"
    "SoftEtherVPN_Stable/src/Cedar/IPsec_PPP.c"
    "SoftEtherVPN_Stable/src/Cedar/IPsec_EtherIP.c"
    "SoftEtherVPN_Stable/src/Cedar/IPsec_IPC.c"
    "SoftEtherVPN_Stable/src/Cedar/EtherLog.c"
    "SoftEtherVPN_Stable/src/Cedar/WebUI.c"
    "SoftEtherVPN_Stable/src/Cedar/WaterMark.c"
    "SoftEtherVPN_Stable/src/Cedar/NativeStack.c"
    "src/bridge/ios_ffi.c"
)

# Convert to absolute paths
C_SOURCE_FILES=()
for src in "${C_SOURCES[@]}"; do
    C_SOURCE_FILES+=("$PROJECT_ROOT/$src")
done

# Common compiler flags
CFLAGS=(
    "-std=c99"
    "-D_REENTRANT"
    "-D_THREAD_SAFE"
    "-DCPU_64"
    "-D_FILE_OFFSET_BITS=64"
    "-DVPN_SPEED"
    "-D__bool_true_false_are_defined=1"
    "-DUNIX"
    "-DUNIX_MACOS"
    "-DBUILDING_FOR_IOS=1"
    "-Wno-deprecated-declarations"
    "-Wno-unused-parameter"
    "-Wno-unused-variable"
    "-Wno-sign-compare"
    "-Wno-incompatible-function-pointer-types"
    "-Wno-int-conversion"
    "-Wno-incompatible-pointer-types-discards-qualifiers"
    "-Wno-implicit-function-declaration"
    "-Wno-strict-prototypes"
    "-fno-strict-aliasing"
    "-fsigned-char"
    "-I$PROJECT_ROOT/src"
    "-I$PROJECT_ROOT/src/bridge"
    "-I$PROJECT_ROOT/include"
    "-I$PROJECT_ROOT/SoftEtherVPN_Stable/src"
    "-I$PROJECT_ROOT/SoftEtherVPN_Stable/src/Mayaqua"
    "-I$PROJECT_ROOT/SoftEtherVPN_Stable/src/Cedar"
    "-I/opt/homebrew/opt/openssl@3/include"
)

FRAMEWORK_PATHS=()

# Build for iOS Device (arm64)
echo "📱 Building for iOS arm64..."
IOS_DEVICE_DIR="$BUILD_DIR/ios-arm64"
mkdir -p "$IOS_DEVICE_DIR"

xcrun --sdk iphoneos clang \
    -arch arm64 \
    -target arm64-apple-ios14.0 \
    -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
    "${CFLAGS[@]}" \
    -c "${C_SOURCE_FILES[@]}" \
    -fembed-bitcode

# Collect object files and create static library
OBJ_FILES=(*.o)
xcrun --sdk iphoneos ar rcs "$IOS_DEVICE_DIR/libSoftEtherClient.a" "${OBJ_FILES[@]}"
rm -f *.o

echo "✅ Built iOS arm64 library ($(du -h "$IOS_DEVICE_DIR/libSoftEtherClient.a" | cut -f1))"

# Create framework structure for iOS Device
FRAMEWORK_PATH_DEVICE="$IOS_DEVICE_DIR/SoftEtherClient.framework"
mkdir -p "$FRAMEWORK_PATH_DEVICE/Headers"
mkdir -p "$FRAMEWORK_PATH_DEVICE/Modules"

cp "$IOS_DEVICE_DIR/libSoftEtherClient.a" "$FRAMEWORK_PATH_DEVICE/SoftEtherClient"
cp "$PROJECT_ROOT/include/softether_ffi.h" "$FRAMEWORK_PATH_DEVICE/Headers/"

# Create module map
cat > "$FRAMEWORK_PATH_DEVICE/Modules/module.modulemap" << 'EOF'
framework module SoftEtherClient {
    umbrella header "softether_ffi.h"
    export *
    module * { export * }
}
EOF

# Create Info.plist for iOS Device
cat > "$FRAMEWORK_PATH_DEVICE/Info.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>SoftEtherClient</string>
    <key>CFBundleIdentifier</key>
    <string>com.worxvpn.SoftEtherClient</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>SoftEtherClient</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>CFBundleSupportedPlatforms</key>
    <array>
        <string>iPhoneOS</string>
    </array>
    <key>MinimumOSVersion</key>
    <string>14.0</string>
</dict>
</plist>
EOF

FRAMEWORK_PATHS+=("-framework" "$FRAMEWORK_PATH_DEVICE")

# Build for iOS Simulator (arm64)
echo ""
echo "🖥️  Building for iOS Simulator arm64..."
IOS_SIM_ARM64_DIR="$BUILD_DIR/ios-arm64-simulator-temp"
mkdir -p "$IOS_SIM_ARM64_DIR"

xcrun --sdk iphonesimulator clang \
    -arch arm64 \
    -target arm64-apple-ios14.0-simulator \
    -isysroot $(xcrun --sdk iphonesimulator --show-sdk-path) \
    "${CFLAGS[@]}" \
    -c "${C_SOURCE_FILES[@]}"

# Collect object files and create static library
OBJ_FILES=(*.o)
xcrun --sdk iphonesimulator ar rcs "$IOS_SIM_ARM64_DIR/libSoftEtherClient-arm64.a" "${OBJ_FILES[@]}"
rm -f *.o

echo "✅ Built iOS Simulator arm64 library ($(du -h "$IOS_SIM_ARM64_DIR/libSoftEtherClient-arm64.a" | cut -f1))"

# Build for iOS Simulator (x86_64)
echo ""
echo "🖥️  Building for iOS Simulator x86_64..."
IOS_SIM_X86_DIR="$BUILD_DIR/ios-x86_64-simulator-temp"
mkdir -p "$IOS_SIM_X86_DIR"

xcrun --sdk iphonesimulator clang \
    -arch x86_64 \
    -target x86_64-apple-ios14.0-simulator \
    -isysroot $(xcrun --sdk iphonesimulator --show-sdk-path) \
    "${CFLAGS[@]}" \
    -c "${C_SOURCE_FILES[@]}"

# Collect object files and create static library
OBJ_FILES=(*.o)
xcrun --sdk iphonesimulator ar rcs "$IOS_SIM_X86_DIR/libSoftEtherClient-x86_64.a" "${OBJ_FILES[@]}"
rm -f *.o

echo "✅ Built iOS Simulator x86_64 library ($(du -h "$IOS_SIM_X86_DIR/libSoftEtherClient-x86_64.a" | cut -f1))"

# Create universal simulator binary
echo ""
echo "🔗 Creating universal simulator binary..."
IOS_SIM_DIR="$BUILD_DIR/ios-arm64-simulator"
mkdir -p "$IOS_SIM_DIR"

xcrun lipo -create \
    "$IOS_SIM_ARM64_DIR/libSoftEtherClient-arm64.a" \
    "$IOS_SIM_X86_DIR/libSoftEtherClient-x86_64.a" \
    -output "$IOS_SIM_DIR/libSoftEtherClient.a"

echo "✅ Created universal simulator library ($(du -h "$IOS_SIM_DIR/libSoftEtherClient.a" | cut -f1))"

# Create framework structure for iOS Simulator
FRAMEWORK_PATH_SIM="$IOS_SIM_DIR/SoftEtherClient.framework"
mkdir -p "$FRAMEWORK_PATH_SIM/Headers"
mkdir -p "$FRAMEWORK_PATH_SIM/Modules"

cp "$IOS_SIM_DIR/libSoftEtherClient.a" "$FRAMEWORK_PATH_SIM/SoftEtherClient"
cp "$PROJECT_ROOT/include/softether_ffi.h" "$FRAMEWORK_PATH_SIM/Headers/"

# Create module map
cat > "$FRAMEWORK_PATH_SIM/Modules/module.modulemap" << 'EOF'
framework module SoftEtherClient {
    umbrella header "softether_ffi.h"
    export *
    module * { export * }
}
EOF

# Create Info.plist for iOS Simulator
cat > "$FRAMEWORK_PATH_SIM/Info.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>SoftEtherClient</string>
    <key>CFBundleIdentifier</key>
    <string>com.worxvpn.SoftEtherClient</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>SoftEtherClient</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>CFBundleSupportedPlatforms</key>
    <array>
        <string>iPhoneSimulator</string>
    </array>
    <key>MinimumOSVersion</key>
    <string>14.0</string>
</dict>
</plist>
EOF

FRAMEWORK_PATHS+=("-framework" "$FRAMEWORK_PATH_SIM")

# Create XCFramework
echo ""
echo "📦 Creating XCFramework..."

xcodebuild -create-xcframework \
    "${FRAMEWORK_PATHS[@]}" \
    -output "$XCFRAMEWORK_DIR/SoftEtherClient.xcframework"

echo ""
echo "✅ XCFramework created at: $XCFRAMEWORK_DIR/SoftEtherClient.xcframework"

# Copy to WorxVPN-iOS project
if [ -d "$PROJECT_ROOT/../WorxVPN-iOS/Framework" ]; then
    echo ""
    echo "📋 Copying to WorxVPN-iOS project..."
    rm -rf "$PROJECT_ROOT/../WorxVPN-iOS/Framework/SoftEtherClient.xcframework"
    mkdir -p "$PROJECT_ROOT/../WorxVPN-iOS/Framework"
    cp -R "$XCFRAMEWORK_DIR/SoftEtherClient.xcframework" "$PROJECT_ROOT/../WorxVPN-iOS/Framework/"
    echo "✅ Copied to WorxVPN-iOS/Framework/"
fi

echo ""
echo "🎉 Build complete!"
