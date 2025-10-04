#!/bin/bash
# Build SoftEther VPN Client as XCFramework for iOS
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build_ios"
XCFRAMEWORK_DIR="$PROJECT_ROOT/xcframework"

echo "🔨 Building SoftEther VPN Client XCFramework for iOS..."
echo ""

# Clean previous builds
rm -rf "$BUILD_DIR"
rm -rf "$XCFRAMEWORK_DIR"
mkdir -p "$BUILD_DIR"
mkdir -p "$XCFRAMEWORK_DIR"

FRAMEWORK_PATHS=()

# Build for iOS Device (arm64)
echo "📱 Building for iOS arm64..."
cd "$PROJECT_ROOT"
zig build lib -Dtarget=aarch64-ios -Doptimize=ReleaseSafe

if [ ! -f "$PROJECT_ROOT/zig-out/lib/libSoftEtherClient.a" ]; then
    echo "❌ Failed to build iOS arm64 library"
    exit 1
fi

# Create iOS arm64 framework
TARGET_DIR="$BUILD_DIR/ios-arm64"
mkdir -p "$TARGET_DIR"
FRAMEWORK_NAME="SoftEtherClient.framework"
FRAMEWORK_PATH="$TARGET_DIR/$FRAMEWORK_NAME"
mkdir -p "$FRAMEWORK_PATH/Headers"
mkdir -p "$FRAMEWORK_PATH/Modules"

# Copy library
cp "$PROJECT_ROOT/zig-out/lib/libSoftEtherClient.a" "$FRAMEWORK_PATH/SoftEtherClient"

# Copy headers
cp "$PROJECT_ROOT/include/softether_ffi.h" "$FRAMEWORK_PATH/Headers/"

# Create module map
cat > "$FRAMEWORK_PATH/Modules/module.modulemap" << 'EOF'
framework module SoftEtherClient {
    umbrella header "softether_ffi.h"
    export *
    module * { export * }
}
EOF

# Create Info.plist for iOS
cat > "$FRAMEWORK_PATH/Info.plist" << 'EOF'
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

FRAMEWORK_PATHS+=("-framework" "$FRAMEWORK_PATH")

echo "✅ Built iOS arm64 framework"

# Build for iOS Simulator (arm64)
echo ""
echo "🖥️  Building for iOS Simulator arm64..."
cd "$PROJECT_ROOT"
zig build lib -Dtarget=aarch64-ios-simulator -Doptimize=ReleaseSafe

if [ ! -f "$PROJECT_ROOT/zig-out/lib/libSoftEtherClient.a" ]; then
    echo "❌ Failed to build iOS Simulator library"
    exit 1
fi

# Create iOS Simulator framework
TARGET_DIR="$BUILD_DIR/ios-arm64-simulator"
mkdir -p "$TARGET_DIR"
FRAMEWORK_PATH="$TARGET_DIR/$FRAMEWORK_NAME"
mkdir -p "$FRAMEWORK_PATH/Headers"
mkdir -p "$FRAMEWORK_PATH/Modules"

# Copy library
cp "$PROJECT_ROOT/zig-out/lib/libSoftEtherClient.a" "$FRAMEWORK_PATH/SoftEtherClient"

# Copy library
cp "$PROJECT_ROOT/zig-out/lib/libSoftEtherClient.a" "$FRAMEWORK_PATH/SoftEtherClient"

# Copy headers
cp "$PROJECT_ROOT/include/softether_ffi.h" "$FRAMEWORK_PATH/Headers/"

# Create module map
cat > "$FRAMEWORK_PATH/Modules/module.modulemap" << 'EOF'
framework module SoftEtherClient {
    umbrella header "softether_ffi.h"
    export *
    module * { export * }
}
EOF

# Create Info.plist for Simulator
cat > "$FRAMEWORK_PATH/Info.plist" << 'EOF'
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

FRAMEWORK_PATHS+=("-framework" "$FRAMEWORK_PATH")

echo "✅ Built iOS Simulator arm64 framework"

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
