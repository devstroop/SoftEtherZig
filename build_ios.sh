#!/bin/bash
# iOS Cross-Compilation Build Script
# This script sets up the proper environment for building with OpenSSL-Zig on iOS

set -e  # Exit on error

# Detect iOS SDK paths
IOS_DEVICE_SDK=$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
IOS_SIMULATOR_SDK=$(xcrun --sdk iphonesimulator --show-sdk-path 2>/dev/null)

if [ -z "$IOS_DEVICE_SDK" ] || [ -z "$IOS_SIMULATOR_SDK" ]; then
    echo "❌ Error: Could not find iOS SDKs. Is Xcode installed?"
    echo "Run: xcode-select --install"
    exit 1
fi

echo "📱 iOS SDKs found:"
echo "   Device: $IOS_DEVICE_SDK"
echo "   Simulator: $IOS_SIMULATOR_SDK"
echo ""

# Function to build for a specific target
build_target() {
    local TARGET=$1
    local SDK_PATH=$2
    local OUTPUT_NAME=$3
    
    echo "🔨 Building for $TARGET..."
    echo "   SDK: $SDK_PATH"
    
    # Set C compiler flags to include iOS SDK paths
    export CFLAGS="-isysroot $SDK_PATH -I$SDK_PATH/usr/include"
    export CXXFLAGS="-isysroot $SDK_PATH -I$SDK_PATH/usr/include"
    
    # Build with Zig
    zig build \
        -Dtarget="$TARGET" \
        -Drelease=true \
        --sysroot "$SDK_PATH" \
        2>&1 | tee "build_${OUTPUT_NAME}.log"
    
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        echo "✅ Build successful for $TARGET"
        
        # Copy artifacts with descriptive names
        if [ -f "zig-out/lib/libsoftether_mobile.a" ]; then
            cp "zig-out/lib/libsoftether_mobile.a" "zig-out/lib/libsoftether_mobile_${OUTPUT_NAME}.a"
            echo "   Saved: zig-out/lib/libsoftether_mobile_${OUTPUT_NAME}.a"
        fi
    else
        echo "❌ Build failed for $TARGET"
        echo "   See build_${OUTPUT_NAME}.log for details"
        return 1
    fi
}

# Build for iOS device (ARM64)
echo "========================"
echo "Building iOS Device Framework"
echo "========================"
build_target "aarch64-ios" "$IOS_DEVICE_SDK" "ios-arm64"

echo ""
echo "========================"
echo "Building iOS Simulator Framework (ARM64)"
echo "========================"
build_target "aarch64-ios-simulator" "$IOS_SIMULATOR_SDK" "ios-sim-arm64"

echo ""
echo "========================"
echo "Building iOS Simulator Framework (x86_64)"
echo "========================"
build_target "x86_64-ios-simulator" "$IOS_SIMULATOR_SDK" "ios-sim-x86_64"

echo ""
echo "✅ All builds complete!"
echo ""
echo "Next steps:"
echo "1. Create XCFramework:"
echo "   xcodebuild -create-xcframework \\"
echo "     -library zig-out/lib/libsoftether_mobile_ios-arm64.a \\"
echo "     -library zig-out/lib/libsoftether_mobile_ios-sim-arm64.a \\"
echo "     -library zig-out/lib/libsoftether_mobile_ios-sim-x86_64.a \\"
echo "     -output SoftEtherClient.xcframework"
echo ""
echo "2. Add to WorxVPN:"
echo "   cp -r SoftEtherClient.xcframework ../Frameworks/"
echo "   Open WorxVPN.xcworkspace and link the framework"
