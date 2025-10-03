#!/bin/bash
# Download and integrate OpenSSL XCFramework for iOS
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRAMEWORK_DIR="$SCRIPT_DIR/../WorxVPN-iOS/Framework"
TEMP_DIR="/tmp/openssl-ios"

echo "📦 Downloading OpenSSL XCFramework for iOS..."
echo ""

# Clean temp directory
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

# Download pre-built OpenSSL for iOS from popular maintained repository
# Using krzyzanowskim/OpenSSL which provides XCFramework builds
echo "⬇️  Downloading OpenSSL 3.x for iOS from krzyzanowskim/OpenSSL..."

# Download the latest release (OpenSSL 3.x)
OPENSSL_VERSION="3.3.3001"
OPENSSL_URL="https://github.com/krzyzanowskim/OpenSSL/releases/download/${OPENSSL_VERSION}/OpenSSL.xcframework.zip"

curl -L -o OpenSSL.xcframework.zip "$OPENSSL_URL"

if [ ! -f "OpenSSL.xcframework.zip" ]; then
    echo "❌ Failed to download OpenSSL XCFramework"
    exit 1
fi

echo "✅ Downloaded OpenSSL XCFramework"

# Extract
echo ""
echo "📂 Extracting..."
unzip -q OpenSSL.xcframework.zip

if [ ! -d "OpenSSL.xcframework" ]; then
    echo "❌ Failed to extract OpenSSL XCFramework"
    exit 1
fi

echo "✅ Extracted OpenSSL.xcframework"

# Copy to project
echo ""
echo "📋 Copying to WorxVPN-iOS project..."
mkdir -p "$FRAMEWORK_DIR"
rm -rf "$FRAMEWORK_DIR/OpenSSL.xcframework"
cp -R "OpenSSL.xcframework" "$FRAMEWORK_DIR/"

echo "✅ Copied to: $FRAMEWORK_DIR/OpenSSL.xcframework"

# Verify the framework
echo ""
echo "🔍 Verifying framework structure..."
ls -lh "$FRAMEWORK_DIR/OpenSSL.xcframework"

# Check architectures
echo ""
echo "📱 Checking architectures..."
if [ -d "$FRAMEWORK_DIR/OpenSSL.xcframework/ios-arm64" ]; then
    echo "  ✅ iOS arm64 found"
fi
if [ -d "$FRAMEWORK_DIR/OpenSSL.xcframework/ios-arm64_x86_64-simulator" ] || [ -d "$FRAMEWORK_DIR/OpenSSL.xcframework/ios-arm64-simulator" ]; then
    echo "  ✅ iOS Simulator found"
fi

# Clean up
rm -rf "$TEMP_DIR"

echo ""
echo "🎉 OpenSSL XCFramework installed successfully!"
echo ""
echo "📝 Next steps:"
echo "  1. Run: cd ../WorxVPN-iOS && xcodegen generate"
echo "  2. The project.yml will be updated to include OpenSSL"
echo "  3. Rebuild the project in Xcode"
