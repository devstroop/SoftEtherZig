#!/bin/bash
set -e

# Build iOS Framework Script
# Automatically builds SoftEtherClient.xcframework for iOS device and simulator
# Called from Xcode build phases

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build_ios"
OUTPUT_DIR="${SCRIPT_DIR}"

echo "🔨 Building SoftEther iOS Framework..."
echo "📁 Script dir: ${SCRIPT_DIR}"
echo "📁 Build dir: ${BUILD_DIR}"

# Clean previous builds
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/ios-arm64"
mkdir -p "${BUILD_DIR}/ios-arm64-simulator"

# Build for iOS Device (arm64)
echo "📱 Building for iOS Device (arm64)..."
cd "${SCRIPT_DIR}"
zig build -Dtarget=aarch64-ios -Drelease=true lib mobile-ffi

# Copy the build artifacts IMMEDIATELY (before simulator build can change the cache)
cp -v "${SCRIPT_DIR}/zig-out/lib/libSoftEtherClient.a" "${BUILD_DIR}/ios-arm64/libSoftEtherClient_base.a"
cp -v "${SCRIPT_DIR}/zig-out/lib/libsoftether_mobile.a" "${BUILD_DIR}/ios-arm64/"

# Find and copy the most recent OpenSSL libraries (they were just built)
echo "📦 Finding and copying OpenSSL libraries..."
DEVICE_SSL_LIB=$(find .zig-cache -name "libssl.a" -type f -print0 | xargs -0 ls -t | head -1)
DEVICE_CRYPTO_LIB=$(find .zig-cache -name "libcrypto.a" -type f -print0 | xargs -0 ls -t | head -1)

if [ -z "$DEVICE_SSL_LIB" ] || [ -z "$DEVICE_CRYPTO_LIB" ]; then
    echo "❌ Error: Could not find OpenSSL libraries in cache"
    exit 1
fi

echo "Found SSL: ${DEVICE_SSL_LIB}"
echo "Found Crypto: ${DEVICE_CRYPTO_LIB}"

cp "${DEVICE_SSL_LIB}" "${BUILD_DIR}/ios-arm64/libssl.a"
cp "${DEVICE_CRYPTO_LIB}" "${BUILD_DIR}/ios-arm64/libcrypto.a"

# Build for iOS Simulator (arm64)
echo "📱 Building for iOS Simulator (arm64)..."

# Force Zig to rebuild OpenSSL for simulator by cleaning OpenSSL cache
echo "🧹 Cleaning OpenSSL cache to force rebuild..."
find .zig-cache -name "libssl.a" -delete
find .zig-cache -name "libcrypto.a" -delete

zig build -Dtarget=aarch64-ios-simulator -Drelease=true lib mobile-ffi

# Copy the build artifacts IMMEDIATELY
cp -v "${SCRIPT_DIR}/zig-out/lib/libSoftEtherClient.a" "${BUILD_DIR}/ios-arm64-simulator/libSoftEtherClient_base.a"
cp -v "${SCRIPT_DIR}/zig-out/lib/libsoftether_mobile.a" "${BUILD_DIR}/ios-arm64-simulator/"

# Find and copy the most recent OpenSSL libraries (they were just built)
echo "📦 Finding and copying OpenSSL libraries..."
SIMULATOR_SSL_LIB=$(find .zig-cache -name "libssl.a" -type f -print0 | xargs -0 ls -t | head -1)
SIMULATOR_CRYPTO_LIB=$(find .zig-cache -name "libcrypto.a" -type f -print0 | xargs -0 ls -t | head -1)

if [ -z "$SIMULATOR_SSL_LIB" ] || [ -z "$SIMULATOR_CRYPTO_LIB" ]; then
    echo "❌ Error: Could not find OpenSSL libraries in cache"
    exit 1
fi

echo "Found SSL: ${SIMULATOR_SSL_LIB}"
echo "Found Crypto: ${SIMULATOR_CRYPTO_LIB}"

cp "${SIMULATOR_SSL_LIB}" "${BUILD_DIR}/ios-arm64-simulator/libssl.a"
cp "${SIMULATOR_CRYPTO_LIB}" "${BUILD_DIR}/ios-arm64-simulator/libcrypto.a"

# Now combine the libraries for both architectures
echo "🔨 Combining device libraries..."
libtool -static -o "${BUILD_DIR}/ios-arm64/libSoftEtherClient.a" \
    "${BUILD_DIR}/ios-arm64/libSoftEtherClient_base.a" \
    "${BUILD_DIR}/ios-arm64/libssl.a" \
    "${BUILD_DIR}/ios-arm64/libcrypto.a"
echo "✅ Device library created: $(ls -lh ${BUILD_DIR}/ios-arm64/libSoftEtherClient.a | awk '{print $5}')"

echo "🔨 Combining simulator libraries..."
libtool -static -o "${BUILD_DIR}/ios-arm64-simulator/libSoftEtherClient.a" \
    "${BUILD_DIR}/ios-arm64-simulator/libSoftEtherClient_base.a" \
    "${BUILD_DIR}/ios-arm64-simulator/libssl.a" \
    "${BUILD_DIR}/ios-arm64-simulator/libcrypto.a"
echo "✅ Simulator library created: $(ls -lh ${BUILD_DIR}/ios-arm64-simulator/libSoftEtherClient.a | awk '{print $5}')"

# Clean up intermediate files
rm -f "${BUILD_DIR}/ios-arm64/libSoftEtherClient_base.a" "${BUILD_DIR}/ios-arm64/libssl.a" "${BUILD_DIR}/ios-arm64/libcrypto.a"
rm -f "${BUILD_DIR}/ios-arm64-simulator/libSoftEtherClient_base.a" "${BUILD_DIR}/ios-arm64-simulator/libssl.a" "${BUILD_DIR}/ios-arm64-simulator/libcrypto.a"

# Create XCFramework
echo "📦 Creating XCFramework..."
rm -rf "${OUTPUT_DIR}/SoftEtherClient.xcframework"
xcodebuild -create-xcframework \
  -library "${BUILD_DIR}/ios-arm64/libSoftEtherClient.a" \
  -headers "${SCRIPT_DIR}/include" \
  -library "${BUILD_DIR}/ios-arm64-simulator/libSoftEtherClient.a" \
  -headers "${SCRIPT_DIR}/include" \
  -output "${OUTPUT_DIR}/SoftEtherClient.xcframework"

echo "✅ SoftEtherClient.xcframework built successfully!"
ls -lah "${OUTPUT_DIR}/SoftEtherClient.xcframework/"
