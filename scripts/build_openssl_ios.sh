#!/bin/bash
# Cross-compile OpenSSL 3.6.0 for iOS arm64
# Prerequisites: Xcode with iOS SDK
set -e

OPENSSL_VERSION="3.6.0"
DEPS_DIR="$(cd "$(dirname "$0")/.." && pwd)/deps"
BUILD_DIR="/tmp/openssl-ios-build"
INSTALL_DIR="$DEPS_DIR/openssl-ios"

if [ -f "$INSTALL_DIR/lib/libssl.a" ] && [ -f "$INSTALL_DIR/lib/libcrypto.a" ]; then
    echo "OpenSSL iOS already built at $INSTALL_DIR"
    echo "  libssl.a: $(du -h "$INSTALL_DIR/lib/libssl.a" | cut -f1)"
    echo "  libcrypto.a: $(du -h "$INSTALL_DIR/lib/libcrypto.a" | cut -f1)"
    exit 0
fi

echo "=== Building OpenSSL $OPENSSL_VERSION for iOS arm64 ==="

# Download source
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
if [ ! -d "openssl-$OPENSSL_VERSION" ]; then
    echo "Downloading OpenSSL $OPENSSL_VERSION..."
    curl -sL "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" | tar xz
fi

cd "openssl-$OPENSSL_VERSION"

# Clean previous build
make clean 2>/dev/null || true

# Configure for iOS arm64
echo "Configuring for ios64-xcrun..."
./Configure ios64-xcrun \
    no-shared no-tests no-ui-console \
    --prefix="$INSTALL_DIR" \
    --openssldir="$INSTALL_DIR"

# Build
echo "Building (this takes a few minutes)..."
make -j"$(sysctl -n hw.ncpu)" 2>&1 | tail -5

# Install (headers + libs only)
echo "Installing..."
make install_sw

echo ""
echo "=== OpenSSL iOS build complete ==="
echo "  Install: $INSTALL_DIR"
echo "  libssl.a: $(du -h "$INSTALL_DIR/lib/libssl.a" | cut -f1)"
echo "  libcrypto.a: $(du -h "$INSTALL_DIR/lib/libcrypto.a" | cut -f1)"
