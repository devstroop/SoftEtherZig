#!/bin/bash
# Cross-compile OpenSSL 3.6.0 for Android (arm64-v8a + armeabi-v7a)
# Requires: Android NDK 25+ (for the sysroot and clang toolchain)
#
# Usage:
#   ./scripts/build_openssl_android.sh [--arch arm64|armv7|all]
#
# Output:
#   deps/openssl-android/arm64-v8a/{lib,include}
#   deps/openssl-android/armeabi-v7a/{lib,include}
set -e

OPENSSL_VERSION="3.6.0"
DEPS_DIR="$(cd "$(dirname "$0")/.." && pwd)/deps"
BUILD_DIR="/tmp/openssl-android-build"
ANDROID_API=21

# Find NDK
if [[ -n "${ANDROID_NDK_ROOT:-}" ]]; then
    NDK_ROOT="$ANDROID_NDK_ROOT"
elif [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
    NDK_ROOT="$ANDROID_NDK_HOME"
else
    # Auto-detect from Android SDK
    SDK_ROOT="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
    NDK_ROOT="$(ls -d "$SDK_ROOT/ndk"/*/ 2>/dev/null | sort -V | tail -1)"
    NDK_ROOT="${NDK_ROOT%/}"
fi

if [[ ! -d "$NDK_ROOT/toolchains/llvm" ]]; then
    echo "ERROR: Android NDK not found. Set ANDROID_NDK_ROOT or install via:"
    echo "  sdkmanager --install 'ndk;25.1.8937393'"
    exit 1
fi
echo "Using NDK: $NDK_ROOT"

# Detect host platform for NDK prebuilt tools
case "$(uname -s)-$(uname -m)" in
    Darwin-arm64)  HOST_TAG="darwin-x86_64" ;;  # NDK uses x86_64 even on ARM Mac
    Darwin-x86_64) HOST_TAG="darwin-x86_64" ;;
    Linux-x86_64)  HOST_TAG="linux-x86_64" ;;
    *)             echo "ERROR: Unsupported host: $(uname -s)-$(uname -m)"; exit 1 ;;
esac

export ANDROID_NDK_ROOT="$NDK_ROOT"
TOOLCHAIN="$NDK_ROOT/toolchains/llvm/prebuilt/$HOST_TAG"
export PATH="$TOOLCHAIN/bin:$PATH"

# Parse arguments
ARCHES="all"
for arg in "$@"; do
    case $arg in
        --arch=*) ARCHES="${arg#*=}" ;;
        --arch)   shift; ARCHES="$1" ;;
    esac
done

if [[ "$ARCHES" == "all" ]]; then
    ARCHES="arm64 armv7"
fi

# Download OpenSSL source once
mkdir -p "$BUILD_DIR"
if [ ! -d "$BUILD_DIR/openssl-$OPENSSL_VERSION" ]; then
    echo "Downloading OpenSSL $OPENSSL_VERSION..."
    cd "$BUILD_DIR"
    curl -sL "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" | tar xz
fi

build_arch() {
    local ARCH="$1"
    local OPENSSL_TARGET=""
    local ABI_DIR=""

    case "$ARCH" in
        arm64)
            OPENSSL_TARGET="android-arm64"
            ABI_DIR="arm64-v8a"
            ;;
        armv7)
            OPENSSL_TARGET="android-arm"
            ABI_DIR="armeabi-v7a"
            ;;
        *)
            echo "ERROR: Unknown arch '$ARCH' (use arm64 or armv7)"
            exit 1
            ;;
    esac

    local INSTALL_DIR="$DEPS_DIR/openssl-android/$ABI_DIR"

    # Skip if already built
    if [ -f "$INSTALL_DIR/lib/libssl.a" ] && [ -f "$INSTALL_DIR/lib/libcrypto.a" ]; then
        echo "OpenSSL $ABI_DIR already built at $INSTALL_DIR"
        echo "  libssl.a: $(du -h "$INSTALL_DIR/lib/libssl.a" | cut -f1)"
        echo "  libcrypto.a: $(du -h "$INSTALL_DIR/lib/libcrypto.a" | cut -f1)"
        return 0
    fi

    echo ""
    echo "=== Building OpenSSL $OPENSSL_VERSION for Android $ABI_DIR ==="
    echo "  OpenSSL target: $OPENSSL_TARGET"
    echo "  API level: $ANDROID_API"
    echo ""

    # Work in a per-arch build directory
    local ARCH_BUILD_DIR="$BUILD_DIR/build-$ABI_DIR"
    rm -rf "$ARCH_BUILD_DIR"
    cp -R "$BUILD_DIR/openssl-$OPENSSL_VERSION" "$ARCH_BUILD_DIR"
    cd "$ARCH_BUILD_DIR"

    # Configure OpenSSL with NDK
    echo "Configuring..."
    ./Configure "$OPENSSL_TARGET" \
        -D__ANDROID_API__=$ANDROID_API \
        no-shared no-tests no-ui-console \
        --prefix="$INSTALL_DIR" \
        --openssldir="$INSTALL_DIR" \
        2>&1 | tail -3

    # Build libs only (skip apps to save time/space)
    echo "Building (this takes a few minutes)..."
    make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)" build_libs 2>&1 | tail -5

    # Install headers + libs
    echo "Installing..."
    mkdir -p "$INSTALL_DIR/lib" "$INSTALL_DIR/include"
    cp libssl.a libcrypto.a "$INSTALL_DIR/lib/"
    cp -R include/openssl "$INSTALL_DIR/include/"

    # Clean up build dir to save space
    rm -rf "$ARCH_BUILD_DIR"

    echo ""
    echo "=== OpenSSL $ABI_DIR build complete ==="
    echo "  libssl.a: $(du -h "$INSTALL_DIR/lib/libssl.a" | cut -f1)"
    echo "  libcrypto.a: $(du -h "$INSTALL_DIR/lib/libcrypto.a" | cut -f1)"
}

for arch in $ARCHES; do
    build_arch "$arch"
done

# Clean up source
rm -rf "$BUILD_DIR"

echo ""
echo "=== All Android OpenSSL builds complete ==="
ls -la "$DEPS_DIR/openssl-android"/*/lib/*.a 2>/dev/null || true
