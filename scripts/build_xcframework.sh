#!/bin/bash
# Build script for SoftEther VPN Zig library - iOS
#
# This builds the Zig library for iOS:
# - aarch64-apple-ios (device only)
# Note: Simulator builds skipped - Network Extension doesn't work on simulator
#
# Output is placed directly in the parent WorxVPN-iOS project:
# - ../Frameworks/SoftEtherVPN.xcframework
# - ../WorxVPNTunnel/softether_zig.h

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Project root is parent of SoftEtherZig submodule
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check for required tools
check_tools() {
    if ! command -v zig &> /dev/null; then
        log_error "zig not found. Install Zig: https://ziglang.org/download/"
        exit 1
    fi
    
    if ! command -v xcodebuild &> /dev/null; then
        log_error "xcodebuild not found. Install Xcode from the App Store"
        exit 1
    fi
    
    # Check Zig version
    ZIG_VERSION=$(zig version)
    log_info "Using Zig version: $ZIG_VERSION"
}

# Build for iOS
build_ios() {
    log_info "Building for iOS (device only)..."
    log_info "  Note: Simulator builds skipped - Network Extension not supported"
    
    # Device (arm64) - using the ios build step from build.zig
    log_info "  Building aarch64-apple-ios..."
    zig build ios
    
    # Alternative: use direct target specification
    # zig build -Dtarget=aarch64-ios -Doptimize=ReleaseFast
    
    # Verify output
    if [ ! -f "zig-out/lib/libsoftether_zig.a" ]; then
        log_error "Build failed - library not found"
        exit 1
    fi
    
    LIB_SIZE=$(ls -lh zig-out/lib/libsoftether_zig.a | awk '{print $5}')
    log_info "  Library built: zig-out/lib/libsoftether_zig.a ($LIB_SIZE)"
    
    # Create XCFramework output directory
    mkdir -p zig-out/ios
    
    # Copy library to intermediate location
    cp zig-out/lib/libsoftether_zig.a zig-out/ios/libsoftether_zig.a
    
    # Create XCFramework (device only)
    log_info "  Creating XCFramework..."
    rm -rf zig-out/ios/SoftEtherVPN.xcframework
    xcodebuild -create-xcframework \
        -library zig-out/ios/libsoftether_zig.a -headers include \
        -output zig-out/ios/SoftEtherVPN.xcframework
    
    log_info "iOS build complete: zig-out/ios/SoftEtherVPN.xcframework"
    
    # Install to WorxVPN-iOS project
    install_to_project
}

# Install to parent project
install_to_project() {
    log_info "Installing to WorxVPN-iOS project..."
    
    # Create Frameworks directory if needed
    mkdir -p "$PROJECT_ROOT/Frameworks"
    
    # Copy XCFramework
    rm -rf "$PROJECT_ROOT/Frameworks/SoftEtherVPN.xcframework"
    cp -R zig-out/ios/SoftEtherVPN.xcframework "$PROJECT_ROOT/Frameworks/"
    log_info "  Copied XCFramework to Frameworks/"
    
    # Copy header to extension
    if [ -d "$PROJECT_ROOT/WorxVPNTunnel" ]; then
        cp include/softether_zig.h "$PROJECT_ROOT/WorxVPNTunnel/"
        log_info "  Copied softether_zig.h to WorxVPNTunnel/"
    elif [ -d "$PROJECT_ROOT/WorxVPNExtension" ]; then
        cp include/softether_zig.h "$PROJECT_ROOT/WorxVPNExtension/"
        log_info "  Copied softether_zig.h to WorxVPNExtension/"
    else
        log_warn "  No extension directory found, header not copied"
    fi
    
    log_info "Installation complete!"
}

# Build optimized release
build_release() {
    log_info "Building optimized release for iOS..."
    
    # Use explicit target and optimization flags for maximum control
    zig build -Dtarget=aarch64-ios -Doptimize=ReleaseFast
    
    if [ ! -f "zig-out/lib/libsoftether_zig.a" ]; then
        log_error "Build failed - library not found"
        exit 1
    fi
    
    LIB_SIZE=$(ls -lh zig-out/lib/libsoftether_zig.a | awk '{print $5}')
    log_info "  Library built: zig-out/lib/libsoftether_zig.a ($LIB_SIZE)"
    
    # Continue with XCFramework creation
    mkdir -p zig-out/ios
    cp zig-out/lib/libsoftether_zig.a zig-out/ios/libsoftether_zig.a
    
    log_info "  Creating XCFramework..."
    rm -rf zig-out/ios/SoftEtherVPN.xcframework
    xcodebuild -create-xcframework \
        -library zig-out/ios/libsoftether_zig.a -headers include \
        -output zig-out/ios/SoftEtherVPN.xcframework
    
    log_info "iOS release build complete: zig-out/ios/SoftEtherVPN.xcframework"
    
    install_to_project
}

# Print usage
usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  build    Build for iOS device (default)"
    echo "  release  Build optimized release for iOS"
    echo "  install  Install last build to WorxVPN-iOS project"
    echo "  clean    Clean build artifacts"
    echo ""
    echo "With no command, builds for iOS device."
}

# Main
check_tools

case "${1:-build}" in
    build)
        build_ios
        ;;
    release)
        build_release
        ;;
    install)
        if [ ! -f "zig-out/ios/SoftEtherVPN.xcframework/Info.plist" ]; then
            log_error "No build found. Run '$0 build' first."
            exit 1
        fi
        install_to_project
        ;;
    clean)
        log_info "Cleaning build artifacts..."
        rm -rf zig-out
        rm -rf .zig-cache
        log_info "Clean complete"
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        log_error "Unknown command: $1"
        usage
        exit 1
        ;;
esac
