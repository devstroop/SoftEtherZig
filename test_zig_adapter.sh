#!/bin/bash

# Quick test script for Zig adapter with debug output
# Usage: sudo ./test_zig_adapter.sh

set -e

echo "=========================================="
echo "Zig Adapter Debug Test"
echo "=========================================="
echo ""

echo "Building with Zig adapter..."
zig build -Duse-zig-adapter=true

echo ""
echo "Running VPN client (will stop after 10 seconds)..."
echo ""

timeout 10s sudo ./zig-out/bin/vpnclient \
  --server worxvpn.662.cloud \
  --port 443 \
  --hub VPN \
  --user devstroop \
  --password-hash "T2kl2mB84H5y2tn7n9qf65/8jXI=" \
  --log-level error \
  --ip-version ipv4 \
  --profile \
  2>&1 | tee zig_adapter_test.log || true

echo ""
echo "=========================================="
echo "Test complete. Check zig_adapter_test.log for details."
echo ""
echo "Looking for Zig adapter initialization messages..."
echo "=========================================="
grep -E "\[zig_adapter|ZigPacketAdapter\]" zig_adapter_test.log || echo "No Zig adapter messages found!"
