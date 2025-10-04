#!/bin/bash

# Benchmark script to compare C vs Zig packet adapters
# Usage: ./benchmark_adapters.sh <server> <port> <hub> <user> <password>

set -e

SERVER="${1:-vpn.worxsolutions.net}"
PORT="${2:-443}"
HUB="${3:-SSTP}"
USER="${4:-itsalfredakku}"
PASSWORD="${5}"

if [ -z "$PASSWORD" ]; then
    echo "Error: Password required"
    echo "Usage: $0 <server> <port> <hub> <user> <password>"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="benchmark_results/adapter_comparison_${TIMESTAMP}"
mkdir -p "$RESULTS_DIR"

echo "=========================================="
echo "SoftEther VPN Adapter Benchmark"
echo "=========================================="
echo "Server:    $SERVER:$PORT"
echo "Hub:       $HUB"
echo "User:      $USER"
echo "Results:   $RESULTS_DIR"
echo ""

# Test 1: C Adapter (baseline)
echo "=========================================="
echo "Test 1: C Packet Adapter (baseline)"
echo "=========================================="
echo "Building with C adapter..."
zig build 2>&1 | grep -E "(Building|error)" || true

echo ""
echo "Running VPN client with C adapter for 60 seconds..."
timeout 60s zig-out/bin/vpnclient \
    -s "$SERVER" \
    -p "$PORT" \
    -H "$HUB" \
    -u "$USER" \
    -P "$PASSWORD" \
    --profile \
    2>&1 | tee "$RESULTS_DIR/c_adapter.log" || true

echo ""
echo "C adapter test complete. Results saved to $RESULTS_DIR/c_adapter.log"
sleep 5

# Test 2: Zig Adapter
echo ""
echo "=========================================="
echo "Test 2: Zig Packet Adapter"
echo "=========================================="
echo "Building with Zig adapter..."
zig build -Duse-zig-adapter=true 2>&1 | grep -E "(Building|error|Zig)" || true

echo ""
echo "Running VPN client with Zig adapter for 60 seconds..."
timeout 60s zig-out/bin/vpnclient \
    -s "$SERVER" \
    -p "$PORT" \
    -H "$HUB" \
    -u "$USER" \
    -P "$PASSWORD" \
    --profile \
    2>&1 | tee "$RESULTS_DIR/zig_adapter.log" || true

echo ""
echo "Zig adapter test complete. Results saved to $RESULTS_DIR/zig_adapter.log"

# Generate comparison report
echo ""
echo "=========================================="
echo "Generating comparison report..."
echo "=========================================="

cat > "$RESULTS_DIR/COMPARISON.md" << EOF
# Packet Adapter Comparison Report

**Test Date:** $(date)
**Server:** $SERVER:$PORT
**Hub:** $HUB
**Duration:** 60 seconds each

## Test Configuration
- **C Adapter:** Traditional single-packet polling
- **Zig Adapter:** Batch processing with lock-free ring buffers
  - RX Queue: 8192 packets
  - TX Queue: 4096 packets
  - Batch Size: 32 packets
  - Memory Pool: Pre-allocated packet buffers

## Results

### C Adapter (Baseline)
\`\`\`
$(grep -E "Performance|Throughput|pps|Mbps" "$RESULTS_DIR/c_adapter.log" | tail -10)
\`\`\`

### Zig Adapter
\`\`\`
$(grep -E "Performance|Throughput|pps|Mbps" "$RESULTS_DIR/zig_adapter.log" | tail -10)
\`\`\`

## Analysis

### Throughput Comparison
EOF

# Extract final throughput numbers
C_MBPS=$(grep "Throughput:" "$RESULTS_DIR/c_adapter.log" | tail -1 | grep -o "[0-9.]*" | head -1 || echo "N/A")
ZIG_MBPS=$(grep "Throughput:" "$RESULTS_DIR/zig_adapter.log" | tail -1 | grep -o "[0-9.]*" | head -1 || echo "N/A")

C_PPS=$(grep "pps" "$RESULTS_DIR/c_adapter.log" | tail -1 | grep -o "[0-9.]*" | head -1 || echo "N/A")
ZIG_PPS=$(grep "pps" "$RESULTS_DIR/zig_adapter.log" | tail -1 | grep -o "[0-9.]*" | head -1 || echo "N/A")

echo "- **C Adapter:** ${C_MBPS} Mbps @ ${C_PPS} pps" >> "$RESULTS_DIR/COMPARISON.md"
echo "- **Zig Adapter:** ${ZIG_MBPS} Mbps @ ${ZIG_PPS} pps" >> "$RESULTS_DIR/COMPARISON.md"

# Calculate improvement if numbers are valid
if [ "$C_MBPS" != "N/A" ] && [ "$ZIG_MBPS" != "N/A" ]; then
    IMPROVEMENT=$(echo "scale=2; ($ZIG_MBPS - $C_MBPS) / $C_MBPS * 100" | bc 2>/dev/null || echo "N/A")
    if [ "$IMPROVEMENT" != "N/A" ]; then
        echo "- **Improvement:** ${IMPROVEMENT}%" >> "$RESULTS_DIR/COMPARISON.md"
    fi
fi

cat >> "$RESULTS_DIR/COMPARISON.md" << EOF

### Observations
- Lock-free queues reduce contention between packet I/O and VPN processing
- Batch processing amortizes syscall overhead
- Memory pooling reduces allocation/deallocation overhead
- SPSC (single-producer-single-consumer) design matches VPN session model

## Next Steps
1. If improvement < 2x, investigate packet loss and queue saturation
2. Profile CPU usage to identify remaining bottlenecks
3. Consider tuning queue sizes and batch parameters
4. Test with different packet sizes and traffic patterns
EOF

echo ""
echo "=========================================="
echo "Benchmark Complete!"
echo "=========================================="
echo "Results saved to: $RESULTS_DIR/"
echo ""
cat "$RESULTS_DIR/COMPARISON.md"

# Rebuild with default (C adapter) for normal usage
echo ""
echo "Rebuilding with default C adapter..."
zig build 2>&1 | grep -E "(Building|error)" || true
