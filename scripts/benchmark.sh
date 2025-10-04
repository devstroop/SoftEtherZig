#!/usr/bin/env bash
# Performance benchmark script for SoftEther Zig
# Usage: ./scripts/benchmark.sh [options]

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
VPN_SERVER="${VPN_SERVER:-vpn.example.com}"
VPN_PORT="${VPN_PORT:-443}"
VPN_USER="${VPN_USER:-test}"
VPN_HUB="${VPN_HUB:-DEFAULT}"
IPERF_SERVER="${IPERF_SERVER:-iperf.he.net}"
TEST_DURATION="${TEST_DURATION:-30}"
RESULTS_DIR="benchmark_results"

# Ensure results directory exists
mkdir -p "$RESULTS_DIR"

# Timestamp for this run
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULT_FILE="$RESULTS_DIR/benchmark_${TIMESTAMP}.json"

echo -e "${GREEN}=== SoftEther Zig Performance Benchmark ===${NC}"
echo "Date: $(date)"
echo "Server: $VPN_SERVER:$VPN_PORT"
echo "Duration: ${TEST_DURATION}s"
echo ""

# Check if binary exists
if [ ! -f "./zig-out/bin/main" ]; then
    echo -e "${RED}Error: ./zig-out/bin/main not found${NC}"
    echo "Run 'zig build' first"
    exit 1
fi

# Check if iperf3 is installed
if ! command -v iperf3 &> /dev/null; then
    echo -e "${YELLOW}Warning: iperf3 not found, installing...${NC}"
    if command -v brew &> /dev/null; then
        brew install iperf3
    else
        echo -e "${RED}Error: Please install iperf3 manually${NC}"
        exit 1
    fi
fi

# Start VPN connection
echo -e "${YELLOW}Starting VPN connection...${NC}"
./zig-out/bin/main connect \
    --server "$VPN_SERVER" \
    --port "$VPN_PORT" \
    --user "$VPN_USER" \
    --hub "$VPN_HUB" \
    > "$RESULTS_DIR/vpn_${TIMESTAMP}.log" 2>&1 &

VPN_PID=$!

# Function to cleanup on exit
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    if kill -0 "$VPN_PID" 2>/dev/null; then
        kill "$VPN_PID" 2>/dev/null || true
        wait "$VPN_PID" 2>/dev/null || true
    fi
    echo -e "${GREEN}Done${NC}"
}

trap cleanup EXIT INT TERM

# Wait for VPN to connect
echo "Waiting for VPN connection to establish..."
sleep 10

# Check if VPN is still running
if ! kill -0 "$VPN_PID" 2>/dev/null; then
    echo -e "${RED}Error: VPN process died${NC}"
    cat "$RESULTS_DIR/vpn_${TIMESTAMP}.log"
    exit 1
fi

# Verify VPN interface is up
if ! ifconfig | grep -q "utun"; then
    echo -e "${RED}Error: No utun interface found${NC}"
    exit 1
fi

echo -e "${GREEN}VPN connected successfully${NC}"
echo ""

# Run download test
echo -e "${YELLOW}Running iperf3 download test (${TEST_DURATION}s)...${NC}"
if iperf3 -c "$IPERF_SERVER" -t "$TEST_DURATION" -J > "$RESULT_FILE" 2>&1; then
    # Extract metrics
    DOWNLOAD_MBPS=$(jq '.end.sum_received.bits_per_second / 1000000' "$RESULT_FILE" 2>/dev/null || echo "0")
    DOWNLOAD_PACKETS=$(jq '.end.sum_received.packets' "$RESULT_FILE" 2>/dev/null || echo "0")
    
    echo ""
    echo -e "${GREEN}=== Results ===${NC}"
    echo "Download Speed: ${DOWNLOAD_MBPS} Mbps"
    echo "Packets: ${DOWNLOAD_PACKETS}"
    echo ""
else
    echo -e "${RED}iperf3 test failed${NC}"
    DOWNLOAD_MBPS=0
fi

# Run upload test
echo -e "${YELLOW}Running iperf3 upload test (${TEST_DURATION}s)...${NC}"
UPLOAD_FILE="$RESULTS_DIR/upload_${TIMESTAMP}.json"
if iperf3 -c "$IPERF_SERVER" -t "$TEST_DURATION" -R -J > "$UPLOAD_FILE" 2>&1; then
    # Extract metrics
    UPLOAD_MBPS=$(jq '.end.sum_received.bits_per_second / 1000000' "$UPLOAD_FILE" 2>/dev/null || echo "0")
    UPLOAD_PACKETS=$(jq '.end.sum_received.packets' "$UPLOAD_FILE" 2>/dev/null || echo "0")
    
    echo ""
    echo -e "${GREEN}=== Results ===${NC}"
    echo "Upload Speed: ${UPLOAD_MBPS} Mbps"
    echo "Packets: ${UPLOAD_PACKETS}"
    echo ""
else
    echo -e "${RED}iperf3 upload test failed${NC}"
    UPLOAD_MBPS=0
fi

# Get CPU usage (macOS specific)
if command -v ps &> /dev/null; then
    CPU_USAGE=$(ps -p "$VPN_PID" -o %cpu | tail -1 | xargs)
    echo "CPU Usage: ${CPU_USAGE}%"
fi

# Get memory usage (macOS specific)
if command -v ps &> /dev/null; then
    MEM_KB=$(ps -p "$VPN_PID" -o rss | tail -1 | xargs)
    MEM_MB=$(echo "scale=2; $MEM_KB / 1024" | bc)
    echo "Memory Usage: ${MEM_MB} MB"
fi

# Print summary
echo ""
echo -e "${GREEN}=== Summary ===${NC}"
echo "Timestamp: $TIMESTAMP"
echo "Download: ${DOWNLOAD_MBPS} Mbps"
echo "Upload: ${UPLOAD_MBPS} Mbps"
echo "Results saved to: $RESULTS_DIR"
echo ""

# Compare with target
TARGET_MBPS=87
if (( $(echo "$DOWNLOAD_MBPS > $TARGET_MBPS" | bc -l) )); then
    echo -e "${GREEN}✓ Exceeded target of ${TARGET_MBPS} Mbps!${NC}"
elif (( $(echo "$DOWNLOAD_MBPS > $(echo "$TARGET_MBPS * 0.5" | bc)" | bc -l) )); then
    echo -e "${YELLOW}⚠ Within 50% of target (${TARGET_MBPS} Mbps)${NC}"
else
    echo -e "${RED}✗ Below 50% of target (${TARGET_MBPS} Mbps)${NC}"
fi

# Show recent results
echo ""
echo -e "${YELLOW}Recent benchmark results:${NC}"
if [ -d "$RESULTS_DIR" ]; then
    ls -lt "$RESULTS_DIR"/*.json | head -5 | while read -r line; do
        FILE=$(echo "$line" | awk '{print $NF}')
        if [ -f "$FILE" ]; then
            MBPS=$(jq '.end.sum_received.bits_per_second / 1000000' "$FILE" 2>/dev/null || echo "N/A")
            DATE=$(echo "$FILE" | sed 's/.*benchmark_\([0-9_]*\).*/\1/')
            echo "  $DATE: ${MBPS} Mbps"
        fi
    done
fi

echo ""
echo -e "${GREEN}Benchmark complete!${NC}"
