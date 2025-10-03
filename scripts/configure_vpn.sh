#!/bin/bash

# SoftEther VPN - Static IP Configuration Helper
# Configures macOS TUN device with static IP after VPN connection
#
# Usage: sudo ./configure_vpn.sh [utun_device]
# Example: sudo ./configure_vpn.sh utun7

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VPN_NETWORK="10.21.0.0/16"
VPN_GATEWAY="10.21.0.1"
VPN_CLIENT_IP="10.21.255.100"  # Static IP for this client

echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  SoftEther VPN - Static IP Configuration  ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}❌ Error: This script must be run as root${NC}"
    echo -e "${YELLOW}   Usage: sudo $0 [utun_device]${NC}"
    exit 1
fi

# Get TUN device name
if [ -n "$1" ]; then
    TUN_DEVICE="$1"
else
    # Try to auto-detect
    echo -e "${YELLOW}⚠️  No TUN device specified, searching...${NC}"
    TUN_DEVICE=$(ifconfig | grep "^utun" | tail -1 | cut -d: -f1)
    
    if [ -z "$TUN_DEVICE" ]; then
        echo -e "${RED}❌ Error: No TUN device found${NC}"
        echo -e "${YELLOW}   Make sure VPN is connected first!${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Found TUN device: $TUN_DEVICE${NC}"
fi

# Verify device exists
if ! ifconfig "$TUN_DEVICE" > /dev/null 2>&1; then
    echo -e "${RED}❌ Error: Device $TUN_DEVICE not found${NC}"
    echo -e "${YELLOW}   Available TUN devices:${NC}"
    ifconfig | grep "^utun" | cut -d: -f1 | sed 's/^/     /'
    exit 1
fi

echo
echo -e "${BLUE}Configuration:${NC}"
echo -e "  Device:       ${GREEN}$TUN_DEVICE${NC}"
echo -e "  Client IP:    ${GREEN}$VPN_CLIENT_IP${NC}"
echo -e "  Gateway:      ${GREEN}$VPN_GATEWAY${NC}"
echo -e "  VPN Network:  ${GREEN}$VPN_NETWORK${NC}"
echo

# Configure point-to-point link
echo -e "${YELLOW}→ Configuring point-to-point link...${NC}"
ifconfig "$TUN_DEVICE" "$VPN_CLIENT_IP" "$VPN_GATEWAY" up
echo -e "${GREEN}✓ Interface configured${NC}"

# Add route for VPN network
echo -e "${YELLOW}→ Adding route for VPN network...${NC}"
if route -n get -net "$VPN_NETWORK" > /dev/null 2>&1; then
    echo -e "${YELLOW}  Route already exists, deleting old route...${NC}"
    route delete -net "$VPN_NETWORK" > /dev/null 2>&1 || true
fi

route add -net "$VPN_NETWORK" "$VPN_GATEWAY"
echo -e "${GREEN}✓ Route added${NC}"

# Verify configuration
echo
echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ Configuration complete!${NC}"
echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo

echo -e "${YELLOW}Interface Status:${NC}"
ifconfig "$TUN_DEVICE" | grep -E "inet |flags" | sed 's/^/  /'
echo

echo -e "${YELLOW}Routing Table:${NC}"
netstat -rn | grep "$TUN_DEVICE" | sed 's/^/  /'
echo

echo -e "${BLUE}Test connectivity:${NC}"
echo -e "  ${YELLOW}ping -c 3 $VPN_GATEWAY${NC}    # Ping gateway"
echo -e "  ${YELLOW}ping -c 3 10.21.0.2${NC}       # Ping another IP in VPN"
echo

echo -e "${GREEN}✨ VPN is ready to use!${NC}"
