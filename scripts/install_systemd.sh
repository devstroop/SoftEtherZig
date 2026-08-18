#!/usr/bin/env bash
# install_systemd.sh
#
# Install softether-zig-vpnclient as a systemd service so the VPN connects
# at boot / runs in the background — no terminal or daemon needed.
#
# Usage:
#   sudo bash scripts/install_systemd.sh [path-to-vpnclient]
#
# Steps:
#   1. Validates the vpnclient binary.
#   2. Ensures /etc/softether-zig/config.json exists (copies the user config
#      or the example template; edit it before starting the service).
#   3. Installs + enables + starts softether-zig-vpnclient.service.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${1:-/usr/local/bin/vpnclient}"
UNIT_SRC="$SCRIPT_DIR/../systemd/softether-zig-vpnclient.service"
UNIT_NAME="softether-zig-vpnclient"
CONF_DIR="/etc/softether-zig"
CONF_FILE="$CONF_DIR/config.json"

echo "==> vpnclient binary: $BIN"
if [ ! -x "$BIN" ]; then
    echo "ERROR: $BIN not found or not executable." >&2
    echo "Install it first (release asset or 'zig build --release=fast')." >&2
    exit 1
fi
"$BIN" version >/dev/null 2>&1 || { echo "ERROR: $BIN does not run." >&2; exit 1; }

if [ ! -f "$UNIT_SRC" ]; then
    echo "ERROR: unit file not found: $UNIT_SRC" >&2
    exit 1
fi

echo "==> config: $CONF_FILE"
if [ ! -f "$CONF_FILE" ]; then
    mkdir -p "$CONF_DIR"
    if [ -f "$HOME/.config/softether-zig/config.json" ]; then
        cp "$HOME/.config/softether-zig/config.json" "$CONF_FILE"
        echo "    copied from $HOME/.config/softether-zig/config.json"
    else
        cp "$SCRIPT_DIR/../config.example.json" "$CONF_FILE"
        echo "    copied from config.example.json — EDIT IT before starting: $CONF_FILE"
    fi
    chmod 0600 "$CONF_FILE"
fi

echo "==> installing unit -> /etc/systemd/system/$UNIT_NAME.service"
install -D -m 0644 "$UNIT_SRC" "/etc/systemd/system/$UNIT_NAME.service"
systemctl daemon-reload
systemctl enable "$UNIT_NAME"
echo "==> starting service"
systemctl start "$UNIT_NAME"
systemctl --no-pager status "$UNIT_NAME" --lines=5