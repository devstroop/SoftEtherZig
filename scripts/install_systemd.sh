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

# The unit file executes /usr/local/bin/vpnclient — make sure the binary the
# user pointed us at is the one systemd will start.
if [ "$BIN" != "/usr/local/bin/vpnclient" ]; then
    install -m 0755 "$BIN" /usr/local/bin/vpnclient
    echo "==> installed $BIN -> /usr/local/bin/vpnclient (unit ExecStart path)"
    BIN="/usr/local/bin/vpnclient"
fi

if [ ! -f "$UNIT_SRC" ]; then
    echo "ERROR: unit file not found: $UNIT_SRC" >&2
    exit 1
fi

echo "==> config: $CONF_FILE"
CONFIG_SOURCE=""
if [ ! -f "$CONF_FILE" ]; then
    mkdir -p "$CONF_DIR"
    # Resolve the invoking user's config (sudo sets HOME=/root, so plain
    # $HOME would miss it)
    INVOKER_HOME="$HOME"
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        INVOKER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)" || INVOKER_HOME="$HOME"
    fi
    if [ -f "$INVOKER_HOME/.config/softether-zig/config.json" ]; then
        CONFIG_SOURCE="$INVOKER_HOME/.config/softether-zig/config.json"
    elif [ -f "$HOME/.config/softether-zig/config.json" ]; then
        CONFIG_SOURCE="$HOME/.config/softether-zig/config.json"
    fi
    if [ -n "$CONFIG_SOURCE" ]; then
        cp "$CONFIG_SOURCE" "$CONF_FILE"
        echo "    copied from $CONFIG_SOURCE"
        chmod 0600 "$CONF_FILE"
    else
        # Only the example template is available — never start the service
        # with placeholder credentials (failing restart loop).
        cp "$SCRIPT_DIR/../config.example.json" "$CONF_FILE"
        chmod 0600 "$CONF_FILE"
        echo "    !! No user config found — installed the example template."
        echo "    !! Edit $CONF_FILE with real server/credentials, then:"
        echo "    !!   sudo systemctl start $UNIT_NAME"
        SKIP_START=1
    fi
fi

echo "==> installing unit -> /etc/systemd/system/$UNIT_NAME.service"
install -D -m 0644 "$UNIT_SRC" "/etc/systemd/system/$UNIT_NAME.service"
systemctl daemon-reload
systemctl enable "$UNIT_NAME"
if [ "${SKIP_START:-0}" = "1" ]; then
    echo "==> service enabled but NOT started (config not ready). Edit $CONF_FILE, then 'systemctl start $UNIT_NAME'."
    systemctl --no-pager status "$UNIT_NAME" --lines=3 || true
    exit 0
fi
echo "==> starting service"
systemctl start "$UNIT_NAME"
systemctl --no-pager status "$UNIT_NAME" --lines=5