#!/usr/bin/env bash
set -euo pipefail

BINARY="./zig-out/bin/vpnclient"
LOGDIR="test-logs"
DURATION="${1:-60}"           # seconds per test, default 60
CONFIGS=(
  config.baseline.json
  config.compress.json
  config.halfconn.json
  config.compress-halfconn.json
  config.encrypt-off.json
  config.udp-accel.json
  config.multi-conn.json
  config.stress.json
  config.rawpass.json
  config.static-ip.json
)

mkdir -p "$LOGDIR"
RESULTS=()

if [ ! -f "$BINARY" ]; then
  echo "Building vpnclient first..."
  zig build
fi

# Detect speed test tool
if command -v speedtest &>/dev/null; then
  SPEED_CMD="speedtest --format=json --accept-license --accept-gdpr"
  SPEED_NAME="speedtest (Ookla)"
elif command -v speedtest-cli &>/dev/null; then
  SPEED_CMD="speedtest-cli --simple"
  SPEED_NAME="speedtest-cli"
elif command -v curl &>/dev/null; then
  SPEED_CMD=""
  SPEED_NAME="curl (no speedtest-cli)"
  echo "Warning: speedtest-cli not found, install with: pip install speedtest-cli"
else
  SPEED_CMD=""
  SPEED_NAME="none"
fi

# Detect a timeout wrapper (macOS lacks `timeout`; coreutils provides `gtimeout`).
# Empty => run the speed test without a hard cap.
if command -v timeout &>/dev/null; then
  TIMEOUT_BIN="timeout"
elif command -v gtimeout &>/dev/null; then
  TIMEOUT_BIN="gtimeout"
else
  TIMEOUT_BIN=""
fi

echo "Testing ${#CONFIGS[@]} config variants, ${DURATION}s each"
echo "========================================"

for cfg in "${CONFIGS[@]}"; do
  # Allow server-side session cleanup between configs (prevents rate-limiting)
  sleep 10

  # Defensive cleanup: remove any stale VPN state (utun routes, host routes
  # for the VPN server, dead TUN interfaces) left over from a previous run
  # that was killed or crashed. Without this, a SIGKILL'd prior run can leave
  # the host with no network and break subsequent tests.
  echo -n "[$cfg] cleanup... "
  if sudo "$BINARY" cleanup > /dev/null 2>&1; then
    echo -n "ok "
  else
    echo -n "skipped "
  fi

  name="${cfg%.json}"
  log="$LOGDIR/$name.log"
  ts_log="$LOGDIR/$name.tsv"
  speed_log="$LOGDIR/$name.speed"

  # Clear any artifacts from a previous run so a config that fails early can't
  # display stale throughput/error numbers in the summary table.
  rm -f "$log" "$ts_log" "$speed_log"

  echo -n "[$name] connecting... "

  # Run VPN client in background. --verbose enables the per-second DIAG line
  # (throughput/queue stats) that this harness parses for TUN_UP/TUN_DOWN; it
  # is gated off in normal operation.
  sudo "$BINARY" connect --config "$cfg" --verbose > "$log" 2>&1 &
  VPN_PID=$!

  # Wait for the VPN to actually be ready (default route installed) before
  # launching speedtest. A fixed `sleep N` was too short for multi-conn /
  # stress configs (N TLS handshakes) — speedtest would start while the TUN
  # was still mid-handshake, fall back to en0, and report isVpn:false with
  # LAN-class latency. Poll for the "Full-tunnel routing configured
  # successfully" log line that vpn_client emits AFTER route install and
  # DHCP/static-IP completion. Cap at 45s to surface hangs as failures.
  ROUTE_WAIT_MAX=45
  ROUTE_WAIT_ELAPSED=0
  while [ $ROUTE_WAIT_ELAPSED -lt $ROUTE_WAIT_MAX ]; do
    if ! kill -0 "$VPN_PID" 2>/dev/null; then
      echo "FAILED (immediate exit)"
      RESULTS+=("FAIL  $name  vpn client exited immediately")
      printf "%s\t-\t-\t-\t-\t-\t-\t-\tFAIL\n" "$name" > "$ts_log"
      continue 2
    fi
    if grep -q "\[ROUTING\] ✅ Full-tunnel routing configured successfully" "$log" 2>/dev/null; then
      break
    fi
    sleep 1
    ROUTE_WAIT_ELAPSED=$((ROUTE_WAIT_ELAPSED + 1))
  done
  if [ $ROUTE_WAIT_ELAPSED -ge $ROUTE_WAIT_MAX ]; then
    echo "TIMEOUT (no routing-ready log in ${ROUTE_WAIT_MAX}s) "
    # Don't bail — fall through to speedtest; the speedtest will likely fail
    # and we'll see the "Cannot open socket" pattern in the log, which is
    # itself diagnostic. Better than masking the bug as a clean test pass.
  fi

  # Speed test through the VPN tunnel
  if [ -n "$SPEED_CMD" ]; then
    echo -n "speedtest... "
    if [ -n "$TIMEOUT_BIN" ]; then
      "$TIMEOUT_BIN" $((DURATION - 5)) $SPEED_CMD > "$speed_log" 2>&1 || true
    else
      $SPEED_CMD > "$speed_log" 2>&1 || true
    fi
  fi

  # Short DIAG accumulation window (up to 15s). Exit early if the VPN process
  # terminates (e.g. disconnect or crash) so we don't wait the full DURATION
  # for a dead client.
  for _ in 1 2 3; do
    sleep 5
    kill -0 "$VPN_PID" 2>/dev/null || break
  done

  # Graceful shutdown. The client handles SIGINT by restoring the default route,
  # re-enabling IPv6, and removing the TUN interface. Give it ample time (20s)
  # so cleanup completes — SIGKILL would leave stale routes and a dead TUN
  # interface that break subsequent configs.
  if kill -0 "$VPN_PID" 2>/dev/null; then
    sudo kill -INT "$VPN_PID" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$VPN_PID" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$VPN_PID" 2>/dev/null; then
      echo -n "(not exiting after SIGINT) "
      sudo kill -TERM "$VPN_PID" 2>/dev/null || true
      sleep 3
    fi
  fi
  wait "$VPN_PID" 2>/dev/null || true

  # Extract diag stats across ALL DIAG samples (BSD-safe, no -P).
  # Format: dl=0.0Mbps(2p) ul=0.0Mbps(0p) ... tcp_drop=0p ... pollout_skip=0
  # Report PEAK dl/ul: the last DIAG line is always the idle post-speedtest
  # sample (~0), so tail -1 understates throughput to 0. tcp_drop/pollout_skip
  # are per-window counters (reset each second), so report their max window.
  read -r tunnel_down_mbps tunnel_up_mbps drops poll_skip < <(awk '
    /DIAG/ {
      if (match($0, /dl=[0-9.]+/))           { v=substr($0,RSTART+3,RLENGTH-3)+0;  if (v>md) md=v }
      if (match($0, /ul=[0-9.]+/))           { v=substr($0,RSTART+3,RLENGTH-3)+0;  if (v>mu) mu=v }
      if (match($0, /tcp_drop=[0-9]+/))      { v=substr($0,RSTART+9,RLENGTH-9)+0;  if (v>dr) dr=v }
      if (match($0, /pollout_skip=[0-9]+/))  { v=substr($0,RSTART+13,RLENGTH-13)+0; if (v>ps) ps=v }
    }
    END { printf "%.1f %.1f %d %d\n", md+0, mu+0, dr+0, ps+0 }
  ' "$log") || true
  # Count real error-level log lines (those beginning with "err:" or "error:"),
  # not debug/info lines that merely contain the word "error" — e.g. the benign
  # DNS line "...err: error.InvalidIPAddressFormat" or the Pack "Element 'error'"
  # dump, which previously inflated every run to 1-2 "errors". The utun
  # helper-install failure is non-fatal (routing still works under sudo) and is
  # excluded. awk is used so this never trips `set -e`/pipefail.
  #
  # When a clean SIGINT-driven shutdown occurred ("[●] Shutting down..." appears
  # in the log), three teardown lines are emitted by the data loop's blocking
  # read returning EOF on a freshly-closed TLS socket. These are NOT real
  # errors — they are the orderly unwind of the data loop — and we filter them
  # only in that case so that a genuine mid-session disconnect (no Shutting
  # down line) is still counted.
  if grep -q "\[●\] Shutting down" "$log" 2>/dev/null; then
    errors=$(awk '
      /^(err|error):/ {
        if (/utun_escalate|helper install/) next
        if (/SSL_get_error=1 ret=0 errno=0/) next
        if (/unexpected eof while reading/) next
        if (/Data loop thread exited with error: error\.ConnectionLost/) next
        n++
      }
      END { print n+0 }
    ' "$log")
  else
    errors=$(awk '/^(err|error):/ && !/utun_escalate|helper install/ { n++ } END { print n+0 }' "$log")
  fi

  # Parse speed test result
  dl_mbps="?"; ul_mbps="?"; ping_ms="?"
  if [ -f "$speed_log" ]; then
    if grep -q '"latency"' "$speed_log" 2>/dev/null; then
      # Ookla --format=json (new format: nested objects) (BSD-safe)
      ping_ms=$(awk 'match($0, /"latency":[0-9.]+/) {v=substr($0,RSTART,RLENGTH); gsub(/[^0-9.]/,"",v); print v}' "$speed_log" | tail -1)
      # bandwidth field appears for download (1st) and upload (2nd) on the same line
      bw=$(awk '{r=$0; if(match(r,/"bandwidth":[0-9]+/)){a=substr(r,RSTART+11,RLENGTH-11); gsub(/[^0-9]/,"",a); r=substr(r,RSTART+RLENGTH)} if(match(r,/"bandwidth":[0-9]+/)){b=substr(r,RSTART+11,RLENGTH-11); gsub(/[^0-9]/,"",b)} print a+0, b+0}' "$speed_log")
      dl_raw="${bw%% *}";  dl_raw=${dl_raw:-0}
      ul_raw="${bw##* }";  ul_raw=${ul_raw:-0}
      dl_mbps=$(awk "BEGIN {printf \"%.1f\", ${dl_raw} / 1e6}")
      ul_mbps=$(awk "BEGIN {printf \"%.1f\", ${ul_raw} / 1e6}")
    elif grep -q '"ping"' "$speed_log" 2>/dev/null; then
      # Ookla --format=json (legacy format: primitive values) (BSD-safe, no -P)
      ping_ms=$(awk 'match($0, /"ping":[[:space:]]*[0-9.]+/) {v=substr($0,RSTART,RLENGTH); gsub(/[^0-9.]/,"",v); print v}' "$speed_log" | tail -1)
      dl_raw=$(awk 'match($0, /"download":[[:space:]]*[0-9.]+/) {v=substr($0,RSTART,RLENGTH); gsub(/[^0-9.]/,"",v); print v}' "$speed_log" | tail -1)
      ul_raw=$(awk 'match($0, /"upload":[[:space:]]*[0-9.]+/) {v=substr($0,RSTART,RLENGTH); gsub(/[^0-9.]/,"",v); print v}' "$speed_log" | tail -1)
      # Convert bps to Mbps
      dl_mbps=$(awk "BEGIN {printf \"%.1f\", ${dl_raw:-0} / 1e6}")
      ul_mbps=$(awk "BEGIN {printf \"%.1f\", ${ul_raw:-0} / 1e6}")
    elif grep -q 'Download:' "$speed_log" 2>/dev/null; then
      # speedtest-cli --simple format (BSD-safe)
      ping_ms=$(awk '/Ping:/ {gsub(/[^0-9.]/,"",$2); print $2}' "$speed_log" | tail -1)
      dl_mbps=$(awk '/Download:/ {gsub(/[^0-9.]/,"",$2); print $2}' "$speed_log" | tail -1)
      ul_mbps=$(awk '/Upload:/ {gsub(/[^0-9.]/,"",$2); print $2}' "$speed_log" | tail -1)
    fi
  fi

  # TSV summary row
  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$name" "$tunnel_up_mbps" "$tunnel_down_mbps" \
    "${dl_mbps:-?}" "${ul_mbps:-?}" "${ping_ms:-?}" \
    "$drops" "$poll_skip" "${errors:-0}" > "$ts_log"

  if [ "${errors:-0}" -gt 0 ]; then
    echo "DONE (${errors} err)"
    RESULTS+=("FAIL  $name  up=${tunnel_up_mbps}M  down=${tunnel_down_mbps}M  speedtest=${dl_mbps}M/${ul_mbps}M  ping=${ping_ms}ms")
  else
    echo "DONE"
    RESULTS+=("OK    $name  up=${tunnel_up_mbps}M  down=${tunnel_down_mbps}M  speedtest=${dl_mbps}M/${ul_mbps}M  ping=${ping_ms}ms")
  fi
done

# Print summary
echo ""
echo "========================================"
echo "TEST RESULTS (speedtest timeout: ${DURATION}s)"
echo "========================================"
printf "%-20s %8s %8s %8s %8s %7s %6s %6s %6s\n" "CONFIG" "TUN_UP" "TUN_DOWN" "DL(Mbps)" "UL(Mbps)" "PING" "DROPS" "ERR" "POLL_SKIP"
printf "%-20s %8s %8s %8s %8s %7s %6s %6s %6s\n" "-----" "------" "--------" "--------" "--------" "----" "-----" "---" "---------"
for cfg in "${CONFIGS[@]}"; do
  name="${cfg%.json}"
  if [ -f "$LOGDIR/$name.tsv" ]; then
    IFS=$'\t' read -r _ tunnel_up tunnel_down dl_mbps ul_mbps ping_ms drops poll_skip errors < "$LOGDIR/$name.tsv" || true
    printf "%-20s %8s %8s %8s %8s %7s %6s %6s %6s\n" "$name" "$tunnel_up" "$tunnel_down" "${dl_mbps:-?}" "${ul_mbps:-?}" "${ping_ms:-?}" "${drops:-0}" "${errors:-0}" "${poll_skip:-0}"
  fi
done
echo ""
echo "Full logs: $LOGDIR/"
echo "Speed test tool: ${SPEED_NAME:-none}"
echo "TUN_UP/TUN_DOWN = tunnel throughput from diag stats"
echo "DL/UL/PING = application-layer speed test results"