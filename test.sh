#!/usr/bin/env bash
set -euo pipefail
trap 'echo "[FATAL] test.sh failed at line $LINENO (last cmd: $BASH_COMMAND)" >&2' ERR

BINARY="./zig-out/bin/vpnclient"
LOGDIR="test-logs"
DURATION="${1:-60}"           # max seconds per config (speedtest timeout), default 60
CONFIGS=(
  config.baseline.json
  config.static-ip.json
  config.compress.json
  config.halfconn.json
  config.halfconn-ipv4.json
  config.encrypt-off.json
  config.udp-accel.json
  config.multi-conn.json
  config.stress.json
  config.rawpass.json
)

mkdir -p "$LOGDIR"
RESULTS=()

if [ ! -f "$BINARY" ]; then
  echo "Building vpnclient first..."
  zig build
fi

# Detect test tools independently
NETPROBE="../../netprobe/zig-out/bin/netprobe"
HAS_NETPROBE=false
if [ -x "$NETPROBE" ]; then
  HAS_NETPROBE=true
fi

HAS_SPEEDTEST=false
SPEEDTEST_CMD=""
SPEEDTEST_NAME=""
if command -v speedtest &>/dev/null; then
  HAS_SPEEDTEST=true
  SPEEDTEST_CMD="speedtest --format=json --accept-license --accept-gdpr"
  SPEEDTEST_NAME="speedtest (Ookla)"
elif command -v speedtest-cli &>/dev/null; then
  HAS_SPEEDTEST=true
  SPEEDTEST_CMD="speedtest-cli --simple"
  SPEEDTEST_NAME="speedtest-cli"
fi

# Detect a timeout wrapper (macOS lacks `timeout`; coreutils provides `gtimeout`)
TIMEOUT_BIN=""
if command -v timeout &>/dev/null; then
  TIMEOUT_BIN="timeout"
elif command -v gtimeout &>/dev/null; then
  TIMEOUT_BIN="gtimeout"
fi

ts() { date '+%H:%M:%S'; }

echo "$(ts) Testing ${#CONFIGS[@]} config variants, ${DURATION}s max each"
echo "========================================"

for cfg in "${CONFIGS[@]}"; do
  echo ""
  # Allow server-side session cleanup between configs (prevents rate-limiting)
  echo "[$(ts)] [$cfg] waiting 10s for server-side session cleanup..."
  sleep 10

  # Defensive cleanup: remove any stale VPN state (utun routes, host routes
  # for the VPN server, dead TUN interfaces) left over from a previous run
  # that was killed or crashed. Without this, a SIGKILL'd prior run can leave
  # the host with no network and break subsequent tests.
  echo -n "[$(ts)] [$cfg] cleanup... "
  if sudo "$BINARY" cleanup > /dev/null 2>&1; then
    echo "ok"
  else
    echo "skipped"
  fi

  name="${cfg%.json}"
  log="$LOGDIR/$name.log"
  ts_log="$LOGDIR/$name.tsv"
  speed_log="$LOGDIR/$name.speed"
  netprobe_log="$LOGDIR/$name.netprobe"

  # Clear any artifacts from a previous run so a config that fails early can't
  # display stale throughput/error numbers in the summary table.
  rm -f "$log" "$ts_log" "$speed_log" "$netprobe_log"

  echo -n "[$(ts)] [$name] connecting... "
  sudo "$BINARY" connect --config "$cfg" --verbose > "$log" 2>&1 &
  VPN_PID=$!

  # Poll for routing-ready log line (up to 45s). This is the signal that the
  # VPN tunnel is fully up: default route installed, DHCP/static-IP complete.
  ROUTE_WAIT_MAX=45
  ROUTE_WAIT_ELAPSED=0
  while [ $ROUTE_WAIT_ELAPSED -lt $ROUTE_WAIT_MAX ]; do
    if ! kill -0 "$VPN_PID" 2>/dev/null; then
      echo "[$(ts)] FAILED (immediate exit)"
      RESULTS+=("FAIL  $name  vpn client exited immediately")
      printf "%s\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\tFAIL\n" "$name" > "$ts_log"
      continue 2
    fi
    if grep -q "\[ROUTING\] ✅ Full-tunnel routing configured successfully" "$log" 2>/dev/null; then
      break
    fi
    sleep 1
    ROUTE_WAIT_ELAPSED=$((ROUTE_WAIT_ELAPSED + 1))
  done
  if [ $ROUTE_WAIT_ELAPSED -ge $ROUTE_WAIT_MAX ]; then
    echo "[$(ts)] TIMEOUT (no routing-ready log in ${ROUTE_WAIT_MAX}s, continuing)"
  else
    echo "[$(ts)] routing ready"
  fi

  # Run netprobe for low-level tunnel throughput diagnostics (TCP/UDP)
  # Timeout is short (15s) — if the server is unreachable we don't want to
  # block the entire test suite.
  if $HAS_NETPROBE; then
    echo -n "[$(ts)] netprobe-diag... "
    if [ -n "$TIMEOUT_BIN" ]; then
      "$TIMEOUT_BIN" 15 "$NETPROBE" diag 10.21.0.10:7000 --duration 10 > "$netprobe_log" 2>&1 || true
    else
      "$NETPROBE" diag 10.21.0.10:7000 --duration 10 > "$netprobe_log" 2>&1 || true
    fi
    echo "done"
  fi

  # Run Ookla speedtest for application-layer throughput
  if $HAS_SPEEDTEST; then
    echo -n "[$(ts)] ${SPEEDTEST_NAME}... "
    if [ -n "$TIMEOUT_BIN" ]; then
      "$TIMEOUT_BIN" $((DURATION - 5)) $SPEEDTEST_CMD > "$speed_log" 2>&1 || true
    else
      $SPEEDTEST_CMD > "$speed_log" 2>&1 || true
    fi
    echo "done"
  fi

  # Disconnect immediately — speedtest finished (or timed out). Brief cooldown
  # for final DIAG samples, then SIGINT.
  echo "[$(ts)] disconnecting... "
  sleep 2
  if kill -0 "$VPN_PID" 2>/dev/null; then
    sudo kill -INT "$VPN_PID" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$VPN_PID" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$VPN_PID" 2>/dev/null; then
      echo "[$(ts)] not exiting after SIGINT — sending SIGTERM"
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
  tunnel_down_mbps=0; tunnel_up_mbps=0; drops=0; poll_skip=0
  if [ -f "$log" ]; then
    read -r tunnel_down_mbps tunnel_up_mbps drops poll_skip < <(awk '
      /DIAG/ {
        if (match($0, /dl=[0-9.]+/))           { v=substr($0,RSTART+3,RLENGTH-3)+0;  if (v>md) md=v }
        if (match($0, /ul=[0-9.]+/))           { v=substr($0,RSTART+3,RLENGTH-3)+0;  if (v>mu) mu=v }
        if (match($0, /tcp_drop=[0-9]+/))      { v=substr($0,RSTART+9,RLENGTH-9)+0;  if (v>dr) dr=v }
        if (match($0, /pollout_skip=[0-9]+/))  { v=substr($0,RSTART+13,RLENGTH-13)+0; if (v>ps) ps=v }
      }
      END { printf "%.1f %.1f %d %d\n", md+0, mu+0, dr+0, ps+0 }
    ' "$log") 2>/dev/null || true
  fi
  # Count real error-level log lines (those beginning with "err:" or "error:"),
  # not debug/info lines that merely contain the word "error" — e.g. the benign
  # DNS line "...err: error.InvalidIPAddressFormat" or the Pack "Element 'error'"
  # dump, which previously inflated every run to 1-2 "errors". The utun
  # helper-install failure is non-fatal (routing still works under sudo) and is
  # excluded.
  #
  # When a clean SIGINT-driven shutdown occurred ("[●] Shutting down..." appears
  # in the log), three teardown lines are emitted by the data loop's blocking
  # read returning EOF on a freshly-closed TLS socket. These are NOT real
  # errors — they are the orderly unwind of the data loop — and we filter them
  # only in that case so that a genuine mid-session disconnect (no Shutting
  # down line) is still counted.
  errors=0
  if [ -f "$log" ]; then
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
      ' "$log" 2>/dev/null) || errors=0
    else
      errors=$(awk '/^(err|error):/ && !/utun_escalate|helper install/ { n++ } END { print n+0 }' "$log" 2>/dev/null) || errors=0
    fi
  fi

  # Parse netprobe result (low-level tunnel throughput)
  np_dl="?"; np_ul="?"; np_rtt="?"
  if [ -f "$netprobe_log" ]; then
    if grep -q "tcp_ul DONE" "$netprobe_log" 2>/dev/null || grep -q "tcp_dl DONE" "$netprobe_log" 2>/dev/null; then
      dl_line=$(grep "tcp_dl DONE" "$netprobe_log" | tail -1) || true
      ul_line=$(grep "tcp_ul DONE" "$netprobe_log" | tail -1) || true
      [ -n "$dl_line" ] && np_dl=$(echo "$dl_line" | awk '{print $NF}') || true
      [ -n "$ul_line" ] && np_ul=$(echo "$ul_line" | awk '{print $NF}') || true
      np_rtt_line=$(grep "rtt" "$netprobe_log" | head -1) || true
      [ -n "$np_rtt_line" ] && np_rtt=$(echo "$np_rtt_line" | grep -oE '[0-9]+us' | head -1 | tr -d 'us') || true
    fi
  fi

  # Parse Ookla speedtest result (application-layer throughput)
  st_dl="?"; st_ul="?"; st_ping="?"; st_err=""
  if [ -f "$speed_log" ]; then
    st_err=$(awk 'match($0, /"error":"[^"]+"/) {v=substr($0,RSTART+9,RLENGTH-10); print v}' "$speed_log" | head -1)
    if [ -n "$st_err" ]; then
      st_dl="ERR"; st_ul="$st_err"; st_ping="$st_err"
    elif grep -q '"latency"' "$speed_log" 2>/dev/null; then
      st_ping=$(awk 'match($0, /"latency":[0-9.]+/) {v=substr($0,RSTART,RLENGTH); gsub(/[^0-9.]/,"",v); print v}' "$speed_log" | tail -1)
      bw=$(awk '{r=$0; if(match(r,/"bandwidth":[0-9]+/)){a=substr(r,RSTART+11,RLENGTH-11); gsub(/[^0-9]/,"",a); r=substr(r,RSTART+RLENGTH)} if(match(r,/"bandwidth":[0-9]+/)){b=substr(r,RSTART+11,RLENGTH-11); gsub(/[^0-9]/,"",b)} print a+0, b+0}' "$speed_log")
      st_dl_raw="${bw%% *}";  st_dl_raw=${st_dl_raw:-0}
      st_ul_raw="${bw##* }";  st_ul_raw=${st_ul_raw:-0}
      st_dl=$(awk "BEGIN {printf \"%.1f\", ${st_dl_raw} / 1e6}")
      st_ul=$(awk "BEGIN {printf \"%.1f\", ${st_ul_raw} / 1e6}")
    elif grep -q '"ping"' "$speed_log" 2>/dev/null; then
      st_ping=$(awk 'match($0, /"ping":[[:space:]]*[0-9.]+/) {v=substr($0,RSTART,RLENGTH); gsub(/[^0-9.]/,"",v); print v}' "$speed_log" | tail -1)
      st_dl=$(awk 'match($0, /"download":[[:space:]]*[0-9.]+/) {v=substr($0,RSTART,RLENGTH); gsub(/[^0-9.]/,"",v); print v}' "$speed_log" | tail -1)
      st_ul=$(awk 'match($0, /"upload":[[:space:]]*[0-9.]+/) {v=substr($0,RSTART,RLENGTH); gsub(/[^0-9.]/,"",v); print v}' "$speed_log" | tail -1)
      st_dl=$(awk "BEGIN {printf \"%.1f\", ${st_dl:-0} / 1e6}")
      st_ul=$(awk "BEGIN {printf \"%.1f\", ${st_ul:-0} / 1e6}")
    elif grep -q 'Download:' "$speed_log" 2>/dev/null; then
      st_ping=$(awk '/Ping:/ {gsub(/[^0-9.]/,"",$2); print $2}' "$speed_log" | tail -1)
      st_dl=$(awk '/Download:/ {gsub(/[^0-9.]/,"",$2); print $2}' "$speed_log" | tail -1)
      st_ul=$(awk '/Upload:/ {gsub(/[^0-9.]/,"",$2); print $2}' "$speed_log" | tail -1)
    fi
  fi

  # Build display strings
  st_display="$st_dl/$st_ul"
  if [ -n "$st_err" ]; then st_display="ERR:$st_err"; fi
  np_display="$np_dl/$np_ul"
  if [ "$np_dl" = "?" ] && [ "$np_ul" = "?" ]; then
    if $HAS_NETPROBE; then np_display="RUNNING"; else np_display="SKIP"; fi
  fi

  # TSV summary row (netprobe + speedtest)
  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$name" "$tunnel_up_mbps" "$tunnel_down_mbps" \
    "${np_dl}" "${np_ul}" "${np_rtt}" \
    "${st_dl}" "${st_ul}" "${st_ping}" \
    "$drops" "$poll_skip" "${errors:-0}" > "$ts_log"

  if [ "${errors:-0}" -gt 0 ]; then
    echo "[$(ts)] [$name] DONE (${errors} err)  TUN_UP=${tunnel_up_mbps}M  TUN_DOWN=${tunnel_down_mbps}M  netprobe=${np_display}  speedtest=${st_display}"
    RESULTS+=("FAIL  $name  up=${tunnel_up_mbps}M  down=${tunnel_down_mbps}M  netprobe=${np_display}  speedtest=${st_display}")
  else
    echo "[$(ts)] [$name] DONE  TUN_UP=${tunnel_up_mbps}M  TUN_DOWN=${tunnel_down_mbps}M  netprobe=${np_display}  speedtest=${st_display}"
    RESULTS+=("OK    $name  up=${tunnel_up_mbps}M  down=${tunnel_down_mbps}M  netprobe=${np_display}  speedtest=${st_display}")
  fi
done

# Print summary
echo ""
echo "========================================"
echo "TEST RESULTS (timeout: ${DURATION}s per config)"
echo "========================================"
printf "%-20s %8s %8s %7s %7s %6s %7s %7s %6s %6s %6s\n" "CONFIG" "TUN_UP" "TUN_DOWN" "NP_DL" "NP_UL" "NP_RTT" "ST_DL" "ST_UL" "PING" "DROP" "ERR"
printf "%-20s %8s %8s %7s %7s %6s %7s %7s %6s %6s %6s\n" "-----" "------" "--------" "-----" "-----" "-----" "-----" "-----" "-----" "----" "---"
for cfg in "${CONFIGS[@]}"; do
  name="${cfg%.json}"
  if [ -f "$LOGDIR/$name.tsv" ]; then
    IFS=$'\t' read -r _ tun_up tun_down np_dl np_ul np_rtt st_dl st_ul st_ping drops poll_skip errors < "$LOGDIR/$name.tsv" || true
    printf "%-20s %8s %8s %7s %7s %6s %7s %7s %6s %6s %6s\n" \
      "$name" "${tun_up:-?}" "${tun_down:-?}" \
      "${np_dl:-?}" "${np_ul:-?}" "${np_rtt:-?}" \
      "${st_dl:-?}" "${st_ul:-?}" "${st_ping:-?}" \
      "${drops:-0}" "${errors:-0}"
  fi
done
echo ""
echo "Full logs: $LOGDIR/"
echo "NP=netprobe (tunnel-level), ST=speedtest (application-level)"
echo "TUN_UP/TUN_DOWN = tunnel throughput from diag stats"