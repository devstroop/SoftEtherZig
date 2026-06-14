#!/usr/bin/env python3
"""Standalone VPN data-plane diagnostic — drives vpnclient binary, parses DIAG.

Zero-overhead: uses the already-built binary, no Zig rebuild needed.
Captures DIAG + DIAG-TX lines, detects upload stalls, aggregates stats.

Usage:
  python3 scripts/diag_data_plane.py                          # baseline config, 30s
  python3 scripts/diag_data_plane.py --config config.stress.json --duration 60
  python3 scripts/diag_data_plane.py --config config.baseline.json --duration 45
  python3 scripts/diag_data_plane.py --server 62.24.65.216 --duration 45
  python3 scripts/diag_data_plane.py --server 62.24.65.217 --duration 45
"""

import argparse
import os
import re
import signal
import subprocess
import sys
import time


BINARY = "zig-out/bin/vpnclient"
SUDO = "sudo"


def run_vpn(config: str, duration: int, server: str | None, verbose: bool = False) -> list[str]:
    """Run vpnclient connect, return all captured log lines."""
    if not os.path.isfile(config):
        print(f"ERROR: config file not found: {config}", file=sys.stderr)
        sys.exit(1)

    cmd = [SUDO, BINARY, "connect", "--config", config]
    if server:
        cmd.extend(["--server", server])
    if verbose:
        cmd.append("--verbose")

    print(f"[run] {' '.join(cmd)} (timeout={duration}s)")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    lines: list[str] = []
    start = time.monotonic()

    try:
        while True:
            elapsed = time.monotonic() - start
            if elapsed > duration or proc.poll() is not None:
                break

            # Non-blocking read with short poll
            try:
                line = None
                if hasattr(proc.stdout, 'readline'):
                    import select
                    r, _, _ = select.select([proc.stdout], [], [], 0.5)
                    if r:
                        line = proc.stdout.readline()
                if line:
                    line = line.rstrip('\n\r')
                    if line:
                        lines.append(line)
                        if verbose:
                            print(f"  {line}")
            except (ValueError, OSError):
                break
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    # Drain remaining output
    try:
        for line in proc.stdout:
            line = line.rstrip('\n\r')
            if line:
                lines.append(line)
    except Exception:
        pass

    return lines


DIAG_RE = re.compile(
    r"DIAG dl=([\d.]+)Mbps\((\d+)p\) ul=([\d.]+)Mbps\((\d+)p\)"
    r".*?sendq\[max=(\d+)\s+avg=([\d.]+)\]"
    r"\s+write_blocked=(\d+)"
)

DIAG_TX_RE = re.compile(
    r"DIAG-TX"
    r"\s+tun\[reads=(\d+)\s+bytes=(\d+)B\s+attempts=(\d+)\]"
    r"\s+eth\[pkts=(\d+)\s+bytes=(\d+)B\]"
    r"\s+tls\[calls=(\d+)\s+bytes=(\d+)B\]"
    r"\s+pkts\[small=(\d+)\s+large=(\d+)\]"
    r"\s+sendq\[max=(\d+)B\s+avg=([\d.]+)B\]"
    r"\s+write_blocked=(\d+)"
)

HEALTH_RE = re.compile(
    r"Health check: upload ratio ([\d.]+)% below ([\d.]+)%"
)


def parse_lines(lines: list[str]) -> dict:
    """Parse DIAG and DIAG-TX lines from log output."""
    diags = []
    diag_txs = []
    health_events = []
    connected = False
    disconnected = False
    reason = "unknown"

    for line in lines:
        if "[✓] Connected!" in line:
            connected = True
        if "disconnecting" in line.lower():
            disconnected = True
        if "Disconnected:" in line:
            m = re.search(r"Disconnected:\s*(.+)", line)
            if m:
                reason = m.group(1).strip()

        m = DIAG_RE.search(line)
        if m and "DIAG-TX" not in line:
            diags.append({
                "dl_mbps": float(m.group(1)),
                "dl_pkts": int(m.group(2)),
                "ul_mbps": float(m.group(3)),
                "ul_pkts": int(m.group(4)),
                "sendq_max": int(m.group(5)),
                "sendq_avg": float(m.group(6)),
                "write_blocked": int(m.group(7)),
            })

        m = DIAG_TX_RE.search(line)
        if m:
            diag_txs.append({
                "tun_reads": int(m.group(1)),
                "tun_bytes": int(m.group(2)),
                "tun_attempts": int(m.group(3)),
                "eth_pkts": int(m.group(4)),
                "eth_bytes": int(m.group(5)),
                "tls_calls": int(m.group(6)),
                "tls_bytes": int(m.group(7)),
                "pkt_small": int(m.group(8)),
                "pkt_large": int(m.group(9)),
                "sendq_max": int(m.group(10)),
                "sendq_avg": float(m.group(11)),
                "write_blocked": int(m.group(12)),
            })

        m = HEALTH_RE.search(line)
        if m:
            health_events.append({
                "ratio_pct": float(m.group(1)),
                "threshold_pct": float(m.group(2)),
            })

    return {
        "connected": connected,
        "disconnected": disconnected,
        "reason": reason,
        "diags": diags,
        "diag_txs": diag_txs,
        "health_events": health_events,
    }


def summarize(parsed: dict):
    """Print human-readable summary."""
    print()
    print("=" * 60)
    print("SUMMARY")
    print(f"  Connected:    {'✓' if parsed['connected'] else '✗'}")
    print(f"  Disconnected: {'✓' if parsed['disconnected'] else '✗'} "
          f"reason={parsed['reason']}")
    print(f"  DIAG windows: {len(parsed['diags'])}")
    print(f"  DIAG-TX lines: {len(parsed['diag_txs'])}")
    print(f"  Health events: {len(parsed['health_events'])}")

    if parsed["health_events"]:
        print("\n  ⚠ HEALTH CHECK TRIGGERED:")
        for h in parsed["health_events"]:
            print(f"    upload ratio {h['ratio_pct']:.1f}% < "
                  f"{h['threshold_pct']:.1f}% threshold")

    diags = parsed["diags"]
    if diags:
        dl_max = max(d["dl_mbps"] for d in diags)
        ul_max = max(d["ul_mbps"] for d in diags)
        dl_avg = sum(d["dl_mbps"] for d in diags) / len(diags)
        ul_avg = sum(d["ul_mbps"] for d in diags) / len(diags)
        sq_max = max(d["sendq_max"] for d in diags)
        wb_total = sum(d["write_blocked"] for d in diags)

        print("\n  Throughput:")
        print(f"    DL: max={dl_max:.1f} Mbps  avg={dl_avg:.1f} Mbps")
        print(f"    UL: max={ul_max:.1f} Mbps  avg={ul_avg:.1f} Mbps")
        if dl_avg > 0:
            print(f"    UL/DL ratio: {ul_avg/dl_avg*100:.1f}%")
        print(f"  Kernel sendq: max={sq_max}B ({sq_max/1024:.0f}KB)")
        print(f"  write_blocked events: {wb_total}")

        # Classify
        if dl_avg > 1.0 and ul_avg < 0.5 and ul_avg / dl_avg < 0.02:
            print("\n  ★ VERDICT: UPLOAD STALLED")
            print("    Download healthy, upload nearly zero.")
            print("    Packets reaching UL are mostly TCP ACKs, not data.")
        elif ul_avg > 1.0:
            print("\n  ★ VERDICT: HEALTHY (both directions flowing)")
        else:
            print("\n  ★ VERDICT: LOW THROUGHPUT (both directions slow)")

    txs = parsed["diag_txs"]
    if txs:
        print("\n  TX Pipeline (from DIAG-TX):")
        for tx in txs:
            print(f"    TUN → {tx['tun_reads']} reads, {tx['tun_bytes']}B")
            print(f"    ETH → {tx['eth_pkts']} frames, {tx['eth_bytes']}B")
            print(f"    TLS → {tx['tls_calls']} sends, {tx['tls_bytes']}B")
            print(f"    PKT → {tx['pkt_small']} small (<200B), "
                  f"{tx['pkt_large']} large (≥200B)")
            print(f"    SNDQ → max={tx['sendq_max']}B "
                  f"avg={tx['sendq_avg']}B  wb={tx['write_blocked']}")
            break  # just show first tx window

        if txs[-1]["tun_bytes"] > 0 and txs[-1]["pkt_large"] == 0:
            print("\n  ★ OBSERVATION: All outbound packets < 200B")
            print("    These are TCP ACKs for download, NOT upload data.")
            print("    The OS is NOT sending upload data through the TUN.")
            if txs[-1]["tls_bytes"] > txs[-1]["tun_bytes"] * 1.5:
                print("    TLS bytes > TUN bytes: includes control traffic.")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="VPN data-plane diagnostic (uses vpnclient binary)")
    parser.add_argument("--config", default="config.baseline.json",
                        help="VPN config file (default: config.baseline.json)")
    parser.add_argument("--server", "-s",
                        help="Force server IP/hostname (overrides config)")
    parser.add_argument("--duration", type=int, default=30,
                        help="Max seconds to run (default: 30)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print all VPN client output")
    parser.add_argument("--sudo-pass", help="Sudo password (or set env SUDO_PASS)")
    args = parser.parse_args()

    sudo_pass = args.sudo_pass or os.environ.get("SUDO_PASS", "")
    if sudo_pass:
        # Pre-authorize sudo
        subprocess.run(
            ["sudo", "-S", "-v"],
            input=sudo_pass + "\n", text=True, capture_output=True,
            timeout=10,
        )

    lines = run_vpn(args.config, args.duration, args.server, args.verbose)
    parsed = parse_lines(lines)
    summarize(parsed)


if __name__ == "__main__":
    main()
