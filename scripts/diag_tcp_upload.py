#!/usr/bin/env python3
"""Standalone TCP upload diagnostic — no Zig build, no VPN protocol.

Tests raw TCP upload throughput against the SoftEther server nodes.
Isolates: is the TCP stack itself broken on one node, or is the
SoftEther server software the culprit?

Usage:
  python3 scripts/diag_tcp_upload.py                    # auto-resolve DNS
  python3 scripts/diag_tcp_upload.py --host 1.2.3.4     # test one IP
  python3 scripts/diag_tcp_upload.py --hosts 1.2.3.4,5.6.7.8  # test specific IPs
"""

import argparse
import json
import os
import socket
import ssl
import sys
import time

# ── config ──────────────────────────────────────────────────────────────
SERVER_HOST = "worxvpn.662.cloud"
SERVER_PORT = 443
UPLOAD_MB = 10          # MB to upload (enough to saturate a window)
UPLOAD_CHUNK = 65536    # 64KB writes
REPORT_INTERVAL = 0.5   # seconds between progress lines
TIMEOUT = 15            # seconds before giving up on connect/upload
# ────────────────────────────────────────────────────────────────────────

def resolve(host: str) -> list[str]:
    """Resolve hostname to IP list via getaddrinfo."""
    try:
        infos = socket.getaddrinfo(host, SERVER_PORT, socket.AF_INET,
                                   socket.SOCK_STREAM, socket.IPPROTO_TCP)
        ips = sorted(set(info[4][0] for info in infos))
        print(f"[dns] {host} → {ips}")
        return ips
    except socket.gaierror as e:
        print(f"[dns] {host} → FAILED: {e}")
        return []

def test_raw_tcp(ip: str, port: int, upload_mb: int) -> dict:
    """Open raw TCP to ip:port, push UPLOAD_MB, measure throughput."""
    result = {
        "ip": ip, "port": port,
        "connect_ms": None, "upload_mbps": None,
        "bytes_sent": 0, "elapsed_s": 0,
        "error": None, "tls": False,
        "sendq_at_end": None,
    }

    sock = None
    try:
        # ── connect ──
        t0 = time.monotonic()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((ip, port))
        result["connect_ms"] = (time.monotonic() - t0) * 1000
        print(f"  [tcp:{ip}] connected in {result['connect_ms']:.0f}ms")

        # ── upload ──
        chunk = b"A" * UPLOAD_CHUNK
        target_bytes = upload_mb * 1024 * 1024
        sent = 0
        t_start = time.monotonic()
        last_report = t_start
        last_sent = 0

        sock.settimeout(TIMEOUT)
        while sent < target_bytes:
            remaining = target_bytes - sent
            n = sock.send(chunk[:min(remaining, len(chunk))])
            if n == 0:
                result["error"] = "send() returned 0 (peer closed)"
                break
            sent += n

            now = time.monotonic()
            if now - last_report >= REPORT_INTERVAL:
                elapsed = now - t_start
                mbps = (sent / 1_000_000 * 8) / elapsed if elapsed > 0 else 0
                print(f"  [tcp:{ip}] {sent/1024/1024:.1f}/{upload_mb} MB  "
                      f"{mbps:.1f} Mbps  "
                      f"{(sent - last_sent)/1024/(now - last_report):.0f} KB/s")
                last_report = now
                last_sent = sent

        elapsed = time.monotonic() - t_start
        result["bytes_sent"] = sent
        result["elapsed_s"] = elapsed
        if elapsed > 0:
            result["upload_mbps"] = (sent * 8 / 1_000_000) / elapsed

        # ── check send queue (macOS/Linux only, best-effort) ──
        # SO_NWRITE = 0x1025 on macOS, SIOCOUTQ on Linux
        try:
            if sys.platform == "darwin":
                import struct
                nwrite = sock.getsockopt(socket.SOL_SOCKET, 0x1025)  # SO_NWRITE
                if isinstance(nwrite, int):
                    result["sendq_at_end"] = nwrite
            elif sys.platform == "linux":
                import fcntl, struct
                buf = struct.pack("i", 0)
                nwrite = struct.unpack("i", fcntl.ioctl(sock.fileno(), 0x5411, buf))[0]
                result["sendq_at_end"] = nwrite
        except Exception:
            pass

    except socket.timeout:
        result["error"] = f"timeout after {TIMEOUT}s"
    except ConnectionRefusedError:
        result["error"] = "connection refused"
    except OSError as e:
        result["error"] = str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    return result

def test_tls_tcp(ip: str, port: int, upload_mb: int) -> dict:
    """Open TLS to ip:port, do handshake, push UPLOAD_MB, measure throughput."""
    result = {
        "ip": ip, "port": port,
        "connect_ms": None, "tls_handshake_ms": None,
        "upload_mbps": None, "bytes_sent": 0, "elapsed_s": 0,
        "error": None, "tls": True,
    }

    sock = None
    tls_sock = None
    try:
        # ── TCP connect ──
        t0 = time.monotonic()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((ip, port))
        connect_ms = (time.monotonic() - t0) * 1000
        result["connect_ms"] = connect_ms
        print(f"  [tls:{ip}] TCP connected in {connect_ms:.0f}ms")

        # ── TLS handshake ──
        t1 = time.monotonic()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls_sock = ctx.wrap_socket(sock, server_hostname=SERVER_HOST)
        handshake_ms = (time.monotonic() - t1) * 1000
        result["tls_handshake_ms"] = handshake_ms
        print(f"  [tls:{ip}] TLS handshake in {handshake_ms:.0f}ms"
              f" (cipher={tls_sock.cipher()[0]})")

        # ── upload ──
        chunk = b"B" * UPLOAD_CHUNK
        target_bytes = upload_mb * 1024 * 1024
        sent = 0
        t_start = time.monotonic()
        last_report = t_start
        last_sent = 0

        tls_sock.settimeout(TIMEOUT)
        while sent < target_bytes:
            remaining = target_bytes - sent
            n = tls_sock.send(chunk[:min(remaining, len(chunk))])
            if n == 0:
                result["error"] = "send() returned 0"
                break
            sent += n

            now = time.monotonic()
            if now - last_report >= REPORT_INTERVAL:
                elapsed = now - t_start
                mbps = (sent / 1_000_000 * 8) / elapsed if elapsed > 0 else 0
                print(f"  [tls:{ip}] {sent/1024/1024:.1f}/{upload_mb} MB  "
                      f"{mbps:.1f} Mbps")
                last_report = now
                last_sent = sent

        elapsed = time.monotonic() - t_start
        result["bytes_sent"] = sent
        result["elapsed_s"] = elapsed
        if elapsed > 0:
            result["upload_mbps"] = (sent * 8 / 1_000_000) / elapsed

    except ssl.SSLError as e:
        result["error"] = f"TLS: {e}"
    except socket.timeout:
        result["error"] = f"timeout after {TIMEOUT}s"
    except ConnectionRefusedError:
        result["error"] = "connection refused"
    except OSError as e:
        result["error"] = str(e)
    finally:
        if tls_sock:
            try:
                tls_sock.close()
            except Exception:
                pass
        elif sock:
            try:
                sock.close()
            except Exception:
                pass

    return result


def format_result(r: dict) -> str:
    """One-line summary of a test result."""
    mode = "TLS" if r["tls"] else "TCP"
    if r["error"]:
        return f"  {r['ip']} ({mode}) ❌ {r['error']}"
    upload = f"{r['upload_mbps']:.1f} Mbps" if r["upload_mbps"] is not None else "N/A"
    sendq = f" sendq={r['sendq_at_end']}B" if r.get("sendq_at_end") is not None else ""
    return (f"  {r['ip']} ({mode}) ✅ {r['bytes_sent']/1024/1024:.1f}MB in "
            f"{r['elapsed_s']:.1f}s = {upload}{sendq}")


def main():
    parser = argparse.ArgumentParser(
        description="Standalone TCP/TLS upload diagnostic for SoftEther nodes")
    parser.add_argument("--host", help="Single IP/hostname to test")
    parser.add_argument("--hosts", help="Comma-separated IPs to test")
    parser.add_argument("--mb", type=int, default=UPLOAD_MB,
                        help=f"MB to upload per test (default: {UPLOAD_MB})")
    parser.add_argument("--tls-only", action="store_true",
                        help="Only run TLS tests (skip raw TCP)")
    parser.add_argument("--tcp-only", action="store_true",
                        help="Only run raw TCP tests (skip TLS)")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    args = parser.parse_args()

    # Resolve target IPs
    if args.hosts:
        ips = [h.strip() for h in args.hosts.split(",")]
    elif args.host:
        ips = resolve(args.host)
    else:
        ips = resolve(SERVER_HOST)

    if not ips:
        print("ERROR: no IPs to test", file=sys.stderr)
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"TCP Upload Diagnostic — {args.mb}MB per test")
    print(f"Targets: {', '.join(ips)}:{SERVER_PORT}")
    print(f"{'='*60}\n")

    results = []

    # Raw TCP tests
    if not args.tls_only:
        print("── Raw TCP upload ──")
        for ip in ips:
            r = test_raw_tcp(ip, SERVER_PORT, args.mb)
            results.append(r)
            print(format_result(r))
            print()

    # TLS tests
    if not args.tcp_only:
        print("── TLS upload ──")
        for ip in ips:
            r = test_tls_tcp(ip, SERVER_PORT, args.mb)
            results.append(r)
            print(format_result(r))
            print()

    # Summary
    print(f"{'='*60}")
    errors = [r for r in results if r["error"]]
    ok = [r for r in results if not r["error"]]
    print(f"Results: {len(ok)}/{len(results)} passed, "
          f"{len(errors)} failed")
    if ok:
        speeds = [r["upload_mbps"] for r in ok if r["upload_mbps"] is not None]
        if speeds:
            print(f"Upload range: {min(speeds):.1f} – {max(speeds):.1f} Mbps")
    if errors:
        print(f"Failures:")
        for r in errors:
            print(f"  {r['ip']} ({'TLS' if r['tls'] else 'TCP'}): {r['error']}")

    if args.json:
        print("\n── JSON ──")
        print(json.dumps(results, indent=2))

    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
