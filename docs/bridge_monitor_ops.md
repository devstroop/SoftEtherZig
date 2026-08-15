# Bridge & Monitor Mode — Operator and Security Guide

Covers the two non-client network operating modes introduced by the L2 Network
Bridge proposal:

| Mode | Role | Platform | Data path |
|------|------|----------|-----------|
| `client` (default) | L3 VPN client | all | classic TUN data loop |
| `bridge` | L2 transparent bridge between the hub and physical LAN NICs | **Linux only** | `bridge/loop.zig` AF_PACKET pump |
| `monitor` | passive mirror-only capture of hub traffic | all | `monitor.zig` ring + PCAP pump |

Both modes run their own session pump (`runBridgeLoop` / `runMonitorLoop`);
they never share a data loop with the client mode.

---

## 1. Security boundary (H-9)

**Bridging joins two L2 domains.** A bridge session connects the VPN hub's
virtual L2 domain to the physical LAN segment of the ingress NIC:

- Hub-side devices can **ARP-scan the physical LAN** and reach any host on it
  (subject to SecureNAT / firewall on the server).
- Physical-LAN broadcast/multicast (**mDNS, NetBIOS, ARP**) is flooded into
  the hub, and hub broadcast is flooded back onto the LAN.

Treat an active bridge session as if the hub users and the LAN were **the same
Ethernet segment**. Do not bridge on networks with sensitive hosts unless the
hub is access-controlled. Monitor mode, by contrast, is passive: it never
emits frames to any NIC (mirror-only), so it cannot be used to reach the LAN.

## 2. Bridge mode operation (Linux)

### Prerequisites

- Linux kernel with AF_PACKET (`SOCK_RAW`). Not available on macOS/Windows —
  bridge connect fails with an explicit `AdapterConfigurationFailed`.
- **root** or `CAP_NET_RAW` for the process. Missing capability surfaces as
  `error.NoCapability` at port open — never a silent passthrough.
- A hub that permits bridge sessions (server-side); for end-to-end IP
  connectivity from the LAN the hub should run SecureNAT or a bridged upstream.

### Configuration

| Layer | Setting |
|-------|---------|
| CLI | `--mode bridge --ingress en0 --ingress en1` |
| Env | `SOFTETHER_MODE=bridge`, `SOFTETHER_INGRESS=en0,en1` |
| Config file | `"mode": "bridge"`, `"bridge": { "ingress": ["en0"], "fdb_max": 4096, "fdb_aging_s": 300 }` |
| FFI | `softether_set_network_mode`, `softether_add_ingress_interface`, `softether_remove_ingress_interface` |

```bash
sudo ./zig-out/bin/vpnclient connect \
  -s vpn.example.com -H VPN -u user -P pass \
  --mode bridge --ingress eth0
```

### Operational rules

- **Ingress NIC should carry no IP (H-5).** If the NIC has a host address,
  the host's own traffic is bridged into the VPN. The port logs a warning at
  open; prefer an unnumbered/dedicated NIC. (IP on the NIC also means the
  traffic is sniffed and re-injected — loops and duplicated ACKs.)
- **Same-segment multi-NIC loop:** bridging two NICs on the same physical
  segment causes frame loops (L2 loop). Use one NIC per segment, or rely on
  the FDB learning to keep unicast unicast — broadcast still floods.
- **MTU clamp (H-3):** the session L2 frame budget is 1514 bytes (14-byte
  header + 1500 payload). An ingress MTU > 1500 logs a warning; frames > 1514
  are dropped and counted in `PortStats.drops`. Keep the NIC MTU ≤ 1500.
- **FDB sizing:** `fdb_max` (default 4096) — on overflow the engine floods
  after FIFO eviction; `fdb_aging_s` (default 300) prunes stale MACs.
- **Single connection (I-14):** `max_connections > 1` is coerced to 1 with a
  WARN. Bridge v1 always uses one TLS session.
- **No UDP acceleration:** the bridge pump polls a single TLS socket; RUDP is
  disabled for bridge/monitor sessions regardless of server support.
- **No-echo guard:** a frame arriving on a port is never flooded back to the
  same port; inbound session frames are never re-sent to the session.

### Stats

`softether_get_bridge_stats(client, &stats)` — FDB table size, forwarded /
flooded / blocked packets, LAN RX/TX, session RX/TX, drops. Zeroed when bridge
mode is not active.

## 3. Monitor mode operation

Passive capture of the hub's mirrored traffic (requires server support — the
auth pack sends `require_monitor_mode=true`, H-4). Frames land in a bounded
ring (default 4096) and optionally in a PCAP file.

### Configuration

| Layer | Setting |
|-------|---------|
| CLI | `--mode monitor --pcap out.pcap` |
| Env | `SOFTETHER_MODE=monitor`, `SOFTETHER_PCAP=out.pcap` |
| Config file | `"mode": "monitor"`, `"monitor": { "pcap_file": "out.pcap" }` |
| FFI | `softether_set_network_mode`, `softether_set_monitor_pcap` |

```bash
sudo ./zig-out/bin/vpnclient connect \
  -s vpn.example.com -H VPN -u user -P pass \
  --mode monitor --pcap capture.pcap
```

### Semantics

- **Drop-and-count, never evicts:** a full ring drops new frames
  (`frames_dropped`) instead of overwriting old captures — the ring is a
  forensic buffer, not a live tail.
- **PCAP:** written little-endian, tcpdump/tshark-readable (LINKTYPE_ETHERNET,
  snaplen 1514). A bad `pcap_file` aborts the monitor session with the raw
  file error at pump start.
- **Retrieval (FFI):** `softether_monitor_frame_count(client)` (live count,
  -1 when pump not running), `softether_monitor_get_frame(client, index,
  out, cap)` (index 0 = oldest, truncated to `cap`, stable snapshot under the
  loop mutex; 0 when out of range).
- **Stats:** `softether_get_monitor_stats(client, &stats)` — captured /
  dropped / bytes, `ring_used`, PCAP records/bytes/write-errors.
- **Security note:** the ring and PCAP contain **decrypted cleartext traffic**
  — protect `pcap_file` with filesystem permissions and never ship captures
  without consent.

## 4. MTU reference

| Path | Frame size |
|------|-----------|
| Session L2 frame budget (monitor + bridge) | 1514 bytes (14 header + 1500 payload) |
| Client-mode TUN MTU default | 1486 (1500 − 14 header) |
| Frames above budget | dropped + counted (bridge `drops`, monitor H-3 clamp + `frames_dropped` empty-ring cases) |

## 5. FFI semantics in bridge/monitor mode

- `softether_get_bridge_stats` / `softether_get_monitor_stats` — return 0 and
  fill **zeroed** structs when the respective mode is not active/pump stopped.
- `softether_monitor_frame_count` / `softether_monitor_get_frame` — return −1
  when the client is invalid or the monitor pump is not running; 0 for an
  out-of-range index.
- `softether_set_network_mode` — applies on the **next connect**; a running
  session is unaffected. 0=client, 1=bridge, 2=monitor; invalid values
  ignored.
- `softether_set_monitor_pcap` / `softether_add_ingress_interface` — call
  **before connect**; owned strings, safe to call repeatedly.
- Bridge mode has no client-mode TUN getters: `get_assigned_ip`,
  `get_assigned_mask`, `get_gateway_ip`, etc. return 0 (no DHCP in bridge/
  monitor mode).

## 6. Errata

- **FFI export baseline:** current exports count is **76** `softether_*`
  functions (was 62 at the field-dispatch milestone; +bridge stats, +mode
  setter, +ingress setter/remover, +pcap setter, +2 monitor frame getters).
- **`test.sh` removed** in 0.3.10 (commit `07e7c06`): the functional
  bridge/monitor scenarios that lived there are covered by deterministic
  unit/integration fixtures (scripted in-memory session-block drain, FDB
  aging with injected clock, no-socket transport).
- **PACKET_MMAP** RX ring for AF_PACKET ports is deferred — the port uses
  plain `read()` on the raw socket.
- **Platform ports backlog:** Android `EthernetManager` (#59), macOS `bpf`
  + SUID allowlist (#60), Windows `npcap` with graceful degrade (#61) — all
  behind the `NetPort` abstraction (issue #51).
- **Bridge/monitor multi-connection** is backlog (issue #58) — v1 is
  single-TLS (I-14).

## 7. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `error.NoCapability` at port open | missing CAP_NET_RAW — `sudo` or `setcap cap_net_raw=ep` |
| `AdapterConfigurationFailed` on macOS/Windows | bridge mode is Linux-only (AF_PACKET) — use monitor instead |
| WARN "interface has a host IP address" | ingress NIC carries an address — unnumber it (H-5) |
| WARN "MTU > 1500 — jumbo frames unsupported" | frames > 1514 dropped (H-3) — lower the NIC MTU |
| monitor session aborts with file error | `pcap_file` path is not writable — the file is opened at pump start |
| `max_connections=4 … using a single connection` | bridge/monitor v1 is single-TLS (I-14) |
| tcpdump can't read capture | ensure `--mode monitor --pcap` both set; file opened at pump start, closed at session end |