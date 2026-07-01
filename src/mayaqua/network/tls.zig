//! TLS Module
//!
//! TLS wrapper for SoftEther VPN connections using OpenSSL.
//! OpenSSL is required because SoftEther VPN servers typically use self-signed
//! certificates, and we need fine-grained control over certificate verification.

const std = @import("std");
const log = std.log.scoped(.mayaqua_tls);
const builtin = @import("builtin");
const net = std.net;
const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/x509.h");
});
const Allocator = std.mem.Allocator;

/// Network interface index to bind outbound TLS sockets to (Darwin IP_BOUND_IF /
/// IPV6_BOUND_IF). Set via softether_set_bind_interface() in ffi.zig. Required on
/// iOS NEPacketTunnelProvider so the extension's own outbound connection bypasses
/// the tunnel that's about to be established. Zero = no binding.
pub var bind_interface_index: c_uint = 0;

/// Optional host-provided TCP dial function. When set, libsoftether's TLS connect
/// path skips DNS+POSIX-connect and instead asks the host for a connected fd.
/// Required on iOS NEPacketTunnelProvider where NECP denies the extension's own
/// connect() — Swift dials via NEProvider.createTCPConnection (outside the
/// tunnel) and bridges bytes through a socketpair. Zero/null = use POSIX path.
pub const ExternalTcpDialFn = *const fn (host: [*:0]const u8, port: u16) callconv(.c) c_int;
pub var external_tcp_dial: ?ExternalTcpDialFn = null;

/// Darwin socket option constants (sys/socket.h). Not in std.posix on iOS.
const DARWIN_IP_BOUND_IF: c_int = 25;
const DARWIN_IPV6_BOUND_IF: c_int = 125;
const DARWIN_IPPROTO_IP: c_int = 0;
const DARWIN_IPPROTO_IPV6: c_int = 41;
const testing = std.testing;

const socket_mod = @import("socket.zig");
const TcpSocket = socket_mod.TcpSocket;
const dns_cache_mod = @import("dns_cache.zig");
const http_mod = @import("http.zig");
const route_heal = @import("../../adapter/route_heal.zig");

/// Proxy configuration for TLS connect. Re-exported for convenience.
pub const ProxyConfig = http_mod.ProxyConfig;

/// Global DNS cache instance for TLS connections
var global_dns_cache: ?dns_cache_mod.DnsCache = null;
var dns_cache_init_mutex: std.Thread.Mutex = .{};

/// Get or initialize the global DNS cache
fn getDnsCache(allocator: Allocator) *dns_cache_mod.DnsCache {
    dns_cache_init_mutex.lock();
    defer dns_cache_init_mutex.unlock();

    if (global_dns_cache == null) {
        global_dns_cache = dns_cache_mod.DnsCache.init(allocator, null);
    }
    return &global_dns_cache.?;
}

/// TLS errors
pub const TlsError = error{
    HandshakeFailed,
    CertificateVerificationFailed,
    CertificateExpired,
    CertificateRevoked,
    HostnameMismatch,
    UnsupportedProtocol,
    AlertReceived,
    RecordOverflow,
    BadCertificate,
    InternalError,
    TlsInitializationFailed,
    ConnectionClosed,
    ConnectionFailed,
    OutOfMemory,
};

/// TLS version
pub const TlsVersion = enum {
    tls_1_2,
    tls_1_3,
};

/// TLS configuration
pub const TlsConfig = struct {
    /// Verify server certificate (should be true in production)
    verify_certificate: bool = true,

    /// Minimum TLS version
    min_version: TlsVersion = .tls_1_2,

    /// Connection timeout in milliseconds
    timeout_ms: u32 = 30000,

    /// SoftEther-specific: Accept self-signed certificates
    /// WARNING: Only use for testing or when server cert is pinned
    allow_self_signed: bool = false,

    /// Client certificate PEM data (for certificate authentication)
    client_cert_pem: ?[]const u8 = null,

    /// Client private key PEM data (for certificate authentication)
    client_key_pem: ?[]const u8 = null,

    /// SNI hostname override. When set, this is used for the TLS SNI extension
    /// instead of the hostname passed to connect(). Required on cluster-redirect
    /// where the TCP connection goes to an IP literal but the load balancer needs
    /// the original server hostname to route the TLS handshake.
    sni_hostname: ?[]const u8 = null,

    /// Proxy configuration. When set, the TCP connection is established through
    /// the proxy before the TLS handshake. Supports HTTP CONNECT, SOCKS4, SOCKS5.
    proxy: ?ProxyConfig = null,

    /// Network interface index to bind outbound sockets to (Darwin IP_BOUND_IF).
    /// Overrides the global bind_interface_index when set to non-null.
    bind_interface_index: ?c_uint = null,

    /// Host-provided TCP dial function for this specific connection.
    /// Overrides the global external_tcp_dial when set.
    external_tcp_dial: ?ExternalTcpDialFn = null,

    /// Enable TCP_NODELAY (disable Nagle's algorithm) for low latency.
    /// True by default — SoftEther VPN benefits from immediate packet delivery.
    /// Set to false for bulk-throughput workloads where Nagle's buffering helps.
    tcp_nodelay: bool = true,
};

/// TCP connect with configurable timeout using non-blocking socket + poll.
/// Avoids the OS default 75s SYN timeout that causes apparent freezes.
fn tcpConnectWithTimeout(address: net.Address, timeout_ms: u32, bind_if_idx: ?c_uint) !std.posix.socket_t {
    const fd = try std.posix.socket(address.any.family, std.posix.SOCK.STREAM, 0);
    errdefer {
        if (builtin.os.tag == .windows) {
            _ = std.os.windows.ws2_32.closesocket(fd);
        } else {
            std.posix.close(fd);
        }
    }

    // Darwin: bind socket to specific interface BEFORE connect(). Required on iOS
    // NEPacketTunnelProvider extensions, otherwise the kernel's NECP layer routes
    // the extension's outbound socket through the (not-yet-established) tunnel
    // and we get instant ECONNREFUSED.
    const effective_bind_if = bind_if_idx orelse bind_interface_index;
    if ((builtin.os.tag == .ios or builtin.os.tag == .macos) and effective_bind_if != 0) {
        const idx_bytes = std.mem.asBytes(&effective_bind_if);
        if (address.any.family == std.posix.AF.INET6) {
            std.posix.setsockopt(fd, DARWIN_IPPROTO_IPV6, DARWIN_IPV6_BOUND_IF, idx_bytes) catch |err| {
                std.log.warn("TLS: IPV6_BOUND_IF(idx={d}) failed: {}", .{ effective_bind_if, err });
            };
        } else {
            std.posix.setsockopt(fd, DARWIN_IPPROTO_IP, DARWIN_IP_BOUND_IF, idx_bytes) catch |err| {
                std.log.warn("TLS: IP_BOUND_IF(idx={d}) failed: {}", .{ effective_bind_if, err });
            };
        }
    }

    if (builtin.os.tag == .windows) {
        // Windows: use ioctlsocket for non-blocking mode
        const ws2 = std.os.windows.ws2_32;
        var nonblocking: c_ulong = 1;
        _ = ws2.ioctlsocket(fd, @as(i32, @bitCast(@as(u32, 0x8004667e))), &nonblocking); // FIONBIO

        // Initiate connect
        std.posix.connect(fd, &address.any, address.getOsSockLen()) catch |err| switch (err) {
            error.WouldBlock => {},
            else => return err,
        };

        // Poll for write-readiness
        var poll_fds = [1]std.posix.pollfd{
            .{ .fd = fd, .events = std.posix.POLL.OUT, .revents = 0 },
        };
        const effective_timeout: i32 = if (timeout_ms > 0) @intCast(timeout_ms) else 30000;
        const poll_result = try std.posix.poll(&poll_fds, effective_timeout);
        if (poll_result == 0) {
            return error.ConnectionTimedOut;
        }

        // Check for connect error via revents
        if (poll_fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP) != 0) {
            std.log.err("TLS: TCP connect failed (poll revents={x})", .{poll_fds[0].revents});
            return error.ConnectionRefused;
        }

        // Restore blocking mode
        nonblocking = 0;
        _ = ws2.ioctlsocket(fd, @as(i32, @bitCast(@as(u32, 0x8004667e))), &nonblocking); // FIONBIO
    } else {
        // POSIX: use fcntl for non-blocking mode
        // O_NONBLOCK differs per OS: macOS/BSD = 0x0004, Linux/Android = 0x0800
        const O_NONBLOCK: usize = if (builtin.os.tag == .linux) 0x0800 else 0x0004;
        const flags = try std.posix.fcntl(fd, std.posix.F.GETFL, 0);
        _ = try std.posix.fcntl(fd, std.posix.F.SETFL, flags | O_NONBLOCK);

        // Initiate connect — returns immediately with WouldBlock (EINPROGRESS)
        std.posix.connect(fd, &address.any, address.getOsSockLen()) catch |err| switch (err) {
            error.WouldBlock => {},
            else => return err,
        };

        // Poll for write-readiness (connection completion)
        var poll_fds = [1]std.posix.pollfd{
            .{ .fd = fd, .events = std.posix.POLL.OUT, .revents = 0 },
        };
        const effective_timeout: i32 = if (timeout_ms > 0) @intCast(timeout_ms) else 30000;
        const poll_result = try std.posix.poll(&poll_fds, effective_timeout);
        if (poll_result == 0) {
            return error.ConnectionTimedOut;
        }

        // Check for connect error via SO_ERROR
        var so_error: c_int = 0;
        var optlen: std.posix.socklen_t = @sizeOf(c_int);
        const rc = std.c.getsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.ERROR, @ptrCast(&so_error), &optlen);
        if (rc != 0) {
            return error.ConnectionRefused;
        }
        if (so_error != 0) {
            return error.ConnectionRefused;
        }

        // Restore blocking mode
        _ = try std.posix.fcntl(fd, std.posix.F.SETFL, flags);
    }

    return fd;
}

/// Emit a contextual error message for a TCP connect failure. For the
/// generic case this is just the error tag; for `AddressNotAvailable` on
/// Darwin/Linux this expands into a stale-route diagnosis with the exact
/// `route delete` command the operator should run.
///
/// Background: a previous VPN session that crashed or was kill -9'd leaves
/// behind a host route to the server pointing through a now-defunct utunN
/// interface. When the kernel resolves the destination, it picks the dead
/// interface, can't bind a source address, and returns EADDRNOTAVAIL — even
/// though the destination is otherwise reachable (verifiable with `nc -vz`).
fn logConnectError(err: anyerror, hostname: []const u8, port: u16) void {
    if (err == error.AddressNotAvailable) {
        std.log.err(
            "TLS: TCP connect to {s}:{d} failed with AddressNotAvailable. " ++
                "This is almost always a stale host route from a previous VPN session " ++
                "(usually pointing through a now-defunct utunN interface). " ++
                "Recover with:  sudo route -n delete {s}  — then retry.",
            .{ hostname, port, hostname },
        );
    } else {
        std.log.err("TLS: TCP connect to {s}:{d} failed: {}", .{ hostname, port, err });
    }
}

/// TLS-wrapped socket using OpenSSL
pub const TlsSocket = struct {
    allocator: Allocator,
    tcp_fd: std.posix.socket_t,
    ssl_ctx: ?*c.SSL_CTX,
    ssl: ?*c.SSL,
    config: TlsConfig,
    hostname_buf: []u8,
    connected: bool,
    /// Counter incremented every time writeAllNonBlocking hits WANT_WRITE (i.e.
    /// the underlying TCP sndbuf was full). Surfaced via DIAG to detect
    /// TX-bound bufferbloat.
    write_block_count: u64 = 0,

    /// Stashed pending outbound data from an incomplete SSL_write (WANT_WRITE).
    /// The main loop checks needs_pollout, registers POLLOUT interest in the
    /// poll fd array, and calls retryPendingWrite() when POLLOUT fires.
    /// OpenSSL requires retrying WANT_WRITE with the exact same buffer pointer,
    /// so this slice must point to a persistent buffer (send_buffer in data loop).
    pending_outbound: []const u8 = "",
    needs_pollout: bool = false,

    /// Read-ahead buffer for batched SSL_read. When a read() call finds this
    /// buffer empty, it issues one large SSL_read (up to READ_BUF_SIZE) to fill
    /// it, then serves subsequent small reads from the buffer without another
    /// SSL_read call. This reduces the number of SSL_read calls from ~19 per
    /// 9-packet batch (one for each 4-byte header + data chunk) to ~1 per batch,
    /// dramatically improving throughput on high-latency TLS connections.
    read_buf: []u8 = "",
    read_buf_available: usize = 0,
    read_buf_offset: usize = 0,

    /// Size of the read-ahead buffer. 64KB = 4× TLS max record size (16KB),
    /// allowing up to 4 full TLS records to be batched in one SSL_read call.
    const READ_BUF_SIZE: usize = 64 * 1024;

    /// Connect to hostname:port with TLS
    pub fn connect(allocator: Allocator, hostname: []const u8, port: u16, config: TlsConfig) !TlsSocket {
        // Initialize OpenSSL (idempotent in modern OpenSSL)
        _ = c.OPENSSL_init_ssl(0, null);

        // Resolve and connect TCP
        var tcp_fd: std.posix.socket_t = undefined;

        // iOS NECP bypass via POSIX socket + IP_BOUND_IF. When the host has
        // bound to a physical interface (bind_interface_index != 0, set by
        // softether_set_bind_interface from Swift), use tcpConnectWithTimeout
        // which applies IP_BOUND_IF + sets a large 4MB SO_RCVBUF. This
        // bypasses the NWConnection autotune that keeps iOS DL at 2-3 Mbps.
        var via_host_dial: bool = false;
        if (builtin.os.tag == .ios and (config.bind_interface_index orelse bind_interface_index) != 0) {
            // Try direct POSIX socket with IP_BOUND_IF. The bind-interface
            // selection comes from Swift's activePhysicalInterfaceName()
            // which prefers en0 (Wi-Fi) over other en* / pdp_ip* interfaces.
            // When the active interface cannot reach the server IP (e.g.,
            // en2 = USB tethering has no route), connect fails with
            // NetworkUnreachable. In that case we retry ONCE without
            // IP_BOUND_IF before falling back to the host dial callback —
            // this gives the kernel routing table a chance to pick the
            // correct egress interface (which works when NECP doesn't
            // actively block it, i.e. the service side has established
            // that the flow is for the tunnel provider itself).
            var dns_ok = false;
            var connect_ok = false;
            if (std.net.getAddressList(allocator, hostname, port)) |addrs| {
                defer addrs.deinit();
                if (addrs.addrs.len > 0) {
                    dns_ok = true;
                    const address = addrs.addrs[0];
                    const connect_result = tcpConnectWithTimeout(address, config.timeout_ms, config.bind_interface_index);
                    if (connect_result) |fd| {
                        tcp_fd = fd;
                        const rcv_cap: u32 = 4 * 1024 * 1024;
                        _ = std.posix.setsockopt(tcp_fd, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&rcv_cap)) catch {};
                        std.log.info("TLS: direct POSIX socket + IP_BOUND_IF + 4MB RCVBUF", .{});
                        connect_ok = true;
                    } else |err| {
                        // Retry once without IP_BOUND_IF — the kernel
                        // routing table may find a path that the bound
                        // interface doesn't have.
                        const retry_result = tcpConnectWithTimeout(address, config.timeout_ms, null);
                        if (retry_result) |fd| {
                            tcp_fd = fd;
                            const rcv_cap: u32 = 4 * 1024 * 1024;
                            _ = std.posix.setsockopt(tcp_fd, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&rcv_cap)) catch {};
                            std.log.info("TLS: POSIX retry OK without IP_BOUND_IF (initial {})", .{err});
                            connect_ok = true;
                        } else |retry_err| {
                            std.log.warn("TLS: POSIX connect failed ({}), retry without IP_BOUND_IF also failed ({}), falling back to host dial", .{ err, retry_err });
                            if (config.external_tcp_dial orelse external_tcp_dial) |dial| {
                                const c_host = try allocator.dupeZ(u8, hostname);
                                defer allocator.free(c_host);
                                const fd_int = dial(c_host.ptr, port);
                                if (fd_int >= 0) {
                                    tcp_fd = @intCast(fd_int);
                                    via_host_dial = true;
                                } else return TlsError.ConnectionFailed;
                            } else return TlsError.ConnectionFailed;
                        }
                    }
                }
            } else |_| {
                std.log.warn("TLS: DNS resolution failed, falling back to host dial", .{});
            }
            if (!dns_ok and !connect_ok and !via_host_dial) {
                // DNS failed or no addresses — use dial callback
                if (config.external_tcp_dial orelse external_tcp_dial) |dial| {
                    const c_host = try allocator.dupeZ(u8, hostname);
                    defer allocator.free(c_host);
                    const fd_int = dial(c_host.ptr, port);
                    if (fd_int >= 0) {
                        tcp_fd = @intCast(fd_int);
                        via_host_dial = true;
                    } else return TlsError.ConnectionFailed;
                } else return TlsError.ConnectionFailed;
            }
        } else if (config.external_tcp_dial orelse external_tcp_dial) |dial| {
            const c_host = try allocator.dupeZ(u8, hostname);
            defer allocator.free(c_host);
            std.log.info("TLS: dialing {s}:{d} via host callback", .{ hostname, port });
            const fd_int = dial(c_host.ptr, port);
            if (fd_int < 0) {
                std.log.err("TLS: host dial callback returned {d} for {s}:{d}", .{ fd_int, hostname, port });
                return TlsError.ConnectionFailed;
            }
            // Windows: socket_t is an opaque *SOCKET pointer; reconstruct from the integer fd.
            // Other platforms: socket_t is an integer.
            tcp_fd = if (builtin.os.tag == .windows)
                @ptrFromInt(@as(usize, @intCast(fd_int)))
            else
                @intCast(fd_int);
            via_host_dial = true;
        } else if (config.proxy) |proxy| {
            // Proxy connect: delegate TCP establishment to the proxy (HTTP CONNECT,
            // SOCKS4, or SOCKS5). TLS is layered on top as usual.
            var proxy_sock = try http_mod.connectViaProxy(allocator, proxy, hostname, port);
            errdefer proxy_sock.close();
            tcp_fd = proxy_sock.stream.handle;
        } else
        // First try to parse as IP address
        if (net.Address.resolveIp(hostname, port)) |address| {
            std.log.debug("TLS: Resolved IP address directly: {s}:{d}", .{ hostname, port });
            const connect_result = tcpConnectWithTimeout(address, config.timeout_ms, config.bind_interface_index);
            if (connect_result) |fd| {
                tcp_fd = fd;
            } else |err| {
                // #9: Auto-repair stale host route on EADDRNOTAVAIL, then retry once
                if (err == error.AddressNotAvailable and
                    route_heal.repairStaleHostRoute(allocator, hostname, port))
                {
                    std.log.info("TLS: Retrying {s}:{d} after stale-route repair", .{ hostname, port });
                    tcp_fd = tcpConnectWithTimeout(address, config.timeout_ms, config.bind_interface_index) catch |retry_err| {
                        logConnectError(retry_err, hostname, port);
                        return TlsError.ConnectionFailed;
                    };
                } else {
                    logConnectError(err, hostname, port);
                    return TlsError.ConnectionFailed;
                }
            }
        } else |resolve_err| {
            std.log.debug("TLS: Not an IP, trying DNS for: {s} (err: {})", .{ hostname, resolve_err });

            // Try DNS cache first, fall back to OS resolution
            const cache = getDnsCache(allocator);
            const cached_addrs = cache.resolveWithCache(hostname, port) catch |err| {
                std.log.err("TLS: DNS resolution failed: {}", .{err});
                return TlsError.ConnectionFailed;
            };

            if (cached_addrs.len == 0) {
                std.log.err("TLS: No addresses found for {s}", .{hostname});
                return TlsError.ConnectionFailed;
            }

            // Iterate ALL DNS results (RFC 6724 / "Happy Eyeballs"-lite). On iOS the
            // system resolver typically returns AAAA before A; if the server has no
            // IPv6 listener (or the path RSTs) we get instant ECONNREFUSED on the
            // first result and must fall through to the next address. Without this
            // loop the iOS NEPacketTunnel extension fails to connect even though
            // macOS/Android happen to work because their first result is reachable.
            var last_err: anyerror = error.ConnectionRefused;
            var connected_idx: ?usize = null;
            for (cached_addrs, 0..) |addr, i| {
                const result = tcpConnectWithTimeout(addr, config.timeout_ms, config.bind_interface_index);
                if (result) |fd| {
                    tcp_fd = fd;
                    connected_idx = i;
                    break;
                } else |err| {
                    std.log.warn("TLS: TCP connect to DNS result #{d} failed: {} (trying next)", .{ i, err });
                    last_err = err;
                }
            }
            if (connected_idx == null) {
                cache.invalidate(hostname);
                std.log.err("TLS: All {d} DNS results failed for {s}, last err: {}", .{ cached_addrs.len, hostname, last_err });
                // #9: Auto-repair stale host route on EADDRNOTAVAIL, then retry once
                if (last_err == error.AddressNotAvailable and
                    route_heal.repairStaleHostRoute(allocator, hostname, port))
                {
                    std.log.info("TLS: Retrying {s}:{d} after stale-route repair", .{ hostname, port });
                    for (cached_addrs, 0..) |addr, retry_i| {
                        const retry_result = tcpConnectWithTimeout(addr, config.timeout_ms, config.bind_interface_index);
                        if (retry_result) |fd| {
                            tcp_fd = fd;
                            connected_idx = retry_i;
                            break;
                        } else |retry_err| {
                            std.log.warn("TLS: Retry #{d} failed: {}", .{ retry_i, retry_err });
                        }
                    }
                    if (connected_idx == null) {
                        logConnectError(last_err, hostname, port);
                        return TlsError.ConnectionFailed;
                    }
                } else {
                    if (last_err == error.AddressNotAvailable) {
                        logConnectError(last_err, hostname, port);
                    }
                    return TlsError.ConnectionFailed;
                }
            }
        }
        errdefer {
            if (builtin.os.tag == .windows) {
                _ = std.os.windows.ws2_32.closesocket(tcp_fd);
            } else {
                std.posix.close(tcp_fd);
            }
        }

        // CRITICAL: Disable Nagle's algorithm for low latency.
        // Skip on host-dialed sockets (AF_UNIX socketpair from iOS NEPacketTunnel
        // bridge) — TCP_NODELAY is invalid on AF_UNIX (returns ENOPROTOOPT) and
        // Nagle is handled by NWTCPConnection on the host side.
        if (!via_host_dial and config.tcp_nodelay) {
            const nodelay: u32 = 1;
            const IPPROTO_TCP = 6;
            const TCP_NODELAY = 1;
            std.posix.setsockopt(tcp_fd, IPPROTO_TCP, TCP_NODELAY, std.mem.asBytes(&nodelay)) catch |err| {
                std.log.warn("Failed to set TCP_NODELAY: {}", .{err});
            };
        }

        // TCP_NOTSENT_LOWAT: limits unsent data in the kernel send buffer so that
        // ACKs for DL data don't get queued behind large amounts of UL data on a
        // single TCP connection carrying bidirectional VPN traffic. Without this,
        // nwrite_max reaches 1.3+ MB during concurrent UL/DL, and the server never
        // sees DL ACKs fast enough to grow its congestion window — DL collapses to
        // ~1 Mbps even though UL runs at 50 Mbps.
        //
        // Choice of 128KB:
        //   - At 50 Mbps UL, 128KB = ~20ms of data → DL ACK delay ~20ms
        //   - Without NOTSENT_LOWAT, 1.3MB = ~200ms delay → DL ACKs arrive too late
        //   - The kernel's TCP stack is sized for bulk-throughput, not interleaved
        //     bidirectional flows. NOTSENT_LOWAT re-prioritizes ACKs inside the
        //     kernel's output queue without application-level changes.
        //   - SO_SNDBUF (2MB) still caps the total send buffer; NOTSENT_LOWAT just
        //     makes SSL_write/EAGAIN return sooner when the pipeline is full.
        //
        // Darwin constant: <netinet/tcp.h> TCP_NOTSENT_LOWAT = 0x200.
        if (!via_host_dial) {
            const notsent_lowat: u32 = 128 * 1024; // 128 KB
            const TCP_NOTSENT_LOWAT: u32 = 0x200;
            const IPPROTO_TCP: u32 = 6;
            std.posix.setsockopt(tcp_fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, std.mem.asBytes(&notsent_lowat)) catch |err| {
                std.log.warn("Failed to set TCP_NOTSENT_LOWAT: {}", .{err});
            };
        }

        // On Windows, disable delayed ACKs — default 200ms ACK delay adds latency
        if (builtin.os.tag == .windows) {
            const SIO_TCP_SET_ACK_FREQUENCY = @as(u32, 0x98000017);
            var ack_freq: u32 = 1; // ACK every packet immediately
            var bytes_returned: u32 = 0;
            _ = std.os.windows.ws2_32.WSAIoctl(
                tcp_fd,
                SIO_TCP_SET_ACK_FREQUENCY,
                @ptrCast(&ack_freq),
                @sizeOf(u32),
                null,
                0,
                &bytes_returned,
                null,
                null,
            );
        }

        // Apply timeout
        if (config.timeout_ms > 0) {
            TcpSocket.setReadTimeout(tcp_fd, config.timeout_ms) catch {};
            TcpSocket.setWriteTimeout(tcp_fd, config.timeout_ms) catch {};
        }

        // Allocate hostname buffer
        const hostname_buf = try allocator.dupe(u8, hostname);
        errdefer allocator.free(hostname_buf);

        // Create SSL context
        const method = c.TLS_client_method();
        const ssl_ctx = c.SSL_CTX_new(method) orelse {
            std.log.err("Failed to create SSL context", .{});
            return TlsError.TlsInitializationFailed;
        };
        errdefer c.SSL_CTX_free(ssl_ctx);

        // For SoftEther with self-signed certs, disable verification
        if (config.allow_self_signed or !config.verify_certificate) {
            c.SSL_CTX_set_verify(ssl_ctx, c.SSL_VERIFY_NONE, null);
        }

        // Load client certificate for certificate authentication
        if (config.client_cert_pem) |cert_pem| {
            const cert_bio = c.BIO_new_mem_buf(cert_pem.ptr, @intCast(cert_pem.len)) orelse {
                std.log.err("TLS: Failed to create BIO for client certificate", .{});
                return TlsError.TlsInitializationFailed;
            };
            defer _ = c.BIO_free(cert_bio);
            const cert = c.PEM_read_bio_X509(cert_bio, null, null, null) orelse {
                std.log.err("TLS: Failed to parse client certificate PEM", .{});
                return TlsError.BadCertificate;
            };
            defer c.X509_free(cert);
            if (c.SSL_CTX_use_certificate(ssl_ctx, cert) != 1) {
                std.log.err("TLS: Failed to set client certificate", .{});
                logOpenSslErrors();
                return TlsError.BadCertificate;
            }
            std.log.info("TLS: Client certificate loaded", .{});
        }

        // Load client private key for certificate authentication
        if (config.client_key_pem) |key_pem| {
            const key_bio = c.BIO_new_mem_buf(key_pem.ptr, @intCast(key_pem.len)) orelse {
                std.log.err("TLS: Failed to create BIO for client key", .{});
                return TlsError.TlsInitializationFailed;
            };
            defer _ = c.BIO_free(key_bio);
            const pkey = c.PEM_read_bio_PrivateKey(key_bio, null, null, null) orelse {
                std.log.err("TLS: Failed to parse client private key PEM", .{});
                return TlsError.BadCertificate;
            };
            defer c.EVP_PKEY_free(pkey);
            if (c.SSL_CTX_use_PrivateKey(ssl_ctx, pkey) != 1) {
                std.log.err("TLS: Failed to set client private key", .{});
                logOpenSslErrors();
                return TlsError.BadCertificate;
            }
            // Verify cert/key match
            if (c.SSL_CTX_check_private_key(ssl_ctx) != 1) {
                std.log.err("TLS: Client certificate and private key do not match", .{});
                logOpenSslErrors();
                return TlsError.BadCertificate;
            }
            std.log.info("TLS: Client private key loaded and verified", .{});
        }

        // Create SSL connection
        const ssl = c.SSL_new(ssl_ctx) orelse {
            std.log.err("Failed to create SSL object", .{});
            return TlsError.TlsInitializationFailed;
        };
        errdefer c.SSL_free(ssl);

        // Set hostname for SNI. On a cluster redirect the TCP connection goes
        // to an IP literal but the load balancer may need the original server
        // hostname to route the TLS handshake; config.sni_hostname lets the
        // caller override what is sent in the SNI extension.
        const sni_name = config.sni_hostname orelse hostname;
        const hostname_z = try allocator.dupeZ(u8, sni_name);
        defer allocator.free(hostname_z);
        _ = c.SSL_set_tlsext_host_name(ssl, hostname_z.ptr);

        // Attach to socket
        const fd_int: c_int = if (builtin.os.tag == .windows) @intCast(@intFromPtr(tcp_fd)) else @intCast(tcp_fd);
        if (c.SSL_set_fd(ssl, fd_int) != 1) {
            std.log.err("Failed to set SSL fd", .{});
            return TlsError.TlsInitializationFailed;
        }

        // Perform TLS handshake with retry loop for WANT_READ/WANT_WRITE
        // (defensive: blocking sockets can still return these in edge cases on Android)
        const fd_for_poll: std.posix.socket_t = tcp_fd;
        var attempts: u32 = 0;
        const max_attempts: u32 = 100;
        while (true) : (attempts += 1) {
            if (attempts >= max_attempts) {
                std.log.err("TLS handshake failed: exceeded max retries", .{});
                return TlsError.HandshakeFailed;
            }
            const ret = c.SSL_connect(ssl);
            if (ret == 1) break;
            const err = c.SSL_get_error(ssl, ret);
            switch (err) {
                c.SSL_ERROR_WANT_READ => {
                    var pfd = [1]std.posix.pollfd{.{ .fd = fd_for_poll, .events = std.posix.POLL.IN, .revents = 0 }};
                    const pr = std.posix.poll(&pfd, 30000) catch 0;
                    if (pr == 0) {
                        std.log.err("TLS handshake failed: timeout waiting for read", .{});
                        return TlsError.HandshakeFailed;
                    }
                    continue;
                },
                c.SSL_ERROR_WANT_WRITE => {
                    var pfd = [1]std.posix.pollfd{.{ .fd = fd_for_poll, .events = std.posix.POLL.OUT, .revents = 0 }};
                    const pr = std.posix.poll(&pfd, 30000) catch 0;
                    if (pr == 0) {
                        std.log.err("TLS handshake failed: timeout waiting for write", .{});
                        return TlsError.HandshakeFailed;
                    }
                    continue;
                },
                else => {
                    std.log.err("TLS handshake failed: SSL error {d} (ret={d}, errno={d})", .{ err, ret, std.c._errno().* });
                    logOpenSslErrors();
                    return TlsError.HandshakeFailed;
                },
            }
        }

        // Log connection info
        const version = c.SSL_get_version(ssl);
        if (version) |v| {
            std.log.info("TLS connected with {s}", .{std.mem.span(v)});
        }

        // Allocate read-ahead buffer. 64KB = 4× TLS max record size, allowing
        // up to 4 full TLS records to be batched in one SSL_read call.
        const read_buf = try allocator.alloc(u8, READ_BUF_SIZE);
        errdefer allocator.free(read_buf);

        return TlsSocket{
            .allocator = allocator,
            .tcp_fd = tcp_fd,
            .ssl_ctx = ssl_ctx,
            .ssl = ssl,
            .config = config,
            .hostname_buf = hostname_buf,
            .connected = true,
            .read_buf = read_buf,
        };
    }

    fn logOpenSslErrors() void {
        var err = c.ERR_get_error();
        while (err != 0) {
            var buf: [256]u8 = undefined;
            c.ERR_error_string_n(err, &buf, buf.len);
            std.log.err("OpenSSL: {s}", .{std.mem.sliceTo(&buf, 0)});
            err = c.ERR_get_error();
        }
    }

    /// Close the connection
    pub fn close(self: *TlsSocket) void {
        if (self.connected) {
            if (self.ssl) |ssl| {
                _ = c.SSL_shutdown(ssl);
                c.SSL_free(ssl);
            }
            if (self.ssl_ctx) |ctx| {
                c.SSL_CTX_free(ctx);
            }
            if (builtin.os.tag == .windows) {
                _ = std.os.windows.ws2_32.closesocket(self.tcp_fd);
            } else {
                std.posix.close(self.tcp_fd);
            }
            self.connected = false;
            self.ssl = null;
            self.ssl_ctx = null;
        }

        self.allocator.free(self.hostname_buf);
        if (self.read_buf.len > 0) {
            self.allocator.free(self.read_buf);
            self.read_buf = "";
        }
    }

    /// Read data from the TLS connection with read-ahead buffering.
    ///
    /// When the internal read buffer has data, serves from there without calling
    /// SSL_read. When empty, issues one large SSL_read (up to READ_BUF_SIZE) to
    /// refill the buffer, then serves the requested bytes. This reduces the number
    /// of SSL_read calls from ~19 per 9-packet batch to ~1 per batch.
    ///
    /// Semantics:
    ///   N > 0          : received N bytes
    ///   0              : peer closed gracefully (TLS close_notify)
    ///   error.WouldBlock : no data right now (non-blocking, caller retry)
    ///   error.BrokenPipe : hard TLS / TCP error; connection lost
    pub fn read(self: *TlsSocket, buffer: []u8) !usize {
        if (!self.connected) return error.BrokenPipe;
        const ssl = self.ssl orelse return error.BrokenPipe;

        // Serve from read-ahead buffer if data available.
        if (self.read_buf_available > 0) {
            const to_copy = @min(buffer.len, self.read_buf_available);
            @memcpy(buffer[0..to_copy], self.read_buf[self.read_buf_offset..][0..to_copy]);
            self.read_buf_offset += to_copy;
            self.read_buf_available -= to_copy;
            return to_copy;
        }

        // Buffer empty: do one large SSL_read to refill.
        const ret = c.SSL_read(ssl, self.read_buf.ptr, @intCast(self.read_buf.len));
        if (ret <= 0) {
            const err_no = c.SSL_get_error(ssl, ret);
            switch (err_no) {
                c.SSL_ERROR_ZERO_RETURN => {
                    self.connected = false;
                    return 0;
                },
                c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => {
                    return error.WouldBlock;
                },
                else => {
                    std.log.err("TlsSocket.read: SSL_get_error={d} ret={d} errno={d}", .{ err_no, ret, std.c._errno().* });
                    logOpenSslErrors();
                    self.connected = false;
                    return error.BrokenPipe;
                },
            }
        }

        const nread = @as(usize, @intCast(ret));
        if (nread == 0) return error.BrokenPipe;

        // Refill buffer, then serve the requested bytes from it.
        self.read_buf_offset = 0;
        self.read_buf_available = nread;
        const to_copy = @min(buffer.len, nread);
        @memcpy(buffer[0..to_copy], self.read_buf[0..to_copy]);
        self.read_buf_offset += to_copy;
        self.read_buf_available -= to_copy;
        return to_copy;
    }

    /// Read with built-in poll-on-WouldBlock retry, for control-plane use
    /// where the caller expects classical blocking semantics regardless of
    /// the underlying socket mode. Returns 0 only on graceful TLS close.
    pub fn readBlocking(self: *TlsSocket, buffer: []u8) !usize {
        while (true) {
            const n = self.read(buffer) catch |err| switch (err) {
                error.WouldBlock => {
                    var pfd = [_]std.posix.pollfd{.{
                        .fd = self.tcp_fd,
                        .events = std.posix.POLL.IN,
                        .revents = 0,
                    }};
                    const pr = std.posix.poll(&pfd, 30000) catch 0;
                    if (pr == 0) return error.BrokenPipe;
                    continue;
                },
                else => return err,
            };
            return n;
        }
    }

    /// Read exactly n bytes
    pub fn readAll(self: *TlsSocket, buffer: []u8) !void {
        var index: usize = 0;
        while (index < buffer.len) {
            const n = try self.read(buffer[index..]);
            if (n == 0) return error.EndOfStream;
            index += n;
        }
    }

    /// Check if OpenSSL has buffered decrypted application data invisible to poll().
    /// Also checks the internal read-ahead buffer so the drain loop doesn't exit
    /// early when there's still data to process.
    pub fn hasPending(self: *TlsSocket) bool {
        if (self.read_buf_available > 0) return true;
        const ssl = self.ssl orelse return false;
        return c.SSL_pending(ssl) > 0;
    }

    /// DIAGNOSTIC: Returns count of decrypted bytes buffered inside OpenSSL.
    pub fn pendingBytes(self: *const TlsSocket) u32 {
        const ssl = self.ssl orelse return 0;
        const p = c.SSL_pending(ssl);
        return if (p > 0) @intCast(p) else 0;
    }

    /// DIAGNOSTIC: Returns bytes currently in the read-ahead buffer (decrypted
    /// data that has been read from OpenSSL but not yet consumed by the caller).
    /// Non-zero values prove the 64KB buffer is actively batching SSL_read calls,
    /// reducing per-packet TLS decryption overhead. Sampled in DIAG as `buf_avail`
    /// alongside `ssl_pend` and `nread` to validate the buffer code path.
    pub fn readBufAvailable(self: *const TlsSocket) u32 {
        return @intCast(self.read_buf_available);
    }

    /// DIAGNOSTIC: Returns bytes currently sitting in the kernel recv queue
    /// (data arrived in kernel buffer but not yet consumed by OpenSSL).
    /// Uses ioctl(FIONREAD) for portability across platforms and fd types
    /// (real TCP sockets, AF_UNIX socketpairs, pipes, etc.).
    ///
    /// On macOS and Linux (real TCP fd): returns kernel TCP receive buffer
    /// depth — encrypted bytes that arrived from network but haven't been
    /// read by OpenSSL's BIO. High values mean we're not draining fast enough
    /// → server's advertised window is shrinking → TCP backpressure.
    ///
    /// On iOS (AF_UNIX SOCK_STREAM socketpair via NWTCPConnection bridge):
    /// returns bytes waiting in the socketpair recv buffer — encrypted TLS
    /// data that was delivered by the TCP bridge but hasn't been consumed
    /// by OpenSSL yet. The drain loop uses this as a secondary signal:
    /// even when hasPending() is false (OpenSSL buffer empty), non-zero
    /// kernelRecvQueue() keeps the drain loop running so it pulls fresh
    /// data from the BIO instead of exiting and re-entering poll().
    pub fn kernelRecvQueue(self: *const TlsSocket) u32 {
        if (builtin.os.tag == .windows) return 0;
        var n: c_int = 0;
        const fd_int: c_int = @intCast(self.tcp_fd);
        // FIONREAD = 0x541B on Linux, 0x4004667f on Darwin (macOS/iOS) and other BSDs
        const FIONREAD: u32 = switch (builtin.os.tag) {
            .linux => 0x541B,
            .macos, .ios, .tvos, .watchos, .freebsd, .netbsd, .openbsd, .dragonfly => 0x4004667f,
            else => return 0,
        };
        const rc = std.c.ioctl(fd_int, FIONREAD, &n);
        if (rc != 0 or n < 0) return 0;
        return @intCast(n);
    }

    /// DIAGNOSTIC (macOS/iOS): Returns bytes currently in the kernel send
    /// queue (queued but not yet ACK'd / sent). High values mean we can't
    /// push outbound fast enough → our send window is full → upload
    /// backpressure / risk of SSL_write deadlock.
    ///
    /// Uses SO_NWRITE (Darwin-specific socket option) which works on both
    /// real TCP sockets and AF_UNIX socketpair fds.
    pub fn kernelSendQueue(self: *const TlsSocket) u32 {
        if (builtin.os.tag != .macos and builtin.os.tag != .ios) return 0;
        var n: c_int = 0;
        var len: u32 = @sizeOf(c_int);
        // SO_NWRITE = 0x1024 on macOS/Darwin — works on real sockets and socketpairs
        const SO_NWRITE: u32 = 0x1024;
        const fd_int: c_int = @intCast(self.tcp_fd);
        const rc = std.c.getsockopt(fd_int, std.posix.SOL.SOCKET, SO_NWRITE, &n, &len);
        if (rc != 0 or n < 0) return 0;
        return @intCast(n);
    }

    /// Write data to the TLS connection.
    ///
    /// Semantics:
    ///   N > 0          : wrote N bytes
    ///   0              : caller-supplied empty buffer
    ///   error.WouldBlock : non-blocking socket cannot accept data right now
    ///   error.BrokenPipe : hard TLS / TCP error; connection lost
    pub fn write(self: *TlsSocket, data: []const u8) !usize {
        if (!self.connected) return error.BrokenPipe;

        const ssl = self.ssl orelse return error.BrokenPipe;
        const ret = c.SSL_write(ssl, data.ptr, @intCast(data.len));

        if (ret <= 0) {
            const err = c.SSL_get_error(ssl, ret);
            switch (err) {
                c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => {
                    return error.WouldBlock;
                },
                else => {
                    self.connected = false;
                    return error.BrokenPipe;
                },
            }
        }

        return @intCast(ret);
    }

    /// Write with poll-based waiting (avoids busy spin)
    pub fn writeWithPoll(self: *TlsSocket, data: []const u8) !usize {
        if (!self.connected) return error.BrokenPipe;

        const ssl = self.ssl orelse return error.BrokenPipe;
        const ret = c.SSL_write(ssl, data.ptr, @intCast(data.len));

        if (ret <= 0) {
            const err = c.SSL_get_error(ssl, ret);
            switch (err) {
                c.SSL_ERROR_WANT_WRITE => {
                    // Wait for socket to be writable (max 1ms to avoid blocking too long)
                    var pfd = [_]std.posix.pollfd{.{
                        .fd = self.tcp_fd,
                        .events = std.posix.POLL.OUT,
                        .revents = 0,
                    }};
                    _ = std.posix.poll(&pfd, 1) catch {};
                    return 0;
                },
                c.SSL_ERROR_WANT_READ => {
                    return 0;
                },
                else => {
                    self.connected = false;
                    return error.BrokenPipe;
                },
            }
        }

        return @intCast(ret);
    }

    /// Write all data, polling for socket writability when the kernel
    /// send buffer is full. Safe on a non-blocking socket: WouldBlock from
    /// Write all data with non-blocking retry using poll(POLLOUT, 1).
    ///
    /// When the kernel send buffer is full, `SSL_write` returns `SSL_ERROR_WANT_WRITE`.
    /// We call `poll(POLLOUT, 1)` — which returns immediately on macOS when kqueue
    /// signals POLLOUT (the kernel drained enough bytes for at least one write).
    /// Write all data with non-blocking retry. When the kernel send buffer is
    /// full, SSL_write returns WANT_WRITE. Instead of spinning poll(POLLOUT, 1)
    /// internally (which starves inbound processing and causes DL collapse),
    /// we stash the remaining unwritten data and set needs_pollout=true, then
    /// return WouldBlock. The write_fn adapter catches WouldBlock and returns
    /// data.len (silent success) — the main loop drains the pending data via
    /// POLLOUT events. This eliminates inbound starvation while satisfying
    /// OpenSSL's requirement that WANT_WRITE be retried with the same pointer.
    pub fn writeAllNonBlocking(self: *TlsSocket, data: []const u8) !void {
        // If there's pending data from a previous WANT_WRITE that the main
        // loop hasn't drained yet, we can't write new data. OpenSSL requires
        // retrying WANT_WRITE with the SAME pointer before any other SSL_write.
        // The write_fn adapter catches WouldBlock and the main loop eventually
        // drains it. This SHOULD be a rare edge case during heavy burst.
        if (self.needs_pollout) {
            return error.WouldBlock;
        }
        var index: usize = 0;
        while (index < data.len) {
            const n = self.write(data[index..]) catch |err| switch (err) {
                error.WouldBlock => {
                    self.write_block_count +%= 1;
                    self.pending_outbound = data[index..];
                    self.needs_pollout = true;
                    return error.WouldBlock;
                },
                else => return err,
            };
            if (n == 0) return error.BrokenPipe;
            index += n;
        }
    }

    /// Retry a pending outbound write. Returns true when fully written.
    /// Called from main loop when POLLOUT fires on this socket.
    ///
    /// Loops internally to drain as many TLS records as possible in a single
    /// call. Without the loop, a 100KB pending buffer with 16KB TLS records
    /// takes 6+ poll(1ms) iterations to drain — and during every drain
    /// iteration, TUN reads are silently dropped (needs_pollout=true blocks
    /// writeAllNonBlocking). Each dropped TUN read is lost UL data. The loop
    /// eliminates the per-record iteration cost.
    pub fn retryPendingWrite(self: *TlsSocket) !bool {
        while (self.pending_outbound.len > 0) {
            const n = self.write(self.pending_outbound) catch |err| switch (err) {
                error.WouldBlock => return false, // sndbuf full, retry next iter
                else => |e| {
                    self.pending_outbound = "";
                    self.needs_pollout = false;
                    return e;
                },
            };
            if (n == 0) {
                self.pending_outbound = "";
                self.needs_pollout = false;
                return error.BrokenPipe;
            }
            if (n >= self.pending_outbound.len) {
                self.pending_outbound = "";
                self.needs_pollout = false;
                return true;
            }
            // Partial write — advance and loop to write the next TLS record
            self.pending_outbound = self.pending_outbound[n..];
        }
        return true;
    }

    /// Switch the underlying TCP socket to non-blocking mode.
    /// Call this AFTER the TLS handshake has completed and BEFORE entering
    /// the data-plane poll loop. Once non-blocking:
    ///   - read()  returns error.WouldBlock when no data is available
    ///   - write() returns error.WouldBlock when kernel sndbuf is full
    /// Use writeAllNonBlocking() for sends that must complete atomically.
    pub fn setNonBlocking(self: *TlsSocket) !void {
        if (builtin.os.tag == .windows) {
            const ws2 = std.os.windows.ws2_32;
            var nonblocking: c_ulong = 1;
            _ = ws2.ioctlsocket(self.tcp_fd, @as(i32, @bitCast(@as(u32, 0x8004667e))), &nonblocking);
        } else {
            const O_NONBLOCK: usize = 0x0004;
            const flags = try std.posix.fcntl(self.tcp_fd, std.posix.F.GETFL, 0);
            _ = try std.posix.fcntl(self.tcp_fd, std.posix.F.SETFL, flags | O_NONBLOCK);
        }
    }

    /// Write all data (blocking until complete)
    pub fn writeAll(self: *TlsSocket, data: []const u8) !void {
        var index: usize = 0;
        while (index < data.len) {
            const n = try self.write(data[index..]);
            if (n == 0) continue;
            index += n;
        }
    }

    /// Check if connection is still alive
    pub fn isConnected(self: *const TlsSocket) bool {
        return self.connected;
    }

    /// Get the underlying socket
    pub fn getFd(self: *const TlsSocket) std.posix.socket_t {
        return self.tcp_fd;
    }

    /// Remove read/write timeouts set during connect phase and configure
    /// socket for the poll-based data loop. Matches C SoftEther's
    /// SetTimeout(sock, INFINITE) after connect.
    ///
    /// SO_SNDBUF policy:
    ///   - NONE → macOS autotunes to multi-MB → DL ACKs queue behind UL data
    ///     in TLS egress for 800-1400ms → server sees ACK loss → DL collapses
    ///     to 5-7 Mbps with 1100ms RTT spikes (Cloudflare-confirmed).
    ///   - 512KB cap (Cycle 10) → still queues ~50ms of DL ACKs; UL capped.
    ///   - 128KB cap → bounds DL-ACK queueing latency to ~10ms at 100 Mbps
    ///     egress while still allowing autotune RWND headroom on receive.
    ///     This is the latency vs throughput tradeoff for single-thread
    ///     poll-driven encap loop. Long-term fix is split-thread I/O.
    /// SO_RCVBUF policy:
    ///   - NONE → kernel autotune. In practice on macOS/iOS over TLS the
    ///     advertised RWND grows VERY slowly because the read pattern is
    ///     "drain-to-empty then idle" (we read everything ssl_pending says
    ///     is there, then poll). Autotune sees small instantaneous queue
    ///     depth (nread_max=8KB observed even mid-DL) and keeps RWND tiny.
    ///     Server's BDP-bound send cap = RWND/RTT → 8KB/180ms ≈ 360 kbps.
    ///     This explains DL stuck at 1-2 Mbps even though the loop is idle.
    ///   - 4MB explicit → forces a large advertised RWND from the start.
    ///     At 180ms RTT, BDP = 4MB → up to ~178 Mbps single-flow DL ceiling.
    ///     Memory cost is bounded (one TLS conn → 4MB kernel rcvbuf).
    pub fn clearTimeouts(self: *TlsSocket) void {
        TcpSocket.setReadTimeout(self.tcp_fd, 0) catch {};
        TcpSocket.setWriteTimeout(self.tcp_fd, 0) catch {};

        // Enable TCP keepalive
        const keepalive: u32 = 1;
        std.posix.setsockopt(self.tcp_fd, std.posix.SOL.SOCKET, std.posix.SO.KEEPALIVE, std.mem.asBytes(&keepalive)) catch {};

        // SO_SNDBUF sizing:
        //   - 2MB: BDP at 90 Mbps / 180ms RTT = 2.0MB. Matches the sendq
        //     throttle thresholds (critical=1.5MB = 75%). When the throttle
        //     limits batch to 1 at 1.5MB, the buffer has only 0.5MB headroom
        //     to fill before hitting the ceiling → Server cwnd never fully
        //     collapses → UL oscillates in a narrow 20-50→80 Mbps band
        //     instead of violent 28-96 Mbps plunges.
        //   - 4MB: 2.5MB headroom between throttle (1.5MB) and ceiling (4MB)
        //     → buffer fills completely → server cwnd collapses to zero →
        //     10+ second drain at 3 Mbps ACK rate → violent TCP sawtooth.
        //     The original deadlock (poll(0) busy-spin) is now fixed via
        //     needs_pollout poll timeout, so 4MB no longer causes permanent
        //     DL collapse — but the bufferbloat-induced cwnd sawtooth remains.
        //   - Kernel does NOT double SO_SNDBUF on macOS (measured via SO_NWRITE).
        //
        // iOS special case: TCP_NOTSENT_LOWAT is NOT supported on iOS direct
        // POSIX sockets (returns error.InvalidProtocolOption). Without it,
        // DL TCP ACKs can be queued behind ~1MB of UL data in the kernel send
        // buffer, delaying server ACK delivery and collapsing DL throughput.
        // Reducing SO_SNDBUF to 512KB on iOS bounds the queueing delay to
        // ~80ms at 50 Mbps UL (vs ~320ms at 2MB), giving the server enough
        // ACK clock to maintain DL congestion window. The 512KB cap limits
        // UL BDP to ~25 Mbps at 166ms RTT — acceptable since UL already
        // hits 48-53 Mbps through the dual socketpair + Swift pump (the
        // actual bottleneck is the tunnel protocol's compression/crypto).
        const snd_cap: u32 = 2 * 1024 * 1024;
        std.posix.setsockopt(self.tcp_fd, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&snd_cap)) catch {};

        // SO_RCVBUF: forces a large advertised RWND from the start so the
        // server isn't BDP-capped by tiny autotune values.
        //
        // Platform-specific tuning:
        //
        // macOS (and Linux/desktop): 4 MB. Drain via utun fd is very fast
        //   (100+ Mbps), so a big buffer just enables high-BDP flows. At
        //   180ms RTT, 4MB → up to ~178 Mbps single-flow DL ceiling.
        //
        // iOS: 1 MB. Tradeoff calibrated empirically:
        //   4 MB → DL 4.4 Mbps but ping_DL=2426ms (massive bufferbloat
        //          in NEPacketTunnelFlow.writePackets opaque queue)
        //   256 KB → DL 1.57 Mbps with ping_DL=1351ms (BDP cap too low,
        //          single-flow throughput collapses)
        //   1 MB → expected DL ~10-20 Mbps with ping_DL ~600-900ms
        //          Single-flow BDP at 200ms RTT = 40 Mbps cap.
        // The fundamental problem is writePackets has no completion API,
        // so we can't true-backpressure. The outer rcvbuf is our only
        // throttle on inbound rate. Cap = (rcvbuf / inner-RTT-no-bloat).
        const rcv_cap: u32 = if (@import("builtin").target.os.tag == .ios) 1024 * 1024 else 4 * 1024 * 1024;
        std.posix.setsockopt(self.tcp_fd, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&rcv_cap)) catch {};
    }

    /// Get the hostname this socket connected to
    pub fn getHostname(self: *const TlsSocket) []const u8 {
        return self.hostname_buf;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "TlsConfig defaults" {
    const config = TlsConfig{};
    try testing.expect(config.verify_certificate);
    try testing.expectEqual(TlsVersion.tls_1_2, config.min_version);
    try testing.expectEqual(@as(u32, 30000), config.timeout_ms);
    try testing.expect(!config.allow_self_signed);
}

test "TlsSocket structure" {
    // Test that the structure compiles correctly
    // Actual connection tests require a server
    const T = TlsSocket;
    try testing.expect(@sizeOf(T) > 0);
}
