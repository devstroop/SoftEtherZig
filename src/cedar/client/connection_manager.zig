//! Multi-TCP Connection Manager for SoftEther VPN
//!
//! Manages multiple parallel TCP/TLS connections to the VPN server.
//! Supports direction-aware I/O for half-connection mode and
//! least-loaded send selection for load balancing.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const tls = @import("../../mayaqua/network/tls.zig");
const protocol_tunnel = @import("../protocol/tunnel.zig");
const TunnelConnection = protocol_tunnel.TunnelConnection;

/// Maximum number of TCP connections per session (SoftEther protocol limit)
pub const MAX_CONNECTIONS: usize = 32;

/// TCP connection direction (matches SoftEther protocol values)
pub const TcpDirection = enum(u8) {
    bidirectional = 0, // TCP_BOTH
    server_to_client = 1, // TCP_SERVER_TO_CLIENT
    client_to_server = 2, // TCP_CLIENT_TO_SERVER

    pub fn canSend(self: TcpDirection) bool {
        return self != .server_to_client;
    }

    pub fn canRecv(self: TcpDirection) bool {
        return self != .client_to_server;
    }
};

/// A single managed TCP connection with its tunnel and metadata
pub const ManagedConnection = struct {
    tls_socket: tls.TlsSocket,
    tunnel: TunnelConnection,
    direction: TcpDirection,
    is_primary: bool,
    pending_bytes: u64,
    last_send_time: i64,
    established: bool,
    /// Original direction before DHCP override (for restoring)
    saved_direction: TcpDirection,
};

/// Manages multiple TCP connections to the VPN server
pub const ConnectionManager = struct {
    allocator: Allocator,
    connections: [MAX_CONNECTIONS]?ManagedConnection,
    count: u8,
    max_connections: u8,
    half_connection: bool,
    use_compress: bool,
    dhcp_override_active: bool,

    /// Maps poll fd index → connection index (for reverse lookup after poll)
    poll_conn_map: [MAX_CONNECTIONS]u8,
    poll_conn_count: usize,

    pub fn init(
        allocator: Allocator,
        max_connections: u8,
        half_connection: bool,
        use_compress: bool,
    ) ConnectionManager {
        return .{
            .allocator = allocator,
            .connections = [_]?ManagedConnection{null} ** MAX_CONNECTIONS,
            .count = 0,
            .max_connections = max_connections,
            .half_connection = half_connection,
            .use_compress = use_compress,
            .dhcp_override_active = false,
            .poll_conn_map = undefined,
            .poll_conn_count = 0,
        };
    }

    pub fn deinit(self: *ConnectionManager) void {
        for (&self.connections) |*slot| {
            if (slot.*) |*conn| {
                conn.tunnel.deinit();
                conn.tls_socket.close();
                slot.* = null;
            }
        }
        self.count = 0;
    }

    /// Add a connection to the manager. Returns the connection index.
    pub fn addConnection(
        self: *ConnectionManager,
        sock: tls.TlsSocket,
        direction: TcpDirection,
        is_primary: bool,
    ) !u8 {
        // Find empty slot
        for (&self.connections, 0..) |*slot, i| {
            if (slot.* == null) {
                const managed = ManagedConnection{
                    .tls_socket = sock,
                    .tunnel = undefined, // initialized below
                    .direction = direction,
                    .is_primary = is_primary,
                    .pending_bytes = 0,
                    .last_send_time = 0,
                    .established = true,
                    .saved_direction = direction,
                };

                // Create TunnelConnection wrapping this socket's I/O.
                // We need the pointer to be stable, so we init the tunnel
                // with the socket that's already stored in the ManagedConnection.
                // The tunnel's context pointer will point to the tls_socket field
                // within the ManagedConnection stored in our fixed array.
                slot.* = managed;

                // Now that the ManagedConnection is in the array, set up the tunnel
                // with a pointer to the socket in its final location.
                const conn_ptr = &(slot.*.?);
                conn_ptr.tunnel = TunnelConnection.init(
                    self.allocator,
                    @ptrCast(&conn_ptr.tls_socket),
                    struct {
                        fn read(ctx: *anyopaque, buf: []u8) anyerror!usize {
                            const s = @as(*tls.TlsSocket, @ptrCast(@alignCast(ctx)));
                            return s.read(buf);
                        }
                    }.read,
                    struct {
                        fn write(ctx: *anyopaque, data: []const u8) anyerror!usize {
                            const s = @as(*tls.TlsSocket, @ptrCast(@alignCast(ctx)));
                            // Atomic-from-caller's-view write on a non-blocking
                            // socket: WANT_WRITE is handled by a short
                            // poll(POLLOUT) inside writeAllNonBlocking.
                            try s.writeAllNonBlocking(data);
                            return data.len;
                        }
                    }.write,
                );
                conn_ptr.tunnel.use_compress = self.use_compress;
                conn_ptr.tunnel.initCompression();

                // Switch socket to non-blocking now that the TLS handshake
                // and any per-connection RPC has completed. The tunnel state
                // machine handles error.WouldBlock from the read adapter.
                conn_ptr.tls_socket.setNonBlocking() catch |e|
                    std.log.warn("setNonBlocking failed for conn {d}: {}", .{ i, e });

                self.count += 1;
                std.log.info("Added connection {d} (direction={s}, primary={}, total={d})", .{
                    i,
                    @tagName(direction),
                    is_primary,
                    self.count,
                });
                return @intCast(i);
            }
        }
        return error.TooManyConnections;
    }

    /// Remove a connection by index. Closes its TLS socket.
    pub fn removeConnection(self: *ConnectionManager, index: u8) void {
        if (index >= MAX_CONNECTIONS) return;
        if (self.connections[index]) |*conn| {
            std.log.warn("Removing connection {d} (primary={}, remaining={d})", .{
                index, conn.is_primary, self.count -| 1,
            });
            conn.tunnel.deinit();
            conn.tls_socket.close();
            self.connections[index] = null;
            self.count -|= 1;
        }
    }

    /// Get the primary connection (index 0 typically)
    pub fn getPrimary(self: *ConnectionManager) ?*ManagedConnection {
        for (&self.connections) |*slot| {
            if (slot.*) |*conn| {
                if (conn.is_primary) return conn;
            }
        }
        return null;
    }

    /// Build poll fd array for recv-capable connections.
    /// Returns number of fds written. Populates poll_conn_map internally.
    pub fn buildPollFds(self: *ConnectionManager, out_fds: []std.posix.pollfd) usize {
        var count: usize = 0;
        for (&self.connections, 0..) |*slot, i| {
            if (slot.*) |*conn| {
                if (!conn.established) continue;
                if (!conn.direction.canRecv()) continue;
                if (count >= out_fds.len) break;

                out_fds[count] = .{
                    .fd = conn.tls_socket.getFd(),
                    .events = std.posix.POLL.IN,
                    .revents = 0,
                };
                self.poll_conn_map[count] = @intCast(i);
                count += 1;
            }
        }
        self.poll_conn_count = count;
        return count;
    }

    /// Select the best connection for sending (least-loaded, send-capable).
    pub fn selectSendConnection(self: *ConnectionManager) ?*ManagedConnection {
        var best: ?*ManagedConnection = null;
        var best_load: u64 = std.math.maxInt(u64);

        for (&self.connections) |*slot| {
            if (slot.*) |*conn| {
                if (!conn.established) continue;
                if (!conn.direction.canSend()) continue;
                if (conn.pending_bytes < best_load) {
                    best_load = conn.pending_bytes;
                    best = conn;
                }
            }
        }
        return best;
    }

    /// Iterate readable connections after poll(). Calls the callback for each
    /// connection that has data ready. Returns the index of a dead connection
    /// (or null if all healthy).
    pub fn forEachReadable(
        self: *ConnectionManager,
        poll_fds: []const std.posix.pollfd,
    ) ReadableIterator {
        return .{
            .manager = self,
            .poll_fds = poll_fds,
            .current = 0,
        };
    }

    pub const ReadableIterator = struct {
        manager: *ConnectionManager,
        poll_fds: []const std.posix.pollfd,
        current: usize,

        pub fn next(self: *ReadableIterator) ?*ManagedConnection {
            while (self.current < self.manager.poll_conn_count) {
                const idx = self.current;
                self.current += 1;

                if (idx >= self.poll_fds.len) break;

                const conn_idx = self.manager.poll_conn_map[idx];
                if (self.manager.connections[conn_idx]) |*conn| {
                    if (!conn.established) continue;
                    // A connection is readable if ANY of three sources has data:
                    //   1. poll() flagged POLLIN (fresh kernel readability), OR
                    //   2. OpenSSL has decrypted application data buffered that
                    //      poll() can't see (hasPending), OR
                    //   3. the kernel TCP recv buffer has undrained bytes
                    //      (kernelRecvQueue) that SSL_read hasn't pulled in yet.
                    //
                    // (3) is essential: the data loop's skip_poll optimization
                    // SKIPS poll() whenever any connection has kernelRecvQueue>0,
                    // which leaves `revents` stale (0). Without checking the
                    // kernel queue directly here, such a connection is never
                    // selected for draining — its kernel buffer grows unbounded
                    // and nothing is ever received (the half-connection S2C
                    // deadlock). This mirrors the single-conn tls_readable check.
                    const poll_ready = (self.poll_fds[idx].revents & std.posix.POLL.IN) != 0;
                    const ssl_pending = conn.tls_socket.hasPending();
                    const kernel_ready = conn.tls_socket.kernelRecvQueue() > 0;
                    if (!poll_ready and !ssl_pending and !kernel_ready) continue;
                    return conn;
                }
            }
            return null;
        }
    };

    /// Send keepalive on all send-capable connections (C: Connection.c:1037-1044).
    /// In half-connection mode, S2C connections are recv-only — don't write to them.
    pub fn sendKeepaliveAll(self: *ConnectionManager) void {
        for (&self.connections) |*slot| {
            if (slot.*) |*conn| {
                if (conn.established and conn.direction.canSend()) {
                    conn.tunnel.sendKeepalive() catch {};
                }
            }
        }
    }

    /// Temporarily make primary connection bidirectional for DHCP.
    /// In half-connection mode, primary is C2S-only, but DHCP needs
    /// to also receive on the primary before S2C connections are ready.
    pub fn enableDhcpBidirectional(self: *ConnectionManager) void {
        if (!self.half_connection or self.dhcp_override_active) return;
        if (self.getPrimary()) |primary| {
            primary.saved_direction = primary.direction;
            primary.direction = .bidirectional;
            self.dhcp_override_active = true;
            std.log.debug("DHCP override: primary connection set to bidirectional", .{});
        }
    }

    /// Restore primary connection direction after DHCP completes.
    pub fn restoreDhcpDirections(self: *ConnectionManager) void {
        if (!self.dhcp_override_active) return;
        if (self.getPrimary()) |primary| {
            primary.direction = primary.saved_direction;
            self.dhcp_override_active = false;
            std.log.debug("DHCP override restored: primary direction={s}", .{@tagName(primary.direction)});
        }
    }

    /// Decay pending bytes on all connections (call each poll iteration).
    /// Decay rate: ~10 MB/s = ~10 bytes per microsecond.
    /// With 1ms poll timeout, that's ~10000 bytes per iteration.
    pub fn decayPendingBytes(self: *ConnectionManager) void {
        const decay: u64 = 10000; // ~10KB per ms poll cycle
        for (&self.connections) |*slot| {
            if (slot.*) |*conn| {
                conn.pending_bytes -|= decay;
            }
        }
    }

    /// Check for and remove dead connections. Returns true if primary died.
    pub fn cleanupDead(self: *ConnectionManager) bool {
        var primary_dead = false;
        for (&self.connections, 0..) |*slot, i| {
            if (slot.*) |*conn| {
                if (!conn.established) {
                    if (conn.is_primary) {
                        primary_dead = true;
                    }
                    self.removeConnection(@intCast(i));
                }
            }
        }
        return primary_dead;
    }

    /// Check if we need more connections
    pub fn needsMoreConnections(self: *const ConnectionManager) bool {
        return self.count < self.max_connections;
    }

    /// Prepare all sockets for the poll-based data loop.
    /// Removes blocking read/write timeouts that were set during the
    /// connect/handshake phase — these would cause SSL_read to fail
    /// on recv-only (S2C) sockets in half-connection mode if no data
    /// arrives within the timeout period.
    /// Matches C behavior: SetTimeout(sock, INFINITE) after additional_connect.
    pub fn prepareForDataLoop(self: *ConnectionManager) void {
        for (&self.connections) |*slot| {
            if (slot.*) |*conn| {
                conn.tls_socket.clearTimeouts();
            }
        }
        std.log.debug("Cleared socket timeouts for data loop ({d} connections)", .{self.count});
    }
};

// ============================================================================
// Tests
// ============================================================================

test "TcpDirection canSend/canRecv" {
    try std.testing.expect(TcpDirection.bidirectional.canSend());
    try std.testing.expect(TcpDirection.bidirectional.canRecv());
    try std.testing.expect(TcpDirection.client_to_server.canSend());
    try std.testing.expect(!TcpDirection.client_to_server.canRecv());
    try std.testing.expect(!TcpDirection.server_to_client.canSend());
    try std.testing.expect(TcpDirection.server_to_client.canRecv());
}

test "ConnectionManager init" {
    var cm = ConnectionManager.init(std.testing.allocator, 4, false, false);
    defer cm.deinit();

    try std.testing.expectEqual(@as(u8, 0), cm.count);
    try std.testing.expectEqual(@as(u8, 4), cm.max_connections);
    try std.testing.expect(!cm.half_connection);
    try std.testing.expect(cm.needsMoreConnections());
}
