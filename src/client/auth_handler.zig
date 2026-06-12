//! Authentication handler for the SoftEther VPN client.
//!
//! Extracted from `vpn_client.zig` so the client orchestration file stays
//! focused on state-machine and lifecycle code. Owns the full handshake
//! sequence: signature → hello → auth → optional cluster redirect → ticket
//! re-auth → server-overrides apply → UDP-acceleration setup.
//!
//! Entry point: `run(client) !void`. Operates on `*VpnClient` directly
//! (mutates `auth_session_key`, `auth_hello_random`, `bulk_keys`, `udp_accel`,
//! `tls_socket`, `server_ip`, `effective_server_*`, and `config.*` server-
//! overridable fields). Returns `ClientError` on failure.

const std = @import("std");
const net = std.Io.net;

const tls = @import("../net/net.zig").tls;
const softether_proto = @import("../protocol/softether_protocol.zig");
const pack_mod = @import("../protocol/pack.zig");
const udp_accel_mod = @import("../net/udp_accel.zig");
const core = @import("../core/mod.zig");
const formatAddress = core.formatAddressForHost;

const vpn_client = @import("vpn_client.zig");
const VpnClient = vpn_client.VpnClient;
const ClientError = vpn_client.ClientError;
const makeProtoWriter = vpn_client.makeProtoWriter;
const makeProtoReader = vpn_client.makeProtoReader;

/// Drive the SoftEther handshake to completion. On success the client's
/// session state (`auth_session_key`, `auth_hello_random`, server-applied
/// session params, optional UDP acceleration) is ready for
/// `establishSession`. On failure the caller is responsible for setting
/// `disconnect_reason` and transitioning state — this function only returns
/// the error code.
pub fn run(client: *VpnClient) !void {
    // Get the TLS socket for communication
    const sock = &(client.tls_socket orelse return ClientError.ConnectionFailed);

    // Create protocol writer and reader wrappers for TLS socket
    const writer = makeProtoWriter(sock);
    const reader = makeProtoReader(sock);

    // Format server IP as string for HTTP Host header (like C code does)
    var ip_str_buf: [48]u8 = undefined;
    const host_for_http = if (client.server_ip) |addr| formatAddress(addr, &ip_str_buf) else client.config.server_host;

    std.log.debug("Uploading protocol signature...", .{});

    // Step 1: Upload signature (WaterMark)
    softether_proto.uploadSignature(client.allocator, writer, host_for_http) catch |err| {
        std.log.err("Failed to upload signature: {}", .{err});
        return ClientError.ProtocolError;
    };

    std.log.debug("Downloading server hello...", .{});

    // Step 2: Download Hello (get server random challenge)
    var hello = softether_proto.downloadHello(client.allocator, reader) catch |err| {
        std.log.err("Failed to download hello: {}", .{err});
        return ClientError.ProtocolError;
    };
    defer hello.deinit(client.allocator);

    std.log.debug("Building authentication request...", .{});

    // Generate bulk encryption keys for UDP acceleration
    var bulk_keys_storage: softether_proto.UdpBulkKeys = if (client.config.udp_acceleration)
        softether_proto.UdpBulkKeys.generate()
    else
        undefined;
    const bulk_keys_ptr: ?*const softether_proto.UdpBulkKeys = if (client.config.udp_acceleration)
        &bulk_keys_storage
    else
        null;
    if (client.config.udp_acceleration) {
        client.bulk_keys = bulk_keys_storage;
    }

    // Step 3: Build and upload auth
    const session_opts = softether_proto.SessionOptions{
        .max_connection = client.config.max_connections,
        .half_connection = client.config.half_connection,
        .qos = client.config.qos,
        .use_encrypt = client.config.use_encrypt,
        .use_compress = client.config.use_compress,
    };

    const auth_data = switch (client.config.auth) {
        .password => |p| blk: {
            if (p.is_hashed) {
                // Password is pre-hashed (base64 encoded), decode and use directly
                break :blk softether_proto.buildPasswordAuthWithHash(
                    client.allocator,
                    p.username,
                    p.password, // base64-encoded hash
                    client.config.hub_name,
                    &hello.random,
                    client.config.udp_acceleration,
                    bulk_keys_ptr,
                    session_opts,
                ) catch return ClientError.OutOfMemory;
            } else {
                // Password is plain text, hash it first
                break :blk softether_proto.buildPasswordAuth(
                    client.allocator,
                    p.username,
                    p.password,
                    client.config.hub_name,
                    &hello.random,
                    client.config.udp_acceleration,
                    bulk_keys_ptr,
                    session_opts,
                ) catch return ClientError.OutOfMemory;
            }
        },
        .anonymous => softether_proto.buildAnonymousAuth(
            client.allocator,
            client.config.hub_name,
            client.config.udp_acceleration,
            bulk_keys_ptr,
            session_opts,
        ) catch return ClientError.OutOfMemory,
        .certificate => |cert| softether_proto.buildCertificateAuth(
            client.allocator,
            cert.cert_data,
            cert.key_data,
            client.config.hub_name,
            &hello.random,
            client.config.udp_acceleration,
            bulk_keys_ptr,
            session_opts,
        ) catch return ClientError.AuthenticationFailed,
    };
    defer client.allocator.free(auth_data);

    std.log.debug("Uploading authentication...", .{});

    // Step 4: Upload auth and get result (use IP address for Host header like C code)
    var auth_result = softether_proto.uploadAuth(
        client.allocator,
        writer,
        reader,
        host_for_http,
        auth_data,
    ) catch |err| {
        std.log.err("Failed to upload auth: {}", .{err});
        return ClientError.AuthenticationFailed;
    };
    defer auth_result.deinit(client.allocator);

    if (!auth_result.success) {
        std.log.err("Authentication failed: code {d}", .{auth_result.error_code});
        if (auth_result.error_message) |msg| {
            std.log.err("Error: {s}", .{msg});
        }
        return ClientError.AuthenticationFailed;
    }

    // Check for redirect (cluster server setup)
    if (auth_result.redirect) |redirect| {
        return runRedirect(client, redirect, bulk_keys_ptr, session_opts);
    }

    // Store session key and server challenge for session encryption
    if (auth_result.session_key) |key| {
        client.auth_session_key = key;
        client.auth_hello_random = hello.random;
    }

    // Apply server-overridden session parameters (C: Protocol.c:4720-4741)
    applyServerOverrides(client, auth_result);

    // Initialize UDP acceleration if server supports it
    if (auth_result.udp_accel_enabled and client.config.udp_acceleration) {
        startUdpAcceleration(client, auth_result);
    }

    std.log.info("Authentication successful!", .{});
}

/// Handle a cluster-redirect response: ack the redirect on the current
/// connection, dial the redirect IP (with fallback to the original server),
/// then re-run signature → hello → ticket auth on the new connection.
fn runRedirect(
    client: *VpnClient,
    redirect: softether_proto.RedirectInfo,
    bulk_keys_ptr: ?*const softether_proto.UdpBulkKeys,
    session_opts: softether_proto.SessionOptions,
) !void {
    std.log.debug("Redirecting to data server...", .{});

    // Store the ticket for redirect auth
    const ticket = redirect.ticket;
    const redirect_ip = redirect.ip;
    const redirect_port = redirect.port;

    // CRITICAL: Send empty pack to acknowledge redirect before disconnecting
    // This tells the controller we received the redirect info
    std.log.debug("Sending redirect acknowledgment...", .{});
    var empty_pack = pack_mod.Pack.init(client.allocator);
    defer empty_pack.deinit();
    const empty_data = empty_pack.toBytes(client.allocator) catch {
        std.log.err("Failed to serialize empty pack", .{});
        return ClientError.ProtocolError;
    };
    defer client.allocator.free(empty_data);

    // Send via HTTP POST
    const current_sock = &(client.tls_socket orelse return ClientError.ConnectionFailed);
    const ack_writer = makeProtoWriter(current_sock);

    // Get current host for HTTP header
    var current_ip_buf: [48]u8 = undefined;
    const current_host = if (client.server_ip) |addr| formatAddress(addr, &current_ip_buf) else client.config.server_host;

    softether_proto.sendHttpPost(client.allocator, ack_writer, current_host, empty_data) catch {
        std.log.err("Failed to send redirect ack", .{});
        return ClientError.ProtocolError;
    };

    // Wait a moment for the server to process the redirect
    {
        var ts: std.c.timespec = .{ .sec = @intCast(@divFloor(100 * std.time.ns_per_ms, std.time.ns_per_s)), .nsec = @intCast(@mod(100 * std.time.ns_per_ms, std.time.ns_per_s)) };
        _ = std.c.nanosleep(&ts, null);
    }

    // Close current connection
    if (client.tls_socket) |*old_sock| {
        old_sock.close();
        client.tls_socket = null;
    }

    // Try redirect IP first, then fallback to original server IP.
    // Redirects are IPv4-only in the current protocol (RedirectInfo.ip is u32).
    var connected = false;
    var actual_ip: u32 = redirect_ip;
    var last_connect_error: ?anyerror = null;
    // True when we land on the original server because the redirect target
    // was unreachable. The ticket we received is only valid for the redirect
    // target, so ticket auth will almost certainly fail on the original.
    var used_fallback_after_redirect_unreachable = false;

    const original = blk: {
        if (client.server_ip) |srv| {
            switch (srv) {
                .ip4 => |v4| break :blk @as(u32, @bitCast(v4.bytes)),
                .ip6 => {},
            }
        }
        break :blk redirect_ip;
    };

    for ([_]u32{ redirect_ip, original }) |try_ip| {
        var try_ip_str: [48]u8 = undefined;
        const try_ip_bytes: [4]u8 = @bitCast(try_ip);
        const addr_for_fmt = net.IpAddress{
            .ip4 = net.Ip4Address{ .bytes = try_ip_bytes, .port = 0 },
        };
        const try_hostname = formatAddress(addr_for_fmt, &try_ip_str);

        if (try_ip == redirect_ip) {
            std.log.debug("Connecting to redirect server: {s}:{d}", .{ try_hostname, redirect_port });
        } else {
            std.log.info("Redirect server unreachable, trying original server: {s}:{d}", .{ try_hostname, redirect_port });
        }

        const redirect_tls_config = tls.TlsConfig{
            .verify_certificate = client.config.verify_certificate,
            .allow_self_signed = !client.config.verify_certificate,
            .timeout_ms = client.config.connect_timeout_ms,
            .client_cert_pem = switch (client.config.auth) {
                .certificate => |cert| cert.cert_data,
                else => null,
            },
            .client_key_pem = switch (client.config.auth) {
                .certificate => |cert| cert.key_data,
                else => null,
            },
            // Use the original server hostname for SNI, not the
            // redirect IP literal. Load balancers routing on SNI
            // will drop connections with an IP as SNI.
            .sni_hostname = client.config.server_host,
            .proxy = client.config.proxy,
        };

        client.tls_socket = tls.TlsSocket.connect(
            client.allocator,
            try_hostname,
            redirect_port,
            redirect_tls_config,
        ) catch |err| {
            last_connect_error = err;
            std.log.warn("Failed to connect to {s}:{d}: {}", .{ try_hostname, redirect_port, err });
            continue;
        };

        connected = true;
        actual_ip = try_ip;
        used_fallback_after_redirect_unreachable = (try_ip != redirect_ip);
        break;
    }

    if (!connected) {
        // Specific message for the most common transient failure mode: the
        // redirect target's backend went down briefly. Operators / users can
        // act on this (wait + retry) instead of treating it as a credentials
        // problem.
        const rip = @as([4]u8, @bitCast(redirect_ip));
        const is_unreachable = if (last_connect_error) |e| e == error.AddressNotAvailable else false;
        if (is_unreachable) {
            std.log.err(
                "Redirect target {d}.{d}.{d}.{d}:{d} is UNREACHABLE (AddressNotAvailable). " ++
                    "This is usually a transient infrastructure issue — the VPN server's data " ++
                    "backend is offline or unreachable from this network. Wait a few minutes " ++
                    "and retry. If it persists, the backend may be down for maintenance.",
                .{ rip[0], rip[1], rip[2], rip[3], redirect_port },
            );
        } else {
            std.log.err("Failed to connect to any redirect server (last error: {?})", .{last_connect_error});
        }
        return ClientError.ConnectionFailed;
    }

    if (used_fallback_after_redirect_unreachable) {
        const rip = @as([4]u8, @bitCast(redirect_ip));
        std.log.warn(
            "Redirect target {d}.{d}.{d}.{d}:{d} was unreachable; connected to original server instead. " ++
                "Ticket auth that follows is likely to fail because the ticket is bound to the redirect target. " ++
                "If ticket auth fails with code 9, the redirect target's backend is down — not a credentials issue.",
            .{ rip[0], rip[1], rip[2], rip[3], redirect_port },
        );
    }

    // Update server IP to what we actually connected to
    const actual_ip_bytes: [4]u8 = @bitCast(actual_ip);
    const actual_addr = net.IpAddress{
        .ip4 = net.Ip4Address{ .bytes = actual_ip_bytes, .port = 0 },
    };
    client.server_ip = actual_addr;
    client.effective_server_ip = actual_addr;
    client.effective_server_port = redirect_port;

    // Get username for ticket auth
    const username = switch (client.config.auth) {
        .password => |p| p.username,
        .anonymous => "anonymous",
        .certificate => "certificate",
    };

    // Redo authentication with ticket
    const redirect_sock = &(client.tls_socket orelse return ClientError.ConnectionFailed);
    const redirect_writer = makeProtoWriter(redirect_sock);
    const redirect_reader = makeProtoReader(redirect_sock);

    // Format actual connected IP for HTTP Host header
    var redirect_ip_buf: [48]u8 = undefined;
    const redirect_host = formatAddress(actual_addr, &redirect_ip_buf);

    // Upload signature to redirect server
    softether_proto.uploadSignature(client.allocator, redirect_writer, redirect_host) catch |err| {
        std.log.err("Failed to upload signature to redirect server: {}", .{err});
        return ClientError.AuthenticationFailed;
    };

    // Download hello from redirect server
    var redirect_hello = softether_proto.downloadHello(client.allocator, redirect_reader) catch |err| {
        std.log.err("Failed to download hello from redirect server: {}", .{err});
        return ClientError.AuthenticationFailed;
    };
    defer redirect_hello.deinit(client.allocator);

    // Build ticket auth
    const ticket_auth_data = softether_proto.buildTicketAuth(
        client.allocator,
        client.config.hub_name,
        username,
        &ticket,
        client.config.udp_acceleration,
        bulk_keys_ptr,
        session_opts,
    ) catch return ClientError.OutOfMemory;
    defer client.allocator.free(ticket_auth_data);

    // Upload ticket auth
    var ticket_auth_result = softether_proto.uploadAuth(
        client.allocator,
        redirect_writer,
        redirect_reader,
        redirect_host,
        ticket_auth_data,
    ) catch |err| {
        std.log.err("Failed to upload ticket auth: {}", .{err});
        return ClientError.AuthenticationFailed;
    };
    defer ticket_auth_result.deinit(client.allocator);

    if (!ticket_auth_result.success) {
        if (used_fallback_after_redirect_unreachable) {
            // The ticket was issued by the redirect target. We couldn't reach
            // it and connected to the original instead — the original
            // (typically a load balancer) doesn't honour tickets meant for a
            // specific backend. Surface this as ConnectionFailed so the
            // caller / UI distinguishes "infrastructure problem" from "wrong
            // password" — both used to look the same in the logs.
            std.log.err(
                "Ticket auth failed (code {d}) on FALLBACK connection — the redirect target was unreachable " ++
                    "and the original server doesn't accept the ticket. This is an infrastructure issue, " ++
                    "not a credentials issue. Retry after the redirect target's backend recovers.",
                .{ticket_auth_result.error_code},
            );
            return ClientError.ConnectionFailed;
        }
        std.log.err("Ticket authentication failed: code {d}", .{ticket_auth_result.error_code});
        return ClientError.AuthenticationFailed;
    }

    // Store session key from ticket auth for session encryption
    if (ticket_auth_result.session_key) |key| {
        client.auth_session_key = key;
        client.auth_hello_random = redirect_hello.random;
    } else {
        std.log.warn("Ticket auth succeeded but no session_key in response — session will be unencrypted", .{});
    }

    // Apply server overrides from redirect server too
    applyServerOverrides(client, ticket_auth_result);

    std.log.debug("Ticket authentication successful!", .{});
}

/// Apply server-overridden session parameters.
/// Client's requested value is the upper bound — server cannot override higher.
fn applyServerOverrides(client: *VpnClient, result: softether_proto.AuthResult) void {
    var effective_max = result.server_max_connection;
    effective_max = @min(effective_max, client.config.max_connections);
    effective_max = @min(effective_max, 32);
    effective_max = @max(effective_max, 1);

    const effective_half = result.server_half_connection;

    if (effective_max != client.config.max_connections) {
        std.log.info("Server overrode max_connections: {d} -> {d}", .{ client.config.max_connections, effective_max });
    }
    if (effective_half != client.config.half_connection) {
        std.log.info("Server overrode half_connection: {} -> {}", .{ client.config.half_connection, effective_half });
    }

    client.config.max_connections = @intCast(effective_max);
    client.config.half_connection = effective_half;
    client.config.use_compress = result.server_use_compress;
    client.config.use_encrypt = result.server_use_encrypt;

    // NOTE: policy:NoRouting must NOT disable full-tunnel. In SoftEther that
    // policy forbids the SESSION from acting as an IPv4 router (forwarding
    // packets for other hosts/subnets behind this client — site-to-site / LAN
    // router use). It does not govern whether a single client points its own
    // default route at the VPN gateway: a full-tunnel client originates its own
    // traffic, which the server NATs upstream. Honor the user's configured
    // default_route regardless of NoRouting. (server_no_routing is still parsed
    // and surfaced in the "Server session params" debug line for diagnostics.)
}

/// Initialize UDP acceleration after a successful auth that the server
/// agreed to. Failure is non-fatal — we fall back to TCP-only.
fn startUdpAcceleration(client: *VpnClient, auth_result: softether_proto.AuthResult) void {
    const bk = client.bulk_keys orelse return;

    // Server's send key is our recv key and vice versa
    const recv_key = auth_result.server_bulk_send_key orelse bk.recv_key;
    const send_key = auth_result.server_bulk_recv_key orelse bk.send_key;

    // Derive HMAC keys from bulk keys (SHA-1 of the key)
    var send_hmac: [20]u8 = undefined;
    var recv_hmac: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(&send_key, &send_hmac, .{});
    std.crypto.hash.Sha1.hash(&recv_key, &recv_hmac, .{});

    // Use server IP for UDP
    var server_ip_buf: [48]u8 = undefined;
    const server_ip_str = if (client.server_ip) |addr| formatAddress(addr, &server_ip_buf) else client.config.server_host;

    const udp_config = udp_accel_mod.UdpAccelConfig{
        .server_ip = server_ip_str,
        .server_port = auth_result.udp_accel_port,
        .use_encrypt = auth_result.udp_accel_use_encrypt,
        .send_key = send_key,
        .recv_key = recv_key,
        .send_hmac_key = send_hmac,
        .recv_hmac_key = recv_hmac,
    };

    client.udp_accel = udp_accel_mod.UdpAccelEngine.init(client.allocator, udp_config);
    client.udp_accel.?.start() catch |err| {
        std.log.warn("Failed to start UDP acceleration: {}", .{err});
        client.udp_accel = null;
    };
}
