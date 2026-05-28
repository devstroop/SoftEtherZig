const std = @import("std");

const tls = @import("../net/net.zig").tls;
const softether_proto = @import("../protocol/softether_protocol.zig");
const core = @import("../core/mod.zig");
const formatIpv4Buf = core.formatIpv4;

const vpn_client = @import("vpn_client.zig");
const VpnClient = vpn_client.VpnClient;
const ClientError = vpn_client.ClientError;
const SessionOptions = vpn_client.SessionOptions;
const SessionWrapper = vpn_client.SessionWrapper;
const makeProtoWriter = vpn_client.makeProtoWriter;
const makeProtoReader = vpn_client.makeProtoReader;

const connection_manager = @import("connection_manager.zig");
const ConnectionManager = connection_manager.ConnectionManager;
const TcpDirection = connection_manager.TcpDirection;

pub fn run(client: *VpnClient) void {
    createSession(client);
    establishAdditionalConnections(client);
}

fn createSession(client: *VpnClient) void {
    if (client.config.use_encryption and client.auth_session_key != null and client.auth_hello_random != null) {
        const username = switch (client.config.auth) {
            .password => |p| p.username,
            .anonymous => "anonymous",
            .certificate => "certificate",
        };
        const options = SessionOptions{
            .host = client.config.server_host,
            .port = client.config.server_port,
            .hub = client.config.hub_name,
            .username = username,
            .use_encryption = true,
            .use_compression = client.config.use_compression,
        };
        client.session = SessionWrapper.initWithOptions(client.allocator, options);

        if (client.session) |*sess| {
            sess.initEncryption(&client.auth_session_key.?, &client.auth_hello_random.?);
        }
        std.log.info("Session established with AES-256-CBC encryption", .{});
    } else {
        client.session = SessionWrapper.init(client.allocator, false);
        std.log.info("Session established without encryption", .{});
    }
}

fn establishAdditionalConnections(client: *VpnClient) void {
    if (client.config.max_connections <= 1) return;

    const session_key = client.auth_session_key orelse {
        std.log.warn("No session key available, skipping additional connections", .{});
        return;
    };

    client.conn_manager = ConnectionManager.init(
        client.allocator,
        client.config.max_connections,
        client.config.half_connection,
        client.config.use_compression,
    );

    const primary_sock = client.tls_socket orelse {
        std.log.warn("No primary socket, skipping additional connections", .{});
        client.conn_manager = null;
        return;
    };

    const primary_direction: TcpDirection = if (client.config.half_connection)
        .client_to_server
    else
        .bidirectional;

    _ = client.conn_manager.?.addConnection(primary_sock, primary_direction, true) catch |err| {
        std.log.err("Failed to add primary connection to manager: {}", .{err});
        client.conn_manager = null;
        return;
    };

    client.tls_socket = null;

    const tls_config = tls.TlsConfig{
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
        .sni_hostname = client.config.server_host,
    };

    var ip_str_buf: [16]u8 = undefined;
    const host_for_http = formatIpv4Buf(client.effective_server_ip, &ip_str_buf);

    var established: u8 = 1;
    var i: u8 = 1;
    while (i < client.config.max_connections) : (i += 1) {
        if (@atomicLoad(bool, &client.should_stop, .acquire)) break;

        establishOne(client, &client.conn_manager.?, &session_key, tls_config, host_for_http, i);
        established = client.conn_manager.?.count;
    }

    std.log.info("Established {d}/{d} TCP connections (half_connection={})", .{
        established,
        client.config.max_connections,
        client.config.half_connection,
    });
}

fn establishOne(
    client: *VpnClient,
    cm: *ConnectionManager,
    session_key: *const [20]u8,
    tls_config: tls.TlsConfig,
    host_for_http: []const u8,
    conn_index: u8,
) void {
    var new_sock = tls.TlsSocket.connect(
        client.allocator,
        host_for_http,
        client.effective_server_port,
        tls_config,
    ) catch |err| {
        std.log.warn("Additional connection {d} TLS failed: {}", .{ conn_index, err });
        return;
    };

    const writer = makeProtoWriter(&new_sock);
    const reader = makeProtoReader(&new_sock);

    softether_proto.uploadSignature(client.allocator, writer, host_for_http) catch |err| {
        std.log.warn("Additional connection {d} signature failed: {}", .{ conn_index, err });
        new_sock.close();
        return;
    };

    var hello = softether_proto.downloadHello(client.allocator, reader) catch |err| {
        std.log.warn("Additional connection {d} hello failed: {}", .{ conn_index, err });
        new_sock.close();
        return;
    };
    hello.deinit(client.allocator);

    const result = softether_proto.uploadAdditionalConnect(
        client.allocator,
        writer,
        reader,
        host_for_http,
        session_key,
    ) catch |err| {
        std.log.warn("Additional connection {d} handshake failed: {}", .{ conn_index, err });
        new_sock.close();
        return;
    };

    if (!result.success) {
        std.log.warn("Additional connection {d} rejected: error_code={d}", .{ conn_index, result.error_code });
        new_sock.close();
        return;
    }

    const direction: TcpDirection = switch (result.direction) {
        1 => .server_to_client,
        2 => .client_to_server,
        else => .bidirectional,
    };

    _ = cm.addConnection(new_sock, direction, false) catch |err| {
        std.log.warn("Additional connection {d} add failed: {}", .{ conn_index, err });
        new_sock.close();
        return;
    };
}
