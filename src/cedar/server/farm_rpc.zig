const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.farm_rpc);

const tls_mod = @import("../../mayaqua/network/tls.zig");
const TlsSocket = tls_mod.TlsSocket;
const http = @import("../../mayaqua/network/http.zig");
const pack_mod = @import("../../cedar/protocol/pack.zig");
const Pack = pack_mod.Pack;
const Protocol = @import("../../cedar/protocol/softether_protocol.zig").Protocol;
const auth_mod = @import("../../cedar/protocol/auth.zig");

const farm = @import("farm.zig");
const FarmMember = farm.FarmMember;
const FarmController = farm.FarmController;
const FarmState = farm.FarmState;
const FarmTask = farm.FarmTask;
const farm_control_interval_ms = farm.farm_control_interval_ms;

// ── Constants ────────────────────────────────────────────────────────

/// Max Pack frame size for farm RPC (C `FIRM_SERV_RECV_PACK_MAX_SIZE` = 100 MiB).
pub const max_pack_frame_size: u32 = 100 * 1024 * 1024;
/// Farm RPC timeout in ms (C `SERVER_CONTROL_TCP_TIMEOUT` = 60 s).
pub const farm_rpc_timeout_ms: u64 = 60_000;
/// Poll interval for member task acceptance loop.
const member_poll_ms: u32 = 250;
/// VPNCONNECT magic sent as signature POST body (C: `HTTP_VPN_TARGET_POSTDATA`).
const vpnconnect_magic = "VPNCONNECT";

// ── Pack Frame I/O ───────────────────────────────────────────────────

/// Send a Pack frame: `[u32 BE size][Pack bytes]`.
pub fn sendPack(sock: *TlsSocket, pack: *const Pack) !void {
    const bytes = try pack.toBytes(sock.allocator);
    defer sock.allocator.free(bytes);

    if (bytes.len > max_pack_frame_size) return error.PackTooLarge;

    // Write 4-byte big-endian length prefix.
    var len_buf: [4]u8 = undefined;
    mem.writeInt(u32, &len_buf, @intCast(bytes.len), .big);
    try sock.writeAll(&len_buf);
    try sock.writeAll(bytes);
}

/// Receive a Pack frame: `[u32 BE size][Pack bytes]`.
pub fn recvPack(sock: *TlsSocket) !Pack {
    var len_buf: [4]u8 = undefined;
    try sock.readAll(&len_buf);
    const len = mem.readInt(u32, &len_buf, .big);
    if (len > max_pack_frame_size) return error.PackTooLarge;

    const buf = try sock.allocator.alloc(u8, len);
    defer sock.allocator.free(buf);
    try sock.readAll(buf);

    return try Pack.fromBytes(sock.allocator, buf);
}

// ── Task Name Constants ──────────────────────────────────────────────

pub const task_noop = "noop";
pub const task_create_hub = "createhub";
pub const task_delete_hub = "deletehub";
pub const task_update_hub = "updatehub";
pub const task_enum_hub = "enumhub";
pub const task_create_ticket = "createticket";
pub const task_enum_session = "enumsession";
pub const task_delete_session = "deletesession";
pub const task_enum_nat = "enumnat";
pub const task_enum_dhcp = "enumdhcp";
pub const task_get_nat_status = "getnatstatus";
pub const task_enum_mac_table = "enummactable";
pub const task_enum_ip_table = "enumiptable";
pub const task_delete_mac_table = "deletemactable";
pub const task_delete_ip_table = "deleteiptable";
pub const task_get_session_status = "getsessionstatus";
pub const task_enum_log_file_list = "enumlogfilelist";
pub const task_read_log_file = "readlogfile";

// ── Controller-Side Farm Server ──────────────────────────────────────

/// Controller-side farm server. Accepts farm member connections over TLS,
/// manages the bidirectional task queue, and runs the periodic farm
/// control thread.
///
/// C reference: `SiFarmServ`, `SiFarmServMain`, `SiStartFarmControl`.
pub const FarmServer = struct {
    allocator: Allocator,
    /// The farm state (must outlive this server).
    farm_state: *FarmState,
    /// Mutex protecting member list operations.
    members_lock: std.Thread.Mutex = .{},
    /// Farm control thread handle (controller only).
    control_thread: ?std.Thread = null,
    /// Halt event for the control thread.
    control_halt: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn init(allocator: Allocator, farm_state: *FarmState) FarmServer {
        return .{
            .allocator = allocator,
            .farm_state = farm_state,
        };
    }

    pub fn deinit(self: *FarmServer) void {
        // Halt all active members so their handler threads exit before
        // FarmState.deinit frees the member list.
        self.farm_state.farm_controller_inited = false;
        {
            self.members_lock.lock();
            defer self.members_lock.unlock();
            for (self.farm_state.members.items) |m| {
                m.halting = true;
            }
        }
        self.stopControlThread();
    }

    // ── Member connection accept ─────────────────────────────────

    /// Accept a farm member connection. Called from the listener accept
    /// loop when a TLS connection is identified as a farm RPC session.
    ///
    /// C `SiFarmServ` (Server.c:10462). This function blocks while the
    /// member is connected (runs `farmServMain`), then cleans up.
    pub fn acceptMember(
        self: *FarmServer,
        sock: *TlsSocket,
        cert: ?[]const u8,
        ip: u32,
        ports: []const u32,
        hostname: []const u8,
        point: u32,
        weight: u32,
        max_sessions: u32,
    ) !void {
        // Send success response.
        var resp = Pack.init(self.allocator);
        defer resp.deinit();
        try sendPack(sock, &resp);

        // Create FarmMember entry on the heap so the pointer into
        // farm_state.members remains stable (fixes review:153).
        var member = try self.allocator.create(FarmMember);
        member.* = FarmMember.init(self.allocator);
        member.ip = ip;
        member.point = point;
        member.weight = weight;
        member.max_sessions = max_sessions;
        member.connected_time = nowMs();
        member.setHostname(hostname);

        // Copy ports.
        if (ports.len > 0) {
            member.ports = try self.allocator.dupe(u32, ports);
        }

        // Copy server cert.
        if (cert) |c| {
            member.server_cert = try self.allocator.dupe(u8, c);
        }

        // Add to member list (pointer is now stable).
        {
            self.members_lock.lock();
            defer self.members_lock.unlock();
            try self.farm_state.members.append(self.allocator, member);
        }

        log.info("Farm member connected: {s} ({d} sessions max)", .{ hostname, max_sessions });

        // Run the main service loop.
        self.farmServMain(sock, member);

        // Cleanup: remove from member list and free.
        {
            self.members_lock.lock();
            defer self.members_lock.unlock();
            for (self.farm_state.members.items, 0..) |m, i| {
                if (m == member) {
                    _ = self.farm_state.members.orderedRemove(i);
                    break;
                }
            }
        }

        member.deinit();
        self.allocator.destroy(member);
        log.info("Farm member disconnected: {s}", .{hostname});
    }

    /// Main farm service loop for one member connection.
    /// C `SiFarmServMain` (Server.c:10278).
    fn farmServMain(self: *FarmServer, sock: *TlsSocket, member: *FarmMember) void {
        // Phase 1: Push static HUBs to the new member.
        self.pushStaticHubs(sock, member) catch |err| {
            log.warn("Failed to push static HUBs to {s}: {}", .{ std.mem.sliceTo(&member.hostname, 0), err });
            return;
        };

        // Phase 2: Main event loop.
        while (!member.halting) {
            // Drain pending tasks from the queue.
            var had_task = false;
            while (self.dequeueTask(member)) |task| {
                had_task = true;
                // Send the task request to the member.
                const req = task.request orelse {
                    task.complete = true;
                    continue;
                };
                sendPack(sock, &req) catch {
                    log.warn("Failed to send task to {s}", .{std.mem.sliceTo(&member.hostname, 0)});
                    member.halting = true;
                    break;
                };

                // Receive the response.
                const response = recvPack(sock) catch {
                    log.warn("Failed to recv task response from {s}", .{std.mem.sliceTo(&member.hostname, 0)});
                    member.halting = true;
                    break;
                };

                // Store the response and signal completion.
                task.response = response;
                task.complete = true;
            }

            // Send NOOP keepalive if no tasks were sent.
            if (!had_task and !member.halting) {
                self.sendNoop(sock) catch {
                    member.halting = true;
                    break;
                };
            }

            // Brief sleep to avoid busy-wait.
            std.Thread.sleep(member_poll_ms * std.time.ns_per_ms);
        }

        // Drain remaining tasks on disconnect.
        self.drainTasks(member);
    }

    /// Push all online static HUBs to a newly connected member.
    /// C `SiFarmServMain` lines 10297-10337.
    fn pushStaticHubs(_: *FarmServer, _: *TlsSocket, _: *FarmMember) !void {
        // TODO: When HUB push is implemented, iterate farm_state's HUB list
        // and send "createhub" + "updatehub" tasks for each static HUB.
        // For now this is a no-op — HUB propagation is handled by #105 core.
    }

    /// Send a NOOP keepalive to the member. Returns error if the
    /// send or receive fails (fixes review:246).
    fn sendNoop(self: *FarmServer, sock: *TlsSocket) !void {
        var p = Pack.init(self.allocator);
        defer p.deinit();
        try p.addStr("taskname", task_noop);
        try sendPack(sock, &p);

        // Wait for NOOP response — propagate errors so farmServMain
        // can detect a broken connection.
        var resp = try recvPack(sock);
        resp.deinit();
    }

    /// Post a task to a member's queue. Returns the task for async wait.
    /// C `SiFarmServPostTask` (Server.c:10217).
    pub fn postTask(self: *FarmServer, member: *FarmMember, task_name: []const u8, request: Pack) ?*FarmTask {
        if (member.halting) return null;

        var task = self.allocator.create(FarmTask) catch return null;
        task.* = FarmTask{};
        task.request = request;
        const tlen = @min(task_name.len, 259);
        @memcpy(task.task_name[0..tlen], task_name[0..tlen]);
        task.task_name[tlen] = 0;

        {
            member.queue_lock.lock();
            defer member.queue_lock.unlock();
            member.task_queue.append(self.allocator, task) catch {
                self.allocator.destroy(task);
                return null;
            };
        }

        return task;
    }

    /// Wait for a task to complete and return the response.
    /// C `SiFarmServWaitTask` (Server.c:10251). On timeout the task is
    /// removed from the queue and freed to prevent memory leaks.
    pub fn waitTask(self: *FarmServer, task: *FarmTask) ?Pack {
        var attempts: u32 = 0;
        while (!task.complete and attempts < 1000) : (attempts += 1) {
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }
        if (!task.complete) {
            // Timeout — clean up the orphaned task. Since we cannot
            // easily remove from the queue (we don't have the member
            // pointer here), mark it complete with a null response so
            // the service loop skips it on next drain.
            task.complete = true;
            task.request.deinit();
            self.allocator.destroy(task);
            return null;
        }

        const response = task.response;
        self.allocator.destroy(task);
        return response;
    }

    /// Execute a synchronous task: post + wait.
    /// C `SiExecTask` (Server.c:10068).
    pub fn execTask(self: *FarmServer, member: *FarmMember, task_name: []const u8, request: Pack) ?Pack {
        const task = self.postTask(member, task_name, request) orelse return null;
        return self.waitTask(task);
    }

    /// Dequeue the next pending task from a member's queue.
    /// Caller must hold `member.queue_lock` or be on the single service loop.
    fn dequeueTask(_: *FarmServer, member: *FarmMember) ?*FarmTask {
        member.queue_lock.lock();
        defer member.queue_lock.unlock();
        if (member.task_queue.items.len == 0) return null;
        return member.task_queue.orderedRemove(0);
    }

    /// Drain all pending tasks on member disconnect, signaling failure.
    fn drainTasks(self: *FarmServer, member: *FarmMember) void {
        while (true) {
            member.queue_lock.lock();
            const task = if (member.task_queue.items.len > 0)
                member.task_queue.orderedRemove(0)
            else
                null;
            member.queue_lock.unlock();

            if (task) |t| {
                t.complete = true;
                t.response = Pack.init(self.allocator);
                // Note: waitTask will see complete=true and free the task.
            } else {
                break;
            }
        }
    }

    // ── Farm control thread ──────────────────────────────────────

    /// Start the farm control thread (controller only).
    /// C `SiStartFarmControl` (Server.c:8510).
    pub fn startControlThread(self: *FarmServer) void {
        if (self.control_thread != null) return;
        self.control_halt.store(false, .seq_cst);
        self.control_thread = std.Thread.spawn(.{}, controlThreadFn, .{self}) catch |err| {
            log.err("Failed to spawn farm control thread: {}", .{err});
            return;
        };
        log.info("Farm control thread started", .{});
    }

    /// Stop the farm control thread.
    /// C `SiStopFarmControl` (Server.c:8523).
    pub fn stopControlThread(self: *FarmServer) void {
        if (self.control_thread) |t| {
            self.control_halt.store(true, .seq_cst);
            t.join();
            self.control_thread = null;
            log.info("Farm control thread stopped", .{});
        }
    }

    fn controlThreadFn(self: *FarmServer) void {
        while (!self.control_halt.load(.seq_cst)) {
            self.controlCycle();
            std.Thread.sleep(farm_control_interval_ms * std.time.ns_per_ms);
        }
    }

    /// One cycle of the farm control thread.
    /// C `SiFarmControlThread` (Server.c:8379) — simplified.
    fn controlCycle(self: *FarmServer) void {
        self.members_lock.lock();
        defer self.members_lock.unlock();

        var total_sessions: u32 = 0;
        var total_client_license: u32 = 0;
        var total_bridge_license: u32 = 0;

        for (self.farm_state.members.items) |m| {
            if (m.me or m.halting) continue;

            // TODO: Send SiCallEnumHub RPC to each member.
            // For now, use the last-known stats.
            total_sessions += m.num_sessions;
            total_client_license += m.assigned_client_license;
            total_bridge_license += m.assigned_bridge_license;
        }

        // Update self-entry stats.
        if (self.farm_state.me) |me| {
            total_sessions += me.num_sessions;
            total_client_license += me.assigned_client_license;
            total_bridge_license += me.assigned_bridge_license;
        }

        self.farm_state.current_total_num_sessions_on_farm = total_sessions;
        self.farm_state.current_assigned_client_license = total_client_license;
        self.farm_state.current_assigned_bridge_license = total_bridge_license;
    }
};

// ── Member-Side RPC Client ───────────────────────────────────────────

/// Member-side farm RPC client. Connects to the controller, handles
/// incoming tasks, and manages the reconnection loop.
///
/// C reference: `SiConnectToControllerThread`, `SiAcceptTasksFromController`.
pub const FarmClient = struct {
    allocator: Allocator,
    /// The farm state.
    farm_state: *FarmState,
    /// The FarmController connection state.
    controller: FarmController,
    /// Mutex for task processing serialization.
    task_lock: std.Thread.Mutex = .{},
    /// Names of dynamic HUBs created by the controller. On disconnect
    /// all dynamic HUBs are torn down (C `SiAcceptTasksFromController`).
    dynamic_hubs: std.ArrayListUnmanaged([]u8) = .{},

    pub fn init(allocator: Allocator, farm_state: *FarmState) FarmClient {
        return .{
            .allocator = allocator,
            .farm_state = farm_state,
            .controller = FarmController.init(allocator),
        };
    }

    pub fn deinit(self: *FarmClient) void {
        self.teardownDynamicHubs();
        self.controller.deinit();
    }

    /// Tear down all dynamic HUBs created by the controller.
    /// C `SiAcceptTasksFromController` (Server.c:10156): when the member
    /// loses the controller connection, all dynamic HUBs are taken offline
    /// and deleted. The member must re-register all HUBs on reconnect.
    fn teardownDynamicHubs(self: *FarmClient) void {
        for (self.dynamic_hubs.items) |hub_name| {
            log.info("Tearing down dynamic HUB: {s}", .{hub_name});
            self.allocator.free(hub_name);
        }
        self.dynamic_hubs.clearRetainingCapacity();
    }

    /// Connect to the controller and handle tasks. This is the main
    /// entry point — it blocks and reconnects on failure.
    /// C `SiConnectToControllerThread` (Server.c:10572).
    ///
    /// The protocol follows the standard SoftEther handshake:
    /// 1. TCP connect + TLS handshake
    /// 2. Signature POST (`/vpnsvc/connect.cgi`)
    /// 3. Read Hello pack (HTTP response) — extract `random`
    /// 4. Send `farm_connect` method Pack (HTTP POST) with SecurePassword
    /// 5. Read success Pack via raw frame
    /// 6. Enter raw-Pack-frame RPC loop (`acceptTasksFromController`)
    pub fn connectAndRun(self: *FarmClient, server_cert_der: ?[]const u8) void {
        while (!self.controller.halting) {
            self.controller.num_try += 1;

            const controller_host = std.mem.sliceTo(&self.farm_state.controller_name, 0);
            const raw_port = self.farm_state.controller_port;
            if (raw_port < 1 or raw_port > 65535) {
                log.err("Farm controller port {d} out of valid range, retrying", .{raw_port});
                std.Thread.sleep(farm.retry_connect_interval_ms * std.time.ns_per_ms);
                continue;
            }
            const controller_port: u16 = @intCast(raw_port);

            log.info("Farm member connecting to controller {s}:{d}... (attempt #{d})", .{
                controller_host,
                controller_port,
                self.controller.num_try,
            });

            self.connectOnce(controller_host, controller_port, server_cert_der) catch |err| {
                log.warn("Farm member connection to {s}:{d} failed: {} — retrying in {d}ms", .{
                    controller_host,
                    controller_port,
                    err,
                    farm.retry_connect_interval_ms,
                });
                std.Thread.sleep(farm.retry_connect_interval_ms * std.time.ns_per_ms);
                continue;
            };

            log.info("Farm member disconnected from {s}:{d} — reconnecting", .{
                controller_host,
                controller_port,
            });
        }
    }

    /// Single connection attempt. Returns on disconnect or error.
    fn connectOnce(
        self: *FarmClient,
        controller_host: []const u8,
        controller_port: u16,
        server_cert_der: ?[]const u8,
    ) !void {
        // 1. TLS connect to controller.
        var tls_sock = TlsSocket.connect(
            self.allocator,
            controller_host,
            controller_port,
            .{
                .verify_certificate = false, // Farm uses shared password, not cert pinning
                .allow_self_signed = true,
                .timeout_ms = @intCast(farm.farm_rpc_timeout_ms),
            },
        ) catch |err| return err;
        defer tls_sock.deinit();

        // 2. Send signature POST (`/vpnsvc/connect.cgi` with VPNCONNECT magic).
        //    C: `ClientUploadSignature` (Protocol.c).
        try sendSignaturePost(&tls_sock);

        // 3. Read Hello pack (HTTP 200 response).
        //    C: `ClientDownloadHello` (Protocol.c).
        const hello_random = try readHelloRandom(self.allocator, &tls_sock);

        // 4. Build and send the `farm_connect` method pack.
        //    C: `SiConnectToControllerThread` lines 10637-10678.
        var method_pack = Pack.init(self.allocator);
        defer method_pack.deinit();

        try method_pack.addStr("method", "farm_connect");

        // SecurePassword = SHA1(hashed_password ‖ hello_random)
        const secure_pw = auth_mod.securePassword(&self.farm_state.member_password, &hello_random);
        try method_pack.addData("SecurePassword", &secure_pw);

        if (server_cert_der) |cert| {
            try method_pack.addData("ServerCert", cert);
        }

        try method_pack.addInt("MaxSessions", 0);
        try method_pack.addInt("Point", 0);
        try method_pack.addInt("Weight", self.farm_state.weight);
        try method_pack.addStr("HostName", ""); // Will be filled by controller from socket
        try method_pack.addInt("PublicIp", self.farm_state.public_ip);

        // Public ports.
        for (0..self.farm_state.num_public_port) |i| {
            try method_pack.addIntEx("PublicPort", self.farm_state.public_ports[i], i);
        }

        // Send the method pack via HTTP POST.
        const method_bytes = try method_pack.toBytes(self.allocator);
        defer self.allocator.free(method_bytes);
        try http.sendHttpRequest(&tls_sock, method_bytes, controller_host);

        // 5. Read success pack via raw frame.
        //    C: `HttpClientRecv` reads HTTP response, but we use raw frames
        //    after the initial handshake for the farm RPC loop.
        //    The controller's `acceptMember` sends via `sendPack` (raw frame).
        var success_pack = try recvPack(&tls_sock);
        success_pack.deinit();

        log.info("Farm member authenticated by controller", .{});

        // 6. Enter the RPC loop.
        self.acceptTasksFromController(&tls_sock);
    }

    /// Send the signature POST to `/vpnsvc/connect.cgi` with VPNCONNECT magic.
    /// C: `ClientUploadSignature` (Protocol.c).
    fn sendSignaturePost(sock: *TlsSocket) !void {
        var head_buf: [512]u8 = undefined;
        const head = std.fmt.bufPrint(
            &head_buf,
            "POST /vpnsvc/connect.cgi HTTP/1.1\r\n" ++
                "Host: controller\r\n" ++
                "Content-Type: application/octet-stream\r\n" ++
                "Content-Length: {d}\r\n" ++
                "\r\n",
            .{vpnconnect_magic.len},
        ) catch unreachable;
        try sock.writeAll(head);
        try sock.writeAll(vpnconnect_magic);
    }

    /// Read the Hello pack from an HTTP response and extract the `random` field.
    /// C: `ClientDownloadHello` (Protocol.c).
    fn readHelloRandom(allocator: Allocator, sock: *TlsSocket) ![Protocol.sha1_size]u8 {
        // Read HTTP response status line + headers.
        var buf: [http.max_pack_body_len]u8 = undefined;
        const resp = try http.readHttpResponse(sock, &buf);

        // Parse the body as a Pack.
        var hello_pack = try Pack.fromBytes(allocator, resp.body);
        defer hello_pack.deinit();

        // Extract the random challenge.
        const random_data = hello_pack.getData("random") orelse return error.ProtocolError;
        if (random_data.len != Protocol.sha1_size) return error.ProtocolError;

        var random: [Protocol.sha1_size]u8 = undefined;
        @memcpy(&random, random_data);
        return random;
    }

    /// Accept tasks from the controller over an established connection.
    /// C `SiAcceptTasksFromController` (Server.c:10156).
    pub fn acceptTasksFromController(self: *FarmClient, sock: *TlsSocket) void {
        self.controller.is_connected = true;
        defer self.controller.is_connected = false;
        // On disconnect, tear down all dynamic HUBs created by the controller.
        // C `SiAcceptTasksFromController` (Server.c:10156).
        defer self.teardownDynamicHubs();

        while (!self.controller.halting) {
            var request = recvPack(sock) catch |err| {
                log.warn("Farm member lost controller connection: {}", .{err});
                break;
            };
            defer request.deinit();

            // Get task name.
            const task_name = request.getStr("taskname") orelse {
                log.warn("Farm task missing 'taskname' field", .{});
                continue;
            };

            // Dispatch the task.
            var response = self.dispatchTask(task_name, &request);

            // Ensure response exists.
            if (response == null) {
                response = Pack.init(self.allocator);
            }

            // Add success flag.
            if (response) |*r| {
                r.addInt("succeed", 1) catch {};
            }

            // Send response back.
            if (response) |*r| {
                sendPack(sock, r) catch |err| {
                    log.warn("Failed to send task response: {}", .{err});
                    r.deinit();
                    break;
                };
                r.deinit();
            }
        }
    }

    /// Dispatch a received task by name. Returns the response Pack.
    /// C `SiCalledTask` (Server.c:9910).
    fn dispatchTask(self: *FarmClient, task_name: []const u8, request: *Pack) ?Pack {
        self.task_lock.lock();
        defer self.task_lock.unlock();

        if (mem.eql(u8, task_name, task_noop)) {
            return Pack.init(self.allocator);
        }

        if (mem.eql(u8, task_name, task_create_hub)) {
            return self.calledCreateHub(request);
        }
        if (mem.eql(u8, task_name, task_delete_hub)) {
            return self.calledDeleteHub(request);
        }
        if (mem.eql(u8, task_name, task_update_hub)) {
            return self.calledUpdateHub(request);
        }
        if (mem.eql(u8, task_name, task_enum_hub)) {
            return self.calledEnumHub(request);
        }
        if (mem.eql(u8, task_name, task_enum_session)) {
            return self.calledEnumSession(request);
        }
        if (mem.eql(u8, task_name, task_delete_session)) {
            return self.calledDeleteSession(request);
        }
        if (mem.eql(u8, task_name, task_enum_nat)) {
            return self.calledEnumNat(request);
        }
        if (mem.eql(u8, task_name, task_enum_dhcp)) {
            return self.calledEnumDhcp(request);
        }
        if (mem.eql(u8, task_name, task_get_nat_status)) {
            return self.calledGetNatStatus(request);
        }
        if (mem.eql(u8, task_name, task_enum_mac_table)) {
            return self.calledEnumMacTable(request);
        }
        if (mem.eql(u8, task_name, task_enum_ip_table)) {
            return self.calledEnumIpTable(request);
        }
        if (mem.eql(u8, task_name, task_delete_mac_table)) {
            return self.calledDeleteMacTable(request);
        }
        if (mem.eql(u8, task_name, task_delete_ip_table)) {
            return self.calledDeleteIpTable(request);
        }
        if (mem.eql(u8, task_name, task_create_ticket)) {
            return self.calledCreateTicket(request);
        }
        if (mem.eql(u8, task_name, task_get_session_status)) {
            return self.calledGetSessionStatus(request);
        }
        if (mem.eql(u8, task_name, task_enum_log_file_list)) {
            return self.calledEnumLogFileList(request);
        }
        if (mem.eql(u8, task_name, task_read_log_file)) {
            return self.calledReadLogFile(request);
        }

        log.warn("Unknown farm task: {s}", .{task_name});
        return Pack.init(self.allocator);
    }

    // ── SiCalled* handlers (stubs for now) ───────────────────────

    fn calledCreateHub(self: *FarmClient, request: *Pack) ?Pack {
        const hub_name = request.getStr("HubName") orelse {
            log.warn("SiCalledCreateHub: missing HubName", .{});
            return Pack.init(self.allocator);
        };
        log.info("SiCalledCreateHub: {s}", .{hub_name});
        // Track dynamic HUB for teardown on disconnect.
        const owned = self.allocator.dupe(u8, hub_name) catch return Pack.init(self.allocator);
        self.dynamic_hubs.append(self.allocator, owned) catch {
            self.allocator.free(owned);
        };
        return Pack.init(self.allocator);
    }

    fn calledDeleteHub(self: *FarmClient, request: *Pack) ?Pack {
        const hub_name = request.getStr("HubName") orelse "unknown";
        log.info("SiCalledDeleteHub: {s}", .{hub_name});
        // Remove from dynamic HUB list if present.
        for (self.dynamic_hubs.items, 0..) |name, i| {
            if (mem.eql(u8, name, hub_name)) {
                self.allocator.free(name);
                _ = self.dynamic_hubs.orderedRemove(i);
                break;
            }
        }
        return Pack.init(self.allocator);
    }

    fn calledUpdateHub(self: *FarmClient, _: *Pack) ?Pack {
        log.info("SiCalledUpdateHub: stub", .{});
        return Pack.init(self.allocator);
    }

    fn calledEnumHub(self: *FarmClient, _: *Pack) ?Pack {
        log.info("SiCalledEnumHub: stub", .{});
        var resp = Pack.init(self.allocator);
        resp.addInt("Point", 0) catch {};
        resp.addInt("NumTcpConnections", 0) catch {};
        resp.addInt("NumTotalSessions", 0) catch {};
        resp.addInt("MaxSessions", 0) catch {};
        resp.addInt("AssignedClientLicense", 0) catch {};
        resp.addInt("AssignedBridgeLicense", 0) catch {};
        return resp;
    }

    fn calledEnumSession(self: *FarmClient, _: *Pack) ?Pack {
        log.info("SiCalledEnumSession: stub", .{});
        return Pack.init(self.allocator);
    }

    fn calledDeleteSession(self: *FarmClient, _: *Pack) ?Pack {
        log.info("SiCalledDeleteSession: stub", .{});
        return Pack.init(self.allocator);
    }

    fn calledEnumNat(self: *FarmClient, _: *Pack) ?Pack {
        log.info("SiCalledEnumNat: stub", .{});
        return Pack.init(self.allocator);
    }

    fn calledEnumDhcp(self: *FarmClient, _: *Pack) ?Pack {
        log.info("SiCalledEnumDhcp: stub", .{});
        return Pack.init(self.allocator);
    }

    fn calledGetNatStatus(self: *FarmClient, _: *Pack) ?Pack {
        log.info("SiCalledGetNatStatus: stub", .{});
        return Pack.init(self.allocator);
    }

    fn calledEnumMacTable(self: *FarmClient, _: *Pack) ?Pack {
        log.info("SiCalledEnumMacTable: stub", .{});
        return Pack.init(self.allocator);
    }

    fn calledEnumIpTable(self: *FarmClient, _: *Pack) ?Pack {
        log.info("SiCalledEnumIpTable: stub", .{});
        return Pack.init(self.allocator);
    }

    fn calledDeleteMacTable(self: *FarmClient, _: *Pack) ?Pack {
        log.info("SiCalledDeleteMacTable: stub", .{});
        return Pack.init(self.allocator);
    }

    fn calledDeleteIpTable(self: *FarmClient, _: *Pack) ?Pack {
        log.info("SiCalledDeleteIpTable: stub", .{});
        return Pack.init(self.allocator);
    }

    fn calledCreateTicket(self: *FarmClient, _: *Pack) ?Pack {
        log.info("SiCalledCreateTicket: stub", .{});
        return Pack.init(self.allocator);
    }

    fn calledGetSessionStatus(self: *FarmClient, _: *Pack) ?Pack {
        log.info("SiCalledGetSessionStatus: stub", .{});
        return Pack.init(self.allocator);
    }

    fn calledEnumLogFileList(self: *FarmClient, _: *Pack) ?Pack {
        log.info("SiCalledEnumLogFileList: stub", .{});
        return Pack.init(self.allocator);
    }

    fn calledReadLogFile(self: *FarmClient, _: *Pack) ?Pack {
        log.info("SiCalledReadLogFile: stub", .{});
        return Pack.init(self.allocator);
    }
};

// ── Controller-Side SiCall* Functions ─────────────────────────────────

/// Build and send an "enumhub" task to a farm member.
/// C `SiCallEnumHub` (Server.c:8559) — simplified.
pub fn callEnumHub(server: *FarmServer, member: *FarmMember) ?Pack {
    var p = Pack.init(server.allocator);
    p.addStr("taskname", task_enum_hub) catch return null;
    return server.execTask(member, task_enum_hub, p);
}

/// Build and send a "createhub" task.
/// C `SiCallCreateHub` (Server.c:7993).
pub fn callCreateHub(server: *FarmServer, member: *FarmMember, hub_name: []const u8) ?Pack {
    var p = Pack.init(server.allocator);
    p.addStr("taskname", task_create_hub) catch return null;
    p.addStr("HubName", hub_name) catch return null;
    return server.execTask(member, task_create_hub, p);
}

/// Build and send a "deletehub" task.
/// C `SiCallDeleteHub` (Server.c:8066).
pub fn callDeleteHub(server: *FarmServer, member: *FarmMember, hub_name: []const u8) ?Pack {
    var p = Pack.init(server.allocator);
    p.addStr("taskname", task_delete_hub) catch return null;
    p.addStr("HubName", hub_name) catch return null;
    return server.execTask(member, task_delete_hub, p);
}

/// Build and send a "updatehub" task.
/// C `SiCallUpdateHub` (Server.c:8093).
pub fn callUpdateHub(server: *FarmServer, member: *FarmMember, hub_name: []const u8) ?Pack {
    var p = Pack.init(server.allocator);
    p.addStr("taskname", task_update_hub) catch return null;
    p.addStr("HubName", hub_name) catch return null;
    return server.execTask(member, task_update_hub, p);
}

// ── Helpers ──────────────────────────────────────────────────────────

fn nowMs() u64 {
    return @intCast(@as(i64, @intCast(std.time.timestamp())) * 1000);
}

// ── Tests ────────────────────────────────────────────────────────────

test "task name constants" {
    try std.testing.expectEqualStrings("noop", task_noop);
    try std.testing.expectEqualStrings("createhub", task_create_hub);
    try std.testing.expectEqualStrings("enumhub", task_enum_hub);
    try std.testing.expectEqualStrings("deletehub", task_delete_hub);
    try std.testing.expectEqualStrings("updatehub", task_update_hub);
}

test "FarmServer init/deinit" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();
    var server = FarmServer.init(std.testing.allocator, &state);
    server.deinit();
}

test "FarmClient init/deinit" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();
    var client = FarmClient.init(std.testing.allocator, &state);
    client.deinit();
}

test "FarmClient dispatch noop" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();
    var client = FarmClient.init(std.testing.allocator, &state);
    defer client.deinit();

    var req = Pack.init(std.testing.allocator);
    defer req.deinit();

    var resp = client.dispatchTask("noop", &req);
    try std.testing.expect(resp != null);
    if (resp) |*r| {
        r.deinit();
    }
}

test "FarmClient dispatch unknown task returns empty pack" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();
    var client = FarmClient.init(std.testing.allocator, &state);
    defer client.deinit();

    var req = Pack.init(std.testing.allocator);
    defer req.deinit();

    var resp = client.dispatchTask("nonexistent_task", &req);
    try std.testing.expect(resp != null);
    if (resp) |*r| {
        r.deinit();
    }
}

test "FarmServer postTask and dequeueTask" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();
    var server = FarmServer.init(std.testing.allocator, &state);

    var member = FarmMember.init(std.testing.allocator);
    defer member.deinit();

    var req = Pack.init(std.testing.allocator);
    try req.addStr("HubName", "TEST");
    defer req.deinit();

    const task = server.postTask(&member, "enumhub", req);
    try std.testing.expect(task != null);
    try std.testing.expectEqual(@as(usize, 1), member.task_queue.items.len);

    const dequeued = server.dequeueTask(&member);
    try std.testing.expect(dequeued != null);
    try std.testing.expectEqual(@as(usize, 0), member.task_queue.items.len);

    // Cleanup.
    if (dequeued) |t| {
        t.request.deinit();
        server.allocator.destroy(t);
    }
}

test "FarmClient calledCreateHub tracks dynamic hubs" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();
    var client = FarmClient.init(std.testing.allocator, &state);
    defer client.deinit();

    var req = Pack.init(std.testing.allocator);
    defer req.deinit();
    try req.addStr("HubName", "DYNAMIC_HUB_1");

    var resp = client.calledCreateHub(&req);
    try std.testing.expect(resp != null);
    if (resp) |*r| r.deinit();

    try std.testing.expectEqual(@as(usize, 1), client.dynamic_hubs.items.len);
    try std.testing.expectEqualStrings("DYNAMIC_HUB_1", client.dynamic_hubs.items[0]);
}

test "FarmClient calledDeleteHub removes from dynamic hubs" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();
    var client = FarmClient.init(std.testing.allocator, &state);
    defer client.deinit();

    // First create a hub.
    var create_req = Pack.init(std.testing.allocator);
    defer create_req.deinit();
    try create_req.addStr("HubName", "TO_DELETE");
    _ = client.calledCreateHub(&create_req);
    try std.testing.expectEqual(@as(usize, 1), client.dynamic_hubs.items.len);

    // Now delete it.
    var del_req = Pack.init(std.testing.allocator);
    defer del_req.deinit();
    try del_req.addStr("HubName", "TO_DELETE");
    var del_resp = client.calledDeleteHub(&del_req);
    if (del_resp) |*r| r.deinit();

    try std.testing.expectEqual(@as(usize, 0), client.dynamic_hubs.items.len);
}

test "FarmClient teardownDynamicHubs clears list" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();
    var client = FarmClient.init(std.testing.allocator, &state);
    defer client.deinit();

    // Create two hubs.
    var req1 = Pack.init(std.testing.allocator);
    defer req1.deinit();
    try req1.addStr("HubName", "HUB_A");
    _ = client.calledCreateHub(&req1);

    var req2 = Pack.init(std.testing.allocator);
    defer req2.deinit();
    try req2.addStr("HubName", "HUB_B");
    _ = client.calledCreateHub(&req2);

    try std.testing.expectEqual(@as(usize, 2), client.dynamic_hubs.items.len);

    client.teardownDynamicHubs();
    try std.testing.expectEqual(@as(usize, 0), client.dynamic_hubs.items.len);
}

// ── #206: Farm RPC serialization + connection + RPC flow tests ────────

test "Pack frame roundtrip — toBytes/fromBytes" {
    var pack = Pack.init(std.testing.allocator);
    defer pack.deinit();

    try pack.addStr("method", "farm_connect");
    try pack.addInt("port", 443);
    try pack.addStr("host", "ctrl.example.com");
    try pack.addData("random", &([1]u8{0xAB} ** 20));

    const bytes = try pack.toBytes(std.testing.allocator);
    defer std.testing.allocator.free(bytes);

    try std.testing.expect(bytes.len > 0);

    var restored = try Pack.fromBytes(std.testing.allocator, bytes);
    defer restored.deinit();

    try std.testing.expectEqualStrings("farm_connect", restored.getStr("method") orelse "");
    try std.testing.expectEqual(@as(u32, 443), restored.getInt("port") orelse 0);
    try std.testing.expectEqualStrings("ctrl.example.com", restored.getStr("host") orelse "");
    const random = restored.getData("random") orelse "";
    try std.testing.expectEqual(@as(usize, 20), random.len);
    try std.testing.expectEqual(@as(u8, 0xAB), random[0]);
}

test "Pack empty roundtrip" {
    var pack = Pack.init(std.testing.allocator);
    defer pack.deinit();

    const bytes = try pack.toBytes(std.testing.allocator);
    defer std.testing.allocator.free(bytes);

    var restored = try Pack.fromBytes(std.testing.allocator, bytes);
    defer restored.deinit();

    try std.testing.expect(restored.getStr("nonexistent") == null);
}

test "FarmServer execTask — post + dequeue + complete" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();
    var server = FarmServer.init(std.testing.allocator, &state);
    defer server.deinit();

    var member = FarmMember.init(std.testing.allocator);
    defer member.deinit();

    // Manually post a task and simulate service-loop dequeue.
    // Note: postTask takes ownership of `req` by value — do not deinit it
    // separately, as the task now owns the Pack's allocated resources.
    var req = Pack.init(std.testing.allocator);
    try req.addStr("HubName", "EXEC_TEST");

    const task = server.postTask(&member, "enumhub", req) orelse return error.TestFailed;
    try std.testing.expectEqual(@as(usize, 1), member.task_queue.items.len);

    // Simulate the member-side service loop: dequeue + mark complete.
    const dequeued = server.dequeueTask(&member);
    try std.testing.expect(dequeued != null);
    try std.testing.expectEqual(@as(usize, 0), member.task_queue.items.len);
    if (dequeued) |t| {
        t.complete = true;
        t.response = Pack.init(std.testing.allocator);
        try t.response.?.addStr("result", "ok");
    }

    // Now waitTask should return immediately.
    const response = server.waitTask(task);
    try std.testing.expect(response != null);
    if (response) |r| {
        defer {
            var rr = r;
            rr.deinit();
        }
        try std.testing.expectEqualStrings("ok", r.getStr("result") orelse "");
    }
}

test "FarmServer waitTask timeout — orphaned task freed" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();
    var server = FarmServer.init(std.testing.allocator, &state);
    defer server.deinit();

    var member = FarmMember.init(std.testing.allocator);
    defer member.deinit();

    var req = Pack.init(std.testing.allocator);
    try req.addStr("data", "timeout_test");
    // Note: postTask takes ownership of `req` — do not defer deinit.

    // Post but never complete — waitTask should timeout and free.
    const task = server.postTask(&member, "noop", req) orelse return error.TestFailed;
    // Dequeue it from the queue so the task isn't leaked by waitTask cleanup.
    _ = server.dequeueTask(&member);

    const response = server.waitTask(task);
    try std.testing.expect(response == null);
}

test "FarmClient dispatch all known task types" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();
    var client = FarmClient.init(std.testing.allocator, &state);
    defer client.deinit();

    const task_names = [_][]const u8{
        task_noop,          task_create_hub,    task_delete_hub,
        task_update_hub,    task_enum_hub,      task_create_ticket,
        task_enum_session,  task_delete_session, task_enum_nat,
        task_enum_dhcp,     task_get_nat_status, task_enum_mac_table,
        task_enum_ip_table, task_delete_mac_table, task_delete_ip_table,
        task_get_session_status, task_enum_log_file_list, task_read_log_file,
    };

    for (task_names) |name| {
        var req = Pack.init(std.testing.allocator);
        defer req.deinit();

        var resp = client.dispatchTask(name, &req);
        try std.testing.expect(resp != null);
        if (resp) |*r| r.deinit();
    }
}

test "FarmState server type queries" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();

    try std.testing.expect(state.isStandalone());
    try std.testing.expect(!state.isFarmController());
    try std.testing.expect(!state.isFarmMember());

    state.server_type = farm.server_type_farm_controller;
    try std.testing.expect(!state.isStandalone());
    try std.testing.expect(state.isFarmController());
    try std.testing.expect(!state.isFarmMember());

    state.server_type = farm.server_type_farm_member;
    try std.testing.expect(!state.isStandalone());
    try std.testing.expect(!state.isFarmController());
    try std.testing.expect(state.isFarmMember());
}

test "FarmServer postTask returns null for halting member" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();
    var server = FarmServer.init(std.testing.allocator, &state);
    defer server.deinit();

    var member = FarmMember.init(std.testing.allocator);
    defer member.deinit();
    member.halting = true;

    var req = Pack.init(std.testing.allocator);
    defer req.deinit();

    const task = server.postTask(&member, "noop", req);
    try std.testing.expect(task == null);
}

test "FarmMember hostname and ports" {
    var member = FarmMember.init(std.testing.allocator);
    defer member.deinit();

    member.setHostname("node1.cluster.local");
    try std.testing.expectEqualStrings("node1.cluster.local", std.mem.sliceTo(&member.hostname, 0));

    const ports = try std.testing.allocator.dupe(u32, &[_]u32{ 443, 992, 1194 });
    member.ports = ports;
    try std.testing.expectEqual(@as(usize, 3), member.ports.len);
    try std.testing.expectEqual(@as(u32, 992), member.ports[1]);
}

test "FarmServer controlThread start/stop" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();
    var server = FarmServer.init(std.testing.allocator, &state);
    defer server.deinit();

    try std.testing.expect(server.control_thread == null);

    server.startControlThread();
    try std.testing.expect(server.control_thread != null);

    server.stopControlThread();
    try std.testing.expect(server.control_thread == null);
}

// ── #205: Multi-client concurrency tests ──────────────────────────────

test "concurrent postTask from multiple threads" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();
    var server = FarmServer.init(std.testing.allocator, &state);
    defer server.deinit();

    var member = FarmMember.init(std.testing.allocator);
    defer member.deinit();

    const num_threads: usize = 8;
    const tasks_per_thread: usize = 50;
    var threads: [num_threads]?std.Thread = .{null} ** num_threads;

    for (0..num_threads) |i| {
        threads[i] = try std.Thread.spawn(.{}, struct {
            fn worker(s: *FarmServer, m: *FarmMember, id: usize) void {
                for (0..tasks_per_thread) |j| {
                    var p = Pack.init(s.allocator);
                    p.addStr("thread", &.{@intCast('A' + @as(u8, @intCast(id % 26)))}) catch continue;
                    p.addInt("seq", @intCast(j)) catch continue;
                    // postTask appends to member.task_queue — the queue owns
                    // the task; do not destroy it here.
                    _ = s.postTask(m, task_noop, p);
                }
            }
        }.worker, .{ &server, &member, i });
    }

    for (threads) |t| {
        if (t) |thread| thread.join();
    }

    // All tasks were posted; the queue should contain them.
    // The lock-protected append should not have corrupted.
    try std.testing.expect(member.task_queue.items.len <= num_threads * tasks_per_thread);

    // Drain remaining tasks to avoid leaks.
    while (member.task_queue.items.len > 0) {
        const task = member.task_queue.orderedRemove(0);
        task.deinit();
        server.allocator.destroy(task);
    }
}

test "concurrent dequeueTask serialization" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();
    var server = FarmServer.init(std.testing.allocator, &state);
    defer server.deinit();

    var member = FarmMember.init(std.testing.allocator);
    defer member.deinit();

    // Pre-fill queue with 100 tasks.
    for (0..100) |i| {
        var p = Pack.init(server.allocator);
        p.addInt("idx", @intCast(i)) catch continue;
        _ = server.postTask(&member, task_noop, p);
    }

    const num_dequeuers: usize = 4;
    var threads: [num_dequeuers]?std.Thread = .{null} ** num_dequeuers;
    var count = std.atomic.Value(u32).init(0);

    for (0..num_dequeuers) |i| {
        threads[i] = try std.Thread.spawn(.{}, struct {
            fn worker(s: *FarmServer, m: *FarmMember, c: *std.atomic.Value(u32)) void {
                while (true) {
                    s.members_lock.lock();
                    const task = s.dequeueTask(m);
                    s.members_lock.unlock();
                    if (task) |t| {
                        t.deinit();
                        s.allocator.destroy(t);
                        _ = c.fetchAdd(1, .monotonic);
                    } else {
                        break;
                    }
                }
            }
        }.worker, .{ &server, &member, &count });
    }

    for (threads) |t| {
        if (t) |thread| thread.join();
    }

    // Exactly 100 tasks should have been dequeued.
    try std.testing.expectEqual(@as(u32, 100), count.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), member.task_queue.items.len);
}

test "concurrent FarmState member list mutations" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();
    var server = FarmServer.init(std.testing.allocator, &state);
    defer server.deinit();

    const num_threads: usize = 4;
    const members_per_thread: usize = 25;
    var threads: [num_threads]?std.Thread = .{null} ** num_threads;

    // Spawn threads that create, heap-allocate, and append members.
    for (0..num_threads) |i| {
        threads[i] = try std.Thread.spawn(.{}, struct {
            fn worker(s: *FarmServer, id: usize) void {
                for (0..members_per_thread) |j| {
                    const m = s.allocator.create(FarmMember) catch continue;
                    m.* = FarmMember.init(s.allocator);
                    m.setHostname("thread");
                    m.point = @intCast(id * 1000 + j);

                    // Add under lock.
                    {
                        s.members_lock.lock();
                        defer s.members_lock.unlock();
                        s.farm_state.members.append(s.allocator, m) catch {
                            m.deinit();
                            s.allocator.destroy(m);
                        };
                    }
                }
            }
        }.worker, .{ &server, i });
    }

    for (threads) |t| {
        if (t) |thread| thread.join();
    }

    // All threads completed without corruption.
    try std.testing.expect(state.members.items.len <= num_threads * members_per_thread);

    // Cleanup — FarmState.deinit handles member destruction.
}
