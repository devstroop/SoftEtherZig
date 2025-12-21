//! SoftEther VPN Session Layer
//!
//! This module implements VPN session management in pure Zig.
//! Phase 5 of the C-to-Zig migration.
//!
//! A Session represents an established VPN connection and handles:
//! - Session state machine (connecting, authenticating, established, etc.)
//! - Encryption keys and cipher contexts
//! - Packet encryption/decryption for the data channel
//! - Keep-alive and timeout management
//! - Traffic statistics

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

// ============================================================================
// Local Crypto Helpers (self-contained for testing)
// ============================================================================

/// Fill buffer with random bytes
fn randomBytes(buf: []u8) void {
    std.crypto.random.bytes(buf);
}

/// Generate random u32
fn randomU32() u32 {
    var buf: [4]u8 = undefined;
    std.crypto.random.bytes(&buf);
    return mem.readInt(u32, &buf, .little);
}

/// Convert bytes to hex string
fn toHex(comptime len: usize, data: *const [len]u8) [len * 2]u8 {
    const hex_chars = "0123456789abcdef";
    var result: [len * 2]u8 = undefined;
    for (data, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    return result;
}

/// Simple AES-256-CBC implementation for session encryption
pub const Aes256Cbc = struct {
    key: [32]u8,
    iv: [16]u8,

    pub fn init(key: *const [32]u8, iv: *const [16]u8) Aes256Cbc {
        return .{
            .key = key.*,
            .iv = iv.*,
        };
    }

    /// PKCS7 padding
    fn pkcs7Pad(allocator: Allocator, data: []const u8) ![]u8 {
        const block_size = 16;
        const padding_len = block_size - (data.len % block_size);
        const padded = try allocator.alloc(u8, data.len + padding_len);
        @memcpy(padded[0..data.len], data);
        @memset(padded[data.len..], @intCast(padding_len));
        return padded;
    }

    /// PKCS7 unpad
    fn pkcs7Unpad(allocator: Allocator, data: []const u8) ![]u8 {
        if (data.len == 0 or data.len % 16 != 0) {
            return error.InvalidPadding;
        }
        const padding_len = data[data.len - 1];
        if (padding_len == 0 or padding_len > 16) {
            return error.InvalidPadding;
        }
        const unpadded_len = data.len - padding_len;
        const result = try allocator.alloc(u8, unpadded_len);
        @memcpy(result, data[0..unpadded_len]);
        return result;
    }

    /// Encrypt data with AES-256-CBC
    pub fn encrypt(self: *Aes256Cbc, allocator: Allocator, plaintext: []const u8) ![]u8 {
        const padded = try pkcs7Pad(allocator, plaintext);
        defer allocator.free(padded);

        const ctx = std.crypto.core.aes.Aes256.initEnc(self.key);
        const result = try allocator.alloc(u8, padded.len);
        errdefer allocator.free(result);

        var prev_block = self.iv;
        var i: usize = 0;
        while (i < padded.len) : (i += 16) {
            var block: [16]u8 = undefined;
            @memcpy(&block, padded[i..][0..16]);

            // XOR with previous ciphertext (or IV for first block)
            for (&block, prev_block) |*b, p| {
                b.* ^= p;
            }

            // Encrypt block
            ctx.encrypt(&block, &block);

            @memcpy(result[i..][0..16], &block);
            prev_block = block;
        }

        return result;
    }

    /// Decrypt data with AES-256-CBC
    pub fn decrypt(self: *Aes256Cbc, allocator: Allocator, ciphertext: []const u8) ![]u8 {
        if (ciphertext.len == 0 or ciphertext.len % 16 != 0) {
            return error.InvalidCiphertext;
        }

        const ctx = std.crypto.core.aes.Aes256.initDec(self.key);
        const decrypted = try allocator.alloc(u8, ciphertext.len);
        errdefer allocator.free(decrypted);

        var prev_block = self.iv;
        var i: usize = 0;
        while (i < ciphertext.len) : (i += 16) {
            var block: [16]u8 = undefined;
            const cipher_block = ciphertext[i..][0..16];
            @memcpy(&block, cipher_block);

            // Decrypt block
            ctx.decrypt(&block, &block);

            // XOR with previous ciphertext (or IV for first block)
            for (&block, prev_block) |*b, p| {
                b.* ^= p;
            }

            @memcpy(decrypted[i..][0..16], &block);
            @memcpy(&prev_block, cipher_block);
        }

        const result = pkcs7Unpad(allocator, decrypted) catch |err| {
            allocator.free(decrypted);
            return err;
        };
        allocator.free(decrypted); // Free intermediate buffer
        return result;
    }
};

// ============================================================================
// Session Configuration
// ============================================================================

/// Session configuration constants
pub const Config = struct {
    /// Default session timeout in milliseconds (30 seconds)
    pub const default_timeout_ms: u64 = 30_000;

    /// Keep-alive interval in milliseconds (10 seconds)
    pub const keepalive_interval_ms: u64 = 10_000;

    /// Maximum packet size for VPN data
    pub const max_packet_size: usize = 1600;

    /// Session key size (SHA-1 hash size)
    pub const session_key_size: usize = 20;

    /// Encryption key size for AES-256
    pub const encryption_key_size: usize = 32;

    /// IV size for AES-CBC
    pub const iv_size: usize = 16;

    /// Maximum queued packets
    pub const max_queue_size: usize = 1024;

    /// Default retry count
    pub const default_retry_count: u32 = 5;

    /// Retry interval in milliseconds
    pub const retry_interval_ms: u64 = 5_000;
};

// ============================================================================
// Session State
// ============================================================================

/// VPN session states
pub const SessionState = enum(u32) {
    /// Initial state, not connected
    idle = 0,
    /// TCP connection being established
    connecting = 1,
    /// Performing protocol handshake
    handshake = 2,
    /// Authenticating with server
    authenticating = 3,
    /// Session established, can send/receive data
    established = 4,
    /// Session is being disconnected
    disconnecting = 5,
    /// Session has been disconnected
    disconnected = 6,
    /// Connection failed, waiting for retry
    retry_wait = 7,
    /// Fatal error, session cannot recover
    error_state = 8,
};

/// Client status (compatible with SoftEther CLIENT_STATUS)
pub const ClientStatus = enum(u32) {
    idle = 0,
    connecting = 1,
    negotiation = 2,
    auth = 3,
    established = 4,
    retry = 5,
    retry_count_max = 6,
};

/// Session error codes
pub const SessionError = error{
    /// Session timed out
    Timeout,
    /// Authentication failed
    AuthFailed,
    /// Server rejected connection
    Rejected,
    /// Protocol error
    ProtocolError,
    /// Network error
    NetworkError,
    /// Session was cancelled
    Cancelled,
    /// Maximum retries exceeded
    MaxRetriesExceeded,
    /// Device/driver error
    DeviceError,
    /// Invalid state transition
    InvalidState,
    /// Server unavailable
    ServerUnavailable,
    /// Hub not found
    HubNotFound,
    /// User not found
    UserNotFound,
    /// Access denied
    AccessDenied,
    /// Certificate error
    CertificateError,
    /// Encryption error
    EncryptionError,
    /// Allocation failed
    OutOfMemory,
};

// ============================================================================
// Session Keys and Encryption
// ============================================================================

/// Session encryption keys
pub const SessionKeys = struct {
    /// Session key (20 bytes, SHA-1 size)
    session_key: [Config.session_key_size]u8,

    /// 32-bit session key (for fast lookup)
    session_key_32: u32,

    /// Encryption key for client-to-server
    send_key: [Config.encryption_key_size]u8,

    /// Encryption key for server-to-client
    recv_key: [Config.encryption_key_size]u8,

    /// UDP send encryption key (16 bytes)
    udp_send_key: [16]u8,

    /// UDP receive encryption key (16 bytes)
    udp_recv_key: [16]u8,

    /// Whether encryption is enabled
    use_encryption: bool,

    /// Whether to use fast RC4 (legacy)
    use_fast_rc4: bool,

    /// Create new random session keys
    pub fn generate() SessionKeys {
        var keys: SessionKeys = undefined;

        // Generate random session key
        randomBytes(&keys.session_key);

        // Generate 32-bit key
        keys.session_key_32 = randomU32();

        // Generate encryption keys
        randomBytes(&keys.send_key);
        randomBytes(&keys.recv_key);

        // Generate UDP keys
        randomBytes(&keys.udp_send_key);
        randomBytes(&keys.udp_recv_key);

        keys.use_encryption = true;
        keys.use_fast_rc4 = false;

        return keys;
    }

    /// Derive keys from authentication material
    pub fn deriveFromAuth(
        password_hash: *const [20]u8,
        server_challenge: *const [20]u8,
    ) SessionKeys {
        var keys: SessionKeys = undefined;

        // Use SHA-256 to derive keys
        var sha = std.crypto.hash.sha2.Sha256.init(.{});
        sha.update(password_hash);
        sha.update(server_challenge);
        sha.update(&[_]u8{0x01}); // direction byte
        sha.final(&keys.send_key);

        sha = std.crypto.hash.sha2.Sha256.init(.{});
        sha.update(password_hash);
        sha.update(server_challenge);
        sha.update(&[_]u8{0x02});
        sha.final(&keys.recv_key);

        // Session key from first 20 bytes of send_key
        @memcpy(&keys.session_key, keys.send_key[0..20]);
        keys.session_key_32 = mem.readInt(u32, keys.send_key[0..4], .big);

        // UDP keys derived similarly
        @memcpy(&keys.udp_send_key, keys.send_key[0..16]);
        @memcpy(&keys.udp_recv_key, keys.recv_key[0..16]);

        keys.use_encryption = true;
        keys.use_fast_rc4 = false;

        return keys;
    }

    /// Get session key as hex string
    pub fn sessionKeyStr(self: *const SessionKeys) [40]u8 {
        return toHex(20, &self.session_key);
    }
};

// ============================================================================
// Traffic Statistics
// ============================================================================

/// Traffic counters for one direction
pub const TrafficCounters = struct {
    /// Unicast packet count
    unicast_count: u64 = 0,
    /// Unicast byte count
    unicast_bytes: u64 = 0,
    /// Broadcast packet count
    broadcast_count: u64 = 0,
    /// Broadcast byte count
    broadcast_bytes: u64 = 0,

    /// Add a packet to statistics
    pub fn addPacket(self: *TrafficCounters, size: usize, is_broadcast: bool) void {
        if (is_broadcast) {
            self.broadcast_count += 1;
            self.broadcast_bytes += size;
        } else {
            self.unicast_count += 1;
            self.unicast_bytes += size;
        }
    }

    /// Get total packet count
    pub fn totalCount(self: *const TrafficCounters) u64 {
        return self.unicast_count + self.broadcast_count;
    }

    /// Get total byte count
    pub fn totalBytes(self: *const TrafficCounters) u64 {
        return self.unicast_bytes + self.broadcast_bytes;
    }
};

/// Session traffic statistics
pub const TrafficStats = struct {
    /// Sent traffic
    send: TrafficCounters = .{},
    /// Received traffic
    recv: TrafficCounters = .{},

    /// Total bytes sent (including encryption overhead)
    total_send_size: u64 = 0,
    /// Total bytes received
    total_recv_size: u64 = 0,
    /// Total bytes sent (before compression)
    total_send_size_real: u64 = 0,
    /// Total bytes received (before decompression)
    total_recv_size_real: u64 = 0,
};

// ============================================================================
// Session Policy
// ============================================================================

/// Session policy (access control from server)
pub const SessionPolicy = struct {
    /// Allow access
    access: bool = true,
    /// DHCP filtering
    dhcp_filter: bool = false,
    /// DHCP server operation prohibited
    dhcp_no_server: bool = false,
    /// DHCP client only
    dhcp_force: bool = false,
    /// Bridge prohibited
    no_bridge: bool = true,
    /// Routing prohibited
    no_routing: bool = true,
    /// MAC address limit
    max_mac: u32 = 0,
    /// IP address limit
    max_ip: u32 = 0,
    /// Upload bandwidth limit (bps)
    max_upload: u32 = 0,
    /// Download bandwidth limit (bps)
    max_download: u32 = 0,
    /// Monitoring mode
    monitor_port: bool = false,
    /// Number of TCP connections
    max_connection: u32 = 32,
    /// Timeout (seconds)
    timeout: u32 = 20,
    /// Auto disconnect (seconds, 0 = disabled)
    auto_disconnect: u32 = 0,
    /// Filter broadcast packets
    filter_broadcast: bool = false,
    /// Filter IPv6
    filter_ipv6: bool = false,
    /// No QoS
    no_qos: bool = false,
};

// ============================================================================
// Node Information
// ============================================================================

/// Client node information sent to server
pub const NodeInfo = struct {
    /// Client product name
    client_product_name: [64]u8 = [_]u8{0} ** 64,
    /// Client version
    client_version: u32 = 0,
    /// Client build number
    client_build: u32 = 0,
    /// OS name
    os_name: [64]u8 = [_]u8{0} ** 64,
    /// OS version
    os_version: [128]u8 = [_]u8{0} ** 128,
    /// OS product ID
    os_product_id: [64]u8 = [_]u8{0} ** 64,
    /// Hostname
    hostname: [64]u8 = [_]u8{0} ** 64,
    /// IP address
    ip_address: [46]u8 = [_]u8{0} ** 46,
    /// MAC address (first 6 bytes used)
    mac_address: [6]u8 = [_]u8{0} ** 6,
    /// Unique ID
    unique_id: [20]u8 = [_]u8{0} ** 20,

    /// Create node info with default values
    pub fn create() NodeInfo {
        var info = NodeInfo{};

        // Set product name
        const name = "SoftEther VPN Client (Zig)";
        @memcpy(info.client_product_name[0..name.len], name);

        // Version 4.19
        info.client_version = 419;
        info.client_build = 9799;

        // OS info (placeholder)
        const os = "macOS";
        @memcpy(info.os_name[0..os.len], os);

        // Generate unique ID
        randomBytes(&info.unique_id);

        return info;
    }
};

// ============================================================================
// VPN Packet
// ============================================================================

/// VPN data packet
pub const VpnPacket = struct {
    /// Packet data (Ethernet frame)
    data: []u8,
    /// Packet size
    size: usize,
    /// Is broadcast packet
    is_broadcast: bool,
    /// Priority (QoS)
    priority: bool,
    /// Timestamp when received
    timestamp: i64,

    /// Check if packet is broadcast (first byte has multicast bit set)
    pub fn checkBroadcast(data: []const u8) bool {
        if (data.len >= 1) {
            return (data[0] & 0x01) != 0;
        }
        return false;
    }
};

// ============================================================================
// Packet Queue
// ============================================================================

/// Thread-safe packet queue
pub const PacketQueue = struct {
    allocator: Allocator,
    packets: std.ArrayListUnmanaged(VpnPacket),
    mutex: std.Thread.Mutex,
    max_size: usize,

    pub fn init(allocator: Allocator, max_size: usize) PacketQueue {
        return .{
            .allocator = allocator,
            .packets = .{},
            .mutex = .{},
            .max_size = max_size,
        };
    }

    pub fn deinit(self: *PacketQueue) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.packets.items) |packet| {
            self.allocator.free(packet.data);
        }
        self.packets.deinit(self.allocator);
    }

    /// Enqueue a packet (copies data)
    pub fn enqueue(self: *PacketQueue, data: []const u8, priority: bool) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Drop if queue is full
        if (self.packets.items.len >= self.max_size) {
            return;
        }

        const packet_data = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(packet_data);

        try self.packets.append(self.allocator, .{
            .data = packet_data,
            .size = data.len,
            .is_broadcast = VpnPacket.checkBroadcast(data),
            .priority = priority,
            .timestamp = std.time.milliTimestamp(),
        });
    }

    /// Dequeue a packet (caller owns the data)
    pub fn dequeue(self: *PacketQueue) ?VpnPacket {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.packets.items.len == 0) {
            return null;
        }

        // Return first packet
        return self.packets.orderedRemove(0);
    }

    /// Get queue length
    pub fn len(self: *PacketQueue) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.packets.items.len;
    }

    /// Check if queue is empty
    pub fn isEmpty(self: *PacketQueue) bool {
        return self.len() == 0;
    }
};

// ============================================================================
// Session
// ============================================================================

/// VPN Session
pub const Session = struct {
    allocator: Allocator,

    /// Session name
    name: [64]u8,

    /// Current state
    state: SessionState,

    /// Client status (for UI)
    client_status: ClientStatus,

    /// Session keys
    keys: SessionKeys,

    /// Session policy from server
    policy: SessionPolicy,

    /// Node information
    node_info: NodeInfo,

    /// Traffic statistics
    traffic: TrafficStats,

    /// Connection options
    server_host: [256]u8,
    server_port: u16,
    hub_name: [256]u8,
    username: [256]u8,

    /// Timing
    created_time: i64,
    last_comm_time: i64,
    timeout_ms: u64,
    keepalive_interval_ms: u64,

    /// Retry configuration
    retry_count: u32,
    max_retry_count: u32,
    retry_interval_ms: u64,

    /// Flags
    use_encryption: bool,
    use_compression: bool,
    half_connection: bool,
    qos_enabled: bool,
    bridge_mode: bool,
    monitor_mode: bool,

    /// Error information
    last_error: ?SessionError,
    error_code: u32,

    /// Send/receive queues
    send_queue: PacketQueue,
    recv_queue: PacketQueue,

    /// AES cipher for encryption (lazily initialized)
    send_cipher: ?Aes256Cbc,
    recv_cipher: ?Aes256Cbc,

    /// Create a new session
    pub fn init(allocator: Allocator, options: SessionOptions) Session {
        var sess = Session{
            .allocator = allocator,
            .name = [_]u8{0} ** 64,
            .state = .idle,
            .client_status = .idle,
            .keys = SessionKeys.generate(),
            .policy = .{},
            .node_info = NodeInfo.create(),
            .traffic = .{},
            .server_host = [_]u8{0} ** 256,
            .server_port = options.port,
            .hub_name = [_]u8{0} ** 256,
            .username = [_]u8{0} ** 256,
            .created_time = std.time.milliTimestamp(),
            .last_comm_time = std.time.milliTimestamp(),
            .timeout_ms = options.timeout_ms orelse Config.default_timeout_ms,
            .keepalive_interval_ms = options.keepalive_interval_ms orelse Config.keepalive_interval_ms,
            .retry_count = 0,
            .max_retry_count = options.max_retry_count orelse Config.default_retry_count,
            .retry_interval_ms = options.retry_interval_ms orelse Config.retry_interval_ms,
            .use_encryption = options.use_encryption,
            .use_compression = options.use_compression,
            .half_connection = options.half_connection,
            .qos_enabled = options.qos_enabled,
            .bridge_mode = false,
            .monitor_mode = false,
            .last_error = null,
            .error_code = 0,
            .send_queue = PacketQueue.init(allocator, Config.max_queue_size),
            .recv_queue = PacketQueue.init(allocator, Config.max_queue_size),
            .send_cipher = null,
            .recv_cipher = null,
        };

        // Copy strings
        const host_len = @min(options.host.len, sess.server_host.len - 1);
        @memcpy(sess.server_host[0..host_len], options.host[0..host_len]);

        const hub_len = @min(options.hub.len, sess.hub_name.len - 1);
        @memcpy(sess.hub_name[0..hub_len], options.hub[0..hub_len]);

        const user_len = @min(options.username.len, sess.username.len - 1);
        @memcpy(sess.username[0..user_len], options.username[0..user_len]);

        // Generate session name
        const session_name = "SES_";
        @memcpy(sess.name[0..session_name.len], session_name);

        return sess;
    }

    /// Clean up session resources
    pub fn deinit(self: *Session) void {
        self.send_queue.deinit();
        self.recv_queue.deinit();
    }

    /// Get current state
    pub fn getState(self: *const Session) SessionState {
        return self.state;
    }

    /// Check if session is connected
    pub fn isConnected(self: *const Session) bool {
        return self.state == .established;
    }

    /// Check if session timed out
    pub fn isTimedOut(self: *const Session) bool {
        const now = std.time.milliTimestamp();
        const elapsed: u64 = @intCast(now - self.last_comm_time);
        return elapsed > self.timeout_ms;
    }

    /// Check if keep-alive should be sent
    pub fn shouldSendKeepalive(self: *const Session) bool {
        const now = std.time.milliTimestamp();
        const elapsed: u64 = @intCast(now - self.last_comm_time);
        return elapsed > self.keepalive_interval_ms;
    }

    /// Update last communication time
    pub fn updateCommTime(self: *Session) void {
        self.last_comm_time = std.time.milliTimestamp();
    }

    /// Transition to a new state
    pub fn setState(self: *Session, new_state: SessionState) SessionError!void {
        // Validate state transitions
        const valid = switch (self.state) {
            .idle => new_state == .connecting or new_state == .error_state,
            .connecting => new_state == .handshake or new_state == .error_state or new_state == .retry_wait,
            .handshake => new_state == .authenticating or new_state == .error_state or new_state == .retry_wait,
            .authenticating => new_state == .established or new_state == .error_state or new_state == .retry_wait,
            .established => new_state == .disconnecting or new_state == .error_state,
            .disconnecting => new_state == .disconnected or new_state == .error_state,
            .disconnected => new_state == .connecting or new_state == .idle,
            .retry_wait => new_state == .connecting or new_state == .error_state or new_state == .idle,
            .error_state => new_state == .idle,
        };

        if (!valid) {
            return SessionError.InvalidState;
        }

        self.state = new_state;

        // Update client status for UI
        self.client_status = switch (new_state) {
            .idle => .idle,
            .connecting => .connecting,
            .handshake => .negotiation,
            .authenticating => .auth,
            .established => .established,
            .retry_wait => .retry,
            else => self.client_status,
        };
    }

    /// Set session error
    pub fn setError(self: *Session, err: SessionError, code: u32) void {
        self.last_error = err;
        self.error_code = code;
        self.state = .error_state;
    }

    /// Initialize encryption with derived keys
    pub fn initEncryption(self: *Session, password_hash: *const [20]u8, challenge: *const [20]u8) void {
        self.keys = SessionKeys.deriveFromAuth(password_hash, challenge);

        // Initialize ciphers with a random IV (IV will be updated per-packet)
        var iv: [16]u8 = undefined;
        randomBytes(&iv);

        self.send_cipher = Aes256Cbc.init(&self.keys.send_key, &iv);
        self.recv_cipher = Aes256Cbc.init(&self.keys.recv_key, &iv);

        self.use_encryption = true;
    }

    /// Encrypt a packet for sending
    pub fn encryptPacket(self: *Session, plaintext: []const u8) ![]u8 {
        if (!self.use_encryption or self.send_cipher == null) {
            // No encryption, return copy
            return try self.allocator.dupe(u8, plaintext);
        }

        var cipher = self.send_cipher.?;

        // Generate new IV for this packet
        var iv: [16]u8 = undefined;
        randomBytes(&iv);
        cipher.iv = iv;

        // Encrypt (includes padding)
        const ciphertext = try cipher.encrypt(self.allocator, plaintext);
        errdefer self.allocator.free(ciphertext);

        // Prepend IV
        const result = try self.allocator.alloc(u8, 16 + ciphertext.len);
        @memcpy(result[0..16], &iv);
        @memcpy(result[16..], ciphertext);
        self.allocator.free(ciphertext);

        return result;
    }

    /// Decrypt a received packet
    pub fn decryptPacket(self: *Session, ciphertext: []const u8) ![]u8 {
        if (!self.use_encryption or self.recv_cipher == null) {
            // No encryption
            return try self.allocator.dupe(u8, ciphertext);
        }

        if (ciphertext.len < 16) {
            return SessionError.EncryptionError;
        }

        var cipher = self.recv_cipher.?;

        // Extract IV from first 16 bytes
        cipher.iv = ciphertext[0..16].*;

        // Decrypt
        return cipher.decrypt(self.allocator, ciphertext[16..]) catch {
            return SessionError.EncryptionError;
        };
    }

    /// Queue a packet for sending
    pub fn sendPacket(self: *Session, data: []const u8, priority: bool) !void {
        if (self.state != .established) {
            return SessionError.InvalidState;
        }

        // Update statistics
        const is_broadcast = VpnPacket.checkBroadcast(data);
        self.traffic.send.addPacket(data.len, is_broadcast);
        self.traffic.total_send_size_real += data.len;

        try self.send_queue.enqueue(data, priority);
    }

    /// Get next packet to send (encrypted if enabled)
    pub fn getNextSendPacket(self: *Session) !?[]u8 {
        if (self.send_queue.dequeue()) |packet| {
            defer self.allocator.free(packet.data);

            if (self.use_encryption) {
                return try self.encryptPacket(packet.data);
            } else {
                return try self.allocator.dupe(u8, packet.data);
            }
        }
        return null;
    }

    /// Process a received packet (decrypt and queue)
    pub fn receivePacket(self: *Session, data: []const u8) !void {
        if (self.state != .established) {
            return;
        }

        self.updateCommTime();

        // Decrypt if needed
        const plaintext = if (self.use_encryption)
            try self.decryptPacket(data)
        else
            try self.allocator.dupe(u8, data);

        errdefer self.allocator.free(plaintext);

        // Update statistics
        const is_broadcast = VpnPacket.checkBroadcast(plaintext);
        self.traffic.recv.addPacket(plaintext.len, is_broadcast);
        self.traffic.total_recv_size += data.len;
        self.traffic.total_recv_size_real += plaintext.len;

        // Queue for processing
        try self.recv_queue.enqueue(plaintext, false);
        self.allocator.free(plaintext);
    }

    /// Get next received packet
    pub fn getNextRecvPacket(self: *Session) ?VpnPacket {
        return self.recv_queue.dequeue();
    }

    /// Get session name as string
    pub fn getName(self: *const Session) []const u8 {
        const end = mem.indexOfScalar(u8, &self.name, 0) orelse self.name.len;
        return self.name[0..end];
    }

    /// Get session key as hex string
    pub fn getSessionKeyStr(self: *const Session) [40]u8 {
        return self.keys.sessionKeyStr();
    }
};

/// Session creation options
pub const SessionOptions = struct {
    host: []const u8,
    port: u16 = 443,
    hub: []const u8,
    username: []const u8,
    use_encryption: bool = true,
    use_compression: bool = false,
    half_connection: bool = false,
    qos_enabled: bool = true,
    timeout_ms: ?u64 = null,
    keepalive_interval_ms: ?u64 = null,
    max_retry_count: ?u32 = null,
    retry_interval_ms: ?u64 = null,
};

// ============================================================================
// Keep-Alive
// ============================================================================

/// Keep-alive packet content
pub const KEEP_ALIVE_STRING = "Internet Connectivity Check";

/// Create a keep-alive packet
pub fn createKeepAlivePacket(allocator: Allocator) ![]u8 {
    return try allocator.dupe(u8, KEEP_ALIVE_STRING);
}

/// Check if packet is a keep-alive
pub fn isKeepAlivePacket(data: []const u8) bool {
    return mem.eql(u8, data, KEEP_ALIVE_STRING);
}

// ============================================================================
// Tests
// ============================================================================

test "SessionKeys generation" {
    const keys = SessionKeys.generate();

    // Check that keys are not all zeros
    var all_zero = true;
    for (keys.session_key) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
    try testing.expect(keys.use_encryption);
}

test "SessionKeys derivation" {
    const password_hash = [_]u8{0x01} ** 20;
    const challenge = [_]u8{0x02} ** 20;

    const keys = SessionKeys.deriveFromAuth(&password_hash, &challenge);

    // Keys should be deterministic
    const keys2 = SessionKeys.deriveFromAuth(&password_hash, &challenge);
    try testing.expectEqualSlices(u8, &keys.send_key, &keys2.send_key);
    try testing.expectEqualSlices(u8, &keys.recv_key, &keys2.recv_key);

    // Send and recv keys should be different
    try testing.expect(!mem.eql(u8, &keys.send_key, &keys.recv_key));
}

test "SessionKeys hex string" {
    const keys = SessionKeys.generate();
    const hex = keys.sessionKeyStr();

    // Should be 40 hex characters
    try testing.expectEqual(@as(usize, 40), hex.len);

    // All should be valid hex characters
    for (hex) |c| {
        try testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "TrafficCounters" {
    var counters = TrafficCounters{};

    counters.addPacket(100, false); // unicast
    counters.addPacket(200, true); // broadcast

    try testing.expectEqual(@as(u64, 1), counters.unicast_count);
    try testing.expectEqual(@as(u64, 100), counters.unicast_bytes);
    try testing.expectEqual(@as(u64, 1), counters.broadcast_count);
    try testing.expectEqual(@as(u64, 200), counters.broadcast_bytes);
    try testing.expectEqual(@as(u64, 2), counters.totalCount());
    try testing.expectEqual(@as(u64, 300), counters.totalBytes());
}

test "Session creation" {
    const sess = Session.init(testing.allocator, .{
        .host = "vpn.example.com",
        .port = 443,
        .hub = "DEFAULT",
        .username = "testuser",
    });
    defer @constCast(&sess).deinit();

    try testing.expectEqual(SessionState.idle, sess.state);
    try testing.expectEqual(ClientStatus.idle, sess.client_status);
    try testing.expect(sess.use_encryption);
}

test "Session state transitions" {
    var sess = Session.init(testing.allocator, .{
        .host = "vpn.example.com",
        .hub = "DEFAULT",
        .username = "testuser",
    });
    defer sess.deinit();

    // Valid transitions
    try sess.setState(.connecting);
    try testing.expectEqual(SessionState.connecting, sess.state);

    try sess.setState(.handshake);
    try testing.expectEqual(SessionState.handshake, sess.state);

    try sess.setState(.authenticating);
    try sess.setState(.established);
    try testing.expectEqual(SessionState.established, sess.state);
    try testing.expect(sess.isConnected());

    // Invalid transition
    try testing.expectError(SessionError.InvalidState, sess.setState(.idle));
}

test "PacketQueue operations" {
    var queue = PacketQueue.init(testing.allocator, 10);
    defer queue.deinit();

    const data1 = &[_]u8{ 0x00, 0x02, 0x03 }; // unicast (first byte even)
    const data2 = &[_]u8{ 0xFF, 0xFE, 0xFD }; // broadcast (first byte has bit 0 set)

    try queue.enqueue(data1, false);
    try queue.enqueue(data2, true);

    try testing.expectEqual(@as(usize, 2), queue.len());

    const packet1 = queue.dequeue().?;
    defer testing.allocator.free(packet1.data);
    try testing.expectEqualSlices(u8, data1, packet1.data);
    try testing.expect(!packet1.is_broadcast);

    const packet2 = queue.dequeue().?;
    defer testing.allocator.free(packet2.data);
    try testing.expectEqualSlices(u8, data2, packet2.data);
    try testing.expect(packet2.is_broadcast);

    try testing.expect(queue.isEmpty());
}

test "VpnPacket broadcast detection" {
    // Unicast (first byte even)
    const unicast = &[_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    try testing.expect(!VpnPacket.checkBroadcast(unicast));

    // Broadcast (first byte has bit 0 set)
    const broadcast = &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    try testing.expect(VpnPacket.checkBroadcast(broadcast));

    // Multicast
    const multicast = &[_]u8{ 0x01, 0x00, 0x5E, 0x00, 0x00, 0x01 };
    try testing.expect(VpnPacket.checkBroadcast(multicast));
}

test "Keep-alive packet" {
    const packet = try createKeepAlivePacket(testing.allocator);
    defer testing.allocator.free(packet);

    try testing.expect(isKeepAlivePacket(packet));
    try testing.expect(!isKeepAlivePacket("other data"));
}

test "NodeInfo creation" {
    const info = NodeInfo.create();

    // Should have product name set
    try testing.expect(info.client_product_name[0] != 0);
    try testing.expectEqual(@as(u32, 419), info.client_version);

    // Unique ID should not be all zeros
    var all_zero = true;
    for (info.unique_id) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "AES-256-CBC encryption round-trip" {
    const key = [_]u8{0x01} ** 32;
    const iv = [_]u8{0x02} ** 16;

    var cipher = Aes256Cbc.init(&key, &iv);

    const plaintext = "Hello, SoftEther VPN!";
    const encrypted = try cipher.encrypt(testing.allocator, plaintext);
    defer testing.allocator.free(encrypted);

    // Reset cipher to decrypt
    cipher.iv = iv;
    const decrypted = try cipher.decrypt(testing.allocator, encrypted);
    defer testing.allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}
