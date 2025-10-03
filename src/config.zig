const std = @import("std");
const errors = @import("errors.zig");

const VpnError = errors.VpnError;

/// Authentication method
pub const AuthMethod = union(enum) {
    anonymous,
    password: struct {
        username: []const u8,
        password: []const u8,
        is_hashed: bool = false,  // True if password is pre-hashed (base64-encoded SHA1)
    },
    certificate: struct {
        cert_path: []const u8,
        key_path: []const u8,
    },
    smart_card,
};

/// VPN connection configuration
pub const ConnectionConfig = struct {
    server_name: []const u8,
    server_port: u16,
    hub_name: []const u8,
    account_name: []const u8,
    auth: AuthMethod,
    use_encrypt: bool = true,
    use_compress: bool = true,
    max_connection: u32 = 1,
    half_connection: bool = false,
    additional_connection_interval: u32 = 1,

    /// Create a configuration builder
    pub fn builder() ConfigBuilder {
        return ConfigBuilder{};
    }
};

/// Builder pattern for ConnectionConfig
pub const ConfigBuilder = struct {
    server_name: ?[]const u8 = null,
    server_port: u16 = 443,
    hub_name: ?[]const u8 = null,
    account_name: ?[]const u8 = null,
    auth: ?AuthMethod = null,
    use_encrypt: bool = true,
    use_compress: bool = true,
    max_connection: u32 = 1,
    half_connection: bool = false,
    additional_connection_interval: u32 = 1,

    /// Set VPN server address and port
    pub fn setServer(self: *ConfigBuilder, name: []const u8, port: u16) *ConfigBuilder {
        self.server_name = name;
        self.server_port = port;
        return self;
    }

    /// Set virtual hub name
    pub fn setHub(self: *ConfigBuilder, hub: []const u8) *ConfigBuilder {
        self.hub_name = hub;
        return self;
    }

    /// Set account name
    pub fn setAccount(self: *ConfigBuilder, account: []const u8) *ConfigBuilder {
        self.account_name = account;
        return self;
    }

    /// Set authentication method
    pub fn setAuth(self: *ConfigBuilder, auth: AuthMethod) *ConfigBuilder {
        self.auth = auth;
        return self;
    }

    /// Set encryption flag
    pub fn setEncrypt(self: *ConfigBuilder, encrypt: bool) *ConfigBuilder {
        self.use_encrypt = encrypt;
        return self;
    }

    /// Set compression flag
    pub fn setCompress(self: *ConfigBuilder, compress: bool) *ConfigBuilder {
        self.use_compress = compress;
        return self;
    }

    /// Set maximum number of connections
    pub fn setMaxConnection(self: *ConfigBuilder, max: u32) *ConfigBuilder {
        self.max_connection = max;
        return self;
    }

    /// Build the final configuration
    pub fn build(self: ConfigBuilder) !ConnectionConfig {
        const server_name = self.server_name orelse return VpnError.MissingParameter;
        const hub_name = self.hub_name orelse return VpnError.MissingParameter;
        const account_name = self.account_name orelse return VpnError.MissingParameter;
        const auth = self.auth orelse return VpnError.MissingParameter;

        return ConnectionConfig{
            .server_name = server_name,
            .server_port = self.server_port,
            .hub_name = hub_name,
            .account_name = account_name,
            .auth = auth,
            .use_encrypt = self.use_encrypt,
            .use_compress = self.use_compress,
            .max_connection = self.max_connection,
            .half_connection = self.half_connection,
            .additional_connection_interval = self.additional_connection_interval,
        };
    }
};

test "config builder validation" {
    // Missing server should fail
    const result1 = ConnectionConfig.builder()
        .setHub("HUB")
        .setAccount("test")
        .setAuth(.anonymous)
        .build();
    try std.testing.expectError(VpnError.MissingParameter, result1);

    // Complete config should succeed
    const result2 = ConnectionConfig.builder()
        .setServer("vpn.example.com", 443)
        .setHub("HUB")
        .setAccount("test")
        .setAuth(.anonymous)
        .build();
    try std.testing.expect(result2 != VpnError.MissingParameter);
}

test "config builder chaining" {
    var builder = ConnectionConfig.builder();
    _ = builder
        .setServer("test.vpn.com", 8443)
        .setHub("TEST_HUB")
        .setAccount("user1")
        .setEncrypt(false)
        .setCompress(false);

    try std.testing.expectEqualStrings("test.vpn.com", builder.server_name.?);
    try std.testing.expectEqual(@as(u16, 8443), builder.server_port);
    try std.testing.expectEqual(false, builder.use_encrypt);
}
