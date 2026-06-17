//! Error Types
//!
//! Consolidated error definitions used across the codebase.

const std = @import("std");

/// VPN error types
pub const VpnError = error{
    // Initialization errors
    InitializationFailed,
    CleanupFailed,
    ClientCreationFailed,
    ConfigurationError,

    // Connection errors
    ConnectionFailed,
    DisconnectionFailed,
    AlreadyConnected,
    NotConnected,
    TimeoutError,

    // Authentication errors
    AuthenticationFailed,
    InvalidCredentials,
    CertificateError,

    // Configuration errors
    InvalidParameter,
    InvalidServerAddress,
    InvalidPort,
    InvalidHubName,
    MissingParameter,

    // Operation errors
    OperationFailed,
    NotInitialized,
    InternalError,
    OutOfMemory,

    // Network errors
    NetworkError,
    ProtocolError,
    ServerUnreachable,
};

/// Get error message for VpnError
pub fn errorMessage(err: VpnError) []const u8 {
    return switch (err) {
        VpnError.InitializationFailed => "Failed to initialize VPN client",
        VpnError.CleanupFailed => "Failed to cleanup resources",
        VpnError.ClientCreationFailed => "Failed to create client instance",
        VpnError.ConfigurationError => "Configuration error",
        VpnError.ConnectionFailed => "Failed to establish VPN connection",
        VpnError.DisconnectionFailed => "Failed to disconnect",
        VpnError.AlreadyConnected => "Already connected",
        VpnError.NotConnected => "Not connected",
        VpnError.TimeoutError => "Operation timed out",
        VpnError.AuthenticationFailed => "Authentication failed",
        VpnError.InvalidCredentials => "Invalid credentials provided",
        VpnError.CertificateError => "Certificate validation error",
        VpnError.InvalidParameter => "Invalid parameter",
        VpnError.InvalidServerAddress => "Invalid server address",
        VpnError.InvalidPort => "Invalid port number",
        VpnError.InvalidHubName => "Invalid hub name",
        VpnError.MissingParameter => "Required parameter is missing",
        VpnError.OperationFailed => "Operation failed",
        VpnError.NotInitialized => "Not initialized",
        VpnError.InternalError => "Internal error",
        VpnError.OutOfMemory => "Out of memory",
        VpnError.NetworkError => "Network error occurred",
        VpnError.ProtocolError => "VPN protocol error",
        VpnError.ServerUnreachable => "Server unreachable",
    };
}

test "error message lookup" {
    try std.testing.expectEqualStrings("Already connected", errorMessage(VpnError.AlreadyConnected));
    try std.testing.expectEqualStrings("Authentication failed", errorMessage(VpnError.AuthenticationFailed));
}
