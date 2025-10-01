const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Detect target OS
    const target_os = target.result.os.tag;

    // Platform-specific OpenSSL paths
    const openssl_prefix = switch (target_os) {
        .macos => "/opt/homebrew/opt/openssl@3",
        .linux => "/usr",
        .windows => "C:/OpenSSL-Win64",
        else => "/usr",
    };

    // Base C flags (common to all platforms)
    const base_c_flags = &[_][]const u8{
        "-std=c99",
        "-D_REENTRANT",
        "-D_THREAD_SAFE",
        "-DCPU_64",
        "-D_FILE_OFFSET_BITS=64",
        "-DVPN_SPEED",
        "-D__bool_true_false_are_defined=1",
        "-Wno-deprecated-declarations",
        "-Wno-unused-parameter",
        "-Wno-unused-variable",
        "-Wno-sign-compare",
        "-Wno-incompatible-function-pointer-types",
        "-Wno-int-conversion",
        "-Wno-incompatible-pointer-types-discards-qualifiers",
        "-Wno-implicit-function-declaration",
        "-Wno-strict-prototypes",
        "-fno-strict-aliasing",
        "-fsigned-char",
        "-fno-sanitize=shift",
        "-fno-sanitize=null",
        "-fno-sanitize=undefined",
    };

    // Platform-specific defines
    var c_flags: []const []const u8 = undefined;

    if (target_os == .macos) {
        c_flags = base_c_flags ++ &[_][]const u8{ "-DUNIX", "-DUNIX_MACOS" };
    } else if (target_os == .linux) {
        c_flags = base_c_flags ++ &[_][]const u8{ "-DUNIX", "-DUNIX_LINUX" };
    } else if (target_os == .windows) {
        c_flags = base_c_flags ++ &[_][]const u8{ "-DWIN32", "-D_WIN32" };
    } else {
        c_flags = base_c_flags ++ &[_][]const u8{"-DUNIX"};
    }

    // Platform-specific packet adapter and timing files
    const packet_adapter_file = switch (target_os) {
        .macos => "src/bridge/packet_adapter_macos.c",
        .linux => "src/bridge/packet_adapter_linux.c",
        .windows => "src/bridge/packet_adapter_windows.c",
        else => "src/bridge/packet_adapter_linux.c", // fallback
    };

    const tick64_file = switch (target_os) {
        .macos => "src/bridge/tick64_macos.c",
        .linux => "src/bridge/tick64_linux.c",
        .windows => "src/bridge/tick64_windows.c",
        else => "src/bridge/tick64_linux.c", // fallback
    };

    const c_sources = &[_][]const u8{
        "src/bridge/softether_bridge.c",
        "src/bridge/unix_bridge.c",
        tick64_file,
        packet_adapter_file,
        "src/bridge/Mayaqua/Mayaqua.c",
        "src/bridge/Mayaqua/Memory.c",
        "SoftEtherVPN_Stable/src/Mayaqua/Str.c",
        "src/bridge/Mayaqua/Object.c",
        "SoftEtherVPN_Stable/src/Mayaqua/OS.c",
        "SoftEtherVPN_Stable/src/Mayaqua/FileIO.c",
        "src/bridge/Mayaqua/Kernel.c",
        "SoftEtherVPN_Stable/src/Mayaqua/Network.c",
        "SoftEtherVPN_Stable/src/Mayaqua/TcpIp.c",
        "SoftEtherVPN_Stable/src/Mayaqua/Encrypt.c",
        "SoftEtherVPN_Stable/src/Mayaqua/Secure.c",
        "SoftEtherVPN_Stable/src/Mayaqua/Pack.c",
        "SoftEtherVPN_Stable/src/Mayaqua/Cfg.c",
        "SoftEtherVPN_Stable/src/Mayaqua/Table.c",
        "SoftEtherVPN_Stable/src/Mayaqua/Tracking.c",
        "SoftEtherVPN_Stable/src/Mayaqua/Microsoft.c",
        "SoftEtherVPN_Stable/src/Mayaqua/Internat.c",
        "SoftEtherVPN_Stable/src/Cedar/Cedar.c",
        "src/bridge/Cedar/Client.c",
        "src/bridge/Cedar/Protocol.c",
        "SoftEtherVPN_Stable/src/Cedar/Connection.c",
        "src/bridge/Cedar/Session.c",
        "SoftEtherVPN_Stable/src/Cedar/Account.c",
        "SoftEtherVPN_Stable/src/Cedar/Admin.c",
        "SoftEtherVPN_Stable/src/Cedar/Command.c",
        "SoftEtherVPN_Stable/src/Cedar/Hub.c",
        "SoftEtherVPN_Stable/src/Cedar/Listener.c",
        "SoftEtherVPN_Stable/src/Cedar/Logging.c",
        "SoftEtherVPN_Stable/src/Cedar/Sam.c",
        "SoftEtherVPN_Stable/src/Cedar/Server.c",
        "SoftEtherVPN_Stable/src/Cedar/Virtual.c",
        "SoftEtherVPN_Stable/src/Cedar/Link.c",
        "SoftEtherVPN_Stable/src/Cedar/SecureNAT.c",
        "SoftEtherVPN_Stable/src/Cedar/NullLan.c",
        "SoftEtherVPN_Stable/src/Cedar/Bridge.c",
        "SoftEtherVPN_Stable/src/Cedar/BridgeUnix.c",
        "SoftEtherVPN_Stable/src/Cedar/Nat.c",
        "SoftEtherVPN_Stable/src/Cedar/UdpAccel.c",
        "SoftEtherVPN_Stable/src/Cedar/Database.c",
        "SoftEtherVPN_Stable/src/Cedar/Remote.c",
        "SoftEtherVPN_Stable/src/Cedar/DDNS.c",
        "SoftEtherVPN_Stable/src/Cedar/AzureClient.c",
        "SoftEtherVPN_Stable/src/Cedar/AzureServer.c",
        "SoftEtherVPN_Stable/src/Cedar/Radius.c",
        "SoftEtherVPN_Stable/src/Cedar/Console.c",
        "SoftEtherVPN_Stable/src/Cedar/Layer3.c",
        "SoftEtherVPN_Stable/src/Cedar/Interop_OpenVPN.c",
        "SoftEtherVPN_Stable/src/Cedar/Interop_SSTP.c",
        "SoftEtherVPN_Stable/src/Cedar/IPsec.c",
        "SoftEtherVPN_Stable/src/Cedar/IPsec_IKE.c",
        "SoftEtherVPN_Stable/src/Cedar/IPsec_IkePacket.c",
        "SoftEtherVPN_Stable/src/Cedar/IPsec_L2TP.c",
        "SoftEtherVPN_Stable/src/Cedar/IPsec_PPP.c",
        "SoftEtherVPN_Stable/src/Cedar/IPsec_EtherIP.c",
        "SoftEtherVPN_Stable/src/Cedar/IPsec_IPC.c",
        "SoftEtherVPN_Stable/src/Cedar/EtherLog.c",
        "SoftEtherVPN_Stable/src/Cedar/WebUI.c",
        "SoftEtherVPN_Stable/src/Cedar/WaterMark.c",
        "SoftEtherVPN_Stable/src/Cedar/NativeStack.c",
    };

    // ============================================
    // 1. LIBRARY MODULE (for Zig programs)
    // ============================================
    const lib_module = b.addModule("softether", .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
    });
    lib_module.addIncludePath(b.path("src"));
    lib_module.link_libc = true;

    // ============================================
    // 2. CLI CLIENT (production tool)
    // ============================================
    const cli = b.addExecutable(.{
        .name = "vpnclient",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "softether", .module = lib_module },
            },
        }),
    });

    cli.addIncludePath(b.path("src"));
    cli.addIncludePath(b.path("src/bridge"));
    cli.addIncludePath(b.path("SoftEtherVPN_Stable/src"));
    cli.addIncludePath(b.path("SoftEtherVPN_Stable/src/Mayaqua"));
    cli.addIncludePath(b.path("SoftEtherVPN_Stable/src/Cedar"));

    // Add OpenSSL include path (platform-specific)
    const openssl_include = b.fmt("{s}/include", .{openssl_prefix});
    cli.addIncludePath(.{ .cwd_relative = openssl_include });

    cli.addCSourceFiles(.{
        .files = c_sources,
        .flags = c_flags,
    });

    // Add OpenSSL library path (platform-specific)
    const openssl_lib = b.fmt("{s}/lib", .{openssl_prefix});
    cli.addLibraryPath(.{ .cwd_relative = openssl_lib });

    // Link OpenSSL (all platforms)
    cli.linkSystemLibrary("ssl");
    cli.linkSystemLibrary("crypto");
    cli.linkLibC();

    // Platform-specific system libraries
    if (target_os != .windows) {
        // Unix-like systems
        cli.linkSystemLibrary("pthread");
        cli.linkSystemLibrary("z");

        if (target_os == .macos) {
            cli.linkSystemLibrary("iconv");
            cli.linkSystemLibrary("readline");
            cli.linkSystemLibrary("ncurses");
        } else if (target_os == .linux) {
            cli.linkSystemLibrary("rt");
            cli.linkSystemLibrary("dl");
        }
    } else {
        // Windows
        cli.linkSystemLibrary("ws2_32");
        cli.linkSystemLibrary("iphlpapi");
        cli.linkSystemLibrary("advapi32");
    }

    b.installArtifact(cli);

    // Run step for CLI
    const run_cli = b.addRunArtifact(cli);
    run_cli.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cli.addArgs(args);
    }

    const run_step = b.step("run", "Run the VPN client CLI");
    run_step.dependOn(&run_cli.step);
}
