const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Build option to use Zig packet adapter
    const use_zig_adapter = b.option(bool, "use-zig-adapter", "Use Zig packet adapter instead of C adapter (default: false)") orelse false;

    // Detect target OS
    const target_os = target.result.os.tag;
    const is_ios = target_os == .ios;

    // Platform-specific OpenSSL paths
    const openssl_prefix = switch (target_os) {
        .macos => "/opt/homebrew/opt/openssl@3",
        .ios => "/opt/homebrew/opt/openssl@3", // Will use macOS OpenSSL for now
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
    var c_flags_list = std.ArrayList([]const u8){};
    c_flags_list = std.ArrayList([]const u8).initCapacity(b.allocator, 50) catch unreachable;
    defer c_flags_list.deinit(b.allocator);

    // Add base flags
    c_flags_list.appendSlice(b.allocator, base_c_flags) catch unreachable;

    // Add Zig adapter flag if enabled
    if (use_zig_adapter) {
        c_flags_list.append(b.allocator, "-DUSE_ZIG_ADAPTER=1") catch unreachable;
    }

    if (is_ios) {
        c_flags_list.appendSlice(b.allocator, &[_][]const u8{ "-DUNIX", "-DUNIX_MACOS", "-DUNIX_IOS", "-DTARGET_OS_IPHONE=1" }) catch unreachable;
    } else if (target_os == .macos) {
        c_flags_list.appendSlice(b.allocator, &[_][]const u8{ "-DUNIX", "-DUNIX_MACOS" }) catch unreachable;
    } else if (target_os == .linux) {
        c_flags_list.appendSlice(b.allocator, &[_][]const u8{ "-DUNIX", "-DUNIX_LINUX" }) catch unreachable;
    } else if (target_os == .windows) {
        c_flags_list.appendSlice(b.allocator, &[_][]const u8{ "-DWIN32", "-D_WIN32" }) catch unreachable;
    } else {
        c_flags_list.append(b.allocator, "-DUNIX") catch unreachable;
    }

    const c_flags = c_flags_list.items;

    // Platform-specific packet adapter and timing files
    const packet_adapter_file = switch (target_os) {
        .ios => "src/bridge/ios/packet_adapter_ios.c",
        .macos => "src/bridge/packet_adapter_macos.c",
        .linux => "src/bridge/packet_adapter_linux.c",
        .windows => "src/bridge/packet_adapter_windows.c",
        else => "src/bridge/packet_adapter_linux.c", // fallback
    };

    const tick64_file = switch (target_os) {
        .macos, .ios => "src/bridge/tick64_macos.c",
        .linux => "src/bridge/tick64_linux.c",
        .windows => "src/bridge/tick64_windows.c",
        else => "src/bridge/tick64_linux.c", // fallback
    };

    const c_sources = &[_][]const u8{
        "src/bridge/softether_bridge.c",
        "src/bridge/unix_bridge.c",
        tick64_file,
        packet_adapter_file,
        "src/bridge/zig_packet_adapter.c", // Zig adapter wrapper
        "src/bridge/logging.c", // Phase 2: Log level system
        "src/bridge/security_utils.c", // Phase 3: Secure password handling
        "src/bridge/client_bridge.c", // NEW: Zig adapter bridge (replaces VLanGetPacketAdapter)
        "src/bridge/zig_bridge.c", // NEW: C wrapper for Zig packet adapter
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
    };

    // NativeStack.c uses system() which is unavailable on iOS
    // It's only needed for server-side routing, not client VPN
    const native_stack_sources = &[_][]const u8{
        "SoftEtherVPN_Stable/src/Cedar/NativeStack.c",
    };

    // ============================================
    // 1. LIBRARY MODULE (for Zig programs)
    // ============================================

    // Add ZigTapTun dependency
    const taptun = b.dependency("taptun", .{
        .target = target,
        .optimize = optimize,
    });

    const lib_module = b.addModule("softether", .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
    });
    lib_module.addIncludePath(b.path("src"));
    lib_module.addImport("taptun", taptun.module("taptun"));
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

    // Add NativeStack for non-iOS builds
    if (!is_ios) {
        cli.addCSourceFiles(.{
            .files = native_stack_sources,
            .flags = c_flags,
        });
    }

    // Add ZigTapTun wrapper module
    const taptun_wrapper_module = b.createModule(.{
        .root_source_file = b.path("src/bridge/taptun_wrapper.zig"),
        .target = target,
        .optimize = optimize,
    });
    taptun_wrapper_module.addImport("taptun", taptun.module("taptun"));

    const taptun_wrapper = b.addObject(.{
        .name = "taptun_wrapper",
        .root_module = taptun_wrapper_module,
    });
    cli.addObject(taptun_wrapper);

    // Add Zig packet adapter (Phase 1) - compiled as static object
    const packet_adapter_module = b.createModule(.{
        .root_source_file = b.path("src/packet/adapter.zig"),
        .target = target,
        .optimize = optimize,
    });

    const packet_adapter_obj = b.addObject(.{
        .name = "zig_packet_adapter",
        .root_module = packet_adapter_module,
    });
    cli.addObject(packet_adapter_obj);

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

    // ============================================
    // 3. STATIC LIBRARY (for iOS/FFI)
    // ============================================
    const lib = b.addLibrary(.{
        .name = "SoftEtherClient",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });

    lib.linkLibC();

    // Add all the same includes and sources as CLI
    lib.addIncludePath(b.path("src"));
    lib.addIncludePath(b.path("src/bridge"));
    lib.addIncludePath(b.path("include"));
    lib.addIncludePath(b.path("SoftEtherVPN_Stable/src"));
    lib.addIncludePath(b.path("SoftEtherVPN_Stable/src/Mayaqua"));
    lib.addIncludePath(b.path("SoftEtherVPN_Stable/src/Cedar"));
    lib.addIncludePath(.{ .cwd_relative = openssl_include });

    // Add iOS SDK includes when cross-compiling for iOS
    if (is_ios) {
        // Add our iOS stub headers FIRST (before system includes)
        lib.addIncludePath(b.path("src/bridge/ios_include"));

        const ios_sdk_path = if (target.result.cpu.arch == .aarch64 and target.result.abi == .simulator)
            "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk"
        else if (target.result.cpu.arch == .x86_64)
            "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk"
        else
            "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk";

        const ios_include = b.fmt("{s}/usr/include", .{ios_sdk_path});
        lib.addSystemIncludePath(.{ .cwd_relative = ios_include });
    }

    // Add C sources
    lib.addCSourceFiles(.{
        .files = c_sources,
        .flags = c_flags,
    });

    // Add NativeStack for non-iOS builds
    if (!is_ios) {
        lib.addCSourceFiles(.{
            .files = native_stack_sources,
            .flags = c_flags,
        });
    }

    // Add FFI implementation
    lib.addCSourceFile(.{
        .file = b.path("src/bridge/ios_ffi.c"),
        .flags = c_flags,
    });

    // For iOS builds, skip OpenSSL linking (will be provided by XCFramework or system)
    if (!is_ios) {
        lib.addLibraryPath(.{ .cwd_relative = openssl_lib });
        lib.linkSystemLibrary("ssl");
        lib.linkSystemLibrary("crypto");
    }
    lib.linkLibC();

    // For iOS, use iOS SDK system libraries instead of macOS ones
    if (is_ios) {
        // For iOS cross-compilation, don't link any system libraries
        // They will be linked by Xcode when building the final app
        // Just link libc
    } else if (target_os == .macos) {
        lib.linkSystemLibrary("pthread");
        lib.linkSystemLibrary("z");
        lib.linkSystemLibrary("iconv");
    } else if (target_os == .linux) {
        lib.linkSystemLibrary("pthread");
        lib.linkSystemLibrary("z");
        lib.linkSystemLibrary("rt");
        lib.linkSystemLibrary("dl");
    } else if (target_os == .windows) {
        lib.linkSystemLibrary("ws2_32");
        lib.linkSystemLibrary("iphlpapi");
        lib.linkSystemLibrary("advapi32");
    }

    b.installArtifact(lib);

    // Add a step to build just the library
    const lib_step = b.step("lib", "Build static library for iOS/FFI");
    lib_step.dependOn(&b.addInstallArtifact(lib, .{}).step);
}
