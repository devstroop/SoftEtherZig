const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });

    // Build option to select packet adapter (Zig adapter is default for better performance)
    const use_zig_adapter = b.option(bool, "use-zig-adapter", "Use Zig packet adapter instead of C (default: true)") orelse true;

    // Detect target OS
    const target_os = target.result.os.tag;
    const is_ios = target_os == .ios;

    // Build option for SSL: use system OpenSSL on native macOS/Linux, OpenSSL-Zig for iOS/cross-compile
    const is_native_desktop = (target_os == .macos or target_os == .linux) and
        target.result.cpu.arch == std.Target.Cpu.Arch.aarch64;
    const use_system_ssl = b.option(bool, "system-ssl", "Use system OpenSSL instead of OpenSSL-Zig (default: true for native macOS/Linux)") orelse
        is_native_desktop;

    // iOS SDK configuration for OpenSSL-Zig
    const ios_sdk_path = if (is_ios) blk: {
        if (target.result.cpu.arch == .aarch64 and target.result.abi == .simulator) {
            break :blk "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk";
        } else if (target.result.cpu.arch == .x86_64) {
            break :blk "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk";
        } else {
            break :blk "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk";
        }
    } else null;

    // Get OpenSSL dependency (conditional based on use_system_ssl)
    const openssl_dep = if (!use_system_ssl) b.dependency("openssl", .{
        .target = target,
        .optimize = optimize,
    }) else null;
    const openssl = if (openssl_dep) |dep| blk: {
        const ssl_lib = dep.artifact("ssl");
        // Add iOS SDK sysroot for OpenSSL-Zig
        if (ios_sdk_path) |sdk| {
            const ios_include = b.fmt("{s}/usr/include", .{sdk});
            const ios_frameworks = b.fmt("{s}/System/Library/Frameworks", .{sdk});
            ssl_lib.addSystemIncludePath(.{ .cwd_relative = ios_include });
            ssl_lib.addFrameworkPath(.{ .cwd_relative = ios_frameworks });
            // iOS doesn't have CoreServices, use Foundation instead
            ssl_lib.linkFramework("Foundation");
            ssl_lib.linkFramework("Security");
        }
        break :blk ssl_lib;
    } else null;

    const crypto = if (openssl_dep) |dep| blk: {
        const crypto_lib = dep.artifact("crypto");
        // Add iOS SDK sysroot for OpenSSL-Zig
        if (ios_sdk_path) |sdk| {
            const ios_include = b.fmt("{s}/usr/include", .{sdk});
            const ios_frameworks = b.fmt("{s}/System/Library/Frameworks", .{sdk});
            crypto_lib.addSystemIncludePath(.{ .cwd_relative = ios_include });
            crypto_lib.addFrameworkPath(.{ .cwd_relative = ios_frameworks });
            // iOS doesn't have CoreServices, use Foundation instead
            crypto_lib.linkFramework("Foundation");
            crypto_lib.linkFramework("Security");
        }
        break :blk crypto_lib;
    } else null;

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

    // Print build configuration
    std.debug.print("Build Configuration:\n", .{});
    std.debug.print("  Target: {s}\n", .{@tagName(target_os)});
    std.debug.print("  Optimize: {s}\n", .{@tagName(optimize)});
    std.debug.print("  SSL: {s}\n", .{if (use_system_ssl) "system" else "OpenSSL-Zig"});
    std.debug.print("  Packet Adapter: {s}\n", .{if (use_zig_adapter) "Zig (native)" else "C (legacy)"});
    std.debug.print("\n", .{});

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

    // Get the taptun module and configure it for iOS if needed
    const taptun_module = taptun.module("taptun");
    if (is_ios) {
        if (ios_sdk_path) |sdk| {
            const ios_include = b.fmt("{s}/usr/include", .{sdk});
            taptun_module.addSystemIncludePath(.{ .cwd_relative = ios_include });
        }
    }

    const lib_module = b.addModule("softether", .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
    });
    lib_module.addIncludePath(b.path("src"));
    lib_module.addImport("taptun", taptun_module);
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

    // Link OpenSSL (system or bundled)
    if (use_system_ssl) {
        cli.linkSystemLibrary("ssl");
        cli.linkSystemLibrary("crypto");
    } else {
        if (crypto) |c| cli.linkLibrary(c);
        if (openssl) |s| cli.linkLibrary(s);
    }

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
    taptun_wrapper_module.addImport("taptun", taptun_module);

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

    // Add iOS SDK paths to the module itself (for @cImport in dependencies)
    if (is_ios) {
        if (ios_sdk_path) |sdk| {
            const ios_include = b.fmt("{s}/usr/include", .{sdk});
            packet_adapter_module.addSystemIncludePath(.{ .cwd_relative = ios_include });
        }
    }

    // Add taptun dependency for L2/L3 translation
    packet_adapter_module.addImport("taptun", taptun_module);

    const packet_adapter_obj = b.addObject(.{
        .name = "zig_packet_adapter",
        .root_module = packet_adapter_module,
    });
    packet_adapter_obj.addIncludePath(b.path("src/bridge"));

    // Add iOS SDK paths for C imports
    if (is_ios) {
        if (ios_sdk_path) |sdk| {
            const ios_include = b.fmt("{s}/usr/include", .{sdk});
            packet_adapter_obj.addSystemIncludePath(.{ .cwd_relative = ios_include });
        }
    }
    cli.addObject(packet_adapter_obj);

    // Link C library
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
    // 3. FFI LIBRARY (Cross-Platform)
    // ============================================
    const ffi_lib = b.addLibrary(.{
        .name = "softether_ffi",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ffi/ffi.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    ffi_lib.root_module.addImport("taptun", taptun_module);
    ffi_lib.linkLibC();
    ffi_lib.addIncludePath(b.path("include"));
    ffi_lib.addIncludePath(b.path("src"));

    // Add iOS SDK configuration for FFI
    if (is_ios) {
        ffi_lib.addIncludePath(b.path("src/bridge/ios_include"));
        if (ios_sdk_path) |sdk| {
            const ios_include = b.fmt("{s}/usr/include", .{sdk});
            const ios_frameworks = b.fmt("{s}/System/Library/Frameworks", .{sdk});
            ffi_lib.addSystemIncludePath(.{ .cwd_relative = ios_include });
            ffi_lib.addFrameworkPath(.{ .cwd_relative = ios_frameworks });
            ffi_lib.linkFramework("Foundation");
            ffi_lib.linkFramework("Security");
        }
    }

    // Link OpenSSL (system or bundled)
    if (use_system_ssl) {
        ffi_lib.linkSystemLibrary("ssl");
        ffi_lib.linkSystemLibrary("crypto");
    } else {
        if (crypto) |c| ffi_lib.linkLibrary(c);
        if (openssl) |s| ffi_lib.linkLibrary(s);
    }

    b.installArtifact(ffi_lib);

    // Also install the header
    b.installFile("include/ffi.h", "include/ffi.h");

    const ffi_step = b.step("ffi", "Build FFI library (cross-platform)");
    ffi_step.dependOn(&b.addInstallArtifact(ffi_lib, .{}).step);

    // ============================================
    // 4. TESTS
    // ============================================

    // Test for macOS platform adapter
    const macos_adapter_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/platform/test_macos_adapter.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    macos_adapter_tests.root_module.addImport("taptun", taptun_module);

    const run_macos_adapter_tests = b.addRunArtifact(macos_adapter_tests);

    // Main test step
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_macos_adapter_tests.step);

    // ============================================
    // 5. HELP AND INFORMATION
    // ============================================

    const help_step = b.step("help", "Show build system help");
    const help_run = b.addSystemCommand(&[_][]const u8{
        "echo",
        \\
        \\SoftEtherZig Build System
        \\========================
        \\
        \\Available Build Targets:
        \\  zig build                  - Build all targets (default)
        \\  zig build run              - Build and run VPN client CLI
        \\  zig build ffi              - Build FFI library only
        \\  zig build test             - Run unit tests
        \\  zig build clean            - Clean build artifacts
        \\
        \\Build Options:
        \\  -Doptimize=<mode>          - Build mode: Debug, ReleaseSafe, ReleaseFast, ReleaseSmall
        \\                               (default: ReleaseFast)
        \\  -Dtarget=<triple>          - Target platform (e.g., aarch64-macos, x86_64-linux)
        \\  -Dsystem-ssl=<bool>        - Use system OpenSSL (default: true for macOS/Linux)
        \\  -Duse-zig-adapter=<bool>   - Use Zig packet adapter (default: true)
        \\
        \\Examples:
        \\  # Build optimized CLI
        \\  zig build -Doptimize=ReleaseFast
        \\
        \\  # Build for iOS simulator
        \\  zig build -Dtarget=aarch64-ios-simulator -Dsystem-ssl=false
        \\
        \\  # Run tests
        \\  zig build test
        \\
        \\  # Run CLI with arguments
        \\  zig build run -- -h
        \\
        \\  # Cross-compile for Linux from macOS
        \\  zig build -Dtarget=x86_64-linux-gnu
        \\
        \\Documentation:
        \\  README.md                  - Quick start guide
        \\  docs/ZIG_PORTING_ROADMAP.md - Complete porting strategy
        \\  docs/ZIG_PORTING_PROGRESS.md - Task-by-task progress
        \\  docs/MACOS_ADAPTER_MILESTONE.md - Phase 1a completion report
        \\  SECURITY.md                - Security best practices
        \\
        \\Current Status:
        \\  Phase 1: Foundation Layer (20% complete)
        \\  Overall Migration: 3% (2,100/70,000 lines)
        \\  Latest: macOS adapter Phase 1a complete ✓
        \\
        \\Need Help?
        \\  zig build --help           - Standard Zig build help
        \\  zig build help             - This message
        \\
    });
    help_step.dependOn(&help_run.step);
}
