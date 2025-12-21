const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });

    // Build option to select packet adapter (kept for future use, but currently only pure Zig client is built)
    const use_zig_adapter = b.option(bool, "use-zig-adapter", "Use Zig packet adapter instead of C (default: true)") orelse true;

    // Detect target OS
    const target_os = target.result.os.tag;
    // const is_ios = target_os == .ios; // Only needed for C-based client

    // C flags and sources are only needed for the C-based client (commented out below)
    // // Base C flags (common to all platforms)
    // const base_c_flags = &[_][]const u8{
    //     "-std=c99",
    //     "-D_REENTRANT",
    //     "-D_THREAD_SAFE",
    //     "-DCPU_64",
    //     "-D_FILE_OFFSET_BITS=64",
    //     "-DVPN_SPEED",
    //     "-D__bool_true_false_are_defined=1",
    //     "-Wno-deprecated-declarations",
    //     "-Wno-unused-parameter",
    //     "-Wno-unused-variable",
    //     "-Wno-sign-compare",
    //     "-Wno-incompatible-function-pointer-types",
    //     "-Wno-int-conversion",
    //     "-Wno-incompatible-pointer-types-discards-qualifiers",
    //     "-Wno-implicit-function-declaration",
    //     "-Wno-strict-prototypes",
    //     "-fno-strict-aliasing",
    //     "-fsigned-char",
    //     "-fno-sanitize=shift",
    //     "-fno-sanitize=null",
    //     "-fno-sanitize=undefined",
    // };

    // // Platform-specific defines
    // var c_flags_list = std.ArrayList([]const u8){};
    // c_flags_list = std.ArrayList([]const u8).initCapacity(b.allocator, 50) catch unreachable;
    // defer c_flags_list.deinit(b.allocator);

    // // Add base flags
    // c_flags_list.appendSlice(b.allocator, base_c_flags) catch unreachable;

    // // Add Zig adapter flag if enabled
    // if (use_zig_adapter) {
    //     c_flags_list.append(b.allocator, "-DUSE_ZIG_ADAPTER=1") catch unreachable;
    // }

    // if (is_ios) {
    //     c_flags_list.appendSlice(b.allocator, &[_][]const u8{ "-DUNIX", "-DUNIX_MACOS", "-DUNIX_IOS", "-DTARGET_OS_IPHONE=1" }) catch unreachable;
    // } else if (target_os == .macos) {
    //     c_flags_list.appendSlice(b.allocator, &[_][]const u8{ "-DUNIX", "-DUNIX_MACOS" }) catch unreachable;
    // } else if (target_os == .linux) {
    //     c_flags_list.appendSlice(b.allocator, &[_][]const u8{ "-DUNIX", "-DUNIX_LINUX" }) catch unreachable;
    // } else if (target_os == .windows) {
    //     c_flags_list.appendSlice(b.allocator, &[_][]const u8{ "-DWIN32", "-D_WIN32" }) catch unreachable;
    // } else {
    //     c_flags_list.append(b.allocator, "-DUNIX") catch unreachable;
    // }

    // const c_flags = c_flags_list.items;

    // Print build configuration
    std.debug.print("Build Configuration:\n", .{});
    std.debug.print("  Target: {s}\n", .{@tagName(target_os)});
    std.debug.print("  Optimize: {s}\n", .{@tagName(optimize)});
    std.debug.print("  SSL: system OpenSSL\n", .{});
    std.debug.print("  Packet Adapter: {s}\n", .{if (use_zig_adapter) "Zig (native)" else "C (legacy)"});
    std.debug.print("\n", .{});

    // C sources - only needed for C-based client (commented out below)
    // // Platform-specific packet adapter and timing files
    // const packet_adapter_file = switch (target_os) {
    //     .ios => "src/bridge/ios/packet_adapter_ios.c",
    //     .macos => "src/bridge/packet_adapter_macos.c",
    //     .linux => "src/bridge/packet_adapter_linux.c",
    //     .windows => "src/bridge/packet_adapter_windows.c",
    //     else => "src/bridge/packet_adapter_linux.c", // fallback
    // };

    // const tick64_file = switch (target_os) {
    //     .macos, .ios => "src/bridge/tick64_macos.c",
    //     .linux => "src/bridge/tick64_linux.c",
    //     .windows => "src/bridge/tick64_windows.c",
    //     else => "src/bridge/tick64_linux.c", // fallback
    // };

    // const c_sources = &[_][]const u8{
    //     "src/bridge/softether_bridge.c",
    //     "src/bridge/unix_bridge.c",
    //     tick64_file,
    //     packet_adapter_file,
    //     "src/bridge/zig_packet_adapter.c", // Zig adapter wrapper
    //     "src/bridge/logging.c", // Phase 2: Log level system
    //     "src/bridge/security_utils.c", // Phase 3: Secure password handling
    //     "src/bridge/client_bridge.c", // NEW: Zig adapter bridge (replaces VLanGetPacketAdapter)
    //     "src/bridge/zig_bridge.c", // NEW: C wrapper for Zig packet adapter
    //     "src/bridge/Mayaqua/Mayaqua.c",
    //     "src/bridge/Mayaqua/Memory.c",
    //     "SoftEtherVPN/src/Mayaqua/Str.c",
    //     "src/bridge/Mayaqua/Object.c",
    //     "SoftEtherVPN/src/Mayaqua/OS.c",
    //     "SoftEtherVPN/src/Mayaqua/FileIO.c",
    //     "src/bridge/Mayaqua/Kernel.c",
    //     "SoftEtherVPN/src/Mayaqua/Network.c",
    //     "SoftEtherVPN/src/Mayaqua/TcpIp.c",
    //     "SoftEtherVPN/src/Mayaqua/Encrypt.c",
    //     "SoftEtherVPN/src/Mayaqua/Secure.c",
    //     "SoftEtherVPN/src/Mayaqua/Pack.c",
    //     "SoftEtherVPN/src/Mayaqua/Cfg.c",
    //     "SoftEtherVPN/src/Mayaqua/Table.c",
    //     "SoftEtherVPN/src/Mayaqua/Tracking.c",
    //     "SoftEtherVPN/src/Mayaqua/Microsoft.c",
    //     "SoftEtherVPN/src/Mayaqua/Internat.c",
    //     "SoftEtherVPN/src/Cedar/Cedar.c",
    //     "src/bridge/Cedar/Client.c",
    //     "src/bridge/Cedar/Protocol.c",
    //     "SoftEtherVPN/src/Cedar/Connection.c",
    //     "src/bridge/Cedar/Session.c",
    //     "SoftEtherVPN/src/Cedar/Account.c",
    //     "SoftEtherVPN/src/Cedar/Admin.c",
    //     "SoftEtherVPN/src/Cedar/Command.c",
    //     "SoftEtherVPN/src/Cedar/Hub.c",
    //     "SoftEtherVPN/src/Cedar/Listener.c",
    //     "SoftEtherVPN/src/Cedar/Logging.c",
    //     "SoftEtherVPN/src/Cedar/Sam.c",
    //     "SoftEtherVPN/src/Cedar/Server.c",
    //     "SoftEtherVPN/src/Cedar/Virtual.c",
    //     "SoftEtherVPN/src/Cedar/Link.c",
    //     "SoftEtherVPN/src/Cedar/SecureNAT.c",
    //     "SoftEtherVPN/src/Cedar/NullLan.c",
    //     "SoftEtherVPN/src/Cedar/Bridge.c",
    //     "SoftEtherVPN/src/Cedar/BridgeUnix.c",
    //     "SoftEtherVPN/src/Cedar/Nat.c",
    //     "SoftEtherVPN/src/Cedar/UdpAccel.c",
    //     "SoftEtherVPN/src/Cedar/Database.c",
    //     "SoftEtherVPN/src/Cedar/Remote.c",
    //     "SoftEtherVPN/src/Cedar/DDNS.c",
    //     "SoftEtherVPN/src/Cedar/AzureClient.c",
    //     "SoftEtherVPN/src/Cedar/AzureServer.c",
    //     "SoftEtherVPN/src/Cedar/Radius.c",
    //     "SoftEtherVPN/src/Cedar/Console.c",
    //     "SoftEtherVPN/src/Cedar/Layer3.c",
    //     "SoftEtherVPN/src/Cedar/Interop_OpenVPN.c",
    //     "SoftEtherVPN/src/Cedar/Interop_SSTP.c",
    //     "SoftEtherVPN/src/Cedar/IPsec.c",
    //     "SoftEtherVPN/src/Cedar/IPsec_IKE.c",
    //     "SoftEtherVPN/src/Cedar/IPsec_IkePacket.c",
    //     "SoftEtherVPN/src/Cedar/IPsec_L2TP.c",
    //     "SoftEtherVPN/src/Cedar/IPsec_PPP.c",
    //     "SoftEtherVPN/src/Cedar/IPsec_EtherIP.c",
    //     "SoftEtherVPN/src/Cedar/IPsec_IPC.c",
    //     "SoftEtherVPN/src/Cedar/EtherLog.c",
    //     "SoftEtherVPN/src/Cedar/WebUI.c",
    //     "SoftEtherVPN/src/Cedar/WaterMark.c",
    // };

    // // NativeStack.c uses system() which is unavailable on iOS
    // // It's only needed for server-side routing, not client VPN
    // const native_stack_sources = &[_][]const u8{
    //     "SoftEtherVPN/src/Cedar/NativeStack.c",
    // };

    // ============================================
    // 1. LIBRARY MODULE (for Zig programs)
    // ============================================

    // Add ZigTapTun dependency
    const taptun = b.dependency("taptun", .{
        .target = target,
        .optimize = optimize,
    });

    // Get the taptun module
    const taptun_module = taptun.module("taptun");

    const lib_module = b.addModule("softether", .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
    });
    lib_module.addIncludePath(b.path("src"));
    lib_module.addImport("taptun", taptun_module);
    lib_module.link_libc = true;

    // ============================================
    // 2. CLI CLIENT (C-based - DISABLED)
    // Requires SoftEtherVPN submodule. Use vpnclient-pure instead.
    // ============================================
    // const cli = b.addExecutable(.{
    //     .name = "vpnclient",
    //     .root_module = b.createModule(.{
    //         .root_source_file = b.path("src/cli.zig"),
    //         .target = target,
    //         .optimize = optimize,
    //         .imports = &.{
    //             .{ .name = "softether", .module = lib_module },
    //         },
    //     }),
    // });
    //
    // cli.addIncludePath(b.path("src"));
    // cli.addIncludePath(b.path("src/bridge"));
    // cli.addIncludePath(b.path("SoftEtherVPN/src"));
    // cli.addIncludePath(b.path("SoftEtherVPN/src/Mayaqua"));
    // cli.addIncludePath(b.path("SoftEtherVPN/src/Cedar"));
    //
    // // Link system OpenSSL
    // cli.linkSystemLibrary("ssl");
    // cli.linkSystemLibrary("crypto");
    //
    // cli.addCSourceFiles(.{
    //     .files = c_sources,
    //     .flags = c_flags,
    // });
    //
    // // Aggressive optimizations for release builds
    // if (optimize != .Debug) {
    //     cli.want_lto = true; // Link-time optimization for better performance
    // }
    //
    // // Add NativeStack for non-iOS builds
    // if (!is_ios) {
    //     cli.addCSourceFiles(.{
    //         .files = native_stack_sources,
    //         .flags = c_flags,
    //     });
    // }
    //
    // // Add ZigTapTun wrapper module
    // const taptun_wrapper_module = b.createModule(.{
    //     .root_source_file = b.path("src/bridge/taptun_wrapper.zig"),
    //     .target = target,
    //     .optimize = optimize,
    // });
    // taptun_wrapper_module.addImport("taptun", taptun_module);
    //
    // const taptun_wrapper = b.addObject(.{
    //     .name = "taptun_wrapper",
    //     .root_module = taptun_wrapper_module,
    // });
    // cli.addObject(taptun_wrapper);
    //
    // // Add Zig packet adapter (Phase 1) - compiled as static object
    // const packet_adapter_module = b.createModule(.{
    //     .root_source_file = b.path("src/packet/adapter.zig"),
    //     .target = target,
    //     .optimize = optimize,
    // });
    //
    // // Add taptun dependency for L2/L3 translation
    // packet_adapter_module.addImport("taptun", taptun_module);
    //
    // const packet_adapter_obj = b.addObject(.{
    //     .name = "zig_packet_adapter",
    //     .root_module = packet_adapter_module,
    // });
    // packet_adapter_obj.addIncludePath(b.path("src/bridge"));
    // cli.addObject(packet_adapter_obj);
    //
    // // Phase 2.1: Add DHCP parser module (30-40% faster parsing)
    // const dhcp_module = b.createModule(.{
    //     .root_source_file = b.path("src/packet/dhcp.zig"),
    //     .target = target,
    //     .optimize = optimize,
    // });
    //
    // const dhcp_obj = b.addObject(.{
    //     .name = "zig_dhcp",
    //     .root_module = dhcp_module,
    // });
    // cli.addObject(dhcp_obj);
    //
    // // Phase 2.2: Add protocol builders (DHCP/ARP packet generation, 10-15% gain)
    // const protocol_module = b.createModule(.{
    //     .root_source_file = b.path("src/packet/protocol.zig"),
    //     .target = target,
    //     .optimize = optimize,
    // });
    //
    // const protocol_obj = b.addObject(.{
    //     .name = "zig_protocol",
    //     .root_module = protocol_module,
    // });
    // cli.addObject(protocol_obj);
    //
    // // Link C library
    // cli.linkLibC();
    //
    // // Platform-specific system libraries
    // if (target_os != .windows) {
    //     // Unix-like systems
    //     cli.linkSystemLibrary("pthread");
    //     cli.linkSystemLibrary("z");
    //
    //     if (target_os == .macos) {
    //         cli.linkSystemLibrary("iconv");
    //         cli.linkSystemLibrary("readline");
    //         cli.linkSystemLibrary("ncurses");
    //     } else if (target_os == .linux) {
    //         cli.linkSystemLibrary("rt");
    //         cli.linkSystemLibrary("dl");
    //     }
    // } else {
    //     // Windows
    //     cli.linkSystemLibrary("ws2_32");
    //     cli.linkSystemLibrary("iphlpapi");
    //     cli.linkSystemLibrary("advapi32");
    // }
    //
    // b.installArtifact(cli);
    //
    // // Run step for CLI
    // const run_cli = b.addRunArtifact(cli);
    // run_cli.step.dependOn(b.getInstallStep());
    // if (b.args) |args| {
    //     run_cli.addArgs(args);
    // }
    //
    // const run_step = b.step("run", "Run the VPN client CLI");
    // run_step.dependOn(&run_cli.step);

    // ============================================
    // 2.5. PURE ZIG CLIENT (no C dependencies)
    // ============================================
    const pure_client = b.addExecutable(.{
        .name = "vpnclient-pure",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main_pure.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // Link OpenSSL for TLS
    // Note: On macOS with Homebrew, we need to specify the library path.
    // We avoid addRPath because linkSystemLibrary2 with .use_pkg_config = .no
    // already handles the linking, and adding rpath manually causes duplicates.
    if (target_os == .macos) {
        // On macOS with Homebrew, specify the paths for include and library
        pure_client.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/lib" });
        pure_client.addIncludePath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/include" });
        // Link both ssl and crypto - they share the same library path
        pure_client.linkSystemLibrary2("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
        pure_client.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
    } else {
        pure_client.linkSystemLibrary("ssl");
        pure_client.linkSystemLibrary("crypto");
    }
    pure_client.linkLibC();

    // Add TapTun module for network interface
    pure_client.root_module.addImport("taptun", taptun_module);

    b.installArtifact(pure_client);

    // Run step for pure client - depends only on pure_client install, not all installs
    const run_pure = b.addRunArtifact(pure_client);
    run_pure.step.dependOn(&b.addInstallArtifact(pure_client, .{}).step);
    if (b.args) |args| {
        run_pure.addArgs(args);
    }

    const run_pure_step = b.step("run-pure", "Run the pure Zig VPN client");
    run_pure_step.dependOn(&run_pure.step);

    // Add a dedicated build step for pure client only
    const build_pure_step = b.step("pure", "Build only the pure Zig VPN client");
    build_pure_step.dependOn(&b.addInstallArtifact(pure_client, .{}).step);

    // // ============================================
    // // 3. FFI LIBRARY (Cross-Platform)
    // // ============================================
    // const ffi_lib = b.addLibrary(.{
    //     .name = "softether_ffi",
    //     .root_module = b.createModule(.{
    //         .root_source_file = b.path("src/ffi/ffi.zig"),
    //         .target = target,
    //         .optimize = optimize,
    //     }),
    // });
    // ffi_lib.root_module.addImport("taptun", taptun_module);
    // ffi_lib.linkLibC();
    // ffi_lib.addIncludePath(b.path("include"));
    // ffi_lib.addIncludePath(b.path("src"));

    // // Add iOS SDK configuration for FFI
    // if (is_ios) {
    //     ffi_lib.addIncludePath(b.path("src/bridge/ios_include"));
    //     ffi_lib.linkFramework("Foundation");
    //     ffi_lib.linkFramework("Security");
    // }

    // // Link system OpenSSL
    // ffi_lib.linkSystemLibrary("ssl");
    // ffi_lib.linkSystemLibrary("crypto");

    // b.installArtifact(ffi_lib);

    // // Also install the header
    // b.installFile("include/ffi.h", "include/ffi.h");

    // const ffi_step = b.step("ffi", "Build FFI library (cross-platform)");
    // ffi_step.dependOn(&b.addInstallArtifact(ffi_lib, .{}).step);

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
