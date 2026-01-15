const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });

    const target_os = target.result.os.tag;

    // Print build configuration
    std.debug.print("Build Configuration:\n", .{});
    std.debug.print("  Target: {s}\n", .{@tagName(target_os)});
    std.debug.print("  Optimize: {s}\n", .{@tagName(optimize)});
    std.debug.print("  SSL: system OpenSSL\n", .{});
    std.debug.print("\n", .{});

    // ============================================
    // STATIC LIBRARY (for iOS/Android FFI)
    // ============================================
    const ffi_module = b.createModule(.{
        .root_source_file = b.path("src/ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    const static_lib = b.addLibrary(.{
        .name = "softether_zig",
        .root_module = ffi_module,
        .linkage = .static,
    });

    // Link OpenSSL for TLS (iOS uses system Security.framework instead)
    if (target_os == .macos) {
        static_lib.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/lib" });
        static_lib.addIncludePath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/include" });
    } else if (target_os == .ios) {
        // iOS: Use Security.framework, no OpenSSL linking needed for static lib
        // The app will link Security.framework
    } else {
        static_lib.linkSystemLibrary("ssl");
        static_lib.linkSystemLibrary("crypto");
    }
    static_lib.linkLibC();

    // Install the static library and header
    b.installArtifact(static_lib);
    b.installFile("include/softether_zig.h", "include/softether_zig.h");

    // Static library build step
    const lib_step = b.step("lib", "Build static library for FFI");
    lib_step.dependOn(&static_lib.step);

    // ============================================
    // VPN CLIENT (executable)
    // ============================================
    const main_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const vpnclient = b.addExecutable(.{
        .name = "vpnclient",
        .root_module = main_module,
    });

    // Link OpenSSL for TLS
    if (target_os == .macos) {
        vpnclient.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/lib" });
        vpnclient.addIncludePath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/include" });
        vpnclient.linkSystemLibrary2("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
        vpnclient.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
    } else {
        vpnclient.linkSystemLibrary("ssl");
        vpnclient.linkSystemLibrary("crypto");
    }
    vpnclient.linkLibC();

    b.installArtifact(vpnclient);

    // Run step
    const run_cmd = b.addRunArtifact(vpnclient);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the VPN client");
    run_step.dependOn(&run_cmd.step);

    // ============================================
    // TESTS
    // ============================================
    const test_step = b.step("test", "Run unit tests");
    _ = test_step;

    // ============================================
    // iOS BUILD HELPER
    // ============================================
    const ios_step = b.step("ios", "Build static library for iOS (aarch64)");
    const ios_ffi_module = b.createModule(.{
        .root_source_file = b.path("src/ffi.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .aarch64,
            .os_tag = .ios,
        }),
        .optimize = .ReleaseFast,
    });
    const ios_lib = b.addLibrary(.{
        .name = "softether_zig",
        .root_module = ios_ffi_module,
        .linkage = .static,
    });
    ios_lib.linkLibC();

    // Install the iOS library to zig-out/lib
    const ios_install = b.addInstallArtifact(ios_lib, .{});
    ios_step.dependOn(&ios_install.step);

    // Also install header
    const ios_header_install = b.addInstallFile(b.path("include/softether_zig.h"), "include/softether_zig.h");
    ios_step.dependOn(&ios_header_install.step);

    // ============================================
    // HELP
    // ============================================
    const help_step = b.step("help", "Show build system help");
    const help_run = b.addSystemCommand(&[_][]const u8{
        "echo",
        \\
        \\SoftEtherZig Build System
        \\========================
        \\
        \\Build Targets:
        \\  zig build          - Build VPN client executable
        \\  zig build lib      - Build static library (libsoftether_zig.a)
        \\  zig build ios      - Build static library for iOS
        \\  zig build run      - Build and run VPN client
        \\  zig build test     - Run unit tests
        \\
        \\Build Options:
        \\  -Doptimize=<mode>  - Debug, ReleaseSafe, ReleaseFast (default), ReleaseSmall
        \\  -Dtarget=<triple>  - Target platform (e.g., aarch64-macos, aarch64-ios)
        \\
        \\Examples:
        \\  zig build lib -Doptimize=ReleaseFast
        \\  zig build ios
        \\  zig build -Dtarget=aarch64-ios -Doptimize=ReleaseFast lib
        \\
        \\iOS Integration:
        \\  1. Run: zig build ios
        \\  2. Copy zig-out/lib/libsoftether_zig.a to your Xcode project
        \\  3. Copy include/softether_zig.h to your project
        \\  4. Add to bridging header: #include "softether_zig.h"
        \\
    });
    help_step.dependOn(&help_run.step);
}
