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
    // VPN CLIENT
    // ============================================
    const vpnclient = b.addExecutable(.{
        .name = "vpnclient",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // Link OpenSSL for TLS
    if (target_os == .macos) {
        vpnclient.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/lib" });
        vpnclient.addIncludePath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/include" });
        vpnclient.linkSystemLibrary2("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
        vpnclient.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
    } else if (target_os == .windows) {
        vpnclient.linkSystemLibrary("ssl");
        vpnclient.linkSystemLibrary("crypto");
        vpnclient.linkSystemLibrary("ws2_32");
        vpnclient.linkSystemLibrary("kernel32");
        vpnclient.linkSystemLibrary("advapi32");
        vpnclient.linkSystemLibrary("iphlpapi");
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
    // SHARED LIBRARY (for FFI: Flutter, Python, etc.)
    // ============================================
    const shared_lib = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "softether",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ffi.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // Link OpenSSL for shared library too
    if (target_os == .macos) {
        shared_lib.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/lib" });
        shared_lib.addIncludePath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/include" });
        shared_lib.linkSystemLibrary2("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
        shared_lib.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
    } else if (target_os == .windows) {
        shared_lib.linkSystemLibrary("ssl");
        shared_lib.linkSystemLibrary("crypto");
        shared_lib.linkSystemLibrary("ws2_32");
        shared_lib.linkSystemLibrary("kernel32");
        shared_lib.linkSystemLibrary("advapi32");
        shared_lib.linkSystemLibrary("iphlpapi");
    } else {
        shared_lib.linkSystemLibrary("ssl");
        shared_lib.linkSystemLibrary("crypto");
    }
    shared_lib.linkLibC();

    const install_shared_lib = b.addInstallArtifact(shared_lib, .{});

    const shared_lib_step = b.step("shared-lib", "Build shared library (libsoftether.dylib/.so/.dll)");
    shared_lib_step.dependOn(&install_shared_lib.step);

    // ============================================
    // STATIC LIBRARY (for mobile: iOS/Android embedding)
    // ============================================
    const static_lib = b.addLibrary(.{
        .linkage = .static,
        .name = "softether",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ffi.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // Static library links OpenSSL statically for mobile
    if (target_os == .ios) {
        static_lib.addLibraryPath(.{ .cwd_relative = "deps/openssl-ios/lib" });
        static_lib.addIncludePath(.{ .cwd_relative = "deps/openssl-ios/include" });
        // iOS SDK sysroot for system headers (sys/types.h etc.)
        static_lib.addSystemIncludePath(.{ .cwd_relative = "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/usr/include" });
        static_lib.linkSystemLibrary2("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
        static_lib.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
    } else if (target_os == .macos) {
        static_lib.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/lib" });
        static_lib.addIncludePath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/include" });
        static_lib.linkSystemLibrary2("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
        static_lib.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
    } else {
        static_lib.linkSystemLibrary("ssl");
        static_lib.linkSystemLibrary("crypto");
    }
    static_lib.linkLibC();

    const install_static_lib = b.addInstallArtifact(static_lib, .{});

    const static_lib_step = b.step("static-lib", "Build static library (for iOS/Android embedding)");
    static_lib_step.dependOn(&install_static_lib.step);

    // ============================================
    // UTUN HELPER (macOS privilege escalation)
    // ============================================
    if (target_os == .macos) {
        const utun_helper = b.addExecutable(.{
            .name = "softether-utun-helper",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/adapter/utun_helper_main.zig"),
                .target = target,
                .optimize = optimize,
            }),
        });
        utun_helper.linkLibC();

        b.installArtifact(utun_helper);

        // Make shared-lib step also build the helper
        shared_lib_step.dependOn(&b.addInstallArtifact(utun_helper, .{}).step);
    }

    // ============================================
    // TESTS
    // ============================================
    const test_step = b.step("test", "Run unit tests");
    _ = test_step;

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
        \\  zig build              - Build VPN client
        \\  zig build run          - Build and run VPN client
        \\  zig build shared-lib   - Build shared library for FFI
        \\  zig build static-lib   - Build static library (iOS/Android)
        \\  zig build test         - Run unit tests
        \\
        \\Build Options:
        \\  -Doptimize=<mode>  - Debug, ReleaseSafe, ReleaseFast (default), ReleaseSmall
        \\  -Dtarget=<triple>  - Target platform (e.g., aarch64-macos, x86_64-linux)
        \\
        \\Examples:
        \\  zig build -Doptimize=ReleaseFast
        \\  zig build shared-lib -Doptimize=ReleaseFast
        \\  zig build run -- --config config.json
        \\  zig build -Dtarget=x86_64-linux-gnu
        \\
        \\Documentation:
        \\  README.md          - Quick start guide
        \\  SECURITY.md        - Security best practices
        \\
    });
    help_step.dependOn(&help_run.step);
}
