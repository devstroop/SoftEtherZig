const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });

    const target_os = target.result.os.tag;
    const target_abi = target.result.abi;
    const target_arch = target.result.cpu.arch;
    const is_android = target_os == .linux and (target_abi == .android or target_abi == .androideabi);

    // Detect Homebrew OpenSSL path (ARM vs Intel Mac)
    const openssl_lib: []const u8 = if (target_os == .macos) blk: {
        const candidates = [_][]const u8{
            "/opt/homebrew/opt/openssl@3/lib",
            "/usr/local/opt/openssl@3/lib",
        };
        for (candidates) |p| {
            std.fs.accessAbsolute(p, .{}) catch continue;
            break :blk p;
        }
        break :blk "/opt/homebrew/opt/openssl@3/lib"; // fallback
    } else "";
    const openssl_include: []const u8 = if (target_os == .macos) blk: {
        const candidates = [_][]const u8{
            "/opt/homebrew/opt/openssl@3/include",
            "/usr/local/opt/openssl@3/include",
        };
        for (candidates) |p| {
            std.fs.accessAbsolute(p, .{}) catch continue;
            break :blk p;
        }
        break :blk "/opt/homebrew/opt/openssl@3/include"; // fallback
    } else "";

    // Windows: detect OpenSSL installation path
    const win_openssl_lib: []const u8 = if (target_os == .windows) blk: {
        const candidates = [_][]const u8{
            "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD",
            "C:/Program Files/OpenSSL-Win64/lib",
        };
        for (candidates) |p| {
            std.fs.accessAbsolute(p, .{}) catch continue;
            break :blk p;
        }
        break :blk "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD";
    } else "";
    const win_openssl_include: []const u8 = if (target_os == .windows) blk: {
        std.fs.accessAbsolute("C:/Program Files/OpenSSL-Win64/include", .{}) catch {
            break :blk "";
        };
        break :blk "C:/Program Files/OpenSSL-Win64/include";
    } else "";

    // Android: per-arch OpenSSL deps
    const android_ssl_lib: []const u8 = if (is_android) switch (target_arch) {
        .aarch64 => "deps/openssl-android/arm64-v8a/lib",
        .arm => "deps/openssl-android/armeabi-v7a/lib",
        .x86_64 => "deps/openssl-android/x86_64/lib",
        else => "deps/openssl-android/arm64-v8a/lib",
    } else "";
    const android_ssl_include: []const u8 = if (is_android) switch (target_arch) {
        .aarch64 => "deps/openssl-android/arm64-v8a/include",
        .arm => "deps/openssl-android/armeabi-v7a/include",
        .x86_64 => "deps/openssl-android/x86_64/include",
        else => "deps/openssl-android/arm64-v8a/include",
    } else "";

    // Print build configuration
    std.debug.print("Build Configuration:\n", .{});
    std.debug.print("  Target: {s}{s}\n", .{ @tagName(target_os), if (is_android) " (android)" else "" });
    std.debug.print("  Optimize: {s}\n", .{@tagName(optimize)});
    std.debug.print("  SSL: {s}\n", .{if (is_android) "static (deps/openssl-android)" else "system OpenSSL"});
    std.debug.print("\n", .{});

    // Bundled zlib C source files (for block compression)
    const zlib_sources = [_][]const u8{
        "deps/zlib/adler32.c",
        "deps/zlib/compress.c",
        "deps/zlib/crc32.c",
        "deps/zlib/deflate.c",
        "deps/zlib/inffast.c",
        "deps/zlib/inflate.c",
        "deps/zlib/inftrees.c",
        "deps/zlib/trees.c",
        "deps/zlib/uncompr.c",
        "deps/zlib/zutil.c",
    };
    const zlib_c_flags = [_][]const u8{"-std=c99"};

    // Helper to add bundled zlib to a compile step
    const addZlib = struct {
        fn add(step: *std.Build.Step.Compile, builder: *std.Build) void {
            step.addIncludePath(builder.path("deps/zlib"));
            for (zlib_sources) |src| {
                step.addCSourceFile(.{ .file = builder.path(src), .flags = &zlib_c_flags });
            }
        }
    }.add;

    // Helper to link OpenSSL for a given compile step
    const linkOpenSsl = struct {
        fn link(step: *std.Build.Step.Compile, os: std.Target.Os.Tag, android: bool, mac_lib: []const u8, mac_inc: []const u8, win_lib: []const u8, win_inc: []const u8, and_lib: []const u8, and_inc: []const u8) void {
            if (android) {
                step.addLibraryPath(.{ .cwd_relative = and_lib });
                step.addIncludePath(.{ .cwd_relative = and_inc });
                step.linkSystemLibrary2("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
                step.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
                // NDK sysroot lib path for liblog, libdl, libm, libc...
                if (std.posix.getenv("ANDROID_NDK_LIB_DIR")) |ndk_lib| {
                    step.addLibraryPath(.{ .cwd_relative = ndk_lib });
                }
                step.linkSystemLibrary2("log", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
            } else if (os == .macos) {
                step.addLibraryPath(.{ .cwd_relative = mac_lib });
                step.addIncludePath(.{ .cwd_relative = mac_inc });
                step.linkSystemLibrary2("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
                step.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
            } else if (os == .windows) {
                step.addLibraryPath(.{ .cwd_relative = win_lib });
                step.addIncludePath(.{ .cwd_relative = win_inc });
                step.linkSystemLibrary2("libssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
                step.linkSystemLibrary2("libcrypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
                step.linkSystemLibrary("ws2_32");
                step.linkSystemLibrary("kernel32");
                step.linkSystemLibrary("advapi32");
                step.linkSystemLibrary("iphlpapi");
                step.linkSystemLibrary("winmm");
            } else {
                step.linkSystemLibrary("ssl");
                step.linkSystemLibrary("crypto");
            }
            step.linkLibC();
        }
    }.link;

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
        vpnclient.addLibraryPath(.{ .cwd_relative = openssl_lib });
        vpnclient.addIncludePath(.{ .cwd_relative = openssl_include });
        vpnclient.linkSystemLibrary2("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
        vpnclient.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
    } else if (target_os == .windows) {
        vpnclient.addLibraryPath(.{ .cwd_relative = win_openssl_lib });
        vpnclient.addIncludePath(.{ .cwd_relative = win_openssl_include });
        vpnclient.linkSystemLibrary2("libssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
        vpnclient.linkSystemLibrary2("libcrypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
        vpnclient.linkSystemLibrary("ws2_32");
        vpnclient.linkSystemLibrary("kernel32");
        vpnclient.linkSystemLibrary("advapi32");
        vpnclient.linkSystemLibrary("iphlpapi");
    } else {
        vpnclient.linkSystemLibrary("ssl");
        vpnclient.linkSystemLibrary("crypto");
    }
    vpnclient.linkLibC();
    addZlib(vpnclient, b);

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
    linkOpenSsl(shared_lib, target_os, is_android, openssl_lib, openssl_include, win_openssl_lib, win_openssl_include, android_ssl_lib, android_ssl_include);
    addZlib(shared_lib, b);

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
    } else if (is_android) {
        static_lib.addLibraryPath(.{ .cwd_relative = android_ssl_lib });
        static_lib.addIncludePath(.{ .cwd_relative = android_ssl_include });
        static_lib.linkSystemLibrary2("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
        static_lib.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
    } else if (target_os == .macos) {
        static_lib.addLibraryPath(.{ .cwd_relative = openssl_lib });
        static_lib.addIncludePath(.{ .cwd_relative = openssl_include });
        static_lib.linkSystemLibrary2("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
        static_lib.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
    } else {
        static_lib.linkSystemLibrary("ssl");
        static_lib.linkSystemLibrary("crypto");
    }
    static_lib.linkLibC();
    addZlib(static_lib, b);

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

    // Test modules — each source file with `test` blocks
    const test_sources = [_][]const u8{
        "src/crypto/sha0.zig",
        "src/crypto/cipher.zig",
        "src/crypto/hash.zig",
        "src/protocol/pack.zig",
        "src/protocol/auth.zig",
        "src/protocol/rpc.zig",
        "src/client/state.zig",
        "src/client/stats.zig",
        "src/client/events.zig",
        "src/core/ip.zig",
        "src/core/errors.zig",
        "src/core/types.zig",
        "src/config.zig",
        "src/types.zig",
        "src/app/config.zig",
        "src/app/events.zig",
        "src/app/password_hash.zig",
        "src/app/state.zig",
        "src/tunnel/arp.zig",
        "src/tunnel/dhcp.zig",
        "src/cli/args.zig",
        "src/cli/config_manager.zig",
        "src/net/dns_cache.zig",
        "src/net/udp_accel.zig",
    };

    for (test_sources) |test_src| {
        const t = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(test_src),
                .target = target,
                .optimize = optimize,
            }),
        });

        // Tests may need OpenSSL (cipher.zig uses it)
        if (target_os == .macos) {
            t.addLibraryPath(.{ .cwd_relative = openssl_lib });
            t.addIncludePath(.{ .cwd_relative = openssl_include });
            t.linkSystemLibrary2("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
            t.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
        } else if (target_os == .windows) {
            t.addLibraryPath(.{ .cwd_relative = win_openssl_lib });
            t.addIncludePath(.{ .cwd_relative = win_openssl_include });
            t.linkSystemLibrary2("libssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
            t.linkSystemLibrary2("libcrypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
        } else {
            t.linkSystemLibrary("ssl");
            t.linkSystemLibrary("crypto");
        }
        t.linkLibC();

        const run_t = b.addRunArtifact(t);
        test_step.dependOn(&run_t.step);
    }

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
