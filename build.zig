const std = @import("std");

/// Embed build.zig.zon at comptime so we can extract the version
/// without duplicating it across files.
const build_zon = @embedFile("build.zig.zon");

/// Extract the version string from build.zig.zon at comptime.
/// Parses the `.version = "X.Y.Z"` field using simple string search.
fn parseVersion(comptime zon: []const u8) []const u8 {
    const marker = ".version = \"";
    const start = std.mem.indexOf(u8, zon, marker).? + marker.len;
    const end = std.mem.indexOfScalarPos(u8, zon, start, '"').?;
    return zon[start..end];
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });

    const target_os = target.result.os.tag;
    const target_abi = target.result.abi;
    const target_arch = target.result.cpu.arch;
    const is_android = target_os == .linux and (target_abi == .android or target_abi == .androideabi);

    // Parse version from build.zig.zon (single source of truth)
    const version = comptime parseVersion(build_zon);
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);
    const build_options_mod = build_options.createModule();

    // Detect Homebrew OpenSSL path (ARM vs Intel Mac)
    const openssl_lib: []const u8 = if (target_os == .macos) "/opt/homebrew/opt/openssl@3/lib" else "";
    const openssl_include: []const u8 = if (target_os == .macos) "/opt/homebrew/opt/openssl@3/include" else "";

    // Windows: detect OpenSSL installation path.
    // Zig 0.16 note: std.fs.cwd().access() is removed. Use hardcoded
    // paths; CI scripts should copy/symlink OpenSSL to these standard locations.
    const win_openssl_lib: []const u8 = if (target_os == .windows)
        "C:/OpenSSL-Win64/lib/VC/x64/MD"
    else
        "";
    const win_openssl_include: []const u8 = if (target_os == .windows)
        "C:/OpenSSL-Win64/include"
    else
        "";

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
    // Disable ubsan (Undefined Behavior Sanitizer) for zlib C sources.
    // Zig 0.15.2's bundled Clang implicitly enables ubsan for C compilation,
    // which inserts references to ___ubsan_handle_* symbols. The Xcode 26.5
    // arm64 linker rejects unresolved ubsan handlers at archive link time.
    const zlib_c_flags = [_][]const u8{ "-std=c99", "-fno-sanitize=undefined" };

    // Helper to add bundled zlib to a compile step
    const addZlib = struct {
        fn add(step: *std.Build.Step.Compile, builder: *std.Build) void {
            step.root_module.addIncludePath(builder.path("deps/zlib"));
            for (zlib_sources) |src| {
                step.root_module.addCSourceFile(.{ .file = builder.path(src), .flags = &zlib_c_flags });
            }
        }
    }.add;

    // Helper to set up Android NDK sysroot include paths, library paths,
    // and generate a libc configuration file at build time.
    // NOTE: Full NDK setup not yet ported to Zig 0.16; stub for now.
    const setupAndroidNdk = struct {
        fn setup(builder: *std.Build, step: *std.Build.Step.Compile, arch: std.Target.Cpu.Arch) void {
            _ = arch;
            _ = step;
            if (builder.graph.environ_map.get("ANDROID_NDK_HOME") == null) {
                std.log.err("ANDROID_NDK_HOME must be set for Android builds", .{});
                std.process.exit(1);
            }
            @panic("Android NDK setup not yet ported to Zig 0.16; use an older Zig for Android builds");
        }
    }.setup;

    // Helper to link OpenSSL for a given compile step
    const linkOpenSsl = struct {
        fn link(builder: *std.Build, step: *std.Build.Step.Compile, os: std.Target.Os.Tag, android: bool, arch: std.Target.Cpu.Arch, mac_lib: []const u8, mac_inc: []const u8, win_lib: []const u8, win_inc: []const u8, and_lib: []const u8, and_inc: []const u8) void {
            if (android) {
                setupAndroidNdk(builder, step, arch);
                step.root_module.addLibraryPath(.{ .cwd_relative = and_lib });
                step.root_module.addIncludePath(.{ .cwd_relative = and_inc });
                step.root_module.linkSystemLibrary("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
                step.root_module.linkSystemLibrary("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
                step.root_module.linkSystemLibrary("log", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
            } else if (os == .macos) {
                step.root_module.addLibraryPath(.{ .cwd_relative = mac_lib });
                step.root_module.addIncludePath(.{ .cwd_relative = mac_inc });
                step.root_module.linkSystemLibrary("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
                step.root_module.linkSystemLibrary("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
            } else if (os == .windows) {
                step.root_module.addLibraryPath(.{ .cwd_relative = win_lib });
                step.root_module.addIncludePath(.{ .cwd_relative = win_inc });
                step.root_module.linkSystemLibrary("libssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
                step.root_module.linkSystemLibrary("libcrypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
                step.root_module.linkSystemLibrary("ws2_32", .{});
                step.root_module.linkSystemLibrary("kernel32", .{});
                step.root_module.linkSystemLibrary("advapi32", .{});
                step.root_module.linkSystemLibrary("iphlpapi", .{});
                step.root_module.linkSystemLibrary("winmm", .{});
            } else {
                step.root_module.linkSystemLibrary("ssl", .{});
                step.root_module.linkSystemLibrary("crypto", .{});
            }
            step.root_module.link_libc = true;
        }
    }.link;

    // ============================================
    // VPN CLIENT (CLI — disabled on Zig 0.16 due to Io.File.writeAll removal)
    // ============================================
    // TODO(zig-0.16): port display.zig to use Zig 0.16 writer API
    const cli_disabled = true;
    if (!cli_disabled) {
        const vpnclient = b.addExecutable(.{
            .name = "vpnclient",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "build_options", .module = build_options_mod },
                },
            }),
        });

        // Link OpenSSL for TLS
        if (target_os == .macos) {
            vpnclient.root_module.addLibraryPath(.{ .cwd_relative = openssl_lib });
            vpnclient.root_module.addIncludePath(.{ .cwd_relative = openssl_include });
            vpnclient.root_module.linkSystemLibrary("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
            vpnclient.root_module.linkSystemLibrary("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
        } else if (target_os == .windows) {
            vpnclient.root_module.addLibraryPath(.{ .cwd_relative = win_openssl_lib });
            vpnclient.root_module.addIncludePath(.{ .cwd_relative = win_openssl_include });
            vpnclient.root_module.linkSystemLibrary("libssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
            vpnclient.root_module.linkSystemLibrary("libcrypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
            vpnclient.root_module.linkSystemLibrary("ws2_32", .{});
            vpnclient.root_module.linkSystemLibrary("kernel32", .{});
            vpnclient.root_module.linkSystemLibrary("advapi32", .{});
            vpnclient.root_module.linkSystemLibrary("iphlpapi", .{});
        } else {
            vpnclient.root_module.linkSystemLibrary("ssl", .{});
            vpnclient.root_module.linkSystemLibrary("crypto", .{});
        }
        if (is_android) setupAndroidNdk(b, vpnclient, target_arch);
        vpnclient.root_module.link_libc = true;
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
    } // !cli_disabled

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
            .strip = optimize != .Debug and target_os != .macos,
            .imports = &.{
                .{ .name = "build_options", .module = build_options_mod },
            },
        }),
    });

    // Leave room for install_name_tool to rewrite dylib install name at bundle time
    if (target_os == .macos) {
        shared_lib.headerpad_max_install_names = true;
    }

    // Link OpenSSL for shared library too
    linkOpenSsl(b, shared_lib, target_os, is_android, target_arch, openssl_lib, openssl_include, win_openssl_lib, win_openssl_include, android_ssl_lib, android_ssl_include);
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
            .strip = optimize != .Debug,
            .imports = &.{
                .{ .name = "build_options", .module = build_options_mod },
            },
        }),
    });

    // Static library links OpenSSL statically for mobile
    if (target_os == .ios) {
        static_lib.root_module.addLibraryPath(.{ .cwd_relative = "deps/openssl-ios/lib" });
        static_lib.root_module.addIncludePath(.{ .cwd_relative = "deps/openssl-ios/include" });
        // iOS SDK sysroot for system headers (sys/types.h etc.)
        static_lib.root_module.addSystemIncludePath(.{ .cwd_relative = "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/usr/include" });
        static_lib.root_module.linkSystemLibrary("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
        static_lib.root_module.linkSystemLibrary("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
    } else if (is_android) {
        setupAndroidNdk(b, static_lib, target_arch);
        static_lib.root_module.addLibraryPath(.{ .cwd_relative = android_ssl_lib });
        static_lib.root_module.addIncludePath(.{ .cwd_relative = android_ssl_include });
        static_lib.root_module.linkSystemLibrary("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
        static_lib.root_module.linkSystemLibrary("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
    } else if (target_os == .macos) {
        static_lib.root_module.addLibraryPath(.{ .cwd_relative = openssl_lib });
        static_lib.root_module.addIncludePath(.{ .cwd_relative = openssl_include });
        static_lib.root_module.linkSystemLibrary("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
        static_lib.root_module.linkSystemLibrary("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
    } else {
        static_lib.root_module.linkSystemLibrary("ssl", .{});
        static_lib.root_module.linkSystemLibrary("crypto", .{});
    }
    static_lib.root_module.link_libc = true;
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
        utun_helper.root_module.link_libc = true;

        b.installArtifact(utun_helper);

        // Make shared-lib step also build the helper
        shared_lib_step.dependOn(&b.addInstallArtifact(utun_helper, .{}).step);
    }

    // ============================================
    // TESTS
    // ============================================
    const test_step = b.step("test", "Run unit tests");

    // Test modules — each source file with `test` blocks
    // NOTE: Files under src/app/ and src/net/ import sibling modules and
    // must be tested as part of the full package, not as standalone modules.
    // On Zig 0.16, some standalone tests are disabled due to API removals
    // (std.io.fixedBufferStream, ArrayList.writer, etc.)
    const test_sources = if (!cli_disabled)
        [_][]const u8{
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
            "src/tunnel/arp.zig",
            "src/tunnel/dhcp.zig",
            "src/cli/args.zig",
            "src/cli/config_manager.zig",
            "src/net/dns_cache.zig",
            "src/net/socks.zig",
        }
    else
        [_][]const u8{
            "src/crypto/sha0.zig",
            "src/crypto/hash.zig",
            "src/protocol/pack.zig",
            "src/client/state.zig",
            "src/client/stats.zig",
            "src/client/events.zig",
            "src/core/ip.zig",
            "src/core/errors.zig",
            "src/types.zig",
            "src/tunnel/arp.zig",
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
            t.root_module.addLibraryPath(.{ .cwd_relative = openssl_lib });
            t.root_module.addIncludePath(.{ .cwd_relative = openssl_include });
            t.root_module.linkSystemLibrary("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
            t.root_module.linkSystemLibrary("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
        } else if (target_os == .windows) {
            t.root_module.addLibraryPath(.{ .cwd_relative = win_openssl_lib });
            t.root_module.addIncludePath(.{ .cwd_relative = win_openssl_include });
            t.root_module.linkSystemLibrary("libssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
            t.root_module.linkSystemLibrary("libcrypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
        } else {
            t.root_module.linkSystemLibrary("ssl", .{});
            t.root_module.linkSystemLibrary("crypto", .{});
        }
        if (is_android) setupAndroidNdk(b, t, target_arch);
        t.root_module.link_libc = true;

        const run_t = b.addRunArtifact(t);
        test_step.dependOn(&run_t.step);
    }

    // FFI tests — ffi.zig imports the full client module tree, so it builds
    // as a whole-package test with the same OpenSSL/zlib linkage as the
    // shared library. The filter restricts execution to tests defined in
    // ffi.zig itself; transitive test blocks in other files have their own
    // entries above (or are intentionally excluded as stale).
    {
        const ffi_test = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/ffi.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "build_options", .module = build_options_mod },
                },
            }),
            .filters = &.{"ffi"},
        });
        linkOpenSsl(b, ffi_test, target_os, is_android, target_arch, openssl_lib, openssl_include, win_openssl_lib, win_openssl_include, android_ssl_lib, android_ssl_include);
        addZlib(ffi_test, b);
        if (is_android) setupAndroidNdk(b, ffi_test, target_arch);
        ffi_test.root_module.link_libc = true;

        const run_ffi_test = b.addRunArtifact(ffi_test);
        test_step.dependOn(&run_ffi_test.step);
    }

    // Protocol integration tests — drive the full handshake (signature →
    // hello → auth) against a scripted in-memory transport. Lives under
    // test/integration so it is clearly separate from in-source unit tests.
    // Imports the protocol module by name since Zig 0.15 disallows relative
    // imports that escape the module's source root.
    // Disabled on Zig 0.16: proto_mod imports softether_protocol.zig which
    // uses ../compat/ imports not reachable from standalone module scope.
    if (!cli_disabled) {
        const proto_mod = b.createModule(.{
            .root_source_file = b.path("src/protocol/softether_protocol.zig"),
            .target = target,
            .optimize = optimize,
        });
        // proto_mod compiles auth.zig which uses @cImport(openssl/pem.h)
        // and needs the include path to find the header.
        if (target_os == .macos) {
            proto_mod.addIncludePath(.{ .cwd_relative = openssl_include });
        } else if (target_os == .windows) {
            proto_mod.addIncludePath(.{ .cwd_relative = win_openssl_include });
        }
        const test_mod = b.createModule(.{
            .root_source_file = b.path("test/integration/handshake_fixture_test.zig"),
            .target = target,
            .optimize = optimize,
        });
        test_mod.addImport("proto", proto_mod);

        const integration_test = b.addTest(.{ .root_module = test_mod });
        linkOpenSsl(b, integration_test, target_os, is_android, target_arch, openssl_lib, openssl_include, win_openssl_lib, win_openssl_include, android_ssl_lib, android_ssl_include);
        addZlib(integration_test, b);
        if (is_android) setupAndroidNdk(b, integration_test, target_arch);
        integration_test.root_module.link_libc = true;

        const run_integration_test = b.addRunArtifact(integration_test);
        test_step.dependOn(&run_integration_test.step);
    } // protocol integration test

    // DHCPv6 wire-format tests — validates byte layout of Solicit/Request/Reply
    // messages against RFC 8415. No sockets, no live server, CI-friendly.
    // Disabled on Zig 0.16: dhcpv6_mod imports ../compat/random.zig.
    if (!cli_disabled) {
        const dhcpv6_mod = b.createModule(.{
            .root_source_file = b.path("src/tunnel/dhcpv6.zig"),
            .target = target,
            .optimize = optimize,
        });
        const test_mod = b.createModule(.{
            .root_source_file = b.path("test/integration/dhcpv6_wire_test.zig"),
            .target = target,
            .optimize = optimize,
        });
        test_mod.addImport("dhcpv6", dhcpv6_mod);

        const dhcpv6_test = b.addTest(.{ .root_module = test_mod });
        if (target_os == .macos) {
            dhcpv6_test.root_module.link_libc = true;
        }
        const run_dhcpv6_test = b.addRunArtifact(dhcpv6_test);
        test_step.dependOn(&run_dhcpv6_test.step);
    } // dhcpv6 test

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
