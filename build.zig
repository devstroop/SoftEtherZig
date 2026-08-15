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

    // Pure-Zig MD4 module (NTLM / NT password hash). auth.zig imports it by
    // name because a relative import from cedar/protocol/ escapes the
    // package source root (Zig 0.15 rule).
    const md4_mod = b.createModule(.{
        .root_source_file = b.path("src/mayaqua/encrypt/md4.zig"),
        .target = target,
        .optimize = optimize,
    });

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
    } else if (target_os == .ios) blk: {
        const ios_root = b.build_root.path orelse ".";
        const ios_lib = std.fs.path.join(b.allocator, &.{ ios_root, "deps", "openssl-ios", "lib" }) catch break :blk "";
        break :blk ios_lib;
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
    } else if (target_os == .ios) blk: {
        // iOS cross-compilation: use bundled static OpenSSL libs from deps/
        const ios_root = b.build_root.path orelse ".";
        const ios_inc = std.fs.path.join(b.allocator, &.{ ios_root, "deps", "openssl-ios", "include" }) catch break :blk "";
        break :blk ios_inc;
    } else "";

    // Windows: detect OpenSSL installation path
    const win_openssl_lib: []const u8 = if (target_os == .windows) blk: {
        // Check OPENSSL_DIR env var (set by CI via vcpkg)
        check_env: {
            const env_dir = std.process.getEnvVarOwned(b.allocator, "OPENSSL_DIR") catch break :check_env;
            defer b.allocator.free(env_dir);
            const joined = std.fs.path.join(b.allocator, &[_][]const u8{ env_dir, "lib" }) catch break :check_env;
            if (std.fs.cwd().access(joined, .{})) |_| {
                break :blk joined;
            } else |_| {
                b.allocator.free(joined);
            }
        }

        // Check vcpkg default path
        if (std.fs.cwd().access("C:/vcpkg/installed/x64-windows/lib", .{})) |_| {
            break :blk "C:/vcpkg/installed/x64-windows/lib";
        } else |_| {}

        // Check standard installation paths (choco installs to C:/OpenSSL-Win64 or C:/Program Files/OpenSSL)
        for ([_][]const u8{
            "C:/OpenSSL-Win64/lib/VC/x64/MD",
            "C:/OpenSSL-Win64/lib/VC/arm64/MD",
            "C:/OpenSSL-Win64/lib",
            "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD",
            "C:/Program Files/OpenSSL-Win64/lib/VC/arm64/MD",
            "C:/Program Files/OpenSSL-Win64/lib",
            "C:/Program Files/OpenSSL/lib/VC/x64/MD",
            "C:/Program Files/OpenSSL/lib/VC/arm64/MD",
            "C:/Program Files/OpenSSL/lib/VC/arm64",
            "C:/Program Files/OpenSSL/lib",
        }) |p| {
            if (std.fs.cwd().access(p, .{})) |_| {
                break :blk p;
            } else |_| {}
        }

        break :blk "C:/OpenSSL-Win64/lib";
    } else "";
    const win_openssl_include: []const u8 = if (target_os == .windows) blk: {
        // Check OPENSSL_DIR env var
        check_env_inc: {
            const env_dir = std.process.getEnvVarOwned(b.allocator, "OPENSSL_DIR") catch break :check_env_inc;
            defer b.allocator.free(env_dir);
            const joined = std.fs.path.join(b.allocator, &[_][]const u8{ env_dir, "include" }) catch break :check_env_inc;
            if (std.fs.cwd().access(joined, .{})) |_| {
                break :blk joined;
            } else |_| {
                b.allocator.free(joined);
            }
        }

        // Check vcpkg default include path
        if (std.fs.cwd().access("C:/vcpkg/installed/x64-windows/include", .{})) |_| {
            break :blk "C:/vcpkg/installed/x64-windows/include";
        } else |_| {}

        // Check standard include paths
        for ([_][]const u8{
            "C:/OpenSSL-Win64/include",
            "C:/Program Files/OpenSSL-Win64/include",
            "C:/Program Files/OpenSSL/include",
        }) |p| {
            if (std.fs.cwd().access(p, .{})) |_| {
                break :blk p;
            } else |_| {}
        }
        break :blk "C:/OpenSSL-Win64/include";
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

    // Linux multiarch triplet (e.g. x86_64-linux-gnu).
    // Used for the fallback library path (NOT include path — that would pull
    // in system glibc headers and cause symbol version conflicts). Instead
    // the CI workflow symlinks the multiarch OpenSSL config header into the
    // standard include tree so /usr/include alone suffices.
    const linux_multiarch: ?[]const u8 = if (target_os == .linux) switch (target_arch) {
        .x86_64 => "x86_64-linux-gnu",
        .aarch64 => "aarch64-linux-gnu",
        .arm => "arm-linux-gnueabihf",
        .riscv64 => "riscv64-linux-gnu",
        else => null,
    } else null;
    const linux_lib_dir = if (linux_multiarch) |t| b.fmt("/usr/lib/{s}", .{t}) else null;

    // Print build configuration
    std.debug.print("Build Configuration:\n", .{});
    std.debug.print("  Target: {s}{s}\n", .{ @tagName(target_os), if (is_android) " (android)" else "" });
    std.debug.print("  Optimize: {s}\n", .{@tagName(optimize)});
    std.debug.print("  SSL: {s}\n", .{if (is_android) "static (deps/openssl-android)" else "system OpenSSL"});
    if (linux_lib_dir) |d| std.debug.print("  Linux lib dir: {s}\n", .{d});
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
            step.addIncludePath(builder.path("deps/zlib"));
            for (zlib_sources) |src| {
                step.addCSourceFile(.{ .file = builder.path(src), .flags = &zlib_c_flags });
            }
        }
    }.add;

    // Helper to set up Android NDK sysroot include paths, library paths,
    // and generate a libc configuration file at build time.
    // Requires ANDROID_NDK_HOME env var. Optional ANDROID_API_LEVEL (default 21).
    const setupAndroidNdk = struct {
        fn setup(builder: *std.Build, step: *std.Build.Step.Compile, arch: std.Target.Cpu.Arch) void {
            const ndk_home = std.process.getEnvVarOwned(builder.allocator, "ANDROID_NDK_HOME") catch {
                std.log.err("ANDROID_NDK_HOME must be set for Android builds", .{});
                std.process.exit(1);
            };
            defer builder.allocator.free(ndk_home);

            const host_triple = switch (@import("builtin").os.tag) {
                .macos => blk: {
                    // NDK prebuilts may be darwin-x86_64 even on ARM Macs
                    const arch_triple = switch (@import("builtin").target.cpu.arch) {
                        .aarch64 => "darwin-aarch64",
                        else => "darwin-x86_64",
                    };
                    const prebuilt_dir = std.fs.path.join(builder.allocator, &[_][]const u8{
                        ndk_home, "toolchains", "llvm", "prebuilt", arch_triple,
                    }) catch break :blk "darwin-x86_64";
                    defer builder.allocator.free(prebuilt_dir);
                    if (std.fs.cwd().access(prebuilt_dir, .{})) |_| {
                        break :blk arch_triple;
                    } else |_| {
                        break :blk "darwin-x86_64";
                    }
                },
                .linux => "linux-x86_64",
                .windows => "windows-x86_64",
                else => {
                    std.log.err("Unsupported host OS for Android cross-build", .{});
                    std.process.exit(1);
                },
            };

            const sysroot = std.fs.path.join(builder.allocator, &[_][]const u8{ ndk_home, "toolchains", "llvm", "prebuilt", host_triple, "sysroot" }) catch {
                std.log.err("NDK sysroot not found at {s}/toolchains/llvm/prebuilt/{s}/sysroot", .{ ndk_home, host_triple });
                std.process.exit(1);
            };
            defer builder.allocator.free(sysroot);

            const usr_include = std.fs.path.join(builder.allocator, &[_][]const u8{ sysroot, "usr", "include" }) catch return;
            defer builder.allocator.free(usr_include);
            step.addSystemIncludePath(.{ .cwd_relative = usr_include });

            const arch_triple = switch (arch) {
                .aarch64 => "aarch64-linux-android",
                .arm => "arm-linux-androideabi",
                .x86_64 => "x86_64-linux-android",
                else => {
                    std.log.err("Unsupported Android arch", .{});
                    std.process.exit(1);
                },
            };

            const arch_include = std.fs.path.join(builder.allocator, &[_][]const u8{ usr_include, arch_triple }) catch return;
            defer builder.allocator.free(arch_include);
            step.addSystemIncludePath(.{ .cwd_relative = arch_include });

            // Determine API level (default 21)
            const api_level = if (std.process.getEnvVarOwned(builder.allocator, "ANDROID_API_LEVEL")) |level| blk: {
                defer builder.allocator.free(level);
                break :blk level;
            } else |_| "21";

            // Compute NDK lib dir for system libs (liblog, libc, libm, libdl)
            const ndk_lib_dir = std.fs.path.join(builder.allocator, &[_][]const u8{ sysroot, "usr", "lib", arch_triple, api_level }) catch return;
            defer builder.allocator.free(ndk_lib_dir);
            step.addLibraryPath(.{ .cwd_relative = ndk_lib_dir });

            // Generate libc config file for CRT objects (crtbegin_so.o, crtend_so.o)
            const libc_config = std.fmt.allocPrint(builder.allocator,
                \\include_dir={s}
                \\sys_include_dir={s}
                \\crt_dir={s}
                \\msvc_lib_dir=
                \\kernel32_lib_dir=
                \\gcc_dir=
            , .{ usr_include, arch_include, ndk_lib_dir }) catch return;
            defer builder.allocator.free(libc_config);

            const conf_name = std.fmt.allocPrint(builder.allocator, "android-libc-{s}.conf", .{@tagName(arch)}) catch return;
            defer builder.allocator.free(conf_name);

            const conf_path = std.fs.path.join(builder.allocator, &[_][]const u8{ ".zig-cache", conf_name }) catch return;
            {
                std.fs.cwd().makePath(".zig-cache") catch {};
                const f = std.fs.cwd().createFile(conf_path, .{}) catch {
                    std.log.err("Failed to write libc config to {s}", .{conf_path});
                    std.process.exit(1);
                };
                defer f.close();
                f.writeAll(libc_config) catch {
                    std.log.err("Failed to write libc config to {s}", .{conf_path});
                    std.process.exit(1);
                };
            }
            step.setLibCFile(.{ .cwd_relative = conf_path });
        }
    }.setup;

    // Helper to link OpenSSL for a given compile step
    const linkOpenSsl = struct {
        fn link(builder: *std.Build, step: *std.Build.Step.Compile, os: std.Target.Os.Tag, android: bool, arch: std.Target.Cpu.Arch, mac_lib: []const u8, mac_inc: []const u8, win_lib: []const u8, win_inc: []const u8, and_lib: []const u8, and_inc: []const u8, linux_lib: ?[]const u8) void {
            if (android) {
                setupAndroidNdk(builder, step, arch);
                step.addLibraryPath(.{ .cwd_relative = and_lib });
                step.addIncludePath(.{ .cwd_relative = and_inc });
                step.linkSystemLibrary2("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
                step.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
                step.linkSystemLibrary2("log", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
            } else if (os == .macos) {
                step.addLibraryPath(.{ .cwd_relative = mac_lib });
                step.addIncludePath(.{ .cwd_relative = mac_inc });
                step.linkSystemLibrary2("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
                step.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
            } else if (os == .ios) {
                step.addLibraryPath(.{ .cwd_relative = mac_lib });
                step.addIncludePath(.{ .cwd_relative = mac_inc });
                step.addSystemIncludePath(.{ .cwd_relative = mac_inc });
                step.linkSystemLibrary2("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
                step.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
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
                if (linux_lib) |d| {
                    step.addLibraryPath(.{ .cwd_relative = d });
                }
                step.addSystemIncludePath(.{ .cwd_relative = "/usr/include" });
                step.linker_allow_shlib_undefined = true;
                step.linkSystemLibrary2("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
                step.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
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
            .imports = &.{
                .{ .name = "build_options", .module = build_options_mod },
                .{ .name = "md4", .module = md4_mod },
            },
        }),
    });

    // Link OpenSSL for TLS (platform branches mirror linkOpenSsl below:
    // Android/iOS get the bundled static libs, desktop gets system libs)
    linkOpenSsl(b, vpnclient, target_os, is_android, target_arch, openssl_lib, openssl_include, win_openssl_lib, win_openssl_include, android_ssl_lib, android_ssl_include, linux_lib_dir);
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
            .strip = optimize != .Debug and target_os != .macos,
            .imports = &.{
                .{ .name = "build_options", .module = build_options_mod },
                .{ .name = "md4", .module = md4_mod },
            },
        }),
    });

    // Leave room for install_name_tool to rewrite dylib install name at bundle time
    if (target_os == .macos) {
        shared_lib.headerpad_max_install_names = true;
    }

    // Link OpenSSL for shared library too
    linkOpenSsl(b, shared_lib, target_os, is_android, target_arch, openssl_lib, openssl_include, win_openssl_lib, win_openssl_include, android_ssl_lib, android_ssl_include, linux_lib_dir);
    addZlib(shared_lib, b);

    // Android 15+ requires 16KB-aligned PT_LOAD segments. `patchelf
    // --page-size` does not physically re-align segments, so set the lld
    // `-z max-page-size` at link time, which re-aligns PT_LOAD segments.
    if (is_android) {
        shared_lib.link_z_max_page_size = 16384;
    }

    // jni_bridge.c removed — moved to android/app/src/main/cpp/ (app-layer binding, not engine code).
    // Compiled into softether_jni.so via CMake, loaded after libsoftether.so.

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
                .{ .name = "md4", .module = md4_mod },
            },
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
        setupAndroidNdk(b, static_lib, target_arch);
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
        if (linux_lib_dir) |d| static_lib.addLibraryPath(.{ .cwd_relative = d });
        static_lib.addSystemIncludePath(.{ .cwd_relative = "/usr/include" });
        static_lib.linker_allow_shlib_undefined = true;
        static_lib.linkSystemLibrary2("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
        static_lib.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .static });
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
    // NOTE: Files under src/app/ and src/net/ import sibling modules and
    // must be tested as part of the full package, not as standalone modules.
    const test_sources = [_][]const u8{
        "src/mayaqua/encrypt/sha0.zig",
        "src/mayaqua/encrypt/cipher.zig",
        "src/mayaqua/encrypt/hash.zig",
        "src/mayaqua/encrypt/md4.zig",
        "src/mayaqua/encrypt/rc4.zig",
        "src/cedar/protocol/pack.zig",
        "src/cedar/protocol/rpc.zig",
        "src/cedar/client/state.zig",
        "src/cedar/client/stats.zig",
        "src/cedar/client/events.zig",
        "src/mayaqua/kernel/ip.zig",
        "src/mayaqua/kernel/errors.zig",
        "src/mayaqua/kernel/types.zig",
        "src/config.zig",
        "src/types.zig",
        "src/cedar/tunnel/arp.zig",
        "src/cedar/tunnel/dhcp.zig",
        "src/cli/args.zig",
        "src/cli/config_manager.zig",
        "src/mayaqua/network/dns_cache.zig",
        "src/mayaqua/network/socks.zig",
        "src/bridge/fdb.zig",
        "src/bridge/engine.zig",
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
            if (linux_lib_dir) |d| t.addLibraryPath(.{ .cwd_relative = d });
            t.addSystemIncludePath(.{ .cwd_relative = "/usr/include" });
            t.linker_allow_shlib_undefined = true;
            t.linkSystemLibrary2("ssl", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
            t.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no, .preferred_link_mode = .dynamic });
        }
        if (is_android) setupAndroidNdk(b, t, target_arch);
        t.linkLibC();

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
                    .{ .name = "md4", .module = md4_mod },
                },
            }),
            .filters = &.{"ffi"},
        });
        linkOpenSsl(b, ffi_test, target_os, is_android, target_arch, openssl_lib, openssl_include, win_openssl_lib, win_openssl_include, android_ssl_lib, android_ssl_include, linux_lib_dir);
        addZlib(ffi_test, b);
        if (is_android) setupAndroidNdk(b, ffi_test, target_arch);
        ffi_test.linkLibC();

        const run_ffi_test = b.addRunArtifact(ffi_test);
        test_step.dependOn(&run_ffi_test.step);
    }

    // Whole-package test — same root as shared-lib (ffi.zig).
    // Runs ALL embedded test blocks in every imported module transitively
    // (session, protocol, net, crypto, etc.) that need sibling-import linkage
    // and can't be tested standalone.
    // Excludes: adapter.* (needs TUN), client.vpn_client (needs server),
    // protocol.tunnel (zlib state not reset between tests, issue #82).
    // auth.zig tests run here (not standalone) because it imports md4.zig
    // outside its source root.
    {
        const all_test = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/ffi.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "build_options", .module = build_options_mod },
                    .{ .name = "md4", .module = md4_mod },
                },
            }),
            .filters = &.{
                "crypto.",
                "core.",
                "net.",
                "mayaqua_tls.",
                "mayaqua_http.",
                "session.",
                "server.session.",
                "server.auth.",
                "client.state",
                "client.stats",
                "client.events",
                "tunnel.arp",
                "tunnel.dhcpv6",
                "tunnel.dhcp.",
                "config.",
                "types.",
                "protocol.pack",
                "protocol.auth",
                "protocol.rpc",
                "cli.args",
                "cli.config_manager",
                // auth.zig test blocks (cross-tree md4 import → run here)
                "ClientAuth",
                "Challenge generation",
                "Secure password computation",
                "Session key derivation",
                "certPemToDer",
                "signWithPrivateKey",
                "extractCertCommonName",
                "SHA-0 determinism",
                "MS-CHAPv2",
            },
        });
        linkOpenSsl(b, all_test, target_os, is_android, target_arch, openssl_lib, openssl_include, win_openssl_lib, win_openssl_include, android_ssl_lib, android_ssl_include, linux_lib_dir);
        addZlib(all_test, b);
        if (is_android) setupAndroidNdk(b, all_test, target_arch);
        all_test.linkLibC();

        const run_all_test = b.addRunArtifact(all_test);
        test_step.dependOn(&run_all_test.step);
    }

    // Protocol integration tests — drive the full handshake (signature →
    // hello → auth) against a scripted in-memory transport. Lives under
    // test/integration so it is clearly separate from in-source unit tests.
    // Imports the protocol module by name since Zig 0.15 disallows relative
    // imports that escape the module's source root.
    {
        const proto_mod = b.createModule(.{
            .root_source_file = b.path("src/cedar/protocol/softether_protocol.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "md4", .module = md4_mod },
            },
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
        linkOpenSsl(b, integration_test, target_os, is_android, target_arch, openssl_lib, openssl_include, win_openssl_lib, win_openssl_include, android_ssl_lib, android_ssl_include, linux_lib_dir);
        addZlib(integration_test, b);
        if (is_android) setupAndroidNdk(b, integration_test, target_arch);
        integration_test.linkLibC();

        const run_integration_test = b.addRunArtifact(integration_test);
        test_step.dependOn(&run_integration_test.step);
    }

    // DHCPv6 wire-format tests — validates byte layout of Solicit/Request/Reply
    // messages against RFC 8415. No sockets, no live server, CI-friendly.
    {
        const dhcpv6_mod = b.createModule(.{
            .root_source_file = b.path("src/cedar/tunnel/dhcpv6.zig"),
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
            dhcpv6_test.linkLibC();
        }
        const run_dhcpv6_test = b.addRunArtifact(dhcpv6_test);
        test_step.dependOn(&run_dhcpv6_test.step);
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
