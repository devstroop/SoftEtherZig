#!/usr/bin/env bash
# setup_zig_0152.sh
#
# Set up zig 0.15.2 as the active `zig` on a machine where a different zig
# (e.g. 0.16.0) is installed system-wide, and work around zig 0.15.2's bundled
# lld 18 being unable to link against newer system glibc (2.44+, gcc 16)
# because crt1.o / libc_nonshared.a contain .sframe section relocations
# (R_X86_64_PC64) that lld 18 does not handle.
#
# What it does:
#   1. Symlinks zig-0.15.2 into /usr/local/bin/zig (takes PATH precedence over
#      /usr/bin/zig). Requires zig 0.15.2 already installed, e.g. at
#      /usr/local/zig-x86_64-linux-0.15.2/zig (https://ziglang.org/download).
#   2. Creates /usr/local/zig-crt-0152: copies of the system CRT objects with
#      .sframe stripped, plus the glibc linker scripts (libc.so/libm.so).
#   3. Writes /usr/local/etc/zig-glibc-0152.conf pointing crt_dir at it.
#   4. Strips .sframe from the system libc_nonshared.a (timestamped backup
#      kept in /usr/local/zig-crt-0152/). Needed because zig resolves
#      libc_nonshared.a from the system lib dir unconditionally (OpenSSL pulls
#      pthread_atfork.oS out of it). Idempotent: no-op when already stripped.
#
# build.zig auto-detects the libc file (/usr/local/etc/zig-glibc-0152.conf)
# for native Linux builds only; other platforms are unaffected.
#
# Re-run after a pacman/apt glibc upgrade: system crt files may be replaced.

set -euo pipefail

ZIG_0152="/usr/local/bin/zig-0.15.2"
CRT_DIR="/usr/local/zig-crt-0152"
CONF="/usr/local/etc/zig-glibc-0152.conf"
# System lib dir (where libc.so, libc_nonshared.a and the CRT objects live).
# Derive it from `gcc -print-file-name=libc.so` (e.g. /usr/lib on Arch,
# /usr/lib/x86_64-linux-gnu on Debian) and resolve any `..` components.
SYS_LIB="$(gcc -print-file-name=libc.so | xargs dirname)"
SYS_LIB="$(cd "$SYS_LIB" && pwd)"
# GCC's own lib dir (libgcc.a) for the libc file's gcc_dir field.
GCC_DIR="$(gcc -print-file-name=libgcc.a | xargs dirname)"
GCC_DIR="$(cd "$GCC_DIR" && pwd)"

echo "==> zig 0.15.2 -> /usr/local/bin/zig"
if ! "$ZIG_0152" version >/dev/null 2>&1; then
    echo "ERROR: $ZIG_0152 not found or not executable." >&2
    echo "Download zig 0.15.2 from https://ziglang.org/download and extract to /usr/local/" >&2
    exit 1
fi
ln -sf "$(readlink -f "$ZIG_0152")" /usr/local/bin/zig

echo "==> stripped CRT objects -> $CRT_DIR"
mkdir -p "$CRT_DIR"
for f in crt1.o crti.o crtn.o; do
    objcopy --remove-section .sframe "$SYS_LIB/$f" "$CRT_DIR/$f"
done
# glibc linker scripts zig looks up in crt_dir
cp "$SYS_LIB/libc.so" "$SYS_LIB/libm.so" "$CRT_DIR/"

echo "==> libc paths file -> $CONF"
mkdir -p /usr/local/etc
cat > "$CONF" <<EOF
include_dir=/usr/include
sys_include_dir=/usr/include
crt_dir=$CRT_DIR
msvc_lib_dir=
kernel32_lib_dir=
gcc_dir=$GCC_DIR
EOF

# Strip .sframe from the system libc_nonshared.a. Idempotent: only touches it
# when .sframe is present, and each modification gets its own timestamped
# backup so an upgrade + re-run never clobbers the previous recovery copy.
if objdump -h "$SYS_LIB/libc_nonshared.a" | grep -q '\.sframe'; then
    cp "$SYS_LIB/libc_nonshared.a" "$CRT_DIR/libc_nonshared.a.orig.$(date +%s)"
    objcopy --remove-section .sframe "$SYS_LIB/libc_nonshared.a"
    echo "==> stripped .sframe from system libc_nonshared.a (backup in $CRT_DIR/)"
else
    echo "==> libc_nonshared.a already stripped, skipping"
fi

echo "==> done. zig version: $(zig version)"
zig build