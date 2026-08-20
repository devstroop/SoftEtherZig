#!/usr/bin/env python3
"""Validate that include/softether.h declares every export in src/ffi.zig.

Exit 0 if in sync, exit 1 if header is missing declarations.
This script is designed to run in CI to catch header drift.
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FFI_ZIG = REPO / "src" / "ffi.zig"
HEADER_H = REPO / "include" / "softether.h"

def extract_ffi_exports(ffi_path: Path) -> set[str]:
    """Extract all 'export fn softether_*' names from ffi.zig."""
    exports = set()
    for line in ffi_path.read_text().splitlines():
        m = re.match(r'\s*export\s+fn\s+(softether_\w+)', line)
        if m:
            exports.add(m.group(1))
    return exports

def extract_header_fns(header_path: Path) -> set[str]:
    """Extract all 'softether_*' function names declared in the header."""
    fns = set()
    text = header_path.read_text()
    # Match function declarations: return_type softether_xxx(...)
    # Excludes typedefs, comments, and struct/enum definitions.
    for m in re.finditer(r'\b(softether_\w+)\s*\(', text):
        name = m.group(1)
        # Skip function pointer types in typedefs
        if 'typedef' in text[max(0, m.start()-20):m.start()]:
            continue
        fns.add(name)
    return fns

def main() -> int:
    if not FFI_ZIG.exists():
        print(f"ERROR: {FFI_ZIG} not found", file=sys.stderr)
        return 1
    if not HEADER_H.exists():
        print(f"ERROR: {HEADER_H} not found", file=sys.stderr)
        return 1

    ffi_exports = extract_ffi_exports(FFI_ZIG)
    header_fns = extract_header_fns(HEADER_H)

    missing_in_header = sorted(ffi_exports - header_fns)
    extra_in_header = sorted(header_fns - ffi_exports)

    ok = True

    if missing_in_header:
        ok = False
        print(f"FAIL: {len(missing_in_header)} export(s) in ffi.zig missing from header:")
        for name in missing_in_header:
            print(f"  - {name}")

    if extra_in_header:
        # Extra in header is a warning — could be intentionally kept for
        # forward-compat or deprecated APIs.
        print(f"WARN: {len(extra_in_header)} function(s) in header not found in ffi.zig:")
        for name in extra_in_header:
            print(f"  - {name}")

    if ok:
        print(f"OK: Header in sync ({len(ffi_exports)} exports, {len(header_fns)} declarations)")
        return 0
    else:
        print(f"\nPlease update include/softether.h to match src/ffi.zig exports.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
