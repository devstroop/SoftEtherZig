#!/usr/bin/env python3
"""Bump the version in build.zig.zon.

Usage:
    scripts/bump_version.py patch   # 0.3.10 -> 0.3.11
    scripts/bump_version.py minor   # 0.3.10 -> 0.4.0
    scripts/bump_version.py major   # 0.3.10 -> 1.0.0
    scripts/bump_version.py set X.Y.Z  # explicit version
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ZON = REPO / "build.zig.zon"

VERSION_RE = re.compile(r'^(\s*\.version\s*=\s*")([^"]+)(",?\s*)$', re.MULTILINE)

def read_version() -> str:
    text = ZON.read_text()
    m = VERSION_RE.search(text)
    if not m:
        print("ERROR: Cannot find .version in build.zig.zon", file=sys.stderr)
        sys.exit(1)
    return m.group(2)

def write_version(new: str) -> None:
    text = ZON.read_text()
    def repl(m):
        return f'{m.group(1)}{new}{m.group(3)}'
    new_text = VERSION_RE.sub(repl, text, count=1)
    if new_text == text:
        print("ERROR: Version replacement had no effect", file=sys.stderr)
        sys.exit(1)
    ZON.write_text(new_text)

def bump(version: str, part: str) -> str:
    parts = version.split('.')
    if len(parts) != 3:
        print(f"ERROR: Unexpected version format: {version}", file=sys.stderr)
        sys.exit(1)
    major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
    if part == "major":
        return f"{major + 1}.0.0"
    elif part == "minor":
        return f"{major}.{minor + 1}.0"
    elif part == "patch":
        return f"{major}.{minor}.{patch + 1}"
    else:
        print(f"ERROR: Unknown part '{part}'. Use: major, minor, patch, or set X.Y.Z", file=sys.stderr)
        sys.exit(1)

def main() -> int:
    old = read_version()

    if len(sys.argv) < 2:
        print(f"Current version: {old}")
        print("Usage: bump_version.py <major|minor|patch|set X.Y.Z>")
        return 0

    action = sys.argv[1]
    if action == "set":
        if len(sys.argv) < 3:
            print("ERROR: 'set' requires a version argument (e.g., set 1.0.0)", file=sys.stderr)
            return 1
        new = sys.argv[2]
        if not re.match(r'^\d+\.\d+\.\d+$', new):
            print(f"ERROR: Invalid version format '{new}'. Expected X.Y.Z (e.g., 1.0.0)", file=sys.stderr)
            return 1
    else:
        new = bump(old, action)

    write_version(new)
    print(f"Version bumped: {old} -> {new}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
