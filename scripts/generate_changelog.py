#!/usr/bin/env python3
"""Generate changelog entries from git log since the last tag.

Usage:
    scripts/generate_changelog.py          # Print to stdout
    scripts/generate_changelog.py > CHANGELOG片段.md  # Write to file

Commits are grouped by conventional commit prefix (feat, fix, etc.).
"""

import re
import subprocess
import sys
from collections import defaultdict

def get_last_tag() -> str | None:
    try:
        result = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None

def get_commits_since(tag: str | None) -> list[tuple[str, str]]:
    """Return list of (hash, subject) since tag (or all commits if no tag)."""
    cmd = ["git", "log", "--oneline", "--no-merges"]
    if tag:
        cmd.append(f"{tag}..HEAD")
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    commits = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        parts = line.split(" ", 1)
        if len(parts) == 2:
            commits.append((parts[0], parts[1]))
    return commits

def categorize(commits: list[tuple[str, str]]) -> dict[str, list[tuple[str, str]]]:
    categories = defaultdict(list)
    for hash_, subject in commits:
        m = re.match(r'^(feat|fix|test|docs|refactor|perf|chore|ci|build)(?:\(.+?\))?:\s*(.+)', subject)
        if m:
            prefix, msg = m.group(1), m.group(2)
            label = {
                "feat": "Added",
                "fix": "Fixed",
                "test": "Tests",
                "docs": "Documentation",
                "refactor": "Refactored",
                "perf": "Performance",
                "chore": "Maintenance",
                "ci": "CI/CD",
                "build": "Build",
            }.get(prefix, prefix.title())
            categories[label].append((hash_, msg))
        else:
            categories["Other"].append((hash_, subject))
    return dict(categories)

def main() -> None:
    tag = get_last_tag()
    commits = get_commits_since(tag)
    if not commits:
        print("No commits since last tag." if tag else "No commits found.")
        return

    categories = categorize(commits)
    version = subprocess.run(
        ["grep", "-oP", r'\\.version\\s*=\\s*"\\K[^"]+'],
        capture_output=True, text=True
    ).stdout.strip() or "unknown"

    print(f"## [{version}] - Unreleased\n")
    if tag:
        print(f"Changes since `{tag}`:\n")

    order = ["Added", "Fixed", "Tests", "Documentation", "Refactored",
             "Performance", "CI/CD", "Build", "Maintenance", "Other"]
    for cat in order:
        items = categories.get(cat, [])
        if not items:
            continue
        print(f"### {cat}\n")
        for hash_, msg in items:
            print(f"- {msg} (`{hash_}`)")
        print()

if __name__ == "__main__":
    main()
