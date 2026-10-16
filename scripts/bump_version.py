#!/usr/bin/env python3
"""
scripts/bump_version.py — BAP Version Management Tool
======================================================
Automates semantic version bumping across all repository components:
  - Go packages: bap-controlplane, bap-edge, bap-gateway
  - Python packages: bap, pyproject.toml, setup.py
  - Packaging scripts: Intune WiX MSI, Jamf PKG, Linux DEB
  - Multi-platform builder: build_all_platforms.ps1

Usage:
  python scripts/bump_version.py --minor                # 1.0.0 -> 1.1.0
  python scripts/bump_version.py --patch                # 1.0.0 -> 1.0.1
  python scripts/bump_version.py --major                # 1.0.0 -> 2.0.0
  python scripts/bump_version.py --set 1.2.0           # Explicit version
  python scripts/bump_version.py --dry-run --minor      # Preview changes only
  python scripts/bump_version.py --minor --rebuild      # Bump and trigger update_binaries.ps1
"""

import argparse
import os
import re
import subprocess
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Canonical files to update
TARGET_FILES = [
    {
        "path": os.path.join("bap-controlplane", "pkg", "version", "version.go"),
        "pattern": r'(Version\s*=\s*")v?[0-9]+\.[0-9]+\.[0-9]+(")',
        "replacement": r'\g<1>v{semver}\g<2>'
    },
    {
        "path": os.path.join("bap-edge", "pkg", "version", "version.go"),
        "pattern": r'(Version\s*=\s*")v?[0-9]+\.[0-9]+\.[0-9]+(")',
        "replacement": r'\g<1>v{semver}\g<2>'
    },
    {
        "path": os.path.join("bap-gateway", "pkg", "version", "version.go"),
        "pattern": r'(Version\s*=\s*")v?[0-9]+\.[0-9]+\.[0-9]+(")',
        "replacement": r'\g<1>v{semver}\g<2>'
    },
    {
        "path": "pyproject.toml",
        "pattern": r'(version\s*=\s*")[0-9]+\.[0-9]+\.[0-9]+(")',
        "replacement": r'\g<1>{semver}\g<2>'
    },
    {
        "path": "setup.py",
        "pattern": r'(version\s*=\s*")[0-9]+\.[0-9]+\.[0-9]+(")',
        "replacement": r'\g<1>{semver}\g<2>'
    },
    {
        "path": os.path.join("bap", "__init__.py"),
        "pattern": r'(__version__\s*=\s*")[0-9]+\.[0-9]+\.[0-9]+(")',
        "replacement": r'\g<1>{semver}\g<2>'
    },
    {
        "path": "build_all_platforms.ps1",
        "pattern": r'(\[string\]\$Version\s*=\s*")v?[0-9]+\.[0-9]+\.[0-9]+(")',
        "replacement": r'\g<1>v{semver}\g<2>'
    },
    {
        "path": os.path.join("packaging", "intune", "build_msi.ps1"),
        "pattern": r'(\[string\]\$Version\s*=\s*")[0-9]+\.[0-9]+\.[0-9]+(")',
        "replacement": r'\g<1>{semver}\g<2>'
    },
    {
        "path": os.path.join("packaging", "intune", "build_msi.ps1"),
        "pattern": r'(bapedge-windows-amd64-)[0-9]+\.[0-9]+\.[0-9]+(\.msi)',
        "replacement": r'\g<1>{semver}\g<2>'
    },
    {
        "path": os.path.join("packaging", "intune", "bapedge.wxs"),
        "pattern": r'(Version=")[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(")',
        "replacement": r'\g<1>{semver}.0\g<2>'
    },
    {
        "path": os.path.join("packaging", "jamf", "build_pkg.sh"),
        "pattern": r'(\$\{2:-)[0-9]+\.[0-9]+\.[0-9]+(\})',
        "replacement": r'\g<1>{semver}\g<2>'
    },
    {
        "path": os.path.join("packaging", "linux", "build_deb.sh"),
        "pattern": r'(\$\{2:-)[0-9]+\.[0-9]+\.[0-9]+(\})',
        "replacement": r'\g<1>{semver}\g<2>'
    }
]


def get_current_version() -> str:
    """Reads current version from pyproject.toml."""
    pyproject_path = os.path.join(REPO_ROOT, "pyproject.toml")
    with open(pyproject_path, "r", encoding="utf-8") as f:
        content = f.read()
    match = re.search(r'version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"', content)
    if not match:
        raise ValueError("Could not find current version in pyproject.toml")
    return match.group(1)


def bump_version_string(current: str, bump_type: str) -> str:
    """Computes next semantic version based on bump type."""
    parts = [int(p) for p in current.split(".")]
    if len(parts) != 3:
        raise ValueError(f"Invalid semver string: {current}")

    major, minor, patch = parts
    if bump_type == "major":
        return f"{major + 1}.0.0"
    elif bump_type == "minor":
        return f"{major}.{minor + 1}.0"
    elif bump_type == "patch":
        return f"{major}.{minor}.{patch + 1}"
    else:
        raise ValueError(f"Unknown bump type: {bump_type}")


def apply_version(new_semver: str, dry_run: bool = False):
    """Updates all target files with the new semantic version."""
    print(f"\n==========================================")
    print(f"BAP Version Manager: Target Version -> {new_semver}")
    print(f"Mode: {'DRY RUN (Preview Only)' if dry_run else 'APPLY CHANGES'}")
    print(f"==========================================\n")

    updated_files = set()

    for item in TARGET_FILES:
        rel_path = item["path"]
        full_path = os.path.join(REPO_ROOT, rel_path)
        if not os.path.exists(full_path):
            print(f"[SKIP] File not found: {rel_path}")
            continue

        with open(full_path, "r", encoding="utf-8") as f:
            content = f.read()

        replacement = item["replacement"].format(semver=new_semver)
        new_content, count = re.subn(item["pattern"], replacement, content)

        if count > 0:
            if not dry_run:
                with open(full_path, "w", encoding="utf-8") as f:
                    f.write(new_content)
            updated_files.add(rel_path)
            print(f"[OK] {rel_path} -> Updated ({count} occurrence{'s' if count > 1 else ''})")
        else:
            print(f"[WARN] No matching pattern found in: {rel_path}")

    print(f"\nTotal files updated: {len(updated_files)}")
    return len(updated_files)


def main():
    parser = argparse.ArgumentParser(description="Bump semantic versions across BAP codebase")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--minor", action="store_true", help="Bump minor version (e.g. 1.0.0 -> 1.1.0)")
    group.add_argument("--patch", action="store_true", help="Bump patch version (e.g. 1.0.0 -> 1.0.1)")
    group.add_argument("--major", action="store_true", help="Bump major version (e.g. 1.0.0 -> 2.0.0)")
    group.add_argument("--set", type=str, help="Set explicit semantic version (e.g. 1.2.0)")
    group.add_argument("--current", action="store_true", help="Display current version and exit")

    parser.add_argument("--dry-run", action="store_true", help="Preview modifications without writing to disk")
    parser.add_argument("--rebuild", action="store_true", help="Run update_binaries.ps1 after bumping version")

    args = parser.parse_args()

    current = get_current_version()
    if args.current:
        print(f"Current BAP version: {current}")
        return

    if args.set:
        # validate semver
        if not re.match(r'^[0-9]+\.[0-9]+\.[0-9]+$', args.set):
            print(f"Error: Invalid semantic version format '{args.set}'. Expected X.Y.Z", file=sys.stderr)
            sys.exit(1)
        new_version = args.set
    elif args.minor:
        new_version = bump_version_string(current, "minor")
    elif args.patch:
        new_version = bump_version_string(current, "patch")
    elif args.major:
        new_version = bump_version_string(current, "major")
    else:
        parser.print_help()
        sys.exit(1)

    print(f"Current Version: {current}")
    print(f"Target  Version: {new_version}")

    apply_version(new_version, dry_run=args.dry_run)

    if not args.dry_run and args.rebuild:
        print("\n[REBUILD] Triggering update_binaries.ps1...")
        cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", os.path.join(REPO_ROOT, "update_binaries.ps1")]
        res = subprocess.run(cmd, cwd=REPO_ROOT)
        if res.returncode == 0:
            print("[REBUILD] Binaries compiled and updated successfully.")
        else:
            print(f"[REBUILD ERROR] Failed with exit code {res.returncode}", file=sys.stderr)


if __name__ == "__main__":
    main()
