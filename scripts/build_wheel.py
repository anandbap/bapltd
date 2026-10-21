#!/usr/bin/env python3
"""
BAP Wheel Builder -- Packages Go Binaries and Core Assets into Python Wheels
============================================================================
Supports two packaging modes:
  1. Universal Fat Wheel (py3-none-any) bundling all 5 platforms [DEFAULT]
  2. Platform-Specific Wheels (e.g. win_amd64, macosx_arm64, manylinux_x86_64) (~5-6 MB each)
"""

import os
import sys
import shutil
import zipfile
import subprocess
import argparse
import platform

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BAP_PKG_DIR = os.path.join(REPO_ROOT, "bap")
BAP_BIN_DIR = os.path.join(BAP_PKG_DIR, "bin")

PLATFORM_TAG_MAP = {
    "windows-amd64": "win_amd64",
    "windows-arm64": "win_arm64",
    "darwin-arm64": "macosx_11_0_arm64",
    "darwin-amd64": "macosx_10_9_x86_64",
    "linux-amd64": "manylinux2014_x86_64",
    "linux-arm64": "manylinux2014_aarch64",
}

PLATFORM_GO_MAP = {
    "windows-amd64": {"GOOS": "windows", "GOARCH": "amd64", "ext": ".exe"},
    "windows-arm64": {"GOOS": "windows", "GOARCH": "arm64", "ext": ".exe"},
    "darwin-arm64":  {"GOOS": "darwin",  "GOARCH": "arm64", "ext": ""},
    "darwin-amd64":  {"GOOS": "darwin",  "GOARCH": "amd64", "ext": ""},
    "linux-amd64":   {"GOOS": "linux",   "GOARCH": "amd64", "ext": ""},
    "linux-arm64":   {"GOOS": "linux",   "GOARCH": "arm64", "ext": ""},
}

UNIVERSAL_PLATFORMS = ["windows-amd64", "darwin-arm64", "darwin-amd64", "linux-amd64", "linux-arm64"]

def get_platform_id() -> str:
    machine = platform.machine().lower()
    is_arm = machine in ("arm64", "aarch64", "armv8b", "armv8l")
    if sys.platform == "win32":
        return "windows-arm64" if is_arm else "windows-amd64"
    elif sys.platform == "darwin":
        return "darwin-arm64" if is_arm else "darwin-amd64"
    else:
        return "linux-arm64" if is_arm else "linux-amd64"

def ensure_binaries(platforms: list):
    """
    Verifies that client binaries (bapedge and interceptor) exist for all requested platforms.
    If missing, automatically cross-compiles them using Go (CGO_ENABLED=0).
    """
    go_cmd = shutil.which("go")
    for plat in platforms:
        plat_cfg = PLATFORM_GO_MAP.get(plat)
        if not plat_cfg:
            continue
        ext = plat_cfg["ext"]
        target_dir = os.path.join(REPO_ROOT, "dist", plat, "claude-client")
        os.makedirs(target_dir, exist_ok=True)

        bapedge_target = os.path.join(target_dir, f"bapedge{ext}")
        interceptor_target = os.path.join(target_dir, f"interceptor{ext}")

        need_bapedge = not (
            os.path.isfile(bapedge_target) or
            os.path.isfile(os.path.join(REPO_ROOT, "dist", plat, f"bapedge{ext}")) or
            (plat.startswith("windows") and os.path.isfile(os.path.join(REPO_ROOT, "bapedge.exe")))
        )
        need_interceptor = not (
            os.path.isfile(interceptor_target) or
            os.path.isfile(os.path.join(REPO_ROOT, "dist", plat, f"interceptor{ext}")) or
            (plat.startswith("windows") and os.path.isfile(os.path.join(REPO_ROOT, "cchook", "interceptor.exe")))
        )

        if (need_bapedge or need_interceptor) and go_cmd:
            env = os.environ.copy()
            env["CGO_ENABLED"] = "0"
            env["GOOS"] = plat_cfg["GOOS"]
            env["GOARCH"] = plat_cfg["GOARCH"]

            if need_bapedge:
                print(f"[*] Cross-compiling bapedge for {plat} (GOOS={env['GOOS']}, GOARCH={env['GOARCH']})...")
                res = subprocess.run(
                    [go_cmd, "build", "-trimpath", "-ldflags", "-s -w", "-o", bapedge_target, "."],
                    cwd=os.path.join(REPO_ROOT, "bap-edge"),
                    env=env,
                    capture_output=True,
                    text=True
                )
                if res.returncode != 0:
                    print(f"[!] Warning: failed to build bapedge for {plat}: {res.stderr}")
                else:
                    print(f"  [+] Built: {bapedge_target}")

            if need_interceptor:
                print(f"[*] Cross-compiling interceptor for {plat} (GOOS={env['GOOS']}, GOARCH={env['GOARCH']})...")
                res = subprocess.run(
                    [go_cmd, "build", "-trimpath", "-ldflags", "-s -w", "-o", interceptor_target, "interceptor.go"],
                    cwd=os.path.join(REPO_ROOT, "cchook"),
                    env=env,
                    capture_output=True,
                    text=True
                )
                if res.returncode != 0:
                    print(f"[!] Warning: failed to build interceptor for {plat}: {res.stderr}")
                else:
                    print(f"  [+] Built: {interceptor_target}")

def stage_binaries(platforms: list):
    """Stages precompiled Go client binaries and configs into bap/bin/<plat>/."""
    if os.path.isdir(BAP_BIN_DIR):
        shutil.rmtree(BAP_BIN_DIR)
    os.makedirs(BAP_BIN_DIR, exist_ok=True)

    staged_count = 0
    for plat in platforms:
        plat_src = os.path.join(REPO_ROOT, "dist", plat, "claude-client")
        if not os.path.isdir(plat_src):
            plat_src = os.path.join(REPO_ROOT, "dist", plat)

        target_dir = os.path.join(BAP_BIN_DIR, plat)
        os.makedirs(target_dir, exist_ok=True)

        ext = ".exe" if plat.startswith("windows") else ""
        binaries = ["bapedge" + ext, "interceptor" + ext]

        for b in binaries:
            src = os.path.join(plat_src, b)
            if not os.path.isfile(src):
                alt = os.path.join(REPO_ROOT, "dist", plat, b)
                if os.path.isfile(alt):
                    src = alt
                elif b.startswith("interceptor"):
                    alt2 = os.path.join(plat_src, "cchook-interceptor" + ext)
                    if os.path.isfile(alt2):
                        src = alt2
                    elif plat.startswith("windows") and os.path.isfile(os.path.join(REPO_ROOT, "cchook", "interceptor.exe")):
                        src = os.path.join(REPO_ROOT, "cchook", "interceptor.exe")
                elif b.startswith("bapedge") and plat.startswith("windows") and os.path.isfile(os.path.join(REPO_ROOT, "bapedge.exe")):
                    src = os.path.join(REPO_ROOT, "bapedge.exe")

            if os.path.isfile(src):
                dst = os.path.join(target_dir, b)
                shutil.copy2(src, dst)
                if not plat.startswith("windows"):
                    os.chmod(dst, 0o755)
                sz_mb = os.path.getsize(dst) / (1024 * 1024)
                print(f"[+] Staged {plat}/{b} ({sz_mb:.2f} MB)")
                staged_count += 1
            else:
                print(f"[!] Warning: Could not find {b} for {plat} at {src}")

        # Copy configs
        for cfg in ["policy.cedar", "schema.json", "bap-config.json"]:
            src = os.path.join(REPO_ROOT, cfg)
            if not os.path.isfile(src):
                src = os.path.join(REPO_ROOT, "dist", plat, cfg)
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(target_dir, cfg))

    print(f"[*] Total binaries staged: {staged_count} across {len(platforms)} platform(s)")

def copy_installer_script():
    installer_src = os.path.join(REPO_ROOT, "scripts", "bap_install.py")
    if os.path.isfile(installer_src):
        shutil.copy2(installer_src, os.path.join(BAP_PKG_DIR, "bap_install.py"))

def clean_build_artifacts():
    shutil.rmtree(os.path.join(REPO_ROOT, "build"), ignore_errors=True)
    shutil.rmtree(os.path.join(REPO_ROOT, "bap_ltd.egg-info"), ignore_errors=True)

def build_single_wheel(plat_id: str, plat_tag: str = None):
    print(f"\n[*] Packaging wheel for platform: {plat_id} (tag: {plat_tag or 'any'})...")
    clean_build_artifacts()
    ensure_binaries([plat_id])
    stage_binaries([plat_id])
    copy_installer_script()

    cmd = [sys.executable, "setup.py", "bdist_wheel"]
    if plat_tag:
        cmd.extend(["--plat-name", plat_tag])

    res = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[!] Error building wheel: {res.stderr}\n{res.stdout}")
        sys.exit(res.returncode or 1)

    dist_dir = os.path.join(REPO_ROOT, "dist")
    wheels = [os.path.join(dist_dir, f) for f in os.listdir(dist_dir) if f.endswith(".whl")]
    if wheels:
        latest = max(wheels, key=os.path.getmtime)
        sz_mb = os.path.getsize(latest) / (1024 * 1024)
        print(f"  [+] Built: {os.path.basename(latest)} ({sz_mb:.2f} MB)")
        return latest
    print("[!] Error: No wheel was created in dist/")
    sys.exit(1)

def build_universal_wheel():
    print(f"\n[*] Packaging Universal Fat Wheel (all 5 platforms)...")
    clean_build_artifacts()
    ensure_binaries(UNIVERSAL_PLATFORMS)
    stage_binaries(UNIVERSAL_PLATFORMS)
    copy_installer_script()

    cmd = [sys.executable, "setup.py", "bdist_wheel"]
    res = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[!] Error building universal wheel: {res.stderr}\n{res.stdout}")
        sys.exit(res.returncode or 1)

    dist_dir = os.path.join(REPO_ROOT, "dist")
    wheels = [os.path.join(dist_dir, f) for f in os.listdir(dist_dir) if f.endswith("-py3-none-any.whl")]
    if wheels:
        latest = max(wheels, key=os.path.getmtime)
        sz_mb = os.path.getsize(latest) / (1024 * 1024)
        print(f"  [+] Built Universal Wheel: {os.path.basename(latest)} ({sz_mb:.2f} MB)")
        return latest
    print("[!] Error: Universal wheel (-py3-none-any.whl) not found in dist/")
    sys.exit(1)

def build_sdist():
    print("\n[*] Packaging Python source distribution (sdist .tar.gz)...")
    cmd = [sys.executable, "setup.py", "sdist"]
    res = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[!] Error building sdist: {res.stderr}\n{res.stdout}")
        sys.exit(res.returncode or 1)
    dist_dir = os.path.join(REPO_ROOT, "dist")
    sdists = [os.path.join(dist_dir, f) for f in os.listdir(dist_dir) if f.endswith(".tar.gz") and "bap" in f]
    if sdists:
        latest = max(sdists, key=os.path.getmtime)
        sz_mb = os.path.getsize(latest) / (1024 * 1024)
        print(f"  [+] Built sdist: {os.path.basename(latest)} ({sz_mb:.2f} MB)")
        return latest
    print("[!] Error: sdist (.tar.gz) not found in dist/")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Build BAP Python Wheels")
    parser.add_argument("--universal", action="store_true", default=False, help="Build single fat universal wheel with all 5 platforms (py3-none-any) [Default]")
    parser.add_argument("--all", action="store_true", default=False, help="Alias for --universal")
    parser.add_argument("--platform-wheels", action="store_true", help="Build separate lean platform-specific wheels instead of universal")
    parser.add_argument("--single-platform", action="store_true", help="Build single platform-specific wheel for the current host")
    parser.add_argument("--sdist", action="store_true", default=True, help="Build source distribution (.tar.gz) [Default]")
    parser.add_argument("--no-sdist", action="store_true", help="Skip building source distribution")
    args = parser.parse_args()

    if args.platform_wheels:
        print("[*] Building all platform-specific wheels...")
        for plat_id, plat_tag in PLATFORM_TAG_MAP.items():
            build_single_wheel(plat_id, plat_tag)
    elif args.single_platform:
        curr_plat = get_platform_id()
        curr_tag = PLATFORM_TAG_MAP.get(curr_plat, "any")
        build_single_wheel(curr_plat, curr_tag)
    else:
        # Default: Universal Fat Wheel (all 5 platforms)
        build_universal_wheel()

    if not args.no_sdist:
        build_sdist()

if __name__ == "__main__":
    main()
