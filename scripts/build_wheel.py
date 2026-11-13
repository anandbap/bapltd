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
import json

try:
    from . import bap_release
except ImportError:
    _scripts_dir = os.path.dirname(os.path.abspath(__file__))
    if _scripts_dir not in sys.path:
        sys.path.insert(0, _scripts_dir)
    import bap_release

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
    """Build official clients with developer override compiled out.

    A timestamp cannot distinguish a newer laptop development build from an
    official artifact. Release packaging always compiles its own client outputs.
    """
    go_cmd = shutil.which("go")
    if not go_cmd:
        raise RuntimeError("Go is required to compile and verify official release clients")
    git_commit = "dev"
    try:
        git_commit = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=REPO_ROOT,
            text=True, stderr=subprocess.DEVNULL, timeout=10
        ).strip() or "dev"
    except (OSError, subprocess.SubprocessError):
        pass
    for plat in platforms:
        cfg = PLATFORM_GO_MAP.get(plat)
        if not cfg:
            raise ValueError(f"Unsupported release platform: {plat}")
        directory = os.path.join(REPO_ROOT, "dist", plat, "claude-client")
        os.makedirs(directory, exist_ok=True)
        env = dict(os.environ, CGO_ENABLED="0", GOOS=cfg["GOOS"], GOARCH=cfg["GOARCH"])
        components = [
            ("bap-edge", "bapedge", f"-s -w -X bap-edge/pkg/version.GitCommit={git_commit} -X bap-edge/pkg/version.AllowDevOverrides=false"),
            ("cchook", "interceptor", "-s -w -X main.AllowDevOverrides=false"),
        ]
        for module, name, flags in components:
            target = os.path.join(directory, name + cfg["ext"])
            print(f"[*] Compiling official {name} for {plat}...")
            result = subprocess.run(
                [go_cmd, "build", "-trimpath", "-ldflags", flags, "-o", target, "."],
                cwd=os.path.join(REPO_ROOT, module), env=env,
                capture_output=True, text=True, timeout=180
            )
            if result.returncode:
                raise RuntimeError(f"Official {name} build failed for {plat}: {result.stderr}")
            if name == "interceptor":
                legacy_dir = os.path.join(directory, "cchook")
                os.makedirs(legacy_dir, exist_ok=True)
                shutil.copy2(target, os.path.join(legacy_dir, name + cfg["ext"]))


def _safe_build_directory(path):
    root = os.path.realpath(REPO_ROOT)
    target = os.path.realpath(path)
    try:
        inside = os.path.commonpath([root, target]) == root
    except ValueError:
        inside = False
    if not inside or target == root or os.path.islink(path):
        raise RuntimeError(f"Build directory must remain inside the source workspace: {path}")
    return target


def stage_binaries(platforms: list):
    """Stage only the official outputs; developer copies never win by mtime."""
    destination = _safe_build_directory(BAP_BIN_DIR)
    if os.path.isdir(destination):
        shutil.rmtree(destination)
    os.makedirs(destination, exist_ok=True)
    staged_count = 0
    for plat in platforms:
        if plat not in PLATFORM_GO_MAP:
            raise ValueError(f"Unsupported release platform: {plat}")
        target_dir = os.path.join(destination, plat)
        os.makedirs(target_dir, exist_ok=True)
        ext = PLATFORM_GO_MAP[plat]["ext"]
        for name in ("bapedge", "interceptor"):
            filename = name + ext
            source = os.path.join(REPO_ROOT, "dist", plat, "claude-client", filename)
            if not os.path.isfile(source):
                raise RuntimeError(f"Missing official client artifact: {source}")
            target = os.path.join(target_dir, filename)
            shutil.copy2(source, target)
            if not plat.startswith("windows"):
                os.chmod(target, 0o755)
            staged_count += 1
        for filename in ("policy.cedar", "schema.json", "bap-config.json"):
            source = os.path.join(REPO_ROOT, filename)
            if not os.path.isfile(source):
                source = os.path.join(REPO_ROOT, "dist", plat, filename)
            if os.path.isfile(source):
                shutil.copy2(source, os.path.join(target_dir, filename))
    print(f"[*] Staged {staged_count} official clients across {len(platforms)} platforms")


def copy_installer_script():
    # 1. Scripts & Debugging tools
    for sname in [
        "bap_install.py", "bap_startup.py", "bap_doctor.py", "bap_release.py", "bap_launch.py", "bap_harness.py", "bap_launcher_engine.ps1",
        "review_session.ps1", "review_session.bat", "review_session.sh",
        "watch_session.ps1", "watch_session.bat", "watch_session.sh",
        "verify_sts_obo_exchange.py", "verify_sts.bat", "verify_sts.sh",
        "check_stale_copies.ps1", "check_stale_copies.bat", "check_stale_copies.sh",
        "supervise_controlplane.ps1", "supervise_controlplane.sh"
    ]:
        src = os.path.join(REPO_ROOT, "scripts", sname)
        if not os.path.isfile(src):
            src = os.path.join(REPO_ROOT, sname)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(BAP_PKG_DIR, sname))

    # 2. Configs
    for cname in ["policy.cedar", "schema.json", "bap-config.json"]:
        src = os.path.join(REPO_ROOT, cname)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(BAP_PKG_DIR, cname))

    # 3. Launchers
    launchers_dir = os.path.join(BAP_PKG_DIR, "launchers")
    os.makedirs(launchers_dir, exist_ok=True)
    all_launchers = [
        "run_antigravity_cli_bap.bat", "run_antigravity_cli_bap.ps1", "run_antigravity_cli_bap.sh",
        "run_antigravity_ide_bap.bat", "run_antigravity_ide_bap.ps1", "run_antigravity_ide_bap.sh",
        "run_copilot_cli_bap.bat", "run_copilot_cli_bap.ps1", "run_copilot_cli_bap.sh",
        "run_copilot_ide_bap.bat", "run_copilot_ide_bap.ps1", "run_copilot_ide_bap.sh",
        "run_claude_cli_bap.bat", "run_claude_cli_bap.ps1", "run_claude_cli_bap.sh",
        "run_claude_ide_bap.bat", "run_claude_ide_bap.ps1", "run_claude_ide_bap.sh",
        "run_claude_bap.bat", "run_claude_bap.ps1", "run_claude_bap.sh",
        "run_cursor_bap.bat", "run_cursor_bap.ps1", "run_cursor_bap.sh",
        "run_gemini_cli_bap.bat", "run_gemini_cli_bap.ps1", "run_gemini_cli_bap.sh",
        "copilot-wrap.bat", "copilot-wrap.ps1", "copilot-wrap.sh",
        "bap_launcher_engine.ps1"
    ]
    for lf in all_launchers:
        candidates = [
            os.path.join(REPO_ROOT, lf),
            os.path.join(REPO_ROOT, "copilot", lf),
            os.path.join(REPO_ROOT, "scripts", lf),
            os.path.join(REPO_ROOT, "dist", "windows-amd64", "claude-client", lf),
            os.path.join(REPO_ROOT, "dist", "linux-amd64", "claude-client", lf),
        ]
        for cand in candidates:
            if os.path.isfile(cand):
                shutil.copy2(cand, os.path.join(launchers_dir, lf))
                shutil.copy2(cand, os.path.join(BAP_PKG_DIR, lf))
                break

    # 4. Native Agent Plugins (including hidden folders like .claude-plugin)
    plugins_src = os.path.join(REPO_ROOT, "plugins")
    if os.path.isdir(plugins_src):
        plugins_dst = os.path.join(BAP_PKG_DIR, "plugins")
        shutil.rmtree(plugins_dst, ignore_errors=True)
        shutil.copytree(plugins_src, plugins_dst, dirs_exist_ok=True)

def clean_build_artifacts():
    directory = _safe_build_directory(os.path.join(REPO_ROOT, "build"))
    if os.path.isdir(directory):
        shutil.rmtree(directory)
    shutil.rmtree(os.path.join(REPO_ROOT, "bap_ltd.egg-info"), ignore_errors=True)

def build_single_wheel(plat_id: str, plat_tag: str = None):
    print(f"\n[*] Packaging wheel for platform: {plat_id} (tag: {plat_tag or 'any'})...")
    clean_build_artifacts()
    ensure_binaries([plat_id])
    stage_binaries([plat_id])
    copy_installer_script()
    write_release_manifests([plat_id])

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

def write_release_manifests(platforms):
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True, timeout=5).strip()
    except (OSError, subprocess.SubprocessError):
        commit = "unknown"
    for platform_id in platforms:
        directory = os.path.join(BAP_BIN_DIR, platform_id)
        paths = bap_release.component_paths(directory, BAP_PKG_DIR, os.path.join(BAP_PKG_DIR, "launchers"), platform_id)
        identities = {name: bap_release.build_identity(paths[name]) for name in ("edge", "interceptor")}
        manifest = bap_release.create_manifest(platform_id, paths, commit, identities)
        with open(os.path.join(directory, "bap-release.json"), "w", encoding="utf-8") as stream:
            json.dump(manifest, stream, indent=2, sort_keys=True)


def build_universal_wheel():
    print(f"\n[*] Packaging Universal Fat Wheel (all 5 platforms)...")
    clean_build_artifacts()
    ensure_binaries(UNIVERSAL_PLATFORMS)
    stage_binaries(UNIVERSAL_PLATFORMS)
    copy_installer_script()

    write_release_manifests(UNIVERSAL_PLATFORMS)

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
