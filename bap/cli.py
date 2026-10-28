#!/usr/bin/env python3
"""
BAP Unified CLI Entrypoint (bap command)
========================================
Main developer interface for BAP Zero-Trust AI Agent Governance.
"""

import sys
import os
import shutil
import subprocess

from . import __version__
from .install import main as install_main
from .launch import main as launch_main
from .doctor import main as doctor_main

USAGE = f"""BAP Zero-Trust Governance CLI (v{__version__})
Usage: bap <command> [options]

Commands:
  install       Run single-click user-mode onboarding installer
  uninstall     Cleanly remove BAP binaries, PATH entries, and agent hooks
  login         Authenticate workstation session with corporate SSO (Google / GitHub / Entra / Okta)
  logout        Deregister workstation and clear authenticated corporate session
  launch        Start developer cockpit, verify hooks & monitor agents
  doctor        Run comprehensive pre-flight diagnostic health check
  status        Check health of local edge daemon and central control plane
  exec <cmd>    Execute a shell command under Zero-Trust Cedar invariants
  pin <subcmd>  Manage cryptographic content pins (scan, list, verify)
  version       Display current BAP version

Examples:
  bap install
  bap login
  bap uninstall
  bap doctor
  bap launch
  bap status
  bap exec "npm test"
  bap pin verify
"""

def get_platform_id() -> str:
    import platform
    machine = platform.machine().lower()
    is_arm = machine in ("arm64", "aarch64", "armv8b", "armv8l")
    if sys.platform == "win32":
        return "windows-arm64" if is_arm else "windows-amd64"
    elif sys.platform == "darwin":
        return "darwin-arm64" if is_arm else "darwin-amd64"
    else:
        return "linux-arm64" if is_arm else "linux-amd64"

def find_bapedge() -> str:
    ext = ".exe" if sys.platform == "win32" else ""
    binary_name = "bapedge" + ext
    home = os.path.expanduser("~")
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    plat_id = get_platform_id()

    candidates = [
        os.path.join(home, "bin", binary_name),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "BAP", "bin", binary_name),
        os.path.join(os.environ.get("APPDATA", ""), "BAP", "bin", binary_name),
        os.path.expanduser(f"~/.local/bin/{binary_name}"),
        os.path.expanduser(f"~/.bap/bin/{binary_name}"),
        os.path.join(pkg_dir, "bin", plat_id, binary_name),
        os.path.join(pkg_dir, "bin", plat_id.replace("arm64", "amd64"), binary_name),
        os.path.abspath(binary_name),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            bin_dir = os.path.dirname(os.path.abspath(c))
            path_parts = os.environ.get("PATH", "").split(os.pathsep)
            if bin_dir and bin_dir not in path_parts:
                os.environ["PATH"] = bin_dir + os.pathsep + os.environ.get("PATH", "")
            return os.path.abspath(c)

    # Search system PATH, skipping python script shims to avoid recursion
    curr_exe = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else ""
    found = shutil.which(binary_name)
    if found:
        found_abs = os.path.abspath(found)
        if found_abs.lower() != curr_exe.lower() and "scripts" not in os.path.dirname(found_abs).lower():
            return found_abs

    return candidates[0]

def bapedge_proxy():
    """Direct proxy console_script entry point for 'bapedge'.
    Enables 'bapedge' to be immediately available on PATH right after 'pip install bap-ltd'
    via Python's Scripts directory.
    """
    bapedge = find_bapedge()
    if os.path.isfile(bapedge):
        sys.exit(subprocess.call([bapedge] + sys.argv[1:]))
    else:
        print("[!] bapedge binary not found in standard user paths (~/bin, %LOCALAPPDATA%\\BAP\\bin).")
        print("    Please run 'bap install' to download and set up the local BAP Edge engine.")
        sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print(USAGE)
        sys.exit(0)

    cmd = sys.argv[1].lower()
    rest = sys.argv[2:]

    if cmd in ["-h", "--help", "help"]:
        print(USAGE)
        sys.exit(0)
    elif cmd in ["-v", "--version", "version"]:
        print(f"bap version {__version__}")
        sys.exit(0)
    elif cmd in ["install", "setup"]:
        sys.argv = [sys.argv[0]] + rest
        install_main()
    elif cmd in ["uninstall", "remove"]:
        sys.argv = [sys.argv[0], "--uninstall"] + rest
        install_main()
    elif cmd == "login":
        bapedge = find_bapedge()
        if not os.path.isfile(bapedge):
            print(f"[!] bapedge binary not found. Please run 'bap install' first.")
            sys.exit(1)
        sub_cmd = [bapedge, "login"] + rest
        sys.exit(subprocess.call(sub_cmd))
    elif cmd == "logout":
        bapedge = find_bapedge()
        if os.path.isfile(bapedge):
            sub_cmd = [bapedge, "logout"] + rest
            sys.exit(subprocess.call(sub_cmd))
        else:
            # Fallback local credential cleanup
            home = os.path.expanduser("~")
            candidates = [
                os.path.join(home, ".bapstate", "credentials.json"),
                os.path.join(home, ".ltd", "credentials.json"),
            ]
            removed = False
            for c in candidates:
                if os.path.exists(c):
                    try:
                        os.remove(c)
                        removed = True
                    except Exception:
                        pass
            if removed:
                print("[✓] Local session credentials removed. Workstation is logged out.")
            else:
                print("[i] No active enrolled credentials found. Workstation is already logged out.")
            sys.exit(0)
    elif cmd == "launch":
        sys.argv = [sys.argv[0]] + rest
        launch_main()
    elif cmd == "doctor":
        sys.argv = [sys.argv[0]] + rest
        doctor_main()
    elif cmd in ["exec", "run"]:
        bapedge = find_bapedge()
        if not os.path.isfile(bapedge):
            print(f"[!] bapedge binary not found. Please run 'bap install' first.")
            sys.exit(1)
        sub_cmd = [bapedge, "exec"] + rest
        sys.exit(subprocess.call(sub_cmd))
    elif cmd == "status":
        bapedge = find_bapedge()
        if os.path.isfile(bapedge):
            if rest and rest[0] == "daemon":
                sys.exit(subprocess.call([bapedge, "daemon", "status"] + rest[1:]))
            sys.exit(subprocess.call([bapedge, "status"] + rest))
        else:
            print(f"[!] bapedge binary not found. Please run 'bap install' first.")
            sys.exit(1)
    elif cmd == "pin":
        bapedge = find_bapedge()
        if os.path.isfile(bapedge):
            sys.exit(subprocess.call([bapedge, "pin"] + rest))
        else:
            print(f"[!] bapedge binary not found. Please run 'bap install' first.")
            sys.exit(1)
    else:
        # Default fallback to bapedge
        bapedge = find_bapedge()
        if os.path.isfile(bapedge):
            sys.exit(subprocess.call([bapedge, cmd] + rest))
        else:
            print(f"Unknown command: {cmd}\n")
            print(USAGE)
            sys.exit(1)

if __name__ == "__main__":
    main()
