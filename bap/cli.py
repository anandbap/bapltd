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
  login         Authenticate workstation session with corporate SSO (Entra ID / Okta OIDC)
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

def find_bapedge() -> str:
    ext = ".exe" if sys.platform == "win32" else ""
    binary_name = "bapedge" + ext
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, "bin", binary_name),
        os.path.join(os.environ.get("APPDATA", ""), "BAP", "bin", binary_name),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "BAP", "bin", binary_name),
        os.path.expanduser(f"~/.local/bin/{binary_name}"),
        os.path.expanduser(f"~/.bap/bin/{binary_name}"),
        os.path.abspath(binary_name),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    found = shutil.which(binary_name)
    if found:
        return found
    return candidates[0]

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
            sys.exit(subprocess.call([bapedge, "daemon", "status"] + rest))
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
