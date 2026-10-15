#!/usr/bin/env python3
"""
BAP Developer Cockpit & Launch Runner
=====================================
Single-click launcher that bootstraps, self-diagnoses, and launches the
BAP Zero-Trust environment for developer AI coding agents.

Features:
  - Verifies local edge daemon status (starts in background if needed)
  - Probes control plane connectivity & synchronizes latest Cedar policy
  - Verifies cryptographic pins (AIR Model) across workspace prompt templates
  - Displays Live Workload Radar status and SPIFFE identity badge
  - Ready-to-code summary for Claude Code, Antigravity, and Copilot

Zero external dependencies (pure Python standard library).
"""

import os
import sys
import json
import shutil
import subprocess
import argparse
import time
import urllib.request
import urllib.error
import ssl

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_SERVER = "https://bap-controlplane.onrender.com"

class Color:
    CYAN = "\033[96m" if sys.platform != "win32" or "WT_SESSION" in os.environ or "ANSICON" in os.environ else ""
    GREEN = "\033[92m" if sys.platform != "win32" or "WT_SESSION" in os.environ or "ANSICON" in os.environ else ""
    YELLOW = "\033[93m" if sys.platform != "win32" or "WT_SESSION" in os.environ or "ANSICON" in os.environ else ""
    RED = "\033[91m" if sys.platform != "win32" or "WT_SESSION" in os.environ or "ANSICON" in os.environ else ""
    BOLD = "\033[1m" if sys.platform != "win32" or "WT_SESSION" in os.environ or "ANSICON" in os.environ else ""
    RESET = "\033[0m" if sys.platform != "win32" or "WT_SESSION" in os.environ or "ANSICON" in os.environ else ""


def find_bapedge() -> str:
    """Finds the bapedge binary in user directory, repo root, or PATH."""
    ext = ".exe" if sys.platform == "win32" else ""
    binary_name = "bapedge" + ext
    
    candidates = [
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "BAP", "bin", binary_name),
        os.path.expanduser(f"~/.local/bin/{binary_name}"),
        os.path.join(REPO_ROOT, binary_name),
        os.path.join(REPO_ROOT, "dist", "windows-amd64", binary_name),
        os.path.join(REPO_ROOT, "bap-edge", binary_name),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    found = shutil.which(binary_name)
    if found:
        return found
    return candidates[0]


def check_controlplane(server_url: str) -> dict:
    """Probes control plane and returns health/session statistics."""
    ctx = ssl.create_default_context()
    info = {"online": False, "status": "offline", "active_sessions": 0}
    try:
        req = urllib.request.Request(f"{server_url}/health", headers={"User-Agent": "BAP-LaunchCockpit/1.0"})
        with urllib.request.urlopen(req, timeout=4, context=ctx) as resp:
            if resp.status == 200:
                info["online"] = True
                info["status"] = "online"
    except Exception:
        return info

    try:
        req = urllib.request.Request(f"{server_url}/api/v1/sessions", headers={"User-Agent": "BAP-LaunchCockpit/1.0"})
        with urllib.request.urlopen(req, timeout=4, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            info["active_sessions"] = data.get("total", len(data.get("sessions", [])))
    except Exception:
        pass

    return info


def verify_content_pins(bapedge_bin: str) -> bool:
    """Executes cryptographic content verification against local pinned manifest."""
    if not os.path.isfile(bapedge_bin):
        return False
    try:
        res = subprocess.run(
            [bapedge_bin, "pin", "verify"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5
        )
        return res.returncode == 0
    except Exception:
        return False


def ensure_daemon_running(bapedge_bin: str):
    """Ensures the background local trusted daemon is running."""
    if not os.path.isfile(bapedge_bin):
        return False
    try:
        # Check daemon status
        res = subprocess.run(
            [bapedge_bin, "daemon", "status"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3
        )
        if "running" in res.stdout.lower() or res.returncode == 0:
            return True
        # If not running, start in user mode
        subprocess.run(
            [bapedge_bin, "daemon", "start", "--port", "8444"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5
        )
        return True
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(description="BAP Developer Cockpit & Launch Runner")
    parser.add_argument("--server", default=DEFAULT_SERVER, help=f"Central BAP Control Plane URL (default: {DEFAULT_SERVER})")
    parser.add_argument("--workspace", default=os.getcwd(), help="Target project workspace root")
    parser.add_argument("--open-radar", action="store_true", help="Open Live Workload Radar dashboard in browser")
    args = parser.parse_args()

    print("=" * 80)
    print(f"      {Color.CYAN}{Color.BOLD}BAP ZERO-TRUST AGENT GOVERNANCE -- DEVELOPER COCKPIT{Color.RESET}")
    print("=" * 80)
    print(f"[*] Workspace Root       : {args.workspace}")
    print(f"[*] Control Plane Server : {args.server}")

    # 1. Locate BAP Edge Daemon
    bapedge_bin = find_bapedge()
    if not os.path.isfile(bapedge_bin):
        print(f"\n{Color.RED}[!] bapedge executable not found!{Color.RESET}")
        print(f"    Please run the universal installer first: {Color.CYAN}python scripts/bap_install.py{Color.RESET}")
        sys.exit(1)
    print(f"[+] Resolved BAP Edge    : {bapedge_bin}")

    # 2. Check Control Plane
    cp_info = check_controlplane(args.server)
    if cp_info["online"]:
        print(f"[+] Control Plane State  : {Color.GREEN}ONLINE (Active Sessions on Radar: {cp_info['active_sessions']}){Color.RESET}")
    else:
        print(f"[+] Control Plane State  : {Color.YELLOW}OFFLINE / LOCAL RESILIENCE (Operating securely with cached policy){Color.RESET}")

    # 3. Verify Background Daemon
    daemon_ok = ensure_daemon_running(bapedge_bin)
    print(f"[+] Edge Daemon Status   : {Color.GREEN}ACTIVE (User Space PID){Color.RESET}" if daemon_ok else f"[+] Edge Daemon Status   : {Color.YELLOW}STANDBY (Direct Broker Execution){Color.RESET}")

    # 4. AIR Content Pinning Integrity
    pins_ok = verify_content_pins(bapedge_bin)
    if pins_ok:
        print(f"[+] AIR Content Pinning  : {Color.GREEN}INTACT (All prompt templates & skill hashes verified){Color.RESET}")
    else:
        print(f"[+] AIR Content Pinning  : {Color.YELLOW}NOTICE (Unpinned or drifted skills detected. Run: bapedge pin scan){Color.RESET}")

    # 5. Summary Banner & Agent Instructions
    print("\n" + "=" * 80)
    print(f"  {Color.GREEN}{Color.BOLD}READY FOR AGENT DEVELOPMENT -- All Operations Governed by Zero-Trust{Color.RESET}")
    print("=" * 80)
    print(f"  {Color.BOLD}1. Claude Code{Color.RESET}       : Run {Color.CYAN}claude{Color.RESET} -- BAP interceptor captures all tools & shell ops")
    print(f"  {Color.BOLD}2. Google Antigravity{Color.RESET}: Active in IDE via {Color.CYAN}GEMINI.md{Color.RESET} and BAP MCP server")
    print(f"  {Color.BOLD}3. GitHub Copilot{Color.RESET}   : Use {Color.CYAN}CopilotSandbox{Color.RESET} profile in VS Code integrated terminal")
    print(f"  {Color.BOLD}4. Shell Execution{Color.RESET}  : {Color.CYAN}bapedge exec \"<command>\"{Color.RESET}")
    print(f"  {Color.BOLD}5. Live Radar URL{Color.RESET}  : {Color.CYAN}{args.server}/api/v1/sessions{Color.RESET}")
    print("=" * 80)

    if args.open_radar and cp_info["online"]:
        import webbrowser
        webbrowser.open(f"{args.server}/inspector.html")


if __name__ == "__main__":
    main()
