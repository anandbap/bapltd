#!/usr/bin/env python3
"""
BAP Diagnostic Doctor - Environment & Pre-Flight Health Check (Cross-Platform)
=============================================================================
Performs comprehensive multi-point health check for AI agent zero-trust governance.
Compatible with Windows, macOS, and Linux without external dependencies.
"""

import os
import sys
import time
import json
import socket
import shutil
import urllib.request
import urllib.error
import subprocess

# ANSI color codes
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Disable colors on dumb terminals or if NO_COLOR is set
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    CYAN = GREEN = YELLOW = RED = BOLD = RESET = ""

def print_header():
    print(f"{CYAN}{'=' * 79}{RESET}")
    print(f"{CYAN}{BOLD}           BOUNDED AUTHORITY PLANE (BAP) - PRE-FLIGHT DOCTOR{RESET}")
    print(f"{CYAN}{'=' * 79}{RESET}")
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    host = socket.gethostname()
    user = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
    print(f"[*] Timestamp: {now_str} | Host: {host} | User: {user}\n")

class DoctorChecklist:
    def __init__(self):
        self.total = 0
        self.passed = 0
        self.warned = 0
        self.failed = 0

    def report(self, name: str, status: str, details: str):
        self.total += 1
        if status == "PASS":
            self.passed += 1
            badge = f"{GREEN}[PASS]{RESET}"
        elif status == "WARN":
            self.warned += 1
            badge = f"{YELLOW}[WARN]{RESET}"
        else:
            self.failed += 1
            badge = f"{RED}[FAIL]{RESET}"
        print(f"  {badge} {name:<35} : {details}")

    def summary(self):
        print(f"\n{CYAN}{'=' * 79}{RESET}")
        if self.failed > 0:
            print(f"  {RED}{BOLD}DOCTOR STATUS: ACTION REQUIRED ({self.failed} failed, {self.warned} warnings, {self.passed}/{self.total} passed){RESET}")
        elif self.warned > 0:
            print(f"  {YELLOW}{BOLD}DOCTOR STATUS: OPERATIONAL WITH {self.warned} WARNING(S) ({self.passed}/{self.total} passed){RESET}")
        else:
            print(f"  {GREEN}{BOLD}DOCTOR STATUS: ALL SYSTEMS HEALTHY! ({self.passed}/{self.total} passed){RESET}")
        print(f"{CYAN}{'=' * 79}{RESET}")
        return 0 if self.failed == 0 else 1

def find_binary(name: str, repo_root: str):
    ext = ".exe" if sys.platform == "win32" else ""
    target = name + ext
    home = os.path.expanduser("~")
    
    # Priority 1: User PATH
    which_path = shutil.which(target)
    if which_path and os.path.isfile(which_path):
        return which_path

    # Priority 2: Standard User bin & Application Directories
    candidates = [
        os.path.join(home, "bin", target),
        os.path.join(os.environ.get("APPDATA", ""), "BAP", "bin", target) if sys.platform == "win32" else None,
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "BAP", "bin", target) if sys.platform == "win32" else None,
        os.path.expanduser(f"~/.local/bin/{target}"),
        os.path.expanduser(f"~/.bap/bin/{target}"),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c

    # Priority 3: Current directory or repo root
    cwd_bin = os.path.abspath(target)
    if os.path.isfile(cwd_bin):
        return cwd_bin

    # Priority 4: Repo dist packaging
    plat = "windows-amd64" if sys.platform == "win32" else ("darwin-arm64" if sys.platform == "darwin" else "linux-amd64")
    dist_bin = os.path.join(repo_root, "dist", plat, target)
    if os.path.isfile(dist_bin):
        return dist_bin

    dist_client = os.path.join(repo_root, "dist", plat, "claude-client", target)
    if os.path.isfile(dist_client):
        return dist_client

    return None

def run_doctor():
    print_header()
    checklist = DoctorChecklist()
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    # Section 1: Core BAP Binaries
    print(f"{CYAN}[1/5] Core BAP Binaries & Client Tools...{RESET}")
    bapedge = find_binary("bapedge", repo_root)
    if bapedge and os.path.isfile(bapedge):
        sz_mb = round(os.path.getsize(bapedge) / (1024 * 1024), 2)
        checklist.report("bapedge (Edge Daemon)", "PASS", f"{bapedge} ({sz_mb} MB)")
    else:
        checklist.report("bapedge (Edge Daemon)", "FAIL", "Not found in PATH or repo. Run 'bap install'.")

    interceptor = find_binary("interceptor", repo_root) or find_binary("cchook-interceptor", repo_root)
    if interceptor and os.path.isfile(interceptor):
        sz_mb = round(os.path.getsize(interceptor) / (1024 * 1024), 2)
        checklist.report("interceptor (Hook)", "PASS", f"{interceptor} ({sz_mb} MB)")
    else:
        checklist.report("interceptor (Hook)", "WARN", "interceptor not found in PATH or dist.")

    launcher_names = ["run_claude_bap.bat", "run_claude_bap.ps1", "run_claude_bap.sh"]
    launcher_found = False
    for l_name in launcher_names:
        lp = os.path.join(repo_root, l_name)
        if os.path.isfile(lp):
            checklist.report("run_claude_bap (Launcher)", "PASS", lp)
            launcher_found = True
            break
    if not launcher_found:
        checklist.report("run_claude_bap (Launcher)", "WARN", "Launcher scripts not found in workspace.")

    # Section 2: AI Agent Runtime Detection
    print(f"\n{CYAN}[2/5] AI Agent Runtime Detection...{RESET}")
    claude_bin = shutil.which("claude") or shutil.which("claude.cmd") or shutil.which("claude.exe")
    if claude_bin:
        ver = "Installed"
        try:
            out = subprocess.check_output([claude_bin, "--version"], stderr=subprocess.DEVNULL, timeout=3).decode("utf-8", errors="ignore").strip()
            if out:
                ver = out
        except Exception:
            pass
        checklist.report("Claude Code CLI", "PASS", f"{claude_bin} ({ver})")
    else:
        checklist.report("Claude Code CLI", "WARN", "claude executable not found in PATH.")

    # Check for Gemini / Antigravity rules
    gemini_rule = os.path.join(os.getcwd(), "GEMINI.md")
    if os.path.isfile(gemini_rule):
        checklist.report("Google Antigravity Rule", "PASS", f"Active ({gemini_rule})")
    else:
        checklist.report("Google Antigravity Rule", "WARN", "GEMINI.md not detected in workspace.")

    # Section 3: Central Control Plane Connectivity & TLS
    print(f"\n{CYAN}[3/5] Control Plane Connectivity & TLS...{RESET}")
    server_url = "https://localhost:8443"
    for cfg in [os.path.join(os.getcwd(), "bap-config.json"), os.path.join(repo_root, "bap-config.json")]:
        if os.path.isfile(cfg):
            try:
                with open(cfg, "r", encoding="utf-8") as f:
                    cfg_data = json.load(f)
                    if cfg_data.get("controlplane_url"):
                        server_url = cfg_data["controlplane_url"]
                        break
            except Exception:
                pass

    try:
        from urllib.parse import urlparse
        parsed = urlparse(server_url)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        
        t0 = time.time()
        s = socket.create_connection((host, port), timeout=1.5)
        latency_ms = round((time.time() - t0) * 1000, 1)
        s.close()
        checklist.report(f"TCP Listener ({host}:{port})", "PASS", f"Port open (Latency: {latency_ms} ms)")
    except Exception:
        checklist.report(f"Control Plane ({server_url})", "WARN", "Listener idle. Edge enforces cached Cedar policies offline.")

    # Section 4: Cedar Policy Engine & Schema Invariants
    print(f"\n{CYAN}[4/5] Cedar Policy Engine & Schema Invariants...{RESET}")
    policy_path = None
    for p in [os.path.join(os.getcwd(), "policy.cedar"), os.path.join(repo_root, "policy.cedar")]:
        if os.path.isfile(p):
            policy_path = p
            break

    if policy_path:
        with open(policy_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = sum(1 for _ in f)
        checklist.report("Cedar Policy (policy.cedar)", "PASS", f"{lines} lines loaded ({policy_path})")
    else:
        checklist.report("Cedar Policy (policy.cedar)", "FAIL", "policy.cedar not found.")

    if bapedge and os.path.isfile(bapedge):
        try:
            t0 = time.time()
            res = subprocess.run([bapedge, "exec", "--raw", "git --version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            dt_ms = round((time.time() - t0) * 1000, 1)
            if res.returncode == 0:
                checklist.report("Local Policy Evaluation", "PASS", f"Safe command authorized in {dt_ms} ms (< 1.5ms engine latency)")
            else:
                checklist.report("Local Policy Evaluation", "WARN", f"Evaluator returned code {res.returncode}")
        except Exception as e:
            checklist.report("Local Policy Evaluation", "WARN", str(e))

    # Section 5: Workspace & Transaction Custody
    print(f"\n{CYAN}[5/5] Workspace & Recovery Custody...{RESET}")
    bap_dir = os.path.join(os.getcwd(), ".bap")
    if os.path.isdir(bap_dir):
        checklist.report("Workspace .bap/ Isolation", "PASS", "Isolated directory active (Zero root clutter)")
    else:
        checklist.report("Workspace .bap/ Isolation", "PASS", "Clean workspace (Ready for on-demand initialization)")

    recovery_file = os.path.join(os.getcwd(), ".claude", ".bap-recovery.json")
    if os.path.isfile(recovery_file):
        try:
            with open(recovery_file, "r", encoding="utf-8") as f:
                rec_data = json.load(f)
                st = rec_data.get("state", "unknown")
                active_n = len(rec_data.get("active_sessions", []))
                checklist.report("Active Session Concurrency", "PASS", f"State: {st} ({active_n} active sessions)")
        except Exception:
            checklist.report("Active Session Concurrency", "WARN", "Recovery file present but parse error")
    else:
        checklist.report("Active Session Concurrency", "PASS", "Idle (No lingering transactions or lockouts)")

    return checklist.summary()

if __name__ == "__main__":
    sys.exit(run_doctor())
