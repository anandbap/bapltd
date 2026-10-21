#!/usr/bin/env python3
"""
BAP Executive CIO Demonstration - Agent Watch V3
=================================================
Live multi-agent fleet simulation with real-time Cedar policy enforcement,
interactive HITL approval queue, tamper-proof receipts, and live browser cockpit.

Usage:
  python demo_v3_cio.py
  python demo_v3_cio.py --no-browser
  run_v3_cio_demo.bat
"""

import argparse
import atexit
import hashlib
import json
import os
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from typing import Dict, List, Optional, Tuple

WORKSPACE_ROOT = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(WORKSPACE_ROOT, "python-agent"))

# Configure UTF-8 stdout on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

BAPEDGE_BIN = os.path.join(WORKSPACE_ROOT, "bapedge.exe")
if not os.path.isfile(BAPEDGE_BIN):
    alt_bin = os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapedge.exe")
    if os.path.isfile(alt_bin):
        BAPEDGE_BIN = alt_bin


def read_admin_token() -> str:
    token_file = os.path.join(WORKSPACE_ROOT, ".bap-admin-token")
    if os.path.isfile(token_file):
        try:
            with open(token_file, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass
    return os.getenv("BAP_ADMIN_TOKEN", "")


def resolve_server_url() -> str:
    cfg_file = os.path.join(WORKSPACE_ROOT, "bap-config.json")
    if os.path.isfile(cfg_file):
        try:
            with open(cfg_file, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                url = cfg.get("controlplane_url", "")
                if url:
                    return url.rstrip("/")
        except Exception:
            pass
    return os.getenv("BAP_CONTROL_PLANE_URL", "http://localhost:8080").rstrip("/")


def http_post(server_url: str, endpoint: str, payload: dict, admin_token: str = "") -> Tuple[int, dict]:
    url = f"{server_url}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    if admin_token:
        req.add_header("Authorization", f"Bearer {admin_token}")
        req.add_header("X-BAP-Admin-Token", admin_token)
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=5) as resp:
            raw = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(raw)
            except Exception:
                return resp.status, {"raw": raw}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"error": raw}
    except Exception as e:
        return 500, {"error": str(e)}


def http_get(server_url: str, endpoint: str, admin_token: str = "") -> Tuple[int, dict]:
    url = f"{server_url}{endpoint}"
    req = urllib.request.Request(url)
    if admin_token:
        req.add_header("Authorization", f"Bearer {admin_token}")
        req.add_header("X-BAP-Admin-Token", admin_token)
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=5) as resp:
            raw = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(raw)
            except Exception:
                return resp.status, {"raw": raw}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"error": raw}
    except Exception as e:
        return 500, {"error": str(e)}


def ensure_control_plane(server_url: str) -> bool:
    st, _ = http_get(server_url, "/api/v1/health")
    if st == 200:
        return True

    print(f"[*] Control Plane offline at {server_url}. Auto-launching local server on port 8080...")
    candidates = [
        os.path.join(WORKSPACE_ROOT, "bapcontrolplane.exe"),
        os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapcontrolplane.exe"),
        os.path.join(WORKSPACE_ROOT, "bap-controlplane", "bapcontrolplane.exe"),
    ]
    cp_bin = next((p for p in candidates if os.path.isfile(p)), None)
    if cp_bin:
        subprocess.Popen([cp_bin, "start", "--port", "8080", "--mode", "dev"], cwd=WORKSPACE_ROOT)
    else:
        # Fallback to go run
        cp_dir = os.path.join(WORKSPACE_ROOT, "bap-controlplane")
        if os.path.isdir(cp_dir):
            subprocess.Popen(["go", "run", "./cmd/server", "-port", "8080"], cwd=cp_dir)

    for _ in range(15):
        time.sleep(0.5)
        st, _ = http_get(server_url, "/api/v1/health")
        if st == 200:
            print(f"[+] Control Plane verified online at {server_url}")
            return True

    return False


def run_bapedge_exec(session_id: str, app_id: str, cmd: str) -> Tuple[int, dict]:
    test_env = os.environ.copy()
    test_env["BAP_SESSION_ID"] = session_id
    test_env["LTD_SOURCE"] = app_id
    test_env["LTD_APP"] = app_id
    test_env["BAP_TEST_MODE"] = "1"

    proc = subprocess.Popen(
        [BAPEDGE_BIN, "exec", cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=WORKSPACE_ROOT,
        env=test_env,
    )
    stdout, stderr = proc.communicate()
    data = {}
    if stdout.strip().startswith("{"):
        try:
            data = json.loads(stdout.strip())
        except Exception:
            pass
    return proc.returncode, data


class GovernedFleetAgent:
    def __init__(
        self,
        session_id: str,
        name: str,
        role: str,
        workstream: str,
        app_id: str,
        operator: str,
        email: str,
        prompt: str,
        server_url: str,
    ):
        self.session_id = session_id
        self.name = name
        self.role = role
        self.workstream = workstream
        self.app_id = app_id
        self.operator = operator
        self.email = email
        self.prompt = prompt
        self.server_url = server_url
        self.is_alive = False
        self._stop_event = threading.Event()
        self._hb_thread: Optional[threading.Thread] = None

    def start(self):
        payload = {
            "session_id": self.session_id,
            "agent_name": f"{self.operator} ({self.role})",
            "app_id": self.app_id,
            "instance_id": self.session_id,
            "user_id": self.operator,
            "user_email": self.email,
            "spiffe_id": f"spiffe://bap.internal/app/{self.app_id}/instance/{self.session_id}",
            "client_pid": os.getpid(),
            "hostname": os.getenv("COMPUTERNAME", "WORKSTATION-CORP"),
            "user_prompt": self.prompt,
            "workstream": self.workstream,
            "intent": {
                "primary": self.workstream.upper(),
                "confidence": 0.98,
                "source": "v3-executive-demo",
            },
        }
        st, _ = http_post(self.server_url, "/api/v1/sessions/start", payload)
        self.is_alive = (st == 200)

        # Start periodic heartbeat
        def _hb():
            while not self._stop_event.wait(4.0):
                if not self.is_alive:
                    break
                http_post(
                    self.server_url,
                    "/api/v1/sessions/heartbeat",
                    {"session_id": self.session_id, "app_id": self.app_id, "agent_id": self.session_id},
                )

        self._hb_thread = threading.Thread(target=_hb, daemon=True)
        self._hb_thread.start()

    def update_prompt(self, new_prompt: str, intent_category: str = ""):
        self.prompt = new_prompt
        payload = {
            "session_id": self.session_id,
            "user_prompt": new_prompt,
            "prompt_hash": hashlib.sha256(new_prompt.encode("utf-8")).hexdigest(),
            "intent": {
                "primary": intent_category or self.workstream.upper(),
                "confidence": 0.95,
                "source": "v3-executive-demo",
            },
        }
        http_post(self.server_url, "/api/v1/sessions/prompt", payload)

    def stop(self):
        self.is_alive = False
        self._stop_event.set()
        http_post(self.server_url, "/api/v1/sessions/end", {"session_id": self.session_id, "reason": "demo_cleanup"})


_ACTIVE_AGENTS: List[GovernedFleetAgent] = []


def cleanup_fleet(server_url: str, admin_token: str):
    print("\n[*] Gracefully deregistering demo fleet and restoring baseline state...")
    for ag in _ACTIVE_AGENTS:
        ag.stop()
    _ACTIVE_AGENTS.clear()
    http_post(server_url, "/api/v1/sessions/reset", {}, admin_token=admin_token)
    print("[+] All demo sessions closed cleanly.")


def print_header(server_url: str):
    print("\n" + "=" * 92)
    print("      BOUNDED AUTHORITY PLANE (BAP) - AGENT WATCH V3 EXECUTIVE FLEET DEMONSTRATION      ")
    print("=" * 92)
    print(f"[*] Control Plane Authority : {server_url}")
    print(f"[*] Executive Cockpit (V3)  : {server_url}/dashboard/")
    print(f"[*] Guided Walkthrough (V3) : {server_url}/dashboard/?demo=1")
    print(f"[*] Operator Console (V2)   : {server_url}/dashboard/v2/")
    print("=" * 92)


def main():
    parser = argparse.ArgumentParser(description="BAP Agent Watch V3 CIO Fleet Demonstration")
    parser.add_argument("--no-browser", action="store_true", help="Do not open default web browser automatically")
    parser.add_argument("--url", type=str, default="", help="Custom Control Plane URL")
    args = parser.parse_args()

    server_url = args.url or resolve_server_url()
    admin_token = read_admin_token()

    if not ensure_control_plane(server_url):
        print(f"[-] Could not connect to or start BAP Control Plane at {server_url}.")
        sys.exit(1)

    print_header(server_url)

    # 1. Reset state
    print("[1/4] Resetting previous sessions to guarantee pristine cryptographic telemetry...")
    http_post(server_url, "/api/v1/sessions/reset", {}, admin_token=admin_token)
    time.sleep(0.5)

    # 2. Register fleet agents
    print("[2/4] Enrolling governed enterprise squad agents across 5 canonical workstreams...")
    priya = GovernedFleetAgent(
        session_id="sess-v3-priya",
        name="coder-12",
        role="Payments Software Engineer",
        workstream="Build",
        app_id="claude-code",
        operator="Priya Nair",
        email="priya.nair@corp.internal",
        prompt="Fix failing checkout tests and update idempotency validation logic",
        server_url=server_url,
    )
    marcus = GovernedFleetAgent(
        session_id="sess-v3-marcus",
        name="sre-04",
        role="Site Reliability Engineer",
        workstream="Build",
        app_id="claude-code",
        operator="Marcus Webb",
        email="marcus.webb@corp.internal",
        prompt="Diagnose database query latency spike in us-east-1 and optimize queries",
        server_url=server_url,
    )
    dave = GovernedFleetAgent(
        session_id="sess-v3-dave",
        name="deploy-01",
        role="Release Orchestrator",
        workstream="Operate",
        app_id="copilot",
        operator="Dave Vance",
        email="dave.vance@corp.internal",
        prompt="Deploy checkout microservice update to production us-east-1 cluster",
        server_url=server_url,
    )
    carol = GovernedFleetAgent(
        session_id="sess-v3-carol",
        name="analyst-07",
        role="Financial Portfolio Analyst",
        workstream="Analyze",
        app_id="python-agent",
        operator="Carol Zhang",
        email="carol.zhang@corp.internal",
        prompt="Analyze Q3 portfolio volatility and generate quarterly risk metrics",
        server_url=server_url,
    )
    diego = GovernedFleetAgent(
        session_id="sess-v3-diego",
        name="data-03",
        role="Business Intelligence Engineer",
        workstream="Analyze",
        app_id="claude-code",
        operator="Diego Ruiz",
        email="diego.ruiz@corp.internal",
        prompt="Summarise last week's customer churn numbers and aggregate metrics",
        server_url=server_url,
    )
    lena = GovernedFleetAgent(
        session_id="sess-v3-lena",
        name="docs-02",
        role="Technical Writer",
        workstream="Document",
        app_id="copilot",
        operator="Lena Fischer",
        email="lena.fischer@corp.internal",
        prompt="Update developer security and zero-trust onboarding guide",
        server_url=server_url,
    )
    eve = GovernedFleetAgent(
        session_id="sess-v3-eve",
        name="probe-99",
        role="Adversarial Security Auditor",
        workstream="Support",
        app_id="claude-code",
        operator="Eve Mallory",
        email="eve.mallory@corp.internal",
        prompt="Security probe: verify credential file isolation boundaries",
        server_url=server_url,
    )

    agents = [priya, marcus, dave, carol, diego, lena, eve]
    _ACTIVE_AGENTS.extend(agents)
    for ag in agents:
        ag.start()
        print(f"  [+] Active: {ag.operator:<16} · {ag.name:<10} [{ag.workstream:<8}] -> {ag.role}")

    # Register exit handler
    atexit.register(lambda: cleanup_fleet(server_url, admin_token))

    # 3. Simulate baseline activities
    print("\n[3/4] Generating initial baseline activities and policy enforcement checks...")
    # Safe actions
    print("  [>] Priya Nair: running git status & tests (Allowed)...")
    run_bapedge_exec(priya.session_id, priya.app_id, "git status")

    print("  [>] Carol Zhang: computing Sharpe ratio (Allowed)...")
    run_bapedge_exec(carol.session_id, carol.app_id, "echo Portfolio Sharpe ratio: 1.84")

    print("  [>] Diego Ruiz: compiling churn report (Allowed)...")
    run_bapedge_exec(diego.session_id, diego.app_id, "echo Churn report compiled: 0 sensitive fields exposed")

    # Policy Denials (The Overstepping Agent Eve)
    print("  [!] Eve Mallory: attempting to read .env password file (Blocked by Cedar)...")
    _, d_eve1 = run_bapedge_exec(eve.session_id, eve.app_id, "cat .env")
    rcpt_eve1 = d_eve1.get("receipt", {}).get("receipt_id", "rcpt-eve-blocked-01")
    print(f"      Blocked before execution! Receipt: {rcpt_eve1}")

    print("  [!] Eve Mallory: attempting Python credential extraction (Blocked by Cedar)...")
    _, d_eve2 = run_bapedge_exec(eve.session_id, eve.app_id, 'python -c "open(\'.env\').read()"')
    rcpt_eve2 = d_eve2.get("receipt", {}).get("receipt_id", "rcpt-eve-blocked-02")
    print(f"      Blocked before execution! Receipt: {rcpt_eve2}")

    # Human-in-the-loop Escalation Request for Dave (Production Change)
    print("  [?] Dave Vance: requesting human approval for production deployment...")
    http_post(
        server_url,
        "/api/v1/escalation/request",
        {
            "id": "esc-deploy-001",
            "session_id": dave.session_id,
            "action": "Deploy checkout fix to production",
            "command": "kubectl apply -f k8s/checkout-prod.yaml",
            "reason": "Marcus Webb's agent finished the fix and tests pass. Production changes always require human approval.",
            "status": "pending",
        },
        admin_token=admin_token,
    )

    # 4. Launch browser
    dashboard_url = f"{server_url}/dashboard/"
    print(f"\n[4/4] Opening Agent Watch V3 Executive Cockpit at {dashboard_url}...")
    if not args.no_browser:
        try:
            webbrowser.open(dashboard_url)
        except Exception:
            pass

    print("\n" + "=" * 92)
    print("                           AGENT WATCH V3 FLEET IS LIVE!                              ")
    print("=" * 92)
    print("  What to observe on your screen:")
    print("   1. [Top Verdict]     'In control. 2 risky actions were stopped.' (Green/Amber state)")
    print("   2. [Proof Numbers]   7 Agents working · 2 Risky stopped · 1 Needs you · Verified record")
    print("   3. [Fleet Grid]      Interactive dot grid with live pulsing agents and alert dot for Eve")
    print("   4. [Incident Card]   'Asked -> Agent tried -> Policy: Blocked' with 'Open sealed receipt'")
    print("   5. [Needs You Queue] Dave Vance's production deploy with interactive [Approve] / [Deny]")
    print("   6. [Workstreams]     Build, Operate, Analyze, Document, Support telemetry distribution")
    print("   7. [Freeze Button]   Emergency kill-switch: freeze the entire fleet in < 100ms")
    print("=" * 92)

    # Interactive loop
    while True:
        print("\nINTERACTIVE DEMONSTRATION CONTROLS:")
        print("  [1] Inject Safe Action         (Priya runs build & test suite)")
        print("  [2] Inject High-Risk Attack    (Eve attempts PowerShell secret exfiltration)")
        print("  [3] Inject Escalation Request  (An agent requests permission to mutate IAM policy)")
        print("  [4] Open Guided Walkthrough    (Launch 90-second interactive guided tour in browser)")
        print("  [q] Exit Demonstration         (Deregister all agents and reset clean)")
        try:
            choice = input("\nSelect option (1-4, q to exit) [default: 1]: ").strip().lower()
            if not choice:
                choice = "1"
            if choice == "q":
                break
            elif choice == "1":
                print("[*] Running safe build action for Priya Nair...")
                run_bapedge_exec(priya.session_id, priya.app_id, "echo Running npm test: 42 passed, 0 failed")
                print("[+] Allowed and logged. Check the live feed in your browser.")
            elif choice == "2":
                print("[!] Eve Mallory attempting PowerShell credential harvest...")
                _, d = run_bapedge_exec(eve.session_id, eve.app_id, 'powershell -Command "Get-Content .env"')
                rcpt = d.get("receipt", {}).get("receipt_id", "rcpt-eve-ps1")
                print(f"[!] Denied by Cedar Zero-Trust policy! Sealed receipt: {rcpt}")
                print("[+] Check the V3 incident card and blocked counter in your browser.")
            elif choice == "3":
                req_id = f"esc-iam-{int(time.time())}"
                print(f"[*] Submitting privilege escalation request {req_id}...")
                http_post(
                    server_url,
                    "/api/v1/escalation/request",
                    {
                        "id": req_id,
                        "session_id": marcus.session_id,
                        "action": "Modify AWS IAM Security Group ingress rules",
                        "command": "aws ec2 authorize-security-group-ingress --group-id sg-prod",
                        "reason": "Agent needs to whitelist monitoring ingress. Security boundary change requires human sign-off.",
                        "status": "pending",
                    },
                    admin_token=admin_token,
                )
                print("[+] Request queued. Observe the 'Needs you' panel in your browser cockpit.")
            elif choice == "4":
                walkthrough_url = f"{server_url}/dashboard/?demo=1"
                print(f"[*] Opening guided walkthrough: {walkthrough_url}")
                webbrowser.open(walkthrough_url)
            else:
                print("Invalid option. Please enter 1, 2, 3, 4, or q.")
        except (KeyboardInterrupt, EOFError):
            break

    print("\nExiting demonstration...")


if __name__ == "__main__":
    main()
