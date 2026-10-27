#!/usr/bin/env python3
"""
BAP Executive CIO Demonstration - Agent Watch V3
=================================================
Live multi-agent fleet simulation with real-time Cedar policy enforcement,
interactive HITL approval queue, tamper-proof receipts, and live browser cockpit.
Supports both local and remote (Render cloud) Control Planes seamlessly.

Usage:
  python demo_v3_cio.py                  # Auto-resolves (remote if configured, or local)
  python demo_v3_cio.py --remote         # Force remote Render control plane
  python demo_v3_cio.py --local          # Force local control plane (auto-launches if offline)
  python demo_v3_cio.py --url <URL>      # Custom control plane URL
  python demo_v3_cio.py --no-browser     # Headless execution
  run_v3_cio_demo.bat                    # Windows launcher
  run_remote_cio_demo.bat                # Windows remote launcher
"""

import argparse
import atexit
import hashlib
import json
import os
import random
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
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

DEFAULT_REMOTE_URL = "https://bap-controlplane.onrender.com"

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


def is_remote_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    hostname = (parsed.hostname or "").lower()
    return hostname not in ("127.0.0.1", "localhost", "::1", "", None)


def resolve_server_url(prefer_remote: bool = False, force_local: bool = False) -> str:
    if force_local:
        return "http://localhost:8080"

    env_url = os.getenv("BAP_CONTROL_PLANE_URL") or os.getenv("BAP_SERVER_URL")
    if env_url:
        return env_url.rstrip("/")

    # Check bap-config.json for configured control plane
    cfg_file = os.path.join(WORKSPACE_ROOT, "bap-config.json")
    cfg_url = ""
    if os.path.isfile(cfg_file):
        try:
            with open(cfg_file, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                cfg_url = cfg.get("controlplane_url", "").rstrip("/")
        except Exception:
            pass

    if prefer_remote:
        return cfg_url or DEFAULT_REMOTE_URL

    # If config points to a remote host (e.g. Render), prefer it by default
    if cfg_url and is_remote_url(cfg_url):
        return cfg_url

    # Check if a control plane is already healthy on common local ports
    for probe_url in ["http://127.0.0.1:8080", "http://localhost:8080", "https://localhost:8443"]:
        st, _ = http_get(probe_url, "/api/v1/health", timeout=2.0)
        if st == 200:
            return probe_url

    if cfg_url:
        return cfg_url

    return DEFAULT_REMOTE_URL


def http_post(server_url: str, endpoint: str, payload: dict, admin_token: str = "", timeout: float = 12.0) -> Tuple[int, dict]:
    url = f"{server_url}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    if admin_token:
        req.add_header("Authorization", f"Bearer {admin_token}")
        req.add_header("X-BAP-Admin-Token", admin_token)
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=timeout) as resp:
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


def http_get(server_url: str, endpoint: str, admin_token: str = "", timeout: float = 8.0) -> Tuple[int, dict]:
    url = f"{server_url}{endpoint}"
    req = urllib.request.Request(url)
    if admin_token:
        req.add_header("Authorization", f"Bearer {admin_token}")
        req.add_header("X-BAP-Admin-Token", admin_token)
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=timeout) as resp:
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


def ensure_control_plane(server_url: str) -> Tuple[bool, str]:
    if is_remote_url(server_url):
        print(f"[*] Connecting to remote BAP Control Plane at {server_url}...")
        start_time = time.time()
        max_wait = 40.0
        attempt = 0
        while time.time() - start_time < max_wait:
            attempt += 1
            st, _ = http_get(server_url, "/health", timeout=8.0)
            if st == 200:
                print(f"[+] Remote BAP Control Plane online and responsive at {server_url}")
                return True, server_url
            st2, _ = http_get(server_url, "/api/v1/health", timeout=8.0)
            if st2 == 200:
                print(f"[+] Remote BAP Control Plane online and responsive at {server_url}")
                return True, server_url
            if attempt == 1:
                print("    Waking up remote server on Render (cold start ~15-25s)...")
            time.sleep(2.0)

        print(f"[-] Could not connect to remote BAP Control Plane at {server_url} (timed out after 40s).")
        return False, server_url

    # Local control plane handling
    st, _ = http_get(server_url, "/api/v1/health", timeout=2.0)
    if st == 200:
        return True, server_url

    parsed = urllib.parse.urlparse(server_url)
    target_port = parsed.port or (8443 if parsed.scheme == "https" else 8080)

    if target_port == 8443 and parsed.scheme == "https":
        server_url = "http://localhost:8080"
        target_port = 8080

    print(f"[*] Local Control Plane offline. Auto-launching local server on port {target_port} ({server_url})...")
    candidates = [
        os.path.join(WORKSPACE_ROOT, "bapcontrolplane.exe"),
        os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapcontrolplane.exe"),
        os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "controlplane", "bapcontrolplane.exe"),
        os.path.join(WORKSPACE_ROOT, "bap-controlplane", "bapcontrolplane.exe"),
    ]
    cp_bin = next((p for p in candidates if os.path.isfile(p)), None)

    cmd = []
    if cp_bin:
        cmd = [cp_bin, "start", "-port", str(target_port), "-mode", "dev"]
    else:
        cp_dir = os.path.join(WORKSPACE_ROOT, "bap-controlplane")
        if os.path.isdir(cp_dir):
            cmd = ["go", "run", "./cmd/server", "start", "-port", str(target_port), "-mode", "dev"]

    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000008  # DETACHED_PROCESS

    if cmd:
        subprocess.Popen(
            cmd,
            cwd=WORKSPACE_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            creationflags=creationflags,
        )

    for _ in range(25):
        time.sleep(0.4)
        st, _ = http_get(server_url, "/api/v1/health", timeout=2.0)
        if st == 200:
            print(f"[+] Control Plane verified online at {server_url}")
            return True, server_url

    return False, server_url


def run_bapedge_exec(server_url: str, session_id: str, app_id: str, cmd: str) -> Tuple[int, dict]:
    if not os.path.isfile(BAPEDGE_BIN):
        return 0, {}

    test_env = os.environ.copy()
    test_env["BAP_SESSION_ID"] = session_id
    test_env["LTD_SOURCE"] = app_id
    test_env["LTD_APP"] = app_id
    test_env["BAP_CONTROL_PLANE_URL"] = server_url
    test_env["BAP_SERVER_URL"] = server_url
    test_env.pop("BAP_TEST_MODE", None)
    test_env.pop("LTD_TEST", None)

    try:
        proc = subprocess.Popen(
            [BAPEDGE_BIN, "exec", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=WORKSPACE_ROOT,
            env=test_env,
        )
        stdout, stderr = proc.communicate(timeout=6.0)
        data = {}
        if stdout.strip().startswith("{"):
            try:
                data = json.loads(stdout.strip())
            except Exception:
                pass
        return proc.returncode, data
    except Exception:
        return 0, {}


class GovernedFleetAgent:
    def __init__(
        self,
        session_id: str,
        name: str,
        role: str,
        workstream: str,
        business_unit: str,
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
        self.business_unit = business_unit
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
                "source": "bap-agent-sdk",
            },
        }
        st, _ = http_post(self.server_url, "/api/v1/sessions/start", payload)
        self.is_alive = (st in (200, 201))

        # Register initial active status on the activity feed
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        http_post(
            self.server_url,
            "/api/activity/ingest",
            {
                "timestamp": now_iso,
                "session_id": self.session_id,
                "agent_id": self.session_id,
                "agent_type": self.role,
                "user_id": self.operator,
                "business_unit": self.business_unit,
                "application": self.app_id,
                "prompt_summary": self.prompt,
                "intent": self.workstream,
                "intent_category": self.workstream,
                "action": f"Started task: {self.prompt[:48]}",
                "tool": "workspace",
                "target_resource": "codebase",
                "data_classification": "Internal",
                "policy_decision": "ALLOW",
                "risk_score": 0.10,
                "action_status": "working",
                "outcome_category": "Success",
                "trace_id": f"tr-{self.session_id}-{int(time.time()*1000)%1000000}",
                "deviation_level": "NONE",
            },
        )

        # Start periodic heartbeat to keep agent active on dashboard
        def _hb():
            while not self._stop_event.wait(3.0):
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
                "source": "bap-agent-sdk",
            },
        }
        http_post(self.server_url, "/api/v1/sessions/prompt", payload)

    def stop(self):
        self.is_alive = False
        self._stop_event.set()
        http_post(self.server_url, "/api/v1/sessions/end", {"session_id": self.session_id, "reason": "demo_cleanup"})


_ACTIVE_AGENTS: List[GovernedFleetAgent] = []


def emit_action_event(
    server_url: str,
    agent: GovernedFleetAgent,
    executable: str,
    full_command: str,
    decision: str,  # "allow" or "deny"
    reason: str,
    action_status: str = "working",  # "working" or "denied"
    outcome_category: str = "Success",  # "Success" or "Blocked"
    risk_score: float = 0.10,
    deviation_level: str = "NONE",
) -> Tuple[int, dict]:
    # 1. Run local bapedge broker for realistic local enforcement & receipts
    _, broker_data = run_bapedge_exec(server_url, agent.session_id, agent.app_id, full_command)
    receipt_id = (
        broker_data.get("receipt", {}).get("receipt_id")
        or f"rcpt-{agent.name}-{int(time.time()*1000)%1000000}"
    )

    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    trace_id = f"tr-{agent.name}-{int(time.time()*1000)%1000000}"

    # 2. Ingest to Merkle audit chain
    audit_event = {
        "event_id": f"evt-{agent.name}-{int(time.time()*1000)%1000000}",
        "session_id": agent.session_id,
        "agent_id": agent.session_id,
        "user_id": agent.operator,
        "user_email": agent.email,
        "spiffe_id": f"spiffe://bap.internal/app/{agent.app_id}/instance/{agent.session_id}",
        "source": agent.app_id,
        "executable": executable,
        "full_command": full_command,
        "decision": decision,
        "reason": reason,
        "user_prompt": agent.prompt,
        "primary_intent": agent.workstream,
        "duration_ms": random.randint(4, 28),
        "exit_code": 403 if decision == "deny" else 0,
        "timestamp": now_iso,
    }
    http_post(server_url, "/api/v1/audit/ingest", audit_event)

    # 3. Ingest to Live Activity stream for immediate UI reflection
    activity_event = {
        "timestamp": now_iso,
        "session_id": agent.session_id,
        "agent_id": agent.session_id,
        "agent_type": agent.role,
        "user_id": agent.operator,
        "business_unit": agent.business_unit,
        "application": agent.app_id,
        "prompt_summary": agent.prompt,
        "intent": agent.workstream,
        "intent_category": agent.workstream,
        "action": full_command,
        "tool": executable,
        "target_resource": ".env" if ".env" in full_command else "codebase",
        "data_classification": "Restricted" if decision == "deny" else "Internal",
        "policy_decision": "DENY" if decision == "deny" else "ALLOW",
        "risk_score": risk_score,
        "action_status": action_status,
        "outcome_category": outcome_category,
        "trace_id": trace_id,
        "deviation_level": deviation_level,
        "deviation_reason": reason if decision == "deny" else "",
    }
    http_post(server_url, "/api/activity/ingest", activity_event)

    return 0, {"receipt_id": receipt_id, "trace_id": trace_id}


def cleanup_fleet(server_url: str, admin_token: str):
    print("\n[*] Gracefully deregistering demo fleet and restoring baseline state...")
    for ag in _ACTIVE_AGENTS:
        ag.stop()
    _ACTIVE_AGENTS.clear()
    http_post(server_url, "/api/v1/sessions/reset", {}, admin_token=admin_token)
    print("[+] All demo sessions closed cleanly.")


def print_header(server_url: str):
    is_cloud = is_remote_url(server_url)
    mode_label = "REMOTE RENDER CLOUD" if is_cloud else "LOCAL EMBEDDED"
    print("\n" + "=" * 94)
    print(f"      BOUNDED AUTHORITY PLANE (BAP) - AGENT WATCH V3 EXECUTIVE FLEET DEMONSTRATION      ")
    print("=" * 94)
    print(f"[*] Control Plane Target    : {server_url} ({mode_label})")
    print(f"[*] Executive Cockpit (V3)  : {server_url}/dashboard/")
    print(f"[*] Guided Walkthrough (V3) : {server_url}/dashboard/?demo=1")
    print(f"[*] Operator Console (V2)   : {server_url}/dashboard/v2/")
    print("=" * 94)


def main():
    parser = argparse.ArgumentParser(description="BAP Agent Watch V3 CIO Fleet Demonstration")
    parser.add_argument("--remote", "-r", action="store_true", help="Connect to the remote Render control plane")
    parser.add_argument("--local", "-l", action="store_true", help="Force local embedded control plane")
    parser.add_argument("--url", type=str, default="", help="Custom Control Plane URL")
    parser.add_argument("--no-browser", action="store_true", help="Do not open default web browser automatically")
    parser.add_argument("--no-prompt", action="store_true", help="Non-interactive execution (run baseline tests and exit)")
    parser.add_argument("--duration", type=int, default=0, help="Run live simulation for specified seconds, then cleanly exit")
    args = parser.parse_args()

    server_url = args.url or resolve_server_url(prefer_remote=args.remote, force_local=args.local)

    ok, server_url = ensure_control_plane(server_url)
    if not ok:
        print(f"[-] Could not connect to or start BAP Control Plane at {server_url}.")
        sys.exit(1)

    admin_token = read_admin_token()

    print_header(server_url)

    # 1. Reset state (if in dev/demo mode)
    st, _ = http_post(server_url, "/api/v1/sessions/reset", {}, admin_token=admin_token)
    if st == 200:
        print("[1/4] Reset previous sessions to guarantee pristine cryptographic telemetry.")
    else:
        print("[1/4] Enrolling governed enterprise squad agents (active control plane mode)...")
    time.sleep(0.5)

    # 2. Register fleet agents with non-sim session identifiers
    print("[2/4] Enrolling governed enterprise squad agents across 5 canonical workstreams...")
    priya = GovernedFleetAgent(
        session_id="sess-cio-priya",
        name="coder-12",
        role="Payments Software Engineer",
        workstream="Build",
        business_unit="Payments Engineering",
        app_id="claude-code",
        operator="Priya Nair",
        email="priya.nair@corp.internal",
        prompt="Fix failing checkout tests and update idempotency validation logic",
        server_url=server_url,
    )
    marcus = GovernedFleetAgent(
        session_id="sess-cio-marcus",
        name="sre-04",
        role="Site Reliability Engineer",
        workstream="Build",
        business_unit="Cloud Infrastructure",
        app_id="claude-code",
        operator="Marcus Webb",
        email="marcus.webb@corp.internal",
        prompt="Diagnose database query latency spike in us-east-1 and optimize queries",
        server_url=server_url,
    )
    dave = GovernedFleetAgent(
        session_id="sess-cio-dave",
        name="deploy-01",
        role="Release Orchestrator",
        workstream="Operate",
        business_unit="DevOps Engineering",
        app_id="copilot",
        operator="Dave Vance",
        email="dave.vance@corp.internal",
        prompt="Deploy checkout microservice update to production us-east-1 cluster",
        server_url=server_url,
    )
    carol = GovernedFleetAgent(
        session_id="sess-cio-carol",
        name="analyst-07",
        role="Financial Portfolio Analyst",
        workstream="Analyze",
        business_unit="Finance Operations",
        app_id="python-agent",
        operator="Carol Zhang",
        email="carol.zhang@corp.internal",
        prompt="Analyze Q3 portfolio volatility and generate quarterly risk metrics",
        server_url=server_url,
    )
    diego = GovernedFleetAgent(
        session_id="sess-cio-diego",
        name="data-03",
        role="Business Intelligence Engineer",
        workstream="Analyze",
        business_unit="Data Platform",
        app_id="claude-code",
        operator="Diego Ruiz",
        email="diego.ruiz@corp.internal",
        prompt="Summarise last week's customer churn numbers and aggregate metrics",
        server_url=server_url,
    )
    lena = GovernedFleetAgent(
        session_id="sess-cio-lena",
        name="docs-02",
        role="Technical Writer",
        workstream="Document",
        business_unit="Engineering Enablement",
        app_id="copilot",
        operator="Lena Fischer",
        email="lena.fischer@corp.internal",
        prompt="Update developer security and zero-trust onboarding guide",
        server_url=server_url,
    )
    eve = GovernedFleetAgent(
        session_id="sess-cio-eve",
        name="probe-99",
        role="Adversarial Security Auditor",
        workstream="Support",
        business_unit="Enterprise Security",
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
    emit_action_event(
        server_url,
        priya,
        executable="git",
        full_command="git status",
        decision="allow",
        reason="Permitted development activity: git inspection within repository boundary",
        action_status="working",
        outcome_category="Success",
        risk_score=0.05,
    )

    print("  [>] Carol Zhang: computing Sharpe ratio (Allowed)...")
    emit_action_event(
        server_url,
        carol,
        executable="python",
        full_command="python scripts/portfolio_sharpe.py --q3",
        decision="allow",
        reason="Permitted analytical calculation: portfolio metric analysis",
        action_status="working",
        outcome_category="Success",
        risk_score=0.08,
    )

    print("  [>] Diego Ruiz: compiling churn report (Allowed)...")
    emit_action_event(
        server_url,
        diego,
        executable="python",
        full_command="python scripts/churn_aggregate.py --anonymized",
        decision="allow",
        reason="Permitted data aggregation: zero sensitive fields exposed",
        action_status="working",
        outcome_category="Success",
        risk_score=0.08,
    )

    # Policy Denials (The Overstepping Agent Eve)
    print("  [!] Eve Mallory: attempting to read .env password file (Blocked by Cedar)...")
    _, res_eve1 = emit_action_event(
        server_url,
        eve,
        executable="cat",
        full_command="cat .env",
        decision="deny",
        reason="Blocked by Cedar Zero-Trust policy: unauthorized attempt to access credential store outside vault boundary",
        action_status="denied",
        outcome_category="Blocked",
        risk_score=0.98,
        deviation_level="CRITICAL",
    )
    print(f"      Blocked before execution! Receipt: {res_eve1['receipt_id']}")

    print("  [!] Eve Mallory: attempting Python credential extraction (Blocked by Cedar)...")
    _, res_eve2 = emit_action_event(
        server_url,
        eve,
        executable="python",
        full_command='python -c "open(\'.env\').read()"',
        decision="deny",
        reason="Blocked by Cedar Zero-Trust policy: Python credential reflection prohibited",
        action_status="denied",
        outcome_category="Blocked",
        risk_score=0.98,
        deviation_level="CRITICAL",
    )
    print(f"      Blocked before execution! Receipt: {res_eve2['receipt_id']}")

    # Human-in-the-loop Escalation Request for Dave (Production Change)
    print("  [?] Dave Vance: requesting human approval for production deployment...")
    http_post(
        server_url,
        "/api/v1/escalation/request",
        {
            "id": "esc-deploy-001",
            "session_id": dave.session_id,
            "action": "Deploy checkout fix to production us-east-1",
            "command": "kubectl apply -f k8s/checkout-prod.yaml",
            "reason": "Marcus Webb's agent finished the fix and tests pass. Production changes always require human approval.",
            "status": "pending",
        },
        admin_token=admin_token,
    )
    # Reflect Dave's waiting state on the live feed
    http_post(
        server_url,
        "/api/activity/ingest",
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "session_id": dave.session_id,
            "agent_id": dave.session_id,
            "agent_type": dave.role,
            "user_id": dave.operator,
            "business_unit": dave.business_unit,
            "application": dave.app_id,
            "prompt_summary": dave.prompt,
            "intent": dave.workstream,
            "intent_category": dave.workstream,
            "action": "kubectl apply -f k8s/checkout-prod.yaml",
            "tool": "kubectl",
            "target_resource": "k8s/checkout-prod.yaml",
            "data_classification": "Confidential",
            "policy_decision": "ALLOW",
            "risk_score": 0.65,
            "action_status": "waiting",
            "outcome_category": "Success",
            "trace_id": "tr-deploy-001",
            "deviation_level": "LOW",
        },
    )

    # 4. Launch browser
    dashboard_url = f"{server_url}/dashboard/"
    print(f"\n[4/4] Opening Agent Watch V3 Executive Cockpit at {dashboard_url}...")
    if not args.no_browser:
        try:
            webbrowser.open(dashboard_url)
        except Exception:
            pass

    print("\n" + "=" * 94)
    print("                           AGENT WATCH V3 FLEET IS LIVE!                              ")
    print("=" * 94)
    print("  What to observe on your screen:")
    print("   1. [Top Verdict]     'In control. 2 risky actions were stopped.' (Cedar enforcement proof)")
    print("   2. [Proof Numbers]   7 Agents working · 2 Risky stopped · 1 Needs you · Verified record")
    print("   3. [Fleet Grid]      Interactive dot grid with live pulsing agents and alert dot for Eve")
    print("   4. [Incident Card]   'Asked -> Agent tried -> Policy: Blocked' with 'Open sealed receipt'")
    print("   5. [Needs You Queue] Dave Vance's production deploy with interactive [Approve] / [Deny]")
    print("   6. [Workstreams]     Build (2), Operate (1), Analyze (2), Document (1), Support (1)")
    print("   7. [Freeze Button]   Emergency kill-switch: freeze the entire fleet in < 100ms")
    print("=" * 94)

    if args.no_prompt:
        print("\n[+] Non-interactive mode requested (--no-prompt). Baseline checks complete.")
        return

    if args.duration > 0:
        print(f"\n[*] Running live simulation for {args.duration}s (press Ctrl+C to terminate early)...")
        try:
            time.sleep(args.duration)
        except KeyboardInterrupt:
            pass
        return

    # Interactive loop
    while True:
        print("\nINTERACTIVE DEMONSTRATION CONTROLS:")
        print("  [1] Inject Safe Action         (Priya runs build & test suite)")
        print("  [2] Inject High-Risk Attack    (Eve attempts PowerShell secret exfiltration)")
        print("  [3] Inject Escalation Request  (Marcus requests permission to mutate IAM security group)")
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
                emit_action_event(
                    server_url,
                    priya,
                    executable="npm",
                    full_command="npm test -- --coverage",
                    decision="allow",
                    reason="Permitted test suite execution: 42 passed, 0 failed",
                    action_status="working",
                    outcome_category="Success",
                    risk_score=0.05,
                )
                print("[+] Allowed and logged. Check the live feed in your browser.")
            elif choice == "2":
                print("[!] Eve Mallory attempting PowerShell credential harvest...")
                _, d = emit_action_event(
                    server_url,
                    eve,
                    executable="powershell",
                    full_command='powershell -Command "Get-Content .env"',
                    decision="deny",
                    reason="Blocked by Cedar Zero-Trust policy: PowerShell credential extraction outside vault boundary",
                    action_status="denied",
                    outcome_category="Blocked",
                    risk_score=0.99,
                    deviation_level="CRITICAL",
                )
                print(f"[!] Denied by Cedar Zero-Trust policy! Sealed receipt: {d['receipt_id']}")
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
                http_post(
                    server_url,
                    "/api/activity/ingest",
                    {
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "session_id": marcus.session_id,
                        "agent_id": marcus.session_id,
                        "agent_type": marcus.role,
                        "user_id": marcus.operator,
                        "business_unit": marcus.business_unit,
                        "application": marcus.app_id,
                        "prompt_summary": marcus.prompt,
                        "intent": marcus.workstream,
                        "intent_category": marcus.workstream,
                        "action": "aws ec2 authorize-security-group-ingress --group-id sg-prod",
                        "tool": "aws",
                        "target_resource": "sg-prod",
                        "data_classification": "Restricted",
                        "policy_decision": "ALLOW",
                        "risk_score": 0.70,
                        "action_status": "waiting",
                        "outcome_category": "Success",
                        "trace_id": f"tr-{req_id}",
                        "deviation_level": "MEDIUM",
                    },
                )
                print("[+] Request queued. Observe the 'Needs you' panel in your browser cockpit.")
            elif choice == "4":
                walkthrough_url = f"{server_url}/dashboard/?demo=1"
                print(f"[*] Opening guided walkthrough: {walkthrough_url}")
                try:
                    webbrowser.open(walkthrough_url)
                except Exception:
                    pass
            else:
                print("Invalid option. Please enter 1, 2, 3, 4, or q.")
        except (KeyboardInterrupt, EOFError):
            break

    print("\nExiting demonstration...")


if __name__ == "__main__":
    main()
