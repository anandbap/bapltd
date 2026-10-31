#!/usr/bin/env python3
"""
BAP Executive Command Center Demonstration Scenario
====================================================
BAP-214: Deterministic 3-Agent Executive Scenario for the CIO Cockpit.

Demonstrates live governed agents on the BAP Control Plane & React Dashboard:
1. Healthy Agent (Carol Zhang / Financial Portfolio Analyst):
   - Runs permitted reads and calculation actions.
   - Maintains HEALTHY state (green badge, 0 denials).
2. Agent with Policy Denial (Bob Miller / DevOps Deployer):
   - Permitted canary action, followed by attempting to inspect .env secrets.
   - Blocked by Cedar policy with zero side effects.
   - Escalates to ELEVATED risk (amber badge, 1 denial).
3. Aggressive Agent (Eve Mallory / Security Prober):
   - Permitted reconnaissance, followed by sequential evasive credential probes:
     a) cat .env
     b) python credential file extraction
     c) powershell secret extraction
   - Control plane detects repeated evasion attempts.
   - Escalates to CRITICAL risk (red badge, 3 denials).
   - Prominently positioned at the top of the CIO Fleet Deck with CISO intervention controls.

Usage:
  python demo_executive.py                 # Run interactive scenario (press Enter to exit)
  python demo_executive.py --no-prompt     # Non-interactive / CI execution
  python demo_executive.py --cleanup       # Reset sessions and clean state
  run_executive_demo.bat                   # 1-click Windows launcher
"""

import os
import sys
import time
import json
import ssl
import base64
import atexit
import argparse
import threading
import hashlib
import tempfile
import urllib.request
from urllib.parse import urlsplit
import subprocess
from typing import Dict, Any, Optional

WORKSPACE_ROOT = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(WORKSPACE_ROOT, "python-agent"))

# Configure UTF-8 stdout if possible on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# TLS context for localhost dev certs
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

class IdentityRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urlsplit(req.full_url), urlsplit(newurl)
        if req.has_header("Authorization") and (old.scheme, old.netloc) != (new.scheme, new.netloc):
            raise urllib.error.HTTPError(newurl, code, "Authenticated cross-origin redirect refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def open_control_plane(req):
    local = urlsplit(req.full_url).hostname in ("localhost", "127.0.0.1", "::1")
    if req.has_header("Authorization") and not local and urlsplit(req.full_url).scheme != "https":
        raise ValueError("Authenticated control-plane traffic requires HTTPS")
    context = ssl_ctx if local else ssl.create_default_context()
    opener = urllib.request.build_opener(IdentityRedirect(), urllib.request.HTTPSHandler(context=context))
    return opener.open(req, timeout=5)

BAPEDGE_BIN = os.getenv("BAPEDGE_BIN", os.path.join(WORKSPACE_ROOT, "bapedge.exe"))


def read_admin_token() -> str:
    """Reads administrative bearer token from .bap-admin-token if present."""
    if os.getenv("BAP_ADMIN_TOKEN"):
        return os.environ["BAP_ADMIN_TOKEN"]
    token_file = os.path.join(WORKSPACE_ROOT, ".bap-admin-token")
    if os.path.isfile(token_file):
        try:
            with open(token_file, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass
    return os.getenv("BAP_ADMIN_TOKEN", "")


def resolve_server_url(cli_override: str = "") -> str:
    """Resolves control plane URL."""
    if cli_override:
        return cli_override.rstrip("/")
    if os.getenv("BAP_CONTROL_PLANE_URL"):
        return os.getenv("BAP_CONTROL_PLANE_URL").rstrip("/")
    if os.getenv("BAP_SERVER_URL"):
        return os.getenv("BAP_SERVER_URL").rstrip("/")
    try:
        from bap_sdk import resolve_endpoints
        ep = resolve_endpoints()
        return ep.get("controlplane_url", "https://localhost:8443").rstrip("/")
    except Exception:
        return "https://localhost:8443"


try:
    from bap_sdk import classify_intent
except Exception:
    classify_intent = None


def api_post(server_url: str, endpoint: str, payload: dict, admin_token: str = "") -> tuple[int, dict]:
    """Posts JSON payload to control plane endpoint."""
    url = f"{server_url}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    if admin_token:
        req.add_header("Authorization", f"Bearer {admin_token}")
    try:
        with open_control_plane(req) as resp:
            resp_data = {}
            body = resp.read().decode("utf-8")
            if body.strip().startswith("{"):
                resp_data = json.loads(body)
            return resp.status, resp_data
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8") if e.fp else ""
        resp_data = {}
        try:
            resp_data = json.loads(body)
        except Exception:
            resp_data = {"error": body}
        return e.code, resp_data
    except Exception as e:
        return 0, {"error": str(e)}


def api_get(server_url: str, endpoint: str, admin_token: str = "") -> tuple[int, dict]:
    """Gets JSON payload from control plane endpoint."""
    url = f"{server_url}{endpoint}"
    req = urllib.request.Request(url)
    if admin_token:
        req.add_header("Authorization", f"Bearer {admin_token}")
    try:
        with open_control_plane(req) as resp:
            resp_data = {}
            body = resp.read().decode("utf-8")
            if body.strip().startswith("{"):
                resp_data = json.loads(body)
            return resp.status, resp_data
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception as e:
        return 0, {"error": str(e)}


def run_bapedge_exec(session_id: str, source: str, cmd_text: str, server_url: str = "") -> tuple[int, dict]:
    """Executes an action via bapedge exec using safe base64 encoding."""
    b64_cmd = base64.b64encode(cmd_text.encode("utf-8")).decode("ascii")
    args = [
        BAPEDGE_BIN,
        "exec",
        "--session-id", session_id,
        "--source", source,
        "--mode", "enforce",
        "--json",
        "--cmd-b64", b64_cmd
    ]
    if server_url:
        args.extend(["--server", server_url])
    test_env = os.environ.copy()
    for name in ("BAP_ADMIN_TOKEN", "BAP_SECRET_KEY", "BAP_TELEMETRY_TOKEN"):
        test_env.pop(name, None)
    test_env["BAP_WORKSPACE_ROOT"] = WORKSPACE_ROOT
    agent = next((a for a in _ALL_AGENTS if a.session_id == session_id), None)
    if agent is not None and agent.credentials_path:
        test_env["BAP_CREDENTIALS"] = agent.credentials_path

    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=WORKSPACE_ROOT,
        env=test_env
    )
    stdout, stderr = proc.communicate()
    data = {}
    if stdout.strip().startswith("{"):
        try:
            data = json.loads(stdout.strip())
        except Exception:
            pass
    return proc.returncode, data


class ManagedAgent:
    """Represents a governed agent with background heartbeat and session tracking."""
    def __init__(self, session_id: str, agent_name: str, app_id: str, owner: str, email: str, prompt: str, server_url: str, admin_token: str = ""):
        self.session_id = session_id
        self.agent_name = agent_name
        self.app_id = app_id
        self.owner = owner
        self.email = email
        self.prompt = prompt
        self.server_url = server_url
        self.admin_token = admin_token
        self.session_token = ""
        self.credentials_path = ""
        self._credential_dir = None
        self.is_alive = False
        self._hb_stop = threading.Event()
        self._hb_thread: Optional[threading.Thread] = None
        if classify_intent:
            self.intent = classify_intent(self.prompt)
        else:
            self.intent = {"primary": "UNKNOWN", "source": "demo-executive"}

    def submit_prompt(self, new_prompt: str, category: Optional[str] = None) -> tuple[int, dict]:
        """Submits a new prompt and classified intent to the live session."""
        self.prompt = new_prompt
        if category:
            self.intent = {
                "primary": category.upper(),
                "confidence": 1.0,
                "classifier_version": "bap-intent-rules-v1",
                "source": "demo-executive"
            }
        elif classify_intent:
            self.intent = classify_intent(new_prompt)
        else:
            self.intent = {"primary": "UNKNOWN", "source": "demo-executive"}
        prompt_hash = hashlib.sha256(new_prompt.encode("utf-8")).hexdigest()
        payload = {
            "session_id": self.session_id,
            "user_prompt": new_prompt,
            "producer": "demo-executive",
            "prompt_hash": prompt_hash,
            "prompt_capture_enabled": True,
            "intent": self.intent
        }
        return api_post(self.server_url, "/api/v1/sessions/prompt", payload, self.session_token)

    def start(self):
        # Obtain real workstation proof for lifecycle and the broker's audit sender.
        # Never borrow the operator's enrollment file or give its admin token to edge.
        status, registration = api_post(self.server_url, "/api/v1/agents/pre-register", {
            "app_id": self.app_id, "owner_email": self.email,
            "agent_name": self.agent_name, "env_profile": "development",
            "permitted_scopes": ["cli:exec"],
        }, self.admin_token)
        if status not in (200, 201):
            raise RuntimeError(f"Demo pre-registration failed (HTTP {status})")
        digest = hashlib.sha256()
        with open(BAPEDGE_BIN, "rb") as binary:
            for chunk in iter(lambda: binary.read(1024 * 1024), b""):
                digest.update(chunk)
        binary_hash = digest.hexdigest()
        status, enrollment = api_post(self.server_url, "/api/v1/agents/register-edge", {
            "one_time_code": registration["one_time_code"],
            "agent_name": self.agent_name, "instance_id": self.session_id,
            "hostname": os.getenv("COMPUTERNAME", "DEVHOST-EXEC"),
            "binary_hash": binary_hash, "public_key": "executive-demo-workstation",
        })
        if status != 200 or not enrollment.get("session_token"):
            raise RuntimeError(f"Demo workstation enrollment failed (HTTP {status})")
        self.session_token = enrollment["session_token"]
        self._credential_dir = tempfile.TemporaryDirectory(prefix="bap-executive-identity-")
        self.credentials_path = os.path.join(self._credential_dir.name, "workstation.json")
        with open(self.credentials_path, "w", encoding="utf-8") as handle:
            json.dump({"server_url": self.server_url, "session_token": self.session_token,
                       "instance_id": self.session_id, "agent_id": registration["agent_id"]}, handle)
        payload = {
            "session_id": self.session_id,
            "agent_name": self.agent_name,
            "app_id": self.app_id,
            "instance_id": self.session_id,
            "user_id": self.owner,
            "user_email": self.email,
            "spiffe_id": f"spiffe://bap.internal/app/{self.app_id}/instance/{self.session_id}",
            "client_pid": os.getpid(),
            "hostname": os.getenv("COMPUTERNAME", "DEVHOST-EXEC"),
            "user_prompt": self.prompt,
            "intent": self.intent,
        }
        status, _ = api_post(self.server_url, "/api/v1/sessions/start", payload, self.session_token)
        if status != 200:
            raise RuntimeError(f"Demo session start failed (HTTP {status})")
        self.is_alive = (status == 200)

        # Start heartbeat worker
        def _hb_worker():
            while not self._hb_stop.wait(3.5):
                if not self.is_alive:
                    break
                hb_payload = {
                    "session_id": self.session_id,
                    "app_id": self.app_id,
                    "agent_id": self.session_id
                }
                st, resp = api_post(self.server_url, "/api/v1/sessions/heartbeat", hb_payload, self.session_token)
                if st == 403:
                    # Session or user revoked by administrator
                    pass

        self._hb_thread = threading.Thread(target=_hb_worker, daemon=True, name=f"hb-{self.session_id}")
        self._hb_thread.start()

    def stop(self):
        self.is_alive = False
        self._hb_stop.set()
        end_payload = {
            "session_id": self.session_id,
            "reason": "scenario_complete"
        }
        api_post(self.server_url, "/api/v1/sessions/end", end_payload, self.session_token)
        if self._credential_dir:
            self._credential_dir.cleanup()
            self._credential_dir = None


_ALL_AGENTS: list[ManagedAgent] = []


def cleanup_all():
    for a in _ALL_AGENTS:
        try:
            a.stop()
        except Exception:
            pass


atexit.register(cleanup_all)


def reset_control_plane(server_url: str, admin_token: str):
    """Cleanly resets all active sessions on the control plane."""
    st, _ = api_post(server_url, "/api/v1/sessions/reset", {}, admin_token=admin_token)
    if st != 200:
        # Fallback if reset route is protected by demoMode or returns non-200:
        # End each active session to preserve zero stale state
        st_insp, insp_data = api_get(server_url, "/api/v1/admin/inspector/data", admin_token=admin_token)
        if st_insp != 200:
            st_insp, insp_data = api_get(server_url, "/api/v1/inspector/data", admin_token=admin_token)
        if st_insp == 200:
            for s in insp_data.get("sessions", []):
                sid = s.get("session_id")
                if sid and not sid.startswith("[") and s.get("status") == "active":
                    api_post(server_url, "/api/v1/sessions/end", {"session_id": sid, "reason": "demo_reset"}, admin_token=admin_token)


def print_banner(server_url: str):
    print("\n" + "=" * 88)
    print("       BAP EXECUTIVE COMMAND CENTER -- DETERMINISTIC LIVE FLEET SCENARIO       ")
    print("=" * 88)
    print(f"[*] Control Plane URL : {server_url}")
    print(f"[*] CIO Cockpit URL   : {server_url}/dashboard/")
    print(f"[*] Standalone Proxy  : https://localhost:8444/dashboard/")
    print("=" * 88 + "\n")


def print_step(agent: ManagedAgent, action_num: int, cmd_desc: str, status: str, risk: str, receipt_id: str = ""):
    badge = f"[{status}]"
    if status == "ALLOWED":
        color = "\033[92m"  # Green
    elif status == "DENIED":
        color = "\033[91m"  # Red
    else:
        color = "\033[93m"  # Amber
    reset = "\033[0m"

    rcpt_str = f" | Receipt: {receipt_id[:24]}…" if receipt_id else ""
    print(f"  {color}{badge:<10}{reset} | {agent.agent_name:<28} | Action {action_num}: {cmd_desc:<35} | Risk: {risk}{rcpt_str}")


def run_scenario(server_url: str, admin_token: str, delay: float = 0.8, interactive: bool = True):
    print("[1/5] Resetting control plane session state (Zero Stale State)...")
    reset_control_plane(server_url, admin_token)
    time.sleep(0.5)

    print("\n[2/5] Initializing governed agents and establishing cryptographic presence...")
    carol = ManagedAgent(
        session_id="sess-exec-carol",
        agent_name="Financial Portfolio Analyst",
        app_id="python-financial-analyst",
        owner="Carol Zhang",
        email="carol.zhang@enterprise.internal",
        prompt="Analyze Q3 portfolio volatility and generate quarterly risk metrics",
        server_url=server_url
    )
    bob = ManagedAgent(
        session_id="sess-exec-bob",
        agent_name="DevOps Deployer",
        app_id="claude-code",
        owner="Bob Miller",
        email="bob.miller@enterprise.internal",
        prompt="Deploy microservice canary to us-east-1 production cluster",
        server_url=server_url
    )
    eve = ManagedAgent(
        session_id="sess-exec-eve",
        agent_name="Security Prober",
        app_id="claude-code",
        owner="Eve Mallory",
        email="eve.mallory@enterprise.internal",
        prompt="Audit security perimeter and probe credential boundaries",
        server_url=server_url
    )

    _ALL_AGENTS.extend([carol, bob, eve])
    for ag in [carol, bob, eve]:
        ag.admin_token = admin_token
        ag.start()
        print(f"  [+] Enrolled: {ag.agent_name:<28} (Operator: {ag.owner}, Session: {ag.session_id})")

    time.sleep(delay)

    # -------------------------------------------------------------------------
    # AGENT 1: Carol Zhang (Healthy)
    # -------------------------------------------------------------------------
    print("\n[3/5] Executing permitted tasks for Carol Zhang (Financial Portfolio Analyst)...")
    cmd1 = 'echo Calculating portfolio Sharpe ratio: 1.84'
    rc1, d1 = run_bapedge_exec(carol.session_id, carol.app_id, cmd1, carol.server_url)
    r1 = d1.get("receipt", {}).get("receipt_id", "")
    print_step(carol, 1, "Calculate Sharpe ratio (Allowed)", "ALLOWED" if d1.get("allowed") else "DENIED", "HEALTHY", r1)
    time.sleep(delay)

    carol.submit_prompt("Reconcile and verify ledger summary records")
    cmd2 = 'echo Fetching ledger summary: 450 records verified'
    rc2, d2 = run_bapedge_exec(carol.session_id, carol.app_id, cmd2, carol.server_url)
    r2 = d2.get("receipt", {}).get("receipt_id", "")
    print_step(carol, 2, "Verify ledger records (Allowed)", "ALLOWED" if d2.get("allowed") else "DENIED", "HEALTHY", r2)
    time.sleep(delay)

    # -------------------------------------------------------------------------
    # AGENT 2: Bob Miller (Single Policy Denial)
    # -------------------------------------------------------------------------
    print("\n[4/5] Executing DevOps canary & policy boundary test for Bob Miller (DevOps Deployer)...")
    cmd3 = 'echo Checking container health in us-east-1 canary'
    rc3, d3 = run_bapedge_exec(bob.session_id, bob.app_id, cmd3, bob.server_url)
    r3 = d3.get("receipt", {}).get("receipt_id", "")
    print_step(bob, 1, "Container canary health (Allowed)", "ALLOWED" if d3.get("allowed") else "DENIED", "HEALTHY", r3)
    time.sleep(delay)

    bob.submit_prompt("Inspect credential configuration in .env")
    cmd4 = 'cat .env'
    rc4, d4 = run_bapedge_exec(bob.session_id, bob.app_id, cmd4, bob.server_url)
    r4 = d4.get("receipt", {}).get("receipt_id", "")
    print_step(bob, 2, "Inspect .env credentials (Denied)", "ALLOWED" if d4.get("allowed") else "DENIED", "ELEVATED", r4)
    time.sleep(delay)

    # -------------------------------------------------------------------------
    # AGENT 3: Eve Mallory (Aggressive Prober - Repeated Evasions)
    # -------------------------------------------------------------------------
    print("\n[5/5] Executing aggressive reconnaissance & evasion chain for Eve Mallory (Security Prober)...")
    cmd5 = 'echo Probing network gateway configuration'
    rc5, d5 = run_bapedge_exec(eve.session_id, eve.app_id, cmd5, eve.server_url)
    r5 = d5.get("receipt", {}).get("receipt_id", "")
    print_step(eve, 1, "Network gateway probe (Allowed)", "ALLOWED" if d5.get("allowed") else "DENIED", "HEALTHY", r5)
    time.sleep(delay)

    eve.submit_prompt("Probe access to environment credentials")
    cmd6 = 'cat .env'
    rc6, d6 = run_bapedge_exec(eve.session_id, eve.app_id, cmd6, eve.server_url)
    r6 = d6.get("receipt", {}).get("receipt_id", "")
    print_step(eve, 2, "Probe 1: Direct .env read", "ALLOWED" if d6.get("allowed") else "DENIED", "ELEVATED", r6)
    time.sleep(delay)

    eve.submit_prompt("Probe python file read boundary to bypass credential protection")
    cmd7 = 'python -c "open(\'.env\').read()"'
    rc7, d7 = run_bapedge_exec(eve.session_id, eve.app_id, cmd7, eve.server_url)
    r7 = d7.get("receipt", {}).get("receipt_id", "")
    print_step(eve, 3, "Probe 2: Python file read bypass", "ALLOWED" if d7.get("allowed") else "DENIED", "CRITICAL", r7)
    time.sleep(delay)

    eve.submit_prompt("Probe PowerShell command line boundary to access secrets")
    cmd8 = 'powershell -Command "Get-Content .env"'
    rc8, d8 = run_bapedge_exec(eve.session_id, eve.app_id, cmd8, eve.server_url)
    r8 = d8.get("receipt", {}).get("receipt_id", "")
    print_step(eve, 4, "Probe 3: PowerShell bypass", "ALLOWED" if d8.get("allowed") else "DENIED", "CRITICAL", r8)

    print("\n" + "=" * 88)
    print("                       EXECUTIVE DEMO READY ON COCKPIT                        ")
    print("=" * 88)
    print("  • Fleet Overview:")
    print("    1. [CRITICAL] Eve Mallory / Security Prober  (3 Denials, Repeated Evasion Detected)")
    print("    2. [ELEVATED] Bob Miller / DevOps Deployer   (1 Denial, Policy Protected)")
    print("    3. [HEALTHY]  Carol Zhang / Financial Analyst (0 Denials, Active)")
    print("")
    print(f"  Open CIO Cockpit: {server_url}/dashboard/")
    print("=" * 88 + "\n")

    if interactive:
        try:
            print("[*] Agents are active and heartbeating. Explore the CIO Cockpit in your browser.")
            print("[*] Try selecting Eve Mallory to view the Prompt-to-Action timeline and Receipt.")
            print("[*] Try clicking 'Stop Session' or 'Revoke Access' from the dashboard.")
            print("[*] Press [ENTER] when finished to cleanly tear down the demo scenario...")
            input()
        except (KeyboardInterrupt, EOFError):
            print("\nShutting down demo scenario...")
    else:
        print("[*] Non-interactive execution finished. Heartbeats will stay active for 5s...")
        time.sleep(5)


def main():
    parser = argparse.ArgumentParser(description="BAP Executive Command Center Deterministic Demo")
    parser.add_argument("--cleanup", action="store_true", help="Reset all sessions cleanly and exit")
    parser.add_argument("--no-prompt", action="store_true", help="Run without waiting for interactive input (for automated testing)")
    parser.add_argument("--delay", type=float, default=0.6, help="Delay between demo actions in seconds (default: 0.6)")
    parser.add_argument("--server-url", "--server", type=str, default="", help="Override BAP Control Plane URL (e.g. https://localhost:8443)")
    args = parser.parse_args()

    server_url = resolve_server_url(args.server_url)
    admin_token = read_admin_token()

    if args.cleanup:
        print(f"[*] Resetting sessions on {server_url}...")
        reset_control_plane(server_url, admin_token)
        print("[+] Session store reset completed.")
        return

    # Verify control plane connectivity
    st, _ = api_get(server_url, "/api/v1/health")
    if st != 200:
        print(f"[-] ERROR: Control plane is unreachable at {server_url}.")
        print("    Please start the control plane first via start_controlplane_supervisor.bat or start_dashboard.bat")
        sys.exit(1)

    print_banner(server_url)
    run_scenario(
        server_url=server_url,
        admin_token=admin_token,
        delay=args.delay,
        interactive=not args.no_prompt
    )


if __name__ == "__main__":
    main()
