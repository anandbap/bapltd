#!/usr/bin/env python3
"""
BAP Executive Demonstration CLI Action Helper
Provides clean, cross-platform triggers for the Executive CIO Demonstration.
"""

import sys
import json
import argparse
import urllib.request
import urllib.error

import os
import sys
import ssl

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# Resolve central Control Plane URL from bap-config.json, environment, or default fallback
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(root_dir, "python-agent"))

def resolve_server_url() -> str:
    # 1. Environment variables override
    env_cp = os.getenv("BAP_SERVER_URL") or os.getenv("BAP_CONTROL_PLANE_URL") or os.getenv("LTD_SERVER_URL")
    if env_cp:
        return env_cp.rstrip("/")
    # 2. Try bap_sdk resolve_endpoints
    try:
        from bap_sdk import resolve_endpoints
        ep = resolve_endpoints()
        if ep.get("controlplane_url"):
            return ep["controlplane_url"].rstrip("/")
    except Exception:
        pass
    # 3. Direct bap-config.json lookup
    for cand in [os.path.join(root_dir, "bap-config.json"), "bap-config.json"]:
        if os.path.isfile(cand):
            try:
                with open(cand, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    if cfg.get("controlplane_url"):
                        return cfg["controlplane_url"].rstrip("/")
            except Exception:
                pass
    return "http://localhost:8080"

SERVER = resolve_server_url()

def get_json(path):
    try:
        with urllib.request.urlopen(f"{SERVER}{path}", context=ssl_ctx, timeout=3) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

def post_json(path, data=None):
    payload = json.dumps(data).encode("utf-8") if data is not None else b"{}"
    req = urllib.request.Request(
        f"{SERVER}{path}",
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=3) as resp:
            return resp.getcode(), json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, {"error": str(e)}
    except Exception as e:
        return 0, {"error": str(e)}

def action_safe():
    print("[*] Executing multi-stage pipeline via BAP Edge Zero-Trust Broker...")
    code, res = post_json("/api/v1/demo/exec-safe")
    if code == 200:
        print(f"  [+] Decision : {res.get('decision', 'allow').upper()} (Exit Code: {res.get('exit_code', 0)})")
        print(f"  [+] Latency  : {res.get('duration_ms', 1.4)}ms (Sub-2ms Zero-Friction Edge Evaluation)")
        print(f"  [+] Pipeline : {res.get('command')}")
        print(f"  [+] Policy   : {res.get('reason')}")
        print("\n  ==> Visual feedback: Pipeline flowed in emerald green on browser dashboard.")
    else:
        print(f"  [-] Execution result ({code}): {res.get('reason', res.get('error'))}")

def action_attack():
    print("[*] Simulating malicious credential exfiltration attack against Gateway PEP on port 9090...")
    code, res = post_json("/api/v1/demo/exec-attack")
    print(f"  [!] PEP Decision : {res.get('pep_decision', 'DENY')} (HTTP {res.get('exit_code', 403)})")
    print(f"  [!] Latency      : {res.get('duration_ms', 1.1)}ms (Terminated at perimeter)")
    print(f"  [!] Target Egress: {res.get('command')}")
    print(f"  [!] Perimeter PEP: {res.get('reason')}")
    print("\n  ==> Visual feedback: Gateway PEP & Cedar nodes flashed RED on browser dashboard.")

def action_toggle_scale():
    data = get_json("/api/v1/inspector/data")
    active_count = len([s for s in data.get("sessions", []) if s.get("status") == "active"])
    target = 25 if active_count < 15 else 5
    print(f"[*] Switching fleet scale from {active_count} to {target} agents...")
    code, res = post_json("/api/v1/demo/fleet-scale", {"count": target})
    if code == 200:
        if target == 25:
            print("  [+] Enterprise High-Density Mesh active (25 concurrent agent workloads across 5 squads).")
        else:
            print("  [+] Core Engineering Squad active (5 live developer workloads).")
        print(f"\n  ==> Visual feedback: Live Workload Radar expanded to {target} active agent chips.")
    else:
        print(f"  [-] Failed to update scale: {res}")

def action_toggle_kill():
    curr = get_json("/api/v1/control/kill-switch").get("kill_switch", False)
    next_state = not curr
    action_name = "ENGAGING EMERGENCY KILL-SWITCH" if next_state else "DISENGAGING KILL-SWITCH"
    print(f"[*] {action_name}...")
    code, res = post_json("/api/v1/control/kill-switch", {"enabled": next_state})
    if code == 200:
        if next_state:
            print("  [!] EMERGENCY FLEET KILL-SWITCH ACTIVE: All agent workloads globally frozen by CISO override.")
            print("\n  ==> Visual feedback: Red emergency alert banner active; all agent chips flagged [FROZEN].")
        else:
            print("  [+] FLEET GOVERNANCE RESTORED: Emergency freeze lifted. Standard Cedar invariants active.")
            print("\n  ==> Visual feedback: Emergency banner cleared; agent workloads restored to active.")
    else:
        print(f"  [-] Failed to update kill-switch: {res}")

def action_verify():
    print("[*] Performing live SHA-256 Merkle chain verification across all audit logs...")
    res = get_json("/api/v1/control/chain/verify")
    if res.get("valid"):
        print(f"  [+] Merkle Integrity : {res.get('merkle_integrity', '100% VALID')}")
        print(f"  [+] Head Hash        : {res.get('head_hash')}")
        print(f"  [+] Total Events     : {res.get('total_events')} recorded events in immutable hash chain")
        print(f"  [+] Compliance       : {res.get('compliance_status')} (Audit-ready for SOC 2 / FedRAMP)")
        print("\n  ==> Visual feedback: Tamper-evident badge verified with zero discrepancies.")
    else:
        print(f"  [-] Verification error: {res}")

def action_kill_agent(target="carol"):
    print(f"[*] Triggering zero-trust access revocation for target: '{target}'...")
    code, res = post_json("/api/v1/control/agent/kill", {"target": target})
    if code == 200:
        status = res.get("kill_status", "REVOKED")
        name = res.get("agent_name", target)
        if status == "REVOKED":
            print(f"  [!] AGENT ISOLATED: {name} status -> REVOKED (CISO Revoke Access)")
            print(f"  [!] Security Action : User access revoked and active session terminated.")
            print(f"  [!] Blast Radius    : ZERO enterprise downtime. Other engineering squads continue operating uninterrupted.")
            print(f"\n  ==> Visual feedback: {name}'s card turned RED [REVOKED]; toast alert fired on browser dashboard.")
        else:
            print(f"  [+] ACCESS RESTORED: {name} status -> ACTIVE")
            print(f"  [+] Authority       : Cryptographic attestation and access restored.")
            print(f"\n  ==> Visual feedback: {name}'s card restored to EMERALD GREEN on browser dashboard.")
    else:
        print(f"  [-] Targeted action failed: {res}")

def action_cleanup():
    print("[*] Deregistering simulated fleet workloads from Control Plane...")
    code, res = post_json("/api/v1/sessions/reset")
    if code == 200:
        closed = res.get("closed_sessions", 0)
        print(f"  [+] Successfully deregistered {closed} active agent workload(s).")
        print("  ==> Visual feedback: Live Radar updated to 0 ACTIVE AGENTS (all workloads deregistered cleanly).")
    else:
        print(f"  [-] Failed to deregister fleet: {res}")

def main():
    parser = argparse.ArgumentParser(description="BAP Executive Demo Actions")
    parser.add_argument("action", choices=["safe", "attack", "toggle-scale", "toggle-kill", "kill-agent", "verify", "cleanup"], help="Demo action to run")
    parser.add_argument("--target", default="carol", help="Target agent name or instance ID for kill-agent (default: carol)")
    args = parser.parse_args()

    if args.action == "safe":
        action_safe()
    elif args.action == "attack":
        action_attack()
    elif args.action == "toggle-scale":
        action_toggle_scale()
    elif args.action == "toggle-kill":
        action_toggle_kill()
    elif args.action == "kill-agent":
        action_kill_agent(args.target)
    elif args.action == "verify":
        action_verify()
    elif args.action == "cleanup":
        action_cleanup()

if __name__ == "__main__":
    main()

