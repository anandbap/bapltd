import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
import uuid

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def compute_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

TEST_ADMIN_TOKEN = "test-admin-secret-token-12345"

def http_post_json(url, data, headers=None):
    hdrs = {"Content-Type": "application/json"}
    if url.endswith(("/agents/pre-register", "/grants/acquire", "/audit/ingest")) or "/api/v1/sessions/" in url:
        hdrs["X-BAP-Admin-Token"] = TEST_ADMIN_TOKEN
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=hdrs
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"raw": body}
        return e.code, parsed

def http_get_json(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"raw": body}
        return e.code, parsed

def main():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    
    # Resolve bapcontrolplane (alias ltd-service)
    service_candidates = [
        os.path.join(root_dir, "dist", "windows-amd64", "controlplane", "bapcontrolplane.exe"),
        os.path.join(root_dir, "dist", "windows-amd64", "bapcontrolplane.exe"),
        os.path.join(root_dir, "bap-controlplane", "bapcontrolplane.exe"),
        os.path.join(root_dir, "ltd-service", "bapcontrolplane.exe"),
    ]
    service_exe = next((p for p in service_candidates if os.path.exists(p)), None)
    if not service_exe:
        print(f"[FAIL] Missing control plane binary. Expected {service_candidates[0]}")
        sys.exit(1)

    # Resolve bapedge (LTD) (alias ltd-agent)
    agent_candidates = [
        os.path.join(root_dir, "dist", "windows-amd64", "claude-client", "bapedge.exe"),
        os.path.join(root_dir, "dist", "windows-amd64", "bapedge.exe"),
        os.path.join(root_dir, "bap-edge", "bapedge.exe"),
        os.path.join(root_dir, "ltd-agent", "bapedge.exe"),
    ]
    agent_exe = next((p for p in agent_candidates if os.path.exists(p)), None)
    if not agent_exe:
        print(f"[FAIL] Missing edge LTD binary. Expected {agent_candidates[0]}")
        sys.exit(1)

    agent_hash = compute_sha256(agent_exe)
    print(f"[*] Target agent binary ({os.path.basename(agent_exe)}) hash: {agent_hash}")

    port = get_free_port()
    base_url = f"http://127.0.0.1:{port}"
    print(f"[*] Starting {os.path.basename(service_exe)} on port {port}...")

    policy_candidates = [
        os.path.join(root_dir, "bap-edge", "policy.cedar"),
        os.path.join(root_dir, "ltd-agent", "policy.cedar"),
    ]
    policy_file = next((p for p in policy_candidates if os.path.exists(p)), policy_candidates[0])

    schema_candidates = [
        os.path.join(root_dir, "bap-edge", "schema.json"),
        os.path.join(root_dir, "ltd-agent", "schema.json"),
    ]
    schema_file = next((p for p in schema_candidates if os.path.exists(p)), schema_candidates[0])

    admin_token = "test-admin-secret-token-12345"
    server_proc = subprocess.Popen(
        [
            service_exe,
            "-port", str(port),
            "-secret", "integration-test-secret-key-32b!",
            "-admin-token", admin_token,
            "-allow-remote-admin",
            "-policy", policy_file,
            "-schema", schema_file
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        # Wait for server ready
        healthy = False
        for _ in range(30):
            time.sleep(0.2)
            try:
                status, data = http_get_json(f"{base_url}/api/v1/health")
                if status == 200 and data.get("status") == "ok":
                    healthy = True
                    break
            except Exception:
                continue

        if not healthy:
            print("[FAIL] ltd-service failed to start or pass health check.")
            sys.exit(1)

        print("[PASS] 1. Control plane health check ok")

        # 2. Test Development Self-Registration with One-Time Code
        pre_reg_data = {
            "app_id": "analytics-worker",
            "owner_email": "dev@company.internal",
            "agent_name": "AnalyticsAgentDev",
            "env_profile": "development",
            "permitted_scopes": ["cli:exec", "metrics:write"]
        }
        status, resp = http_post_json(f"{base_url}/api/v1/agents/pre-register", pre_reg_data)
        assert status == 201, f"Expected 201 Created, got {status}: {resp}"
        otc_code = resp["one_time_code"]
        agent_id = resp["agent_id"]
        assert otc_code.startswith("LTD-OTC-"), f"Invalid OTC format: {otc_code}"
        print(f"[PASS] 2. Pre-registration minted OTC: {otc_code} for {agent_id}")

        # 3. Edge Agent Registration with ltd-agent CLI
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_creds_path = tmp.name

        try:
            reg_cmd = [
                agent_exe, "register",
                "--server", base_url,
                "--code", otc_code,
                "--config", tmp_creds_path
            ]
            run_res = subprocess.run(reg_cmd, capture_output=True, text=True)
            assert run_res.returncode == 0, f"ltd-agent register failed: {run_res.stderr}\n{run_res.stdout}"
            assert os.path.exists(tmp_creds_path), "Credentials file not created"

            with open(tmp_creds_path, "r", encoding="utf-8") as f:
                creds = json.load(f)

            assert creds["agent_id"] == agent_id, f"Agent ID mismatch: {creds}"
            assert creds["status"] == "active", f"Status not active: {creds}"
            assert creds["session_token"], "Missing session token"
            print("[PASS] 3. Edge agent self-enrolled via CLI and received JWT session token")

            # 4. Anti-Spoofing: Replay Attack Defense (consuming burned OTC)
            run_replay = subprocess.run(reg_cmd, capture_output=True, text=True)
            assert run_replay.returncode != 0, "Replay attack should have failed!"
            assert "already been consumed" in run_replay.stderr or "Unauthorized" in run_replay.stderr
            print("[PASS] 4. Replay attack blocked: single-use OTC burned immediately")

            # 5. Production Profile: Attestation Enforces Whitelist
            # 5a. Rogue / Unmatched Hash in Production
            status, rogue_resp = http_post_json(f"{base_url}/api/v1/agents/pre-register", {
                "app_id": "payments-core",
                "owner_email": "secops@company.internal",
                "agent_name": "PaymentsAgentProd",
                "env_profile": "production",
                "allowed_binary_hashes": ["0000000000000000000000000000000000000000000000000000000000000000"]
            })
            assert status == 201
            rogue_otc = rogue_resp["one_time_code"]

            run_rogue = subprocess.run([
                agent_exe, "register",
                "--server", base_url,
                "--code", rogue_otc,
                "--config", tmp_creds_path + ".rogue"
            ], capture_output=True, text=True)
            assert run_rogue.returncode != 0, "Registration with mismatched prod hash should fail!"
            assert "attestation failed" in run_rogue.stderr.lower() or "forbidden" in run_rogue.stderr.lower()
            print("[PASS] 5a. Binary attestation rejected rogue binary hash in production")

            # 5b. Valid Hash in Production
            status, legit_resp = http_post_json(f"{base_url}/api/v1/agents/pre-register", {
                "app_id": "payments-core-legit",
                "owner_email": "secops@company.internal",
                "agent_name": "PaymentsAgentProdLegit",
                "env_profile": "production",
                "allowed_binary_hashes": [agent_hash]
            })
            assert status == 201
            legit_otc = legit_resp["one_time_code"]
            legit_agent_id = legit_resp["agent_id"]

            run_legit = subprocess.run([
                agent_exe, "register",
                "--server", base_url,
                "--code", legit_otc,
                "--config", tmp_creds_path + ".legit"
            ], capture_output=True, text=True)
            assert run_legit.returncode == 0, f"Registration failed with valid hash: {run_legit.stderr}"
            print("[PASS] 5b. Binary attestation authorized approved binary hash in production")

            # 6. Short-Lived Grants Acquisition
            status, grant_resp = http_post_json(f"{base_url}/api/v1/grants/acquire", {
                "agent_id": legit_agent_id,
                "binary_hash": agent_hash,
                "scopes": ["cli:exec"]
            })
            assert status == 200, f"Failed to acquire grant: {grant_resp}"
            assert grant_resp["token"], "Missing grant token"
            assert grant_resp["token_type"] == "Bearer"
            assert grant_resp["expires_in"] > 0
            print(f"[PASS] 6. Short-lived authority grant acquired (TTL: {grant_resp['expires_in']}s)")

            # 7. Grant Atomic Consumption (STS PEP Interface)
            status, consume_resp = http_post_json(f"{base_url}/api/v1/grants/consume", {
                "token": grant_resp["token"],
                "resource": "cli:exec"
            })
            assert status == 200, f"Failed to consume grant: {consume_resp}"
            assert consume_resp["consumed"] is True
            assert consume_resp["grant_id"], "Missing consumed grant ID"

            # Replay consumption must fail
            status, replay_consume = http_post_json(f"{base_url}/api/v1/grants/consume", {
                "token": grant_resp["token"],
                "resource": "cli:exec"
            })
            assert status == 403, "Replay consumption of grant should fail"
            print("[PASS] 7. Grant atomically consumed; replay consumption blocked")

            # 8. Central Policy Bundle & Remote Edge Sync
            status, bundle_resp = http_get_json(f"{base_url}/api/v1/policy/bundle")
            assert status == 200, f"Failed to get policy bundle: {bundle_resp}"
            assert bundle_resp["version"] >= 1
            assert bundle_resp["digest"], "Missing bundle rules digest"

            status, sync_resp = http_post_json(f"{base_url}/api/v1/policy/sync", {
                "agent_id": legit_agent_id,
                "installed_version": 0,
                "installed_digest": ""
            })
            assert status == 200
            assert sync_resp["directive"] == "UPDATE_REQUIRED"
            assert sync_resp["bundle"]["digest"] == bundle_resp["digest"]

            # When edge is up-to-date, directive is CURRENT
            status, sync_current = http_post_json(f"{base_url}/api/v1/policy/sync", {
                "agent_id": legit_agent_id,
                "installed_version": bundle_resp["version"],
                "installed_digest": bundle_resp["digest"]
            })
            assert status == 200
            assert sync_current["directive"] == "CURRENT"
            print("[PASS] 8. Central policy bundle distribution and remote sync verified")

            # 9. Central Audit Ingestion & Cryptographic Chain Verification
            audit_records = [
                {
                    "event_id": f"e2e-audit-{int(time.time())}-1",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "source": "claude-code",
                    "executable": "git",
                    "full_command": "git status",
                    "decision": "allow",
                    "duration_ms": 42,
                    "exit_code": 0
                },
                {
                    "event_id": f"e2e-audit-{int(time.time())}-2",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "source": "copilot",
                    "executable": "cat",
                    "full_command": "cat .env",
                    "decision": "deny",
                    "reason": "policy1",
                    "duration_ms": 2,
                    "exit_code": 1
                }
            ]
            status, ingest_resp = http_post_json(f"{base_url}/api/v1/audit/ingest", audit_records)
            assert status == 200, f"Failed to ingest audit records: {ingest_resp}"
            assert ingest_resp["ingested"] == 2
            assert ingest_resp["chain_valid"] is True

            status, audit_events_resp = http_get_json(f"{base_url}/api/v1/audit/events")
            assert status == 200
            assert audit_events_resp["chain_status"] == "valid"
            assert audit_events_resp["count"] >= 2
            print("[PASS] 9. Central audit ingestion and tamper-evident hash-chain verified")

            # 10. Remote Kill-Switch & Admin Security Verification
            # 10a-1. Unauthenticated kill-switch must be rejected (401 Unauthorized)
            status, unauth_resp = http_post_json(f"{base_url}/api/v1/control/kill-switch", {"enabled": True})
            assert status == 401, f"Expected 401 Unauthorized for unauthenticated kill-switch, got {status}"

            # 10a-2. Invalid/guessed admin token must be rejected (403 Forbidden)
            status, bad_token_resp = http_post_json(f"{base_url}/api/v1/control/kill-switch", {"enabled": True}, headers={"Authorization": "Bearer guessed-token"})
            assert status == 403, f"Expected 403 Forbidden for bad admin token, got {status}"

            # 10a-3. Admin login handshake verification
            status, login_resp = http_post_json(f"{base_url}/api/v1/auth/admin-login", {"token": admin_token})
            assert status == 200, f"Expected 200 for valid admin login, got {status}"
            assert login_resp["role"] == "ciso_admin"
            assert "kill_switch" in login_resp["permissions"]

            # 10a-4. Authorized kill-switch with valid admin token succeeds
            status, auth_ks_resp = http_post_json(f"{base_url}/api/v1/control/kill-switch", {"enabled": False}, headers={"X-BAP-Admin-Token": admin_token})
            assert status == 200, f"Expected 200 for authorized kill-switch, got {status}"
            print("[PASS] 10a. Admin API security verified: 401 on unauthenticated, 403 on invalid token, 200 with admin token")

            # 10b. Remote Kill-Switch (Revocation)
            status, revoke_resp = http_post_json(f"{base_url}/api/v1/agents/revoke", {
                "agent_id": legit_agent_id
            }, headers={"X-BAP-Admin-Token": admin_token})
            assert status == 200
            assert revoke_resp["status"] == "revoked"

            # Verify subsequent grant request is forbidden
            status, post_revoke_grant = http_post_json(f"{base_url}/api/v1/grants/acquire", {
                "agent_id": legit_agent_id,
                "binary_hash": agent_hash
            })
            assert status == 403, f"Expected 403 Forbidden after revocation, got {status}"
            print("[PASS] 10. Instant kill-switch verified: revoked agent cannot acquire authority grants")

            # 10b. Multi-Instance Fleet Enrollment & SPIFFE Workload Identity
            fleet_pre_reg = {
                "app_id": "fleet-deployer",
                "owner_email": "devops@company.internal",
                "agent_name": "FleetDeployerWorker",
                "env_profile": "dev",
                "allowed_binary_hashes": [agent_hash],
                "max_instances": 2
            }
            status, fleet_pre_resp = http_post_json(f"{base_url}/api/v1/agents/pre-register", fleet_pre_reg)
            assert status == 201, f"Expected 201 Created for fleet pre-register, got {status}"
            fleet_code = fleet_pre_resp["one_time_code"]
            assert fleet_code.startswith("BAP-FLEET-"), f"Expected BAP-FLEET- prefix, got {fleet_code}"
            print(f"[*] Fleet OTC generated: {fleet_code} (Max instances: 2)")

            # Enroll Instance 1
            tmp_fleet1 = tempfile.mktemp(prefix="creds_fleet1_")
            reg_proc1 = subprocess.run([
                agent_exe, "register",
                "--server", base_url,
                "--code", fleet_code,
                "--instance-id", "worker-node-01",
                "--config", tmp_fleet1
            ], capture_output=True, text=True)
            assert reg_proc1.returncode == 0, f"Fleet instance 1 registration failed: {reg_proc1.stderr}"
            with open(tmp_fleet1, "r", encoding="utf-8") as f:
                creds_fleet1 = json.load(f)
            assert creds_fleet1["instance_id"] == "worker-node-01"
            assert creds_fleet1["spiffe_id"] == "spiffe://bap.internal/app/fleet-deployer/instance/worker-node-01"
            print(f"[PASS] 10b-1. Instance 1 enrolled with SPIFFE ID: {creds_fleet1['spiffe_id']}")

            # Enroll Instance 2 using same fleet OTC
            tmp_fleet2 = tempfile.mktemp(prefix="creds_fleet2_")
            reg_proc2 = subprocess.run([
                agent_exe, "register",
                "--server", base_url,
                "--code", fleet_code,
                "--instance-id", "worker-node-02",
                "--config", tmp_fleet2
            ], capture_output=True, text=True)
            assert reg_proc2.returncode == 0, f"Fleet instance 2 registration failed: {reg_proc2.stderr}"
            with open(tmp_fleet2, "r", encoding="utf-8") as f:
                creds_fleet2 = json.load(f)
            assert creds_fleet2["instance_id"] == "worker-node-02"
            assert creds_fleet2["spiffe_id"] == "spiffe://bap.internal/app/fleet-deployer/instance/worker-node-02"
            print(f"[PASS] 10b-2. Instance 2 enrolled with SPIFFE ID: {creds_fleet2['spiffe_id']}")

            # Attempt to enroll Instance 3 (Quota Exceeded) -> Expect Failure
            tmp_fleet3 = tempfile.mktemp(prefix="creds_fleet3_")
            reg_proc3 = subprocess.run([
                agent_exe, "register",
                "--server", base_url,
                "--code", fleet_code,
                "--instance-id", "worker-node-03",
                "--config", tmp_fleet3
            ], capture_output=True, text=True)
            assert reg_proc3.returncode != 0, "Instance 3 must be rejected when quota is exceeded!"
            print("[PASS] 10b-3. Fleet quota enforcement: 3rd instance enrollment rejected")

            # Heartbeat check for Instance 1
            status, hb_resp = http_post_json(f"{base_url}/api/v1/instances/heartbeat", {
                "agent_id": creds_fleet1["agent_id"]
            })
            assert status == 200 and hb_resp.get("status") == "alive"
            print(f"[PASS] 10b-4. Liveness heartbeat verified for {creds_fleet1['agent_id']}")

            # Per-instance vs Fleet-level revocation
            # Revoke instance 1 specifically
            status, _ = http_post_json(f"{base_url}/api/v1/agents/revoke", {"agent_id": creds_fleet1["agent_id"]}, headers={"X-BAP-Admin-Token": admin_token})
            assert status == 200

            # Instance 1 grant should fail
            status, _ = http_post_json(f"{base_url}/api/v1/grants/acquire", {"agent_id": creds_fleet1["agent_id"], "binary_hash": agent_hash})
            assert status == 403, "Instance 1 should be forbidden after individual revocation"

            # Instance 2 grant should still SUCCEED!
            status, grant2 = http_post_json(f"{base_url}/api/v1/grants/acquire", {"agent_id": creds_fleet2["agent_id"], "binary_hash": agent_hash})
            assert status == 200, "Instance 2 should remain active"
            print("[PASS] 10b-5. Per-instance isolation verified: Revoking instance 1 did not affect instance 2")

            # App-level revocation (Fleet kill switch)
            status, app_rev_resp = http_post_json(f"{base_url}/api/v1/apps/revoke", {"app_id": "fleet-deployer"}, headers={"X-BAP-Admin-Token": admin_token})
            assert status == 200 and app_rev_resp.get("status") == "revoked"

            # Instance 2 grant should now also FAIL!
            status, _ = http_post_json(f"{base_url}/api/v1/grants/acquire", {"agent_id": creds_fleet2["agent_id"], "binary_hash": agent_hash})
            assert status == 403, "Instance 2 should be forbidden after app-level revocation"
            print("[PASS] 10b-6. App-level fleet revocation killed all remaining instances across the fleet")

            # Clean up fleet creds
            for p in [tmp_fleet1, tmp_fleet2, tmp_fleet3]:
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass

            # 10c. Agent Session Lifecycle & Real-Time Edge Telemetry Streaming
            sess_id = f"sess-claude-test-{uuid.uuid4().hex[:8]}"
            status, sess_start_resp = http_post_json(f"{base_url}/api/v1/sessions/start", {
                "session_id": sess_id,
                "app_id": "claude-code",
                "client_pid": os.getpid(),
                "hostname": "test-runner"
            })
            assert status == 200, f"Session start failed: {status}"
            assert sess_start_resp["status"] == "active"
            print(f"[*] Started agent session: {sess_id}")

            # Execute edge commands with --session-id and --server (simulating Claude Code / cchook)
            old_test_mode = os.environ.get("BAP_TEST_MODE")
            if "BAP_TEST_MODE" in os.environ:
                del os.environ["BAP_TEST_MODE"]
            try:
                cmd_exec1 = subprocess.run([
                    agent_exe, "exec",
                    "--source", "claude-code",
                    "--session-id", sess_id,
                    "--server", base_url,
                    "--raw", "git --version"
                ], capture_output=True, text=True)
                assert cmd_exec1.returncode == 0

                cmd_exec2 = subprocess.run([
                    agent_exe, "exec",
                    "--source", "claude-code",
                    "--session-id", sess_id,
                    "--server", base_url,
                    "--raw", "cat .env"
                ], capture_output=True, text=True)
                assert cmd_exec2.returncode != 0
            finally:
                if old_test_mode is not None:
                    os.environ["BAP_TEST_MODE"] = old_test_mode

            time.sleep(0.3)

            # Query session from control plane
            status, sess_detail = http_get_json(f"{base_url}/api/v1/sessions/{sess_id}")
            assert status == 200, f"Failed to get session {sess_id}: {status}"
            assert sess_detail["total_events"] >= 2, f"Expected >= 2 events, got {sess_detail['total_events']}"
            assert sess_detail["allowed_count"] >= 1, "Expected >= 1 allowed event"
            assert sess_detail["denied_count"] >= 1, "Expected >= 1 denied event"
            print(f"[PASS] 10c-1. Real-time edge telemetry streamed to control plane session ({sess_detail['total_events']} events)")

            # End the session
            status, sess_end_resp = http_post_json(f"{base_url}/api/v1/sessions/end", {
                "session_id": sess_id,
                "reason": "agent test completed"
            })
            assert status == 200
            assert sess_end_resp["status"] == "closed"
            print(f"[PASS] 10c-2. Session {sess_id} successfully closed upon agent shutdown")

            # 10c-3. Verify agent registry marks agent deregistered and dashboard live count is 0
            status, agents_resp = http_get_json(f"{base_url}/api/v1/agents")
            assert status == 200
            agents_list = agents_resp.get("agents", []) if isinstance(agents_resp, dict) else agents_resp
            matching_agents = [a for a in agents_list if a.get("app_id") == "claude-code"]
            assert any(a.get("status") == "deregistered" for a in matching_agents), "Agent was not marked deregistered in registry"

            status, inspector_resp = http_get_json(f"{base_url}/api/v1/inspector/data", headers={"Authorization": f"Bearer {admin_token}"})
            assert status == 200
            active_sessions = [s for s in inspector_resp.get("sessions", []) if s.get("status") == "active"]
            assert not any(s.get("session_id") == sess_id for s in active_sessions), "Session still active on inspector dashboard"
            print(f"[PASS] 10c-3. Agent cleanly deregistered from registry and Live Radar")

            # 10d. Antigravity IDE First-Class Session & Live Workload Radar Presence
            ag_sess_id = f"sess-antigravity-{uuid.uuid4().hex[:8]}"
            status, ag_start = http_post_json(f"{base_url}/api/v1/sessions/start", {
                "session_id": ag_sess_id,
                "app_id": "antigravity",
                "client_pid": os.getpid(),
                "hostname": "antigravity-dev-box"
            })
            assert status == 200, f"Antigravity session start failed: {status}"
            assert ag_start["status"] == "active"
            print(f"[*] Started Antigravity session: {ag_sess_id}")

            status, ag_radar = http_get_json(f"{base_url}/api/v1/inspector/data", headers={"Authorization": f"Bearer {admin_token}"})
            assert status == 200
            active_ag = [s for s in ag_radar.get("sessions", []) if s.get("session_id") == ag_sess_id]
            assert len(active_ag) == 1, f"Antigravity session {ag_sess_id} missing from Live Workload Radar"
            assert active_ag[0]["app_id"] == "antigravity"

            # Stream allowed & denied commands from Antigravity
            old_test_mode = os.environ.get("BAP_TEST_MODE")
            if "BAP_TEST_MODE" in os.environ:
                del os.environ["BAP_TEST_MODE"]
            try:
                ag_exec_allow = subprocess.run([
                    agent_exe, "exec",
                    "--source", "antigravity",
                    "--session-id", ag_sess_id,
                    "--server", base_url,
                    "--raw", "git status"
                ], capture_output=True, text=True)
                assert ag_exec_allow.returncode == 0

                ag_exec_deny = subprocess.run([
                    agent_exe, "exec",
                    "--source", "antigravity",
                    "--session-id", ag_sess_id,
                    "--server", base_url,
                    "--raw", "type .env"
                ], capture_output=True, text=True)
                assert ag_exec_deny.returncode != 0
            finally:
                if old_test_mode is not None:
                    os.environ["BAP_TEST_MODE"] = old_test_mode

            time.sleep(0.3)

            # Query Antigravity session telemetry
            status, ag_detail = http_get_json(f"{base_url}/api/v1/sessions/{ag_sess_id}")
            assert status == 200
            assert ag_detail["total_events"] >= 2, f"Expected >= 2 Antigravity events, got {ag_detail['total_events']}"
            assert ag_detail["allowed_count"] >= 1
            assert ag_detail["denied_count"] >= 1
            print(f"[PASS] 10d-1. Antigravity IDE workload enrolled and streaming telemetry to Live Radar ({ag_detail['total_events']} events)")

            # End Antigravity session
            status, ag_end = http_post_json(f"{base_url}/api/v1/sessions/end", {
                "session_id": ag_sess_id,
                "reason": "antigravity paired session finished"
            })
            assert status == 200
            print(f"[PASS] 10d-2. Antigravity session {ag_sess_id} deregistered cleanly from control plane")

            # 11. Control Plane DOWN Resilience (Operating with Prior Secure Settings)
            tmp_policy_dir = tempfile.mkdtemp(prefix="bap_policy_cache_")
            try:
                # 11a. Sync policy to cache while control plane is online
                sync_proc = subprocess.run([
                    agent_exe, "sync",
                    "--server", base_url,
                    "--policy-dir", tmp_policy_dir
                ], capture_output=True, text=True)
                assert sync_proc.returncode == 0, f"bapedge sync failed: {sync_proc.stderr}"
                cached_cedar = os.path.join(tmp_policy_dir, "policy.cedar")
                assert os.path.exists(cached_cedar), "Cached policy.cedar not found"

                # 11b. Kill the control plane process completely (Simulate outage)
                print("[*] Terminating bapcontrolplane to simulate control plane outage...")
                server_proc.terminate()
                try:
                    server_proc.wait(timeout=3)
                except Exception:
                    server_proc.kill()

                # Verify server is indeed DOWN (connection refused)
                server_dead = False
                try:
                    http_get_json(f"{base_url}/api/v1/health")
                except Exception:
                    server_dead = True
                assert server_dead, "Server should be dead!"
                print("[*] bapcontrolplane is verified DOWN (Connection Refused).")

                # 11c. bapedge sync reports offline fallback and succeeds using prior settings
                offline_sync = subprocess.run([
                    agent_exe, "sync",
                    "--server", base_url,
                    "--policy-dir", tmp_policy_dir
                ], capture_output=True, text=True)
                assert offline_sync.returncode == 0
                assert "OFFLINE RESILIENCE ACTIVE" in offline_sync.stdout
                print("[PASS] 11a. bapedge sync detected offline control plane and fell back to prior cache")

                # 11d. bapedge exec evaluates commands securely using cached policy while server is DOWN
                run_allowed_offline = subprocess.run([
                    agent_exe, "exec",
                    "--policy", cached_cedar,
                    "--raw", "git --version"
                ], capture_output=True, text=True)
                assert run_allowed_offline.returncode == 0, f"Allowed offline execution failed: {run_allowed_offline.stderr}"
                print("[PASS] 11b. Allowed command executed successfully while control plane was DOWN")

                run_forbidden_offline = subprocess.run([
                    agent_exe, "exec",
                    "--policy", cached_cedar,
                    "--raw", "cat .env"
                ], capture_output=True, text=True)
                assert run_forbidden_offline.returncode != 0, "Forbidden command must be denied offline!"
                print("[PASS] 11c. Forbidden command denied by cached security invariants while control plane was DOWN")

                # 11e. Kill-Switch Persistence Offline
                # Write persistent kill-switch in cached policy-state.json
                state_path = os.path.join(tmp_policy_dir, "policy-state.json")
                with open(state_path, "w", encoding="utf-8") as f:
                    json.dump({"version": 1, "digest": "dummy", "kill_switch": True}, f)

                run_killswitch_offline = subprocess.run([
                    agent_exe, "exec",
                    "--policy", cached_cedar,
                    "--raw", "git --version"
                ], capture_output=True, text=True)
                assert run_killswitch_offline.returncode != 0, "Kill-switch must block execution offline!"
                assert "kill-switch is active" in run_killswitch_offline.stdout.lower() or "kill-switch is active" in run_killswitch_offline.stderr.lower()
                print("[PASS] 11d. Kill-switch persisted offline: network partition cannot bypass emergency lock")

            finally:
                import shutil
                shutil.rmtree(tmp_policy_dir, ignore_errors=True)

        finally:
            for p in [tmp_creds_path, tmp_creds_path + ".rogue", tmp_creds_path + ".legit"]:
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass

    finally:
        if server_proc.stdout:
            try:
                server_proc.stdout.close()
            except Exception:
                pass
        if server_proc.stderr:
            try:
                server_proc.stderr.close()
            except Exception:
                pass
        server_proc.terminate()
        try:
            server_proc.wait(timeout=3)
        except Exception:
            server_proc.kill()

    print("\n==================================================")
    print("  ALL CONTROL PLANE INTEGRATION TESTS PASSED!")
    print("==================================================")

if __name__ == "__main__":
    main()
