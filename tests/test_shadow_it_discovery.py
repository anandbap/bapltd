"""Authenticated workstation discovery: metadata-only reports, lifecycle and fleet integration.
No test asks the control plane to inspect its filesystem or credential files.
"""

from datetime import datetime, timezone
import uuid
import concurrent.futures
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONTROL_PLANE_BIN = os.environ.get("BAP_CONTROLPLANE_BIN") or os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapcontrolplane.exe")

TEST_SECRET = "shadow-it-discovery-test-secret-32b!"
TEST_ADMIN_TOKEN = "shadow-it-admin-token-123456"
CP_PORT = 19255
CP_URL = f"http://127.0.0.1:{CP_PORT}"


def http_req(url, method="GET", data=None, headers=None, retries=2):
    """Robust HTTP request helper with connection close and retries."""
    hdrs = dict(headers or {})
    # Fleet simulation is seeded by this test server's authorized operator.
    if method == "POST" and url.startswith(CP_URL + "/api/v1/sessions/"):
        hdrs.setdefault("X-BAP-Admin-Token", TEST_ADMIN_TOKEN)
    if "Connection" not in hdrs:
        hdrs["Connection"] = "close"
    body_bytes = None
    if data is not None:
        if isinstance(data, (dict, list)):
            body_bytes = json.dumps(data).encode("utf-8")
            if "Content-Type" not in hdrs:
                hdrs["Content-Type"] = "application/json"
        elif isinstance(data, str):
            body_bytes = data.encode("utf-8")
        else:
            body_bytes = data

    for attempt in range(retries):
        req = urllib.request.Request(url, data=body_bytes, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                raw = resp.read()
                parsed = {}
                try:
                    parsed = json.loads(raw.decode("utf-8"))
                except Exception:
                    pass
                return resp.status, parsed, raw
        except urllib.error.HTTPError as e:
            raw = e.read()
            parsed = {}
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except Exception:
                pass
            return e.code, parsed, raw
        except Exception:
            if attempt == retries - 1:
                raise
            time.sleep(0.15)


class TestShadowITDiscovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="bap_shadow_it_test_")
        cls.db_path = os.path.join(cls.temp_dir, "test_shadow_it.db")
        cls.worm_path = os.path.join(cls.temp_dir, "worm_audit")
        os.makedirs(cls.worm_path, exist_ok=True)

        env = os.environ.copy()
        env["BAP_SECRET_KEY"] = TEST_SECRET
        env["BAP_ADMIN_TOKEN"] = TEST_ADMIN_TOKEN

        cls.cp_proc = subprocess.Popen(
            [
                CONTROL_PLANE_BIN,
                "-port", str(CP_PORT),
                "-secret", TEST_SECRET,
                "-admin-token", TEST_ADMIN_TOKEN,
                "-allow-remote-admin",
                "-db", cls.db_path,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            cwd=WORKSPACE_ROOT,
        )

        ready = False
        for _ in range(30):
            try:
                status, _, _ = http_req(f"{CP_URL}/health")
                if status == 200:
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.15)

        if not ready:
            if cls.cp_proc:
                cls.cp_proc.terminate()
            raise RuntimeError(f"Control Plane failed to start on port {CP_PORT}")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "cp_proc") and cls.cp_proc:
            cls.cp_proc.terminate()
            try:
                cls.cp_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cls.cp_proc.kill()
        if os.path.exists(cls.temp_dir):
            shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def enroll(self, instance):
        admin = {"X-BAP-Admin-Token": TEST_ADMIN_TOKEN}
        code, registered, _ = http_req(CP_URL + "/api/v1/agents/pre-register", "POST", {
            "app_id": "discovery-" + instance, "owner_email": "pilot@example.test",
            "agent_name": "Discovery test", "env_profile": "dev",
            "allowed_binary_hashes": ["synthetic-hash"], "permitted_scopes": ["cli:exec"]}, admin)
        self.assertEqual(code, 201, registered)
        code, enrolled, _ = http_req(CP_URL + "/api/v1/agents/register", "POST", {
            "one_time_code": registered["one_time_code"], "binary_hash": "synthetic-hash", "instance_id": instance,
            "hostname": "synthetic-laptop", "os": "windows", "arch": "amd64"})
        self.assertEqual(code, 200, enrolled)
        if not hasattr(self, "enrolled_agents"):
            self.enrolled_agents = {}
        self.enrolled_agents[instance] = enrolled["agent_id"]
        return {"Authorization": "Bearer " + enrolled["session_token"]}

    def report(self, names=(), status="complete", epoch=0):
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return {"version": 1, "run_id": uuid.uuid4().hex, "epoch": epoch,
                "started_at": now, "completed_at": now, "status": status,
                "scopes": [{"id": "project-mcp", "status": "complete" if status == "complete" else "error"}],
                "observations": [{"key": "mcp-" + name, "scope": "project-mcp", "kind": "mcp_config",
                                  "name": name, "client": "claude-code", "evidence": "configured",
                                  "observed_at": now} for name in names]}

    def read(self, suffix):
        status, result, _ = http_req(CP_URL + "/api/v1/discovery/shadow-it/" + suffix,
                                    headers={"X-BAP-Admin-Token": TEST_ADMIN_TOKEN})
        self.assertEqual(status, 200, result)
        return result

    def test_01_authenticated_clean_completion_and_privacy(self):
        proof = self.enroll("clean-machine")
        path = CP_URL + "/api/v1/discovery/shadow-it/scan"
        report = self.report()
        self.assertEqual(http_req(path, "POST", report)[0], 401)
        for forbidden in ({"workspace_root": "C:/"}, {"env_map": {"PRIVATE": "synthetic"}},
                          {**report, "instance_id": "forged"}, {**report, "config_paths": ["outside"]}):
            self.assertEqual(http_req(path, "POST", forbidden, proof)[0], 400)
        code, ack, _ = http_req(path, "POST", report, proof)
        self.assertEqual(code, 200, ack)
        self.assertFalse(ack["durable"])
        self.assertEqual(ack["instance_id"], "clean-machine")
        reports = self.read("reports")["reports"]
        self.assertTrue(any(r["instance_id"] == "clean-machine" and r["status"] == "complete" for r in reports))

    def test_02_multiserver_stability_and_idempotency(self):
        proof = self.enroll("multiserver")
        report = self.report(["filesystem", "database"])
        path = CP_URL + "/api/v1/discovery/shadow-it/scan"
        self.assertEqual(http_req(path, "POST", report, proof)[0], 200)
        self.assertTrue(http_req(path, "POST", report, proof)[1]["duplicate"])
        report["observations"][0]["name"] = "changed"
        self.assertEqual(http_req(path, "POST", report, proof)[0], 409)
        findings = self.read("findings?instance_id=multiserver")["findings"]
        self.assertEqual(len(findings), 2)
        self.assertEqual(len({a["id"] for a in findings}), 2)
        self.assertTrue(all(a["mediation"] == "not_observed" for a in findings))

    def test_03_partial_scope_cannot_resolve_findings(self):
        proof = self.enroll("partial-machine")
        path = CP_URL + "/api/v1/discovery/shadow-it/scan"
        self.assertEqual(http_req(path, "POST", self.report(["server"]), proof)[0], 200)
        self.assertEqual(http_req(path, "POST", self.report(status="partial"), proof)[0], 200)
        findings = self.read("findings?instance_id=partial-machine")["findings"]
        self.assertEqual(findings[0]["state"], "present")
        self.assertEqual(http_req(path, "POST", self.report(), proof)[0], 200)
        self.assertEqual(self.read("findings?instance_id=partial-machine")["findings"][0]["state"], "not_seen")

    def test_04_operator_only_reads_mutations_and_expiring_exception(self):
        proof = self.enroll("review-machine")
        base = CP_URL + "/api/v1/discovery/shadow-it/"
        for suffix in ("findings", "reports", "summary"):
            self.assertIn(http_req(base + suffix)[0], (401, 403))
            self.assertIn(http_req(base + suffix, headers=proof)[0], (401, 403))
        http_req(base + "scan", "POST", self.report(["review"]), proof)
        asset = self.read("findings?instance_id=review-machine")["findings"][0]
        admin = {"X-BAP-Admin-Token": TEST_ADMIN_TOKEN}
        body = {"id": asset["id"], "state": "exception", "reason": "Pilot review"}
        self.assertEqual(http_req(base + "disposition", "POST", body, admin)[0], 400)
        body["state"] = "acknowledged"
        self.assertEqual(http_req(base + "disposition", "POST", body, admin)[0], 200)
        self.assertEqual(self.read("findings?instance_id=review-machine")["findings"][0]["disposition"], "acknowledged")

    def test_05_master_heartbeat_receives_targeted_directive(self):
        proof = self.enroll("target-machine")
        base = CP_URL + "/api/v1/discovery/shadow-it/"
        admin = {"X-BAP-Admin-Token": TEST_ADMIN_TOKEN}
        self.assertIn(http_req(base + "scan/trigger", "POST", {"scope": "fleet"}, proof)[0], (401, 403))
        code, queued, _ = http_req(base + "scan/trigger", "POST", {"scope": "selected", "instances": ["target-machine"]}, admin)
        self.assertEqual(code, 202, queued)
        code, heartbeat, _ = http_req(CP_URL + "/api/v1/control/heartbeat", "POST", {"agent_id": self.enrolled_agents["target-machine"], "instance_id": "target-machine"}, proof)
        self.assertEqual(code, 200, heartbeat)
        self.assertEqual(heartbeat["scan_epoch"], queued["scan_epoch"])

    def test_06_twenty_workstations_concurrent_independent_reports(self):
        def laptop(index):
            instance = "fleet-" + str(index)
            proof = self.enroll(instance)
            code, result, _ = http_req(CP_URL + "/api/v1/discovery/shadow-it/scan", "POST", self.report(["server-one", "server-two"]), proof)
            self.assertEqual(code, 200, result)
            return instance
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            instances = list(pool.map(laptop, range(20)))
        for instance in instances:
            self.assertEqual(self.read("findings?instance_id=" + instance)["count"], 2)


if __name__ == "__main__":
    unittest.main()
