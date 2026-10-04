"""
Automated Test Suite for BAP-450 through BAP-459:
Operations & Governance Extension Architecture
===============================================
Verifies:
1. BAP-450: Immutable Action Proposals
2. BAP-451: Proposal Lineage & Remediation
3. BAP-452: Governance of Administrative Actions ("BAP governs BAP")
4. BAP-453: Operations RBAC & Separation of Duties (Anti-Self-Approval)
5. BAP-454: Out-of-band Execution Path Decoupling
6. BAP-455: Governed Action Lifecycle State Machine & Transition Validation
7. BAP-456: Execution Reconciliation & Orphan Detection
8. BAP-457: Governance Test/Simulation Framework
9. BAP-458: Cryptographically Linked Governance Evidence
10. BAP-459: Operations Investigation Timeline Reconstruction
"""

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
CONTROL_PLANE_BIN = os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapcontrolplane.exe")

TEST_SECRET = "gov-extension-test-signing-key-32-chars-long-ok!"
TEST_ADMIN_TOKEN = "gov-test-admin-secret-token-12345"
CP_PORT = 19180
CP_URL = f"http://127.0.0.1:{CP_PORT}"


def http_req(url, method="GET", data=None, headers=None):
    hdrs = headers or {}
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


class TestGovernanceExtension(unittest.TestCase):
    cp_proc = None
    tmp_dir = None

    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="bap_gov_")
        db_path = os.path.join(cls.tmp_dir, "test-gov.db")

        env = os.environ.copy()
        env["BAP_SECRET_KEY"] = TEST_SECRET
        env["BAP_ADMIN_TOKEN"] = TEST_ADMIN_TOKEN

        cls.cp_proc = subprocess.Popen(
            [
                CONTROL_PLANE_BIN,
                "-port", str(CP_PORT),
                "-secret", TEST_SECRET,
                "-admin-token", TEST_ADMIN_TOKEN,
                "-db", db_path,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            cwd=WORKSPACE_ROOT,
        )

        healthy = False
        for _ in range(30):
            try:
                status, _, _ = http_req(f"{CP_URL}/health")
                if status == 200:
                    healthy = True
                    break
            except Exception:
                pass
            time.sleep(0.1)
        if not healthy:
            raise RuntimeError(f"Control Plane failed to start on port {CP_PORT}")

    @classmethod
    def tearDownClass(cls):
        if cls.cp_proc:
            cls.cp_proc.terminate()
            try:
                cls.cp_proc.wait(timeout=2)
            except Exception:
                cls.cp_proc.kill()
        if cls.tmp_dir and os.path.exists(cls.tmp_dir):
            shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # BAP-450: Immutable Action Proposal
    # -------------------------------------------------------------------------
    def test_bap450_immutable_action_proposal(self):
        payload = {
            "agent_id": "claude-worker-1",
            "session_id": "sess-alpha-1",
            "task_id": "task-update-address",
            "human_id": "alice@company.com",
            "intent": "BUG_FIX",
            "action": "customer.address.update",
            "resource": "customer/124",
            "parameters": {"address": "123 Wrong Street"},
        }
        status, resp, _ = http_req(f"{CP_URL}/api/v1/governance/proposals", method="POST", data=payload)
        self.assertEqual(status, 201)
        proposal_id = resp.get("proposal_id")
        self.assertTrue(proposal_id.startswith("prop-"))
        self.assertEqual(resp.get("state"), "PROPOSED")
        self.assertEqual(resp.get("action"), "customer.address.update")
        self.assertEqual(resp.get("resource"), "customer/124")

        # Query proposal
        status, get_resp, _ = http_req(f"{CP_URL}/api/v1/governance/proposals/{proposal_id}")
        self.assertEqual(status, 200)
        self.assertEqual(get_resp.get("proposal_id"), proposal_id)

    # -------------------------------------------------------------------------
    # BAP-451: Proposal Lineage & Remediation
    # -------------------------------------------------------------------------
    def test_bap451_proposal_lineage_and_remediation(self):
        # 1. Submit parent proposal
        p1_payload = {
            "agent_id": "claude-worker-1",
            "task_id": "task-remediate-1",
            "human_id": "alice@company.com",
            "action": "customer.address.update",
            "resource": "customer/124",
        }
        status, p1, _ = http_req(f"{CP_URL}/api/v1/governance/proposals", method="POST", data=p1_payload)
        self.assertEqual(status, 201)
        p1_id = p1["proposal_id"]

        # Transition parent to DENIED
        http_req(
            f"{CP_URL}/api/v1/governance/proposals/{p1_id}/transition",
            method="POST",
            data={"to_state": "DENIED", "actor": "policy-engine", "reason": "Target customer 124 inactive"},
        )

        # 2. Operator remediates: creates child proposal P2
        rem_payload = {
            "operator_id": "operator-bob@company.com",
            "reason": "Corrected customer target to 123",
            "resource": "customer/123",
            "parameters": {"address": "123 Correct Street"},
        }
        status, p2, _ = http_req(
            f"{CP_URL}/api/v1/governance/proposals/{p1_id}/remediate",
            method="POST",
            data=rem_payload,
        )
        self.assertEqual(status, 201)
        self.assertEqual(p2.get("parent_proposal_id"), p1_id)
        self.assertEqual(p2.get("resource"), "customer/123")
        self.assertEqual(p2.get("state"), "PROPOSED")
        self.assertEqual(p2.get("remediated_by"), "operator-bob@company.com")

        # Verify parent P1 remained unchanged (Rule R1)
        _, parent_check, _ = http_req(f"{CP_URL}/api/v1/governance/proposals/{p1_id}")
        self.assertEqual(parent_check.get("state"), "DENIED")
        self.assertEqual(parent_check.get("resource"), "customer/124")

    # -------------------------------------------------------------------------
    # BAP-452: Govern BAP Administrative Actions ("BAP governs BAP")
    # -------------------------------------------------------------------------
    def test_bap452_govern_bap_administrative_actions(self):
        admin_action = {
            "admin_id": "sec-admin-dave@company.com",
            "role": "PolicyAdmin",
            "action": "policy_change",
            "target": "policy.cedar:v3",
            "details": {"change": "tighten egress boundaries"},
        }
        # Calling without admin token must fail (401)
        status, _, _ = http_req(
            f"{CP_URL}/api/v1/governance/admin/action",
            method="POST",
            data=admin_action,
        )
        self.assertEqual(status, 401)

        # Calling with valid admin token succeeds (BAP-452)
        status, resp, _ = http_req(
            f"{CP_URL}/api/v1/governance/admin/action",
            method="POST",
            data=admin_action,
            headers={"X-BAP-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertEqual(resp.get("status"), "EXECUTED")

    # -------------------------------------------------------------------------
    # BAP-453: Operations RBAC & Separation of Duties (Anti-Self-Approval)
    # -------------------------------------------------------------------------
    def test_bap453_operations_rbac_and_separation_of_duties(self):
        # 1. Create proposal by Alice
        p_payload = {
            "agent_id": "worker-2",
            "human_id": "alice@company.com",
            "action": "subscription.cancel",
            "resource": "subscription/789",
        }
        _, p, _ = http_req(f"{CP_URL}/api/v1/governance/proposals", method="POST", data=p_payload)
        p_id = p["proposal_id"]

        # 2. Alice tries to approve her own proposal -> MUST FAIL (403 Separation of Duties)
        status, resp, _ = http_req(
            f"{CP_URL}/api/v1/governance/proposals/{p_id}/approve",
            method="POST",
            data={"approver_id": "alice@company.com", "reason": "Self-approval"},
        )
        self.assertEqual(status, 403)
        self.assertIn("separation of duties violation", resp.get("error", "").lower())

        # 3. Independent manager Charlie approves -> SUCCEEDS
        status, resp, _ = http_req(
            f"{CP_URL}/api/v1/governance/proposals/{p_id}/approve",
            method="POST",
            data={"approver_id": "charlie-manager@company.com", "reason": "Approved by supervisor"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(resp.get("state"), "AUTHORIZED")

    # -------------------------------------------------------------------------
    # BAP-454: Management UI Outside Execution Path
    # -------------------------------------------------------------------------
    def test_bap454_management_ui_outside_execution_path(self):
        # Health check and proposals endpoints work with zero dependency on UI process
        status, health, _ = http_req(f"{CP_URL}/health")
        self.assertEqual(status, 200)
        status, proposals, _ = http_req(f"{CP_URL}/api/v1/governance/proposals")
        self.assertEqual(status, 200)
        self.assertIn("proposals", proposals)

    # -------------------------------------------------------------------------
    # BAP-455: Governed Action Lifecycle State Machine
    # -------------------------------------------------------------------------
    def test_bap455_governed_action_lifecycle_state_machine(self):
        _, p, _ = http_req(
            f"{CP_URL}/api/v1/governance/proposals",
            method="POST",
            data={"agent_id": "agent-flow", "action": "data.sync", "resource": "warehouse/events"},
        )
        p_id = p["proposal_id"]

        # Illegal transition directly to COMPLETED must fail 400
        status, _, _ = http_req(
            f"{CP_URL}/api/v1/governance/proposals/{p_id}/transition",
            method="POST",
            data={"to_state": "COMPLETED", "actor": "rogue", "reason": "skip steps"},
        )
        self.assertEqual(status, 400)

        # Valid transition PROPOSED -> EVALUATING
        status, p_eval, _ = http_req(
            f"{CP_URL}/api/v1/governance/proposals/{p_id}/transition",
            method="POST",
            data={"to_state": "EVALUATING", "actor": "evaluator", "reason": "Evaluating against Cedar"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(p_eval.get("state"), "EVALUATING")

    # -------------------------------------------------------------------------
    # BAP-456: Execution Reconciliation & Orphan Detection
    # -------------------------------------------------------------------------
    def test_bap456_execution_reconciliation_orphan_detection(self):
        status, report, _ = http_req(
            f"{CP_URL}/api/v1/governance/reconciliation",
            headers={"X-BAP-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertIn("unpresented_grants", report)
        self.assertIn("unconfirmed_executions", report)

    # -------------------------------------------------------------------------
    # BAP-457: Governance Test / Simulation Framework
    # -------------------------------------------------------------------------
    def test_bap457_governance_simulation_framework(self):
        sim_payload = {
            "agent_id": "sim-tester",
            "action": "subscription.cancel",
            "resource": "subscription/789",
            "expected": "APPROVAL_REQUIRED",
        }
        status, resp, _ = http_req(
            f"{CP_URL}/api/v1/governance/simulate",
            method="POST",
            data=sim_payload,
        )
        self.assertEqual(status, 200)
        self.assertTrue(resp.get("is_test"))
        self.assertEqual(resp.get("evaluation_result"), "APPROVAL_REQUIRED")
        self.assertTrue(resp.get("match_expected"))

    # -------------------------------------------------------------------------
    # BAP-458 & BAP-459: Cryptographically Linked Evidence & Timeline
    # -------------------------------------------------------------------------
    def test_bap458_and_bap459_investigation_timeline_reconstruction(self):
        # 1. Create root proposal
        _, p1, _ = http_req(
            f"{CP_URL}/api/v1/governance/proposals",
            method="POST",
            data={"agent_id": "a1", "task_id": "task-composite-1", "action": "db.drop", "resource": "prod/db"},
        )
        p1_id = p1["proposal_id"]

        # 2. Deny P1
        http_req(
            f"{CP_URL}/api/v1/governance/proposals/{p1_id}/transition",
            method="POST",
            data={"to_state": "DENIED", "actor": "policy", "reason": "Destructive drop forbidden"},
        )

        # 3. Remediate to P2
        _, p2, _ = http_req(
            f"{CP_URL}/api/v1/governance/proposals/{p1_id}/remediate",
            method="POST",
            data={"operator_id": "op-dan", "reason": "Changed to non-destructive backup", "action": "db.backup"},
        )
        p2_id = p2["proposal_id"]

        # 4. Query Timeline (BAP-458 & BAP-459)
        status, timeline, _ = http_req(f"{CP_URL}/api/v1/governance/timeline/{p2_id}")
        self.assertEqual(status, 200)
        self.assertEqual(timeline.get("root_proposal_id"), p1_id)
        self.assertEqual(timeline.get("lineage"), [p1_id, p2_id])
        self.assertTrue(len(timeline.get("nodes", [])) >= 2)
        node_stages = [n["stage"] for n in timeline.get("nodes", [])]
        self.assertIn("TASK", node_stages)
        self.assertIn("PROPOSAL", node_stages)


if __name__ == "__main__":
    unittest.main()
