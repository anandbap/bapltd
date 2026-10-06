"""
Epic 28: Agent Watch Persona Architecture, Canonical Activity Telemetry & Intent Deviation
=============================================================================================
Validates BAP-520 through BAP-525:
1. BAP-520: Persona Control Plane Experience (CIO, CISO, SRE/Ops, IT Enablement).
2. BAP-521: Canonical Agent Activity Event Schema & Ingestion.
3. BAP-522: Live Agent Activity Service (HTTP & SSE stream).
4. BAP-523: CIO AI Workforce Pulse & Sub-Intent Drill-Down.
5. BAP-524: Live Agent Map & Enterprise Activity Topology.
6. BAP-525: Intent -> Action Contract & Critical Deviation Detection.
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
CONTROL_PLANE_DIR = os.path.join(WORKSPACE_ROOT, "bap-controlplane")

CP_PORT = 19385
CP_URL = f"http://127.0.0.1:{CP_PORT}"
TEST_ADMIN_TOKEN = "persona-activity-test-admin-token-12345"


def http_req(url, method="GET", data=None, headers=None, retries=2):
    hdrs = dict(headers or {})
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
        except Exception as e:
            if attempt == retries - 1:
                raise e
            time.sleep(0.5)
    return 500, {}, b""


class TestPersonaAndActivityService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="bap_persona_test_")
        cls.proc = subprocess.Popen(
            [
                "go",
                "run",
                "./cmd/server",
                "-port",
                str(CP_PORT),
                "-admin-token",
                TEST_ADMIN_TOKEN,
                "-allow-remote-admin",
                "-db",
                "memory",
            ],
            cwd=CONTROL_PLANE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        started = False
        for _ in range(30):
            try:
                code, data, _ = http_req(f"{CP_URL}/api/v1/health")
                if code == 200:
                    started = True
                    break
            except Exception:
                time.sleep(0.3)
        if not started:
            cls.tearDownClass()
            raise RuntimeError("Failed to start control plane for persona test suite")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "proc") and cls.proc:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        if hasattr(cls, "tmp_dir") and os.path.exists(cls.tmp_dir):
            shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def test_01_persona_controlplane_views(self):
        """BAP-520: Persona Control Plane endpoints return UI cockpit supporting persona query parameter."""
        for p in ["cio", "ciso", "ops", "it"]:
            code, _, raw = http_req(f"{CP_URL}/dashboard?persona={p}")
            self.assertEqual(code, 200, f"Expected 200 for persona={p}")
            html = raw.decode("utf-8")
            self.assertIn("BAP Control Plane", html)
            self.assertIn('data-p="cio"', html)
            self.assertIn('data-p="ciso"', html)
            self.assertIn('data-p="ops"', html)
            self.assertIn('data-p="it"', html)
            self.assertIn("AI Workforce Pulse", html)

    def test_02_canonical_activity_event_ingestion(self):
        """BAP-521: Canonical AgentActivityEvent schema ingestion and retrieval."""
        event = {
            "timestamp": "2026-10-05T09:00:00Z",
            "session_id": "sess-test-canonical-101",
            "agent_id": "agent-claude-test-01",
            "agent_type": "claude-code",
            "runtime_id": "macbook-pro-419",
            "user_id": "dev@enterprise.internal",
            "business_unit": "Payments Engineering",
            "application": "checkout-api",
            "prompt_id": "prmpt-81923",
            "prompt_summary": "Investigating checkout latency spike following deployment",
            "intent": "PRODUCTION_DIAGNOSIS",
            "intent_category": "Investigate / Diagnose",
            "action": "kubectl logs -n prod deploy/checkout-api --tail=100",
            "tool": "kubectl",
            "target_resource": "k8s://prod/checkout-api",
            "data_classification": "Internal",
            "policy_decision": "ALLOW",
            "risk_score": 0.12,
            "grant_id": "zsp-pay-read-991",
            "grant_scope": "read:observability",
            "grant_ttl": 300,
            "action_status": "working",
            "outcome_category": "Success",
            "trace_id": "tr-pay-8192301",
        }

        code, resp, _ = http_req(f"{CP_URL}/api/activity/ingest", method="POST", data=event)
        self.assertEqual(code, 200)
        self.assertEqual(resp.get("status"), "ingested")
        self.assertEqual(resp.get("session_id"), "sess-test-canonical-101")
        self.assertEqual(resp.get("deviation"), "NONE")

    def test_03_live_activity_service(self):
        """BAP-522: Live activity endpoints return valid telemetry for live and demo mode."""
        # 1. Live activities list (contains the ingested event from test_02)
        code, resp, _ = http_req(f"{CP_URL}/api/activity/live?limit=10")
        self.assertEqual(code, 200)
        acts = resp.get("activities", [])
        self.assertIsInstance(acts, list)
        self.assertGreaterEqual(len(acts), 1)

        # 2. Live Activity summary (computed dynamically from live activity)
        code, sum_resp, _ = http_req(f"{CP_URL}/api/activity/summary")
        self.assertEqual(code, 200)
        self.assertIn("total_active_agents", sum_resp)
        self.assertIn("governed_percent", sum_resp)
        self.assertIn("business_units_active", sum_resp)

        # 3. Demo mode Activity summary (simulated 1,284 agents dataset)
        code, demo_sum, _ = http_req(f"{CP_URL}/api/activity/summary?demo=true")
        self.assertEqual(code, 200)
        self.assertEqual(demo_sum.get("total_active_agents"), 1284)
        self.assertEqual(demo_sum.get("governed_percent"), 98.7)
        self.assertEqual(demo_sum.get("business_units_active"), "31/34")

        # 4. Business units endpoint
        code, bu_resp, _ = http_req(f"{CP_URL}/api/activity/business-units")
        self.assertEqual(code, 200)
        self.assertIn("business_units", bu_resp)

        # 5. Demo mode Business units endpoint
        code, demo_bu, _ = http_req(f"{CP_URL}/api/activity/business-units?demo=true")
        self.assertEqual(code, 200)
        self.assertIn("business_units", demo_bu)
        self.assertEqual(demo_bu.get("active_total"), 1284)

    def test_04_cio_workforce_pulse_intents(self):
        """BAP-523: CIO Workforce Pulse categories and drill-down distributions."""
        # Live intents (computed from ingested events)
        code, live_int, _ = http_req(f"{CP_URL}/api/activity/intents")
        self.assertEqual(code, 200)
        self.assertIn("intents", live_int)

        # Demo intents (prototype breakdown: 32% Build, 24% Investigate, etc.)
        code, resp, _ = http_req(f"{CP_URL}/api/activity/intents?demo=true")
        self.assertEqual(code, 200)
        intents = resp.get("intents", [])
        self.assertGreater(len(intents), 0)

        # Check category drill-down
        cat_names = [i["category"] for i in intents]
        self.assertIn("Investigate / Diagnose", cat_names)
        self.assertIn("Build / Change", cat_names)

        investigate = next(i for i in intents if i["category"] == "Investigate / Diagnose")
        self.assertIn("Production Incidents", investigate["subtypes"])
        self.assertEqual(investigate["subtypes"]["Production Incidents"], 47)

    def test_05_live_agent_map_topology(self):
        """BAP-524: Live Agent Map enterprise activity topology hierarchy."""
        # Live topology endpoint
        code, live_top, _ = http_req(f"{CP_URL}/api/activity/topology")
        self.assertEqual(code, 200)
        self.assertEqual(live_top.get("name"), "Enterprise AI Workforce")

        # Demo topology hierarchy
        code, resp, _ = http_req(f"{CP_URL}/api/activity/topology?demo=true")
        self.assertEqual(code, 200)
        self.assertEqual(resp.get("name"), "Enterprise AI Workforce")
        self.assertEqual(resp.get("active_sessions"), 1284)
        children = resp.get("children", [])
        self.assertGreater(len(children), 0)

        bu_names = [c["name"] for c in children]
        self.assertIn("Engineering", bu_names)
        self.assertIn("Operations", bu_names)

    def test_06_intent_action_contract_deviation(self):
        """BAP-525: Intent -> Action Contract evaluation and Critical Deviation Detection."""
        # 1. Critical deviation: Production diagnosis attempting Customer DB update
        code, rep, _ = http_req(
            f"{CP_URL}/api/activity/deviation?intent=PRODUCTION_DIAGNOSIS"
            f"&action=UPDATE+accounts+SET+balance%3D0+WHERE+id%3D42"
            f"&tool=postgres_client&target_resource=db://prod/customer_records"
        )
        self.assertEqual(code, 200)
        self.assertEqual(rep.get("deviation_level"), "CRITICAL")
        self.assertEqual(rep.get("policy_decision"), "DENY")
        self.assertTrue(rep.get("is_deviated"))
        self.assertIn("inconsistent with the session's declared production-diagnosis intent", rep.get("reason", ""))

        # 2. Compliant action: Code refactoring running local unit test
        code, rep_ok, _ = http_req(
            f"{CP_URL}/api/activity/deviation?intent=CODE_REFACTOR"
            f"&action=pytest+tests/unit&tool=pytest&target_resource=fs://workspace"
        )
        self.assertEqual(code, 200)
        self.assertEqual(rep_ok.get("deviation_level"), "NONE")
        self.assertEqual(rep_ok.get("policy_decision"), "ALLOW")
        self.assertFalse(rep_ok.get("is_deviated"))

        # 3. Retrieve recent deviations list
        code, dev_list, _ = http_req(f"{CP_URL}/api/activity/deviation")
        self.assertEqual(code, 200)
        self.assertIn("deviations", dev_list)

    def test_07_bap_477_cio_agent_activity_pulse(self):
        """BAP-477: CIO Agent Activity Pulse, extensible categories, and privacy-safe aggregation."""
        import sys
        sys.path.insert(0, os.path.join(WORKSPACE_ROOT, "python-agent"))
        import bap_sdk

        # 1. Verify Extensible Categories API
        code, cat_resp, _ = http_req(f"{CP_URL}/api/activity/categories")
        self.assertEqual(code, 200)
        self.assertIn("categories", cat_resp)
        cat_names = [c["name"] for c in cat_resp["categories"]]
        expected_categories = [
            "Feature Development / Enhancement",
            "Bug Fix",
            "Testing / Quality",
            "Documentation",
            "Production Operations",
            "Security",
            "Data / Analytics",
            "Research",
            "Automation",
            "Other / Unclassified",
        ]
        for ec in expected_categories:
            self.assertIn(ec, cat_names)

        # 2. Register custom extensible category (Acceptance Criteria 8)
        new_cat = {
            "id": "compliance_audit",
            "name": "Regulatory Compliance & Audit",
            "description": "SOC2 evidence collection, GDPR validation, and audit automation",
            "color": "#10b981",
            "icon": "shield-check"
        }
        code, post_resp, _ = http_req(f"{CP_URL}/api/activity/categories", method="POST", data=new_cat)
        self.assertEqual(code, 201)
        self.assertEqual(post_resp.get("status"), "registered")

        # 3. Verify Story Intent Classification Examples
        test_prompts = [
            ("Fix authentication timeout", "Bug Fix"),
            ("Add retry support to payment API", "Feature Development / Enhancement"),
            ("Generate unit tests", "Testing / Quality"),
            ("Update API documentation", "Documentation"),
            ("Investigate Kubernetes production failure", "Production Operations"),
            ("Unknown arbitrary command 987123", "Other / Unclassified"),
        ]
        for prompt, expected_cat in test_prompts:
            classified = bap_sdk.classify_intent(prompt)
            self.assertEqual(
                classified.get("work_category"),
                expected_cat,
                f"Prompt '{prompt}' classified as '{classified.get('work_category')}', expected '{expected_cat}'"
            )

        # 4. Verify Executive Indicators in Summary
        code, sum_resp, _ = http_req(f"{CP_URL}/api/activity/summary?demo=true")
        self.assertEqual(code, 200)
        self.assertIn("category_mix", sum_resp)
        self.assertIn("category_trends", sum_resp)
        self.assertIn("active_work_count", sum_resp)
        self.assertIn("completed_work_count", sum_resp)
        self.assertIn("estimated_assisted_hours", sum_resp)
        self.assertIn("assisted_fte_equivalent", sum_resp)
        self.assertGreater(sum_resp["estimated_assisted_hours"], 0)

        # 5. Product Principle: Verify zero employee productivity rankings or user leaderboards in CIO view
        self.assertNotIn("employee_rankings", sum_resp)
        self.assertNotIn("user_leaderboard", sum_resp)
        self.assertNotIn("prompt_count_leaderboard", sum_resp)


if __name__ == "__main__":
    unittest.main()
