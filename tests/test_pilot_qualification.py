"""Qualification must distinguish smoke, manual evidence and changed artifacts."""
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("pilot_qualification", Path(__file__).parents[1] / "scripts/pilot_qualification.py")
qualification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualification)


class PilotQualificationTests(unittest.TestCase):
    def test_smoke_alone_never_qualifies_pilot_and_changed_evidence_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            smoke = root / "smoke.json"
            smoke.write_text(json.dumps({"result": "AUTOMATED_SMOKE_PASS", "run_id": "fixture",
                "operator_build_commit": "abcdef0", "edge_sha256": "a" * 64,
                "checks": [{"passed": True}]}), encoding="utf-8")
            output = root / "qualification.json"
            qualification.initialize(argparse.Namespace(smoke=str(smoke), release_commit="abcdef0",
                machine="fixture", operator="operator", output=str(output)))
            report = json.loads(output.read_text())
            self.assertEqual(report["result"], "NOT_READY")
            self.assertEqual(report["checks"]["native_hooks"]["result"], "NOT_TESTED")
            smoke.write_text("{}", encoding="utf-8")
            self.assertEqual(qualification.reconcile(report)["checks"]["smoke"]["result"], "FAIL")

    def test_private_payload_is_not_evidence(self):
        with self.assertRaises(ValueError):
            qualification.reject_private({"nested": [{"session_token": "synthetic-marker"}]})
        with self.assertRaises(ValueError):
            qualification.safe_path(".ssh/id_rsa")
        with self.assertRaises(ValueError):
            qualification.parse_time("2026-11-13T10:00:00")

    def test_manual_pass_requires_actual_reference_and_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bundle.json"
            path.write_text(json.dumps({"schema_version": 1, "checks": {
                name: {"result": "NOT_TESTED"} for name in qualification.CASES}}), encoding="utf-8")
            with self.assertRaises(ValueError):
                qualification.record(argparse.Namespace(bundle=str(path), evidence=[], result="PASS",
                    session_id="", event_id=[], case="native_hooks"))


if __name__ == "__main__":
    unittest.main()
