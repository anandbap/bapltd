import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from scripts import bap_doctor


class Checklist:
    def __init__(self):
        self.results = {}

    def report(self, name, status, details):
        self.results[name] = (status, details)


class ReportingDiagnosticTests(unittest.TestCase):
    def test_missing_hooks_are_partial_even_when_files_and_daemon_exist(self):
        payload = {"daemon": {"version": "fixture", "git_commit": "dev"},
                   "control_plane": {"connected": True, "authenticated_heartbeat_status": "authentication_failed"},
                   "onboarding": {"startup": {"registered": True, "status": "registered"},
                                  "supervisor": {"status": "monitoring"}, "claude_callbacks": {}}}
        checklist = Checklist()
        with patch.object(bap_doctor.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=json.dumps(payload))):
            bap_doctor.check_reporting_baseline("synthetic-edge", checklist)
        self.assertEqual(checklist.results["User logon registration"][0], "PASS")
        self.assertEqual(checklist.results["Crash supervisor"][0], "PASS")
        self.assertEqual(checklist.results["Authenticated heartbeat"][0], "WARN")
        self.assertEqual(checklist.results["Claude UserPromptSubmit"][0], "WARN")
        self.assertEqual(checklist.results["Runtime build provenance"][0], "WARN")

    def test_stopped_daemon_fails_and_invalid_payload_never_claims_ready(self):
        for stdout in ('{"daemon_running":false}', 'invalid-json'):
            checklist = Checklist()
            with patch.object(bap_doctor.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=stdout)):
                bap_doctor.check_reporting_baseline("synthetic-edge", checklist)
            self.assertFalse(any(status == "PASS" for status, _ in checklist.results.values()))


if __name__ == "__main__":
    unittest.main()
