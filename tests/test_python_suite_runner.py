import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_python_tests as runner


class TestPythonSuiteRunner(unittest.TestCase):
    def test_environment_does_not_inherit_real_state_or_mutate_parent(self):
        original = {"BAP_STATE_DIR": "real-state", "BAP_POLICY_DIR": "real-policy",
                    "BAP_CREDENTIALS": "real-credentials", "BAP_SESSION_ID": "real-session",
                    "BAP_TEST_REAL_STATE": "1", "PATH": "existing-tools"}
        with tempfile.TemporaryDirectory() as directory:
            env = runner.test_environment(Path(directory), original)
            self.assertEqual(env["BAP_STATE_DIR"], str(Path(directory) / "state"))
            self.assertEqual(env["TEMP"], str(Path(directory) / "tmp"))
            for name in ("BAP_POLICY_DIR", "BAP_CREDENTIALS", "BAP_SESSION_ID", "BAP_TEST_REAL_STATE"):
                self.assertNotIn(name, env)
            self.assertEqual(env["PATH"], "existing-tools")
            self.assertEqual(original["BAP_STATE_DIR"], "real-state")

    def test_failing_suite_returns_failure_and_keeps_log_without_runtime_state(self):
        class FailedSuite:
            def __init__(self):
                self.stdout = io.StringIO("FAILED (failures=1)\n")

            def wait(self, **kwargs):
                return 1

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(runner, "ROOT", Path(directory)), patch.object(runner.subprocess, "Popen", return_value=FailedSuite()) as launch:
                self.assertEqual(runner.main([]), 1)
                args, kwargs = launch.call_args
                self.assertIn("test*.py", args[0])
                self.assertEqual(kwargs["cwd"], Path(directory))
                self.assertNotEqual(kwargs["env"]["BAP_STATE_DIR"], "real-state")
            runs = list((Path(directory) / ".bap" / "python-tests").iterdir())
            self.assertEqual(len(runs), 1)
            self.assertEqual((runs[0] / "output.log").read_text(), "FAILED (failures=1)\n")
            self.assertEqual(json.loads((runs[0] / "result.json").read_text())["exit_code"], 1)
            self.assertFalse(list(runs[0].glob("runtime-*")))


if __name__ == "__main__":
    unittest.main()
