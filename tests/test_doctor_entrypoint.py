import unittest
from unittest.mock import patch

from bap import bap_doctor, bap_release, cli, doctor


class DoctorEntrypointTests(unittest.TestCase):
    def test_entrypoints_preserve_diagnostic_exit_status(self):
        for entrypoint in (doctor.main, cli.main):
            for status in (0, 1):
                with self.subTest(entrypoint=entrypoint.__module__, status=status):
                    with patch("sys.argv", ["bap", "doctor"]), patch.object(
                        bap_doctor, "run_doctor", return_value=status
                    ) as run:
                        with self.assertRaises(SystemExit) as result:
                            entrypoint()
                    self.assertEqual(result.exception.code, status)
                    run.assert_called_once_with()

    def test_release_integrity_keeps_package_context(self):
        checklist = unittest.mock.Mock()

        def run():
            bap_doctor.check_release_integrity("synthetic-edge", checklist)
            return 0

        with patch.object(bap_doctor, "run_doctor", side_effect=run), patch.object(
            bap_doctor.os.path, "isfile", return_value=True
        ), patch.object(bap_release, "component_paths", return_value={}), patch.object(
            bap_release, "verify_manifest",
            return_value={"release_id": "synthetic-release", "source_qualified": True},
        ) as verify:
            with self.assertRaises(SystemExit) as result:
                doctor.main()
        self.assertEqual(result.exception.code, 0)
        verify.assert_called_once()
        checklist.report.assert_any_call(
            "Release component integrity", "PASS",
            "Installed component hashes match release synthetic-releas",
        )


if __name__ == "__main__":
    unittest.main()
