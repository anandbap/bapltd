import unittest
from unittest.mock import patch

from bap import cli


class TestBoundaryCliRouting(unittest.TestCase):
    def test_runner_and_operator_commands_reach_the_matching_edge_command(self):
        for command, args in [("run", ["--provider", "auto", "--", "agent", "argument with spaces"]),
                              ("exec", ["git status"]), ("learn", ["report"]), ("egress", ["list"])]:
            with self.subTest(command=command), patch("sys.argv", ["bap", command] + args), \
                 patch.object(cli, "find_bapedge", return_value="test-edge"), \
                 patch.object(cli.os.path, "isfile", return_value=True), \
                 patch.object(cli.subprocess, "call", return_value=7) as run:
                with self.assertRaises(SystemExit) as done:
                    cli.main()
                self.assertEqual(done.exception.code, 7)
                run.assert_called_once_with(["test-edge", command] + args)
