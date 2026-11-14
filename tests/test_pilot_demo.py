"""The installed demo must fail closed and never automate operator decisions."""

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from bap.pilot_demo import CheckFailure, Demo, is_allowed, json_object, main, policy_decision


def reply(allowed, reason="", **extra):
    return subprocess.CompletedProcess([], 0 if allowed else 1,
                                       json.dumps(dict(allowed=allowed, reason=reason, **extra)), "")


class ResponseTests(unittest.TestCase):
    def test_json_notices_and_malformed_response(self):
        self.assertEqual(json_object('CLI notice\n{"allowed":false}'), {"allowed": False})
        for output in ('not JSON', '{"allowed":true} trailing error', '{"allowed":'):
            with self.subTest(output=output), self.assertRaises(CheckFailure):
                json_object(output)

    def test_exit_code_and_boolean_must_agree(self):
        for rc, payload in ((0, {"allowed": False}), (1, {"allowed": True}),
                            (0, {"allowed": "true"}), (0, {"status": "ok"})):
            with self.subTest(payload=payload), self.assertRaises(CheckFailure):
                is_allowed(subprocess.CompletedProcess([], rc, json.dumps(payload), ""))

    def test_why_exit_zero_is_not_permission(self):
        self.assertFalse(policy_decision('POLICY DECISION: DENIED (Blocked by Cedar Policy)'))
        self.assertTrue(policy_decision('POLICY DECISION: ALLOWED (Permitted by Policy)'))
        for output in ('POLICY DECISION: EVALUATION ERROR', 'failed',
                       'POLICY DECISION: ALLOWED\nPOLICY DECISION: DENIED'):
            with self.subTest(output=output), self.assertRaises(CheckFailure):
                policy_decision(output)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.demo = Demo("bapedge", Path.cwd(), "codex")

    def test_operator_commands_never_spawn(self):
        with patch('bap.pilot_demo.subprocess.run') as spawn:
            for args in (("trust", "folder"), ("untrust", "folder"),
                         ("zsp", "approve", "req-example"), ("zsp", "deny", "req-example"),
                         ("zsp", "policy-sign"), ("dev-override", "on")):
                with self.subTest(args=args), self.assertRaises(CheckFailure):
                    self.demo.command(*args)
            spawn.assert_not_called()

    def test_commands_have_no_shell_or_approval_terminal(self):
        with patch('bap.pilot_demo.subprocess.run', return_value=reply(False)) as spawn:
            self.demo.check()
        args, kwargs = spawn.call_args
        self.assertNotIn('shell', kwargs)
        self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
        self.assertEqual(kwargs['env']['BAP_SESSION_ID'], self.demo.session)
        self.assertEqual(kwargs['env']['LTD_SOURCE'], 'codex')
        self.assertNotIn('--oob-approve', args[0])

    def test_denial_for_wrong_reason_is_failure(self):
        with self.assertRaises(CheckFailure):
            self.demo.expect('expired', reply(False, 'network unavailable'), False, 'expired')
        self.assertFalse(self.demo.checks)

    def test_actual_decision_is_checked_after_operator_says_done(self):
        self.demo.interactive = True
        with patch.object(self.demo, 'authorize', return_value=reply(False, 'human approval required')), \
             patch.object(self.demo, 'check', return_value=reply(False, 'no grant')), \
             patch('builtins.input', return_value=''), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(CheckFailure):
                self.demo.human_approval()

    def test_failure_is_reported_and_own_session_is_revoked(self):
        self.demo.initialized = True
        with patch.object(self.demo, 'local', side_effect=CheckFailure('wrong boundary')), \
             patch.object(self.demo, 'command', return_value=reply(True)) as command, \
             contextlib.redirect_stdout(io.StringIO()):
            result = self.demo.run()
        self.assertEqual(result['result'], 'FAIL')
        command.assert_called_once_with('zsp', 'revoke', '--session-id', self.demo.session)
        self.assertTrue(all(v == 'NOT_TESTED' for v in result['manual_checks'].values()))

    def test_local_pass_never_claims_pilot_ready(self):
        with patch.object(self.demo, 'local'), contextlib.redirect_stdout(io.StringIO()):
            result = self.demo.run()
        self.assertEqual(result['result'], 'LOCAL_CHECKS_PASS_MANUAL_ACCEPTANCE_REQUIRED')
        self.assertTrue(all(v == 'NOT_TESTED' for v in result['manual_checks'].values()))
        self.assertIn({'name': 'human_approval_transition', 'result': 'NOT_TESTED'},
                      [{k: c[k] for k in ('name', 'result')} for c in result['checks']])

    def test_cleanup_failure_turns_run_red(self):
        self.demo.initialized = True
        with patch.object(self.demo, 'local'), patch.object(self.demo, 'command', return_value=reply(False)), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.demo.run()['result'], 'FAIL')

    def test_complete_local_flow_checks_each_transition_and_cleans_up(self):
        responses = [
            subprocess.CompletedProcess([], 0, 'bapedge v1.13.7', ''),
            subprocess.CompletedProcess([], 0, '{}', ''),
            reply(False, 'ZERO standing privileges'), reply(True),
            reply(False, 'action not in granted scopes'),
            reply(False, 'resource not in granted boundaries'), reply(True),
            reply(False, 'task grant already burned'), reply(True),
            reply(False, 'grant expired'), reply(True), reply(True),
            reply(False, 'grant revoked'),
            reply(False, 'credential access is never grantable'), reply(True),
        ]
        with patch.object(self.demo, 'command', side_effect=responses) as command, \
             patch('bap.pilot_demo.time.sleep'), contextlib.redirect_stdout(io.StringIO()):
            result = self.demo.run()
        self.assertEqual(result['result'], 'LOCAL_CHECKS_PASS_MANUAL_ACCEPTANCE_REQUIRED')
        self.assertEqual(result['edge_version'], '1.13.7')
        self.assertEqual(command.call_count, len(responses))
        passed = {c['name'] for c in result['checks'] if c['result'] == 'PASS'}
        self.assertTrue({'expired_grant_denied', 'used_grant_denied', 'revoked_grant_denied',
                         'different_resource_denied', 'credential_authority_never_granted',
                         'demo_grants_revoked'}.issubset(passed))

    def test_approval_flow_checks_real_allow_then_reuse_denial(self):
        with patch.object(self.demo, 'authorize', return_value=reply(False, 'human approval required')), \
             patch.object(self.demo, 'check', side_effect=[reply(True), reply(False, 'grant burned')]), \
             patch('builtins.input', return_value=''), contextlib.redirect_stdout(io.StringIO()):
            self.demo.human_approval()
        self.assertEqual([c['name'] for c in self.demo.checks],
                         ['publishing_requires_approval', 'human_approved_grant_observed',
                          'approved_grant_cannot_be_reused'])

    def test_broker_invocation_is_refused_before_any_cli_call(self):
        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root)
            (workspace / '.git').mkdir()
            with patch.dict(os.environ, {'BAP_IN_BROKER': '1'}), \
                 patch('bap.pilot_demo.subprocess.run') as spawn, \
                 contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                main(['--workspace', root])
            self.assertEqual(raised.exception.code, 2)
            spawn.assert_not_called()

    def test_report_path_cannot_escape_or_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root) / 'workspace'
            workspace.mkdir()
            (workspace / '.git').mkdir()
            existing = workspace / 'existing.json'
            existing.write_text('original', encoding='utf-8')
            with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stderr(io.StringIO()):
                for path in ('../escape.json', '.env.demo', '.bap/policy.json', 'existing.json'):
                    with self.subTest(path=path), self.assertRaises(SystemExit) as raised:
                        main(['--workspace', str(workspace), '--report', path])
                    self.assertEqual(raised.exception.code, 2)
            self.assertEqual(existing.read_text(encoding='utf-8'), 'original')

    def test_cli_writes_sanitized_report_without_checkout_dependencies(self):
        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root)
            (workspace / '.git').mkdir()
            edge = workspace / 'fake-edge.exe'
            edge.write_bytes(b'test fixture')
            with patch.dict(os.environ, {}, clear=True), \
                 patch('bap.pilot_demo.Demo.local'), contextlib.redirect_stdout(io.StringIO()):
                rc = main(['--workspace', root, '--edge', str(edge)])
            data = json.loads((workspace / '.bap-demo/report.json').read_text(encoding='utf-8'))
            self.assertEqual(rc, 0)
            self.assertEqual(len(data['edge_sha256']), 64)
            self.assertNotIn('stdout', data)
            self.assertNotIn('credentials', data)
            self.assertNotEqual(data['result'], 'PILOT_READY')


if __name__ == '__main__':
    unittest.main()
