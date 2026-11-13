"""Pytest session setup shared by the whole suite.

Isolation: many tests launch the real bapedge / interceptor / control plane as subprocesses. By
default those read and write the developer's REAL BAP state (policy cache, the pinned control
plane signing key, enrollment credentials, the audit log). On an enrolled workstation that makes
a test run able to re-pin the machine to a throwaway control plane or rewrite its signed rules,
which locks the machine out (bapedge fails closed on rules that do not verify).

So the whole suite runs with its own temporary BAP_STATE_DIR. Set BAP_TEST_REAL_STATE=1 to opt
out deliberately (for example when debugging an installed client).
"""
import atexit
import os
import shutil
import tempfile

_ISOLATED_DIR = None

if os.environ.get("BAP_TEST_REAL_STATE") != "1":
    _ISOLATED_DIR = tempfile.mkdtemp(prefix="bap-pytest-state-")
    os.environ["BAP_STATE_DIR"] = _ISOLATED_DIR
    # Never inherit an explicit policy/credential location pointing at a real install.
    os.environ.pop("BAP_POLICY_DIR", None)
    os.environ.pop("BAP_CREDENTIALS", None)
    atexit.register(lambda: shutil.rmtree(_ISOLATED_DIR, ignore_errors=True))


def pytest_report_header(config):
    if _ISOLATED_DIR:
        return f"bap state isolation: BAP_STATE_DIR={_ISOLATED_DIR}"
    return "bap state isolation: DISABLED (BAP_TEST_REAL_STATE=1) - tests may modify the real BAP state"
