"""bapedge process lifecycle: watchers must exit when they should and must never linger.

A stray bapedge process is a reputation problem: users see them in Task Manager and assume
BAP leaks. Every scenario here starts REAL bapedge watchers against a throwaway target process,
in an isolated home and state directory (no control plane, no real state touched), and tearDown
fails the test if any process it started is still alive.

Covers the defects that produced zombies:
  * the watcher ignored SessionEnd and outlived a long-lived parent (terminal / desktop app);
  * duplicate watchers were started for one session and kept resurrecting each other's liveness file.
"""

import ctypes
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_EXE = "bapedge.exe" if os.name == "nt" else "bapedge"
BAPEDGE_BIN = os.environ.get("BAP_TEST_BAPEDGE") or os.path.join(WORKSPACE_ROOT, _EXE)
# Nothing listens here, so every control plane call fails fast: the watcher runs fully offline.
DEAD_SERVER = "http://127.0.0.1:9"


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            if not ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == STILL_ACTIVE
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # A zombie (exited, not yet reaped) still answers kill(0); treat it as gone.
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return True


def wait_until(predicate, timeout, interval=0.25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


@unittest.skipUnless(os.path.isfile(BAPEDGE_BIN), f"{_EXE} not built at {BAPEDGE_BIN}")
class BapedgeProcessLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bap-lifecycle-")
        self.home = os.path.join(self.tmp, "home")
        self.state = os.path.join(self.tmp, "state")
        os.makedirs(self.home)
        os.makedirs(self.state)
        self.env = os.environ.copy()
        self.env.update({
            "HOME": self.home,
            "USERPROFILE": self.home,
            "BAP_STATE_DIR": self.state,
            "BAP_NON_INTERACTIVE": "1",
            "BAP_DEV_OVERRIDE": "",
            "BAP_ENVIRONMENT": "production",
        })
        self.spawned = []  # every bapedge watcher we start: none may outlive the test
        self.targets = []  # throwaway stand-ins for the watched terminal/app (fixtures, not under test)
        self.extra_pids = []  # detached watchers found through their lock file
        self.sid = "e2e" + hashlib.sha1(self.tmp.encode()).hexdigest()[:10]

    def tearDown(self):
        for t in self.targets:
            if t.poll() is None:
                t.kill()
            t.wait(timeout=10)
        leaked = []
        for p in self.spawned:
            if p.poll() is None:
                leaked.append(p.pid)
                p.kill()
            if p.stderr:
                p.stderr.close()
        for pid in self.extra_pids:
            if pid_alive(pid):
                leaked.append(pid)
                try:
                    os.kill(pid, 9) if os.name != "nt" else subprocess.run(
                        ["taskkill", "/F", "/PID", str(pid)], capture_output=True)
                except OSError:
                    pass
        self.assertEqual(leaked, [], f"bapedge/target processes still running after the test (zombies): {leaked}")

    # -- helpers ---------------------------------------------------------------------------

    def start_target(self):
        """A long-lived process standing in for the terminal or desktop app being watched."""
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
        self.targets.append(p)
        return p

    def watch_args(self, target_pid, detach=False):
        args = [BAPEDGE_BIN, "watch", f"--pid={target_pid}", f"--server={DEAD_SERVER}",
                f"--session-id={self.sid}", "--app-id=lifecycle-test"]
        if detach:
            args.append("--detach")
        return args

    def start_watcher(self, target_pid):
        p = subprocess.Popen(self.watch_args(target_pid), cwd=self.tmp, env=self.env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.spawned.append(p)
        return p

    def liveness_file(self):
        return os.path.join(self.home, ".bap", "watchers", self.sid + ".watcher")

    def lock_file(self):
        return os.path.join(self.home, ".bap", "watchers", self.sid + ".lock")

    def session_end(self):
        r = subprocess.run([BAPEDGE_BIN, "session-end", f"--session-id={self.sid}", f"--server={DEAD_SERVER}"],
                           cwd=self.tmp, env=self.env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)

    def wait_running(self, watcher):
        self.assertTrue(wait_until(lambda: os.path.isfile(self.liveness_file()), 30),
                        "watcher never reported liveness; stderr: " +
                        (watcher.stderr.read().decode(errors="replace") if watcher.poll() is not None else "<running>"))

    # -- scenarios -------------------------------------------------------------------------

    def test_watcher_exits_when_its_target_exits(self):
        target = self.start_target()
        w = self.start_watcher(target.pid)
        self.wait_running(w)
        target.kill()
        target.wait(timeout=10)
        self.assertTrue(wait_until(lambda: w.poll() is not None, 30), "watcher must exit after its target dies")
        self.assertFalse(os.path.exists(self.liveness_file()), "a finished watcher must not leave a liveness file")

    def test_watcher_exits_when_session_ends_even_though_target_lives(self):
        """The zombie scenario: the terminal/desktop app outlives the AI session by days."""
        target = self.start_target()
        w = self.start_watcher(target.pid)
        self.wait_running(w)
        self.session_end()
        self.assertIsNone(target.poll(), "test setup: the target must still be alive")
        self.assertTrue(wait_until(lambda: w.poll() is not None, 30),
                        "SessionEnd must stop the watcher; it must not wait for the target to die")
        self.assertFalse(os.path.exists(self.liveness_file()),
                         "the liveness file must not be resurrected after the session ended")
        self.assertFalse(os.path.exists(self.lock_file()), "the watcher must release its lock when it exits")
        target.kill()

    def test_duplicate_watcher_for_the_same_session_stands_down(self):
        target = self.start_target()
        first = self.start_watcher(target.pid)
        self.wait_running(first)
        second = self.start_watcher(target.pid)
        self.assertTrue(wait_until(lambda: second.poll() is not None, 20),
                        "a second watcher for the same session must exit immediately")
        self.assertIsNone(first.poll(), "the original watcher must keep running")
        self.assertTrue(os.path.isfile(self.liveness_file()), "the duplicate must not remove the original's liveness file")
        self.session_end()
        self.assertTrue(wait_until(lambda: first.poll() is not None, 30), "SessionEnd must stop the original too")
        target.kill()

    def test_detached_watcher_is_single_and_leaves_nothing_behind(self):
        target = self.start_target()
        for _ in range(3):  # hooks may race to start a watcher: only one may survive
            subprocess.run(self.watch_args(target.pid, detach=True), cwd=self.tmp, env=self.env,
                           capture_output=True, timeout=60)
        self.assertTrue(wait_until(lambda: os.path.isfile(self.lock_file()), 30), "no detached watcher took the lock")
        time.sleep(3)  # let any losing duplicates exit
        with open(self.lock_file()) as f:
            owner = int(f.read().strip())
        self.extra_pids.append(owner)
        self.assertTrue(pid_alive(owner), "the lock owner must be running")
        self.session_end()
        self.assertTrue(wait_until(lambda: not pid_alive(owner), 30), "the detached watcher must exit on SessionEnd")
        self.assertFalse(os.path.exists(self.lock_file()))
        target.kill()


if __name__ == "__main__":
    unittest.main()
