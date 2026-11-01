"""Real native crash/pause recovery in a private profile; never registers startup."""
import json
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("BAP_SUPERVISOR_E2E_BIN") or ROOT / "dist/windows-amd64/bapedge.exe")


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def do_POST(self):
        self.send_response(503)
        self.end_headers()

    def log_message(self, *_):
        pass


@unittest.skipUnless(os.name == "nt" and BINARY.is_file(), "requires the matched Windows edge build")
class SupervisorRuntimeE2E(unittest.TestCase):
    def test_real_daemon_crash_restart_pause_and_resume(self):
        with tempfile.TemporaryDirectory(prefix="bap-supervisor-e2e-") as directory:
            root = Path(directory)
            profile = root / "profile"
            state = profile / ".bapstate"
            state.mkdir(parents=True)
            fixture = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
            threading.Thread(target=fixture.serve_forever, daemon=True).start()
            server = "http://127.0.0.1:" + str(fixture.server_port)
            env = dict(os.environ)
            env.update(USERPROFILE=str(profile), HOME=str(profile), APPDATA=str(profile / "roaming"),
                       LOCALAPPDATA=str(profile / "local"), PROGRAMDATA=str(root / "programdata"),
                       BAP_STATE_DIR=str(state), BAP_CREDENTIALS=str(root / "absent.json"), BAP_SERVER_URL=server,
                       TEMP=str(root), TMP=str(root))
            (root / "bap-config.json").write_text(json.dumps({"controlplane_url": server}), encoding="utf-8")

            def run(*arguments, startup=False):
                process_env = dict(env)
                if startup:
                    process_env.pop("BAP_STATE_DIR", None)
                result = subprocess.run([str(BINARY), "daemon", *arguments], cwd=root, env=process_env,
                                        capture_output=True, text=True, timeout=12,
                                        creationflags=0x08000000)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return result

            def daemon_record():
                try:
                    return json.loads((state / "daemon.json").read_text())
                except (OSError, ValueError):
                    return {}

            def wait_for(predicate, seconds=12):
                deadline = time.monotonic() + seconds
                while time.monotonic() < deadline:
                    value = predicate()
                    if value:
                        return value
                    time.sleep(0.1)
                self.fail("runtime condition timed out")

            try:
                run("supervise", "-state-dir", str(state), "-server", server, startup=True)
                first = wait_for(lambda: daemon_record())
                supervisor = json.loads((state / "supervisor.json").read_text())
                run("supervise", "-server", server)
                self.assertEqual(json.loads((state / "supervisor.json").read_text())["pid"], supervisor["pid"])
                # Kill only the PID from this private fixture's process-bound daemon record.
                self.assertTrue(first["process_birth"])
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.OpenProcess.restype = wintypes.HANDLE
                kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
                kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
                kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
                kernel.CloseHandle.argtypes = [wintypes.HANDLE]
                handle = kernel.OpenProcess(0x1001, False, first["pid"])
                self.assertTrue(handle)
                try:
                    birth, exited, cpu_kernel, cpu_user = (wintypes.FILETIME() for _ in range(4))
                    self.assertTrue(kernel.GetProcessTimes(handle, ctypes.byref(birth), ctypes.byref(exited), ctypes.byref(cpu_kernel), ctypes.byref(cpu_user)))
                    self.assertEqual(f"{birth.dwHighDateTime:08x}{birth.dwLowDateTime:08x}", first["process_birth"])
                    self.assertTrue(kernel.TerminateProcess(handle, 87))
                finally:
                    kernel.CloseHandle(handle)
                replacement = wait_for(lambda: (record if (record := daemon_record()).get("pid") not in (None, first["pid"]) else None))
                self.assertNotEqual(replacement["pid"], first["pid"])
                run("stop")
                paused_pid = replacement["pid"]
                time.sleep(3)
                self.assertTrue((state / "daemon.paused").exists())
                self.assertEqual(json.loads((state / "supervisor.json").read_text())["status"], "paused")
                run("start", "-server", server)
                resumed = wait_for(lambda: daemon_record())
                self.assertNotEqual(resumed["pid"], paused_pid)
                status = json.loads(run("status", "--json").stdout)
                self.assertEqual(status["onboarding"]["claude_callbacks"]["UserPromptSubmit"]["status"], "not_observed")
                self.assertNotEqual(status["onboarding"]["status"], "ready")
            finally:
                for arguments in (("stop",), ("supervise", "--stop")):
                    try:
                        run(*arguments)
                    except (AssertionError, subprocess.SubprocessError):
                        pass
                fixture.shutdown()
                fixture.server_close()


if __name__ == "__main__":
    unittest.main()
