"""Per-user logon registration. No administrator rights or secret-bearing command."""
import json
import os
import subprocess
import sys
import tempfile

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE = "BAPEdgeSupervisor"


def configure_startup(target_dir, enabled=True):
    state_dir = os.environ.get("BAP_STATE_DIR") or os.path.expanduser("~/.bapstate")
    binary = os.path.abspath(os.path.join(target_dir, "bapedge.exe"))
    result = {"method": "windows_current_user_run", "registered": False,
              "scope": "after_user_logon", "status": "unsupported_platform"}
    if sys.platform == "win32":
        try:
            import winreg
            if enabled:
                if not os.path.isfile(binary):
                    raise OSError("installed edge binary is missing")
                command = subprocess.list2cmdline([binary, "daemon", "supervise", "-state-dir", os.path.abspath(state_dir)])
                with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, VALUE, 0, winreg.REG_SZ, command)
                result.update(registered=True, status="registered", command=command)
            else:
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
                        command, _ = winreg.QueryValueEx(key, VALUE)
                        # Remove only our entry for this exact installation.
                        if command == subprocess.list2cmdline([binary, "daemon", "supervise", "-state-dir", os.path.abspath(state_dir)]):
                            winreg.DeleteValue(key, VALUE)
                            result.update(status="disabled")
                        else:
                            result.update(status="different_installation_preserved")
                except FileNotFoundError:
                    result.update(status="disabled")
        except (OSError, ImportError):
            result.update(status="registration_failed")
    os.makedirs(state_dir, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".startup-", dir=state_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, os.path.join(state_dir, "startup.json"))
    finally:
        if os.path.exists(temp):
            os.remove(temp)
    return result
