"""Run the repository's Python unittest suite with isolated local BAP state."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def test_environment(runtime, inherited):
    env = inherited.copy()
    for name in ("BAP_POLICY_DIR", "BAP_CREDENTIALS", "BAP_SESSION_ID",
                 "LTD_SESSION_ID", "BAP_GRANT_TOKEN", "BAP_TEST_REAL_STATE"):
        env.pop(name, None)
    state = runtime / "state"
    scratch = runtime / "tmp"
    state.mkdir()
    scratch.mkdir()
    env.update(BAP_STATE_DIR=str(state), TEMP=str(scratch), TMP=str(scratch),
               BAP_MODE="dev", BAP_TELEMETRY_CONTENT="redacted",
               PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
    return env


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pattern", default="test*.py", help="Discovery pattern; default runs all test*.py files")
    parser.add_argument("--require-wheel-tests", action="store_true", help="Fail rather than skip when required wheel fixtures are missing")
    args = parser.parse_args(argv)
    result_root = ROOT / ".bap" / "python-tests"
    result_root.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix=datetime.now().strftime("%Y%m%d-%H%M%S-"), dir=result_root))
    log_path = run / "output.log"
    command = [sys.executable, "-X", "faulthandler", "-m", "unittest", "discover",
               "-v", "-s", "tests", "-p", args.pattern]
    code = 1
    started = datetime.now(timezone.utc).isoformat()
    print("Running Python tests from:", ROOT, flush=True)
    print("Output:", log_path, flush=True)
    print("Uses existing dependencies/binaries; does not build, install, or enable overrides.", flush=True)
    try:
        # Only this launch's runtime directory is removed. Logs/results survive;
        # concurrent runs and real workstation state are never cleanup targets.
        with tempfile.TemporaryDirectory(prefix="runtime-", dir=run) as runtime_name:
            env = test_environment(Path(runtime_name), os.environ)
            if args.require_wheel_tests:
                env["BAP_REQUIRE_WHEEL_TESTS"] = "1"
            with log_path.open("w", encoding="utf-8") as log:
                child = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
                try:
                    for line in child.stdout:
                        print(line, end="", flush=True)
                        log.write(line)
                        log.flush()
                    code = child.wait()
                except KeyboardInterrupt:
                    print("\nInterrupted; waiting for test teardown.", flush=True)
                    try:
                        child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        child.terminate()
                        child.wait()
                    code = 130
                finally:
                    child.stdout.close()
    except (OSError, KeyboardInterrupt) as exc:
        print(f"Test runner failed: {exc}", file=sys.stderr)
    (run / "result.json").write_text(json.dumps({"started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
        "command": command, "exit_code": code, "log": str(log_path)}, indent=2), encoding="utf-8")
    print(f"\nPython suite exit code: {code}. Results: {run}", flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
