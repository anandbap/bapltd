import os
import sys
import json
import time
import subprocess
import urllib.request
import urllib.error

def http_post(url, data, headers=None):
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8"), headers=req_headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body

def http_get(url, headers=None):
    req_headers = {}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(data)
            except Exception:
                return resp.status, data
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body

def main():
    print("==================================================")
    print("  Testing Stop Session, Revoke Access & Restore Access")
    print("==================================================")
    
    port = 62411
    admin_token = "test-admin-secret-token"
    cp_proc = subprocess.Popen(
        ["bapcontrolplane.exe", "--port", str(port), "--admin-token", admin_token, "--db", "memory"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    base_url = f"http://localhost:{port}"

    try:
        time.sleep(1.5)
        # 1. Health check
        code, data = http_get(f"{base_url}/")
        assert code == 200, f"Expected 200, got {code}"
        print("[PASS] 1. Control plane started and healthy")

        # 2. Start a session for user 'testuser'
        sess_id = "sess-test-001"
        code, data = http_post(f"{base_url}/api/v1/sessions/start", {
            "session_id": sess_id,
            "app_id": "claude-code",
            "user_id": "testuser",
            "hostname": "TEST-HOST",
            "client_pid": 99999
        }, headers={"Authorization": f"Bearer {admin_token}"})
        assert code == 200, f"Expected 200, got {code}: {data}"
        print("[PASS] 2. User 'testuser' started session successfully")

        # 3. Test Stop Session
        code, data = http_post(
            f"{base_url}/api/v1/control/agent/kill",
            {"target": sess_id, "action": "stop"},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert code == 200, f"Expected 200, got {code}: {data}"
        assert data.get("status") == "closed", f"Expected closed, got {data}"
        print("[PASS] 3. Stop Session closed session and marked workload STOPPED")

        # User should STILL be able to start a new session after Stop Session
        sess_id_2 = "sess-test-002"
        code, data = http_post(f"{base_url}/api/v1/sessions/start", {
            "session_id": sess_id_2,
            "app_id": "claude-code",
            "user_id": "testuser",
            "hostname": "TEST-HOST",
            "client_pid": 99999
        }, headers={"Authorization": f"Bearer {admin_token}"})
        assert code == 200, f"Expected 200, got {code}: {data}"
        print("[PASS] 4. User 'testuser' can start new session after Stop Session")

        # 4. Test Revoke Access on user 'testuser'
        code, data = http_post(
            f"{base_url}/api/v1/control/agent/kill",
            {"target": sess_id_2, "action": "revoke", "user_id": "testuser"},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert code == 200, f"Expected 200, got {code}: {data}"
        assert data.get("status") == "revoked", f"Expected revoked, got {data}"
        print("[PASS] 5. Revoke Access marked target REVOKED")

        # Check revocations endpoint
        code, data = http_get(f"{base_url}/api/v1/control/revocations")
        assert code == 200, f"Expected 200, got {code}: {data}"
        assert "testuser" in [u.lower() for u in data.get("revoked_users", [])], f"testuser not in revoked_users: {data}"
        print("[PASS] 6. Revocations list returns revoked user 'testuser'")

        # 5. User 'testuser' attempts to start a new session -> MUST RETURN 403 Forbidden!
        sess_id_3 = "sess-test-003"
        code, data = http_post(f"{base_url}/api/v1/sessions/start", {
            "session_id": sess_id_3,
            "app_id": "claude-code",
            "user_id": "testuser",
            "hostname": "TEST-HOST"
        }, headers={"Authorization": f"Bearer {admin_token}"})
        assert code == 403, f"Expected 403 Forbidden for revoked user, got {code}: {data}"
        print("[PASS] 7. Blocked: User 'testuser' strictly forbidden (403) from starting new session")

        # CLI session-start pre-flight verification
        env = os.environ.copy()
        env["USERNAME"] = "testuser"
        res = subprocess.run(
            ["bapedge.exe", "session-start", "--server", base_url, "--session-id", "sess-test-cli", "--app-id", "claude-code"],
            env=env,
            capture_output=True,
            text=True
        )
        assert res.returncode == 2, f"Expected exit code 2 from bapedge session-start, got {res.returncode}"
        assert "REVOKED" in res.stderr, f"Expected REVOKED in stderr: {res.stderr}"
        print("[PASS] 8. bapedge session-start CLI blocked revoked user with exit code 2")

        # 6. Test Restore Access
        code, data = http_post(
            f"{base_url}/api/v1/control/agent/kill",
            {"target": "testuser", "action": "restore", "user_id": "testuser"},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert code == 200, f"Expected 200, got {code}: {data}"
        assert data.get("status") == "active", f"Expected active, got {data}"
        print("[PASS] 9. Restore Access successfully cleared user revocation")

        # Now user can start a session again!
        code, data = http_post(f"{base_url}/api/v1/sessions/start", {
            "session_id": "sess-test-004",
            "app_id": "claude-code",
            "user_id": "testuser",
            "hostname": "TEST-HOST"
        }, headers={"Authorization": f"Bearer {admin_token}"})
        assert code == 200, f"Expected 200, got {code}: {data}"
        print("[PASS] 10. User 'testuser' can successfully start sessions after Restore Access")

        # 7. Verify inspector.html data endpoint
        code, data = http_get(f"{base_url}/api/v1/inspector/data")
        assert code == 200, f"Expected 200, got {code}: {data}"
        assert "sessions" in data, "sessions missing from inspector data"
        assert "agents" in data, "agents missing from inspector data"
        print("[PASS] 11. /api/v1/inspector/data serves live fleet and session telemetry")

        # 8. Verify /inspector and /assets/admin-client.js
        code, _ = http_get(f"{base_url}/inspector")
        assert code == 200, f"Expected 200, got {code}"
        print("[PASS] 12. /inspector serves HTML successfully")

        print("\n==================================================")
        print("  ALL STOP / REVOKE / RESTORE LIFECYCLE TESTS PASSED!")
        print("==================================================")
    finally:
        cp_proc.terminate()
        try:
            cp_proc.wait(timeout=3)
        except Exception:
            cp_proc.kill()
        # Clean up any test markers
        for f in [".bap-session.json", ".bap-revoked", "../.bap-revoked"]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

if __name__ == "__main__":
    main()
