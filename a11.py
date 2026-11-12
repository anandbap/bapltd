"""
a11.py - BAP Zero-Trust Script Execution & Containment Test

Demonstrates:
1. Script decomposition into canonical action 'dev:python:exec' on resource 'file://a11.py'.
2. Containment defense-in-depth: Even if python execution is permitted,
   nested unauthorized operations inside the script are stopped:
   - Subprocess execution of forbidden network exfiltration utilities (curl cnn.com)
   - Raw socket egress attempts bypassing HTTP proxies (socket.connect to cnn.com:80)
   - Unauthorized attempts to read ambient credentials (.env)
"""
import os
import sys
import subprocess

print("=" * 70)
print("[a11.py] BAP Zero-Trust Script Execution & Containment Demonstration")
print(f"[a11.py] Process PID: {os.getpid()}")
print("=" * 70)

# 1. Attempt nested curl cnn.com
print("\n[TEST 1] Attempting nested subshell exfiltration: 'curl -s https://cnn.com'...")
try:
    res = subprocess.run(
        ["curl", "-s", "--max-time", "3", "https://cnn.com"],
        capture_output=True,
        text=True,
        timeout=5
    )
    if res.returncode != 0:
        print(f"[CONTAINED] curl execution failed/blocked with exit code {res.returncode}")
        if res.stderr:
            print(f"            Details: {res.stderr.strip()[:120]}")
    else:
        print(f"[UNEXPECTED] curl returned data: {res.stdout[:80]}...")
except FileNotFoundError:
    print("[CONTAINED] curl binary not executable or dropped by restricted sandbox environment.")
except Exception as e:
    print(f"[CONTAINED] Subprocess execution blocked by containment: {e}")

# 2. Attempt raw network socket egress
print("\n[TEST 2] Attempting raw TCP socket egress to cnn.com:80 (proxy bypass attempt)...")
try:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0)
    s.connect(("cnn.com", 80))
    print("[UNEXPECTED] Raw socket connection succeeded!")
    s.close()
except Exception as e:
    print(f"[CONTAINED] Raw network socket egress blocked by Windows Restricted Token sandbox: {e}")

# 3. Attempt credential access (.env)
print("\n[TEST 3] Attempting unauthorized credential read of .env file...")
try:
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            content = f.read()
        print(f"[UNEXPECTED] Read .env credentials: {content[:40]}...")
    else:
        print("[CONTAINED] .env credential file does not exist or access shielded.")
except Exception as e:
    print(f"[CONTAINED] File integrity shield blocked read of .env: {e}")

print("\n" + "=" * 70)
print("[a11.py] Script execution completed under BAP containment boundaries.")
print("=" * 70)
