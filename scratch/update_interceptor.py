import shutil
import os

repo_root = os.path.abspath(os.path.dirname(__file__) + "/..")
src = os.path.join(repo_root, "cchook", "interceptor.exe")
if not os.path.isfile(src):
    raise FileNotFoundError(f"Source binary not found: {src}")

destinations = [
    os.path.join(repo_root, "interceptor.exe"),
    os.path.join(repo_root, "cchook-interceptor.exe"),
    os.path.join(repo_root, "dist", "windows-amd64", "interceptor.exe"),
    os.path.join(repo_root, "dist", "windows-amd64", "cchook-interceptor.exe"),
    os.path.join(repo_root, "dist", "windows-amd64", "claude-client", "interceptor.exe"),
    os.path.join(repo_root, "dist", "windows-amd64", "claude-client", "cchook", "interceptor.exe"),
    os.path.join(repo_root, "bap", "bin", "windows-amd64", "interceptor.exe"),
]

for dst in destinations:
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
    print(f"Updated: {dst}")

print("All interceptor binaries updated successfully.")
