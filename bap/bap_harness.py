#!/usr/bin/env python3
"""
BAP Universal IDE & CLI Harness Manager
========================================
Manages developer harnesses (GitHub Copilot, Google Antigravity, Claude Code):
- Initializes IDE configurations, hooks, and MCP servers.
- Manages dynamic agent & session lifecycles (start, prompt, list, stop, clean).
- Enforces strict Agent Isolation and Session Isolation:
  Multiple concurrent sessions under the same Agent (e.g. 2 Claude sessions,
  2 Copilot sessions) run with distinct session IDs, isolated PIDs, independent
  prompts, and independent audit ledgers.

Zero external dependencies (pure Python standard library).
"""

import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BAPSTATE_DIR = os.path.join(os.path.expanduser("~"), ".bapstate")
SESSIONS_DIR = os.path.join(BAPSTATE_DIR, "sessions")
PROMPTS_DIR = os.path.join(BAPSTATE_DIR, "prompts")
DEFAULT_SERVER_URL = "http://localhost:8080"

SUPPORTED_AGENTS = ["claude-code", "copilot", "antigravity"]


def ensure_dirs():
    os.makedirs(SESSIONS_DIR, exist_ok=True)
    os.makedirs(PROMPTS_DIR, exist_ok=True)


def get_binary_path(name: str) -> str:
    exe_name = name + ".exe" if sys.platform == "win32" and not name.endswith(".exe") else name
    candidates = [
        os.path.join(REPO_ROOT, "dist", "windows-amd64", exe_name),
        os.path.join(REPO_ROOT, "dist", "windows-amd64", "claude-client", exe_name),
        os.path.join(REPO_ROOT, exe_name),
        os.path.join(REPO_ROOT, "bap-edge", exe_name),
        os.path.join(REPO_ROOT, "cchook", exe_name),
        os.path.join(REPO_ROOT, "copilot", exe_name),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    found = shutil.which(exe_name)
    if found:
        return found
    return candidates[0]


def is_pid_alive(pid: int) -> bool:
    if not pid or pid <= 0:
        return False
    if sys.platform == "win32":
        try:
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            SYNCHRONIZE = 0x00100000
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
            if not handle:
                return False
            exit_code = ctypes.c_ulong()
            kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            kernel32.CloseHandle(handle)
            return exit_code.value == 259 # STILL_ACTIVE
        except Exception:
            return True
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


def http_post(url: str, payload: dict, timeout: float = 0.4) -> tuple:
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, body
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        finally:
            e.close()
        return e.code, body
    except Exception as e:
        if hasattr(e, "close"):
            try:
                e.close()
            except Exception:
                pass
        return None, str(e)


def classify_prompt_intent(prompt: str) -> dict:
    lower = prompt.lower()
    primary = "UNKNOWN"
    tags = []

    if any(k in lower for k in ["fix", "bug", "error", "defect", "broken", "issue"]):
        primary = "BUG_FIX"
    elif any(k in lower for k in ["refactor", "clean", "simplify", "restructure"]):
        primary = "REFACTOR"
    elif any(k in lower for k in ["test", "verify", "coverage", "validate"]):
        primary = "TEST_VERIFICATION"
    elif any(k in lower for k in ["deploy", "release", "rollout", "production"]):
        primary = "DEPLOYMENT_RELEASE"
    elif any(k in lower for k in ["investigate", "inspect", "analyze", "review", "status", "audit"]):
        primary = "INVESTIGATION"
    elif any(k in lower for k in ["feature", "add", "implement", "build", "create", "enhance"]):
        primary = "FEATURE_ENHANCEMENT"
    elif any(k in lower for k in ["db", "database", "sql", "migration", "schema"]):
        primary = "DATABASE_CHANGE"

    if "api" in lower or "endpoint" in lower:
        tags.append("API")
    if "security" in lower or "auth" in lower or "secret" in lower:
        tags.append("SECURITY")
    if "database" in lower or "db" in lower:
        tags.append("DATABASE")

    return {
        "primary": primary,
        "confidence": 0.85 if primary != "UNKNOWN" else 0.40,
        "classifier_version": "bap-harness-intent-v1",
        "tags": tags,
    }


# =============================================================================
# 1. INITIALIZE & INSTALL HOOKS
# =============================================================================

def cmd_init(args):
    print("=" * 76)
    print("       BAP UNIVERSAL HARNESS INITIALIZATION & HOOK INSTALLATION        ")
    print("=" * 76)

    target_dir = os.path.abspath(args.workspace or REPO_ROOT)
    print(f"[*] Workspace Target: {target_dir}")

    bapedge_bin = get_binary_path("bapedge")
    cchook_bin = get_binary_path("cchook-interceptor")
    copilot_bin = get_binary_path("copilot-interceptor")
    mcp_bin = get_binary_path("bapmcp")
    if not os.path.isfile(mcp_bin):
        mcp_bin = bapedge_bin

    print(f"[*] Resolved Edge Daemon: {bapedge_bin}")
    print(f"[*] Resolved Claude Hook: {cchook_bin}")
    print(f"[*] Resolved Copilot Hook: {copilot_bin}")

    installed = []

    # 1. Claude Code Hook (.claude/settings.json + .claude/mcp.json)
    claude_dir = os.path.join(target_dir, ".claude")
    claude_hooks_dir = os.path.join(claude_dir, "hooks")
    os.makedirs(claude_hooks_dir, exist_ok=True)

    # Copy / link interceptor binary into .claude/hooks/
    interceptor_dest = os.path.join(claude_hooks_dir, "interceptor.exe" if sys.platform == "win32" else "interceptor")
    if os.path.isfile(cchook_bin):
        try:
            shutil.copy2(cchook_bin, interceptor_dest)
            installed.append(f"Claude Hook Binary: {interceptor_dest}")
        except Exception as e:
            print(f"[-] Warning copying hook: {e}")

    settings_file = os.path.join(claude_dir, "settings.json")
    hook_cmd = "interceptor.exe" if sys.platform == "win32" else "interceptor"
    interceptor_hook = {
        "type": "command",
        "command": hook_cmd
    }
    claude_settings = {
        "hooks": {
            "SessionStart": [
                {"hooks": [interceptor_hook]}
            ],
            "UserPromptSubmit": [
                {"hooks": [interceptor_hook]}
            ],
            "PreToolUse": [
                {"matcher": "*", "hooks": [interceptor_hook]}
            ],
            "SessionEnd": [
                {"hooks": [interceptor_hook]}
            ]
        }
    }
    with open(settings_file, "w", encoding="utf-8") as f:
        json.dump(claude_settings, f, indent=2)
    installed.append(f"Claude Settings: {settings_file}")

    # Claude MCP (.claude/mcp.json)
    claude_mcp_file = os.path.join(claude_dir, "mcp.json")
    claude_mcp = {
        "mcpServers": {
            "bap-zero-trust": {
                "command": mcp_bin if mcp_bin != bapedge_bin else bapedge_bin,
                "args": ["mcp"] if mcp_bin == bapedge_bin else [],
                "env": {
                    "LTD_SOURCE": "claude-code",
                    "BAP_SESSION_ID": "sess-claude-mcp"
                }
            }
        }
    }
    with open(claude_mcp_file, "w", encoding="utf-8") as f:
        json.dump(claude_mcp, f, indent=2)
    installed.append(f"Claude MCP Config: {claude_mcp_file}")

    # 2. GitHub Copilot (.vscode/settings.json + .vscode/mcp.json)
    vscode_dir = os.path.join(target_dir, ".vscode")
    os.makedirs(vscode_dir, exist_ok=True)

    copilot_wrap_bat = os.path.join(REPO_ROOT, "copilot", "copilot-wrap.bat")
    copilot_wrap_sh = os.path.join(REPO_ROOT, "copilot", "copilot-wrap.sh")
    wrap_script = copilot_wrap_bat if sys.platform == "win32" else copilot_wrap_sh

    vscode_settings_file = os.path.join(vscode_dir, "settings.json")
    vscode_settings = {}
    if os.path.isfile(vscode_settings_file):
        try:
            with open(vscode_settings_file, "r", encoding="utf-8") as f:
                vscode_settings = json.load(f)
        except Exception:
            pass

    if sys.platform == "win32":
        vscode_settings["terminal.integrated.profiles.windows"] = {
            "CopilotSandbox": {
                "path": wrap_script,
                "overrideName": True
            }
        }
        vscode_settings["terminal.integrated.defaultProfile.windows"] = "CopilotSandbox"
    else:
        vscode_settings["terminal.integrated.profiles.linux"] = {
            "CopilotSandbox": {
                "path": wrap_script,
                "overrideName": True
            }
        }
        vscode_settings["terminal.integrated.defaultProfile.linux"] = "CopilotSandbox"

    with open(vscode_settings_file, "w", encoding="utf-8") as f:
        json.dump(vscode_settings, f, indent=2)
    installed.append(f"Copilot VS Code Settings: {vscode_settings_file}")

    # Copilot MCP (.vscode/mcp.json)
    vscode_mcp_file = os.path.join(vscode_dir, "mcp.json")
    vscode_mcp = {
        "servers": {
            "bap-zero-trust": {
                "command": mcp_bin if mcp_bin != bapedge_bin else bapedge_bin,
                "args": ["mcp"] if mcp_bin == bapedge_bin else [],
                "env": {
                    "LTD_SOURCE": "copilot-mcp",
                    "BAP_SESSION_ID": "sess-copilot-mcp"
                }
            }
        }
    }
    with open(vscode_mcp_file, "w", encoding="utf-8") as f:
        json.dump(vscode_mcp, f, indent=2)
    installed.append(f"Copilot MCP Config: {vscode_mcp_file}")

    # 3. Google Antigravity (.antigravity/ + GEMINI.md)
    antigravity_dir = os.path.join(target_dir, ".antigravity")
    os.makedirs(antigravity_dir, exist_ok=True)
    gemini_file = os.path.join(target_dir, "GEMINI.md")
    gemini_rule = """# BAP Zero-Trust Policy & Shell Governance for Antigravity

All shell executions, code modifications, and package manager invocations
are governed under BAP Zero-Trust constraints:
- In-process Cedar policy gating evaluates every command before execution.
- Credential theft (.env, ~/.ssh, ~/.aws) and unauthorized exfiltration (curl, wget, nc) are permanently blocked.
- Content hash pinning (AIR Model) prevents skill or prompt drift.
- Operations stream to the Live Workload Radar and immutable audit ledger.
"""
    with open(gemini_file, "w", encoding="utf-8") as f:
        f.write(gemini_rule)
    installed.append(f"Antigravity Rules: {gemini_file}")

    # 4. Claude Desktop User Config (optional, if AppData path exists)
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            desktop_dir = os.path.join(appdata, "Claude")
            if os.path.isdir(desktop_dir):
                desktop_cfg = os.path.join(desktop_dir, "claude_desktop_config.json")
                cfg_data = {}
                if os.path.isfile(desktop_cfg):
                    try:
                        with open(desktop_cfg, "r", encoding="utf-8") as f:
                            cfg_data = json.load(f)
                    except Exception:
                        pass
                if "mcpServers" not in cfg_data:
                    cfg_data["mcpServers"] = {}
                cfg_data["mcpServers"]["bap-zero-trust"] = {
                    "command": mcp_bin if mcp_bin != bapedge_bin else bapedge_bin,
                    "args": ["mcp"] if mcp_bin == bapedge_bin else [],
                    "env": {
                        "LTD_SOURCE": "claude-desktop",
                        "BAP_SESSION_ID": "sess-claude-desktop"
                    }
                }
                with open(desktop_cfg, "w", encoding="utf-8") as f:
                    json.dump(cfg_data, f, indent=2)
                installed.append(f"Claude Desktop MCP Config: {desktop_cfg}")

    print("\n[+] Configured Harness Elements:")
    for item in installed:
        print(f"  - {item}")
    print("\n[OK] All IDE CLI hooks and MCP configurations successfully installed!")


# =============================================================================
# 2. START SESSION (AGENT & SESSION ISOLATION)
# =============================================================================

def cmd_start_session(args):
    ensure_dirs()
    agent = args.agent.lower()
    if agent not in SUPPORTED_AGENTS:
        print(f"[-] Warning: Unrecognized agent {agent}, standard types: {SUPPORTED_AGENTS}")

    session_id = args.session_id or f"sess-{agent}-{uuid.uuid4().hex[:8]}"
    pid = int(args.pid) if args.pid else os.getpid()
    prompt = args.prompt or f"Governed session for {agent}"
    instance_id = args.instance_id or f"{os.environ.get('COMPUTERNAME', 'host')}-{pid}"
    server_url = (args.server or DEFAULT_SERVER_URL).rstrip("/")
    user_id = os.environ.get("USERNAME") or os.environ.get("USER") or "developer"
    hostname = os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "localhost"

    intent = classify_prompt_intent(prompt)

    # 1. Register with Control Plane (idempotent / graceful offline fallback)
    start_payload = {
        "session_id": session_id,
        "app_id": agent,
        "user_id": user_id,
        "hostname": hostname,
        "client_pid": pid,
        "initial_prompt": prompt,
        "intent": intent,
        "instance_id": instance_id,
    }
    status, resp = http_post(f"{server_url}/api/v1/sessions/start", start_payload)
    enrolled_remote = (status == 200)

    # 2. Write Isolated Session Markers
    marker_data = {
        "session_id": session_id,
        "app_id": agent,
        "user_id": user_id,
        "hostname": hostname,
        "client_pid": pid,
        "pid": pid,
        "server_url": server_url,
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "active",
        "initial_prompt": prompt,
        "intent": intent,
        "instance_id": instance_id,
        "enrolled_remote": enrolled_remote,
    }

    # Isolated hash marker: .bapstate/sessions/<hash>.json
    h = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    session_hash_path = os.path.join(SESSIONS_DIR, f"{h}.json")
    with open(session_hash_path, "w", encoding="utf-8") as f:
        json.dump(marker_data, f, indent=2)

    # Isolated PID marker: .bapstate/sessions/pid-<pid>.json
    session_pid_path = os.path.join(SESSIONS_DIR, f"pid-{pid}.json")
    with open(session_pid_path, "w", encoding="utf-8") as f:
        json.dump(marker_data, f, indent=2)

    # Workspace fallback marker: .bap/session.json
    workspace_bap = os.path.join(REPO_ROOT, ".bap")
    os.makedirs(workspace_bap, exist_ok=True)
    with open(os.path.join(workspace_bap, "session.json"), "w", encoding="utf-8") as f:
        json.dump(marker_data, f, indent=2)

    # 3. Cache Initial Prompt
    prompt_hash = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    prompt_cache_file = os.path.join(PROMPTS_DIR, f"{prompt_hash}.txt")
    with open(prompt_cache_file, "w", encoding="utf-8") as f:
        f.write(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] {prompt}\n")

    # 4. Transmit Prompt to Control Plane
    if enrolled_remote:
        prompt_payload = {
            "session_id": session_id,
            "prompt": prompt,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "intent": intent,
        }
        http_post(f"{server_url}/api/v1/sessions/prompt", prompt_payload)

    # 5. Launch Background Watcher Thread if requested
    watcher_launched = False
    if args.watch:
        bapedge_bin = get_binary_path("bapedge")
        if os.path.isfile(bapedge_bin):
            try:
                subprocess.Popen(
                    [
                        bapedge_bin, "watch",
                        f"--pid={pid}",
                        f"--server={server_url}",
                        f"--session-id={session_id}",
                        f"--app={agent}",
                        "--detach"
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
                )
                watcher_launched = True
            except Exception as e:
                print(f"[-] Warning starting watcher: {e}")

    print("+" + "-" * 74 + "+")
    print(f"|  SESSION STARTED: {session_id:<54} |")
    print("+" + "-" * 74 + "+")
    print(f"  - Agent Identity : {agent} (spiffe://bap.local/agent/{agent})")
    print(f"  - Process PID    : {pid}")
    print(f"  - Control Plane  : {'Enrolled (Live Radar active)' if enrolled_remote else 'Offline / Degraded Local'}")
    print(f"  - Primary Intent : {intent['primary']} (confidence: {intent['confidence']:.2f})")
    print(f"  - Watcher Thread : {'Active (pulsing heartbeats)' if watcher_launched else 'Off'}")
    print(f"  - Marker File    : {session_hash_path}")
    print(f"  - Prompt Context : {prompt[:60]}...")
    print("+" + "-" * 74 + "+")

    return marker_data


# =============================================================================
# 3. TRANSMIT PROMPT
# =============================================================================

def cmd_send_prompt(args):
    session_id = args.session_id
    prompt = args.prompt
    server_url = (args.server or DEFAULT_SERVER_URL).rstrip("/")

    intent = classify_prompt_intent(prompt)
    prompt_payload = {
        "session_id": session_id,
        "prompt": prompt,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "intent": intent,
    }
    status, body = http_post(f"{server_url}/api/v1/sessions/prompt", prompt_payload)

    # Append to local prompt history
    ensure_dirs()
    prompt_hash = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    prompt_cache_file = os.path.join(PROMPTS_DIR, f"{prompt_hash}.txt")
    with open(prompt_cache_file, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] {prompt}\n")

    print(f"[+] Prompt transmitted to session {session_id}:")
    print(f"    - Text   : {prompt}")
    print(f"    - Intent : {intent['primary']} (Tags: {', '.join(intent['tags']) if intent['tags'] else 'none'})")
    print(f"    - Status : {'Synchronized with Control Plane' if status == 200 else 'Logged locally'}")


# =============================================================================
# 4. LIST SESSIONS (GROUPED BY AGENT)
# =============================================================================

def cmd_list_sessions(args):
    ensure_dirs()
    sessions = []

    # Read from local session directory
    if os.path.isdir(SESSIONS_DIR):
        for entry in os.listdir(SESSIONS_DIR):
            if entry.endswith(".json") and not entry.startswith("pid-"):
                path = os.path.join(SESSIONS_DIR, entry)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        pid = data.get("client_pid") or data.get("pid", 0)
                        data["alive"] = is_pid_alive(pid) if pid > 0 else False
                        sessions.append(data)
                except Exception:
                    pass

    # Group by Agent app_id
    grouped = {}
    for s in sessions:
        agent = s.get("app_id", "unknown")
        grouped.setdefault(agent, []).append(s)

    print("=" * 86)
    print("                      ACTIVE BAP HARNESS AGENT SESSIONS                       ")
    print("=" * 86)

    if not grouped:
        print("  [i] No active sessions found in .bapstate/sessions/.")
        print("=" * 86)
        return

    total_sessions = 0
    for agent, sess_list in sorted(grouped.items()):
        print(f"\n[*] Agent: {agent.upper()} ({len(sess_list)} concurrent session{'s' if len(sess_list) > 1 else ''})")
        print(f"   SPIFFE Identity: spiffe://bap.local/agent/{agent}")
        print("   " + "-" * 80)
        print("   {:<28} {:<8} {:<10} {:<18} {:<14}".format(
            "Session ID", "PID", "State", "Intent", "Started At"
        ))
        print("   " + "-" * 80)
        for s in sess_list:
            total_sessions += 1
            sess_id = s.get("session_id", "unknown")
            pid = str(s.get("client_pid") or s.get("pid", 0))
            alive = "[ACTIVE]" if s.get("alive") else "[IDLE/OFF]"
            intent = (s.get("intent") or {}).get("primary", "UNKNOWN")
            started = s.get("started_at", "")[:19]
            print(f"   {sess_id:<28} {pid:<8} {alive:<10} {intent:<18} {started:<14}")
            if s.get("initial_prompt"):
                print(f"     +- Prompt: \"{s['initial_prompt'][:68]}...\"")

    print("\n" + "=" * 86)
    print(f"Total: {len(grouped)} Agents Active | {total_sessions} Isolated Sessions Running")
    print("=" * 86)


# =============================================================================
# 5. STOP SESSION
# =============================================================================

def cmd_stop_session(args):
    ensure_dirs()
    target_id = args.session_id
    target_pid = int(args.pid) if args.pid else 0
    server_url = (args.server or DEFAULT_SERVER_URL).rstrip("/")

    found_sessions = []

    if os.path.isdir(SESSIONS_DIR):
        for entry in os.listdir(SESSIONS_DIR):
            if entry.endswith(".json"):
                path = os.path.join(SESSIONS_DIR, entry)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        s_id = data.get("session_id")
                        s_pid = data.get("client_pid") or data.get("pid", 0)
                        if (target_id and s_id == target_id) or (target_pid and s_pid == target_pid):
                            found_sessions.append((path, data))
                except Exception:
                    pass

    if not found_sessions and target_id:
        # Deregister with control plane directly
        http_post(f"{server_url}/api/v1/sessions/end", {"session_id": target_id, "reason": "user_terminated"})
        print(f"[+] Deregistered session {target_id} from control plane.")
        return

    for path, data in found_sessions:
        s_id = data.get("session_id")
        pid = data.get("client_pid") or data.get("pid", 0)

        # Notify Control Plane
        if s_id:
            http_post(f"{server_url}/api/v1/sessions/end", {"session_id": s_id, "reason": "workload_completed"})

        # Remove markers
        if os.path.isfile(path):
            try:
                os.remove(path)
            except Exception:
                pass

        if s_id:
            h = hashlib.sha256(s_id.encode("utf-8")).hexdigest()
            h_path = os.path.join(SESSIONS_DIR, f"{h}.json")
            if os.path.isfile(h_path):
                try:
                    os.remove(h_path)
                except Exception:
                    pass

        if pid:
            pid_path = os.path.join(SESSIONS_DIR, f"pid-{pid}.json")
            if os.path.isfile(pid_path):
                try:
                    os.remove(pid_path)
                except Exception:
                    pass

        print(f"[OK] Stopped and cleaned up session {s_id} (PID: {pid}). Other sessions remain isolated.")


# =============================================================================
# 6. CLEANUP ALL
# =============================================================================

def cmd_cleanup_all(args):
    ensure_dirs()
    server_url = (args.server or DEFAULT_SERVER_URL).rstrip("/")

    # Query active sessions from control plane
    try:
        req = urllib.request.Request(f"{server_url}/api/v1/inspector/data")
        with urllib.request.urlopen(req, timeout=0.4) as resp:
            data = json.loads(resp.read().decode())
            for s in data.get("sessions", []):
                s_id = s.get("session_id")
                if s.get("status") == "active" and s_id:
                    http_post(f"{server_url}/api/v1/sessions/end", {"session_id": s_id, "reason": "cleanup_all"})
                    print(f"  [-] Closed remote session: {s_id}")
    except urllib.error.HTTPError as e:
        try:
            e.close()
        except Exception:
            pass
    except Exception as e:
        if hasattr(e, "close"):
            try:
                e.close()
            except Exception:
                pass

    # Purge local session markers
    purged = 0
    if os.path.isdir(SESSIONS_DIR):
        for entry in os.listdir(SESSIONS_DIR):
            if entry.endswith(".json"):
                try:
                    os.remove(os.path.join(SESSIONS_DIR, entry))
                    purged += 1
                except Exception:
                    pass

    # Purge workspace fallback
    workspace_marker = os.path.join(REPO_ROOT, ".bap", "session.json")
    if os.path.isfile(workspace_marker):
        try:
            os.remove(workspace_marker)
        except Exception:
            pass

    print(f"[OK] Cleaned up {purged} session markers. Active agents count reset to 0.")


# =============================================================================
# 7. RUN GOVERNED COMMAND
# =============================================================================

def cmd_run_governed(args):
    agent = args.agent.lower()
    session_id = args.session_id or f"sess-{agent}-{os.getpid()}"
    cmd_to_run = args.command

    bapedge_bin = get_binary_path("bapedge")
    if not os.path.isfile(bapedge_bin):
        print(f"[-] Error: Could not locate bapedge executable at {bapedge_bin}")
        sys.exit(1)

    exec_args = [bapedge_bin, "exec", "--source", agent, "--session-id", session_id]
    if args.decision_only:
        exec_args.append("--decision-only")
    exec_args.extend(["--", cmd_to_run])

    env = os.environ.copy()
    env["BAP_SESSION_ID"] = session_id
    env["LTD_SOURCE"] = agent

    proc = subprocess.run(exec_args, env=env)
    sys.exit(proc.returncode)


# =============================================================================
# MAIN CLI DISPATCHER
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="BAP Universal IDE & CLI Harness Manager (Copilot, Antigravity, Claude Code)"
    )
    subparsers = parser.add_subparsers(dest="action", help="Harness management command")

    # init
    p_init = subparsers.add_parser("init", help="Install hooks and configure IDEs & CLIs")
    p_init.add_argument("--workspace", help="Target workspace root", default=REPO_ROOT)

    # start-session
    p_start = subparsers.add_parser("start-session", help="Start and register an isolated agent session")
    p_start.add_argument("--agent", required=True, choices=SUPPORTED_AGENTS, help="Agent identity")
    p_start.add_argument("--session-id", help="Custom session ID (auto-generated if omitted)")
    p_start.add_argument("--instance-id", help="Custom instance identifier")
    p_start.add_argument("--prompt", help="Initial user prompt / mission context")
    p_start.add_argument("--pid", type=int, help="Target process PID to bind to session")
    p_start.add_argument("--server", help="BAP Control Plane URL", default=DEFAULT_SERVER_URL)
    p_start.add_argument("--watch", action="store_true", help="Launch detached watcher thread for pulse")

    # send-prompt
    p_prompt = subparsers.add_parser("send-prompt", help="Transmit a prompt to an active session")
    p_prompt.add_argument("--session-id", required=True, help="Target session ID")
    p_prompt.add_argument("--prompt", required=True, help="User prompt to transmit")
    p_prompt.add_argument("--server", help="BAP Control Plane URL", default=DEFAULT_SERVER_URL)

    # list-sessions
    p_list = subparsers.add_parser("list-sessions", help="List all active sessions grouped by agent")

    # stop-session
    p_stop = subparsers.add_parser("stop-session", help="Stop and cleanly deregister a specific session")
    p_stop.add_argument("--session-id", help="Session ID to terminate")
    p_stop.add_argument("--pid", type=int, help="Process PID to terminate")
    p_stop.add_argument("--server", help="BAP Control Plane URL", default=DEFAULT_SERVER_URL)

    # cleanup-all
    p_clean = subparsers.add_parser("cleanup-all", help="Clean up and deregister all active sessions")
    p_clean.add_argument("--server", help="BAP Control Plane URL", default=DEFAULT_SERVER_URL)

    # run-governed
    p_run = subparsers.add_parser("run-governed", help="Execute a command under governed agent session")
    p_run.add_argument("--agent", required=True, choices=SUPPORTED_AGENTS, help="Agent identity")
    p_run.add_argument("--session-id", help="Session ID")
    p_run.add_argument("--decision-only", action="store_true", help="Pre-flight policy check without execution")
    p_run.add_argument("command", help="Shell command to execute")

    args = parser.parse_args()
    if not args.action:
        parser.print_help()
        sys.exit(0)

    if args.action == "init":
        cmd_init(args)
    elif args.action == "start-session":
        cmd_start_session(args)
    elif args.action == "send-prompt":
        cmd_send_prompt(args)
    elif args.action == "list-sessions":
        cmd_list_sessions(args)
    elif args.action == "stop-session":
        cmd_stop_session(args)
    elif args.action == "cleanup-all":
        cmd_cleanup_all(args)
    elif args.action == "run-governed":
        cmd_run_governed(args)


if __name__ == "__main__":
    main()
