# 🚀 BAP Developer Onboarding & Quickstart Guide
## Zero-Trust Runtime Governance for AI Coding Agents

Welcome to the **Bounded Authority Plane (BAP)**. BAP is an enterprise-grade Zero-Trust runtime authorization and identity platform that secures, monitors, and audits autonomous AI coding agents—including **Claude Code**, **Google Antigravity**, **Cursor IDE**, **GitHub Copilot CLI**, and **custom Python agents**—running on developer workstations.

---

## 1. Single-Click Installation (Zero-Privilege / User-Mode)

BAP requires **no administrator or root privileges** (`no UAC`, `no sudo`) for developer workstations. It installs directly into your user environment and configures agent hooks automatically.

### Option A: Via Python / PyPI (Recommended)
```bash
# 1. Install BAP CLI
pip install bap-ltd

# 2. Run automated user-mode installer
bap install

# 3. Run pre-flight health diagnostics
bap doctor

# 4. Open developer cockpit & verify governed agents
bap launch
```

### Option B: Direct Script Execution (Without Pip)
```bash
python scripts/bap_install.py
python scripts/bap_doctor.py
python scripts/bap_launch.py
```

### What the Installer Does Automatically
1. **Deploys Binaries** to user directory (`%LOCALAPPDATA%\BAP\bin` on Windows or `~/.local/bin` on macOS/Linux).
2. **Updates User PATH** persistently across shells without triggering UAC elevation or sudo prompts.
3. **Autodetects Installed Agents**:
   - **Claude Code**: Configures `.claude/settings.json` lifecycle hooks and `.claude/mcp.json`.
   - **Google Antigravity**: Configures zero-trust workspace invariants in `GEMINI.md` and registers the BAP MCP server.
   - **Cursor IDE**: Sets up `.cursorrules` and `.cursor/mcp.json` with terminal broker routing.
   - **GitHub Copilot**: Configures VS Code `CopilotSandbox` profile and terminal execution wrappers.
   - **Python SDK**: Links local `bap_sdk` libraries for autonomous Python agents.
4. **Connects to Control Plane**: Connects to the central control plane (`https://bap-controlplane.onrender.com` or your company's private server).
5. **Cryptographic AIR Pinning**: Scans and cryptographically pins workspace prompts (`CLAUDE.md`, `GEMINI.md`, `policy.cedar`) to detect prompt drift or supply-chain poisoning.

---

## 2. Pre-Flight Diagnostic Health Check (`bap doctor`)

Before starting your day, run the built-in diagnostic doctor to verify system health:

```bash
bap doctor
```

Sample Output:
```text
===============================================================================
           BOUNDED AUTHORITY PLANE (BAP) - PRE-FLIGHT DOCTOR
===============================================================================
[*] Timestamp: 2026-10-20 06:32:02 | Host: WORKSTATION-01 | User: alice

[1/5] Core BAP Binaries & Client Tools...
  [PASS] bapedge (Edge Daemon)               : ~/.local/bin/bapedge (8.25 MB)
  [PASS] interceptor (Hook)                  : ~/.local/bin/interceptor (8.73 MB)
  [PASS] run_claude_bap (Launcher)           : /workspace/run_claude_bap.bat

[2/5] AI Agent Runtime Detection...
  [PASS] Claude Code CLI                     : ~/.local/bin/claude (2.1.289)
  [PASS] Google Antigravity Rule             : Active (GEMINI.md)

[3/5] Control Plane Connectivity & TLS...
  [PASS] TCP Listener (localhost:8443)       : Port open (Latency: 0.8 ms)

[4/5] Cedar Policy Engine & Schema Invariants...
  [PASS] Cedar Policy (policy.cedar)         : 205 lines loaded
  [PASS] Local Policy Evaluation             : Safe command authorized in 1.2 ms

[5/5] Workspace & Recovery Custody...
  [PASS] Workspace .bap/ Isolation           : Isolated directory active (Zero root clutter)
  [PASS] Active Session Concurrency          : Idle (No lingering transactions or lockouts)

===============================================================================
  DOCTOR STATUS: ALL SYSTEMS HEALTHY! (10/10 passed)
===============================================================================
```

---

## 3. Using BAP with Your Coding Agents

### 1. Claude Code
Simply run `claude` inside your project as normal:
```bash
claude
```
- **SessionStart**: Automatically registers your session with a unique SPIFFE ID (`spiffe://bap.internal/app/claude-code/instance/...`).
- **UserPromptSubmit**: Transmits your prompt to the central radar with heuristic intent classification (`BUG_FIX`, `REFACTOR`, `SECURITY`).
- **PreToolUse**: Evaluates shell commands against Cedar invariants. Allowed commands run through `bapedge exec` inside an isolated OS sandbox token.

### 2. Google Antigravity
Pair program with Antigravity directly in your IDE:
- Antigravity follows the zero-trust invariants declared in `GEMINI.md`.
- All commands run governed via `bapedge exec "<cmd>"`.
- Dangerous operations (reading `.env`, dumping SSH keys, deleting outside root) are denied with structured remediation suggestions.

### 3. Cursor IDE
Open the project in Cursor:
- `.cursorrules` instructs the assistant to route terminal executions through `bapedge exec`.
- Background adapter emits `CanonicalActivityEvent` telemetry to the central cockpit.

### 4. GitHub Copilot
In VS Code:
1. Open the Integrated Terminal (`Ctrl+\`` or `Cmd+\``).
2. The terminal defaults to the **`CopilotSandbox`** profile.
3. Outbound commands are automatically brokered and checked against Cedar policies.

### 5. Custom Python Agents (LangChain, AutoGen, CrewAI)
```python
from bap_sdk import BAPSession

# Start a governed agent session
session = BAPSession(app_id="payment-refactor-agent", user_id="alice")
session.start()

# Execute shell operations through the BAP broker
result = session.execute("pytest tests/")
print(f"Allowed: {result.allowed}, Exit Code: {result.exit_code}")

session.end()
```

---

## 4. Human Step-Up Approvals (Cross-Folder Operations)

When an agent attempts a mutating operation outside the workspace boundary (e.g. updating a dependency in a sibling repository):
```text
[!] STEP-UP REQUIRED: Agent requested write outside workspace root.
    Target: ../shared-library/auth.py
    [O] Approve Once
    [S] Remember for this Session
    [P] Remember for this Project
    [G] Remember Globally
    [D] Deny
```
- **Read-Only operations** (`cat`, `dir`, `git status`) outside workspace root are permitted automatically under Cedar Rule 2.
- **Mutations** require explicit Human-in-the-Loop (HITL) approval, preventing agent runaway side-effects.

---

## 5. Enterprise Enforcement Modes: Audit vs Enforce

BAP can operate in two distinct modes configured in `bap-config.json` or via CLI:

| Mode | Behavior | Best Used For |
| :--- | :--- | :--- |
| **`audit` (Shadow)** | Flags policy violations as `shadow_deny` in audit logs, prints warnings, but allows execution to proceed. | Initial onboarding, pilot baselining, zero-friction developer adoption. |
| **`enforce`** | Strictly blocks prohibited commands (`ExitCode: 1`) and isolates processes in restricted sandboxes. | Production security, hardened enterprise compliance. |

To toggle modes:
```bash
# Switch to audit mode
bapedge config --mode audit

# Switch to enforce mode
bapedge config --mode enforce
```

---

## 6. Daily Verification & Diagnostic Commands

| Command | Action |
| :--- | :--- |
| `bap doctor` | Run comprehensive 5-point environment and pre-flight health check |
| `bap launch` | Start developer cockpit, verify hooks & monitor active agents |
| `bap status` | Check status of the local edge daemon and central control plane |
| `bapedge why "<cmd>"` | Direct terminal explanation of Cedar policy decisions ("Why Was It Blocked?") |
| `bapedge permissions` | View active cross-folder permissions across Session, Project, and Global scopes |
| `bap pin verify` | Verify cryptographic hashes of workspace prompts, rules, and skills |
| `bap exec "<cmd>"` | Manually execute a shell command inside the BAP Zero-Trust broker |

---

## 7. Troubleshooting & Emergency Rollback

### If a Command is Unexpectedly Denied:
1. Run `bapedge why "<command>"` to see the exact Cedar policy and explanation.
2. If it is a safe cross-folder operation, authorize it via:
   ```bash
   bapedge trust --path /path/to/folder --scope project --ops write
   ```

### To Temporarily Revert to Unmonitored Mode:
Switch to audit mode:
```bash
bapedge config --mode audit
```

### Complete Clean Uninstallation (< 10 seconds):
```bash
python scripts/bap_install.py --uninstall
```
All agent hooks (`.claude/settings.json`, VS Code configurations, environment variables) are instantly restored to their original pre-install states.
