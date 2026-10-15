# BAP Developer Onboarding & Quickstart Guide

Welcome to the **Bounded Authority Plane (BAP)**. BAP is an enterprise-grade Zero-Trust governance platform that secures, monitors, and audits autonomous AI coding agents—including **Claude Code**, **Google Antigravity**, **GitHub Copilot**, and **Python Agents**—running on developer workstations and enterprise networks.

---

## 1. Single-Click Installation (Zero-Privilege / User-Mode)

BAP requires **no administrator or root privileges** for developer workstations. It installs directly into your user environment and configures agent hooks automatically.

### Option A: Via Python / PyPI (Recommended)

```bash
pip install bap-ltd
bap install
```
Or run directly without installing a pip package:
```bash
python scripts/bap_install.py
```

### What the Installer Does Automatically
1. **Deploys Binaries** to user directory (`%LOCALAPPDATA%\BAP\bin` on Windows or `~/.local/bin` on macOS/Linux).
2. **Updates User PATH** persistently without triggering UAC or `sudo`.
3. **Autodetects Installed Agents**:
   - **Claude Code**: Configures `.claude/settings.json` lifecycle hooks and `.claude/mcp.json`.
   - **Google Antigravity**: Configures workspace rules in `GEMINI.md` and BAP MCP server.
   - **GitHub Copilot**: Configures VS Code `CopilotSandbox` profile and `.vscode/mcp.json`.
   - **Python SDK**: Links local Python agent libraries.
4. **Connects to Control Plane**: Interactively connects to the central cloud control plane (`https://bap-controlplane.onrender.com` by default), or your company's custom server.
5. **Cryptographic AIR Pinning**: Scans and cryptographically pins workspace prompts (`CLAUDE.md`, `GEMINI.md`, `policy.cedar`) to detect prompt drift or supply-chain poisoning.

---

## 2. Launching the Developer Cockpit

Run the unified cockpit from any project directory:
```bash
bap launch
```
Output:
```
================================================================================
      BAP ZERO-TRUST AGENT GOVERNANCE -- DEVELOPER COCKPIT
================================================================================
[*] Workspace Root       : /path/to/my-project
[*] Control Plane Server : https://bap-controlplane.onrender.com
[+] Resolved BAP Edge    : ~/.local/bin/bapedge
[+] Control Plane State  : ONLINE (Active Sessions on Radar: 77)
[+] Edge Daemon Status   : ACTIVE (User Space PID)
[+] AIR Content Pinning  : INTACT (All prompt templates & skill hashes verified)
================================================================================
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
- **PreToolUse**: Intercepts shell executions and tool calls before execution against Cedar invariants.

### 2. Google Antigravity
Pair program with Antigravity directly in your IDE:
- Antigravity follows the zero-trust invariants declared in `GEMINI.md`.
- All commands run governed via `bapedge exec "<cmd>"`.
- Dangerous operations (accessing `.env`, SSH keys, cross-project deletion) are blocked by Cedar policies.

### 3. GitHub Copilot
In VS Code:
1. Open the Integrated Terminal (`Ctrl+\`` or `Cmd+\``).
2. The terminal defaults to the **`CopilotSandbox`** governed profile.
3. Any actions triggered via Copilot terminal execution are monitored and audited in real time.

### 4. Custom Python Agents
If you are building autonomous agents with LangChain, AutoGen, CrewAI, or raw LLMs:
```python
from bap_sdk import BAPSession

session = BAPSession(app_id="my-custom-agent", user_id="developer.name")
session.start()

# Governed command execution
result = session.execute("pytest tests/")
print(f"Allowed: {result.allowed}, Exit Code: {result.exit_code}")

session.end()
```

---

## 4. Human Step-Up Approvals (Cross-Folder Operations)

When an agent attempts a cross-folder modification (e.g. updating a dependency in a parent directory):
1. BAP Edge alerts you with an interactive step-up prompt:
   ```
   [!] STEP-UP REQUIRED: Agent requested write outside workspace root.
       Target: ../shared-library/auth.py
       [O] Approve Once
       [S] Remember for this Session
       [P] Remember for this Project
       [G] Remember Globally
       [D] Deny
   ```
2. Your decision is remembered for the chosen scope, balancing strict zero-trust security with developer productivity.

---

## 5. Helpful Verification Commands

| Command | Action |
| :--- | :--- |
| `bap status` | Check status of the local edge daemon and control plane |
| `bap pin verify` | Verify that workspace prompts haven't been tampered with |
| `bap pin scan` | Discover and pin new skills, rules, and configuration files |
| `bap exec "<cmd>"` | Manually execute a command under BAP Zero-Trust broker |
| `bap launch` | Re-open the developer cockpit and check active agents |
