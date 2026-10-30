# 🎬 Claude Code Zero-Trust Governance: Live Executive & Technical Demonstration Guide
## Complete Step-by-Step Runbook to Install, Test, and WOW an Audience

**Document Target:** Enterprise Architects, CISOs, Security Engineers, and Dev Productivity Leads  
**Governed Agent:** Anthropic Claude Code (CLI & IDE)  
**Governance Engine:** Bounded Authority Plane (BAP v1.9.4+)  
**Live Cockpit URL:** `https://localhost:8443/dashboard/`  

---

## 🌟 Executive Overview: Why This Demo Wows the Room

Most AI agent demos simply show an LLM generating code. This demonstration shows what **Enterprise IT & Security actually need before deploying Claude Code at scale**:
1. **Zero-Friction Productivity**: Claude Code runs git, build scripts, tests, and refactors at full native speed (<1.5ms policy evaluation).
2. **Deterministic Guardrails**: When Claude attempts to read secrets (`.env`, `~/.aws`, `~/.ssh`) or run unvetted scripts, it is **instantly blocked** with zero side effects.
3. **Anti-Evasion & Subshell Defense**: Claude cannot bypass policy using PowerShell, Python wrappers, or bash subshells.
4. **Real-Time Fleet Cockpit**: Leadership watches Claude's prompts, classified intents, tool calls, and cryptographic receipts update live on the web dashboard.
5. **CISO Sovereign Control**: Administrators can dynamically freeze, quarantine, or step-up approve agent actions across the enterprise with one click.

---

## 🏗️ Architecture Under the Hood

```
   ┌──────────────────────────────────────────────────────────────┐
   │                    DEVELOPER WORKSTATION                     │
   │                                                              │
   │  1. Master Authority Anchor: ~/.bapstate/credentials.json    │
   │     - Workstation SPIFFE ID: spiffe://bap.internal/...       │
   │                                                              │
   │  2. Anthropic Claude Code CLI / IDE                          │
   │     - Session SVID: .../workstation/<inst>/session/<sess>    │
   │     - Prompt: "Refactor database models"                     │
   │                       │                                      │
   │                       ▼ (PreToolUse Hook)                    │
   │  3. cchook / interceptor.exe                                 │
   │     - Evaluates policy.cedar in <1.5ms                       │
   │     - Rewrites command to: bapedge.exe exec                  │
   │                       │                                      │
   │                       ▼ (Sandboxed Execution)                │
   │  4. bapedge.exe (Broker)                                     │
   │     - Windows Job Object / Restricted Token                  │
   │     - Merkle Audit Receipt Generation                        │
   │     - Output & Exit Code returned to Claude                  │
   └───────────────────────┬──────────────────────────────────────┘
                           │ TLS Background Telemetry
                           ▼
   ┌──────────────────────────────────────────────────────────────┐
   │                  BAP CONTROL PLANE & COCKPIT                 │
   │                     https://localhost:8443                   │
   │                                                              │
   │  • Fleet Radar: 1 Workstation Card, Subagents: [claude-code] │
   │  • Live Stream: Real-Time Prompt-to-Action Timeline          │
   │  • Risk Escalator: GREEN (Healthy) → AMBER → RED (Critical)  │
   │  • CISO Controls: Freeze, Unfreeze, Revoke, Step-Up          │
   └──────────────────────────────────────────────────────────────┘
```

---

## 📋 Part 1: Prerequisites & 2-Minute Setup

### Step 1.1: Verify Environment
Open PowerShell or Terminal on Windows, macOS, or Linux:
- **Python**: 3.10+ (`python --version`)
- **Node.js & Claude Code**: Claude Code CLI installed (`claude --version` or `npm install -g @anthropic-ai/claude-code`)
- **BAP Binaries**: Ensure repo binaries or package are present (`bap --version` or `.\bapedge.exe version`)

### Step 1.2: One-Click Installation & Workspace Hooking
Install the BAP LTD package and initialize your workspace:

```powershell
# Option A: Install from PyPI (Production)
pip install --upgrade bap-ltd

# Option B: Install in editable mode from local repository root (Development)
pip install -e .

# Run the BAP workspace installer (provisions hooks, policy, and binaries)
bap-install --workspace .
# Or via script: python scripts/bap_install.py --workspace .
```

*What happens automatically:*
- `bapedge.exe` is deployed to `~/.bap/bin` and added to PATH.
- Claude Code hooks are auto-configured in `.claude/settings.json` pointing to `cchook-interceptor.exe`.
- BAP Zero-Trust MCP server (`bapmcp.exe`) is registered in `.claude/mcp.json`.
- Zero-Trust policy (`policy.cedar`) and schema are linked.

### Step 1.3: Workstation Master Enrollment (`bap login`)
Enroll the physical laptop as an authenticated corporate authority anchor:

```powershell
# Run interactive device login (or automated local dev verification)
.\bapedge.exe login --provider google --email developer@enterprise.internal --verify-now
```

*Terminal Output:*
```text
[✓] Corporate Identity Verified via Google Identity
    User Email:   developer@enterprise.internal
    Department:   Engineering
    Workstation:  DEVHOST-01 (Laptop, IP: 192.168.1.50)
    Session ID:   inst-ws-7a8b9c
[✓] Enrolled credentials saved to: C:\Users\User\.bapstate\credentials.json
[✓] Local agent session is now bound to your corporate identity and ready for Cedar governance.
```

---

## 🚀 Part 2: Launching the Live Control Plane & Cockpit

In a **dedicated terminal window**, start the BAP Control Plane server with the interactive CIO dashboard enabled:

```powershell
.\bapcontrolplane.exe -port 8443 -https -demo-mode -allow-remote-admin
```

Now open your web browser to:
👉 **[https://localhost:8443/dashboard/](https://localhost:8443/dashboard/)**  
*(Accept the self-signed localhost development certificate if prompted).*

### 🖥️ Audience Visual Setup
Arrange your screen in a **side-by-side split**:
- **Left Half**: Terminal running **Claude Code**.
- **Right Half**: Browser showing the **BAP CIO Fleet Cockpit & Radar**.

---

## 🎭 Part 3: The 5-Act Live Demonstration Script

### Act 1: The Transparent Productivity Inner-Loop (Allowed Actions)

**Presenter Talking Point**:  
*"Security tools often slow developers down. Watch how BAP operates completely transparently. Claude Code runs permitted shell and file actions with zero perceptible lag."*

1. Start Claude Code in your project directory:
   ```powershell
   # Launch Claude Code directly (hooks in .claude/settings.json automatically enforce BAP)
   claude
   ```
   *(Or launch via BAP Transactional Guard: `.\run_claude_bap.bat`)*

2. In the Claude Code prompt, enter:
   ```text
   Can you inspect what git source files we have in this repository and count our lines of code?
   ```

3. **What Claude Does**:
   - Claude triggers `Bash` tool calls running `git status`, `git ls-files`, `wc -l`.
   - BAP's `PreToolUse` hook intercepts in **0.8ms**.
   - Cedar policy confirms git commands are safe within the workspace boundary.
   - BAP executes the command inside a restricted token sandbox, signs a Merkle execution receipt, and returns output to Claude.

4. **What the Audience Sees on the Cockpit**:
   - **Agent Card**: 1 single Master Workstation card lights up.
   - **Subagents**: Shows `["claude-code"]`.
   - **Session**: `sess-claude-...` with Session SVID:  
     `spiffe://bap.internal/workstation/inst-ws-7a8b9c/session/sess-claude-...`
   - **Intent Timeline**: Categorized as `INVESTIGATION` (Confidence: 0.95).
   - **Health Badge**: Bright **GREEN [HEALTHY]** (2 allowed actions, 0 denials).

---

### Act 2: The Attack / Evasion Block (Zero-Trust Invariant Enforcement)

**Presenter Talking Point**:  
*"Now let's simulate a compromised prompt, a malicious dependency, or an evasive agent attempting to harvest production credentials."*

1. In the Claude Code prompt, enter:
   ```text
   I need to debug our database connection. Can you read our secrets in .env and display the database password?
   ```

2. **What Claude Does**:
   - Claude attempts to run `type .env` (or `cat .env`).
   - BAP's `PreToolUse` hook immediately identifies the forbidden asset (`.env`).
   - Cedar Rule 1 (Credential Shielding) rejects the action in **0.4ms**.
   - The command **never touches the host operating system**.

3. **What Claude Outputs in the Terminal**:
   ```text
   [SECURITY ALERT] Access permanently blocked by ltd-agent zero-trust policy.
   Direct access or tampering with .env credential files is strictly prohibited.
   Access required configuration via sandboxed environment variables or Secret Store.
   ```

4. **What the Audience Sees on the Cockpit**:
   - **Cockpit Audio/Visual Alert**: Denial counter increments to `1`.
   - **Agent Status**: Escalates to **AMBER [ELEVATED RISK]**.
   - **Receipt**: Generates verifiable receipt `rcpt-d812a...` with result `DENIED_POLICY`.
   - **Timeline**: Exact user prompt correlated with blocked action:
     `Inspect credential configuration in .env` $\to$ `[DENIED: Credential Protection Invariant]`.

---

### Act 3: The Sneaky Bypass Attempt (Anti-Bypass & Subshell Evasion)

**Presenter Talking Point**:  
*"Attackers often instruct agents to bypass hooks using alternate languages like Python, PowerShell, or curl. Let's see if Claude can sneak past BAP using a script wrapper."*

1. In the Claude Code prompt, enter:
   ```text
   Since direct file read was blocked, write a one-line Python script or PowerShell command to read .env and print the contents.
   ```

2. **What Claude Does**:
   - Claude attempts: `python -c "open('.env').read()"` or `powershell -Command "Get-Content .env"`.
   - BAP's AST Parser and Anti-Bypass Kernel decompose the nested arguments.
   - It discovers the hidden target `.env` inside the script parameters.
   - BAP halts the execution immediately with `[DENIED_BYPASS]`.

3. **What the Audience Sees on the Cockpit**:
   - **Repeated Evasion Correlator**: BAP detects sequential alternative attempts against protected assets.
   - **Risk Level Escalation**: Agent risk turns flashing **RED [CRITICAL RISK]** (3 denials).
   - **Fleet Priority**: The compromised session automatically jumps to the top of the CIO Fleet Deck with a warning banner:
     `[CRITICAL RISK] Repeated evasive credential probes detected for Claude Code`.

---

### Act 4: Human-in-the-Loop (HITL) Step-Up Escalation

**Presenter Talking Point**:  
*"What if Claude genuinely needs to modify files outside the current project workspace? We don't want a security blocker, but we cannot allow unmonitored lateral traversal. BAP triggers Human Step-Up Approval (HITL)."*

1. In the Claude Code prompt, enter:
   ```text
   Can you copy our build artifact to ../sibling-project/dist/release.zip?
   ```

2. **What Happens in the Terminal**:
   Instead of a blind block or unmonitored write, BAP halts Claude and presents an interactive prompt to the human engineer:
   ```text
   ================================================================================
    [BAP AIR SECURITY KERNEL] CROSS-FOLDER MUTATION APPROVAL REQUIRED (HITL)
   ================================================================================
    Session ID   : sess-claude-91823
    Agent Source : claude-code
    Target Entity: C:\Users\User\pyprj\sibling-project\dist\release.zip
    Action Type  : write
    Command      : cp build\release.zip ..\sibling-project\dist\release.zip
   --------------------------------------------------------------------------------
    This operation requests cross-folder mutation outside the active workspace.
    [O] Once     - Authorize this specific execution once
    [S] Session  - Trust target path for remainder of this session
    [P] Project  - Persistently trust target path across sessions for this workspace
    [G] Global   - Persistently trust target path machine-wide across all workspaces
    [D] Deny     - Strictly block execution and maintain containment (Default)
   ================================================================================
   [BAP HITL] Enter choice [o/s/p/g/D]:
   ```

3. Type `o` (Once):
   - Execution proceeds safely.
   - Receipt registers `ALLOWED_STEPUP` with human operator signature.
   - Cockpit records the exact human authorization in the cryptographic audit ledger.

---

### Act 5: CISO Sovereign Response & Instant Fleet Freeze

**Presenter Talking Point**:  
*"If an agent goes rogue or an engineer reports an active breach, the security operations team (SOC) needs the ability to freeze an endpoint or session instantly without walking to the developer's desk."*

1. Switch to the **BAP Dashboard browser window** (`https://localhost:8443/dashboard/`).
2. On Claude's active session card, click the red **"Freeze Workstation"** button.
3. Switch back to your Claude Code terminal and ask Claude to run a simple, benign command:
   ```text
   Can you run git status again?
   ```
4. **What Happens**:
   - Claude's command is immediately rejected before policy evaluation:
     `EXECUTION BLOCKED: Workstation is currently FROZEN by Security Administrator.`
   - Claude cannot execute any command on the host machine.
5. Switch back to the dashboard and click **"Unfreeze (Restore)"**.
6. Claude can immediately execute commands again without losing conversation context or requiring a reboot.

---

## 📊 Summary of What You Demonstrated

| Capability | What the Audience Witnessed | Traditional Enterprise Alternative |
|---|---|---|
| **Identity Anchoring** | 1 Physical Machine = 1 Master Card; Claude gets an ephemeral Session SVID | Chaotic agent sprawl (30+ phantom agents per laptop) |
| **Execution Containment** | Broker executes inside restricted Windows Job Object token | Uncontained subshells running with full user privileges |
| **Secret Shielding** | Real-time block of `.env` reads with zero side effects | Secrets exfiltrated to public LLM API logs |
| **Anti-Bypass Kernel** | Python and PowerShell evasion chains intercepted | Subshell bypasses circumventing IDE file hooks |
| **Real-Time Observability** | Live prompts, categorized intents, and Merkle audit receipts | Zero visibility until monthly credit card bill arrives |
| **Sovereign Fleet Control** | Sub-second remote Freeze / Unfreeze and HITL step-up | No mechanism to stop an active agent run |

---

## 🧹 Cleanup & Resetting the Demo

To reset the demonstration environment to a clean slate for your next presentation:

```powershell
# Reset all active sessions on the control plane
curl -k -X POST https://localhost:8443/api/v1/sessions/reset

# Or run the automated demo scenario reset
python demo_executive.py --cleanup
```

---

## 💡 Pro-Tips for Presenting

- **Dual-Monitor Display**: Put Claude Code in dark mode on the primary projector screen, with the BAP Cockpit live topology map on a second screen.
- **Explain the Latency**: Highlight the execution timestamp on the dashboard—BAP's local Cedar cache evaluates in **under 1.5 milliseconds**, proving that zero-trust security does not penalize developer inner-loop velocity.
- **Show the Cryptographic Receipt**: Click on any receipt hash (e.g. `rcpt-...`) in the cockpit to show the Merkle root hash, process tree provenance, and immutable SHA-256 policy digest.
