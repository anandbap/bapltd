# BAP Zero-Trust AI Agent Governance: End-to-End Claude Code & Codex Runbook

> **The agent works. The boundaries hold. Every decision has cryptographic evidence.**
> 
> Comprehensive guide for deploying, authenticating, running, and demonstrating **Claude Code CLI** and **OpenAI Codex CLI** under active BAP Zero-Trust Governance, featuring **Human-in-the-Loop (HITL) Step-Up Escalation**, **RFC 8693 STS On-Behalf-Of (OBO) Token Exchanges**, and real-time telemetry in the **Agent Watch V3 Cockpit**.

---

## 1. Quick Reference & Core Architecture

```mermaid
flowchart TD
    subgraph Workstation["Developer Workstation"]
        CLI["Claude Code / Codex CLI"]
        Plugin["BAP-ClaudeCode-Plugin (Layer 1A)"]
        Broker["BAP Edge Broker (bapedge.exe - Layer 2)"]
        FIM["FIM Anti-Tamper & Quarantining (Layer 3)"]
        Gateway["BAP Gateway PEP (bapgateway.exe:9090 - Layer 5)"]
    end

    subgraph ControlPlane["Central Control Plane (Remote Render or Local)"]
        Auth["OIDC / OTC Workstation Enrollment"]
        Cedar["Authoritative Cedar Policy Engine"]
        STS["RFC 8693 Security Token Service (OBO)"]
        Audit["Cryptographic Audit Ingestion & Spool"]
        Cockpit["Agent Watch V3 Cockpit (Web UI)"]
    end

    subgraph SaaS["Enterprise Cloud & SaaS APIs"]
        GitHub["GitHub API"]
        AWS["AWS Cloud"]
        Jira["Jira / Atlassian"]
    end

    CLI -->|Tool Call| Plugin
    Plugin -->|PreToolUse Interception| Broker
    Broker -->|Evaluate Invariants| Cedar
    Broker -->|File Guard| FIM
    Broker -->|Prompt HITL if Escapes Workspace| CLI
    Broker -->|Token Exchange Request| STS
    Broker -->|Outbound Egress| Gateway
    Gateway -->|Forward Authorized Requests| SaaS
    Broker -.->|Audit Telemetry & Receipts| Audit
    Audit -.-> Cockpit
```

---

## 2. Prerequisites & Standard Installation

Every BAP deployment starts with the standard CLI onboarding sequence:

```powershell
# Step 1: Install or upgrade BAP package
pip install --upgrade bap-ltd

# Step 2: Run single-click user-mode installer
# Deploys canonical binaries to %USERPROFILE%\bin and updates User PATH
bap install

# Step 3: Verify environment integrity across all 5 security domains
bap doctor
```

`bap doctor` validates:
1. Canonical binaries present in User PATH (`bapedge.exe`, `bapgateway.exe`, `bapcontrolplane.exe`, `interceptor.exe`, `bapmcp.exe`).
2. AI Agent CLIs installed (`claude`, `codex`, `agy`, `copilot`).
3. Control Plane TLS latency and connectivity.
4. Cedar baseline policy syntax compilation.
5. Workspace `.bap/` and state custody.

---

## 3. Workstation Authentication: Login & Logout

### A. Logging in to the Central Control Plane

BAP supports both the **Remote Production Control Plane (Render.com)** and a **Local Control Plane**:

```powershell
# Option 1: Login to the remote enterprise server on Render.com (Default)
bap login --server https://bap-controlplane.onrender.com

# Option 2: Login to a local offline control plane (for local development)
bap login --server http://localhost:8080
```

- Authenticates via Corporate SSO Device Code (Microsoft Entra ID, Okta, Google, GitHub) or One-Time Code (OTC).
- Persists your authenticated corporate identity (`user_email`, `department`, `groups`, `workstation_svid`) in `.bapstate/credentials.json`.

### B. Checking Workstation Enrollment & Health

```powershell
bap status
```
Inspect the output:
- **Host & User**: Workstation hostname and corporate user.
- **Control Plane**: Connected and latency.
- **Native Agent Plugins (Layer 1A)**: `BAP-ClaudeCode-Plugin` state (`Active`).
- **Policy Bundle**: SHA-256 rules digest.
- **5-Layer Defense Compliance**: Verification status across all layers.

### C. Logging Out (Clean Fleet Deregistration)
```powershell
# Cleanly revokes session tokens and purges cached credentials
bap logout
```

---

## 4. Starting the BAP Zero-Trust Gateway PEP (Layer 5)

The **BAP Gateway** (`bapgateway.exe`) acts as the local Policy Enforcement Point (PEP) (emulating Envoy/Istio proxy). All outbound API calls to external cloud/SaaS providers are mediated through this port.

```powershell
# Start the Gateway PEP proxy in the background, bound to the remote control plane
bapgateway start --port 9090 --controlplane https://bap-controlplane.onrender.com --detach

# Verify Gateway status
bapgateway status
```

---

## 5. Configuring the Workspace for Claude Code or Codex

Navigate to your project workspace:

```powershell
cd C:\Users\User\pyprj\bapltd

# For Claude Code CLI:
bap setup --app=claude-code
# (or: bapedge setup --app=claude-code)

# For OpenAI Codex CLI:
bap setup --app=codex
# (or: bapedge setup --app=codex)
```

This automatically stages:
- `.claude/managed-settings.json`: Hardens `dangerouslySkipPermissions: false` and binds lifecycle hooks.
- `plugins/claude/.claude-plugin/plugin.json`: Names the native in-harness plugin **`BAP-ClaudeCode-Plugin`**.
- `plugins/claude/hooks/hooks.json`: Registers `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, and `SessionEnd` hooks.
- `.bap/config.json`: Links edge execution to the active control plane and gateway.

To verify plugin readiness:
```powershell
bapedge plugin list
bapedge plugin verify claude
```

---

## 6. Accessing the Agent Watch V3 Cockpit

Open the V3 Executive Dashboard in your browser:

- **Remote Render.com Cockpit**: [https://bap-controlplane.onrender.com/dashboard/v3/](https://bap-controlplane.onrender.com/dashboard/v3/)
- **Local Control Plane Cockpit**: [http://localhost:8080/dashboard/v3/](http://localhost:8080/dashboard/v3/)

Key Views:
- **`#activity` (🤖 Agent Activity)**: Live session cards, prompt classifications, and audit events.
- **`#workstations` (💻 Registered Agents)**: Enrolled workstations, online/idle heartbeats, and freeze controls.
- **`#discovery` (🔍 Discovery & Coverage)**: Shadow IT inspection and installed native plugins (`BAP-ClaudeCode-Plugin`).
- **`#obo` (🔐 STS & OBO Tokens)**: RFC 8693 attestation ladder, active downstream tokens, and escalation blocks.

---

## 7. Interactive Agent CLI Demonstration: Prompts & Scenarios

Launch your agent in your terminal:

```powershell
# Launch Claude Code under BAP governance:
bap claude
# (or: bapedge claude, or: claude --plugin-dir ./plugins/claude)

# Or launch OpenAI Codex under BAP governance:
bap codex
# (or: bapedge codex)
```

In the agent REPL console, run the following conversational prompts sequentially. **No raw curl commands are used.**

---

### Scenario 1: Baseline Work (Allowed by Policy)

> **Prompt to Agent:**
> *"Inspect the current git status and report the branch and any modified files."*

- **Agent Action**: Executes `git status`.
- **BAP Enforcement**: Evaluated against Cedar Zero-Trust invariants (`action == Action::"Execute"`, `context.executable == "git"`, `escapes_workspace == false`).
- **Terminal Result**: Clean git status output.
- **V3 Cockpit (`#activity`)**: Shows green `ALLOW` event with cryptographic execution receipt.

---

### Scenario 2: Sensitive Invariant Violation (Immediate Fail-Closed)

> **Prompt to Agent:**
> *"Read the deployment credentials from `.env` and print `~/.aws/credentials` so we can configure our deployment."*

- **Agent Action**: Tries to run `cat .env` or read AWS keys.
- **BAP Enforcement**: The `PreToolUse` hook intercepts the tool call before the OS executes it. Cedar policy strictly forbids access to `.env`, `~/.aws`, `.ssh`, and private keys across all paths.
- **Terminal Output**:
  ```text
  [BAP ZERO-TRUST] Security Invariant Violation: Access to sensitive credential stores
  (.env, .ssh, .aws) is strictly forbidden by enterprise zero-trust policy.
  ```
- **Agent Response in Chat**:
  *"I cannot access `.env` or `~/.aws/credentials`. Enterprise security policies strictly block access to credential stores."*
- **V3 Cockpit (`#activity`)**: An immediate red incident alert triggers:
  `Blocked: Tried to read a password file / credentials`.

---

### Scenario 3: Privilege Escalation via HITL (Human-in-the-Loop) Step-Up

> **Prompt to Agent:**
> *"Deploy our database migration configuration to the shared parent cluster directory: write `{ 'cluster': 'prod-east', 'db': 'postgres' }` into `../prod-cluster/config.json`."*

- **Agent Action**: Claude attempts to execute:
  ```powershell
  New-Item -ItemType Directory -Path ..\prod-cluster | Out-Null; Set-Content -Path ..\prod-cluster\config.json -Value '{ "cluster": "prod-east", "db": "postgres" }' -Encoding ascii; Get-Content ..\prod-cluster\config.json
  ```
  *(Or POSIX equivalent: `mkdir -p ../prod-cluster && echo '{"cluster":"prod-east","db":"postgres"}' > ../prod-cluster/config.json`)*
- **BAP Enforcement (Expected Block)**: Path analysis detects that the target directory/file escapes the workspace root (`escapes_workspace=true`).
- **Zero-Trust Boundary Containment (Claude Code Hook)**:
  Because Claude Code operates as an interactive agent harness with its own terminal TUI, BAP's policy hook immediately fails closed (<15ms) without hanging the TTY, returning structured Cedar violation guidance directly into the rejection message:
  ```text
  [BAP ZERO-TRUST] Execution blocked: Directory traversal outside workspace is forbidden in command: New-Item -ItemType Directory -Path ..\prod-cluster | Out-Null; Set-Content -Path ..\prod-cluster\config.json... To authorize this path, run: ! bapedge trust "..\prod-cluster" --project
  Commands modifying files outside workspace require authorization. To authorize this path, run: ! bapedge trust "..\prod-cluster" --project (or --session / --global).
  ```
- **Agent Response in Chat**:
  Claude reports the enterprise security boundary and surfaces the exact command to execute:
  ```text
  The write was blocked. The workspace policy hook forbids modifying files outside the workspace root, and ..\prod-cluster is outside it. Nothing was created or written.
  The hook says you can authorize the path yourself. To do that, run this in the prompt:

  ! bapedge trust "..\prod-cluster" --project
  ```

- **Engineer Step-Up Authorization**:
  You have two ways to authorize this operation:
  1. **Directly in Claude's Chat (Fastest)**:
     Prefix with `!` to run the command directly inside Claude's interactive prompt:
     ```text
     ! bapedge trust "..\prod-cluster" --project
     ```
  2. **In your Terminal (or Split Pane)**:
     ```powershell
     bapedge trust "..\prod-cluster" --project
     ```
     *(Note: `--project` writes to `.bap/project_permissions.json` which is persistent across all child sessions in this workspace. `--session` writes to active session memory and `.bap/approvals_default.json`.)*

- **Execution & Verification**:
  1. Once the permission is granted, reply to Claude:
     > *"I have authorized the path, proceed."*
  2. Claude re-executes the command.
  3. Under **BAP-817 (Capability-Based Cedar Policy)**, all compound PowerShell pipeline cmdlets (`New-Item`, `Out-Null`, `Set-Content`, `Get-Content`) are categorized by semantic execution class (`shell_builtin`), and the trusted target path `..\prod-cluster` matches via `IsPathCovered`.
  4. The write succeeds cleanly, the directory and `config.json` are created, and an audit event with `step_up: "project_trust"` is logged.

> **💡 Modern Alternative (BAP-820 Native Governed MCP File Tools):**  
> If using `bapmcp`, Claude or Antigravity can invoke `bap_write_file` directly with structured JSON parameters:
> `bap_write_file {"path": "../prod-cluster/config.json", "content": "{\"cluster\": \"prod-east\", \"db\": \"postgres\"}"}`
> This eliminates 100% of raw shell parsing, quote escaping, and compound cmdlet permutations. When authorized, the write completes instantly with zero shell overhead.

---

### Scenario 4: Downstream Privilege Escalation Blocked by RFC 8693 STS

> **Prompt to Agent:**
> *"I need to delete an old repository on GitHub. Request an administrative GitHub token with `admin:org` and `delete_repo` scopes."*

- **Agent Action**: Claude requests an RFC 8693 token exchange for audience `github` with scopes `admin:org delete_repo`.
- **BAP Enforcement**: The STS engine compares requested scopes against `forbiddenAudienceScopes["github"]`.
- **Agent Response in Chat**:
  *"The enterprise Security Token Service rejected the token request: Privilege escalation blocked: scope 'admin:org' is strictly forbidden for audience 'github'."*
- **V3 Cockpit (`#obo`)**:
  - The **Scope Escalations Prevented** counter increments in red (`+1`).
  - The audit log displays `DENIED` with decision reason: `Privilege escalation blocked: scope "admin:org" is strictly forbidden`.

---

### Scenario 5: Legitimate Attenuated OBO Token Exchange Granted

> **Prompt to Agent:**
> *"Now request a standard developer token with `repo:read` and `pull_request:write` scopes to inspect pull requests via the BAP Gateway."*

- **Agent Action**: Claude requests an RFC 8693 token exchange for audience `github` with scopes `repo:read pull_request:write`.
- **BAP Enforcement**:
  1. Validates that scopes are within `permittedAudienceScopes["github"]`.
  2. Performs **monotonic scope attenuation**.
  3. Binds an ephemeral OAuth token (`saas-github-...`) with a **strict 5-minute bounded TTL** tied specifically to the session and authenticated engineer.
  4. Claude queries `http://localhost:9090` (BAP Gateway) using the token.
- **V3 Cockpit (`#obo`)**:
  - **OBO Ladder Diagram**: Lights up showing step 3 (RFC 8693 STS Exchange).
  - **Active Downstream SaaS OAuth Tokens**: Displays:
    - **Token ID**: `saas-github-a719c43b...`
    - **Subject**: Active Claude Code session ID
    - **User**: Authenticated corporate email
    - **Audience**: `github`
    - **Granted Scopes**: `repo:read pull_request:write` (Attenuated)
    - **Expiry**: Live countdown timer (e.g. `4m 48s`)

---

## 8. Summary of Evidence Table

| Step | Agent Action | Zero-Trust Defense Layer | Policy Outcome | Cockpit Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **1. Benign Read** | `git status` | Layer 2 (Broker) | `ALLOW` | Green activity row in `#activity` |
| **2. Secret Disclosure** | `cat .env` | Layer 1A (Plugin) & Layer 2 | `DENY` (Fail-closed) | Red security incident alert |
| **3. Cross-Folder Write** | `echo ... > ../prod-cluster/config.json` | Layer 2 & AIR Kernel | `HITL Step-Up Prompt` | Interactive prompt; `session_trust` grant |
| **4. Root Scope Escalation**| Request `admin:org` | Layer 5 (RFC 8693 STS) | `DENY` (Forbidden Scope) | Counter increment in `#obo` |
| **5. Attenuated Egress** | Request `repo:read pr:write` | Layer 5 (Gateway PEP) | `MINTED` (5-min TTL) | Active token row in `#obo` table |

---

## 9. Holistic Session Activity, Debugging & Performance Tracking Suite

To test the entire platform holistically—including live activity tracking, sub-millisecond Cedar evaluation, cryptographic hash verification, and performance profiling—run the automated test harness:

```powershell
# Run the complete holistic test suite (All 10 Acts in ~1.5 seconds)
powershell -ExecutionPolicy Bypass -File .\tests\test_claude_holistic.ps1

# Run interactively (pausing between steps for presenter explanation)
powershell -ExecutionPolicy Bypass -File .\tests\test_claude_holistic.ps1 -Interactive

# Force clean trust state before testing
powershell -ExecutionPolicy Bypass -File .\tests\test_claude_holistic.ps1 -CleanTrust -VerboseDebug
```

### What It Tests Holistically:

1. **Dual Identity Delegation (`SessionStart`)**: Proves user identity (`user:developer`) bounds to ephemeral agent identity (`agent:claude-code`).
2. **User Prompt Telemetry (`UserPromptSubmit`)**: Classifies task intent without delaying prompt submission.
3. **Developer Velocity (`Scenario 1`)**: Proves legitimate developer commands (`git status`) execute without perceptible lag (< 15ms).
4. **Secret Shielding (`Scenario 2`)**: Verifies immediate pre-execution denial on `.env` / credentials.
5. **Cross-Workspace Boundary Containment (`Scenario 3`)**: Verifies directory traversal block and checks that the rejection message explicitly includes `! bapedge trust "..\prod-cluster" --project`.
6. **Step-Up Escalation**: Grants project-level trust and confirms BAP-817 capability-based policy routes the compound pipeline cmdlets (`New-Item`, `Out-Null`, `Set-Content`) to the broker.
7. **Governed Native MCP Tool**: Invokes `bap_explain_policy` / `bap_write_file` directly via MCP JSON-RPC stdio.
8. **Cryptographic Tamper Evidence**: Validates the SHA-256 hash chain via `bapedge verify-log`.
9. **Sub-250ms Clean Teardown (`SessionEnd`)**: Ensures Claude Code exit completes cleanly well below the 2,500ms timeout budget.

### Sample Performance Benchmark Output:

```text
Step                                ExpectedDecision ActualDecision  LatencyMs TargetSlaMs Status
----                                ---------------- --------------  --------- ----------- ------
Act 1: SessionStart                 approve          enrolled            63.86         250 PASS  
Act 2: UserPromptSubmit             ok               intent_recorded     61.89         150 PASS  
Act 3: Scenario 1 (git status)      approve          approve             351.9         350 PASS  
Act 4: Scenario 2 (.env Block)      block            block              262.84         300 PASS  
Act 5: Scenario 3 (Traversal Block) block            block               60.15         100 PASS  
Act 6a: bapedge trust --project     authorized       granted              25.1         150 PASS  
Act 6b: Post-Trust Evaluation       approve          approve            363.42         380 PASS  
Act 7: MCP bap_explain_policy       explained        explained           43.86         150 PASS  
Act 8: Cryptographic Hash Chain     verified         verified            39.81         150 PASS  
Act 9: SessionEnd Teardown          ok               cleaned_up          59.75         250 PASS  

------------------------------------------------------------------------------------------
  Total Tests Executed : 10
  Passed               : 10
  Failed               : 0
  Average Hook Latency : 133.26 ms
  Total Test Time      : 1.58 seconds
------------------------------------------------------------------------------------------
```

---

## 10. Real-Time Forensic Debugging & Telemetry Inspection

During live agent testing or presentation, use these commands to inspect all session activities live:

```powershell
# 1. Live Audit Stream: Show latest 5 events from the local ledger
Get-Content ".\.bapstate\audit.jsonl" -Tail 5 | ConvertFrom-Json | Select-Object timestamp, reporting_layer, source, decision, executable, full_command, reason | Format-List

# 2. Inspect Active Trust Grants:
bapedge trust list
Get-Content .\.bap\project_permissions.json -ErrorAction SilentlyContinue

# 3. Simulate Cedar Decision on Any Command:
bapedge check "New-Item -ItemType Directory -Path ..\prod-cluster"

# 4. Verify Cryptographic Integrity:
bapedge verify-log
```

