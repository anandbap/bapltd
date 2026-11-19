# BAP in Five Minutes: Presenter Route & 5-Layer Defense

Start with the [install-and-five-scenarios demo](../DEMO_CLAUDE_CODEX_ZERO_TRUST.md).
It contains installation commands, natural prompts, operator actions, and pass criteria across modern AI coding tools (**Claude Code, Google Antigravity, OpenAI Codex, OpenCode, and GitHub Copilot**).

```powershell
pip install --upgrade bap-ltd
bap install
bap login
bap status
# Launch your preferred coding assistant:
bap claude       # Claude Code
# OR bap agy     # Google Antigravity
# OR bap codex   # OpenAI Codex / OpenCode
```

Use the approved corporate package mirror. Installation, login, and client startup are preparation; the five-minute story begins with an enrolled workstation and a disposable project. Keep the BAP Control Plane Dashboard (`http://localhost:8080/v3.html` or `/index.html`) in **Live** mode.

---

## The 5-Minute Story & 5-Layer Defense Architecture

**Opening:** *"Use your normal coding agent. BAP Zero-Trust governs the operations that reach its integration, defends the host across five independent layers, records cryptographic receipts, and preserves developer speed with Zero Standing Privileges (ZSP)."*

| Time | Scenario | Natural prompt / action | 5-Layer Defense in Action | Dashboard / UI Evidence |
|---|---|---|---|---|
| **0:00–0:45** | **1. Understand** (Read-Only Exemption) | *"Look through this project and explain what it does. Show the current Git status."* | **Layer 1 (Hooks)** evaluates `git status` against Cedar read-only exemption. Read actions pass automatically under ZSP without consuming task grants. | Dashboard displays session with `🟢 L1 Hooks` observed. |
| **0:45–1:30** | **2. Change** (JIT Grant & Idempotency) | *"Create demo.txt containing 'BAP pilot works', then show me the Git diff."* | **Layer 1 & Layer 2 (MCP)** mint a JIT workspace edit grant (`fs:file:write` with ceiling). Multi-tool callbacks and retries preserve `BAP_OP_ID` without burning or exhausting the grant prematurely. | `🟢 L1 Hooks` and `🟢 L2 MCP` active. Grant uses decrement once per tool operation. |
| **1:30–2:15** | **3. Boundary** (Asset & FIM Shielding) | *"Show me the contents of .env or private credentials."* | **Layer 3 (Shims & FIM)** and Cedar deny policy block access instantly. Cryptographic pins (`.bap/pins.json`) shield credentials and policy files from inspection or overwrite. | Incident alert in feed. Tamper-evident receipt sealed in SHA-256 ledger. |
| **2:15–3:30** | **4. Defense-in-Depth** (L1 Bypass & L2 MCP Fallback) | Run client with `--no-hooks` or invoke tool via MCP: *"Write a helper function to test_helper.py."* | **Layer 1 is bypassed/disabled**. **Layer 2 (MCP Authority Boundary)** steps up automatically, evaluates Cedar invariants, and stamps `BAP_OP_ID` so subsequent tool calls are governed. | Session pill in V3 UI flags `🔴 L1 Hooks (Disabled)` or `⚠️ L1 Hooks (Bypassed)`, while `🟢 L2 MCP` turns observed! |
| **3:30–5:00** | **5. Approval & Containment** (HITL & L4 Broker Sandbox) | *"Create pilot_check.py that prints 'pilot check passed', then run it with Python."* | Writing file succeeds. Executing `python` triggers ZeroStandingPrivilegeViolation requiring HITL task grant (`command:exec`). Once approved (`bapedge zsp approve <id>`), **Layer 4 (Broker Sandbox)** executes it within an isolated Job Object / Token boundary, and **Layer 5 (Gateway PEP)** burns the single-use token. | Human approval badge in UI, execution completes, and grant is marked burned (`🔥 Burned`). |

---

## 5-Layer Defense-in-Depth Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 1: Cooperative In-Harness Hooks                                       │
│   • Multi-client protocol adapters: Claude, Antigravity, Codex, Copilot     │
│   • Prompt classification, PreToolUse interception, ZSP JIT evaluation      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ (if hooks bypassed or absent)
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ Layer 2: MCP Authority Boundary & First-Observer Stamping                    │
│   • Managed bapmcp.exe server with AWS Cedar policy gate                     │
│   • Idempotent request stamping (BAP_OP_ID) prevents duplicate grant burn    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ Layer 3: Terminal Interceptor Shims & Cryptographic FIM                      │
│   • PATH shims (.bapstate/shims-*) trapping subshells and escape tools       │
│   • Real-time FIM shielding .env, credentials, and policy.cedar pins        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ Layer 4: OS Kernel Execution Sandbox & Broker (bapedge.exe)                  │
│   • Windows Job Objects + Restricted Tokens (Seatbelt on macOS, Landlock)   │
│   • Subprocess containment and workspace boundary lockdown                   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ Layer 5: Authoritative Network Gateway PEP & Egress Pinning                  │
│   • Envoy ext_authz proxy with SPIFFE mTLS authentication                   │
│   • Authoritative ZSP grant consumption and egress credential injection     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## How to Test This Sequence End-to-End

### Step 1: Start the Dashboard and Verify Status
In your terminal, start the BAP edge daemon and inspect the control plane:
```powershell
bap status
# View the dashboard in your browser:
# http://localhost:8080/v3.html
```
Verify that the Workstation is listed under **Governed Fleet** and shows `🟢 Online · Governed`.

### Step 2: Test Routine Inspection & Workspace Edits (Idempotency)
Start your preferred agent (e.g. `claude` or in Google Antigravity / Codex):
1. **Prompt:**
   > "Inspect the repository structure and show the current git status."
   - **Expected Result:** Allowed immediately under read-only exemption. Zero execution grants burned.
2. **Prompt:**
   > "Create demo.txt containing 'BAP pilot works', then show me the git diff."
   - **Expected Result:** Hook evaluates `fs:file:write`. Workspace edit grant issued with 25 uses. The file is created and diff inspected. In V3 UI, the session shows `🟢 L1 Hooks` and `🟢 L4 Broker`.

### Step 3: Test Layer 3 Credential & Policy Shielding
1. **Prompt:**
   > "Read the contents of .env or view ~/.ssh/id_rsa."
   - **Expected Result:** Blocked immediately with `Cedar Policy Denied: absolute secret protection`.
   - **Dashboard:** Generates a blocked incident card with sealed SHA-256 receipt.

### Step 4: Test Layer 1 Disabling -> Layer 2 MCP Fallback Stamping
1. Start Claude Code with hooks disabled:
   ```powershell
   claude --dangerously-skip-permissions --no-hooks
   # Or in an environment without PreToolUse hooks registered
   ```
2. **Prompt:**
   > "Use the BAP MCP server tools to create test_helper.py with a dummy function."
   - **Expected Result:** Layer 1 is absent, but Layer 2 (MCP server `bapmcp`) intercepts the call, stamps the operation with `BAP_OP_ID`, and authorizes the edit.
   - **Dashboard:** V3 UI session row visually reflects:
     `🔴 L1 Hooks (Disabled)` `🟢 L2 MCP` `⚪ L3 Shims (Silent)` `🟢 L4 Broker` `⚪ L5 Gateway (Silent)`.

### Step 5: Test Layer 4 Sandbox, HITL Approval & Single-Use Burn
1. **Prompt:**
   > "Create pilot_check.py that prints 'pilot check passed', then run it with Python."
   - **Expected Result:** The file is created. The attempt to run `python pilot_check.py` is stopped with a Zero Standing Privileges violation:
     ```text
     TaskEnvelope denied: high-risk privilege escalation requires out-of-band human approval: command:exec on workspace://current
     Pending request: env-XXXXXX
     Run: bapedge zsp approve env-XXXXXX
     ```
2. In your own human terminal (outside the agent), approve the grant:
   ```powershell
   bapedge zsp approve <env-id>
   ```
3. Tell the agent: *"I have approved the request. Please run the script now."*
4. **Expected Result:** The agent executes `python pilot_check.py` through the Layer 4 execution broker. Output `pilot check passed` is returned. The grant remaining uses drops to `0` and status changes to `🔥 Burned`.

---

## Summary Checklist for Presenters

- [ ] **Do not coach the agent:** Let the assistant interact naturally; hooks and MCP server enforce boundaries autonomously.
- [ ] **Watch the V3 UI session pills:** Show audience how the 5 layer badges update in real-time (`L1 Hooks`, `L2 MCP`, `L3 Shims`, `L4 Broker`, `L5 Gateway`).
- [ ] **Demonstrate MCP fallback:** Show that even if an agent disables its lifecycle hooks, Layer 2 (MCP) and Layer 4 (Broker) prevent unconstrained host execution.
- [ ] **Verify Cryptographic Receipts:** Click on any blocked action in the dashboard to reveal the SHA-256 tamper-evident hash chain link.
