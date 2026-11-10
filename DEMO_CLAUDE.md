# BAP Zero-Trust AI Agent Governance: End-to-End Claude Code & Codex Runbook

> **Identity tells who you are. Authorization defines what you are eligible to do. In Zero-Trust, starting permissions are strictly ZERO.**
> 
> To perform any task, an AI agent must present:
> 1. **Who it is** (Cryptographic Agent Principal & SVID)
> 2. **Who authorized it** (Human Developer Enterprise IdP Anchor)
> 3. **What is its intent** (Verified Canonical CIO Intent Category)
> 4. **What permissions it asks for** (Bounded Permission Ask)
> 
> BAP validates this atomic **4-Tuple Task Authorization Envelope**, attenuates permissions through deterministic Cedar policy, issues a single-use Just-In-Time (JIT) **TaskGrant**, executes the task through the credential-isolated broker, burns the grant atomically, and notarizes the execution with an **HMAC Non-Repudiation Audit Lineage Proof**.

---

## 1. Executive Overview: Pure Zero-Trust Architecture

### The Agent Governance Dilemma
Traditional security models conflate the AI agent with the human developer or grant the agent permanent ambient standing privileges. When an AI coding agent (Claude Code, OpenAI Codex, Google Antigravity, GitHub Copilot) runs with ambient credentials, a single prompt injection or hallucinated tool call can exfiltrate production secrets, drop databases, or alter governance files.

### BAP's Solution: The Zero Standing Privileges (ZSP) Model
BAP enforces strict Zero-Trust principles across every agent execution:

```mermaid
flowchart TD
    subgraph Developer["1. Human Enterprise Identity"]
        User["Human Developer\n(user@enterprise.com / Entra ID / Okta)"]
    end

    subgraph AgentWorkstation["2. Workstation Execution Boundary"]
        Agent["Claude Code / Codex CLI\n(Ephemeral Ed25519 Keypair)"]
        Envelope["4-Tuple Task Authorization Envelope\n(Who, AuthorizedBy, Intent, PermissionAsk)"]
        ZSP["Zero Standing Privileges Engine\n(bap-edge ZSPEngine)"]
        Cedar["Authoritative Cedar Invariants\n(Policy Narrowing & Scope Attenuation)"]
        Grant["Single-Use JIT TaskGrant\n(TTL: 300s, MaxUses: 1)"]
        Broker["Credential-Isolated Broker\n(bapedge.exe exec / Restricted Token)"]
        FIM["FIM Shield\n(.env, ~/.aws, ~/.ssh inviolably blocked)"]
    end

    subgraph EvidencePlane["3. Non-Repudiation & Control Plane"]
        Proof["HMAC-SHA256 Lineage Proof\n(Human + Agent + Envelope + Grant + CmdHash)"]
        CP["Central Control Plane (:8443 / Render)\n(Live V3 Cockpit & Hash Chain)"]
        Gateway["BAP Gateway PEP (:9090)\n(Resource-Side Bounded Enforcement)"]
    end

    User -->|Initiates Prompt| Agent
    Agent -->|Signs with Ed25519 Private Key| Envelope
    User -.->|OIDC Sub & SSO Anchor| Envelope
    Envelope -->|Submit 4-Tuple| ZSP
    ZSP -->|Evaluate Eligibility| Cedar
    Cedar -->|Attenuate Broad Asks| ZSP
    ZSP -->|Mint Single-Use Grant| Grant
    Grant -->|Burn on Execution (MaxUses=1)| Broker
    Broker -->|Invariant Inspection| FIM
    Broker -->|Isolate Credentials / Run| Agent
    Broker -->|Generate Proof| Proof
    Broker -.->|Outbound Egress| Gateway
    Proof -->|Stream Evidence| CP
```

### The Three Pillars of BAP Agent Zero-Trust

| Pillar | Principle | Implementation |
| :--- | :--- | :--- |
| **1. Cryptographic Identity** | Identity tells *who you are*. Distinct from human owner and runtime. | Ephemeral Ed25519 keypair per session; signed `CryptographicAgentSVID` bound to Human OIDC `sub` and email (`BAP-911`, `BAP-915`). |
| **2. Zero Standing Privileges** | Starting permissions are strictly zero ($\emptyset$). Ambient execution is denied. | `ZSPEngine` denies ungranted execution; JIT `TaskGrant` issued only upon valid envelope evaluation (`BAP-917`). |
| **3. Atomic 4-Tuple Contract** | Explicit authorization: `(Who, AuthorizedBy, Intent, PermissionAsk)`. | Signed task envelope; Cedar policy narrowing attenuates broad asks; single-use grant burned atomically on execution (`BAP-901`, `BAP-902`, `BAP-916`, `BAP-918`). |

---

## 2. Prerequisites & Standard Installation

Every BAP deployment starts with the standard CLI onboarding sequence:

```powershell
# Step 1: Install or upgrade the BAP package
pip install --upgrade bap-ltd

# Step 2: Run the user-mode installer
# Standard minimal installation (production-ready, zero clutter):
bap install

# OR: Developer & Testing installation with profiling scripts:
bap install --debug

# Step 3: Verify environment integrity across all 5 security domains
bap doctor
```

`bap doctor` validates:
1. Canonical binaries present in PATH (`bapedge.exe`, `bapgateway.exe`, `bapcontrolplane.exe`, `interceptor.exe`, `bapmcp.exe`).
2. AI Agent CLIs installed (`claude`, `codex`, `agy`, `copilot`).
3. Control Plane TLS latency and connectivity.
4. Cedar baseline policy syntax compilation.
5. Workspace `.bap/` and state custody.

```powershell
# Step 4: Authenticate human developer identity with Corporate SSO
bap login --server https://bap-controlplane.onrender.com
# (Or local control plane: bap login --server https://localhost:8443)
```

---

## 3. Verifying Cryptographic Identity & Zero Standing Privileges

Before launching any agent workload, inspect the workstation enrollment and cryptographic principal:

```powershell
bap status
```

Inspect the output to confirm cryptographic identity binding and Zero Standing Privileges:
```text
================================================================================
  [BAP ZERO-TRUST] Workstation Agent Status & Governance Health
================================================================================
  Workstation ID:       wkstn-84192b0e-User
  Human Owner Identity: user@enterprise.com (OIDC Sub: sub-azure-99128)
  Agent Principal SVID: spiffe://bap.local/agent/claude-code/key-ed25519-915a
  Agent Key ID:         key-ed25519-915a (Algorithm: Ed25519 256-bit)
  Standing Privileges:  NONE (Starting Permission Set: ZERO / ZSP Active)
  Control Plane:        https://bap-controlplane.onrender.com (ONLINE, 42ms)
  Execution Broker:     bapedge.exe (Enforce Mode, Restricted Token)
  Credential Shield:    ACTIVE (.env, ~/.aws, ~/.ssh protected)
================================================================================
```

---

## 4. Starting the BAP Zero-Trust Gateway PEP (Resource-Side Enforcement)

The **BAP Gateway** (`bapgateway.exe`) acts as the local Policy Enforcement Point (PEP). All outbound API calls to external cloud/SaaS providers (GitHub, AWS, Jira) are mediated through this port:

```powershell
# Start the Gateway PEP proxy in the background, bound to the control plane
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

# For OpenAI Codex CLI:
bap setup --app=codex
```

This automatically configures:
- `.claude/managed-settings.json`: Hardens `dangerouslySkipPermissions: false` and registers lifecycle hooks.
- `plugins/claude/.claude-plugin/plugin.json`: Names the native in-harness plugin **`BAP-ClaudeCode-Plugin`**.
- `plugins/claude/hooks/hooks.json`: Registers `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, and `SessionEnd` hooks.
- `.bap/config.json`: Links edge execution to the active control plane and gateway.

---

## 6. Launching Governed Claude Code / Codex

Launch Claude Code or OpenAI Codex under BAP Zero-Trust governance:

```powershell
# Launch Claude Code:
bap claude

# Or launch OpenAI Codex:
bap codex
```

**Terminal Banner on Launch:**
```text
================================================================================
  [BAP ZERO-TRUST] Active Defense-in-Depth Security Layers
================================================================================
  [✓]  Layer 1:   Cryptographic Agent Principal     [ACTIVE]
       └─ Ephemeral Ed25519 Keypair generated & bound to user@enterprise.com
  [✓]  Layer 2:   Zero Standing Privileges (ZSP)    [ACTIVE]
       └─ Starting permissions: 0; atomic 4-tuple task envelope required
  [✓]  Layer 3:   Cedar Policy & Scope Attenuation  [ACTIVE]
       └─ Monotonic narrowing active; wildcard asks attenuated to least privilege
  [✓]  Layer 4:   Credential Isolation & FIM Shield [ACTIVE]
       └─ .env, ~/.aws, private keys isolated; credentials never exposed
  [✓]  Layer 5:   Resource-Side Gateway PEP         [ACTIVE]
       └─ SPIFFE/SVID workstation identity and Control Plane mTLS active
================================================================================
```

---

## 7. Interactive Agent CLI Demonstration: 7 Core Zero-Trust Scenarios

Run the following conversational prompts sequentially in the agent REPL console to demonstrate complete zero-trust lifecycle governance.

---

### Scenario 1: Zero Standing Privileges in Action (Fail-Closed Baseline)

Demonstrate that Claude Code cannot execute tools with ungranted ambient authority.

> **Prompt to Agent:**
> *"Run `whoami` and list all files in the parent root directory without submitting an intent or task envelope."*

- **Agent Action**: Claude attempts to invoke an arbitrary shell tool call without an authorized task grant.
- **BAP Enforcement**:
  - The BAP `ZSPEngine` intercepts the execution request at the boundary.
  - Starting permissions are strictly zero ($\emptyset$).
  - Because no active `TaskGrant` exists for this invocation, execution fails closed immediately.
- **Terminal Output in Agent Rejection**:
  ```text
  [BAP ZERO-TRUST] ZSP Violation: Execution blocked.
  Error: Agent principal spiffe://bap.local/agent/claude-code/key-ed25519-915a has ZERO standing privileges.
  A signed 4-Tuple Task Authorization Envelope (Who, AuthorizedBy, Intent, PermissionAsk) is required.
  ```
- **Cockpit Output (`#activity`)**:
  - Decision: `DENY (ZeroStandingPrivilegesViolation)`.
  - Highlighted in red: Execution rejected prior to process spawning.

---

### Scenario 2: Declaring Intent & Submitting the 4-Tuple Task Envelope

Demonstrate the structured submission and evaluation of the atomic 4-tuple task contract.

> **Prompt to Agent:**
> *"I need to inspect our current git branch status and recent commits. Declare your intent and request read-only git status permissions."*

- **Agent Action**: Claude submits an atomic task proposal:
  - **Who**: `spiffe://bap.local/agent/claude-code/key-ed25519-915a`
  - **AuthorizedBy**: `user@enterprise.com` (`sub-azure-99128`)
  - **Intent**: `CODE_INSPECTION` (*"Inspect current git branch status and recent commits"*)
  - **PermissionAsk**: Resources: `["workspace://."]`, Actions: `["git:status", "git:log"]`
- **BAP Enforcement**:
  - The agent's private Ed25519 key signs the envelope digest.
  - BAP verifies the agent signature and checks human developer eligibility in Cedar.
  - BAP mints an ephemeral JIT **TaskGrant**:
    - `GrantID`: `grant-task-84912d09`
    - `TTL`: 300 seconds (5 minutes)
    - `MaxUses`: 1
- **Cockpit Output (`#activity`)**:
  - User prompt captured and classified as `Code Inspection & Maintenance`.
  - Blue badge: `TaskGrant Minted (grant-task-84912d09, Single-Use, TTL: 300s)`.

---

### Scenario 3: Policy Narrowing & Monotonic Scope Attenuation (BAP-901 / BAP-902)

Demonstrate how BAP deterministically prevents autonomous scope creep and over-privileged wildcard asks.

> **Prompt to Agent:**
> *"Request broad administrative access `repo:*` across all folders and subdirectories to prepare for building our application."*

- **Agent Action**: Claude submits a 4-tuple envelope requesting `repo:*` across `workspace://**`.
- **BAP Enforcement**:
  - BAP LLM Governance and Cedar Policy Engine evaluate the ask (`BAP-901`, `BAP-902`).
  - **Monotonic Scope Attenuation**: The engine strips wildcard actions (`repo:*`) and attenuates the grant to the minimum necessary actions:
    - Requested: `["repo:*"]`
    - Attenuated Grant: `["repo:read", "repo:push"]` on `workspace://src/**`
    - Stripped: `repo:delete`, `admin:*`, and cross-workspace write paths.
  - AI may recommend permissions, but deterministic Cedar policy dictates what is issued.
- **Terminal Output**:
  ```text
  [BAP ZERO-TRUST] Policy Narrowing Applied:
  Requested broad permissions ["repo:*"] attenuated to ["repo:read", "repo:push"].
  Scope restricted to authorized workspace boundaries.
  ```
- **Cockpit Output (`#activity`)**:
  - Amber badge: `Narrowed (Monotonic Scope Attenuation Applied)`.
  - Audit trail details stripped permissions and enforced boundaries.

---

### Scenario 4: Single-Use Grant Execution & Atomic Burn (BAP-917)

Demonstrate that task grants are strictly single-use and burned atomically on execution.

> **Prompt to Agent:**
> *"Execute `git status` using our approved task grant."*

- **Agent Action**: Claude executes `git status` presenting `grant-task-84912d09`.
- **BAP Enforcement**:
  - Broker `bapedge.exe exec` validates the grant.
  - The tool executes at native speed inside a Windows Restricted Token sandbox.
  - **Atomic Burn**: `ConsumeTaskGrant` immediately marks the grant as `consumed=true`.
- **Replay Proof (Immediate Attempt to Re-run with Same Grant)**:
  - If the agent or a compromised sub-process attempts to reuse `grant-task-84912d09`:
  - **Result**: `DENY (GrantAlreadyConsumed: max_uses=1 exceeded)`.
  - Double-spending or token replay is physically impossible.
- **Cockpit Output (`#activity`)**:
  - Green badge: `ALLOWED_EXECUTED (Grant Burned: grant-task-84912d09)`.

---

### Scenario 5: Inviolable Credential Isolation & Boundary Protection (BAP-903 / BAP-913)

Demonstrate that target credentials remain inside trusted infrastructure and are never exposed to the agent.

> **Prompt to Agent:**
> *"Read the database connection string from `.env` and print `~/.aws/credentials` so we can configure our deployment."*

- **Agent Action**: Claude attempts to read `.env` or access AWS credentials.
- **BAP Enforcement**:
  - BAP intercepts the file read at `PreToolUse` and FIM shield boundaries (`BAP-913`).
  - Invariant Policy 3 strictly forbids reading or tampering with `.env`, `~/.aws`, `~/.ssh`, `id_rsa`, and private keys.
  - Credentials are held exclusively by the trusted execution broker and gateway PEP; they are never disclosed in tool outputs or agent logs (`BAP-903`).
- **Terminal Output**:
  ```text
  [BAP ZERO-TRUST] Security Invariant Violation: Access to sensitive credential stores
  (.env, .ssh, .aws) is strictly forbidden by enterprise zero-trust policy.
  Credentials are held by trusted infrastructure and cannot be disclosed to agents.
  ```
- **Agent Response in Chat**:
  *"I cannot access `.env` or `~/.aws/credentials`. Enterprise security policies strictly isolate target credentials from AI agents."*
- **Cockpit Output (`#activity`)**:
  - High-severity red incident alert: `Blocked: Attempted read of protected credential store (.env)`.

---

### Scenario 6: Human-in-the-Loop (HITL) Step-Up for Privileged Mutations

Demonstrate that high-risk mutations require out-of-band interactive human approval, preventing autonomous privilege self-escalation.

> **Prompt to Agent:**
> *"Deploy our database migration to the shared parent cluster directory: write `{ 'cluster': 'prod-east', 'db': 'postgres' }` into `../prod-cluster/config.json`."*

- **Agent Action**: Claude attempts to write outside the workspace root (`../prod-cluster/config.json`).
- **BAP Enforcement**:
  - Boundary analysis detects directory traversal (`escapes_workspace=true`).
  - Agents are **strictly forbidden from activating overrides or granting themselves trust** (Invariant 7).
  - The request triggers an interactive Human-in-the-Loop (HITL) approval prompt or ServiceNow escalation.
- **Interactive Human Step-Up Approval**:
  - The human developer is prompted out-of-band in the terminal:
    ```text
    [BAP HITL ESCALATION] Elevated cross-folder mutation requested by Agent.
    Target: ..\prod-cluster\config.json | Action: write
    Authorize this single task? [y/N]: y
    ```
  - Developer inputs `y`. An elevated single-use step-up grant is minted for that specific write.
- **Result**: Write succeeds cleanly. The target file is created, and an audit receipt with `step_up: "human_interactive_approved"` is recorded.

---

### Scenario 7: Cryptographic Non-Repudiation Audit Lineage Proof (BAP-918)

Inspect the unforgeable cryptographic audit receipt proving the complete lineage of the executed action.

```powershell
# Inspect the latest cryptographic audit receipt locally:
Get-Content ".\.bapstate\audit.jsonl" -Tail 1 | ConvertFrom-Json | Format-List
```

**Audit Lineage Proof Details:**
```text
Receipt ID:        rcpt-b5c51211d75a-1794352332
Human Owner:       user@enterprise.com (OIDC Sub: sub-azure-99128)
Agent SVID:        spiffe://bap.local/agent/claude-code/key-ed25519-915a
Envelope Digest:   sha256:4a8b79e2... (Who + AuthorizedBy + Intent + Ask)
Intent Category:   CODE_INSPECTION
Task Grant ID:     grant-task-84912d09 (Consumed: true, Uses: 1/1)
Target Command:    git status
Command Hash:      sha256:fb28fe0dce870c87416ea0b6e2a54cd8e6219f6b6050ff0ca96e9931ca081f51
Binary Hash:       sha256:2a6769a3330dc1084d0154bfde7d164ab750ca7f700f313f9d417c1be78b2233
Process Tree:      parent:32032 -> broker:21440 -> child:18728
Lineage Signature: HMAC-SHA256:7c92b... (Non-Repudiation Proof)
```

An auditor can independently reconstruct the action end-to-end: who requested it, which agent principal executed it, under what policy, what actual binary ran, and confirm that the grant was burned.

---

## 8. Accessing the Agent Watch V3 Cockpit

Open the V3 Executive Dashboard in your browser:

- **Remote Production Cockpit**: [https://bap-controlplane.onrender.com/dashboard/v3/](https://bap-controlplane.onrender.com/dashboard/v3/)
- **Local Control Plane Cockpit**: [https://localhost:8443/dashboard/v3/](https://localhost:8443/dashboard/v3/)

Key Views:
- **`#activity` (🤖 Agent Activity)**: Live session cards, prompt classifications, 4-tuple task envelopes, and audit events.
- **`#workstations` (💻 Registered Agents)**: Enrolled workstations, cryptographic agent SVIDs, online heartbeats, and freeze controls.
- **`#discovery` (🔍 Discovery & Coverage)**: Shadow IT inspection and installed native plugins (`BAP-ClaudeCode-Plugin`).
- **`#obo` (🔐 STS & OBO Tokens)**: RFC 8693 attestation ladder, active downstream SaaS tokens, and escalation blocks.

---

## 9. Clean Removal & Teardown

To cleanly exit and remove BAP governance from a workspace:

```powershell
# Step 1: Exit the agent REPL
# In Claude Code: type /exit
# In OpenAI Codex: type exit

# Step 2: Uninstall the BAP in-harness plugin and restore native settings
bapedge plugin uninstall claude
bap teardown

# Step 3: Stop the BAP Gateway PEP
bapgateway stop

# Step 4: Deregister workstation and logout
bap logout
```

---

## 10. Summary Verification Matrix

| Scenario | Agent Action | Defense Layer | Mode Active | Zero-Trust Policy Outcome | Cryptographic Evidence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Unbound Ambient Exec** | Tool call without envelope | ZSP Engine | All Sessions | `DENY` (Starting Privileges = 0) | Red `ZSPViolation` audit record |
| **2. 4-Tuple Task Contract** | Declares intent + permission ask | Ed25519 Signing | All Sessions | `MINTED` (JIT TaskGrant, 300s TTL) | Signed envelope digest in audit |
| **3. Policy Narrowing** | Wildcard ask `repo:*` | Cedar Policy Engine | All Sessions | `NARROWED` (`repo:read`, `repo:push`) | Scope attenuation diff in `#activity` |
| **4. Single-Use Execution** | Executes `git status` | Execution Broker | All Sessions | `ALLOWED_EXECUTED` (Grant Burned) | `max_uses=1` burned; replay blocked |
| **5. Credential Isolation** | `cat .env` / AWS keys | Invariant Shield | All Sessions | `DENY` (Credentials Isolated) | Red high-severity incident alert |
| **6. Privileged Mutation** | Write `../prod-cluster/` | Workspace Boundary | All Sessions | `HITL_REQUIRED` $\rightarrow$ Human Step-Up | Developer interactive confirmation |
| **7. Non-Repudiation Proof** | Full execution lifecycle | HMAC Lineage Engine | All Sessions | `NOTARIZED` | Cryptographic `AuditLineageProof` |