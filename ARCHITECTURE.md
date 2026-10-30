# Architecture & Technical Design: Bounded Authority Plane (BAP)

This document specifies the technical architecture, security model, component design, cryptographic protocols, and operational state machines of the **Bounded Authority Plane (BAP)**.

---

## 1. Executive Architecture & Invariants Core

The Bounded Authority Plane (BAP) enforces zero-trust execution boundaries, cryptographic attestation, and least-privilege authority over AI developer agents (such as Claude Code, GitHub Copilot CLI, and autonomous worker agents).

### 1.1. The Five Foundational Invariants (Frozen Baseline)

The entire BAP architecture is anchored on five inviolable architectural invariants:

> **I1 — Intent is context, never authority.**  
> An agent declaring intent to "update customer 123" does not grant executable privilege to write, cancel, or modify resources. Intent provides context for policy evaluation and audit evidence, never executable permission.

> **I2 — `bap-edge` determines what authority an agent may obtain; it is not assumed to execute every resulting operation.**  
> `bap-edge` evaluates local policy and brokers requests, but cannot be assumed to observe or execute every downstream HTTP/RPC call. Local intent or policy approval alone is never proof that an actual operation was authorized.

> **I3 — Actual protected operations are independently enforced at a resource-side PEP against bounded authority.**  
> Business APIs and microservices are protected by gateway Policy Enforcement Points (PEP) that derive actual actions from trusted request characteristics (HTTP method, route, parameters), validating bounded cryptographically signed grants.

> **I4 — Control Plane owns master policy, lifecycle, and centralized state; ordinary authorization must not unnecessarily depend on a synchronous Control Plane round-trip.**  
> The Control Plane distributes signed, immutable policy bundles. High-throughput edge decisions evaluate locally cached policies in sub-2ms; only operations requiring mutable state (e.g. single-use atomic consumption) hit central state.

> **I5 — Observability establishes causality and evidence across Runtime → Authority → PEP → Execution, but telemetry itself is never treated as authorization.**  
> The Observability Plane reconstructs the end-to-end timeline for forensic integrity, but telemetry reporting or health signals never substitute for cryptographic authorization tokens.

---

## 2. System Topology: The Four Operating Planes

BAP is architected into four decoupled, resilient operational planes:

```mermaid
graph TD
    subgraph Central_Control ["1. Control Plane (bapcontrolplane)"]
        CP["bapcontrolplane Core"]
        REG["Agent Registry & SPIFFE SVID Engine"]
        ATTEST["Binary Hash Attestation Store"]
        MINTER["Cryptographic Grant Minter (HMAC-SHA256)"]
        BUNDLE["Authoritative Cedar Policy Store & Sync"]
        BURNER["Atomic Grant Burner (max_uses=1)"]
        AUDIT_CHAIN["Tamper-Evident Merkle Hash Chain (SHA-256)"]
        SESS["Session Lifecycle & Live Radar"]
        
        CP --> REG
        CP --> ATTEST
        CP --> MINTER
        CP --> BUNDLE
        CP --> BURNER
        CP --> AUDIT_CHAIN
        CP --> SESS
    end

    subgraph Edge_Brokerage ["2. Edge Execution Plane (bapedge / Launchers / Hooks)"]
        subgraph Agents ["AI Agent Runtimes"]
            CLAUDE["Claude Code CLI"]
            COPILOT["GitHub Copilot CLI (Standalone v1.0.97+ / gh)"]
            ANTIGRAV["Google Antigravity (IDE Electron & agy CLI)"]
            WORKER["Autonomous Worker Agent (Python SDK)"]
        end

        subgraph Interceptors ["Managed Interception & Lifecycle Layer"]
            CCHOOK["Claude Code Hook (cchook/interceptor.exe)"]
            COPSHIM["Copilot Streamer & Interceptor (run_copilot_cli_bap)"]
            AGYHOOK["Antigravity Lifecycle & Transcript Streamer (run_antigravity_ide/cli)"]
            SUBAGENT_ROUTER["Subagent & Inspection Tool Classifier (cchook)"]
        end

        subgraph Edge_Daemon ["bapedge - Local Execution Broker (LTD)"]
            EDGE_PEP["Local Policy Enforcement Point (PEP)"]
            CEDAR_LOCAL["In-Process Cedar Engine (<2ms)"]
            STORE_LOCAL["PolicyStore Cache (~/.ltd/policy/)"]
            AUDIT_LOCAL["Append-Only Local Logger (ltd-audit.jsonl)"]
            CLASSIFIER["Deterministic Intent Classifier (11 Rules)"]
        end

        CLAUDE -->|PreToolUse / UserPromptSubmit| CCHOOK
        COPILOT -->|events.jsonl Tailing & CLI Intercept| COPSHIM
        ANTIGRAV -->|transcript.jsonl Tailing & Process Guard| AGYHOOK
        WORKER -->|bap_sdk API| EDGE_PEP

        CCHOOK --> SUBAGENT_ROUTER
        SUBAGENT_ROUTER --> EDGE_PEP
        COPSHIM --> EDGE_PEP
        AGYHOOK --> EDGE_PEP
        EDGE_PEP --> CEDAR_LOCAL
        CEDAR_LOCAL --> STORE_LOCAL
        EDGE_PEP --> AUDIT_LOCAL
        CCHOOK --> CLASSIFIER
    end

    subgraph Resource_PEP ["3. Resource Enforcement Plane (bapgateway)"]
        GW_PEP["bapgateway (Zero-Trust Gateway PEP)"]
        EXT_AUTHZ["Envoy / Istio ext_authz Proxy Semantics"]
        DERIVE["Authoritative Operation Derivation (deriveOperation)"]
        BACKEND_API["Protected Microservices (Financial Records, Banking, DB)"]

        GW_PEP --> DERIVE
        GW_PEP --> EXT_AUTHZ
        EXT_AUTHZ -->|Verified 200 OK| BACKEND_API
    end

    subgraph Observability_Plane ["4. Observability & Forensic Plane"]
        COCKPIT["CIO Fleet Command Cockpit (Live Radar)"]
        TIMELINE["Causal Evidence Reconstruction Engine"]
        COLLECTOR["Audit Log Aggregator"]
        
        COCKPIT --> TIMELINE
        TIMELINE --> COLLECTOR
    end

    %% Cross-Plane Comms
    EDGE_PEP <-->|Sub-2ms Local Policy Sync| BUNDLE
    EDGE_PEP -->|Ingest Prompt & Tool Events| AUDIT_CHAIN
    EDGE_PEP <-->|Acquire Bounded Grant Token| MINTER
    
    Agents -->|HTTP Requests with Grant Bearer Token| GW_PEP
    GW_PEP <-->|POST /api/v1/grants/consume (Atomic Burn)| BURNER
    GW_PEP -->|Audit Decision Telemetry| AUDIT_CHAIN
    AUDIT_CHAIN --> COLLECTOR
```

---

## 3. Component Deep Dive

### 3.1. Plane 1: Control Plane (`bapcontrolplane`)

`bapcontrolplane` is the authoritative root of trust for policy, identity, and lifecycle state:

1. **Central Policy Master (BAP-401):**
   - Authoritative source for all Cedar policies. Policies receive immutable version IDs (e.g. `v1-digest`, `v2-digest`).
   - Distributes cryptographically signed bundles. Edge runtimes verify signatures and reject unauthenticated or tampered policy files.
   - Supports zero-downtime policy distribution and instantaneous rollback without restarting agent processes.
2. **Workload Identity & SPIFFE SVID (BAP-403, BAP-404):**
   - Issues cryptographically verified SPIFFE IDs formatted as:
     $$\text{spiffe://}\{\text{trust\_domain}\}/\text{app}/\{\text{app\_id}\}/\text{instance}/\{\text{instance\_id}\}$$
   - Rotates credentials every 5 minutes over mutual TLS (mTLS). SVID rotation does not terminate active healthy sessions.
3. **Cryptographic Bounded Grant Minter (BAP-407, BAP-408):**
   - Issues short-lived, cryptographically bounded tokens encapsulating:
     - `jti`: Unique UUID grant identifier.
     - `sub`: Agent SPIFFE workload identity.
     - `session_id`: Unique developer session identifier.
     - `human_id`: Authenticated user email/ID on whose behalf the agent acts.
     - `action`: Specific allowed operation (e.g. `customer.address.update`).
     - `resource`: Specific canonical resource URI (e.g. `customer/123`).
     - `constraints`: `max_uses: 1`, `max_amount`, cumulative limits.
     - `exp`: Strict ephemeral TTL (default: 30–60 seconds for single actions).
     - `policy_version`: Policy bundle hash active when granted.
4. **Atomic Mutable State Burning (BAP-417, BAP-419):**
   - Houses the centralized mutex-locked consumption store (`consumeActiveGrantWithDetails`).
   - Guarantees that ten simultaneous parallel requests against a `max_uses=1` grant result in **at most one** successful consumption; nine requests are rejected.
5. **Tamper-Evident Merkle Hash Chain (BAP-221, BAP-433):**
   - Every ingested event is hashed with the prior block's hash:
     $$H_n = \text{SHA256}(H_{n-1} \parallel \text{EventJSON})$$
   - Any manual edit to historical database rows breaks the chain, causing `/api/v1/control/chain/verify` to report `valid: false`.

---

### 3.2. Plane 2: Edge Execution Broker (`bapedge` & Hooks)

`bapedge` enforces local execution boundaries directly on developer workstations or CI containers:

1. **Sole Executor Pattern (BAP-200, BAP-421):**
   - Agents are deprived of unmediated shell execution. Command execution occurs exclusively via broker-owned wrappers:
     ```bash
     bapedge exec --source claude-code --session-id <sess_id> --cmd-b64 <base64_payload>
     ```
   - Agent-authored lookalikes or direct process-spawning bypasses are strictly rejected.
2. **In-Process Cedar Policy Engine (BAP-101, BAP-402):**
   - Evaluates AWS Cedar policies in-process in **$<1.5\text{ms}$**, completely eliminating remote RPC latency during coding tasks.
   - Evaluates principal, action, resource, and context locally using cached policy bundles.
3. **Offline Fail-Secure Architecture (BAP-102, BAP-434):**
   - If the Control Plane is offline or partitioned, `bapedge` continues enforcing verified cached policies in `~/.ltd/policy/`.
   - If no valid policy cache exists, it fails secure (`exit code 1`). It **never fails open**.
4. **Deterministic Intent Classifier (BAP-218, BAP-405, BAP-406):**
   - Evaluates user prompts against 11 canonical CIO categories:
     `BUG_FIX`, `DATABASE_CHANGE`, `FEATURE_ENHANCEMENT`, `INVESTIGATION`, `REFACTOR`, `TEST_VERIFICATION`, `DOCUMENTATION`, `MIGRATION`, `DEPLOYMENT_RELEASE`, `WORK_MANAGEMENT`, `SECURITY_REMEDIATION`.
   - Ambiguous or unclassified prompts fail safely to `UNKNOWN` ($0.0$ confidence), which explicitly forces human approval or restricted execution rather than silent privilege escalation.
5. **Anti-Tampering Asset Guard (BAP-200A, BAP-425):**
   - Blocks any agent attempt to read credentials (`.env`, `.aws`, `.ssh`), tamper with BAP assets (`policy.cedar`, `bap-config.json`, `interceptor.exe`), or perform directory traversal outside the authorized workspace.
6. **Subagent & Inspection Tool Classification (`cchook/interceptor.go`):**
   - Distinguishes shell execution tools (`Bash`, `Terminal`, `Shell`) requiring command validation from read-only search/inspection tools and subagents (`search_code_subagent`, `Glob`, `Grep`, `Agent`, `Task`, `LS`, `bap_*`).
   - Prevents false-positive denials on empty command fields for non-shell inspection payloads, while strictly maintaining filesystem jail and credential boundary checks across all tool types.
7. **Direct Broker Command Unwrapping (`unwrapBrokerCommand`):**
   - Governing rules (`AGENTS.md`, `GEMINI.md`) instruct advanced agents to directly call `bapedge.exe exec "<cmd>"`.
   - The interceptor dynamically unwraps nested invocations, preserving source attribution (`copilot`, `antigravity`, `claude-code`) and evaluating the inner command against Cedar policy without recursion or double-wrapping.
8. **Multi-Agent Launchers & Lifecycle Supervision (`scripts/bap_launcher_engine.ps1`):**
   - **Google Antigravity IDE & CLI (`run_antigravity_ide_bap.bat`, `run_antigravity_cli_bap.bat`)**:
     - *GUI Electron Lifecycle Guard*: Overcomes asynchronous process-return where Electron GUI launches immediately detach; holds the BAP session `active` in the Control Plane, monitors the entire process tree, and allows clean console termination.
     - *Live Transcript Streaming*: Fast polling (120ms) of `transcript.jsonl` streams user mission prompts to `/api/v1/sessions/prompt` in real-time.
     - *MCP Governance*: Automates mounting of `bapmcp.exe` in `.antigravity/mcp_config.json`.
   - **GitHub Copilot CLI Standalone v1.0.97+ (`run_copilot_cli_bap.bat`)**:
     - *Native Standalone Prioritization*: Prioritizes standalone `copilot.exe` over `gh copilot` extension.
     - *Live Event Streaming*: Tails `~/.copilot/session-state/*/events.jsonl`, ingesting prompts (`user.message`), assistant answers (`assistant.message`), and token metrics (`session.usage_record`) to the Control Plane.
     - *Audit Accounting Snapshot*: Extracts final `accountingSnapshot` upon session exit, recording tokens (input, cached, output), AI credits (nanoAIU), and API duration directly into the Merkle audit chain (`/api/v1/audit/ingest`).

---

### 3.3. Plane 3: Resource Enforcement Plane (`bapgateway`)

`bapgateway` acts as the independent Zero-Trust Policy Enforcement Point (PEP) guarding enterprise business APIs:

```mermaid
sequenceDiagram
    autonumber
    actor Claude as Claude Code Agent
    participant GW as bapgateway (Gateway PEP)
    participant CP as bapcontrolplane
    participant API as Business Service (e.g. /customers)

    Claude->>GW: PATCH /customers/123/address [Bearer Grant Token]
    Note over GW: 1. Independent Derivation: deriveOperation(PATCH, /customers/123/address)<br/>Derived: action = customer.address.update, resource = customer/123
    Note over GW: 2. Ignore client spoofed headers (X-Agent-Action: read)
    
    GW->>GW: 3. Verify JWT Cryptographic HMAC Signature & Expiration
    alt Signature Tampered or Expired
        GW-->>Claude: 403 Forbidden ("cryptographic signature mismatch")
    end

    GW->>CP: 4. POST /api/v1/grants/consume {token, action, resource, session_id}
    alt Grant Mismatch (Grant for customer/123 used on customer/999)
        CP-->>GW: 403 Forbidden ("action/resource mismatch")
        GW-->>Claude: 403 Forbidden
    else Already Burned (Replay Attack)
        CP-->>GW: 409 Conflict ("grant has already been consumed")
        GW-->>Claude: 403 Forbidden ("replayed grant")
    else Valid & Active
        CP->>CP: Atomically mark grant burned (max_uses -= 1)
        CP-->>GW: 200 OK {consumed: true, agent_id, grant_id}
        GW->>API: 5. Forward request with verified identity headers
        API-->>GW: 200 OK {status: "address updated"}
        GW-->>Claude: 200 OK
    end
```

#### Key Gateway PEP Invariants:
1. **Independent Operation Derivation (`deriveOperation`):**
   The gateway inspects the HTTP verb and path to derive authoritative actions and resources:
   ```go
   func deriveOperation(method, path string) (action, resource string) {
       cleanPath := strings.TrimRight(path, "/")
       if strings.HasPrefix(cleanPath, "/api/v1/financial-records") {
           if method == http.MethodGet {
               return "financial.records.read", "/api/v1/financial-records"
           }
           return "financial.records.write", "/api/v1/financial-records"
       }
       if strings.HasPrefix(cleanPath, "/api/v1/core-banking") {
           if method == http.MethodPost {
               return "core_banking.transfer", cleanPath
           }
           return "core_banking.read", cleanPath
       }
       return strings.ToLower(method) + ":" + cleanPath, cleanPath
   }
   ```
2. **Rejection of Client Header Spoofing (BAP-411):**
   The PEP completely ignores client-injected headers such as `X-Agent-Action: harmless-query`.
3. **Strict Grant-to-Operation Matching (BAP-412):**
   Grants issued for `customer/123` cannot be used on `customer/999` or `subscription/789`. Any mismatch immediately triggers `403 Forbidden`.
4. **Envoy / Istio `ext_authz` Emulation:**
   `bapgateway` provides standard HTTP check endpoints allowing seamless deployment as an external authorization sidecar for Envoy, Istio, Traefik, or Kong API Gateways.

---

### 3.4. Plane 4: Observability Plane & Causal Reconstruction

The Observability Plane answers the fundamental question: **"Why did the agent invoke this operation, under whose authority, and what was the result?"**

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                       CAUSAL EVIDENCE RECONSTRUCTION                        │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Runtime Intent Capture:                                                  │
│    User Prompt: "Investigate latency in customer 123"                       │
│    Classified Intent: INVESTIGATION (Telemetry Context)                     │
│    Prompt SHA-256 Digest: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b9... │
│                                  │                                          │
│                                  ▼                                          │
│ 2. Ephemeral Authority Grant:                                               │
│    Grant ID: G-847294 (Single-use, max_uses=1, TTL=30s)                    │
│    Action: customer.address.read | Resource: customer/123                   │
│    Policy Version: v3-sha256:7f8a9b...                                      │
│                                  │                                          │
│                                  ▼                                          │
│ 3. Gateway PEP Enforcement:                                                 │
│    Derived Operation: GET /customers/123/address -> customer.address.read   │
│    Token Consumption: Atomically Burned at Control Plane                    │
│    Decision: ALLOW (200 OK) | Latency: 1.2ms                                │
│                                  │                                          │
│                                  ▼                                          │
│ 4. Execution & Audit Ledger:                                                │
│    Merkle Link: H_n = SHA-256(H_{n-1} || EventData)                         │
│    Tamper Verification Status: 100% Cryptographically Valid                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 3.4.1. AI Token, Usage & Financial Accounting Pipeline

In addition to runtime command authorization and security boundaries, enterprise governance requires precise accounting of AI compute costs and resource liability. BAP incorporates continuous usage accounting into the Observability Plane:

1. **Turn-by-Turn Usage Records (`session.usage_record`):**
   - Streamed in real-time from agent event state logs (e.g., `~/.copilot/session-state/*/events.jsonl` or Google Antigravity `transcript.jsonl`).
   - Captures per-turn prompt tokens, completion tokens, cached context tokens, and model identifiers.
2. **Session Shutdown Accounting (`accountingSnapshot`):**
   - Captured upon agent exit and ingested into `/api/v1/audit/ingest`:
     - `model`: Specific model version deployed for the task.
     - `input_tokens`, `output_tokens`, `cached_tokens`: Granular breakdown of token volume.
     - `ai_credits`: Exact consumption in nanoAIUs (nano AI Units).
     - `api_duration_ms`: Total upstream LLM inference latency.
3. **Cryptographic Merkle Immutability:**
   - Financial accounting snapshots are chained into BAP's sequential SHA-256 Merkle ledger alongside the human initiator's identity and Cedar authorization decisions, establishing an irrefutable audit trail for enterprise billing and CFO/CIO chargebacks.

---

## 4. The 10-Point Architectural Adversarial Matrix

The BAP architecture is mathematically and programmatically verified against 10 adversarial attacks via [`tests/test_bounded_authority_matrix.py`](file:///c:/Users/User/pyprj/bapltd/tests/test_bounded_authority_matrix.py):

| # | Attack Scenario | Adversary Action | BAP Defense Implementation | Pass Criteria |
|:---:|---|---|---|:---:|
| **1** | **Intent Spoofing** | Claims benign intent `customer.read` but asks for `admin.drop_db`. | [BAP-405, 409](file:///c:/Users/User/pyprj/bapltd/JIRA_STORIES.md#L720): Intent is context, never authority. Evaluated strictly against Cedar rules. | Unearned authority rejected with `401/403`. |
| **2** | **Grant Tampering** | Modifies JWT payload (expands resource or expiry) or signature. | [BAP-408](file:///c:/Users/User/pyprj/bapltd/JIRA_STORIES.md#L750): Gateway PEP verifies HMAC-SHA256 signature with private key. | Tampered token rejected with `403 Forbidden`. |
| **3** | **Cross-Resource Token Reuse** | Uses grant for `customer/123` to access `/core-banking/account-123`. | [BAP-412](file:///c:/Users/User/pyprj/bapltd/JIRA_STORIES.md#L790): Gateway PEP derives resource from path and checks token resource claim. | Mismatched resource rejected with `403 Forbidden`. |
| **4** | **Scope Creep / Header Spoofing** | Sends `POST /financial-records` with `X-Agent-Action: read`. | [BAP-411](file:///c:/Users/User/pyprj/bapltd/JIRA_STORIES.md#L780): Gateway derives `financial.records.write` from `POST`, ignoring headers. | Read grant rejected against write operation (`403`). |
| **5** | **Atomic Replay Attack** | Captures valid single-use token and replays it after initial execution. | [BAP-417](file:///c:/Users/User/pyprj/bapltd/JIRA_STORIES.md#L840): Token is atomically burned on 1st use via `/api/v1/grants/consume`. | 1st call: `200 OK`. 2nd call: `403 Forbidden`. |
| **6** | **Concurrent Race Conditions** | Sends 10 concurrent requests simultaneously using single-use grant. | [BAP-416, 417](file:///c:/Users/User/pyprj/bapltd/JIRA_STORIES.md#L830): Mutex-locked atomic counter decrement in Control Plane. | **Exactly 1 success (`200 OK`)**, 9 rejections (`403`). |
| **7** | **Edge Broker Bypass** | Attempts to modify `policy.cedar` or delete audit logs on disk. | [BAP-200, 421](file:///c:/Users/User/pyprj/bapltd/JIRA_STORIES.md#L880): Interceptor detects writes to protected assets and denies execution. | `permissionDecision: "deny"`, security alert emitted. |
| **8** | **Direct Gateway PEP Bypass** | Sends HTTP request directly to API without Authorization header. | [BAP-410, 438](file:///c:/Users/User/pyprj/bapltd/JIRA_STORIES.md#L770): Gateway PEP drops unauthenticated requests. | `401 Unauthorized`, internal API never contacted. |
| **9** | **Unknown Intent Safe Failure** | Presents ambiguous prompt ("recite poem") to classifier. | [BAP-406](file:///c:/Users/User/pyprj/bapltd/JIRA_STORIES.md#L735): Classifier falls back to `UNKNOWN` ($0.0$ confidence) and requires approval. | Intent recorded as `UNKNOWN`, no privilege escalation. |
| **10** | **Audit Trail Forgery** | Attacker modifies historical database row or event. | [BAP-221, 433](file:///c:/Users/User/pyprj/bapltd/JIRA_STORIES.md#L990): Cryptographic SHA-256 Merkle hash chain verification. | `/api/v1/control/chain/verify` detects broken link. |

---

## 5. Fail-Secure State Machine & Network Resilience

```mermaid
stateDiagram-v2
    [*] --> Initialize: bapedge starts
    Initialize --> InspectLocalCache: Load ~/.ltd/policy/
    
    state InspectLocalCache {
        [*] --> CheckKillSwitch
        CheckKillSwitch --> KillSwitchActive: policy-state.json has kill_switch=true
        CheckKillSwitch --> CheckCachedBundle: kill_switch=false
        CheckCachedBundle --> CacheValid: policy.cedar & schema.json exist
        CheckCachedBundle --> CacheEmpty: No cached bundle
    }

    KillSwitchActive --> HaltExecution: ErrKillSwitchActive (Exit 1)
    
    CacheEmpty --> AttemptControlPlaneSync
    state AttemptControlPlaneSync {
        [*] --> ContactServer: POST /api/v1/policy/sync
        ContactServer --> SyncSuccess: Server responds 200 OK
        ContactServer --> ServerDown: Server unreachable
    }

    ServerDown --> FailSecureDeny: Exit 1 (Never Fails Open)
    SyncSuccess --> WriteCacheAndOperate: Save to ~/.ltd/policy/
    
    CacheValid --> CheckNetwork
    state CheckNetwork {
        [*] --> ProbeServer: Contact bapcontrolplane
        ProbeServer --> OnlineMode: 200 OK received
        ProbeServer --> OfflineMode: Connection Refused / Timeout
    }

    OfflineMode --> EnforceCachedInvariants: Sub-2ms local Cedar evaluation
    OnlineMode --> ApplyServerDirectives: Update bundle or trigger kill-switch
    
    EnforceCachedInvariants --> AllowPermittedCommands: git, python, npm permitted
    EnforceCachedInvariants --> DenyForbiddenCommands: cat .env, curl, ~/.aws blocked
```

---

## 6. Enterprise Scale & High-Throughput Benchmarks

- **Edge Evaluation Latency:** $<1.5\text{ms}$ per decision via in-process Cedar engine.
- **Gateway PEP Ext-Authz Latency:** $<2.5\text{ms}$ for cryptographic verification and synchronous atomic grant burning.
- **Central Control Plane Ingestion Throughput:** **35,620 events / second** benchmarked over 50,000 events (`tests/perf_test_50k.py`).
- **Concurrent Scale:** Verified up to **3,000 concurrent stateful agent connections** with SQLite WAL and memory profiles.
- **Audit Hash Verification Time:** 50,000 sequential events verified in **32.6 ms**.

---

## 7. Operations & Governance Extension Architecture (BAP-450–BAP-459)

The Operations & Governance Extension provides formal operational controls, administrative governance, separation of duties, and state reconciliation on top of the core Dual-PEP architecture.

### 7.1. Extended Causal Governance Chain & Four Frozen Rules

```mermaid
flowchart LR
    Task["1. Task"] --> Intent["2. Intent Context"]
    Intent --> Proposal["3. Immutable Proposal (P)"]
    Proposal --> Decision["4. Policy Decision (Cedar)"]
    Decision --> Grant["5. Bounded Grant (G)"]
    Grant --> PEP["6. Gateway PEP Enforcement"]
    PEP --> Execution["7. Backend Execution"]
    Execution --> Evidence["8. Merkle Audit Evidence"]
```

Four foundational architecture rules govern all operational interventions:

> **R1 — Proposals are immutable.**  
> An Action Proposal cannot be mutated once submitted. Any operational correction generates a child proposal (`parent_proposal_id`) establishing auditable lineage.

> **R2 — Humans remediate inputs, never override decisions.**  
> An operator cannot click a button to manually force a `DENY` into an `ALLOW`. Remediated input must pass through the full policy evaluation pipeline.

> **R3 — Authorization does not prove execution.**  
> Gateway PEP authorization and downstream API completion are evidenced separately. If a network disruption occurs between PEP check and execution, the action is marked `UNKNOWN` and reconciled; authorization is never assumed to be execution.

> **R4 — Operating the governance system is itself governed.**  
> Administrators are subject to the same bounded authority principles. BAP administrative APIs require strong authentication, scoped RBAC, and immutable audit logging. **BAP governs BAP.**

---

### 7.2. Immutable Action Proposals & Remediation Lineage (BAP-450, BAP-451)

Every consequential operation is encapsulated in a cryptographically identified, immutable proposal before policy evaluation:

```json
{
  "proposal_id": "prop-8f92a1b4-7c3d",
  "parent_proposal_id": "prop-7a81b2c3-6d2e",
  "trace_id": "trace-991283",
  "agent_id": "claude-worker-7",
  "session_id": "sess-42",
  "task_id": "task-customer-address-fix",
  "human_id": "alice@company.com",
  "intent": "BUG_FIX",
  "action": "customer.address.update",
  "resource": "customer/123",
  "parameters": {"street": "456 Market St"},
  "timestamp": "2026-10-04T12:00:00Z"
}
```

```text
Proposal P100 (customer=124)
           ↓
     DENIED by Policy
           ↓
Operator Corrects Input (customer=123)
           ↓
Proposal P101 (customer=123, parent=P100)
           ↓
Full Cedar Policy Evaluation
           ↓
    ALLOWED → Grant Issued
```

---

### 7.3. Administrative Governance & RBAC: "BAP Governs BAP" (BAP-452, BAP-453)

Administrative actions (policy edits, session revocations, emergency freeze, agent termination) cannot bypass governance:

1. **Governed Operations:** Policy changes, grant revocations, agent terminations, session kills, approvals, configuration updates, and identity changes.
2. **Separation of Duties Matrix:**
   | Role | View Trace | Investigate | Remediate Proposal | Approve High-Risk | Change Policy |
   |---|:---:|:---:|:---:|:---:|:---:|
   | **Observer** | ✓ | ✓ | — | — | — |
   | **Operator** | ✓ | ✓ | ✓ | — | — |
   | **Approver** | ✓ | ✓ | — | ✓ | — |
   | **Policy Admin** | ✓ | ✓ | — | — | ✓ |
3. **Anti-Self-Approval:** The operator who submitted or remediated a proposal cannot be the approver for that same action.

---

### 7.4. Out-of-Band Management UI (BAP-454)

The BAP Operations UI sits strictly outside the execution path. An outage or restart of the dashboard cannot degrade runtime agent operations:

```text
Operations Cockpit UI
         X (DOWN / CRASHED / MAINTENANCE)

Control Plane Core
        │
Runtime ──► Bounded Grant ──► Gateway PEP ──► Business API
                                  ▲
                             STILL 100% OPERATIONAL
```

---

### 7.5. Governed Action Lifecycle State Machine (BAP-455)

Every proposal transitions through a deterministic, strictly validated lifecycle:

```mermaid
stateDiagram-v2
    [*] --> PROPOSED: Agent Submits Proposal
    PROPOSED --> EVALUATING: Control Plane Receives
    
    EVALUATING --> AUTHORIZED: Cedar Evaluation Permits
    EVALUATING --> DENIED: Cedar Evaluation Forbids
    
    AUTHORIZED --> GRANTED: Bounded Grant Token Minted
    GRANTED --> PRESENTED: Agent Presents Token to Gateway PEP
    GRANTED --> EXPIRED: TTL Elapses Before Presentation
    GRANTED --> REVOKED: Admin Revocation Directive
    
    PRESENTED --> PEP_ALLOWED: Gateway PEP Verifies Token & Burns
    PRESENTED --> DENIED: Action/Resource Mismatch or Tampered Token
    
    PEP_ALLOWED --> EXECUTING: Dispatched to Downstream Service
    EXECUTING --> COMMITTED: Backend Transaction Committed
    COMMITTED --> COMPLETED: 200 OK Returned to Agent
    
    EXECUTING --> UNKNOWN: Network Timeout / Disconnection
    UNKNOWN --> RECONCILING: Orphan Reconciliation Process
    RECONCILING --> COMPLETED: Verified Executed on Backend
    RECONCILING --> FAILED: Verified Rolled Back on Backend
```

---

### 7.6. Execution Reconciliation & Orphan Detection (BAP-456)

In distributed architectures, authorization does not guarantee execution. If a network partition occurs after the Gateway PEP admits a request, BAP marks the state `UNKNOWN` rather than guessing success or failure:

* **Orphan Detection Scenarios:**
  1. *Unpresented Grants:* State remains `GRANTED` until TTL expiry, then transitions to `EXPIRED`.
  2. *Unconfirmed Executions:* State is `PEP_ALLOWED` but lacks backend receipt. Flagged for background reconciliation.
* **Non-Idempotent Safety:** The reconciliation engine **never automatically re-executes** consequential operations (e.g. transfers, payments, drops, cancellations). It queries the downstream service's idempotency log or raises an incident for human investigation.

---

### 7.7. Governance Simulation & Investigation Timeline (BAP-457, BAP-458, BAP-459)

1. **Policy Simulation & Dry-Run Engine:**
   Security engineers run regression suites of historical proposals against draft Cedar bundles ($V_{N} \rightarrow V_{N+1}$) before deployment to preview behavioral diffs without touching production systems.
2. **Investigation Timeline:**
   The operations cockpit reconstructs both serial workflows and concurrent parallel tool invocations using explicit correlation IDs (`trace_id`, `proposal_id`, `task_id`), accurately displaying multi-agent branching.

---

## 8. Layered Endpoint Enforcement & Workstation Hardening (Epic 23 & Epic 30)

### 8.1. Unified Defense-in-Depth: The 5-Layer Architecture

To eliminate reliance on user-space agent cooperativeness, BAP models workstation defense across five decoupled layers:

```mermaid
graph TD
    subgraph Layer1 ["Layer 1: Native Lifecycle & Subagent Interception (User Space)"]
        H1["PreToolUse Lifecycle Hooks"]
        H2["Workspace Rules (GEMINI.md, AGENTS.md)"]
        H3["User-Immutable managed-settings.json"]
        H1 --- H2 --- H3
    end

    subgraph Layer2 ["Layer 2: Model Context Protocol (MCP) Authority Boundary"]
        M1["bapmcp.exe Managed Server"]
        M2["Cedar-gated bap_execute Tool Dispatch"]
        M3["Runtime Introspection (bap_status, bap_explain_policy)"]
        M1 --- M2 --- M3
    end

    subgraph Layer3 ["Layer 3: Tool Call & Terminal Interceptor Shims (PATH Defense)"]
        S1[".bapstate/shims-$SessionId/ (Prepend to PATH)"]
        S2["CLI Shims: git, python, curl, wget, powershell, cat, rm"]
        S3["Unmediated Subprocess Trap -> bapedge exec"]
        S1 --- S2 --- S3
    end

    subgraph Layer4 ["Layer 4: In-Process Broker, OS Kernel Boundary Sandbox & Merkle Audit"]
        K1["bapedge exec In-Process Cedar Engine (<1.5ms)"]
        K2["Windows: Job Objects & Restricted Tokens (LUA)"]
        K3["Linux: Landlock LSM & eBPF Probes / macOS: Seatbelt"]
        K4["Merkle SHA-256 Ledger & Local Rollback"]
        K1 --- K2 --- K3 --- K4
    end

    subgraph Layer5 ["Layer 5: Authoritative Network Gateway PEP & Perimeter Backstop"]
        G1["bapgateway Envoy ext_authz Proxy"]
        G2["ZSP Single-Use Cryptographic Grant Burning"]
        G3["Tenant & Egress Pinning Backstop"]
        G1 --- G2 --- G3
    end

    Layer1 -->|If Bypassed via Direct Tool Call| Layer2
    Layer2 -->|If Agent Spawns Raw Subshell| Layer3
    Layer3 -->|All Invocations Reached At| Layer4
    Layer4 -->|All Network Egress Gated By| Layer5
```

* **Layer 1 (Process & Lifecycle Hooks):** Fast user-space interception for optimal developer experience (<1ms evaluation). Enforces `dangerouslySkipPermissions: false`, prompt classification, and workspace invariants.
* **Layer 2 (MCP Authority Boundary):** Governed tool exposure via `bapmcp.exe`, requiring Cedar policy authorization on all structured tool calls before dispatch.
* **Layer 3 (Terminal Interceptor Shims):** Dynamic per-session PATH interception trapping unmediated subshell commands (`git`, `python`, `curl`, `powershell`) and re-routing to `bapedge exec`.
* **Layer 4 (OS Kernel Boundary Sandbox & Local Broker):** Hard OS containment denying unauthorized process spawns, hidden subshells (`npm` lifecycle scripts), access to standing secrets (`.env`, `id_rsa`), backed by Windows Job Objects / Restricted Tokens, Landlock, and Seatbelt.
* **Layer 5 (Authoritative Network Gateway PEP & Perimeter Backstop):** Centralized perimeter enforcement through `bapgateway` (Envoy `ext_authz`), requiring single-use cryptographic Zero-Trust Session Protocol (ZSP) grant burning and tenant egress pinning before any packet leaves the perimeter.

---

### 8.2. Platform Primitive Matrix

| Control Point | macOS (Sequoia / Sonoma) | Linux (Ubuntu 22.04+ / RHEL 9+) | Windows 11 Enterprise |
| :--- | :--- | :--- | :--- |
| **Execution & Filesystem** | Endpoint Security (`AUTH_EXEC`, `AUTH_OPEN`) + Seatbelt | Landlock LSM + eBPF (`sys_enter_execve`, `bprm_check_security`) | Restricted Tokens (LUA) + Windows Job Objects (Kill-on-Close) |
| **Network Egress** | NetworkExtension Content Filter | eBPF cgroup socket filter | Windows Filtering Platform (WFP) |
| **Agent Sandbox** | Seatbelt sandbox profile | Bubblewrap + seccomp-bpf | AppContainer Isolation |
| **MDM Packaging** | Jamf Pro / Kandji (`.mobileconfig`) | Ansible / Puppet / Intune Linux | Microsoft Intune (OMA-URI / Custom CSP) |

---

### 8.3. Enterprise MDM Deployment Profiles

BAP automatically generates ready-to-deploy configuration profiles:
* **Microsoft Intune (Windows):** Enforces `C:\ProgramData\Claude\managed-settings.json` with `dangerouslySkipPermissions: false`, activates Restricted Token launch wrappers, and configures WFP redirection.
* **Jamf Pro (macOS):** Deploys `/Library/Application Support/Claude/managed-settings.json` and pre-approves system extension and Full Disk Access permissions with zero developer popups.

---

### 8.4. Interactive Biometric Step-Up Approvals (BAP-462)

High-risk operations (e.g. database schema migrations, production secrets access, large financial transactions) do not force blanket denials or rely on ambient agent authority:
1. The Control Plane mints a cryptographically nonced **Step-Up Challenge** (`/api/v1/endpoint/stepup/challenge`).
2. The workstation prompts the human engineer for biometric authentication (`WINDOWS_HELLO`, `TOUCH_ID`, or `FIDO2_HARDWARE_KEY`).
3. Upon physical confirmation, BAP verifies the attestation signature (`/api/v1/endpoint/stepup/verify`) and mints an ephemeral, single-use, HMAC-signed `StepUpToken` (5-minute TTL).
4. The token is burned synchronously upon execution, preventing capture and replay attacks.

---

### 8.5. Scoped Offline Degradation (BAP-463)

To ensure zero-trust controls do not cause developer lockouts on flights or during network outages:
* **Tier 1 (Safe Local Development):** Compiling source code, running unit tests (`cargo test`, `pytest`, `go test`), code formatting, and git status evaluate locally against the cached Cedar policy bundle indefinitely offline.
* **Tier 2 (Protected Enterprise Egress):** Operations targeting corporate microservices, remote databases, or cloud APIs require online signed grants and fail closed when the 15-minute grant TTL expires.

---

### 8.6. The 5-Layer Defense-in-Depth Architecture (BAP-540)

BAP enforces a comprehensive, runtime-level **5-Layer Defense-in-Depth Mechanism** that governs tool discovery, invocation, local execution, and network egress across all AI developer agents before any action affects the host operating system or corporate infrastructure:

```mermaid
flowchart TD
    subgraph L1 ["Layer 1: Native Lifecycle & Subagent Interception"]
        L1A["PreToolUse Hook (interceptor.exe)"]
        L1B["Subagent & Inspection Router (isSafeSubagentOrInspectionTool)"]
        L1C["Direct Broker Unwrapper (unwrapBrokerCommand)"]
        L1D["Live Event / Transcript Tailing (events.jsonl / transcript.jsonl)"]
        L1A --- L1B --- L1C --- L1D
    end

    subgraph L2 ["Layer 2: Model Context Protocol (MCP) Authority Boundary"]
        L2A["bapmcp.exe Managed Server"]
        L2B["bap_execute (Cedar-gated tool execution)"]
        L2C["bap_explain_policy & bap_status"]
        L2A --- L2B --- L2C
    end

    subgraph L3 ["Layer 3: Tool Call & Terminal Interceptor Shims (PATH Hijacking Defense)"]
        L3A[".bapstate/shims-$SessionId/ (Prepend to PATH)"]
        L3B["Command Shims: git, python, curl, wget, powershell, cat, rm"]
        L3C["Unmediated Subprocess Trap -> bapedge exec --raw"]
        L3A --- L3B --- L3C
    end

    subgraph L4 ["Layer 4: In-Process Broker, Sandbox Containment & Merkle Audit"]
        L4A["bapedge exec (Sole Executor Pattern)"]
        L4B["In-Process Cedar Engine (<1.5ms)"]
        L4C["Detached Watcher (bapedge watch) & Process Tree Guard"]
        L4D["Merkle SHA-256 Ledger & Local Rollback"]
        L4A --- L4B --- L4C --- L4D
    end

    subgraph L5 ["Layer 5: Authoritative Network Gateway PEP & Perimeter Backstop"]
        L5A["bapgateway Envoy ext_authz Proxy"]
        L5B["Single-Use ZSP Cryptographic Grant Burning"]
        L5C["Zero-Bypass Tenant & Network Egress Pinning"]
        L5A --- L5B --- L5C
    end

    L1 -->|If Tool Bypasses Hooks| L2
    L2 -->|If Agent Spawns Direct Subshell| L3
    L3 -->|Always Routed To| L4
    L4 -->|All Network Egress Gated By| L5
```

#### Detailed Layer Breakdown:

1. **Layer 1: Native Lifecycle & Subagent Interception:**
   - Intercepts agent tool requests at the prompt and pre-execution phase.
   - Claude Code routes through `cchook/interceptor.exe` on `SessionStart`, `UserPromptSubmit`, and `PreToolUse`.
   - Dedicated inspection router `isSafeSubagentOrInspectionTool` identifies non-shell tools (`search_code_subagent`, `Glob`, `Grep`, `Agent`, `Task`, `LS`, `bap_*`) that lack shell commands, allowing legitimate codebase inspection while maintaining directory traversal and `.env` protections.
   - `unwrapBrokerCommand` unwraps nested `bapedge.exe exec "<cmd>"` calls emitted by agents following workspace rules (`AGENTS.md`, `GEMINI.md`) without recursion, preserving multi-agent source attribution.
   - Live event tailers stream mission prompts and agent responses to the central Control Plane in real time.

2. **Layer 2: Model Context Protocol (MCP) Authority Boundary:**
   - Exposes `bapmcp.exe` as a managed MCP server configured in the agent's MCP catalog (`.claude/settings.json`, `.copilot/mcp-config.json`, `.antigravity/mcp_config.json`).
   - Forces structured tool execution through `bap_execute`, evaluating tool arguments against Cedar policies prior to dispatch.
   - Provides runtime introspection tools: `bap_explain_policy` and `bap_status`.

3. **Layer 3: Tool Call & Terminal Interceptor Shims (`PATH` Hijacking Defense):**
   - Intercepts raw terminal commands or unmediated child subshells that attempt to bypass Layer 1 and Layer 2.
   - The launcher engine (`Initialize-BapShims`) generates per-session command shims in `.bapstate/shims-$SessionId/` for critical CLI executables (`git`, `python`, `curl`, `wget`, `powershell`, `cat`, `rm`) and prepends this directory to `$env:PATH`.
   - Any raw invocation of `git` or `curl` by an agent subshell executes the `.cmd` shim, which immediately forwards execution through `bapedge.exe exec --raw` under the active session and Cedar rules. Re-entrant execution inside the broker is un-shimmed via `BAP_IN_BROKER=1`.

4. **Layer 4: In-Process Broker, Sandbox Containment & Merkle Audit:**
   - The final host-level execution authority: `bapedge exec` with an in-process AWS Cedar engine evaluates operations in $<1.5\text{ms}$.
   - Enforces execution environment variables (`BAP_MODE=enforce`, `BAP_AGENT_SANDBOX=1`).
   - Spawns a detached background watchdog (`bapedge watch`) pulsing liveness heartbeats to `/api/v1/sessions/heartbeat` and enforcing real-time administrative revocations and emergency freezes.
   - Seals every execution result and token accounting record (`accountingSnapshot`) into the tamper-evident SHA-256 Merkle chain at `/api/v1/audit/ingest`.

5. **Layer 5: Authoritative Network Gateway PEP & Perimeter Backstop:**
   - Centralized, authoritative perimeter enforcement via `bapgateway` (Envoy `ext_authz`).
   - Validates that every network call matches a pre-authorized, un-expired Zero-Trust Session Protocol (ZSP) grant.
   - Burns single-use grants upon execution to prevent replay attacks and verifies cryptographic tenant isolation before traffic reaches corporate backends or cloud egress.

---

### 8.7. Multi-Agent Defense Matrix: Implementation Across All Tools

| Agent Toolchain | Layer 1 (Hooks / Invariants) | Layer 2 (MCP Integration) | Layer 3 (Terminal Shims) | Layer 4 (Broker & Sandbox) | Layer 5 (Gateway PEP Egress) | Test Verification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Claude Code CLI** | `cchook/interceptor.exe` (`SessionStart`, `UserPromptSubmit`, `PreToolUse`) | `bapmcp.exe` mounted in `.claude/settings.json` | Active in `.bapstate/shims-$SessionId` | `bapedge exec` + watchdog + refcounted custody | Envoy `ext_authz` + ZSP grant burning | `tests/test_multi_layer_defense.py` |
| **Google Antigravity (IDE)** | `GEMINI.md` zero-trust rules + 120ms `transcript.jsonl` tailer | `bapmcp.exe` mounted in `.antigravity/mcp_config.json` | Active in `.bapstate/shims-$SessionId` | Electron GUI lifecycle guard + `bapedge exec` | Envoy `ext_authz` + ZSP grant burning | `tests/test_multi_layer_defense.py` |
| **Google Antigravity (CLI)** | `GEMINI.md` rules + direct console capture | `bapmcp.exe` mounted in `.antigravity/mcp_config.json` | Active in `.bapstate/shims-$SessionId` | `agy.exe` supervised by `bapedge exec` | Envoy `ext_authz` + ZSP grant burning | Automated launcher suite |
| **GitHub Copilot CLI** | `AGENTS.md` rules + live `events.jsonl` streamer | `bapmcp.exe` mounted in `.copilot/mcp-config.json` | Active in `.bapstate/shims-$SessionId` | Standalone `copilot.exe` + `accountingSnapshot` capture | Envoy `ext_authz` + ZSP grant burning | Automated launcher suite |
| **Autonomous Python SDK** | `bap_sdk.BAPSession` native mission wrapper | MCP tool wrappers & programmatic decorators | Subprocesses routed through `bap.exec()` | Real-time 3s daemon heartbeat + Cedar broker | Envoy `ext_authz` + ZSP grant burning | `tests/test_bounded_authority_matrix.py` |

---

### 8.8. Universal Extension Guide: How to Onboard a New AI Tool

To onboard any new AI tool (e.g. Cursor, Windsurf, Devin, OpenAI Operator, or internal CLI) into BAP's 5-layer defense system, follow this 5-step integration recipe:

#### Step 1: Layer 1 — Hook Configuration or Workspace Rule Injection
1. If the tool supports native lifecycle hooks (JSON on stdin/stdout), register `dist/windows-amd64/interceptor.exe` (or `cchook/interceptor.exe`) in the tool's settings.
2. If the tool is prompt- or rule-driven, inject an authoritative workspace invariant file (e.g. `.cursorrules`, `SYSTEM_PROMPT.md`, `INVARIANTS.md`) directing the agent:
   - All shell executions MUST use `bapedge.exe exec "<cmd>"`.
   - Never execute raw shell commands directly.
3. In [`cchook/interceptor.go`](file:///c:/Users/User/pyprj/bapltd/cchook/interceptor.go), register the tool's source identifier in `unwrapBrokerCommand` (e.g., `source = "newtool"`).

#### Step 2: Layer 2 — MCP Server Catalog Registration
1. Generate the tool's native MCP configuration file (e.g. `.newtool/mcp.json` or `~/.config/newtool/mcp.json`).
2. Mount `bapmcp.exe` as the `bap-zero-trust` MCP server:
   ```json
   {
     "mcpServers": {
       "bap-zero-trust": {
         "command": "C:\\path\\to\\bapltd\\bapmcp.exe",
         "args": []
       }
     }
   }
   ```

#### Step 3: Layer 3 — Terminal Shims Activation
1. When launching the tool, invoke `Initialize-BapShims` from [`scripts/bap_launcher_engine.ps1`](file:///c:/Users/User/pyprj/bapltd/scripts/bap_launcher_engine.ps1).
2. This generates `.cmd` shims for `git`, `python`, `curl`, `wget`, `powershell`, `cat`, `rm` in `.bapstate/shims-$SessionId/`.
3. Prepend the shim directory to `$env:PATH`:
   ```powershell
   $ShimDir = Initialize-BapShims -Workspace $Workspace -BapEdgeBin $BapEdgeBin -AgentId $AgentId -SessionId $SessionId
   $env:PATH = "$ShimDir;$env:PATH"
   ```
4. If the new tool uses custom CLI binaries, append them to the `$toolsToShim` array.

#### Step 4: Layer 4 — Launcher Engine Profile & Lifecycle Supervision
1. Create `run_<newtool>_bap.bat` and `run_<newtool>_bap.ps1`.
2. Invoke `Invoke-BapGovernedSession` with:
   - `AgentId`: e.g. `'newtool'`
   - `AgentMode`: `'cli'` for terminal CLIs, or `'ide'` for GUI/Electron apps (activates active process tree monitoring so the session doesn't prematurely terminate).
   - `CandidateExecutables`: Discovery paths for the tool executable.
   - `ConfigureFiles`: Callback scriptblock injecting the workspace rule file and MCP configuration file.
3. If the tool emits background session logs (e.g. JSON lines of prompts or tokens), attach a lightweight background tailer job (similar to Antigravity's `transcript.jsonl` or Copilot's `events.jsonl`) to stream prompts to `/api/v1/sessions/prompt` and tokens to `/api/v1/audit/ingest`.

#### Step 5: Layer 5 — Gateway PEP Route Registration & Egress Pinning
1. Register backend service endpoints in `bapgateway` Envoy configuration.
2. Require Zero-Trust Session Protocol (ZSP) grant headers on outgoing requests:
   - `X-BAP-Grant-ID`: Single-use capability token minted by BAP Control Plane.
   - `X-BAP-Signature`: Ed25519 cryptographic authorization signature.
3. Ensure unauthenticated direct egress from the host to production backends is blocked at the firewall, forcing all enterprise traffic through `bapgateway`.

---

## 9. Operational Resilience, Crash Sweeps & Developer Tooling Architecture (Epic 24)

### 9.1. Clean Sweep & Crash Recovery Reconciler (BAP-470)

In enterprise deployments, developer laptops abruptly sleep, battery dies, processes are force-killed, or terminals close without executing graceful shutdown hooks. BAP solves state desynchronization via automatic and manual clean sweep routines:

```mermaid
sequenceDiagram
    autonumber
    participant Dev as Developer / CLI
    participant Edge as bapedge Broker
    participant Local as .bap/sessions Cache
    participant CP as Central Control Plane

    Note over Dev,Edge: Workstation crashes or abruptly shuts down
    Dev->>Edge: bapedge sweep (or startup session-start)
    Edge->>Local: Scan .bap/sessions/*.json
    Local-->>Edge: Return stored PIDs & Session IDs
    loop For Each Marker
        Edge->>Edge: Check isProcessAlive(PID)
        alt PID is Dead (Crash Residue)
            Edge->>Local: Delete orphaned marker & release lockfiles
            Edge->>CP: POST /api/v1/control/sweep {session_id, reason: "orphaned_crash_detected"}
        end
    end
    Edge->>CP: POST /api/v1/control/sweep {stale_idle_seconds: 300}
    CP->>CP: PurgeStale() & ReconcileOrphans() (expire unpresented grants)
    CP-->>Edge: HTTP 200 {status: "reconciled", swept_sessions, reconciled_grants}
    Edge-->>Dev: Print clean sweep confirmation & rejoin fleet
```

### 9.2. Developer CLI Tooling Architecture (BAP-471, BAP-472)

To minimize friction and prevent developers from bypassing controls, BAP embeds native operational commands into `bapedge`:

1. **`bapedge setup --app=claude-code` (BAP-471):**
   - Idempotently writes `.claude/managed-settings.json`.
   - Strictly enforces `"dangerouslySkipPermissions": false`.
   - Registers `"pre_tool_use": "bapedge exec"`.
   - Configures central control plane connectivity in `.bap/config.json`.
2. **`bapedge status` (BAP-472):**
   - Real-time terminal inspection of active vs stale sessions.
   - Cedar policy bundle version, rules SHA-256 digest, and kill-switch state.
   - 5-Layer Defense-in-Depth Compliance (Layer 1: Hooks, Layer 2: MCP, Layer 3: Terminal Shims, Layer 4: Kernel Sandbox, Layer 5: Gateway PEP).
   - Offline spool backlog count.
3. **`bapedge why "<command>"` (BAP-472):**
   - In-terminal Cedar policy evaluation with zero browser round-trips.
   - Explains decisions (`ALLOWED` vs `DENIED`).
   - Identifies specific Cedar rule IDs and context attributes (executable, workspace escape status).

### 9.3. Offline Audit Store & Reconnection Flush (BAP-473)

Execution events generated while offline are preserved in `ltd-audit.jsonl` maintaining SHA-256 Merkle chain integrity. Upon network reconnection:
1. `bapedge watch` heartbeat pulse detects active control plane connectivity.
2. Background routine calls `audit.FlushOfflineAudit(serverURL, logPath)`.
3. Control Plane ingests batch (`/api/v1/audit/ingest`) and returns a cryptographic `HandshakeAck` (`chain_valid: true`, `receipt_hash: ...`).
4. `bapedge` safely removes transmitted entries locally, relieving edge disk burden while guaranteeing end-to-end auditability.

---

## 10. Enterprise Identity Provider Federation (Okta / Entra / OIDC Device Flow)

Enterprise organizations require autonomous agent execution to be attributable to verified corporate identities with Multi-Factor Authentication (MFA), rather than relying on unauthenticated developer tokens. BAP integrates directly with Microsoft Entra ID, Okta Workforce Identity Cloud, and standard OpenID Connect providers via the **RFC 8628 OAuth 2.0 Device Authorization Flow**.

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Human Engineer
    participant Edge as bapedge CLI
    participant CP as Control Plane
    participant IdP as Enterprise IdP (Okta / Entra ID)
    participant Cedar as Cedar Policy Engine

    Note over Dev,Edge: 1. Initiate Corporate Identity Login
    Dev->>Edge: bapedge login --provider=entra
    Edge->>CP: GET /api/v1/auth/oidc/config (Discover IdP endpoints & scopes)
    CP-->>Edge: HTTP 200 {provider: "entra", verification_uri: "https://login.microsoftonline.com/...", scopes: [...]}
    Edge->>CP: POST /api/v1/auth/oidc/device-code {client_id, hostname, binary_hash}
    CP-->>Edge: HTTP 200 {device_code: "...", user_code: "WDJB-MJHT", verification_uri: "..."}
    Edge-->>Dev: Display login instructions: "Visit https://... & enter code: WDJB-MJHT"

    Note over Dev,IdP: 2. Browser MFA Authorization
    Dev->>IdP: Authenticate with Corporate SSO & FIDO2/MFA
    IdP-->>Dev: MFA Verification Approved
    IdP->>CP: POST /api/v1/auth/oidc/device-verify {user_code: "WDJB-MJHT", email: "alice@corp.com", dept: "Finance", groups: [...]}
    CP->>CP: Validate AllowedDomains & Enroll Agent with Identity Claims

    Note over Edge,CP: 3. Token Issuance & Credential Binding
    loop Poll Every 1s (RFC 8628 §3.5)
        Edge->>CP: POST /api/v1/auth/oidc/device-token {device_code}
        alt Pending
            CP-->>Edge: HTTP 400 {error: "authorization_pending"}
        else Approved
            CP-->>Edge: HTTP 200 {status: "authorized", user_email: "alice@corp.com", dept: "Finance", session_token: "..."}
        end
    end
    Edge->>Edge: Save to ~/.ltd/credentials.json (auth_mode: "oidc", department: "Finance")
    Edge-->>Dev: [✓] Authenticated as alice@corp.com (Finance). Agent session bound!

    Note over Edge,Cedar: 4. Native Policy Evaluation with Identity Claims
    Dev->>Edge: bapedge exec "billing-tool --report"
    Edge->>Cedar: Evaluate(principal.department="Finance", context.executable="billing-tool")
    Cedar-->>Edge: ALLOWED (Permitted by Finance department rule)
```

### 10.1. Dual-Mode Environment Security Model (Dev vs Prod)

To prevent security misconfigurations while maintaining fast local development velocity, BAP enforces an explicit environment security boundary:

| Feature / Behavior | Development Mode (`mode: dev`) | Production Mode (`mode: prod`) |
|---|---|---|
| **Self-Service OTC Token API (`/dev-request`)** | **Enabled:** Any local developer can request an instant OTC code without credentials. | **Disabled (`403 Forbidden`):** Unauthenticated OTC requests are rejected. |
| **One-Time Code (OTC) Generation** | Instant self-service via `POST /api/v1/auth/otc/dev-request` or `bapedge register --dev`. | Strictly an **offline / out-of-band administrative process** (`POST /api/v1/agents/pre-register` with `X-BAP-Admin-Token`). |
| **Interactive Developer Authentication** | Optional OIDC login or local OTC code. | **Mandatory OIDC Device Flow (`bapedge login`):** Engineers must authenticate through corporate MFA (Okta / Entra). |
| **Headless CI/CD / Build Pipeline Enrollment** | Supported via OTC codes (`bapedge register --code <OTC>`). | Supported via pre-provisioned offline admin OTC codes. |
| **Security Rationale** | Zero friction for onboarding & rapid prototyping. | Hardened zero-trust: no unauthenticated caller can create valid execution credentials. |

### 10.2. Configurable Enterprise IdP Parameters

All OIDC parameters are fully configurable across configuration files, environment variables, and CLI arguments:

```json
{
  "controlplane_url": "https://bap.corp.internal:8080",
  "gateway_url": "https://gateway.corp.internal:9090",
  "environment": "production",
  "oidc": {
    "enabled": true,
    "provider": "entra",
    "issuer_url": "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0",
    "client_id": "bap-edge-agent-client-id",
    "verification_uri": "https://login.microsoftonline.com/common/oauth2/deviceauth",
    "scopes": ["openid", "profile", "email", "groups"],
    "tenant_id": "72f988bf-86f1-41af-91ab-2d7cd011db47",
    "allowed_domains": ["corp.internal", "enterprise.com"],
    "claim_department": "department",
    "claim_groups": "groups",
    "claim_email": "email"
  }
}
```

- **Environment Overrides:** `BAP_OIDC_PROVIDER`, `BAP_OIDC_CLIENT_ID`, `BAP_OIDC_ISSUER_URL`, `BAP_OIDC_TENANT_ID`, `BAP_OIDC_ALLOWED_DOMAINS`.
- **Public Discovery:** Edge clients automatically query `GET /api/v1/auth/oidc/config` to resolve provider verification endpoints dynamically without hardcoding URLs.
- **Client Secret Safety:** Secrets are never sent to edge clients or exposed over discovery APIs.

### 10.3. Native Cedar Policy Claims Propagation

When evaluating local or centralized Cedar policies, `bapedge` and `bapcontrolplane` inject authenticated corporate identity attributes onto the Cedar `Principal` entity and `Context` record:

```cedar
// 1. Role-Based Access: Only Finance team members can invoke financial CLI tools
permit (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    principal.department == "Finance" &&
    ["billing-tool", "invoice-sync", "git"].contains(context.executable)
};

// 2. Strict Boundary: Block production deployment tools unless member of prod-deployers group
forbid (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    !principal.groups.contains("prod-deployers") &&
    context.full_command like "*deploy-prod*"
};
```

### 10.4. Coexistence of OTC & OIDC on Edge Workstations

To ensure headless servers and automated CI/CD runners can operate without interactive browser sessions:
- `bapedge register --code <OTC>` remains fully functional for headless server provisioning and automated integration test pipelines.
- `bapedge login` provides seamless, interactive SSO/MFA authentication for software developers using Claude Code, GitHub Copilot, and Cursor.
- `bapedge status` displays the active enrollment method, corporate identity, department, and group memberships.

---

## 11. Cross-Platform Packaging & CI/CD Release Pipeline Architecture (Epic 26)

### 11.1. Release Pipeline Flow & GitHub Actions Matrix

BAP uses an automated GitHub Actions release matrix (`.github/workflows/release.yml`) and testing matrix (`.github/workflows/ci.yml`) to compile, sign, package, and publish release artifacts across all major operating systems and chip architectures:

```mermaid
flowchart TD
    Tag["Git Release Tag (v*) / Workflow Dispatch"] --> Matrix["GitHub Actions Build Matrix"]
    
    subgraph BuildTargets ["Compilation & Code Signing"]
        Matrix --> M1["macOS Apple Silicon (darwin-arm64)\n• go build -ldflags\n• Apple Developer ID codesign"]
        Matrix --> M2["macOS Intel (darwin-amd64)\n• go build -ldflags\n• Apple Developer ID codesign"]
        Matrix --> M3["Linux x86_64 (linux-amd64)\n• go build CGO=0 static\n• sha256 checksums"]
        Matrix --> M4["Linux ARM64 (linux-arm64)\n• go build CGO=0 static\n• sha256 checksums"]
        Matrix --> M5["Windows AMD64 (windows-amd64)\n• go build -ldflags\n• Authenticode signtool"]
    end

    subgraph MDMPackaging ["Enterprise MDM Packaging"]
        M1 & M2 --> PKG["macOS .pkg Installer\n+ Jamf com.bap.edge.mobileconfig\n+ LaunchDaemon plist"]
        M3 & M4 --> DEB["Debian .deb Package\n+ Linux systemd Unit\n+ Standalone .tar.gz"]
        M5 --> MSI["Windows .msi Installer\n+ Intune-BAP-Policy.xml CSP\n+ Win32 Install-BAPEdge.ps1"]
    end

    PKG & DEB & MSI --> Release["GitHub Release Publisher\n• SHA256SUMS.txt Manifest\n• Signed Binaries & MDM Profiles"]
```

### 11.2. Enterprise MDM Distribution Artifacts

| Platform / MDM Target | Primary Installer | Configuration / Policy Payload | Daemon Supervision | Permissions / TCC |
| :--- | :--- | :--- | :--- | :--- |
| **macOS (Jamf Pro / Kandji)** | `bapedge-darwin-arm64.pkg` | `com.bap.edge.mobileconfig` | LaunchDaemon (`/Library/LaunchDaemons/com.bap.edge.plist`) | Apple TCC Full Disk Access profile for `/usr/local/bin/bapedge` |
| **Windows (Microsoft Intune)** | `bapedge-windows-amd64.msi` | `Intune-BAP-Policy.xml` (OMA-URI CSP) | Windows Service / Scheduled Task (`BAPEdgeDaemon`) | System-level execution & PATH registration in `C:\Program Files\BAP\` |
| **Linux (Ansible / Chef)** | `bapedge-linux-amd64.deb` | `/etc/bap/bap-config.json` | systemd unit (`bapedge.service`) | POSIX root execution with Landlock LSM / eBPF |

### 11.3. Cryptographic Code Signing & Supply Chain Integrity

1. **macOS Gatekeeper & Notarization:**
   - Apple Developer ID certificates sign binaries with the hardened runtime (`--options runtime`).
   - Binaries pass macOS Gatekeeper with zero warning prompts during Jamf enterprise deployment.
2. **Windows SmartScreen & Authenticode:**
   - Signed via Microsoft Authenticode `signtool.exe` with RFC 3161 Digicert timestamping (`/tr http://timestamp.digicert.com`).
   - Prevents Microsoft Defender SmartScreen untrusted binary warnings.
3. **Cryptographic Checksum Ledger:**
   - The release job calculates SHA-256 digests across all compiled packages and produces `SHA256SUMS.txt`.
   - Security teams can independently verify binary digests against the signed manifest before pushing to workstation fleets.

---

## 12. Agent Watch Persona Architecture & Canonical Activity Engine (Epic 28)

### 12.1. Canonical Agent Activity Event Normalization
To prevent disparate data schemas across executive, security, and operational dashboards, BAP enforces a single normalized event structure:
```text
AgentActivityEvent:
  - Identity & Runtime: timestamp (RFC 3339 UTC), session_id, agent_id, agent_type, runtime_id, user_id (redacted), business_unit, application
  - Prompt & Mission: prompt_id, prompt_summary (privacy-safe), intent, intent_category
  - Action & Resource: action, tool, target_resource, data_classification
  - Zero-Trust Policy: policy_decision, risk_score, grant_id, grant_scope, grant_ttl
  - Execution Status: action_status (working/waiting/completed/denied/failed), outcome_category, trace_id, deviation_level
```

### 12.2. Intent to Action Contract & Invariant Deviation Engine
Every agent operation is evaluated against the 8-stage lifecycle contract:
$$\text{Intent} \longrightarrow \text{Interpretation} \longrightarrow \text{Plan} \longrightarrow \text{Capability} \longrightarrow \text{Policy Gate} \longrightarrow \text{ZSP Grant} \longrightarrow \text{Observed Action} \longrightarrow \text{Outcome}$$

When an agent requests capabilities or executes tools conflicting with declared intent (e.g., executing arbitrary database writes during a read-only production latency diagnosis), the engine flags a **CRITICAL DEVIATION**, assigns a high risk score ($0.95$), and denies execution with a human-readable audit explanation.

### 12.3. Enterprise Activity Topology Mapping
Dynamic clustering algorithm groups sessions into a multi-tiered hierarchy:
$$\text{Enterprise Root} \longrightarrow \text{Divisions} \longrightarrow \text{Teams / Applications} \longrightarrow \text{Agent Platforms}$$
Nodes scale proportionally to active session count, while color encodes security posture (`healthy`, `warning`, `critical`).

### 12.4. Production Live Mode vs Demo Simulation
Control Plane natively supports dual operating modes:
- **Pure Live Mode (Default)**: Dynamically aggregates live connected agents, sessions, and activity events. Shows an unsimulated zero-state when the fleet is idle.
- **Demo Mode (`-demo-mode` flag or `?demo=true` param)**: Renders the 1,284-agent enterprise prototype dataset across 31 business units for presentations.

---

## 13. Multi-Layer AIR Defense, MicroVM Sandboxing & Human Step-Up Escalation (Epic 29)

### 13.1. Tiered Sandboxing Architecture vs MicroVMs
While MicroVMs (Firecracker, Cloud-Hypervisor, QEMU/KVM) provide hypervisor-grade isolation, enforcing them exclusively on local developer workstations introduces severe tradeoffs:
1. **Execution Latency**: MicroVM cold boot (150ms–3000ms) and virtio-fs dispatch introduce latency unacceptable for interactive coding assistants requiring sub-10ms CLI responsiveness.
2. **Cross-OS Fragmentation**: Linux relies natively on KVM (Firecracker); Windows requires Hyper-V/WSL2 nested virtualization; macOS relies on Apple Virtualization.framework. A single cross-OS binary cannot run microVMs identically on developer laptops without root/administrator privileges.
3. **Enterprise MDM Conflicts**: BIOS hardware virtualization (VT-x/AMD-V) is frequently locked down by corporate MDM or conflicts with developer Docker Desktop and emulator environments.
4. **Filesystem I/O Tax**: Sharing multi-gigabyte developer repositories (`node_modules`, `.venv`, `.git`) via 9P or virtio-fs incurs a 5x–20x I/O penalty.

**The BAP Hybrid Sandboxing Architecture**:
- **Tier 1 (Host-Native Zero-Dependency Sandbox - Default for CLI/IDE Work)**:
  - Windows: Windows Job Objects (kill-on-close, memory limits) + Restricted Security Tokens (dropping administrative SIDs and `SE_DEBUG_NAME`).
  - Linux: Landlock LSM + unprivileged user/mount namespaces + seccomp-bpf.
  - macOS: `sandbox-exec` Seatbelt confinement.
  - Provides sub-millisecond execution, zero hypervisor requirements, and 100% cross-OS mobility.
- **Tier 2 (On-Demand Ephemeral MicroVM Cloud Runner)**:
  - High-risk, unvetted binaries, unapproved container builds, or untrusted network downloads are routed via BAP Gateway PEP to remote ephemeral Firecracker/E2B microVM workers.

### 13.2. Human-in-the-Loop (HITL) Step-Up Escalation
When an agent encounters a policy boundary (e.g. mutating sibling projects, unapproved installers, or unvetted scripts):
1. **Interactive Step-Up TTY Prompt**:
   - `[A] Approve Once`: Permits single command execution; logs cryptographic receipt `ALLOWED_STEPUP` and audit decision `stepup_allow`.
   - `[S] Trust for Session`: Records persistent session trust in `.bap/approvals_<session_id>.json`; subsequent commands within that session execute seamlessly without prompting.
   - `[D] Deny (Default)`: Strictly blocks execution and logs policy violation.
2. **Headless / CI Mode**: Defaults to fail-closed (`step_up_decision: "denied"`) unless authorized via `BAP_STEPUP_DECISION=approve` or pre-authorized BAP Gateway Grants.
3. **Anti-Tampering Invariant**: BAP protected assets (`policy.cedar`, `bapedge.exe`, lifecycle hooks) are strictly non-escalatable and can never be bypassed via Step-Up.

### 13.3. Software Supply-Chain Corporate Mirror Injection
Prevents dependency confusion and public registry exfiltration by automatically injecting enterprise repository manager configurations (Nexus, Artifactory, CodeArtifact):
- **Maven**: Injects `$env:MAVEN_ARGS = "-s .bapstate/mirrors/settings.xml"` configuring `<mirror>` to route all artifact downloads through corporate Nexus (`nexus.corp.internal`).
- **npm / yarn**: Injects `$env:NPM_CONFIG_USERCONFIG = ".bapstate/mirrors/.npmrc"` enforcing corporate registry with `strict-ssl=true`.
- **pip**: Injects `$env:PIP_CONFIG_FILE = ".bapstate/mirrors/pip.ini"` and `$env:PIP_INDEX_URL`.
- **Policy 6 Enforcement**: Cedar invariants strictly block direct public repository bypass flags (`--index-url http://pypi.org`, `--registry registry.npmjs.org`, `-DremoteRepositories=http://repo.maven.apache.org`).
- **Policy 7 Tripwire**: Immediate alert and termination if an agent probes canary honeytokens (`CORP_CANARY_TOKEN`).

### 13.4. Enterprise Multi-Scope Cross-Folder Governance (`BAP-546`)
Enterprise codebases frequently require cross-repository builds, mono-repo traversals, and shared library modifications:
1. **Separation of Read-Only Traversal vs Mutating Escalation**:
   - Reading sibling repositories (`cat ../sibling/README.md`, `git -C ../dep status`) is natively permitted by Cedar Rule 2.
   - Mutating commands (`write`, `delete`, `tamper`, output redirection `>`) escaping workspace root trigger Human-in-the-Loop (HITL) step-up.
2. **Multi-Scope Persistence Architecture**:
   - `Once`: Single execution grant yielding `ALLOWED_STEPUP` cryptographic receipt.
   - `Session`: Stored in `.bap/approvals_<session_id>.json`.
   - `Project`: Stored in `<workspace>/.bap/project_permissions.json`.
   - `Global`: Stored in `~/.bap/global_permissions.json`.
3. **Canonical Prefix Resolution**:
   - Normalized paths handle symlinks, directory boundaries (`C:\app\sub` vs `C:\app\sub-other`), and case-insensitive Windows filesystem semantics.

---

## 14. Unified CLI Architecture & Binary Lifecycle Parity (Epic 30 — `BAP-547`)

### 14.1. Universal CLI Design & Zero-Surprise Invariant
All four BAP binaries (`bapedge`, `bapcontrolplane`, `bapgateway`, `bapmcp`) adhere to a uniform lifecycle contract:

```mermaid
flowchart TD
    INVOKE["Binary Invocation (bapedge / bapcontrolplane / bapgateway / bapmcp)"]
    
    INVOKE --> CHECK_ARGS{"Arguments Passed?"}
    CHECK_ARGS -->|No Args / 'help' / '--help'| USAGE["Display Structured ASCII Usage Banner (Exit 0)"]
    CHECK_ARGS -->|Flag passed directly e.g. -port| COMPAT["Backward Compatibility Dispatcher -> start [flags]"]
    CHECK_ARGS -->|Subcommand| DISPATCH{"Subcommand Router"}
    
    DISPATCH -->|start| START["runStart: Foreground or Background Daemon (--detach)"]
    DISPATCH -->|stop| STOP["runStop: Read PID file, Graceful Terminate, Purge PID"]
    DISPATCH -->|status| STATUS["runStatus: Inspect Health, Active Port, Uptime, Store"]
    DISPATCH -->|restart| RESTART["runRestart: Sequential Stop -> Sleep -> Start"]
    DISPATCH -->|enable| ENABLE["runEnable: Idempotent Credentials, Dirs & Tokens"]
    DISPATCH -->|serve / run| SERVE["runStart: Foreground Server Alias"]
    DISPATCH -->|Governance / Exec| GOV["bapedge: trust, untrust, permissions, rollback, pin, why, exec, check"]
```

### 14.2. Binary Command Matrix & Parity

| Subcommand | `bapedge` | `bapcontrolplane` | `bapgateway` | `bapmcp` | Description |
|---|:---:|:---:|:---:|:---:|---|
| `start` | ✅ | ✅ | ✅ | — | Start component server / supervisor (supports `--detach` / `-d`, `--port`) |
| `stop` | ✅ | ✅ | ✅ | — | Gracefully terminate running instance via tracked PID |
| `status` | ✅ | ✅ | ✅ | ✅ | Query health, active port, uptime, and database persistence |
| `restart` | ✅ | ✅ | ✅ | — | Atomic restart (`stop` $\to$ wait $\to$ `start`) |
| `enable` | ✅ | ✅ | ✅ | — | Idempotent workstation/service initialization (setup tokens & state) |
| `serve` | ✅ | ✅ | ✅ | ✅ | Explicit foreground server execution alias |
| `trust` | ✅ | — | — | — | Authorize cross-folder mutations (`--session`, `--project`, `--global`) |
| `untrust` | ✅ | — | — | — | Revoke cross-folder mutation authorization |
| `permissions` | ✅ | — | — | — | List all active authorizations across all scopes |
| `rollback` | ✅ | — | — | — | Forensically revert file mutations to pre-execution checkpoints |
| `pin` | ✅ | — | — | — | Cryptographically pin, verify, and re-attest skills, prompts & tools |
| `why` | ✅ | — | — | — | Instant terminal explanation of Cedar policy decisions |
| `exec` / `check` | ✅ | — | — | — | Governed execution / dry-run evaluation under kernel isolation |
| `mcp` | ✅ | — | — | ✅ | Model Context Protocol JSON-RPC stdio server |

### 14.3. Cross-Platform Process Supervision Architecture
Process lifecycle management avoids external shell dependencies and platform-specific lockups:
- **Windows (`proc_windows.go`)**:
  - `isProcessAlive(pid)`: Uses Win32 `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` and `GetExitCodeProcess`.
  - Background Detachment: Spawns processes with `CREATE_NO_WINDOW (0x08000000)` and `CREATE_NEW_PROCESS_GROUP (0x00000200)`, disconnecting standard I/O handles.
  - Termination: `os.FindProcess(pid).Kill()` followed by `taskkill /F /PID <pid>` for complete child process-tree eradication.
- **POSIX (`proc_unix.go`)**:
  - `isProcessAlive(pid)`: `syscall.Kill(pid, 0)`.
  - Background Detachment: Sets `SysProcAttr.Setpgid = true`.
  - Termination: `syscall.Kill(pid, syscall.SIGTERM)` with fallback to `SIGKILL`.

### 14.4. Interactive Terminal Guard on BAP MCP
Running `bapmcp` or `bapedge mcp` in an interactive console without stdin redirection detects terminal mode via `isTerminal(os.Stdin)` and outputs an onboarding guide with instructions for Claude Code (`~/.claude/settings.json`), Google Antigravity (`~/.gemini/antigravity/mcp/bap-zero-trust/`), and Cursor IDE (`~/.cursor/mcp.json`). When spawned by an agent host with piped stdio or passed `--stdio`, it immediately engages the JSON-RPC 2.0 message loop.

---

## 15. Unified Workstation Registration, Child Session SVIDs & Subagent Architecture (Epic 43 — `BAP-800`)

### 15.1. The Workstation Anchor vs Child Session SVID Model
Enterprise fleet governance requires physical host accountability. Rather than permitting each ephemeral AI process to register an independent agent identity (which causes fleet sprawl and breaks device-level attestation), BAP implements a **Workstation Authority Anchor**:
- **Physical Workstation (Master Anchor)**: A single developer laptop, desktop, or CI build runner enrolls via `bap login`, minting a persistent machine credential anchored in `~/.bapstate/credentials.json`.
- **Workstation SPIFFE ID**: `spiffe://<trust_domain>/workstation/<instance_id>` (or `spiffe://<trust_domain>/app/<app_id>/instance/<instance_id>`).
- **Child Workload Session SVID**: Every tool running on the workstation (Claude Code CLI, Claude IDE, Antigravity, GitHub Copilot, custom Python SDK agents) executes as an ephemeral child session bound to a hierarchical Session SVID:
  $$\text{Session SVID} = \text{spiffe://} + \text{TrustDomain} + \text{/workstation/} + \text{InstanceID} + \text{/session/} + \text{SessionID}$$

### 15.2. Hierarchical Identity Topology

```mermaid
flowchart TD
    subgraph CorporateIdP ["Enterprise IdP (RFC 8628 Device Flow)"]
        IdP["Okta / Microsoft Entra ID / Google Identity"]
    end

    subgraph Host ["Physical Workstation / Laptop"]
        Creds["~/.bapstate/credentials.json<br/>- Instance ID: inst-ws-7a8b9c<br/>- Workstation SPIFFE ID: spiffe://bap.internal/workstation/inst-ws-7a8b9c<br/>- User: engineer@enterprise.internal"]
        
        subgraph ChildAgents ["Ephemeral AI Agent Workloads"]
            Claude["Claude Code CLI / IDE<br/>Session: sess-claude-91823<br/>SVID: .../workstation/inst-ws-7a8b9c/session/sess-claude-91823"]
            PySDK["Python SDK Agent<br/>Session: sess-py-48201<br/>SVID: .../workstation/inst-ws-7a8b9c/session/sess-py-48201"]
            AG["Google Antigravity<br/>Session: sess-ag-31940<br/>SVID: .../workstation/inst-ws-7a8b9c/session/sess-ag-31940"]
        end
    end

    subgraph ControlPlane ["BAP Control Plane"]
        Registry["Master Registry (s.agents)<br/>1 Card: Workstation inst-ws-7a8b9c<br/>Subagents: ['claude-code', 'python-agent', 'antigravity']"]
        Sessions["Active Telemetry (s.sessions)<br/>sess-claude-91823 (Active)<br/>sess-py-48201 (Active)<br/>sess-ag-31940 (Active)"]
    end

    IdP -->|bap login| Creds
    Creds -.->|Inherit Workstation Anchor| Claude
    Creds -.->|Inherit Workstation Anchor| PySDK
    Creds -.->|Inherit Workstation Anchor| AG
    
    Claude -->|POST /api/v1/sessions/start| Registry
    PySDK -->|POST /api/v1/sessions/start| Registry
    AG -->|POST /api/v1/sessions/start| Registry

    Registry --> Sessions
```

### 15.3. Control Plane Registry Deduplication (`EnsureSessionAgent`)
To prevent agent sprawl, `EnsureSessionAgent` matches incoming sessions against existing records in `s.agents`:
1. **Instance & Agent Matching**: Checks if `a.InstanceID == instanceID || a.AgentID == instanceID`.
2. **Host & User Matching**: Checks if `a.Hostname == hostname && a.UserEmail == email`.
3. **Subagent Dynamic Append**: When a match is found, appends the tool name (`app_id`) to `master.Subagents` (preventing duplicates), updates `a.LastHeartbeatAt`, and returns the master card without minting a new agent entry in `s.agents`.
4. **Session Isolation**: Ephemeral tool activity is recorded in `s.sessions`, ensuring granular start, prompt, execution receipts, and termination tracking without polluting the master agent inventory.

### 15.4. Unified Workstation Credentials Distribution
All client runtimes resolve the workstation authority anchor via standard path discovery:
- **`bap-edge watch`**: Reads `~/.bapstate/credentials.json`, extracts `user_email` and `spiffe_id`, sets `resource_id`, `workstation_spiffe_id`, and `session_svid` in `startPayload`.
- **`bap-edge identity`**: Prioritizes `credentials.json` in Stage 2 of `resolveLocalIdentity()`, eliminating `"NA"` identity degradations.
- **`python-agent/bap_sdk`**: Automatically loads `credentials.json`, deriving `self.instance_id`, `self.workstation_spiffe_id`, and `self.session_svid` directly on session instantiation.
- **Daemon Route Isolation**: `bapedge exec` validates `serverMatches` before delegating audit telemetry to local daemons, ensuring events are never routed to dead or mismatched test/production endpoints.

### 15.5. Tool-Agnostic Decision Normalization
Developer tooling utilizes divergent JSON output schemas:
- **Anthropic Claude Code**: Strict legacy schema requiring top-level `decision: "approve" | "block"`.
- **Generic CLI & IDE Agents**: Standard schema expecting `decision: "allow" | "deny"`.
- **Interceptors (`interceptor.exe`, `cchook-interceptor.exe`)**: Automatically detect caller binary variants (`claude`, `claude-code`, `claudecode`, wrapper batch files) and synthesize exact matching response schemas, preventing `Hook JSON output validation failed` errors while preserving invariant Cedar policy enforcement.









