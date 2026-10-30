# Architecture Decision Record (ADR-005)
## BAP-800: Unified Workstation Master Enrollment & Ephemeral Session SVIDs

**Status:** Approved  
**Date:** 2026-10-30  
**Deciders:** Enterprise Security Architecture Board, BAP Engineering Lead  
**Technical Area:** Workstation Governance, SPIFFE/SPIRE Identity Mesh, Agent Lifecycle, Zero-Sprawl Registry  

---

### 1. Context and Problem Statement

When developer laptops, workstations, or CI runners are governed by BAP, administrators require clear, unambiguous asset accounting and cryptographic workload attestation. In earlier iterations, BAP utilized a Trust-On-First-Use (TOFU) model where each running AI agent tool (Claude Code, Antigravity IDE, GitHub Copilot, custom Python SDK scripts) generated its own ad-hoc agent ID upon startup.

This per-process registration model led to significant architectural challenges:
1. **Agent Sprawl in Control Plane**: A single developer machine running multiple tools or restarting CLI sessions minted dozens of disconnected agent cards in `s.agents`, cluttering the fleet cockpit and degrading asset reconciliation.
2. **Missing Workstation Cryptographic Root**: Without a single machine-level authority anchor, the control plane could not cryptographically verify whether two distinct AI processes originated from the same enrolled corporate endpoint.
3. **Identity Fragmentation**: Enterprise IdP claims (Entra ID, Okta, Google Workspace) obtained during `bap login` were tied to a local file but not cleanly inherited by ephemeral child workloads as cryptographically verifiable sub-identities.

---

### 2. Evaluated Options

1. **Option A (Retain Per-Process TOFU Registration):**
   - Continue minting independent agent IDs for every CLI or SDK process.
   - *Drawbacks*: Severe agent sprawl, high memory churn in registry database, fragmented SIEM audit logs, no device-level cryptographic anchor.
2. **Option B (Static Machine Token Without Session SVIDs):**
   - All tools on the host reuse the raw workstation token directly without session differentiation.
   - *Drawbacks*: Complete loss of prompt-to-action session isolation; impossible to revoke a rogue Claude Code session without revoking the entire developer workstation.
3. **Option C (Unified Workstation Anchor with Ephemeral Child Session SVIDs — Chosen):**
   - **Workstation Master Anchor**: Running `bap login` establishes exactly **one** master workstation registration on the control plane, assigning a permanent Workstation SPIFFE ID (`spiffe://<trust_domain>/workstation/<instance_id>`) and persisting credentials in `~/.bapstate/credentials.json`.
   - **Child Session SVIDs**: Every tool execution (Claude Code, Python SDK, Antigravity, Copilot) inherits the host workstation's anchor and obtains a deterministic, hierarchical Session SVID:  
     `spiffe://<trust_domain>/workstation/<instance_id>/session/<session_id>`
   - **Zero-Sprawl Control Plane Registry**: `EnsureSessionAgent` links child sessions to the existing workstation master card in `s.agents`, dynamically updating `master.Subagents` (e.g. `["claude-code", "python-agent"]`) while tracking ephemeral runs in `s.sessions`.

---

### 3. Decision Drivers & Architecture Invariants

- **Single Device Anchor (1 Machine = 1 Master Registry Entry)**:  
  An enrolled developer laptop maintains exactly one identity card in the Control Plane registry (`s.agents`). Re-authentications and child agent executions attach to this root authority.
- **Hierarchical SPIFFE Workload Proof**:  
  Child workloads prove device provenance through path-based SPIFFE identity syntax:
  $$\text{Session SVID} = \text{spiffe://} + \text{TrustDomain} + \text{/workstation/} + \text{InstanceID} + \text{/session/} + \text{SessionID}$$
- **Granular Revocation Independence**:  
  Administrators can terminate an individual compromised session (`sess-claude-xyz`) via `/api/v1/sessions/end` without invalidating the developer's enrolled machine credentials.
- **Cross-Tool Schema Neutrality**:  
  The enforcement kernel supports heterogeneous tool protocol contracts simultaneously (e.g., Anthropic Claude Code legacy top-level `decision: "approve" | "block"` alongside generic tools expecting `decision: "allow" | "deny"`), eliminating hook errors regardless of agent client variant.

---

### 4. Technical Specification

#### 4.1 Master Workstation Enrollment (`bap login`)
During RFC 8628 Device Authorization, the control plane registers the physical host:
```json
{
  "agent_id": "agent-ws-7a8b9c",
  "app_id": "claude-code-workstation",
  "instance_id": "inst-ws-7a8b9c",
  "spiffe_id": "spiffe://bap.internal/workstation/inst-ws-7a8b9c",
  "user_email": "engineer@enterprise.internal",
  "auth_mode": "oidc",
  "subagents": []
}
```
Credentials are written to `~/.bapstate/credentials.json` with permissions `0600`.

#### 4.2 Child Agent Session Startup
When an agent session initiates (e.g. Claude Code via `bap-edge watch` or Python agent via `bap_sdk.BAPSession`):
1. Client inspects `~/.bapstate/credentials.json`.
2. Resolves `resource_id = creds.instance_id` and `workstation_spiffe_id = creds.spiffe_id`.
3. Derives `session_svid = f"spiffe://{trust_domain}/workstation/{creds.instance_id}/session/{session_id}"`.
4. Transmits session payload to `POST /api/v1/sessions/start`.
5. Control plane `EnsureSessionAgent` finds the existing workstation record by `instance_id` or `hostname + email`, appends the tool name (`app_id`) to `master.Subagents`, and binds the session without creating a new agent card.

---

### 5. Verification Matrix

| Verification Dimension | Test Target | Result | Evidence |
|---|---|---|---|
| Master Enrollment | `tests/test_workstation_session_svid.py` | **PASS** | `inst-test-ws-001` enrolled via mock `credentials.json` |
| Session SVID Format | `tests/test_workstation_session_svid.py` | **PASS** | Validated `spiffe://bap.internal/workstation/inst-test-ws-001/session/sess-claude-svid-test` |
| Zero Sprawl in `s.agents` | `tests/test_workstation_session_svid.py` | **PASS** | `len(data["agents"]) == 1` with `subagents: ["claude-code", "python-agent"]` |
| Session Termination | `tests/test_workstation_session_svid.py` | **PASS** | Clean closure to `status: "closed"`; master workstation remains active |
| Regression Test Suite | `python -m unittest discover tests` | **PASS** | 261/261 tests passed in 223.7s |

---

### 6. Review Cadence
This architecture decision record is effective immediately and governs all agent launchers, IDE plugins, CLI interceptors, and SDK clients across BAP v1.9.3+.
