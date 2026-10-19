# Architecture Decision Record (ADR-004)
## BAP-704: Enterprise IAM Federation, JWS Signing & Trust-Store Fallback Strategy

**Status:** Approved  
**Date:** 2026-10-19  
**Deciders:** Enterprise Security Architecture Board, BAP Engineering Lead  
**Technical Area:** Workload Identity, OAuth 2.0 Token Exchange, Enterprise IdP Federation  

---

### 1. Context and Problem Statement
Autonomous AI agents require distinct, auditable workload identities and bounded, single-use downstream authorization without human credential sharing or long-lived static secrets. However, enterprise-wide IAM dependencies (e.g. centralized corporate JWKS distribution, SPIRE server federation, Okta/Entra agent federation) often lag fast-moving AI pilot initiatives. 

If agent onboarding blocks entirely on centralized IAM deployment, developer velocity halts, encouraging shadow AI and bypasses. Conversely, if agents use unmanaged static API tokens, enterprise security is fundamentally undermined.

### 2. Evaluated Options
1. **Option A (Full Enterprise IdP Coupling):** Block all agent execution until central Okta / Entra Workload Identity federation is fully deployed.
2. **Option B (Third-Party Identity Broker):** Procure external managed agent identity SaaS (e.g. WorkOS / Keycard / Auth0 Workload Identity).
3. **Option C (Pragmatic Tiered Fallback — Chosen):**
   - **Internal Baseline:** BAP Control Plane operates as an authoritative local SPIFFE CA (`spiffe://bap.internal/...`) and RFC 7515 JWS notary with JWKS publishing (`/.well-known/jwks.json`).
   - **Gateway Brokering:** BAP Gateway PEP performs RFC 8693 single-use grant exchange for downstream services.
   - **Tiered Onboarding:** Low/Medium-risk agents onboard immediately using the BAP internal trust store; High/Critical-risk agents require formal corporate PKI / IdP federation gates.
   - **Fail-Closed Fallback:** Offline or disconnected agents cannot obtain production tokens; fallback strictly restricts agents to local read-only actions.

### 3. Decision Drivers & Architecture Invariants
- **Zero Standing Privileges (ZSP):** No agent receives persistent bearer credentials. Grants are single-use (`maxUses=1`) with a 5-minute maximum TTL.
- **Independence from LLM Outputs:** Self-reported prompt strings or agent claims are never accepted as authorization context.
- **Fail-Closed Isolation:** If identity verification fails or federation endpoints are unreachable, sensitive downstream operations strictly fail-closed (`DENY`).
- **No Shadow IAM:** BAP's internal trust store maps cleanly to corporate SPIFFE namespaces and exports signed JWS assertion tokens conforming to standard RFC 7515 / RFC 7517 specifications.

### 4. Risk Mitigation & Fallback Matrix

| Agent Risk Tier | Environment | Permitted Identity Model | Fallback Behavior on Disconnect |
|---|---|---|---|
| **Tier 1 (Low)** | Dev / Local | Local BAP SPIFFE SVID + Edge Cache | Permitted offline local read operations only. |
| **Tier 2 (Medium)** | Dev / Workspace | Local BAP SPIFFE SVID + Job Sandbox | Local workspace mutation permitted; network egress denied. |
| **Tier 3 (High)** | Staging / Egress | BAP Control Plane JWS Token Exchange | Blocked on disconnect; requires active Control Plane validation. |
| **Tier 4 (Critical)** | Production | Mandatory Enterprise IdP / Hardware SVID | Blocked; strictly requires live dual-custody HITL + mTLS verification. |

### 5. Review and Expiry Cadence
This ADR and the interim internal JWS trust-store implementation will be reviewed on a quarterly cadence or upon corporate enterprise PKI availability.
