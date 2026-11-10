# Complete Network and Control Channel Architecture (BAP-912)

This document formalizes the complete network, communication, and control channel architecture across all subsystems of the **Bounded Authority Plane (BAP)**. It addresses security review requirements by providing verifiable channel topologies, dataflow paths, encryption mechanisms, authentication invariants, failure modes, revocation procedures, and restart semantics.

---

## 1. System Architecture Topology

```mermaid
flowchart TB
    subgraph Workstation["Customer Workstation / Edge Perimeter"]
        subgraph InHarness["Layer 1: Execution Surface"]
            CC["Claude Code / Copilot / Antigravity / Codex"]
            HW["HookWatch / Native Plugins\n(plugins/claude, plugins/copilot)"]
        end

        subgraph LocalRuntime["Layer 2: Edge Runtime & Sandbox"]
            BE["bapedge.exe\n(Agent Runtime Daemon)"]
            PEP1["Local Cedar PEP\n(In-Memory Evaluation)"]
            BRK["bapedge exec\n(Execution Broker)"]
            SBX["Kernel Sandbox\n(Windows Job Object / Landlock LSM)"]
            WATCH["bapedge watch\n(Heartbeat & Anomaly Watchdog)"]
        end
    end

    subgraph ControlPlane["BAP Central Control Plane (Decision Plane)"]
        CP_API["Control Plane API\n(bapcontrolplane)"]
        STS["RFC 8693 STS Engine\n(/api/v1/sts/token)"]
        AUDIT["Immutable Audit Ledger\n(Cryptographic Hash Chaining)"]
        POL_STORE["Central Policy Store\n(Signed JWS Distribution)"]
    end

    subgraph EnterpriseInfra["Enterprise Trust & Identity Infrastructure"]
        IDP["Enterprise IdP\n(Entra ID / Okta / GitHub OIDC)"]
        SPIFFE["SPIFFE Workload CA\n(Hierarchical SVID Minting)"]
    end

    subgraph TargetSystems["Downstream Target Systems (Resource Side)"]
        GW["BAP Gateway PEP\n(bapgateway.exe)"]
        SAAS["Target SaaS APIs\n(GitHub, AWS, Jira, Salesforce)"]
        TARGET_DB["Protected Production Resources"]
    end

    subgraph AdminPlane["Administrative Observability Plane"]
        COCKPIT["Agent Watch V3 Cockpit\n(v3.html / Dashboard UI)"]
        SIEM["Enterprise SOC / SIEM\n(ArcSight CEF / RFC 5424)"]
    end

    %% Communication Channels
    CC -->|CH-01: Local IPC| HW
    HW -->|CH-01: stdio / Pipe| BE
    BE <-->|In-Memory| PEP1
    BE -->|CH-07: Broker Fork| BRK
    BRK -->|Process Sandbox| SBX
    
    BE <-->|CH-02: HTTPS REST / TLS 1.3| CP_API
    POL_STORE -->|CH-03: HTTPS SSE / JWS| BE
    BE <-->|CH-04: RFC 8693 STS / TLS 1.3| STS
    WATCH -->|CH-02: Telemetry Spool| CP_API
    
    CP_API <-->|CH-05: RFC 8628 Device Flow| IDP
    CP_API <-->|SPIFFE Workload Attestation| SPIFFE
    
    STS -->|CH-06: ID-JAG / Ephemeral Token| SAAS
    BRK -->|CH-06: Governed Egress via PEP| GW
    GW -->|Authorized Target Invocation| TARGET_DB

    COCKPIT <-->|CH-08: Admin HTTPS / TLS 1.3| CP_API
    AUDIT -->|RFC 5424 Syslog Export| SIEM
```

---

## 2. Channel Communication Sequence Matrix

The following sequence details an agent task execution from declared prompt to target resource access:

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / Human Owner
    participant Agent as Claude Code / Copilot
    participant HW as HookWatch / Native Plugin
    participant Edge as bapedge (Agent Runtime)
    participant CP as Control Plane (Decision Plane)
    participant STS as RFC 8693 STS Broker
    participant Target as Target SaaS / Resource

    Dev->>Agent: "Create PR for authentication fix"
    Agent->>HW: Prompt / Tool Hook (PreToolUse)
    HW->>Edge: CH-01: Intercept tool request (Local IPC)
    
    alt Session Not Enrolled
        Edge->>CP: CH-02: EnsureSessionStarted (HTTPS REST)
        CP-->>Edge: Issue Session SVID & Agent Principal (BAP-911)
    end

    Edge->>Edge: Evaluate Local Cedar PEP (Inviolable Invariants)
    
    opt Target SaaS Credential Required
        Edge->>STS: CH-04: RFC 8693 Token Exchange (Session SVID)
        STS->>CP: Verify Session Liveness & Monotonic Attenuation
        STS->>Target: CH-06: Exchange Brokered JIT Grant (5-min TTL)
        Target-->>STS: Ephemeral Access Token (saas-github-*)
        STS-->>Edge: Bound Saas Token (never exposed to Agent LLM)
    end

    Edge->>Edge: CH-07: bapedge exec spawns isolated child process
    Edge-->>HW: Allow Execution Receipt
    HW-->>Agent: Permitted Tool Output
    Edge->>CP: CH-02: Stream Tamper-Proof Audit Receipt
```

---

## 3. Machine-Readable Channel Inventory Summary

| Channel ID | Subsystem Path | Protocol & Auth | Encryption | Failure Mode | Revocation & Restart |
|---|---|---|---|---|---|
| **CH-01** | HookWatch $\rightarrow$ Edge Runtime | Local IPC / Parent PID Verification | OS Memory Isolation | Fail-Closed | Immediate tool denial; re-attest on next lifecycle event. |
| **CH-02** | Edge Runtime $\rightarrow$ Control Plane API | HTTPS REST / Session Token | TLS 1.3 Pinning | Fail-Safe Cached (15-min TTL) | SSE disconnect freezes endpoint; re-verify enrollment. |
| **CH-03** | Control Plane $\rightarrow$ Edge Runtime | Server-Sent Events / JWS Signing | TLS 1.3 + RFC 7515 JWS | Fail-Safe Cached | Instant sub-second kill switch; exponential backoff reconnect. |
| **CH-04** | Edge Runtime $\rightarrow$ STS Token Service | RFC 8693 Token Exchange / SVID | TLS 1.3 | Fail-Closed | Atomic grant burn (`BurnGrantOnce`); re-attest session. |
| **CH-05** | Control Plane $\rightarrow$ Enterprise IdP | RFC 8628 Device Flow / OIDC | TLS 1.3 | Fail-Closed | Central IdP logout propagates kill; re-prompt device flow. |
| **CH-06** | Control Plane STS $\rightarrow$ Target SaaS | HTTPS REST / ID-JAG Exchanged Token | TLS 1.3 | Fail-Closed | Ephemeral grant expires in 300s; target token revoked. |
| **CH-07** | Broker $\rightarrow$ Local Sandbox Process | Windows Job Object / Landlock LSM | Kernel Virtualization | Fail-Closed | SIGKILL process tree; re-evaluate policy on next attempt. |
| **CH-08** | Cockpit UI $\rightarrow$ Control Plane API | HTTPS WebSockets / Admin Token | TLS 1.3 + CORS Origin Guard | Fail-Closed | Immediate session freeze; re-authenticate admin token. |

---

## 4. Architectural Invariants for Security Reviewers

1. **Separation of Decision and Execution**: The Control Plane makes policy decisions and notarizes audit events. It **never** executes commands directly on developer workstations and **never** retains raw customer target secrets.
2. **Zero Standing Privileges (ZSP)**: No long-lived downstream API keys are stored on developer endpoints. Target tokens are minted just-in-time with a maximum 5-minute lifespan and bound strictly to the specific `AgentPrincipal` and `SessionID`.
3. **Fail-Closed by Design**: If an agent attempts an action during a network partition that requires central elevation or approval, execution is strictly halted. Low-risk in-workspace developer actions continue under valid cached local Cedar bundles.
4. **Machine-Readable Audit Trail**: The full inventory is validated against `docs/control_channels.json`.
