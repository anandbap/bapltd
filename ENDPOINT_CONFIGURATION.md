# Central Endpoint Configuration Guide: Connecting Developer Laptops to Corporate BAP

## 1. Overview: The Single Source of Truth

In a corporate rollout, the **BAP Control Plane (`bapcontrolplane`)** runs centrally on your enterprise network (e.g. `https://bap-controlplane.corp.internal:8080` or a corporate Kubernetes cluster / VM), while **Claude Code, GitHub Copilot, and Python AI agents** run distributed across hundreds of developer laptops.

To make laptop configuration effortless, BAP provides **a single, simple place** for all hosts and endpoints:

```
┌────────────────────────────────────────────────────────────────────────┐
│               CENTRAL CONFIGURATION FILE: bap-config.json              │
├────────────────────────────────────────────────────────────────────────┤
│ {                                                                      │
│   "controlplane_url": "https://bap-controlplane.corp.internal:8080",    │
│   "gateway_url":      "https://bap-gateway.corp.internal:9090",         │
│   "envoy_url":        "https://bap-envoy.corp.internal:10000",          │
│   "trust_domain":     "bap.corp.internal",                             │
│   "environment":      "production",                                    │
│   "capture_user_prompt": false                                           │
│ }                                                                      │
└────────────────────────────────────────────────────────────────────────┘
                                    │
       ┌────────────────────────────┼────────────────────────────┐
       ▼                            ▼                            ▼
 [Claude Code]               [GitHub Copilot]              [Python SDK]
 (cchook -> bapedge)       (copilot -> bapedge)        (bap_sdk / agents)
       │                            │                            │
       └────────────────────────────┼────────────────────────────┘
                                    ▼
           [Central Corporate BAP Control Plane on Port 8080]
              (Fleet Radar, Agent Registry, Telemetry Stream)
```

`capture_user_prompt` controls raw Claude prompt persistence and transmission. Intent classification remains mandatory and uses `UNKNOWN` when the prompt cannot be classified. The environment variable `BAP_CAPTURE_USER_PROMPT` overrides the file for managed endpoint deployment.

---

## 2. The 4 Configuration Locations (Priority Order)

Every BAP component (`bapedge`, `cchook`, `bap-sdk`, `bapgateway`, demo scripts) resolves endpoints automatically using this hierarchy:

| Priority | Location | Best Used For |
| :---: | :--- | :--- |
| **1 (Highest)** | **Environment Variable (`BAP_SERVER_URL`)** | CI/CD pipelines, containerized test runners, and ephemeral developer shells. |
| **2** | **Project Root (`./bap-config.json`)** | Teams that check corporate endpoints into git repositories so every repo clone connects automatically. |
| **3** | **User Profile (`~/.bap/config.json`)** | Developers working across multiple repositories on their corporate laptops. |
| **4** | **System-Wide Managed (`%PROGRAMDATA%\BAP\config.json`)** | **Enterprise IT / MDM / InTune deployment** — pre-configured system-wide so developers don't have to configure anything. |
| **2** | **Project Root (`./bap-config.json` or `.bap/config.json`)** | Teams that check corporate endpoints into git repositories so every repo clone connects automatically. |
| **3** | **User Profile (`~/.bap/config.json` or `~/.bapstate/config.json`)** | Developers working across multiple repositories on their corporate laptops. |
| **4** | **System-Wide Managed (`%PROGRAMDATA%\BAP\config.json` or `/etc/bap/config.json`)** | **Enterprise IT / MDM / InTune deployment** — pre-configured system-wide so developers don't have to configure anything. |
| **5 (Cascade Discovery)**| **Cloud Render & Local Cascade** | Automatic fallback discovery with 30s cold-start budget when unconfigured. |

---

## 2.1 First-Time Startup: Cascading Discovery, 30s Cold-Start Budget & Fail-Closed Enforcement

When `bapedge` boots on a fresh workstation without explicit configuration, it executes an automated zero-trust discovery cascade:

1. **Primary Option: Cloud Control Plane (`https://bap-controlplane.onrender.com`)**
   - Free-tier or cloud-hosted containers enter sleep when idle. To accommodate cold starts, `bapedge` allocates a **30-second budget**:
     - **Attempt 1**: Initial probe against `/health` with a 12-second socket timeout.
     - **Sleep (15s)**: If Attempt 1 fails, `bapedge` sleeps 15 seconds to allow the remote container to spin up.
     - **Attempt 2**: Second probe with a 15-second socket timeout.
2. **Secondary Option: Local Enterprise HTTPS (`https://localhost:8443` and `https://127.0.0.1:8443`)**
   - If the remote cloud instance does not answer within 30 seconds, `bapedge` probes the local secure TLS control plane.
3. **Tertiary Option: Local HTTP (`http://localhost:8080` and `http://127.0.0.1:8080`)**
   - Standard local development control plane.

### Fail-Closed Enforcement vs. Degraded Mode
- **Policy Sync & Online Mode**:
  As soon as any control plane in the cascade answers, `bapedge` downloads and cryptographically verifies the latest `policy.cedar` bundle and stores it in the authoritative state directory (`.bapstate/policy/policy.cedar`).
- **Degraded Mode (Offline Enforcing)**:
  If all control plane options in the cascade are unreachable after the 30-second budget, but a local `policy.cedar` exists in `.bapstate/policy/` or workspace search paths, `bapedge` enters **Degraded Mode**:
  - Full Cedar security invariants remain strictly enforced offline.
  - Audit records are spooled locally to `.bapstate/audit.jsonl` for automatic flush upon reconnect.
- **Fail-Closed Guarantee**:
  If all control planes in the cascade fail AND no local `policy.cedar` exists, `bapedge` **FAILS CLOSED** with error `ErrNoPolicyAvailable` (`policy.cedar not available`). `bapedge` **REFUSES TO START OR EXECUTE COMMANDS** without policy invariants.

---

## 2.2 Caller Lineage Attestation: Agent Process Originates State

In the BAP zero-trust architecture, `bapedge` is a stateless execution broker. Commands and tool executions originate from agent binaries (`a.exe`, `claude.exe`, `antigravity.exe`, `copilot.exe`).

- **Caller Lineage Inspection**:
  When `cchook` or another tool hook intercepts an action, it queries the operating system kernel (`QueryFullProcessImageNameW` on Windows via `PROCESS_QUERY_LIMITED_INFORMATION`, `/proc/<pid>/exe` on Linux) to identify the parent process.
- **Cryptographic Workload Fingerprint**:
  The interceptor reads the calling executable binary directly from disk, computes its SHA-256 hash (`sha256:...`), derives the calling `AppID`, and forwards the caller context to `bapedge exec` via `--caller-binary`, `--caller-hash`, and `BAP_CALLER_*` environment variables.
- **Execution Receipt Immutability**:
  Every executed command produces an immutable cryptographic `ExecutionReceipt` containing:
  - `caller_binary`: Full absolute path of the calling agent (e.g. `C:\Program Files\Claude\claude.exe`)
  - `caller_hash`: Cryptographic SHA-256 of the binary image
  - `parent_pid`: OS process ID of the calling agent
  - `identity`: Derived SPIFFE workload identity (e.g. `spiffe://bap.local/agent/claude-code`)

### Locked mode (production): the managed config always wins

The table above is the **development** order. In production the system-wide managed config can be made authoritative. Add `"lock_endpoints": true` (or set `"environment": "production"`) to the managed file:

```json
{
  "controlplane_url": "https://bap-controlplane.corp.internal:8443",
  "gateway_url": "https://bap-gateway.corp.internal:9090",
  "environment": "production",
  "lock_endpoints": true,
  "enforcement_mode": "enforce"
}
```

When a managed config is locked:

- It is the **only** source. Environment variables, project `bap-config.json`, and user `~/.bap/config.json` are ignored for endpoints **and** for `enforcement_mode`, so a local setting cannot switch a laptop to non-blocking audit mode.
- There is **no localhost fallback**. If the central server is unreachable, `bapedge` keeps enforcing its cached local policy and queues audit records for later sync; it never contacts a local stand-in server.
- `bapedge config set` refuses to write, because the result would be ignored. `bapedge config show` reports `Endpoint Lock: LOCKED`.
- **Deployment requirement:** the managed folder (`%PROGRAMDATA%\BAP` or `/etc/bap`) must be writable by administrators only. Create it with that ACL (via Intune, Group Policy or your configuration manager) before distributing the config; otherwise a standard user could create their own "managed" file.

Machines with no managed config, or one that is not locked, keep the development behaviour described above.

#### Break-glass override (administrators only, time-boxed)

For an extreme situation (for example, a prolonged central outage), an administrator can place `breakglass.json` **in the managed folder** to point a machine at a different control plane temporarily:

```json
{
  "controlplane_url": "http://localhost:8080",
  "operator": "alice.admin",
  "reason": "Central outage INC-1234",
  "expires_at": "2026-10-24T09:00:00Z"
}
```

- Only the managed folder is read. A `breakglass.json` in a project, home directory, or via an environment variable is never honoured.
- `operator` and `reason` are required, and `expires_at` must be in the future and **no more than 24 hours ahead**; otherwise the file is ignored.
- While active, `bapedge config show` prints `Override: BREAK-GLASS ACTIVE until ... by ...: ...`. Remove the file to end it early.

---

## 3. How to Configure Endpoints (Choose Your Method)

### Method A: One-Click Helper Script (Interactive or Scripted)

#### On Windows (Command Prompt / PowerShell):
```cmd
:: Interactive mode (prompts for corporate URL):
configure_endpoints.bat

:: Direct command line (corporate endpoints):
configure_endpoints.bat https://bap-controlplane.corp.internal:8080 https://bap-gateway.corp.internal:9090

:: Reset to local standalone / offline demo mode:
configure_endpoints.bat http://localhost:8080 http://localhost:9090
```

#### PowerShell:
```powershell
# Set for current workspace:
.\configure_endpoints.ps1 -ControlPlane "https://bap-controlplane.corp.internal:8080"

# Or set globally for all projects on this laptop:
.\configure_endpoints.ps1 -ControlPlane "https://bap-controlplane.corp.internal:8080" -Global
```

---

### Method B: Using the `bapedge` CLI

```bash
# 1. Inspect active endpoints and which configuration source is in effect:
bapedge config show

# 2. Update endpoints in current project:
bapedge config set --server https://bap-controlplane.corp.internal:8080 --gateway https://bap-gateway.corp.internal:9090

# 3. Update endpoints globally for all projects on this machine:
bapedge config set --server https://bap-controlplane.corp.internal:8080 --global
```

#### Example Output of `bapedge config show`:
```text
===============================================================================
   BAP (Bounded Authority Plane) - Central Endpoint Configuration
===============================================================================
Control Plane Host (bapcontrolplane) : https://bap-controlplane.corp.internal:8080
API Gateway PEP (bapgateway / Envoy) : https://bap-gateway.corp.internal:9090
Envoy Container Gateway              : https://bap-envoy.corp.internal:10000
SPIFFE Trust Domain                  : bap.corp.internal
Active Environment                   : production
Resolved From Source                 : C:\Users\User\pyprj\bapltd\bap-config.json
===============================================================================
```

---

### Method C: Enterprise IT / MDM Fleet Deployment (Zero-Touch for Developers)

To configure BAP across thousands of corporate laptops without developer action, distribute the configuration file via Microsoft InTune, Puppet, Ansible, or Group Policy:

#### On Windows:
Deploy `config.json` to:
`%PROGRAMDATA%\BAP\config.json` (typically `C:\ProgramData\BAP\config.json`)

```json
{
  "controlplane_url": "https://bap-controlplane.corp.internal:8080",
  "gateway_url": "https://bap-gateway.corp.internal:9090",
  "envoy_url": "https://bap-envoy.corp.internal:10000",
  "trust_domain": "bap.corp.internal",
  "environment": "production"
}
```

#### On Linux / macOS:
Deploy to:
`/etc/bap/config.json`

Once deployed, any Claude Code invocation on the laptop will automatically discover the central corporate server and stream telemetry in real time.

---

## 4. Verification: How Each Component Uses the Central Config

### 1. Claude Code
When a developer prompts Claude Code (`claude` or `claude-code.cmd`):
1. Claude Code invokes `cchook/interceptor.exe`.
2. `interceptor.exe` invokes `bapedge exec`.
3. `bapedge exec` resolves `controlplane_url` from `bap-config.json`.
4. Telemetry is streamed to `https://bap-controlplane.corp.internal:8080/api/v1/audit/ingest`.
5. The central corporate **Activity Inspector & Live Radar** immediately registers the session and shows active tool usage.

### 2. Python AI Agents (`bap-sdk`)
Python developers do not need to hardcode URLs:
```python
from bap_sdk import BAPSession

# Automatically connects to controlplane_url configured in bap-config.json!
with BAPSession(app_id="financial-analytics") as bap:
    # Ephemeral BAP Grant acquired from corporate control plane:
    token = bap.acquire_grant(scopes=["api:read"])
    print("Corporate Grant:", token)
```

### 3. API Gateway PEP (`bapgateway` or `envoy`)
The Gateway PEP reads `controlplane_url` from `bap-config.json` by default. When agents present grants, the Gateway calls the central control plane at `/api/v1/grants/consume` to validate and burn the token.

---

## 5. Summary

- **Simple File**: `bap-config.json` in project root or `~/.bap/config.json` in user home.
- **One Command**: `bapedge config set --server <url>` or `configure_endpoints.bat <url>`.
- **Zero Friction**: Developers never edit code or batch scripts to point Claude Code to the central corporate control plane.
