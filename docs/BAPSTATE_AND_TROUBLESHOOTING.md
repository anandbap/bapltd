# BAP State Directory (`.bapstate`) & Troubleshooting Guide

This guide covers the **Unified `.bapstate` Architecture**, day-to-day CLI command operations, and comprehensive troubleshooting playbooks across all BAP Zero-Trust modules.

---

## 1. Unified State Directory (`.bapstate`) Architecture

Historically, runtime artifacts (credentials, policy bundles, session markers, and audit logs) were scattered across multiple disparate locations (`~/.ltd`, `.bap/`, and local working directory `ltd-audit.jsonl`). 

All BAP modules (`bap-edge`, `bap-controlplane`, `bap-gateway`, and the Python SDK) now standardize on a single, clean directory: **`.bapstate`**.

### Discovery & Resolution Precedence

When any BAP module initializes, it resolves the active `.bapstate` directory using the following strict precedence:

1. **Environment Variable Override (`BAP_STATE_DIR`)**:
   - If set, BAP strictly uses the specified directory path.
   - *Use Case*: Isolated CI/CD test runners, multi-tenant developer environments, or automated sandbox execution.
2. **User Home Directory (`~/.bapstate`)**:
   - If `~/.bapstate` exists in the user's home directory (`$HOME/.bapstate` on Linux/macOS, `%USERPROFILE%\.bapstate` on Windows), it is used as the global developer state directory.
3. **Current Working Directory (`./.bapstate`)**:
   - If `./.bapstate` exists in the active workspace root, it is used for local workspace isolation.
4. **Default Order**:
   - In standard operation, BAP creates and initializes `~/.bapstate`.
   - If the user's home directory is read-only or unavailable (e.g. restricted containers or ephemeral sandboxes), BAP automatically falls back to `./.bapstate` in the current working directory.

### Directory Layout

```text
.bapstate/
├── audit.jsonl             # Append-only SHA-256 hash-chained audit & offline resilience spool
├── credentials.json        # Enrolled agent identity, session tokens, SPIFFE ID, OIDC/OTC claims
├── config.json             # Central endpoints (control plane URL, gateway PEP, Envoy proxy)
├── policy/                 # Cached Cedar policy bundle
│   ├── policy.cedar        # Authoritative Cedar policy rules
│   ├── schema.json         # Cedar entity schema
│   └── policy-state.json   # Policy version, rules digest, kill-switch flag, and revoked sessions
├── sessions/               # Active session and process tracking
│   ├── pid-<pid>.json      # Per-PID process tracking markers
│   ├── <hash>.json         # Isolated per-session metadata markers
│   └── session.json        # Primary workspace active session fallback
├── prompts/                # Captured prompt hash caches and semantic classifications
├── revoked.json            # Emergency local revocation cache
└── risk_state.json         # Local anomaly detection and risk-scoring telemetry
```

### Automatic Backward Compatibility & Legacy Migration

BAP includes automated migration logic (`state.MigrateLegacy()`):
- **Credentials**: Automatically detects historical `~/.ltd/credentials.json` and copies it into `.bapstate/credentials.json`.
- **Policy Cache**: Automatically migrates `~/.ltd/policy/` into `.bapstate/policy/`.
- **Session & Prompts**: Automatically migrates historical `.bap/sessions/` and `.bap/prompts/` into `.bapstate/`.
- **Audit Spool**: If `.bapstate/audit.jsonl` does not exist, any existing `ltd-audit.jsonl` in the workspace is seamlessly ingested and preserved.
- **Environment Overrides**: If `BAP_CREDENTIALS`, `BAP_CONFIG`, `BAP_AUDIT_LOG`, or `LTD_AUDIT_LOG` are explicitly set, they continue to take precedence.

---

## 2. CLI Command Operations Reference

All commands are executed using the unified edge daemon binary `bapedge` (or `bapedge.exe` on Windows).

### 2.1 `bapedge status`
Inspects developer workstation health, authentication claims, active agent sessions, policy bundle version, layer compliance, and audit spool backlog.

```bash
bapedge status
```

**Key Fields in Output**:
- **Control Plane**: URL of central policy server (e.g. `https://bap-controlplane.onrender.com`).
- **State Directory**: Path to active `.bapstate` directory (e.g. `C:\Users\User\.bapstate`).
- **Auth Mode**: Authentication mechanism (`One-Time Code (OTC)` or `OIDC Federated (Entra/Okta)`).
- **Active Sessions**: Lists running agent processes, PIDs, uptime, and flags dead/orphaned processes.
- **Policy Bundle**: Version number, rules SHA-256 digest, and emergency kill-switch status.
- **3-Tier Layers**: Status of Process Interception (Layer A), Kernel Sandbox (Layer B), and Gateway Egress (Layer C).
- **Spool Backlog**: Count of offline audit entries awaiting transmission to the central control plane.

---

### 2.2 `bapedge sweep`
Executes crash recovery and garbage collection routines:
1. Scans `.bapstate/sessions/` and detects orphaned session markers where the agent process died.
2. Informs the Central Control Plane to close abandoned sessions and reclaim idle resources.
3. Purges stale PID locks and abandoned temporary files.
4. Flushes the offline audit backlog (`.bapstate/audit.jsonl`) in batched chunks to the central ledger.
5. Verifies the workstation is in a clean state to rejoin the fleet.

```bash
# Standard sweep (cleans dead processes and flushes spool)
bapedge sweep

# Force sweep (purges all session markers regardless of PID status)
bapedge sweep --force
```

---

### 2.3 `bapedge login` & `bapedge register`
Authenticates and enrolls the developer workstation.

- **OIDC Corporate Login (Recommended)**: Initiates RFC 8628 Device Flow with Microsoft Entra ID or Okta MFA:
  ```bash
  bapedge login
  ```
  Follow the on-screen browser URL and enter the verification code. Credentials are automatically saved to `.bapstate/credentials.json`.

- **One-Time Code (OTC) Registration**: Used for automated provisioning, dev mode, or CI/CD pipelines:
  ```bash
  # Production enrollment with admin-issued OTC:
  bapedge register --server https://bap-controlplane.onrender.com --code BAP-FLEET-XXXX

  # Self-service development enrollment (dev environments only):
  bapedge register --server https://bap-controlplane.onrender.com --dev
  ```

---

### 2.4 `bapedge why "<command>"`
Evaluates any shell command or tool call against active Cedar policies in real time and explains the authorization decision directly in the terminal without executing the command:

```bash
bapedge why "git status"
bapedge why "rm -rf /"
bapedge why "curl http://169.254.169.254/latest/meta-data/"
```

**Output**: Reports decision (`ALLOW` / `DENY`), matched Cedar policy IDs, and the exact invariant triggered.

---

### 2.5 `bapedge exec -- <command>`
Executes a command through the complete BAP Zero-Trust pipeline:
1. Intercepts arguments and evaluates against local cached Cedar policies (Layer A).
2. Spawns process inside an OS kernel-isolated sandbox (Layer B: Windows Restricted Token / Linux Landlock / macOS sandbox-exec).
3. Injects corporate on-behalf-of identity credentials.
4. Appends tamper-evident SHA-256 hash-chained entry to `.bapstate/audit.jsonl` and streams telemetry to control plane.

```bash
bapedge exec -- git commit -m "Update"
bapedge exec --source=claude-code -- python run_analysis.py
```

---

### 2.6 `bapedge verify-log`
Validates the local cryptographic Merkle chain in `.bapstate/audit.jsonl`. Recalculates every SHA-256 hash $H_n = \text{SHA256}(H_{n-1} \parallel \text{EventData})$ sequentially from genesis:

```bash
bapedge verify-log
```

**Output**:
- `[+] SUCCESS: Audit log is cryptographically valid! (X entries verified, 0 tampering detected)`
- If any line or byte has been altered, the exact line number and hash mismatch are reported.

---

### 2.7 `bapedge endpoints`
Displays all configured central endpoints and indicates whether they were resolved from environment variables, `.bapstate/config.json`, or `.bapstate/credentials.json`.

```bash
bapedge endpoints
```

---

## 3. Comprehensive Troubleshooting Playbooks

### Playbook 1: Spool Backlog Not Flushing (`bapedge sweep` reports 0 flushed or errors)

**Symptom**:
`bapedge status` reports:
```text
Spool Backlog: 2815 un-flushed entries pending network reconnection in .bapstate/audit.jsonl
```
Running `bapedge sweep` shows `Flushed 0 offline audit records` or an HTTP notice.

**Root Causes**:
1. **Edge WAF Rejections (HTTP 403 Forbidden)**:
   - Security audit logs often record denied attacker commands (e.g. `| curl http://...`, SQL injections, or SSRF metadata probes).
   - When transmitted across the public internet to cloud hosts (Render, Cloudflare, AWS), upstream Web Application Firewalls (WAF) inspect POST payloads and block requests matching command injection rules.
2. **Monolithic Payload Timeouts**:
   - Transmitting thousands of entries in a single HTTP request exceeds edge timeouts (> 5s).
3. **Control Plane Cold Start**:
   - Free/starter tier cloud instances (e.g. Render) spin down on inactivity and take 30–60 seconds to spin up.

**Resolution Steps**:
1. Run `bapedge sweep`. BAP automatically defangs shell pipe triggers (`| [curl] http`) and partitions entries into atomic 50-event batches.
2. Verify control plane health:
   ```powershell
   curl.exe -I https://bap-controlplane.onrender.com/health
   ```
   Ensure it returns `HTTP 200 OK`.
3. If an individual corrupted entry is stuck, you can inspect `.bapstate/audit.jsonl`:
   ```powershell
   Get-Content "$HOME\.bapstate\audit.jsonl" | Select-Object -First 5
   ```
4. Once flushed, confirm the backlog is clear:
   ```bash
   bapedge status
   ```

---

### Playbook 2: Orphaned / Stale Agent Sessions

**Symptom**:
`bapedge status` reports:
```text
• [ORPHANED/STALE (Process Dead)] Session: sess-claude-123 App: claude-code PID: 8492 Uptime: 3h 12m
⚠️ Notice: Found 1 orphaned session(s). Run 'bapedge sweep' to clean stale state.
```

**Root Cause**:
The agent terminal was closed abruptly (e.g. window closed, terminal killed with `Ctrl+C` or `taskkill`), leaving a session marker in `.bapstate/sessions/` while the control plane still registers the session as open.

**Resolution Steps**:
1. Run `bapedge sweep`:
   ```bash
   bapedge sweep
   ```
2. The sweep reconciler checks the operating system PID table, detects that PID 8492 is dead, deletes the stale marker from `.bapstate/sessions/`, and sends an authenticated crash recovery heartbeat to the Control Plane to close the remote session.
3. Verify status:
   ```bash
   bapedge status
   ```
   Output will confirm `(No local agent sessions currently active)`.

---

### Playbook 3: "Operation Not Permitted" on macOS or Linux

**Symptom**:
Executing `bapedge` returns `fork/exec: operation not permitted` or macOS Gatekeeper blocks execution.

**Root Cause**:
- On macOS, binaries downloaded from browsers or untrusted networks are tagged with the `com.apple.quarantine` extended attribute.
- On Linux/macOS, the binary may lack POSIX execute bits (`+x`).

**Resolution Steps**:
- **macOS**: Clear Gatekeeper quarantine and grant execute permission:
  ```bash
  xattr -d com.apple.quarantine ./bapedge
  chmod +x ./bapedge
  ```
- **Linux**: Grant execute permissions and ensure kernel Landlock is enabled:
  ```bash
  chmod +x ./bapedge
  # Verify Landlock support (kernel 5.13+):
  uname -r
  ```
- **Windows**: If execution is blocked by PowerShell execution policies:
  ```powershell
  Unblock-File .\bapedge.exe
  ```

---

### Playbook 4: Emergency Kill-Switch Activated or Outdated Policy

**Symptom**:
`bapedge exec` rejects all commands with:
```text
emergency kill-switch is active; all executions are blocked
```

**Root Cause**:
The CISO administrator activated the global fleet kill-switch (`kill_switch: true`), which was synchronized to `.bapstate/policy/policy-state.json`.

**Resolution Steps**:
1. Inspect the local policy state:
   ```powershell
   Get-Content "$HOME\.bapstate\policy\policy-state.json"
   ```
2. If the kill-switch was deactivated on the central server, sync the latest policy bundle:
   ```bash
   bapedge sweep
   ```
3. Check `bapedge status` to confirm `Kill Switch: false` and review the new rules digest.

---

### Playbook 5: Cryptographic Chain Tampering Detected

**Symptom**:
`bapedge verify-log` outputs:
```text
[-] TAMPER DETECTED: hash mismatch at index 42: entry_hash != computed
[-] INTEGRITY FAILURE: Log file has been altered.
```

**Root Cause**:
Lines in `.bapstate/audit.jsonl` were manually edited, deleted, reordered, or partially overwritten by an unauthorized editor.

**Resolution Steps**:
1. Never edit `.bapstate/audit.jsonl` with standard text editors.
2. The index reported (e.g. index 42) indicates the exact zero-based entry where the Merkle chain broke.
3. Compare the local receipt hash with the Central Control Plane ledger:
   ```powershell
   Invoke-RestMethod -Uri "https://bap-controlplane.onrender.com/api/v1/control/chain/verify"
   ```
4. If local corruption cannot be restored, backup the damaged file and run `bapedge sweep` to regenerate a clean local genesis block.

---

### Playbook 6: Overriding State Locations for Testing & Multi-Tenant CI

To run BAP in an isolated environment without affecting the user's primary `~/.bapstate`:

```bash
# Set a custom isolated directory:
export BAP_STATE_DIR=/tmp/bap-test-state
# Or on Windows PowerShell:
$env:BAP_STATE_DIR = "C:\temp\bap-test-state"

# Run any BAP command in full isolation:
bapedge status
bapedge exec -- git status
```

All credentials, logs, policy bundles, and session markers will be isolated to the custom directory without modifying `~/.bapstate`.
