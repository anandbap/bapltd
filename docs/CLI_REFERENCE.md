# BAP Command & Binary Reference

Comprehensive operational and reference documentation for the BAP (Bounded Authority Plane) Zero-Trust platform.

---

## 1. Architecture Overview: The 7 Core Binaries

BAP delivers enterprise-grade defense-in-depth across 7 dedicated binaries:

| Binary | Alias / Package | Role & Responsibility |
|---|---|---|
| **`bap` / `bapedge`** | `bapedge.exe`, `ltd-agent` | Workstation Local Trusted Daemon (LTD), policy engine, execution broker sandbox, and agent launcher. |
| **`bapcontrolplane`** | `bap-controlplane.exe` | Central policy authority, RFC 8693 STS token issuer, OTC enrollment authority, and audit aggregator. |
| **`bapdashboard`** | `bapdashboard.exe` | Dedicated HTTPS operator console, cockpit telemetry UI, and OBO exchange inspector. |
| **`bapgateway`** | `bapgateway.exe` | Egress Policy Enforcement Point (PEP), reverse proxy, and single-use credential consumer. |
| **`bapmcp`** | `bapmcp.exe`, `bapedge mcp` | Model Context Protocol (MCP) server exposing zero-trust execution and task grant tools to AI agents. |
| **`cchook` / `interceptor`** | `cchook-interceptor.exe` | Native hook interceptor (Layer 1A) for Claude Code, Copilot, Antigravity, and Codex. |
| **`bap-hook-adapter`** | `bap-hook-adapter.exe` | Universal cross-agent plugin runtime adapter bridging in-harness events to the BAP broker. |

---

## 2. `bap` / `bapedge` CLI Reference

`bap` and `bapedge` are the primary workstation CLI.

### 2.1 Set Up, Identity & Onboarding

| Command | Arguments / Flags | Description |
|---|---|---|
| `bap login` | `[--verify-now]` | Authenticate developer identity via enterprise OIDC/OAuth2 device flow (Google, GitHub, Okta, Microsoft Entra). Enrolls this machine, pins the policy signing key, and syncs initial signed rules. |
| `bap register` | `<code>` | Enroll edge daemon with central control plane using an administrative One-Time Code (OTC). |
| `bap logout` | *(none)* | Deregister workstation, clear credentials, and purge active session tokens (`alias: deregister`). |
| `bap setup` | `--app <claude-code\|antigravity\|codex\|copilot\|all>` | 1-click workstation onboarding: writes local configs, injects boundary rules (`GEMINI.md`, `CLAUDE.md`, `AGENTS.md`), and registers native hooks. |
| `bap enable` | *(none)* | Enable zero-trust workstation governance and configure local daemon. |
| `bap doctor` | `[--repair-policy] [--hook-copies-json]` | Run comprehensive diagnostic health check verifying binaries, policy digest, certificates, and hook hooks. |

### 2.2 Governed Agent Launchers (Layer 1A Sandbox)

Launch coding agent CLIs wrapped in transactional zero-trust sandboxes. Injects environment variables (`BAP_SESSION_ID`, `LTD_SOURCE`), resolves the global control plane endpoint, enrolls the session, starts background prompt and grant tailers, and auto-cleans on exit.

```powershell
bap agy [args...]             # Launch Google Antigravity CLI (agy) under active governance
bap antigravity [args...]     # Alias for 'bap agy'
bap claude [args...]          # Launch Claude Code CLI under active governance
bap claude-code [args...]     # Alias for 'bap claude'
bap codex [args...]           # Launch OpenAI Codex CLI under active governance
```

**Common Launcher Flags:**
* `--server=<url>`: Override control plane URL for this session (defaults to global setting in `bap-config.json`).
* `--no-hooks`: Launch in unmonitored development mode (only permitted if developer override is enabled).

### 2.3 Daemon & Service Lifecycle

| Command | Arguments / Flags | Description |
|---|---|---|
| `bap start` | `[-foreground] [-server <url>]` | Start background supervisor daemon (`bap-daemon`). Runs unprivileged in user-space. |
| `bap stop` | *(none)* | Gracefully terminate background supervisor daemon. |
| `bap restart` | *(none)* | Restart background supervisor daemon. |
| `bap status` | `[--all] [--json]` | Inspect local active sessions, daemon state, policy cache, spool backlog, and 5-layer compliance. |
| `bap sweep` | *(none)* | Clean sweep orphaned sessions, purge stale process locks, and flush offline audit records to the control plane. |
| `bap daemon` | `<start\|stop\|status\|restart>` | Low-level daemon subsystem management. |

### 2.4 Policy, Inspection & Broker Sandbox

| Command | Arguments / Flags | Description |
|---|---|---|
| `bap exec` | `"<command>" [--timeout <dur>] [--progress] [--shell auto\|cmd\|powershell\|pwsh]` | Evaluate command against Cedar invariants and run inside sandboxed execution broker. See [Quoting rules for `bap exec`](#24a-quoting-rules-for-bap-exec). |
| `bap check` | `"<command>"` | Evaluate command against Cedar policy in decision-only mode (zero execution side effects; alias: `authorize`). |
| `bap why` | `"<command>"` | Explain Cedar policy decision directly in terminal with matched rules and remediation advice (alias: `explain`). |
| `bap sync` | `[--server <url>] [--policy-dir <path>]` | Force immediate synchronization of local signed Cedar policy bundle from the central control plane. |
| `bap config` | `show` | Display resolved control plane, API gateway, trust domain, and enforcement mode. |
| `bap config` | `set [--server <url>] [--gateway <url>] [--mode enforce\|audit] [--global]` | Update control plane URL or enforcement mode locally or globally (`~/.bap/config.json`). |

### 2.4a Quoting rules for `bap exec`

The command is one string. On Windows, PowerShell parses that string first, so the escape character is the
backtick (or a doubled quote), **not** a backslash. `bapedge exec "git commit -m \"msg\""` is split by
PowerShell before BAP sees it and is rejected or mangled. Prefer single quotes *inside* the double-quoted string.

| Situation | Behaviour |
|---|---|
| `bapedge exec "git commit -m 'Fix a; b'"` | Works. Operators inside quotes (`; \| & > <`) are data, not shell operators. |
| `bapedge exec "git commit -m 'Co-Authored-By: X <x@y.com>'"` | Works (build v1.13.39 / `ebc22faa` or later). Older builds fail with `exit status 1`. |
| `git status && echo done`, `git status ; calc`, `a \| b`, `a > file` | Unquoted operators still run through `cmd.exe /c` and every sub-command is evaluated by policy. |
| Unterminated quote | Never guessed at; falls back to the conservative `cmd.exe` path. |
| Unquoted commands and `cmd` builtins (`echo`, `dir`) | Unchanged, run through `cmd.exe /c`. |
| Long or multi-paragraph messages | Use a file: `git commit -F <file>`. This avoids quoting entirely and works on every build. |

A quoted command with no unquoted operator runs directly with an exact argument list when the program is on
`PATH`. Implementation: `bap-edge/internal/sandbox/argv.go` (`hasUnquotedShellOperator`, `splitArgv`).

### 2.5 Zero Standing Privilege (ZSP) & Playback

BAP operates on Zero Standing Privileges: agents start with zero authority and acquire short-lived, least-privilege JIT TaskGrants.

| Command | Arguments / Flags | Description |
|---|---|---|
| `bap zsp status` | `[--all] [--all-sessions]` | Inspect active and burned ephemeral JIT TaskGrants. `--all-sessions` aggregates across all agent sessions. |
| `bap zsp grants` | `[--all] [--all-sessions]` | Alias for `bap zsp status`. Shows grant envelope, principal SVID, allowed scopes, and receipt proofs. |
| `bap zsp playback` | `[--all-sessions]` | Replay chronological grant lifecycle events, distinguishing `[AUTOMATIC (Cedar Policy)]` from `[MANUAL (HITL Challenge)]`. Outputs automation velocity % for policy tuning. |
| `bap zsp authorize` | `--session-id <id> --mission <m> --goal "<text>" --actions <a,b> [--resources <r>] [--max-uses N] [--ttl <dur>] [--authorized-by <email>] [--client <c>] [--json]` | Submit a 4-Tuple Task Authorization Envelope to the policy engine. Defaults: `--mission TASK_EXECUTION`, `--resources workspace://current`, `--max-uses 1`, `--ttl 300s`. Run it as a **standalone** command (no `&&`, `;` or `\|`). A grant is minted, **or** a human-approval request id is raised, **or** the request is denied. |
| `bap zsp approvals` | *(none)* | Human only: list pending high-risk approval requests. Blocked for agents. |
| `bap zsp approve` | `<req-id>` | Human only: approve a pending request. Requires a one-time code typed in the developer's own terminal. Blocked for agents. |
| `bap zsp deny` | `<req-id>` | Human only: deny a pending request. Blocked for agents. |

**Grant classes.** The class is chosen by the actions requested, and `--max-uses` is clamped to the class ceiling.

| Class | Actions | Uses / TTL |
|---|---|---|
| `workspace_edit` | `fs:file:write` only | Honors `--max-uses N` (request one grant sized for a batch of edits). |
| `single_use` | Anything mixed or executable (`cli:bash:exec`, `git:commit:write`, `dev:go:-C`, …) | 1 use, 300 s. One command per grant. |

**Approval flow.** A request returns one of: `JIT TaskGrant Minted` (proceed through `bapedge exec`);
`High-Risk Escalation Blocked … HITL REQUEST RAISED: req-…` (stop, tell the developer, wait for
`bap zsp approve`); or a policy denial. An approval covers only the action requested. Approving
`cli:bash:exec` does not cover `dev:go:-C`. When `BAP ZSP AUTO-APPROVE ON` appears, routine (approve-tier)
requests are granted without a prompt; push, publishing, destructive operations, credential access and network
egress are never auto-approved. See [ZSP_APPROVAL_FLOW.md](../ZSP_APPROVAL_FLOW.md) for the full explanation.

### 2.6 Human-in-the-Loop (HITL) Step-Up Escalations

When an agent requests an action outside routine policy (e.g. interpreter execution `dev:python:exec`, network egress), it triggers a step-up challenge.

| Command | Arguments / Flags | Description |
|---|---|---|
| `bap stepup list` | *(none)* | List pending out-of-scope escalation requests from the Central Control Plane. |
| `bap stepup request` | `<task_id> <action> <resource> [reason]` | Submit an out-of-scope task escalation request to the control plane inbox. |
| `bap stepup status` | `<task_id>` | Query approval state of an escalation request. |
| `bap stepup approve` | `<task_id>` | Human developer interactive approval of an escalation request. |
| `bap stepup reject` | `<task_id> [reason]` | Human developer interactive rejection of an escalation request. |

### 2.7 Cross-Folder Authority & Permissions

| Command | Arguments / Flags | Description |
|---|---|---|
| `bap trust` | `--path <dir> --scope session\|project\|global [--ops read,write,delete]` | Authorize mutations in an external directory outside the workspace root (e.g. `..\sibling-project`). Never permitted for filesystem roots, user home, or credential directories. |
| `bap untrust` | `--path <dir>` | Revoke cross-folder mutation authorization. |
| `bap permissions` | *(none)* | List all active cross-folder authorizations across session, project, and global scopes. |

### 2.8 Native Plugin Management (Layer 1A)

| Command | Arguments / Flags | Description |
|---|---|---|
| `bap plugin list` | `[workspace]` | List discovered and installed native plugins across Claude Code, Copilot, Antigravity, OpenCode, and Codex. |
| `bap plugin install` | `<claude\|copilot\|antigravity\|opencode\|codex\|all>` | Install native in-harness hook extensions and adaptors. |
| `bap plugin uninstall` | `<claude\|copilot\|antigravity\|opencode\|codex\|all>` | Safely remove native plugin registrations. |
| `bap plugin verify` | `[client]` | Verify plugin hook execution, file integrity, and active enforcement. |
| `bap plugin inspect` | `<client>` | Inspect detailed plugin health record, manifest, and adapter paths. |
| `bap plugin layers` | *(none)* | Display the active 5-layer defense-in-depth security status. |

### 2.9 Closed-Loop Policy Recommendations

| Command | Arguments / Flags | Description |
|---|---|---|
| `bap recommend` | *(none)* | List recent blocked calls grouped by effect; prompts developer to pick one to inspect and justify. |
| `bap recommend` | `--pick <n> --justify "<reason>"` | Submit a recommended policy relaxation for routine build/test commands to administrator. |
| `bap recommend` | `--status` | Check status of recommendations submitted by this workstation. |
| `bap review recommend` | *(none)* | Same recommendation flow accessible directly from the session reviewer. |

### 2.10 Enterprise Security, Forensics & Integrity

| Command | Arguments / Flags | Description |
|---|---|---|
| `bap rollback` | `--checkpoint-id <id> [--dry-run]` | Forensically revert filesystem mutations to pre-execution cryptographic checkpoints (BAP-538). |
| `bap pin` | `<verify\|update\|status> [--all]` | Cryptographically pin, verify, and re-attest skills, prompts, and MCP tool schemas (BAP-531). |
| `bap scan` | `[--dir <path>] [--strict]` | Audit workspace skills, prompt templates, and configs for prompt injection, leakage, and drift (BAP-536). |
| `bap shield` | `<status\|canary\|sanitize>` | Ambient credential shielding, disk token virtualization, and canary traps (BAP-562). |
| `bap antibypass` | `<status\|verify\|enforce>` | Multi-tier anti-bypass inspection and egress isolation engine (BAP-560). |
| `bap delegate` | `[args...]` | Multi-agent hierarchical delegation & subagent envelope broker (BAP-532). |
| `bap verify-log` | *(none)* | Verify the tamper-evident SHA-256 hash-chain of the local audit log. |
| `bap dev-override` | `<on\|off\|status>` | Manage time-boxed developer override (interactive human only; strictly blocked for agents). Only works in a binary built with dev overrides (`allow_dev_overrides=true` in `bap version --json`). See [Build modes](#81-build--package). |
| `bap version` | `[-v] [--version] [--json]` | Display semantic version, git commit, build date, and architecture. |

---

## 3. `bapcontrolplane` CLI Reference

The central policy authority, RFC 8693 STS token issuer, and audit repository (`bap-controlplane`).

### 3.1 Commands

```powershell
bapcontrolplane start [flags]       # Start the HTTP/TLS Central Control Plane server
bapcontrolplane stop                # Gracefully terminate running background instance
bapcontrolplane status              # Query status, health, port, uptime, and database metrics
bapcontrolplane restart [flags]     # Restart the Central Control Plane instance
bapcontrolplane enable              # Initialize environment, admin tokens, and state stores
bapcontrolplane serve [flags]       # Run server in foreground (alias for 'start --foreground')
bapcontrolplane version             # Display semantic version, git commit, and build info
```

### 3.2 Flags & Options for `start` / `serve`

| Flag | Default | Description |
|---|---|---|
| `--port <p>` | `8080` / `$PORT` | Port for HTTP/TLS server. |
| `--detach`, `-d` | `false` | Run as detached background daemon. |
| `--foreground`, `--fg` | `false` | Run in foreground. |
| `--mode <prod\|dev>` | `prod` | Environment mode: `prod` (default; strict OTC, OIDC required) or `dev` (open self-service OTC, local development only). An explicit `--mode` overrides `BAP_MODE` / `BAP_ENVIRONMENT`. Prod requires `BAP_SECRET_KEY` (32+ chars), `BAP_POLICY_SIGNING_SEED` (64 hex), `--policy-max-age` / `BAP_POLICY_MAX_AGE` and an absolute `--db`; otherwise startup fails. |
| `--demo-mode` | `false` | Enable synthetic demo data in the activity views (`?demo=true`). Also `BAP_DEMO_MODE=1`. Never in production. The destructive demo endpoints (`/sessions/reset`, `/demo/*`) were removed. |
| `--enable-simulated-endpoints` | *(no-op)* | **Deprecated.** The simulated SPIFFE, TPM, Landlock (not implemented) and eBPF (simulation only) endpoints were removed; the flag is accepted so old launch scripts still start. |
| `--db <path>` | `bap-controlplane.db` | Path to persistent SQLite database (`memory` for in-memory). |
| `--durable` | `false` | Commit authority and audit history to disk before acknowledging API calls (mandatory in prod). |
| `--admin-token <token>` | auto-generated | Administrative secret token for control APIs (`$BAP_ADMIN_TOKEN`). |
| `--allow-remote-admin` | `false` | Allow non-localhost callers with valid admin token to execute admin APIs. |
| `--secret <key>` | auto-generated | HMAC signing secret for session tokens (`$BAP_SECRET_KEY`). |
| `--policy <path>` | *(embedded)* | Path to authoritative Cedar policy file. |
| `--schema <path>` | *(embedded)* | Path to authoritative Cedar schema file. |
| `--trust-domain <dom>` | `bap.internal` | SPIFFE Trust Domain for agent workload identities. |
| `--ttl <minutes>` | `30` | Default grant TTL in minutes. |
| `--tls`, `--https` | `false` | Enable HTTPS/TLS (auto-generates dev certs if none provided). |
| `--tls-cert <path>` | *(empty)* | Path to TLS certificate PEM file. |
| `--tls-key <path>` | *(empty)* | Path to TLS private key PEM file. |
| `--allowed-origins <origins>` | *(empty)* | Comma-separated browser origins for CORS (default: same-origin only). |
| `--oidc-provider <prov>` | `entra` | Enterprise OIDC provider: `entra`, `okta`, or `generic`. |
| `--oidc-issuer <url>` | *(empty)* | OIDC issuer / discovery URL. |
| `--oidc-client-id <id>` | *(empty)* | OIDC application client ID. |
| `--oidc-tenant-id <id>` | *(empty)* | Microsoft Entra tenant ID or Okta org. |
| `--oidc-allowed-domains <doms>`| *(empty)* | Comma-separated corporate email domains permitted. |
| `--min-edge-version <ver>` | *(empty)* | Enforce minimum edge client version. |
| `--pilot-roster <path>` | *(empty)* | Path to operator-assigned pilot roster JSON file. |
| `--initialize-authority` | `false` | Explicitly initialize a new durable authority (first start only). |
| `--policy-max-age <duration>` | `0` | Signed offline policy budget (e.g. `24h`; mandatory in prod). |

### 3.3 Read-API authentication & stream tickets

* **Admin-only read routes** (header `Authorization: Bearer <token>`, `X-BAP-Admin-Token`, or the dashboard cookie):
  `/api/v1/agents`, `/sessions`, `/audit/events`, `/audit/risky-events`, `/inspector/data`, `/sts/tokens`,
  `/sts/inspector`, `/principals`, `/saas/tokens`, and all `/api/activity/*` and `/api/v1/activity/*` reads.
  Missing credential: `401`. Wrong credential: `403`. Repeated bad credentials from one address: `429` with `Retry-After`.
* **No credential in the URL.** `?token=` and `?admin_token=` are not accepted on any route.
* **Streams** (`/api/activity/stream`, `/api/v1/activity/stream`): exchange the admin credential for a
  single-use ticket, then pass only the ticket.

```powershell
# 1. admin credential -> ticket (valid 30 s, single use)
Invoke-RestMethod -Method Post -Uri "$cp/api/v1/auth/stream-ticket" -Headers @{ Authorization = "Bearer $tok" }
# 2. open the stream with the ticket
"$cp/api/activity/stream?ticket=bap_stk_..."
```

* **Intentionally unauthenticated** (called by edge agents): `/health`, `/policy/bundle`, `/sessions/{id}`,
  `/escalation/{id}`, enrollment and session-telemetry routes.
* **Removed:** `/api/v1/spiffe/*`, `/attestation/tpm-quote` and the simulated `/api/v1/sandbox/*` endpoints,
  the destructive demo endpoints (`/sessions/reset`, `/demo/exec-safe`, `/demo/exec-attack`, `/demo/fleet-scale`),
  and the simulated Google/GitHub login pages. `/auth/oauth/start` returns `503` when no provider client ID is configured.
* **Identity must be verified in prod.** In `--mode prod`, `/auth/oauth/google-complete` and `/github-complete`
  (typed-email forms) return `403`, and the Google/GitHub callbacks return `403` unless the provider returned a
  verified email. In `--mode dev` the placeholder identities (`developer@gmail.com` / `developer@github.com`) still work.
* **Dashboard token.** `start_inspector.bat` no longer puts the admin token in the URL; paste it at the dashboard's admin login prompt.

---

## 4. `bapdashboard` CLI Reference

Dedicated operator web console and telemetry inspector (`bapdashboard`).

### 4.1 Flags & Options

```powershell
bapdashboard [flags]
```

| Flag | Default | Description |
|---|---|---|
| `-port <p>` | `8444` | HTTPS port for the standalone dashboard server. |
| `-control-plane <url>` | `https://localhost:8443` | Upstream BAP Control Plane base URL. |
| `-ca-cert <path>` | `$BAP_CA_CERT` | CA certificate file used to verify control plane TLS. |
| `-tls-cert <path>` | `dashboard-cert.pem` | Dashboard HTTPS server certificate. |
| `-tls-key <path>` | `dashboard-key.pem` | Dashboard HTTPS private key. |
| `-client-cert <path>` | *(empty)* | Optional mTLS client certificate presented to control plane. |
| `-client-key <path>` | *(empty)* | Optional mTLS client private key presented to control plane. |
| `-allow-remote-admin` | `false` | Allow remote dashboard clients to invoke administrative APIs. |

---

## 5. `bapgateway` CLI Reference

Zero-Trust Policy Enforcement Point (PEP) and egress reverse proxy (`bapgateway`).

### 5.1 Commands

```powershell
bapgateway start [flags]       # Start the Gateway PEP HTTP server
bapgateway stop                # Gracefully terminate running background instance
bapgateway status              # Query status, health, port, and upstream control plane
bapgateway restart [flags]     # Restart the Gateway PEP instance
bapgateway enable              # Validate configuration and connectivity
bapgateway serve [flags]       # Run in foreground (alias for 'start --foreground')
bapgateway version             # Display version and build info
```

### 5.2 Flags & Options for `start` / `serve`

| Flag | Default | Description |
|---|---|---|
| `--port <p>` | `9090` / `$BAP_GATEWAY_PORT` | Port for Gateway PEP server. |
| `--detach`, `-d` | `false` | Run as detached background daemon. |
| `--controlplane <url>` | `http://localhost:8080` | BAP Control Plane base URL. |
| `--secret <key>` | *(empty)* | HMAC secret key for offline JWT verification. |
| `--consume` | `true` | Atomically consume single-use task grants via control plane on egress. |

---

## 6. `bapmcp` CLI Reference

Model Context Protocol (MCP) broker for Claude Code, Antigravity, Cursor, and Copilot (`bapmcp` / `bapedge mcp`).

### 6.1 Usage & Commands

```powershell
bapmcp --stdio                # Run stdio JSON-RPC 2.0 server (default when launched by agent)
bapmcp status                 # Inspect MCP configuration, policy rules, and audit status
bapmcp help                   # Display onboarding instructions and sample configs
```

### 6.2 Flags & Options

| Flag | Default | Description |
|---|---|---|
| `--stdio` | `false` | Run in stdio JSON-RPC 2.0 protocol mode. |
| `--server <url>` | from config | Central control plane URL for telemetry streaming. |
| `--session-id <id>` | auto-detected | Session identifier for grouping agent actions. |
| `--mode <enforce\|audit>` | from config | Enforcement mode: `enforce` (block violations) or `audit` (log violations). |
| `--policy <path>` | `./policy.cedar` | Path to local Cedar policy file. |
| `--audit-log <path>` | `.bapstate/audit.jsonl` | Path to audit log file in JSON Lines format. |

### 6.3 Exposed MCP Tools

* **`bap_execute`**: Evaluate command against Cedar invariants and execute inside sandboxed broker.
* **`bap_explain_policy`**: Dry-run evaluate Cedar policy without execution; returns decision and suggestions.
* **`bap_status`**: Inspect edge daemon health, active sessions, and local policy cache.
* **`bap_request_task_grant`**: Submit 4-Tuple Task Authorization Envelope (Who, AuthorizedBy, Intent, Ask) to mint ephemeral JIT TaskGrants.
* **`bap_zsp_status`**: Inspect agent's SPIFFE SVID principal, human owner binding, and active grants.
* **`bap_read_file`**, **`bap_write_file`**, **`bap_edit_file`**, **`bap_list_dir`**: Policy-governed workspace filesystem tools.
* **`bap_report_request`**: User turn prompt fallback reporting.

### 6.4 Client Configurations

**Claude Code (`~/.claude/settings.json`):**
```json
{
  "mcpServers": {
    "bap-zero-trust": {
      "command": "bapmcp",
      "args": ["--stdio"]
    }
  }
}
```

**Google Antigravity (`.antigravity/mcp_config.json`):**
```json
{
  "mcpServers": {
    "bap-zero-trust": {
      "command": "bapmcp.exe",
      "args": ["--stdio"],
      "env": {
        "LTD_SOURCE": "antigravity",
        "BAP_SESSION_ID": "sess-antigravity-active"
      }
    }
  }
}
```

**Cursor IDE (`~/.cursor/mcp.json`):**
```json
{
  "mcpServers": {
    "bap-zero-trust": {
      "command": "bapmcp",
      "args": ["--stdio"]
    }
  }
}
```

---

## 7. `cchook` & `bap-hook-adapter` Reference

Layer 1A In-Harness Native Hook Extensions (`cchook`, `interceptor`, `bap-hook-adapter`).

### 7.1 Architecture & Interception Events

`cchook` and `bap-hook-adapter` receive JSON payloads on standard input from agent harnesses during execution lifecycle events:

1. **`PreInvocation` / `UserPrompt`**: Captures user intent and prompts for continuous telemetry.
2. **`PreToolUse` / `PreToolExecution`**: Intercepts shell and filesystem tool calls (`Bash`, `exec`, `write_file`, `git`, etc.) *before* execution.
3. **`PostToolUse`**: Records exit code, output hash, and execution duration.
4. **`SessionStart` / `SessionEnd`**: Manages session enrollment, heartbeat monitors, and cryptographic cleanup.

### 7.2 `bap-hook-adapter` Execution

```powershell
bap-hook-adapter --client <claude|copilot|antigravity|opencode|codex> --event <PreToolUse|PostToolUse|PreInvocation|SessionStart|SessionEnd>
```

*(Or via edge CLI: `bapedge plugin adapter --client antigravity --event PreToolUse`)*

---

## 8. Part 2 – Internal BAP Developer Tooling

> **Note:** The commands below are for BAP core contributors and maintainers building from source.

### 8.1 Build & Package

| Script | Purpose |
|---|---|
| `build_binaries.bat` | Build all Windows binaries (`bap.exe`, `bapcontrolplane.exe`, `bapgateway.exe`, `bapmcp.exe`, `cchook.exe`) and deploy to testing paths. |
| `update_binaries.ps1` | `[-Version vX.Y.Z] [-AllowDevOverrides "true"\|"false"] [-HeadlessStepUp "true"\|"false"] [-SkipUserInstall]`. Builds `bapedge.exe`, `cchook` and the other binaries. **`-AllowDevOverrides` defaults to `"true"`**, which compiles in the `devoverride` tag so `bap dev-override on` works (local developer machines). Pass `"false"` for a release-style build. `-HeadlessStepUp "true"` compiles the test-harness-only step-up bypass (BAP-1096); never install or publish that build. |
| `install_bap_global.bat` / `scripts/install_bap_global.ps1` | `[-AllowDevBuild] [-Debug]`. Installs binaries and global hooks for all agents. It reads `bapedge version --json` and **refuses** a build with `allow_dev_overrides=true` or `headless_stepup=true` (exit 3) unless `-AllowDevBuild` is passed. `-AllowDevBuild` belongs to the installer, not to `update_binaries.ps1`. |
| `build_all_platforms.ps1` | Cross-compile release packages for Windows (`amd64`, `arm64`), Linux (`amd64`, `arm64`), and macOS (`darwin-arm64`, `darwin-amd64`). |
| `python scripts/build_wheel.py [--universal]` | Package Python wheel and source distribution (`bap-ltd`). |

**Build modes and which command to use**

| You want | Build | Install |
|---|---|---|
| Local dev machine, with `bap dev-override` available | `.\update_binaries.ps1` (default) | `.\scripts\install_bap_global.ps1 -AllowDevBuild` (run the `.ps1` directly if the `.bat` does not forward the flag) |
| Machine that runs real agents, approvals always enforced | `.\update_binaries.ps1 -AllowDevOverrides "false"` | `.\install_bap_global.bat` |
| Python end-to-end tests that need headless step-up | `.\update_binaries.ps1 -HeadlessStepUp "true"` | Do not install |

Why the installer refuses a dev build: a dev-override or test-harness build can be told to skip approvals,
and a global install puts that binary under every agent hook on the workstation, including agents. Check any
binary with `bapedge version --json` (`allow_dev_overrides`, `headless_stepup`). Agents may never run
`bap dev-override on`; it needs an interactive human.

### 8.2 Test Suites

| Command | Purpose |
|---|---|
| `go test ./...` in `bap-edge`, `bap-controlplane`, `bap-gateway`, `cchook` | Unit and integration suites. |
| `go test -v -run TestZSP ./...` | Zero Standing Privilege and task grant tests. |
| `go test -v -run TestStepUp ./cmd` | Endpoint resolution and HITL step-up tests. |
| `python -m unittest discover -v tests` | Python integration and end-to-end regression suites. |
| `.\scripts\run_pilot.ps1 [-Quick]` | Automated end-to-end pilot runbook verifying all 5 defense layers. |
