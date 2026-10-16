# Active Task: Claude Concurrency, Infosec Sanitization & Build Stabilization

## Sprint Goal
- Enable developers to launch multiple concurrent Claude Code sessions in the same directory and across different directories without mutex locks or crashes.
- Prevent corporate InfoSec alerts by eliminating all false-positive trigger strings (`evil.com`, `malware`, `payload.exe`) from default test runs.
- Isolate all runtime artifacts into `.bap/` instead of polluting workspace roots.
- Ensure end-to-end multi-platform build and automated test suites pass 100%.

---

## Completed & Fixed

1. **Re-imaged Agent Watch V2 — Mission Control, Trust Command, Capability Atlas (100% Parity & Preservation)**:
   - **Feature Preservation Matrix**: Audited all 17 existing V1 screens/features, permissions, APIs, and models in `agent_watch_v2_feature_matrix_and_ia.md`.
   - **Workspace 1: Mission Control (CIO)**:
     - 10-second executive summary bar answering *"What are agents doing? Is it safe? What value?"*.
     - 6 canonical workstreams (`build`, `operate`, `analyze`, `document`, `support`, `unknown`).
     - Interactive enterprise activity topology map connecting Business Units to Laptop (Win32), Linux Worker, AWS Cloud Agent, and Vendor MCP.
     - Accessible text alternative table with full keyboard toggle.
     - Honest telemetry assurance: estimates tagged as `[ESTIMATED]`, zero fake mocks in production mode.
   - **Workspace 2: Trust Command (CISO/SecOps)**:
     - Real-time fleet inventory with SPIFFE / SVID identity validation and multi-layer containment.
     - Decision feed, bounded single-use JIT grants with atomic PEP burn, Cedar Policy Studio & simulator.
     - Cryptographic SHA-256 tamper-evident hash chain verifier, step-up approvals with fail-close timer, Rule R3 reconciliation queue, and helpdesk diagnostic engine (*"Why Was It Blocked?"*).
     - Scoped emergency action modal enforcing explicit typed confirmation (`"CONFIRM KILL SWITCH"`, `"REVOKE <ID>"`), blast-radius inspection, RBAC check, and audit notarization.
     - Progressive drilldown drawer: `Enterprise > Business Domain > Agent Session > Action > Cryptographic Receipt`.
   - **Workspace 3: Capability Atlas (Architecture & Vendor Governance)**:
     - 12-domain capability heatmap across 5 architecture layers.
     - Objective evidence-backed seed dataset for 4 vendors: Agent Watch / BAP, Keycard, Runlayer, and AIR Security (AIR Defend module).
     - Agent Watch lifecycle status tracking (`designed`, `implemented`, `integration-tested`, `deployed`).
     - Side-by-side vendor comparison and domain filter controls.
     - Interactive evidence drawer showing evidence URLs, evaluators, test outcomes, environment, and demo reproduction requirements.
     - Zero misleading single scores without explicit weighting.
   - **Backward Compatibility & Routing**:
     - Dual routing in `server.go`: `/dashboard/v2/` dedicated V2, `/dashboard/` serves V2 by default, `/dashboard/?v=legacy` preserves 100% of classic V1.
     - Cross-dashboard switch buttons embedded in headers of both V1 and V2.
   - **Testing & Verification**:
     - Go unit tests: `bap-controlplane/internal/dashboardui/server_test.go` PASS (both assets and proxies).
     - Python regression suite: `tests/test_agent_watch_v2.py` (9/9 tests pass in 0.051s).
     - Binaries recompiled and updated via `update_binaries.ps1`.

1. **Purged Corporate InfoSec False Positives**:
   - Sanitized 20 files across `.py`, `.go`, `.ps1`, `.bat`, `.sh`, `.md`, `.html`.
   - Replaced trigger domains/names with non-threatening RFC-compliant internal identifiers (`untrusted-test.internal`, `pkg`, `setup.bin`).
   - Zero occurrences of `evil.com` remain in repository.

2. **Isolated Negative/Deny Security Tests**:
   - Excluded negative tests from `run_all_tests.bat`, `test_complex_cases.ps1`, `simple_local_test.bat`, and `test_financial_reconciler.py`.
   - Created dedicated `run_negative_testcases.bat` for manual, on-demand compliance verification (19/19 deny checks pass).

3. **Workspace Root Cleanliness**:
   - Runtime configuration and session markers moved into `.bap/` (`.bap/sessions/`, `.bap/session.json`, `.bap/bap-config.json`).
   - Recompiled `bapedge.exe` and `cchook/interceptor.exe`.

4. **Multi-Instance Claude Code Concurrency**:
   - Replaced single-instance workspace mutex in `run_claude_bap.ps1` and `run_claude_bap.bat` with reference-counted session tracking under `.claude/.bap-recovery.json`.
   - First instance takes custody of `.claude/settings.json` and starts watchdog; subsequent instances join active session count without settings contention.
   - Original settings restored only when the final session exits.

5. **Fixed PowerShell Read-Only `$PID` Overwrite & Typecasting**:
   - Renamed loop variable `$pId` to `$sessPid` across `run_claude_bap.ps1` and `.bat` (PowerShell is case-insensitive, so `$pId = ...` attempted to overwrite built-in `$PID`).
   - Fixed typecast precedence: `[int]($s.launcher_pid)` instead of `[int]$s.launcher_pid` (which threw cast exceptions on custom objects).

6. **Eliminated Interactive Hangs (`Read-Host`)**:
   - Gated `Read-Host` server prompt behind `$canPrompt` (only executes if zero arguments passed AND interactive console).
   - Scripts and `--version` calls now execute immediately without blocking.

7. **Cross-Directory Global Binary Resolution**:
   - When developers run `run_claude_bap.bat` from any directory outside the repo, `Resolve-Binary` and `Get-ConfigServerUrl` search well-known locations (`%USERPROFILE%\pyprj\bapltd`, `%USERPROFILE%\bin`, `%USERPROFILE%\.bap`).
   - Copied `bapedge.exe` and `interceptor.exe` to `%USERPROFILE%\bin`.

8. **Teardown File Lock Contention**:
   - Watchdog process is now explicitly stopped prior to file restoration, eliminating Windows sharing locks (`The process cannot access the file ... because it is being used by another process`).
   - Added retries with backoff in `Restore-TrackedFile`.

9. **Concurrency Verification Passed**:
   - Automated tests in `scripts/test_claude_concurrency.ps1` pass 100%:
     - Simultaneous overlapping sessions in same directory exit cleanly with original settings restored.
     - Concurrent sessions in separate directories run in parallel with zero conflicts.

---

10. **Multi-Platform Build (`build_all_platforms.bat`)**:
    - Fixed recursion in `Safe-CopyItem` and synchronized `run_claude_bap.ps1` into role packages.
    - Verified: Built static zero-dependency binaries for Windows, Linux (amd64/arm64), and macOS (Intel/Apple Silicon) in 46.9s.
    - Verified: All 72 fleet distribution assets audited and confirmed in exact sync (0 stale copies).

11. **Comprehensive End-to-End Test Suite (`run_all_tests.bat`)**:
    - Fixed kill-switch state discovery in `authorizer.go` to prioritize directory-specific policy state.
    - Ran full test suite across all 12 stages: 31/31 tests passed (Exit Code 0).

---

## Status: Previous Sprint Completed (100% Tests & Builds Green)

---

# Active Sprint: Binary Architecture Organization & Deduplication

## Objective
Standardize and reorganize all BAP executables so there is a single canonical set of binaries, zero duplicate or differently-sized binaries, and clean separation between Server, Edge, and Agent Interceptor roles.

## Binary Taxonomy
| Role | Component | Canonical Binary Name | Description |
| :--- | :--- | :--- | :--- |
| **Server** | Control Plane | `bapcontrolplane` | Central CA, attestation, policy & audit server |
| **Server** | Dashboard | `bapdashboard` | Standalone HTTPS UI dashboard server |
| **Server** | Gateway | `bapgateway` | Zero-trust PEP reverse proxy gateway |
| **Edge** | Edge Daemon | `bapedge` | Machine node daemon, telemetry watcher & CLI |
| **Hook** | Claude Code Interceptor | `interceptor` / `cchook-interceptor` | Claude Code PreToolUse PEP hook |
| **Hook** | GitHub Copilot Interceptor | `copilot-interceptor` | GitHub Copilot CLI execution PEP hook |

## Checklist & Progress

- [x] **Step 1: Unify Build Flags Across Builders**
  - Standardized `build_binaries.bat` and `build_all_platforms.ps1` to use identical `-trimpath -ldflags "-s -w"` flags. All outputs produce identical byte-for-byte binary sizes across the fleet.
- [x] **Step 2: Remove Stale & Legacy Duplicate Binaries**
  - Deleted 14 stale legacy copies (`server.exe`, `ltd-agent.exe`, `*.old`, `*.next.exe`, `*.test.exe`, `bapgateway.exe~`, and staging folders).
  - Eliminated duplicate `bapedge.exe` copies from `cchook/` and `copilot/`.
- [x] **Step 3: Standardize `dist/` Role Package Layout**
  - `dist/windows-amd64/`: Core suite (`bapcontrolplane`, `bapdashboard`, `bapgateway`, `bapedge`, `cchook-interceptor`, `copilot-interceptor`).
  - `dist/windows-amd64/claude-client/`: Clean developer seat package containing ONLY `bapedge.exe`, `interceptor.exe`, `run_claude_bap.bat`, `run_claude_bap.ps1`, `bap-config.json`, `policy.cedar`, `schema.json`.
  - Deleted conflicting `cchook-interceptor.exe` from `claude-client/`.
- [x] **Step 4: Update Reference Scripts & Paths**
  - Verified `run_claude_bap.ps1`, `run_claude_bap.bat`, `test_control_plane.py`, and test runners reference canonical paths.
- [x] **Step 5: Verify Rebuild and Fleet Audit**
  - `build_binaries.bat`: Passed with Exit Code 0 in ~15s (exact 1:1 binary sizes verified).
  - `scripts/test_claude_concurrency.ps1`: Passed with Exit Code 0 (same & different directory concurrency).
  - Stale asset audit: 72/72 fleet distribution assets confirmed in exact sync.

---

# Active Sprint: MVP Enterprise Readiness Pack

## Goals
Implement the top 3 high-impact enterprise MVP capabilities:
1. **1-Click Developer Onboarding (`install_bap_client.bat`)**: Single-script deployment to `%USERPROFILE%\bin` with automatic User `PATH` configuration.
2. **Pre-Flight Diagnostic Health Check (`bap_doctor.bat`)**: Instant 5-point environment and hook health diagnosis.
3. **Enterprise Rollout Mode: Audit/Shadow vs Enforce (`bap-config.json` & `bapedge`)**: Support silent policy monitoring (`audit` mode) with telemetry tagging alongside zero-trust hard blocking (`enforce` mode).

## Completed Tasks
- [x] **Task 1: 1-Click Developer Installer (`install_bap_client.bat` & `scripts/install_client.ps1`)**
  - Copies canonical binaries from `dist/windows-amd64/claude-client/` to `%USERPROFILE%\bin`.
  - Idempotently adds `%USERPROFILE%\bin` to User `PATH` via PowerShell environment API.
  - Updates current session environment so `run_claude_bap` works immediately.
  - Verified: 7 files deployed, PATH configured, 0 errors.
- [x] **Task 2: Pre-Flight Diagnostic Health Check (`bap_doctor.bat` & `scripts/bap_doctor.ps1`)**
  - Tests Core BAP binaries & client tools in `%USERPROFILE%\bin` or repo.
  - Tests Claude Code CLI executable resolution and version (`v2.1.273`).
  - Tests Control Plane reachability & TLS handshake latency.
  - Tests Cedar policy engine compilation, rule validity, and sub-millisecond evaluation latency.
  - Tests Workspace `.bap/` directory isolation and active transaction lockouts.
  - Verified: `bap_doctor.bat` reports 8/9 operational checks passed (offline-safe when CP is idle).
- [x] **Task 3: Enterprise Audit/Shadow Mode vs Enforce Mode**
  - Added `"enforcement_mode": "enforce"` | `"audit"` support in `bap-config.json`, CLI flag `--mode`, and `BAP_ENFORCEMENT_MODE` env var.
  - Updated `bap-edge`: when in `audit` mode, logs violations as `shadow_deny` in audit telemetry with policy details, prints `[BAP AUDIT MODE] Policy violation detected: ... Execution permitted in audit mode.`, and permits command execution.
  - When in `enforce` mode (default), maintains strict Zero-Trust hard blocking.
  - Updated `copilot_interceptor.go` and MCP server to support audit warning reflection.
  - Verified: Automated tests confirm enforce mode blocks credential access (`exit 1`) while audit mode allows execution (`exit 0`) with structured warnings and `shadow_deny` audit events.
- [x] **Task 4: Full Suite & Concurrency Verification**
  - Verified `build_binaries.bat`: 7/7 stages passed (exit 0).
  - Verified `run_all_tests.bat`: 31/31 stages passed (exit 0).
  - Verified `scripts/test_claude_concurrency.ps1`: 100% passed (both same-directory and multi-directory concurrency).
  - Preserved Cedar security rules (`*comsvcs*`, `*minidump*`, `*sekurlsa*`, `*set-mppreference*`, `*disablerealtimemonitoring*`).
  - Audited all `.bat` and `.ps1` scripts to ensure zero escalated or EDR heuristic commands exist.

---

# Active Sprint: Linux Background Supervision & Headless Resiliency Testing

## Goals
1. **Linux Background Auto-Restart Supervisor**: Provide production-grade background daemon supervision (`start`, `stop`, `status`, `restart`) with automatic restart on process death, plus a standard systemd service unit.
2. **Negative Test Isolation Policy**: Isolate all adversarial simulation tests strictly into `run_negative_testcases.bat` (never invoked by automated suites); ignore from indexing via `.cursorignore`.
3. **Automated Headless Resiliency, Scaling, & Integrity Suite**: Verify that the new system withstands process crashes, restarts, scaling bursts, and total server outages without breaking zero-trust integrity.

## Completed Tasks
- [x] **Task 1: Linux Background Auto-Restart Supervisor & Systemd Daemon Service**
  - Created `scripts/supervise_controlplane.sh` (supports `start`, `stop`, `status`, `restart`, and `foreground`).
  - Automatically respawns `bapcontrolplane` within 1 second if killed (`kill -9`, SIGTERM, crash).
  - Created `start_controlplane_supervisor.sh` root wrapper.
  - Created `dist/systemd/bapcontrolplane.service` for systemd integration (`Restart=always`, `RestartSec=2s`).
- [x] **Task 2: .cursorignore & Negative Test Policy Enforcement**
  - Updated `.cursorignore` to ignore `run_negative_testcases.bat`.
  - Confirmed `run_all_tests.bat`, regression suites, and resiliency tests never invoke negative/flagged simulation tests.
- [x] **Task 3: Automated Headless Resiliency, Scaling, & Failover Test Suite**
  - Created `scripts/test_resiliency_headless.ps1` and `run_resiliency_test.bat`.
  - Verified 10/10 automated assertions passing (100% system integrity):
    1. Supervisor initialization & process health (PID logged, port 8443 online).
    2. Dead process auto-respawn: killed PID automatically revived with new PID in ~1.1s.
    3. Port 8443 HTTPS listener fully restored post-kill.
    4. Concurrency scaling: 20 concurrent workers evaluated policy decisions in 1057 ms (~52.8 ms/decision).
    5. Simulated total control plane outage: confirmed port 8443 closed.
    6. Safe commands permitted offline in < 200 ms (Offline-First Zero-Trust).
    7. Workspace boundary containment strictly enforced offline (`ExitCode: 1`, fail-secure).
    8. Enterprise Audit/Shadow mode operable offline (permitted with shadow warning, `ExitCode: 0`).
    9. Service reconnection and telemetry resumption verified.
    10. JSON telemetry output mode (`-Json`) fully operational for headless CI/CD.
- [x] **Task 4: JIRA Stories & Central MVP Deployment Documentation**
  - Created `JIRA_STORIES.md`: Comprehensive product backlog covering 9 completed agile epics (23 user stories/bugs with acceptance criteria and security rationales) plus 5 future enhancement epics (10 backlog stories spanning visual policy authoring, SPIRE hardware attestation, eBPF/Landlock kernel sandboxing, Cloud KMS notarization, and LLM prompt injection detection).
  - Created `MVP_DEPLOYMENT.md`: Central, production-grade enterprise deployment guide with step-by-step instructions for Windows/Linux supervisors, systemd units, 1-click onboarding, pre-flight diagnostics, phased rollout strategy (Shadow vs Enforce), and emergency incident response.
  - Synchronized `PROJECT_MAP.md`.
- [x] **Task 5: Root README Enhancement: SPIFFE, TOFU & Production Governance**
  - Updated `README.md` with complete architectural representation of SPIFFE Workload Identities, Binary Image Attestation (SHA-256), and Ephemeral Scoped On-Behalf-Of (OBO) JWTs.
  - Added dedicated section `## 🆔 Cryptographic Workload Identity & Attestation (SPIFFE)` covering SPIFFE URIs (`spiffe://bap.internal/app/{app_id}/instance/{instance_id}`), 5-stage identity resolution pipeline, dual-identity binding (Operator + Workload), and just-in-time credential injection.
  - Added dedicated section `## 🔒 Secure Client Communication: TOFU to Enterprise Production` explaining how the Control Plane only communicates with verified clients, Trust-On-First-Use (TOFU) in local dev, transition to strict CI/CD cryptographic whitelisting in production, Mutual TLS (mTLS), One-Time Code (OTC) onboarding, and localhost administrative isolation.
  - Added high-impact **Dev vs. Production Governance Matrix** comparing attestation, transport security, enrollment, policy modes, admin access, and credential lifetimes.
  - Updated Mermaid architecture topology with mTLS verified channels, attestation flows, Model Context Protocol (`bapmcp`), OS-level process sandboxing (Job Objects/namespaces), and Python SDK agent integration.
- [x] **Task 6: High-Concurrency Agent Fleet Scaling (35+ Agents)**
  - Enhanced `run_agent_demo.bat` to accept command line arguments (`%*`), enabling instant execution via `run_agent_demo.bat 35` or `run_agent_demo.bat --count 35`.
  - Updated `demo_live_agents.py` with full parameter support (`fleet_size`, `--count`, `-n`, `--mode`, `--headless`).
  - Added interactive scale selection highlighting the 35-agent high-concurrency mode alongside the baseline 5-agent demo.
  - Implemented `MASTER_AGENT_ROSTER` with 40 distinct enterprise agent personas (unique roles, app IDs, operators, prompts).
  - Added background heartbeat management for Claude Code sessions so all 35 agents pulse simultaneously on the Live Workload Radar and Activity Inspector.
  - Dynamic scaling across lifecycle stages: terminates ~25% of the fleet in Stage 2, launches multiple replacements in Stage 3, and cleanly tears down all 35 sessions in Stage 4.
- [x] **Task 7: BAP-200 — Make BAPEdge the Sole Executor for Protected Agent Actions (P0)**
  - Established **Broker-Owned Execution** as the definitive BAP enforcement model across Claude Code, GitHub Copilot CLI, MCP, and Python SDK.
  - Added cryptographic **Execution Receipts** (`ExecutionReceipt` struct) recording `request_hash`, `identity`, `delegation`, `policy_version`, `sandbox_profile`, `session_id`, `timestamp`, and `result`.
  - Added integer process `exit_code` capture to `sandbox.RunSandboxedCommandWithExitCode`.
  - Implemented Claude Code command rewriting via `updatedInput` in `cchook/interceptor.go`: allowed commands are rewritten to `bapedge.exe exec ...`, ensuring Claude Code runs BAPEdge as sole broker, guaranteeing **exactly-once execution** inside the sandbox with zero duplicate native runs.
  - Implemented strict **Anti-Tampering Invariants**: any agent tool (`Write`, `Edit`, `Bash`, `Python`) attempting to delete, overwrite, rename, or modify `.claude/`, `policy.cedar`, `.bap/`, or BAP binaries is denied with `DENIED_TAMPER` (zero side effects).
  - Implemented **Correlated Risk Events**: sequential evasion attempts within a session are tracked in `.bap/risk_state.json`, escalating session threat level (`LOW` -> `ELEVATED` -> `CRITICAL`) and transmitting correlated risk warnings.
  - Authored comprehensive test suite `tests/test_bap200_sole_executor.py` verifying all 9 acceptance criteria (100% pass).
  - Created architectural specification `docs/EXECUTION_MODEL.md`.
- [x] **Task 8: BAP-200A — Safe Broker Handoff and Windows Containment Boundary (P0) — COMPLETE**
  - **Structured Base64 Command Handoff**: Interceptor encodes commands using `--cmd-b64 <base64>` during both `bapedge check` and `updatedInput` rewrite. Completely eliminates shell quote-stripping, backslash mangling, and host shell argument parsing issues.
  - **Windows Restricted Token Containment**: Implemented `CreateRestrictedProcessToken()` using `CreateRestrictedToken` (`DISABLE_MAX_PRIVILEGE`), stripping all administrative, debug, and high-privilege tokens (`SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, `SeSecurityPrivilege`, etc.) down to standard traverse check rights (`SeChangeNotifyPrivilege`).
  - **Windows Job Object Process Sealing**: Implemented `CreateRestrictedJob()` and `AssignProcessToJob()` with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`, guaranteeing that process trees cannot leave orphaned child processes.
  - **Complex Shell Operator Validation**: Tested output redirection (`>`, `>>`, `2>&1`), pipelines (`|`), command chaining (`&&`, `||`, `;`), and substitution (`$(...)`) across safe developer executions and malicious evasion/traversal blocks.
  - **Full Test Suite & Cryptographic Receipts**: Expanded `tests/test_bap200_sole_executor.py` to 15 comprehensive automated tests (100% pass). Cryptographic receipt reflects `sandbox_profile: "windows-restricted-token"`.
  - **Master Suite Regression**: Full regression in `run_all_tests.bat` passed cleanly (32/32 tests passed, Exit Code 0).
- [x] **Task 9: Epic 15 — CIO Agent Command Center MVP (BAP-210 to BAP-215) — COMPLETE**
  - **BAP-210 (Cockpit Consolidation)**: Made React dashboard (`/dashboard/`) the sole supported cockpit. Redirected legacy `/inspector.html` and `/inspector_v2.html` via HTTP 302 and meta-forwarders. Mounted compiled React bundle directly in `bapcontrolplane` on port 8443, enabling single-port access.
  - **BAP-211 (Live Agent Mission View)**: 3-column command center (`360px 1fr 400px`). Auto-sorts fleet cards by threat level (`CRITICAL` -> `ELEVATED` -> `HEALTHY` -> `REVOKED`) to surface highest-risk workloads immediately. Shows operator, agent role, prompt, tool activity, counters, and presence.
  - **BAP-212 (Prompt-to-Action Timeline)**: Vertical narrative timeline mapping human intent -> actions -> risk escalation -> administrative interventions. Includes expandable command drawer with duration, exit codes, and execution receipt previews.
  - **BAP-213 (Closed-Loop Stop and Revoke)**: Live CISO controls with instant visual state transitions (`Active → Stopping → Stopped`), real process termination (`taskkill` / `SIGKILL`), permanent revocation, and instant restoration. Displays Merkle hash-chain status (`VALID`).
  - **BAP-214 (Deterministic Executive Demo Scenario)**: Created `demo_executive.py` with 3 governed agents (Carol Zhang / Healthy, Bob Miller / Single Policy Denial, Eve Mallory / Sequential Evasions escalating to Critical). Executes in <15 seconds with zero stale state. Created 1-click Windows launcher `run_executive_demo.bat`.
  - **BAP-215 (Executive Polish & Hardening)**: Modern dark command-center aesthetic, real-time pulse dots, crisp badges, automated test suite `tests/test_executive_demo.py` (5/5 tests passing 100%). Master regression suite in `run_all_tests.bat` verified 32/32 tests passing.
- [x] **Task 10: Epic 30 — Unified CLI Parity, Cross-Folder HITL & Supply-Chain Governance (BAP-545, BAP-546, BAP-547) — COMPLETE**
  - **BAP-547 (Universal CLI UX & Lifecycle Command Consistency)**:
    - Standardized `start`, `stop`, `status`, `restart`, `enable`, `serve`, and `help` commands across all four BAP binaries (`bapedge`, `bapcontrolplane`, `bapgateway`, `bapmcp`).
    - Zero-surprise invocation: running with no arguments or `--help` prints formatted command guide instead of starting unexpected servers or freezing on stdin.
    - 100% backward compatibility: passing flags directly (e.g. `bapcontrolplane -port 8080`, `bapgateway -port 9090`) defaults to `start`, ensuring zero regression across automated test suites, scripts, and CI/CD pipelines.
    - Cross-platform process management: `proc_windows.go` (Win32 `OpenProcess`, `GetExitCodeProcess`, `CREATE_NO_WINDOW`, `taskkill`) and `proc_unix.go` (`syscall.Kill`, `Setpgid`) for reliable background process detachment and process-tree termination.
    - Interactive terminal detection in `bapmcp`: `isTerminal(os.Stdin)` shows mounting instructions for Claude Code, Antigravity, Cursor; piped execution runs stdio JSON-RPC.
  - **BAP-546 (Enterprise Multi-Scope Cross-Folder Mutation Governance)**:
    - Read-only inspection commands (`cat`, `ls`, `dir`, `git status`) traversing sibling repositories outside the project root are natively permitted under Cedar Rule 2 without friction.
    - Mutating or destructive operations (`write`, `delete`, `tamper`, output redirection) outside workspace boundaries trigger interactive Human-in-the-Loop (HITL) step-up escalation (`[O] Once | [S] Session | [P] Project | [G] Global | [D] Deny`).
    - Multi-scope persistence across Session (`.bap/approvals_<session_id>.json`), Project (`<workspace>/.bap/project_permissions.json`), and Global (`~/.bap/global_permissions.json`) stores.
    - CLI tools: `bapedge trust`, `bapedge untrust`, and `bapedge permissions`.
  - **BAP-545 (Supply-Chain Corporate Mirror Injection & Canary Defense)**:
    - Automatically injects corporate mirror configurations for Maven (`.bapstate/mirrors/settings.xml`), npm (`.bapstate/mirrors/.npmrc`), and pip (`.bapstate/mirrors/pip.ini`).
    - Cedar Rule 6: strictly blocks public repository bypass flags (`--index-url`, `--registry`, `-DremoteRepositories`).
    - Cedar Rule 7: corporate canary honeytoken tripwire defense.
  - **Test Suite Verification**: Verified with 100% pass across `tests/test_hitl_and_supply_chain.py` (15/15), `tests/test_control_plane.py` (100%), `tests/test_bap200_sole_executor.py` (15/15), and `tests/test_bap_534_535_538.py` (4/4).

- [x] **Task 11: Epic 29 Completion — BAP-536, BAP-537, BAP-539 (P1, P2 & Remaining Backlog) — COMPLETE**
  - **BAP-536 (Standing Adversarial Regression & Continuous Add-on Scanning Suite - P1)**:
    - Built comprehensive threat scanner engine `bap-edge/internal/scanner/addon_scanner.go` auditing skills, system instructions, MCP configs, and YAML/markdown definitions for instruction overrides, jailbreaks, prompt injection, base64 obfuscated reverse shells, supply chain bypass (`--index-url`, `--registry`), and content drift.
    - Added CLI command `bapedge scan <dir> [--fail-on <severity>] [--json] [--fix]` in `bap-edge/cmd/scan.go`.
    - Created standing CI/CD runner `scripts/run_adversarial_regression.ps1` and `run_adversarial_regression.bat` (pure ASCII, Windows PowerShell 5.1 and cp1252/UTF-8 safe).
    - Authored test suite `tests/test_bap_536_adversarial_scanner.py` (7/7 tests passing in 0.38s).
  - **BAP-537 (Tamper Resistance & Tiered Fail-Closed Quarantining - P2)**:
    - Implemented File-Integrity Monitoring (FIM) and local quarantine detection in `bap-edge/internal/fim/fim.go`.
    - Integrated fail-closed tamper checking into `bapedge exec` and `bapedge watch`: blocks execution immediately if hooks are modified, deleted, or quarantined.
    - Extended Central Control Plane agent registry with `StatusQuarantined`, `QuarantineTarget`, `UnquarantineTarget`, and automatic silence quarantine (after 9s silence threshold).
    - Wired grant rejection (`403 Forbidden`, `EndpointQuarantined`) for quarantined devices while preserving offline tiered fail-closed local test capability.
    - Authored test suite `tests/test_bap_537_tamper_and_quarantine.py` (4/4 tests passing).
  - **BAP-539 (Multi-Harness Adapters & SaaS Delegated Token Governance - Remaining P2)**:
    - Implemented cross-harness adapters in `bap-edge/internal/adapters`:
      - Cursor IDE (`cursor.go`): Configures `.cursorrules` and `.cursor/mcp.json`, routes terminal commands through `bapedge exec`, emits `CanonicalActivityEvent`.
      - Gemini CLI (`gemini.go`): Injects `GEMINI.md` invariants and emits `CanonicalActivityEvent`.
      - Browser Guard (`browser.go`): Playwright/CDP security evaluator enforcing domain allowlists (`*.corp.internal`, `internal.local`) and blocking sensitive credential file uploads (`.env`, `id_rsa`, private keys).
      - Activity Engine (`activity.go`): Normalized `CanonicalActivityEvent` schema and local/remote telemetry reporting.
    - Added CLI command `bapedge adapter [cursor|gemini|browser|emit]` in `bap-edge/cmd/adapter.go`.
    - Created transactional launchers: `run_cursor_bap.ps1` / `run_cursor_bap.bat`, `run_gemini_cli_bap.ps1` / `run_gemini_cli_bap.bat`.
    - Implemented SaaS Delegated Token Governance in `bap-controlplane/internal/authz/saas_tokens.go` and REST API handlers in `handlers.go` (`POST /api/v1/saas/tokens/bind`, `POST /api/v1/saas/tokens/verify`, `GET /api/v1/saas/tokens`): binds third-party OAuth tokens to attested BAP sessions, strictly rejecting cross-session token reuse with 403 `SaaSTokenSessionBindingViolation`.
    - Authored test suite `tests/test_bap_539_multi_harness.py` (4/4 tests passing in 2.88s).
  - **Epic 29 Status**: All 10 user stories in `BAP-EPIC-29` are now **100% COMPLETE & VERIFIED**.

- [x] **Task 12: Keycard "Defining Auth for Agents" Review & Epic 32 Formulation — COMPLETE**
  - **Comprehensive Architectural Review**:
    - Analyzed Keycard.ai's "Defining Auth for Agents" article ([Ian Livingstone, Oct 2026](https://www.keycard.ai/blog/defining-auth-for-agents/)).
    - Mapped the 5 critical gaps in Keycard's model:
      1. *The Bypass Fallacy*: Unmediated subshells, raw TCP sockets, or unsetting `HTTP_PROXY` bypass application-layer proxies.
      2. *Ambient Disk Credential Discovery*: Merely bemoaning the Railway token incident without preventing file reads of `.env` or disk credentials.
      3. *Untrusted Intent Provenance*: Failure to cryptographically authenticate task intent, leaving agents vulnerable to prompt injection intent hijacking.
      4. *Downstream Credential Isolation*: How to broker task-scoped access to downstream services (Railway, AWS, Stripe) that only accept static keys without creating a compromised master-key vault.
      5. *Multi-Agent Attenuation*: Lack of formal mathematical monotonicity ($\text{Scope}_{\text{child}} \subseteq \text{Scope}_{\text{parent}}$) and cascading process tree termination.
  - **Epic 32 Creation in `JIRA_STORIES.md`**:
    - `BAP-560`: Multi-Tier Anti-Bypass Enforcement Engine (Zero Unmediated Egress & OS-Level Sandboxing) [P0]
    - `BAP-561`: Immutable Intent Attestation & Anti-Drift Task Binding [P0]
    - `BAP-562`: Ambient Credential Shielding, Disk Token Virtualization & Canary Honeytokens [P1]
    - `BAP-563`: Ephemeral JIT Token Brokering & Single-Use Grant Exchange Gateway [P1]
    - `BAP-564`: Cryptographic Multi-Agent Delegation Attenuation & Lineage Forensics [P1]
    - `BAP-565`: Task-Scoped HITL Step-Up Escalation with Approval Fatigue Prevention [P2]
  - **Artifact Created**: Detailed review and architectural blueprint saved to [`keycard_auth_for_agents_review_and_impl_plan.md`](file:///c:/Users/User/.gemini/antigravity/brain/1f6ca452-b244-4d51-90cb-1d44b9f8a1cd/keycard_auth_for_agents_review_and_impl_plan.md).

- [x] **Task 13: Epic 32 Implementation — BAP-560 through BAP-564 (100% COMPLETE & VERIFIED)**
  - **BAP-560 (Anti-Bypass Enforcement Engine - P0)**:
    - Implemented `bap-edge/internal/antibypass/antibypass.go` and `antibypass_test.go` (4/4 tests pass).
    - Detects unmediated raw socket commands (`nc`, `socat`), direct TCP invocations, and protected env var tampering (`HTTP_PROXY`, `BAP_SESSION_ID`).
    - Wired pre-flight anti-bypass gate into `bap-edge/cmd/exec.go`.
    - Added CLI command `bapedge antibypass [check|status]`.
  - **BAP-561 (Immutable Intent Attestation & Anti-Drift Task Binding - P0)**:
    - Implemented `bap-controlplane/internal/intent/intent.go` and `intent_test.go` (3/3 tests pass).
    - `IntentManager` creates HMAC-SHA256 signed task attestations (`AttestTaskIntent`) and verifies actions against intent (`VerifyActionAgainstIntent`).
    - Exposed REST endpoints on Control Plane: `POST /api/v1/intent/attest`, `POST /api/v1/intent/verify`, `GET /api/v1/intent/`.
    - Blocks prompt injection domain drift, environment escalation, and destructive operations with 403 `IntentDriftViolation`.
  - **BAP-562 (Ambient Credential Shielding & Canary Honeytokens - P1)**:
    - Implemented `bap-edge/internal/shield/vault.go` and `vault_test.go` (3/3 tests pass).
    - Solves Railway token incident: `ScanWorkspaceCredentials` scans for standing disk credentials, `VirtualizeCredentials` redacts production keys in non-prod runs, and `PlantCanary` / `InspectForCanaryTrigger` seeds honeytoken tripwires (`.bap_canary_token`).
    - Added CLI command `bapedge shield [scan|plant-canary|check-canary]`.
  - **BAP-563 (Ephemeral JIT Token Brokering & Single-Use Grant Exchange Gateway - P1)**:
    - Implemented `bap-gateway/internal/tokenexchange/exchange.go` and `exchange_test.go` (2/2 tests pass).
    - Single-use grant burning (`BurnGrantOnce`) rejects token replays with 401 `GrantAlreadyBurned`.
    - Downstream credentials minted with 5-minute TTLs (`BrokerDownstreamCredential`) for approved services (Railway, AWS, GitHub, Salesforce, Stripe).
    - Exposed REST endpoint `POST /api/v1/egress/exchange` in `bap-gateway/main.go`.
  - **BAP-564 (Multi-Agent Attenuation & Lineage Forensics - P1)**:
    - Implemented mathematical monotonic delegation attenuation ($\text{Scope}_{\text{child}} \subseteq \text{Scope}_{\text{parent}}$) in `bap-controlplane/internal/authz/grants.go` and `grants_test.go` (10/10 tests pass).
    - Attempts by child subagents to broaden scopes or widen resource paths are rejected with 403 `PrivilegeEscalationBlocked`.
    - Macaroon caveat-chaining, lineage tracking (`orchestrator -> subagent-1`), and fleet cascading kill switch (`RevokeGrant`).
  - **BAP-565 (Task-Scoped HITL Step-Up Escalation with Approval Fatigue Prevention - P2)**:
    - Implemented `bap-controlplane/internal/hitl/escalation.go` and `escalation_test.go` (3/3 tests pass).
    - Contextual escalation tracking with automatic risk classification (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
    - Approval Fatigue Throttling: suppresses rapid duplicate requests within 30-second cooldown window with HTTP 429 (`ApprovalFatigueThrottled`).
    - Enforces maximum escalation limit per task (defaults to 5 attempts) to prevent abuse.
    - Single-task short-lived ephemeral grant minting upon approval (5-minute TTL) with zero permanent authority expansion.
    - Exposed REST endpoints on Control Plane: `POST /api/v1/escalation/request`, `POST /api/v1/escalation/resolve`, `GET /api/v1/escalation/requests`, `GET /api/v1/escalation/{id}`.
    - Added CLI command in `bap-edge`: `bapedge stepup [request|status|list]`.
  - **Fleet Binaries Rebuilt & Synchronized**:
    - Recompiled `bapedge.exe`, `bapcontrolplane.exe`, `bapgateway.exe`.
    - Synchronized via `update_binaries.ps1` and audited via `scripts/check_stale_copies.ps1 -Fix` (72/72 assets in exact sync).
  - **Master Automated Test Suite (`tests/test_bap_epic32_agent_auth.py`)**:
    - Authored end-to-end Python test suite covering all 6 stories (`BAP-560` through `BAP-565`) with isolated Control Plane and Gateway PEP daemon instances.
    - Verified: 6/6 tests passing in 3.43s (100% OK).
  - **Epic 32 Status**: All 6 user stories in `BAP-EPIC-32` are now **100% COMPLETE & VERIFIED**.


