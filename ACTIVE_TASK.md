# Active Task: Claude Concurrency, Infosec Sanitization & Build Stabilization

## Sprint Goal
- Enable developers to launch multiple concurrent Claude Code sessions in the same directory and across different directories without mutex locks or crashes.
- Prevent corporate InfoSec alerts by eliminating all false-positive trigger strings (`evil.com`, `malware`, `payload.exe`) from default test runs.
- Isolate all runtime artifacts into `.bap/` instead of polluting workspace roots.
- Ensure end-to-end multi-platform build and automated test suites pass 100%.

---

## Completed & Fixed

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


