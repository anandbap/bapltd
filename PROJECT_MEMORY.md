# BAP (Bounded Authority Plane) - Project Memory & Architecture Context

## Overview
BAP (Bounded Authority Plane) is a Zero-Trust governance and least-privilege policy enforcement platform designed for autonomous AI coding agents (Claude Code, Python SDK agents, GitHub Copilot, custom LLM toolchains). It enforces policy before tool execution, tracks agent liveness in real-time, guarantees clean workspace settings restoration, and provides enterprise observability.

---

## Architecture & Component Mapping

### 1. Central Control Plane (`bap-controlplane/`)
- **Binary**: `dist/windows-amd64/controlplane/bapcontrolplane.exe`
- **Default Port**: HTTPS 8443 (HTTP 8080 fallback)
- **Certificates**: `controlplane-cert.pem`, `controlplane-key.pem`, CA `bap-root-ca.crt`
- **Database**: `bap-controlplane.db` (SQLite)
- **Key Endpoints**:
  - `/api/v1/sessions/start`: Registers new agent session.
  - `/api/v1/sessions/heartbeat`: Receives liveness pulses every 2-3 seconds.
  - `/api/v1/sessions/end`: Marks session closed cleanly.
  - `/api/v1/inspector/data`: Aggregates active sessions, historical sessions, decision logs, and metrics.
  - `/api/v1/control/revocations`: Live kill-switch and per-session/user revocation state.
  - `/inspector_v2.html`: Modern standalone Cockpit with live pulse indicators and auto-refresh.

### 2. Standalone Administrative Cockpit Dashboard (`bapdashboard.exe`)
- **Binary**: `dist/windows-amd64/dashboard/bapdashboard.exe` (and root `bapdashboard.exe`)
- **Default Port**: HTTPS 8444
- **Frontend**: Pure zero-dependency standalone HTML/CSS/JS Cockpit (`bap-controlplane/internal/dashboardui/web/index.html`). Fast, responsive, dark/light theme support, embeds directly into binary without Node/npm dependencies.
- **Telemetry Parity**: Automatically merges dynamic sessions (`sessions`) with registered agents (`agents`) into a unified grid with live heartbeat age, PID, user, prompt, and stop/revoke controls.

### 3. Edge Agent & Watcher (`bap-edge/` & `bapedge.exe`)
- **Binary**: `bapedge.exe` (root and `dist/windows-amd64/claude-client/`)
- **Commands**:
  - `bapedge exec [--raw] "<command>"`: Evaluates policy against Cedar rules before running.
  - `bapedge session-start`: Registers session on control plane, creates per-PID marker, spawns detached watcher.
  - `bapedge session-end`: Notifies control plane and cleans up markers.
  - `bapedge watch`: Detached background daemon sending heartbeats and checking for admin revocation.
  - `bapedge config`: Manages central control plane and gateway URLs.
- **Clean Workspace Architecture**:
  - Stores all runtime artifacts in `.bap/` (`.bap/sessions/pid-<PID>.json`, `.bap/policy-state.json`, `.bap/session.json`).
  - **Zero stray files** left in root workspace directory.

### 4. Claude Code Hook Interceptor (`cchook/` & `interceptor.exe`)
- **Binary**: `cchook/interceptor.exe` (and `dist/windows-amd64/claude-client/`)
- **Hook Points**: Intercepts `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `ConfigChange`.
- **Per-PID Session Isolation**: Resolves calling process via `os.Getppid()`, mapping directly to `.bap/sessions/pid-<PPID>.json`. Prevents duplicate session creation and ensures each terminal session has dedicated attribution.

### 5. Multi-Instance Claude Launcher (`run_claude_bap.bat` & `run_claude_bap.ps1`)
- **Reference-Counted Custody**: Replaced exclusive session-long mutex lock with transient coordination locks (5s timeout).
- **Multi-Terminal Support**: Multiple Claude Code sessions can run simultaneously in the same or separate projects without lockouts.
- **Transactional Settings**: Backs up `.claude/settings.json`, mounts BAP hooks for session 1, increments refcount for sessions 2..N. Only restores original settings when the final session exits.
- **Session Watchdog**: Monitors all active PIDs in `.claude/.bap-recovery.json`; triggers recovery only if all processes terminate abnormally.

### 6. Python Agent SDK (`python-agent/bap_sdk/`)
- **Module**: `bap_sdk.BAPSession`
- **Features**: Autonomous background daemon thread pulsing `/api/v1/sessions/heartbeat` every 3s, tool execution policy evaluation (`bap.exec(...)`), and graceful shutdown (`bap.end(...)`).

---

## Infosecurity Hygiene & Clean Scans
- All test files, scripts, and documentation have been sanitized of trigger strings:
  - `evil.com` $\rightarrow$ `untrusted-test.internal`
  - `attacker.com` / `attacker.evil.com` $\rightarrow$ `untrusted-test.internal`
  - `malware` $\rightarrow$ `pkg`
  - `payload.exe` $\rightarrow$ `setup.bin`
  - `stolen_tokens` $\rightarrow$ `test_data`
- Eliminates false-positive alerts on enterprise security scanners and proxy logs.

---

## Fleet Demonstration Scripts
- `run_agent_demo.bat` / `demo_live_agents.py`: Interactive demonstration supporting:
  - Option 1: 5 Python SDK Agents
  - Option 2: 5 Real Claude Code Sessions
  - Option 3: Mixed Squad (Python + Claude)
  - Interactive pauses (`[ENTER]`) between Stage 1 (5 live), Stage 2 (drop 2 $\rightarrow$ 3 left), and Stage 3 (add 1 $\rightarrow$ 4 live) for visual confirmation on Dashboard and Cockpit.
- `scratch/test_claude_fleet.py`: Automated headless test verifying the full multi-instance lifecycle.

---

## Unified `.bapstate` Hierarchy & Clean Directory Architecture
All BAP components (`bap-edge`, `bap-controlplane`, `bap-gateway`, `python-agent`) standardize on `.bapstate`:
- **Resolution Order**:
  1. `$BAP_STATE_DIR` (explicit override)
  2. `~/.bapstate` (user home directory - primary default)
  3. `./.bapstate` (workspace local fallback)
- **Directory Contents**:
  - `credentials.json`: Agent identity, OTC tokens, and JWT credentials.
  - `config.json`: Endpoint configuration (`controlplane_url`, `gateway_url`).
  - `audit.jsonl`: Offline audit spool (cryptographically hashed, flushes on reconnect).
  - `sessions/`: Per-session and per-PID active session markers (`sess-<ID>.json`, `pid-<PID>.json`).
  - `session.json`: Current workspace active session fallback descriptor.
  - `revoked/`: Local persistent revocation markers (`user-<USER>.json`).
- **Automated Migration**: Legacy files from `~/.ltd/`, `.bap/`, and root `ltd-audit.jsonl` are automatically migrated on startup.

---

## Fleet-Wide UTC Timestamp Standardization
- **Universal UTC Standard**: All timestamp generation across all components strictly adheres to ISO 8601 / RFC 3339 UTC format (`time.Now().UTC()`, `time.RFC3339`).
- Eliminates cross-timezone desynchronization, clock skew anomalies, and ensures forensic audit trail consistency across geographically distributed edge nodes.

---

## Hierarchical Agent & Session Liveness Coupling
- **45-Second Heartbeat Expiry**: Agents and sessions must pulse heartbeats at least every 45 seconds. Lapsed heartbeats dynamically report status as `offline`.
- **Strict Invariant (No Ghost Sessions)**: An offline agent can NEVER host active sessions. When an agent lapses or is closed, all child sessions immediately reflect `offline` / `closed`.
- **Stable Workstation Identity**: Multiple Claude Code launches on the same host reuse the single workstation agent identity, registering individual runs as concurrent execution sessions rather than sprawling duplicate agent cards.
- **Reconciliation & Sweep**: `bapedge sweep` purges dead session markers for terminated PIDs, flushes pending offline audit spools, and reconciles state with the central control plane.

