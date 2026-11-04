# BAP Native Agent Plugin Architecture (BAP-806)

## 1. Overview & Mission

The **BAP Native Agent Plugin Framework** extends BAP (Agent Watch) to support native plugin architectures for **Claude Code** and **GitHub Copilot** alongside existing standalone hooks.

This provides an additive, standardized integration layer into the **BAP Edge Local Trusted Daemon (`bapedge`)** while preserving all existing security invariants:
* No duplicated policy evaluation engines (Cedar remains the single source of truth).
* Full preservation of SPIFFE/SVID, mTLS, session isolation, and Zero Standing Privilege (ZSP).
* Seamless coexistence between native plugins and standalone workspace configuration hooks.

---

## 2. Multi-Layer Defense-in-Depth Model

A fundamental security principle of BAP is that **a user-space agent plugin alone is not an impenetrable security boundary**. To protect against circumvention, BAP organizes enforcement into 5 defensive layers:

```
┌────────────────────────────────────────────────────────────────────────┐
│ Layer 1: Agent Harness Interception (Cooperative Application Layer)    │
│   ├─ Layer 1A: Native Agent Plugin (Claude Code / Copilot Agent Plugin)│
│   └─ Layer 1B: Standalone Configuration Hook (.claude/settings.json)   │
├────────────────────────────────────────────────────────────────────────┤
│ Layer 2: Execution Broker & Kernel Sandboxing (Host OS Layer)          │
│   └─ bapedge exec / Windows Restricted Token / Namespace Sandboxing    │
├────────────────────────────────────────────────────────────────────────┤
│ Layer 3: Anti-Tamper & Credential Shielding (Storage / FIM Layer)      │
│   └─ Ambient Credential Shield (.env, .ssh) / Canary Traps / Rollback  │
├────────────────────────────────────────────────────────────────────────┤
│ Layer 4: Continuous Health & Telemetry (Attestation Layer)             │
│   └─ Agent Watch LTD Discovery / Callback Heartbeats / Drift Probes    │
├────────────────────────────────────────────────────────────────────────┤
│ Layer 5: Cryptographic Identity & Zero-Trust Egress (Network Layer)    │
│   └─ SPIFFE/SVID / mTLS Attestation / BAP Gateway PEP / STS Revocation │
└────────────────────────────────────────────────────────────────────────┘
```

### Are Plugins and Hooks Both Layer 1 or Different Layers?

**They are two distinct sub-layers within Layer 1 (Agent Harness Interception):**

* **Layer 1A: Native Agent Plugin (In-Harness Extension)**
  * **Role:** Operates inside the agent framework's native extension architecture (Anthropic Claude Code Plugin, GitHub Copilot Agent Plugins 1.0).
  * **Strengths:** Standard vendor packaging, cross-platform path resolution via `${CLAUDE_PLUGIN_ROOT}`, IDE compatibility (VS Code, JetBrains), and structured PreToolUse blocking before execution.
  * **Limitations:** Lives in user space; can be bypassed if the user launches the CLI with `--bare` / safe mode or edits local plugin configuration.
* **Layer 1B: Standalone Configuration Hook (Local Policy Interception)**
  * **Role:** Operates via workspace or global configuration files (e.g. `.claude/settings.json`, `.claude/managed-settings.json`, wrapper scripts).
  * **Strengths:** Directly bound to project workspace roots; fires even if vendor plugin packaging is disabled or unsupported.
  * **Limitations:** Requires file-level configuration in workspace directories.

**Coexistence Guarantee:** When both Layer 1A and Layer 1B are installed on the same workstation, BAP's **Deduplication Engine** coordinates invocations using an idempotency key `(session_id, command_hash, timestamp_window)`. Duplicate tool execution requests within a 5-second window return the cached authorization receipt rather than triggering duplicate evaluations or duplicate audit entries.

---

## 3. Supported Agent Surfaces & Capabilities

| Agent Client | Execution Surface | Interception Mechanism | Capability |
| :--- | :--- | :--- | :--- |
| **Claude Code** | Terminal CLI | Layer 1A Native Plugin & Layer 1B Hooks | Blocking (`PreToolUse`), Telemetry (`SessionStart`, `PostToolUse`, `Stop`) |
| **Claude Code** | VS Code Extension | Layer 1A Native Plugin | Blocking (`PreToolUse`), Workspace Telemetry |
| **Claude Code** | JetBrains IDE | Layer 1A Native Plugin | Blocking (`PreToolUse`), Lifecycle Telemetry |
| **GitHub Copilot** | Copilot CLI | Layer 1A Agent Plugin & Layer 1B Wrapper | Blocking (`preToolExecution`), Telemetry (`sessionStart`, `sessionEnd`) |
| **GitHub Copilot** | VS Code Agent Mode | Layer 1A Agent Plugin 1.0 | Blocking (`preToolExecution`), Structured Denial Directives |

---

## 4. Threat & Bypass Analysis: What the Plugin Can and Cannot Block

### What the Plugin CAN Block
* Any tool invocation attempted through the agent framework (`Bash`, `Write`, `Edit`, `View`) before the command is spawned.
* Modifications to protected enterprise assets (e.g., `policy.cedar`, `.bap/`, BAP binaries).
* Access to ambient credentials (`.env`, `~/.ssh/id_rsa`, `~/.aws/credentials`).
* Unauthorized file mutations outside the approved workspace root without human step-up authorization (`bapedge trust`).

### What the Plugin CANNOT Block (And How BAP Closes the Gap)

| Potential Bypass Route | Why the Plugin Alone Cannot Block It | How BAP Enforces the Boundary |
| :--- | :--- | :--- |
| **Manual Terminal Execution** | Developer types `rm -rf /` or `curl <evil>` directly in PowerShell/Bash outside the AI agent. | **Layer 2 (Execution Broker):** Un-brokered commands do not receive SPIFFE tokens or sandboxed privileges. Corporate proxy/gateway blocks unauthenticated egress. |
| **Plugin Disablement** | Developer starts agent with `--bare`, `--no-plugins`, or deletes plugin manifest. | **Layer 4 & Layer 5 (Attestation & Health):** Agent Watch detects the running agent process (`claude-code`) while the hook heartbeat is missing. Health transitions from `Active` to `Degraded`/`Missing`, triggering Control Plane token revocation. |
| **Unmonitored MCP Tools** | Agent invokes a tool on an unregistered custom MCP server. | **Layer 3 & Layer 2:** File writes and shell calls still run through the OS sandbox token; file system modifications to sensitive paths trigger FIM alerts. |
| **Direct API Calls (Python/cURL)** | Script directly calls Anthropic/OpenAI API endpoints. | **Layer 5 (PEP Gateway):** Corporate egress gateway requires signed JWT from `bapedge attest`. Raw sockets without attestation are rejected. |

---

## 5. Lifecycle Management & Health Telemetry

BAP distinguishes four observable lifecycle states to prevent false confidence:

```
[Agent Discovered] ──> Executable found on system or process tree
       │
[Plugin Installed] ──> Native plugin manifest exists in workspace
       │
  [Hook Active]    ──> Callback event demonstrably received by bapedge
       │
[Enforcement Verified] ──> Synthetic or live policy decision confirmed (ALLOW/DENY applied)
```

### Observable Plugin States

1. **`Active`**: Plugin is installed, hook callbacks are observed within the freshness window, and policy enforcement has been verified.
2. **`Installed`**: Plugin manifest is registered, but no hook callbacks have executed yet.
3. **`Degraded`**: Agent executable is actively running, but plugin hooks have stopped reporting callbacks (signal of tampering or disablement).
4. **`Disabled`**: Plugin has been explicitly deactivated in configuration.
5. **`Missing`**: Agent client is discovered on the workstation, but no BAP native plugin is installed.
6. **`Unsupported`**: Agent client version does not support native plugin architecture.
7. **`Unknown`**: Insufficient telemetry to determine state.

---

## 6. CLI Management Commands

All plugin operations are managed through the unified `bapedge` CLI:

```bash
# List all discovered agent surfaces and installed plugins
bapedge plugin list

# Inspect health state, verification status, and active defense layers
bapedge plugin status

# Install native plugin into the workspace (Claude Code or Copilot)
bapedge plugin install claude
bapedge plugin install copilot

# Verify end-to-end policy enforcement via synthetic probe (Pass/Fail check)
bapedge plugin verify claude
bapedge plugin verify copilot

# Remove plugin registration cleanly without affecting standalone hooks
bapedge plugin uninstall claude

# Display the 5-layer Defense-in-Depth status matrix
bapedge plugin layers
```

---

## 7. Zero Standing Privilege (ZSP) Preservation

Native plugins never store credentials, static tokens, or private keys:
1. When a tool call is intercepted, the plugin adapter delegates to `bapedge`.
2. `bapedge` requests an ephemeral, task-scoped grant bound to the current `session_id`.
3. If an action is denied or anomalous behavior is detected, the grant expires immediately.
4. Revocation caches sync automatically, preventing replay of authorization tokens across sessions.

---

## 8. Migration & Rollback Guide

### Upgrading from Standalone Hooks to Native Plugins
Existing installations using `.claude/settings.json` or `.copilot/mcp-config.json` require zero breaking changes:
1. Run `bapedge plugin install claude`.
2. Both Layer 1A (Plugin) and Layer 1B (Hook) operate simultaneously.
3. The deduplication cache ensures neither double-prompts nor double-audits occur.

### Rollback Procedure
If a vendor plugin framework introduces a regression:
1. Run `bapedge plugin uninstall claude`.
2. Layer 1B (Standalone Hook Guard) remains active and continues to enforce policy via `.claude/settings.json` without downtime.
