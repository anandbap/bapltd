# BAP Multi-Agent Lifecycle Hook & Interceptor Contract Specification

## 1. Executive Summary & Problem Statement

As the Bounded Authority Plane (BAP) expands across multiple autonomous AI coding agents (**Claude Code**, **OpenAI Codex CLI**, **Google Antigravity**, **GitHub Copilot**, and **Cursor IDE**), divergent hook implementations and stdout/stderr response schemas introduce severe regression risk.

A change intended for one agent (e.g. returning `{"continue": true}` for Codex) can inadvertently break another agent's telemetry or existing regression test assertions (which check `{"status": "ok"}`).

This document establishes the **Canonical Universal Hook Contract** for all BAP lifecycle hooks, interceptors, and background daemons.

---

## 2. Universal Hook Response Contract

Every lifecycle hook that completes successfully MUST return a unified JSON payload adhering to the **Universal Agent Schema**:

```json
{
  "status": "ok",
  "continue": true,
  "message": "Hook completed successfully"
}
```

### Invariant Rules
1. **`status: "ok"`** MUST ALWAYS be present for backward compatibility with existing Claude Code monitors, legacy test harnesses, and SIEM parsers.
2. **`continue: true`** MUST ALWAYS be present for modern lifecycle runners (such as OpenAI Codex CLI and Claude Code v2+), confirming that the prompt or tool execution is authorized to proceed.
3. **Denial / Policy Block**: If a tool is denied by Cedar policy, the hook MUST return:
   ```json
   {
     "status": "blocked",
     "continue": false,
     "decision": "DENY",
     "reason": "Cedar policy invariant violation: command unauthorized",
     "suggestion": "Request elevated scope or run with approved arguments"
   }
   ```
4. **Typed Go Struct**: Hook handlers in `cchook/interceptor.go` MUST serialize via a typed Go struct (`HookResponse`) and NEVER write raw, unvalidated JSON string literals.

---

## 3. Supported Agent Lifecycle Event Matrix

| Agent Workload | Interception Mechanism | Hook Config Location | Lifecycle Events Supported | Output Protocol |
|---|---|---|---|---|
| **Claude Code** | CLI Pre/Post Lifecycle Hooks | `.claude/managed-settings.json` or `.claude/settings.json` | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `SessionEnd` | `{"status":"ok","continue":true}` |
| **OpenAI Codex CLI** | Hook Configuration | `.codex/hooks.json` | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `Stop`, `SessionEnd` | `{"status":"ok","continue":true}` |
| **Google Antigravity** | Background Transcript Tailer + BAP MCP | `.gemini/antigravity/mcp/` & `transcript.jsonl` | File-tail `<USER_REQUEST>`, tool calls routed to `bapmcp` | JSON-RPC 2.0 (stdio) |
| **GitHub Copilot CLI** | Wrapper / Interceptor + State Tailer | `~/.copilot/session-state/*/events.jsonl` | `copilot_interceptor.go`, `user.message`, `assistant.message` | Process Exit Code & Merkle Audit |
| **Cursor IDE** | Workspace Rules & MCP Config | `.cursorrules` & `.cursor/mcp.json` | Prompt directive injection + `bapmcp` | JSON-RPC 2.0 (stdio) |

---

## 4. Lifecycle Event Specifications

### 4.1. `SessionStart`
* **Trigger**: When an agent session initializes.
* **Input Stdin**:
  ```json
  {
    "hook_event_name": "SessionStart",
    "session_id": "sess-workload-1234",
    "conversation_id": "conv-5678"
  }
  ```
* **BAP Action**:
  - Enrolls session with central Control Plane via `POST /api/v1/sessions/start`.
  - Creates local session marker in `.bap/session.json`.
  - Spawns background `bapedge watch` if not already managed by a launcher.
* **Output Stdout**:
  ```json
  {"status":"ok","continue":true}
  ```

### 4.2. `UserPromptSubmit`
* **Trigger**: Whenever the human operator submits a conversational prompt to the agent.
* **Input Stdin**:
  ```json
  {
    "hook_event_name": "UserPromptSubmit",
    "session_id": "sess-workload-1234",
    "prompt": "Fix database connection timeout bug"
  }
  ```
* **BAP Action**:
  - Sanitizes prompt for sensitive credentials (regex DLP).
  - Classifies intent (11 standard SOC categories: `BUG_FIX`, `SECURITY_AUDIT`, `DEPLOYMENT`, etc.).
  - Streams telemetry to `POST /api/v1/sessions/prompt`.
* **Output Stdout**:
  ```json
  {"status":"ok","continue":true}
  ```

### 4.3. `PreToolUse`
* **Trigger**: Immediately before the agent executes any tool or shell command.
* **Input Stdin**:
  ```json
  {
    "hook_event_name": "PreToolUse",
    "session_id": "sess-workload-1234",
    "tool_name": "bash",
    "tool_input": {
      "command": "git status"
    }
  }
  ```
* **BAP Action**:
  - Evaluates action against local Cedar policy in `<1.5ms`.
  - In Enforce mode: Blocks prohibited commands (e.g. `curl`, access to `.env` / credentials).
  - Rewrites authorized commands through `bapedge.exe exec --cmd-b64 ...`.
* **Output Stdout (Allowed)**:
  ```json
  {
    "continue": true,
    "status": "ok",
    "tool_input": {
      "command": "bapedge.exe exec --source <agent> --session-id <id> --cmd-b64 <b64>"
    }
  }
  ```

### 4.4. `SessionEnd` / `Stop`
* **Trigger**: When the agent workload shuts down or is terminated via `Ctrl+C`.
* **Input Stdin**:
  ```json
  {
    "hook_event_name": "SessionEnd",
    "session_id": "sess-workload-1234"
  }
  ```
* **BAP Action**:
  - Notifies Control Plane via `POST /api/v1/sessions/end`.
  - Cleans up `.bap/session.json` marker file.
  - Flushes audit event buffer to disk or remote ledger.
* **Output Stdout**:
  ```json
  {"status":"ok","continue":true}
  ```

---

## 5. Architectural Quality Gates to Prevent Future Breaks

To maintain code stability as features expand, the following safeguards are enforced:

### Gate 1: Strongly Typed Serialization (Go)
All hook responses MUST use `cchook.EmitHookResponse(status, continueFlag, msg)` backed by the `HookResponse` struct. Raw `os.Stdout.WriteString("{\"status\":...}")` statements are prohibited.

### Gate 2: Invariant Golden Contract Tests (Go)
Every pull request runs `cchook/contract_test.go`, which verifies that mock payloads for Claude, Codex, Copilot, and Antigravity return conforming JSON with both `"status":"ok"` and `"continue":true`.

### Gate 3: Fast Scenario-Specific Python Suite (`tests/test_agent_lifecycle_matrix.py`)
Developers can run a fast, targeted 2-second test suite covering all 5 agent lifecycle scenarios locally before pushing:
```bash
python -m unittest tests.test_agent_lifecycle_matrix
```

### Gate 4: Zero Flakiness Principle (Fail-Safe Defaults)
If an unknown agent or new lifecycle hook event is encountered, the interceptor MUST default to:
1. Emitting an audit log entry.
2. Returning `{"status":"ok","continue":true}` (or failing closed if in strict Enforce mode).
3. Never hanging or printing unformatted text to stdout that corrupts agent JSON parsers.
