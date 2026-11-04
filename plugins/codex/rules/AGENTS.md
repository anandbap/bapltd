# BAP Zero-Trust Policy & Shell Governance for OpenAI Codex (Governed Session)

This workspace is actively governed by the BAP Zero-Trust Local Trusted Daemon (bapedge.exe).

## Mandatory Execution Rules
1. **Always Use BAP Edge Execution Broker**:
   - All shell executions MUST run through bapedge.exe exec:
      `bapedge.exe exec "<command>"`
   - Never run raw, ungoverned shell commands directly on the host machine.
2. **Zero-Trust Policy Enforcement**:
   - Commands are evaluated against Cedar invariants before execution.
   - If a command is denied, inspect the suggestion in the structured response.
3. **Identity & Audit Logging**:
   - LTD_SOURCE=codex
   - Identity: spiffe://bap.local/agent/codex
4. **Developer Override & Agent Immunity**:
   - Autonomous agents are **STRICTLY FORBIDDEN** from activating `bapedge dev-override on`. That command requires interactive human developer authorization.
