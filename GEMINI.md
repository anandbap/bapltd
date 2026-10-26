# BAP Zero-Trust Policy & Shell Governance for Antigravity (Governed Session: sess-antigravity-cli-46ced79e)

This workspace is actively governed by the BAP Zero-Trust Local Trusted Daemon (bapedge.exe).

## Mandatory Execution Rules
1. **Always Use BAP Edge Execution Broker**:
   - All shell executions MUST run through bapedge.exe exec:
     apedge.exe exec "<command>"
   - Never run raw, ungoverned shell commands on the host machine.
2. **Zero-Trust Policy Enforcement**:
   - Commands are evaluated against Cedar invariants before execution.
   - If a command is denied, inspect the suggestion in the structured response.
3. **Identity & Audit Logging**:
   - LTD_SOURCE=antigravity
   - BAP_SESSION_ID=sess-antigravity-cli-46ced79e
4. **Developer Override & Agent Immunity**:
   - Autonomous agents are **STRICTLY FORBIDDEN** from activating `bapedge dev-override on`. That command requires interactive human developer authorization.
   - In audit mode, violations are logged without blocking execution; observe audit warnings.