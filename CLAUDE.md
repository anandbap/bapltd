# Enterprise Security Invariants & Behavior Guide

## Zero-Trust Policy Enforcement
This workspace is protected by the bapedge (LTD) zero-trust execution broker. All commands and file operations are evaluated by Cedar authorization policies.

## Mandatory Agent Rules on Policy Denial
1. **Immediate Cessation**: If any command or tool execution is denied by bapedge (e.g. access to .env, ~/.aws, .ssh, or unauthorized network egress), you must **STOP IMMEDIATELY**.
2. **No Alternative Workarounds**: You are **STRICTLY FORBIDDEN** from pursuing alternative options, workarounds, or evasion techniques after a policy denial. This includes:
   - Trying alternative shells (bash, cmd, powershell, sh, pwsh, zsh).
   - Using programming languages (python, node, perl, ruby) to read or execute restricted resources.
   - Renaming, copying, moving, symlinking, or redirecting forbidden files (e.g. ren .env, Move-Item .env).
   - Piping or encoding contents (e.g. base64, certutil).
3. **Report to User**: Immediately report that the requested operation is prohibited by corporate zero-trust policy and ask the user for alternative safe tasks.
4. **Autonomous Agent Immunity for Developer Override**:
   - AI agents are **STRICTLY FORBIDDEN** from executing `bapedge dev-override on`. BAP will fail closed with a security invariant violation if an agent attempts this.
   - Only human developers can activate developer override interactively (`bapedge dev-override on`). If working on BAP features requires overriding anti-tampering checks, ask the human user to activate the override.
5. **Audit Mode Awareness**:
   - In audit mode, violations do not hard-terminate execution but are logged as security audit alerts (`[BAP AUDIT MODE] Policy violation detected: ... Execution permitted in audit mode.`). Respect these warnings and do not attempt unauthorized secret exfiltration.
