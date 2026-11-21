# BAP Zero-Trust Policy & Enterprise Governance for Antigravity

This workspace is actively governed by the BAP Zero-Trust Local Trusted Daemon (`bapedge.exe`).

## Mandatory Execution Rules
1. **Always Use BAP Edge Execution Broker with Restricted Shell**:
   - All shell executions MUST run through `bapedge.exe exec --shell bapsh`:
     `bapedge.exe exec --shell bapsh "<command>"` (or `bapedge.exe bapsh -c "<command>"`)
   - **Shell Declaration (REQUIRED)**: Always declare the shell type explicitly using `--shell` so bapsh routes to the correct engine without heuristics:
     - Bash / sh / zsh commands:  `bapedge exec --shell bash "<command>"`  or  `bapedge bapsh -c "<command>" --shell-hint bash`
     - PowerShell commands:       `bapedge exec --shell pwsh "<command>"`  or  `bapedge bapsh -c "<command>" --shell-hint pwsh`
     - Windows cmd.exe commands:  `bapedge exec --shell cmd "<command>"`   or  `bapedge bapsh -c "<command>" --shell-hint cmd`
   - Examples by task:
     - `bapedge exec --shell bash "git status && ls -al"`
     - `bapedge exec --shell pwsh "Get-ChildItem -Recurse | Select-Object Name"`
     - `bapedge exec --shell pwsh "Copy-Item src.txt dst.txt"`
   - Never run raw, ungoverned shell commands directly on the host machine.
2. **Zero-Trust Policy Enforcement**:
   - Commands are evaluated against Cedar invariants before execution.
   - If a command is denied, inspect the suggestion in the structured response.
3. **Secret Protection**:
   - Access to credential stores (`.env`, `~/.aws`, `~/.ssh`) is strictly prohibited.
4. **Developer Override & Agent Immunity**:
   - Autonomous agents are **STRICTLY FORBIDDEN** from activating `bapedge dev-override on`. That command requires interactive human authorization.

## BAP task authorization workflow

Zero Standing Privileges (ZSP) is broker-mediated. Autonomous agents do NOT run
`bapedge zsp authorize` or mint task grants directly.

Submit ordinary supported inspection and workspace edits normally: hooks and the
execution broker (`bapedge exec --shell bapsh "<command>"` on Windows; `bapedge.exe`) evaluate policy
and obtain eligible JIT grants automatically. Native Read/Write/Edit tools remain
governed by their BAP hooks. All shell executions MUST execute through the restricted
BAP shell: `bapedge exec --shell bapsh "<command>"` (or `bapedge bapsh -c "<command>"`).

If an operation requires human approval (e.g. interpreters, git push, deletions,
or network egress), BAP automatically registers a pending approval request in the
ZSP inbox and returns its request ID (`req-xxxx`). When BAP reports a pending approval request:
1. Do NOT run `bapedge zsp authorize` or attempt to approve the request yourself.
2. Stop and notify the human developer of the exact request ID and command to run
   in their own terminal: `bapedge zsp approve <request-id>`.
3. Wait for the developer to confirm approval, then retry your command.

Generic grants remain single-use by default; workspace file edits receive bounded
ceilings (up to 25 edits, 600s). Duplicate callbacks for one stable native tool-use
ID spend once. An expired or exhausted grant is renewed automatically by the broker
when permitted by signed policy.

If BAP reports a permanent policy denial (`BAP POLICY DENIAL`, credential access,
or protected policy assets), stop immediately. Do NOT retry through another tool
or shell. Autonomous agents are strictly forbidden from executing `bapedge dev-override on`.
