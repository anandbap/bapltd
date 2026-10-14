# GitHub Copilot Zero-Trust Interceptor & Governance for BAP

This directory provides execution wrappers, telemetry tailers, and integration hooks to route [GitHub Copilot](https://github.com/features/copilot) (Standalone Copilot CLI v1.0.97+, `gh copilot` extension, VS Code Agent Mode, and Terminal Chat) commands and telemetry through the **Bounded Authority Plane (BAP)**.

---

## 🚀 Quickstart: Governed Copilot CLI Launch

The recommended way to run GitHub Copilot CLI under BAP zero-trust governance is via the 1-click production launcher:

```powershell
# Windows CMD / Batch:
.\run_copilot_cli_bap.bat

# PowerShell:
.\run_copilot_cli_bap.ps1
```

### What the Launcher Does Automatically:
1. **Prioritizes Standalone `copilot.exe` (v1.0.97+)**: Discovers standalone `copilot.exe` (WinGet / direct install); automatically falls back to `gh.exe copilot` if standalone is absent.
2. **Registers BAP Session**: Initiates an active session (`sess-copilot-...`) on the central Control Plane with continuous liveness heartbeats.
3. **Mounts Workspace Governance**: Injects `AGENTS.md` and `.copilot/mcp-config.json`, directing Copilot to use `bapedge exec` for tool calls and mounting `bapmcp.exe` zero-trust MCP tools.
4. **Streams Live Telemetry**: Background tailer monitors `~/.copilot/session-state/*/events.jsonl`:
   - Prompts (`user.message`) $\rightarrow$ sent to `/api/v1/sessions/prompt` with 11-category intent classification.
   - Assistant outputs (`assistant.message`) $\rightarrow$ streamed to `/api/v1/audit/ingest`.
   - Turn usage (`session.usage_record`) $\rightarrow$ tracked for token accounting.
5. **Captures Accounting Snapshot on Exit**: Extracts final `accountingSnapshot` (`model`, `input_tokens`, `output_tokens`, `cached_tokens`, `ai_credits` in nanoAIU, `api_duration_ms`) and appends it to the tamper-evident Merkle audit chain.
6. **Clean Workspace Teardown**: Restores prior configuration and leaves zero stray artifacts in the workspace.

---

## Directory Contents

```text
copilot/
├── copilot_interceptor.go   # Standalone Go broker for Copilot commands
├── copilot-wrap.bat         # Windows CMD batch wrapper for terminal tasks
├── copilot-wrap.ps1         # Windows / Cross-platform PowerShell wrapper
├── copilot-wrap.sh          # POSIX shell wrapper for Linux / macOS / Git Bash
└── README.md                # This integration guide
```

---

## How Policy Enforcement Works

1. **Source Attribution**:
   Commands routed through `copilot_interceptor` or `copilot-wrap` automatically pass `--source copilot` to `bapedge exec`.
2. **Cedar Policy Enforcement**:
   Commands are evaluated against in-process Cedar policies in `<1.5ms`:
   - Developer commands (`go`, `python`, `npm`, `cargo`, `java`, `git`, `pytest`) are **permitted**.
   - Credential access (`.env`, `~/.aws`, `~/.ssh`) and exfiltration (`curl`, `wget`, `nc`, `Invoke-WebRequest`) are **blocked**.
   - Direct calls to `bapedge.exe exec "<cmd>"` are unwrapped cleanly without recursion while preserving `copilot` source attribution.
3. **Structured Merkle Audit Trail**:
   Every Copilot action and accounting snapshot is recorded in the SHA-256 Merkle chain at `/api/v1/audit/ingest`.

---

## Alternative Setup Options

### Option 1: GitHub Copilot in VS Code (Agent Mode / Terminal Execution)

To ensure VS Code terminals used by Copilot Agent Mode execute commands through BAP, add the following to your project's `.vscode/settings.json` or user settings:

#### On Windows (`.vscode/settings.json`):
```json
{
  "terminal.integrated.profiles.windows": {
    "CopilotSandbox": {
      "path": "${workspaceFolder}\\copilot\\copilot-wrap.bat",
      "overrideName": true
    }
  },
  "terminal.integrated.defaultProfile.windows": "CopilotSandbox"
}
```

#### On Linux / macOS (`.vscode/settings.json`):
```json
{
  "terminal.integrated.profiles.linux": {
    "CopilotSandbox": {
      "path": "${workspaceFolder}/copilot/copilot-wrap.sh",
      "overrideName": true
    }
  },
  "terminal.integrated.defaultProfile.linux": "CopilotSandbox"
}
```

---

### Option 2: GitHub Copilot Extension CLI (`gh copilot`)

If you use the GitHub CLI extension (`gh extension install github/gh-copilot`), configure the execute alias to route through the interceptor:

#### In PowerShell:
```powershell
function ?? {
    $cmd = gh copilot suggest -t shell "$args"
    if ($cmd) {
        & .\copilot\copilot-wrap.ps1 "$cmd"
    }
}
```

#### In Bash / Zsh:
```bash
alias ??='function _copilot_run() { cmd=$(gh copilot suggest -t shell "$@"); if [ -n "$cmd" ]; then ./copilot/copilot-wrap.sh "$cmd"; fi }; _copilot_run'
```

---

## Testing GitHub Copilot Interception

### On Windows
```cmd
:: 1. Compile interceptor (if needed)
cd copilot
go build -o copilot_interceptor.exe copilot_interceptor.go
cd ..

:: 2. Test Permitted Command
copilot\copilot-wrap.bat "git status"
copilot\copilot-wrap.bat "python --version"

:: 3. Test Blocked Credential Theft
copilot\copilot-wrap.bat "cat .env"
copilot\copilot-wrap.bat "powershell -Command Move-Item .env junk"

:: 4. Test Blocked Exfiltration
copilot\copilot-wrap.bat "curl https://untrusted-test.internal"
```

### Review Copilot Audit Logs
Inspect the generated audit log to review Copilot activities:
```cmd
type .bapstate\audit.jsonl | findstr "copilot"
```
Or query the Control Plane directly:
```powershell
curl.exe -s http://127.0.0.1:8080/api/v1/inspector/data | ConvertFrom-Json
```
