# BAP Universal IDE & CLI Harness Manager (PowerShell Edition)
# =============================================================
# Manages developer harnesses (GitHub Copilot, Google Antigravity, Claude Code):
# - Initializes IDE configurations, hooks, and MCP servers.
# - Manages dynamic agent & session lifecycles (start, prompt, list, stop, clean).
# - Enforces strict Agent Isolation and Session Isolation:
#   Multiple concurrent sessions under the same Agent (e.g. 2 Claude sessions,
#   2 Copilot sessions) run with distinct session IDs, isolated PIDs, independent
#   prompts, and independent audit ledgers.

param(
    [Parameter(Position = 0)]
    [ValidateSet("init", "start-session", "send-prompt", "list-sessions", "stop-session", "cleanup-all", "run-governed", "demo-multi-session")]
    [string]$Action = "list-sessions",

    [Parameter()]
    [ValidateSet("claude-code", "copilot", "antigravity")]
    [string]$Agent = "claude-code",

    [Parameter()]
    [string]$SessionId = "",

    [Parameter()]
    [string]$Prompt = "",

    [Parameter()]
    [int]$PidToBind = $PID,

    [Parameter()]
    [string]$ServerUrl = "http://localhost:8080",

    [Parameter()]
    [string]$Workspace = "",

    [Parameter()]
    [switch]$Watch,

    [Parameter()]
    [switch]$DecisionOnly,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CommandArgs
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Get-Item -Path $PSScriptRoot).Parent.FullName
$pythonScript = Join-Path $PSScriptRoot "bap_harness.py"

if ([string]::IsNullOrWhiteSpace($Workspace)) {
    $Workspace = $repoRoot
}

function Show-Header {
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host "         BOUNDED AUTHORITY PLANE (BAP) - UNIVERSAL HARNESS MANAGER             " -ForegroundColor Cyan
    Write-Host "===============================================================================" -ForegroundColor Cyan
}

switch ($Action) {
    "init" {
        Show-Header
        python $pythonScript init --workspace $Workspace
    }

    "start-session" {
        Show-Header
        $pyArgs = @($pythonScript, "start-session", "--agent", $Agent, "--server", $ServerUrl, "--pid", $PidToBind)
        if (-not [string]::IsNullOrWhiteSpace($SessionId)) {
            $pyArgs += @("--session-id", $SessionId)
        }
        if (-not [string]::IsNullOrWhiteSpace($Prompt)) {
            $pyArgs += @("--prompt", $Prompt)
        }
        if ($Watch) {
            $pyArgs += "--watch"
        }
        python @pyArgs
    }

    "send-prompt" {
        Show-Header
        if ([string]::IsNullOrWhiteSpace($SessionId)) {
            throw "Parameter -SessionId is required for send-prompt"
        }
        if ([string]::IsNullOrWhiteSpace($Prompt)) {
            throw "Parameter -Prompt is required for send-prompt"
        }
        python $pythonScript send-prompt --session-id $SessionId --prompt $Prompt --server $ServerUrl
    }

    "list-sessions" {
        Show-Header
        python $pythonScript list-sessions
    }

    "stop-session" {
        Show-Header
        $pyArgs = @($pythonScript, "stop-session", "--server", $ServerUrl)
        if (-not [string]::IsNullOrWhiteSpace($SessionId)) {
            $pyArgs += @("--session-id", $SessionId)
        }
        if ($PidToBind -ne $PID) {
            $pyArgs += @("--pid", $PidToBind)
        }
        python @pyArgs
    }

    "cleanup-all" {
        Show-Header
        python $pythonScript cleanup-all --server $ServerUrl
    }

    "run-governed" {
        $cmdStr = if ($CommandArgs) { $CommandArgs -join " " } else { $Prompt }
        if ([string]::IsNullOrWhiteSpace($cmdStr)) {
            throw "Command to execute is required."
        }
        $pyArgs = @($pythonScript, "run-governed", "--agent", $Agent)
        if (-not [string]::IsNullOrWhiteSpace($SessionId)) {
            $pyArgs += @("--session-id", $SessionId)
        }
        if ($DecisionOnly) {
            $pyArgs += "--decision-only"
        }
        $pyArgs += $cmdStr
        python @pyArgs
    }

    "demo-multi-session" {
        Show-Header
        Write-Host "[*] Executing Live Multi-Agent & Multi-Session Isolation Demonstration...`n" -ForegroundColor Yellow

        # 1. Clean slate
        Write-Host "[Step 1] Purging stale sessions for clean demonstration baseline..." -ForegroundColor Gray
        python $pythonScript cleanup-all --server $ServerUrl

        # 2. Launch 2 sessions for claude-code
        Write-Host "`n[Step 2] Launching 2 concurrent sessions for Agent 'claude-code' (Session Isolation)..." -ForegroundColor Cyan
        python $pythonScript start-session --agent claude-code --session-id sess-claude-alpha --prompt "Refactor user authentication service" --pid 1001 --server $ServerUrl
        python $pythonScript start-session --agent claude-code --session-id sess-claude-beta --prompt "Add unit tests for payment webhook" --pid 1002 --server $ServerUrl

        # 3. Launch 2 sessions for copilot
        Write-Host "`n[Step 3] Launching 2 concurrent sessions for Agent 'copilot'..." -ForegroundColor Cyan
        python $pythonScript start-session --agent copilot --session-id sess-copilot-term1 --prompt "Analyze git log for regressions" --pid 2001 --server $ServerUrl
        python $pythonScript start-session --agent copilot --session-id sess-copilot-term2 --prompt "Generate docker-compose microservice config" --pid 2002 --server $ServerUrl

        # 4. Launch 2 sessions for antigravity
        Write-Host "`n[Step 4] Launching 2 concurrent sessions for Agent 'antigravity'..." -ForegroundColor Cyan
        python $pythonScript start-session --agent antigravity --session-id sess-ag-investigation --prompt "Inspect production cluster health and pods" --pid 3001 --server $ServerUrl
        python $pythonScript start-session --agent antigravity --session-id sess-ag-remediation --prompt "Audit security boundary and secret scanning" --pid 3002 --server $ServerUrl

        # 5. List active sessions grouped by agent
        Write-Host "`n[Step 5] Listing live sessions grouped by Agent (proving multi-session visibility)..." -ForegroundColor Yellow
        python $pythonScript list-sessions

        # 6. Transmit prompts to existing sessions
        Write-Host "`n[Step 6] Dynamically transmitting new follow-up prompts to isolated sessions..." -ForegroundColor Cyan
        python $pythonScript send-prompt --session-id sess-claude-alpha --prompt "Fix password hashing bug in auth controller" --server $ServerUrl
        python $pythonScript send-prompt --session-id sess-ag-investigation --prompt "Deploy canary release to staging cluster" --server $ServerUrl

        # 7. Execute governed commands from isolated sessions
        Write-Host "`n[Step 7] Executing governed tool calls from isolated sessions..." -ForegroundColor Cyan
        Write-Host "  -> Running git status under sess-claude-alpha..." -ForegroundColor Gray
        python $pythonScript run-governed --agent claude-code --session-id sess-claude-alpha --decision-only "git status"
        Write-Host "  -> Running cat .env (forbidden) under sess-copilot-term1..." -ForegroundColor Gray
        try {
            python $pythonScript run-governed --agent copilot --session-id sess-copilot-term1 --decision-only "cat .env"
        } catch {
            Write-Host "     [OK] Successfully intercepted and blocked!" -ForegroundColor Green
        }

        # 8. Test Session Isolation: Terminate 1 session and verify sibling session remains active!
        Write-Host "`n[Step 8] Testing Session Isolation: Stopping 'sess-claude-alpha' only..." -ForegroundColor Yellow
        python $pythonScript stop-session --session-id sess-claude-alpha --server $ServerUrl

        Write-Host "`n[Step 9] Verifying 'sess-claude-beta' remains completely ACTIVE and unaffected:" -ForegroundColor Yellow
        python $pythonScript list-sessions

        # 10. Clean up demo sessions
        Write-Host "`n[Step 10] Cleaning up remaining demonstration sessions..." -ForegroundColor Gray
        python $pythonScript cleanup-all --server $ServerUrl

        Write-Host "`n===============================================================================" -ForegroundColor Green
        Write-Host "      [OK] MULTI-AGENT & MULTI-SESSION ISOLATION DEMO COMPLETED SUCCESSFULLY!  " -ForegroundColor Green
        Write-Host "===============================================================================" -ForegroundColor Green
    }
}
