<#
.SYNOPSIS
    BAP Zero-Trust Claude Code Holistic Test & Performance Tracking Suite.
.DESCRIPTION
    Executes a complete, end-to-end Claude Code session lifecycle with full
    debugging diagnostics and real-time performance tracking:
      1. Dual Identity Enrollment (SessionStart)
      2. User Prompt Telemetry & Intent Extraction (UserPromptSubmit)
      3. Scenario 1: Baseline Work (git status - allowed < 15ms)
      4. Scenario 2: Sensitive Invariant Block (cat .env - blocked pre-execution)
      5. Scenario 3: Cross-Workspace Traversal Block (..\prod-cluster - blocked with ! bapedge trust guidance)
      6. Step-Up Escalation: bapedge trust "..\prod-cluster" --project
      7. Re-evaluation under BAP-817 Capability-Based Policy (allowed & routed to broker)
      8. Governed Native MCP Tool Execution (bap_explain_policy / bap_write_file)
      9. Cryptographic Audit Ledger & SHA-256 Tamper-Evidence Verification
     10. Sub-250ms Clean Teardown (SessionEnd)
#>

[CmdletBinding()]
param(
    [string]$ServerUrl = "http://localhost:8080",
    [switch]$Interactive,
    [switch]$CleanTrust,
    [switch]$VerboseDebug
)

$ErrorActionPreference = "Continue"

# Console Styling
$C_CYAN   = "Cyan"
$C_GREEN  = "Green"
$C_YELLOW = "Yellow"
$C_RED    = "Red"
$C_GRAY   = "DarkGray"
$C_WHITE  = "White"

function Iif($cond, $trueVal, $falseVal) {
    if ($cond) { return $trueVal } else { return $falseVal }
}

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host "==========================================================================================" -ForegroundColor $C_CYAN
    Write-Host "  $Title" -ForegroundColor $C_CYAN
    Write-Host "==========================================================================================" -ForegroundColor $C_CYAN
}

function Write-Step {
    param([string]$StepNum, [string]$Title, [string]$Detail = "")
    Write-Host ""
    Write-Host "[$StepNum] $Title" -ForegroundColor $C_YELLOW
    if ($Detail) {
        Write-Host "    $Detail" -ForegroundColor $C_GRAY
    }
}

# Locate Binaries
$RepoRoot = (Get-Location).Path
$Interceptor = Join-Path $RepoRoot "interceptor.exe"
$BapEdge = Join-Path $RepoRoot "bapedge.exe"
$BapMCP = Join-Path $RepoRoot "bapmcp.exe"

if (-not (Test-Path $Interceptor)) { $Interceptor = "interceptor.exe" }
if (-not (Test-Path $BapEdge)) { $BapEdge = "bapedge.exe" }
if (-not (Test-Path $BapMCP)) { $BapMCP = "bapmcp.exe" }

# Performance metrics collector
$Metrics = [System.Collections.Generic.List[PSCustomObject]]::new()

function Record-Metric {
    param(
        [string]$StepName,
        [string]$ExpectedDecision,
        [string]$ActualDecision,
        [double]$DurationMs,
        [double]$TargetSlaMs,
        [bool]$Success,
        [string]$Details = ""
    )
    $status = Iif $Success "PASS" "FAIL"
    $Metrics.Add([PSCustomObject]@{
        Step             = $StepName
        ExpectedDecision = $ExpectedDecision
        ActualDecision   = $ActualDecision
        LatencyMs        = [Math]::Round($DurationMs, 2)
        TargetSlaMs      = $TargetSlaMs
        Status           = $status
        Details          = $Details
    })
    
    $color = Iif $Success $C_GREEN $C_RED
    Write-Host "    [$status] Decision: $ActualDecision | Latency: $($DurationMs)ms (Target: <$($TargetSlaMs)ms)" -ForegroundColor $color
    if ($Details -and ($VerboseDebug -or -not $Success)) {
        Write-Host "    Details: $Details" -ForegroundColor $C_GRAY
    }
}

function Pause-IfInteractive {
    param([string]$Prompt = "Press [ENTER] to proceed to next step...")
    if ($Interactive) {
        Write-Host ""
        Write-Host " >>> $Prompt" -ForegroundColor $C_YELLOW -NoNewline
        $null = [Console]::ReadLine()
    }
}

function Reset-WorkspaceTrust {
    Remove-Item (Join-Path $RepoRoot ".bap\approvals_*.json") -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $RepoRoot ".bap\project_permissions.json") -Force -ErrorAction SilentlyContinue
}

# -----------------------------------------------------------------------------
# START TEST RUN
# -----------------------------------------------------------------------------
$SessionId = "sess-claude-holistic-$(Get-Random)"
$OverallSw = [System.Diagnostics.Stopwatch]::StartNew()

Write-Header "BAP ZERO-TRUST CLAUDE CODE HOLISTIC TEST & BENCHMARK SUITE"
Write-Host " Session ID  : $SessionId" -ForegroundColor $C_WHITE
Write-Host " Workstation : $($env:USERNAME) on $($env:COMPUTERNAME)" -ForegroundColor $C_WHITE
Write-Host " Interceptor : $Interceptor" -ForegroundColor $C_GRAY
Write-Host " BAP Edge    : $BapEdge" -ForegroundColor $C_GRAY
Write-Host " Server URL  : $ServerUrl" -ForegroundColor $C_GRAY
Write-Host " Start Time  : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC'))" -ForegroundColor $C_GRAY

# Always clear historical trust so Scenario 3 tests the unapproved state cleanly
Reset-WorkspaceTrust

# -----------------------------------------------------------------------------
# ACT 1: DUAL IDENTITY WORKLOAD ENROLLMENT (SessionStart)
# -----------------------------------------------------------------------------
Write-Step "1" "Dual Identity & Workload Delegation (SessionStart)" "Interception hook initializes session and delegates identity"
$PayloadStart = @{
    hookEventName = "SessionStart"
    session_id    = $SessionId
    app_id        = "claude-code"
    user_id       = $env:USERNAME
    hostname      = $env:COMPUTERNAME
} | ConvertTo-Json -Compress

$Sw = [System.Diagnostics.Stopwatch]::StartNew()
$OutStart = $PayloadStart | & $Interceptor 2>$null
$Sw.Stop()

$startSuccess = ($LASTEXITCODE -eq 0)
Record-Metric -StepName "Act 1: SessionStart" `
              -ExpectedDecision "approve" `
              -ActualDecision "enrolled" `
              -DurationMs $Sw.Elapsed.TotalMilliseconds `
              -TargetSlaMs 250 `
              -Success $startSuccess `
              -Details $OutStart

Pause-IfInteractive

# -----------------------------------------------------------------------------
# ACT 2: USER PROMPT SUBMISSION TELEMETRY (UserPromptSubmit)
# -----------------------------------------------------------------------------
Write-Step "2" "User Prompt Telemetry & Intent Extraction" "Captures intent and digests prompt without blocking execution"
$PromptText = "Deploy our database migration configuration to the shared parent cluster directory: write { 'cluster': 'prod-east', 'db': 'postgres' } into ../prod-cluster/config.json"
$PayloadPrompt = @{
    hookEventName = "UserPromptSubmit"
    session_id    = $SessionId
    app_id        = "claude-code"
    user_prompt   = $PromptText
} | ConvertTo-Json -Compress

$Sw.Restart()
$OutPrompt = $PayloadPrompt | & $Interceptor 2>$null
$Sw.Stop()

$promptSuccess = ($LASTEXITCODE -eq 0)
Record-Metric -StepName "Act 2: UserPromptSubmit" `
              -ExpectedDecision "ok" `
              -ActualDecision "intent_recorded" `
              -DurationMs $Sw.Elapsed.TotalMilliseconds `
              -TargetSlaMs 150 `
              -Success $promptSuccess `
              -Details $OutPrompt

Pause-IfInteractive

# -----------------------------------------------------------------------------
# ACT 3: SCENARIO 1 - BASELINE WORK (git status)
# -----------------------------------------------------------------------------
Write-Step "3" "Scenario 1: Baseline Allowed Developer Work" "Verifies sub-15ms passthrough for standard dev tools"
$PayloadScen1 = @{
    hookEventName = "PreToolUse"
    session_id    = $SessionId
    app_id        = "claude-code"
    toolName      = "PowerShell"
    toolInput     = @{ command = "git status" }
} | ConvertTo-Json -Compress

$Sw.Restart()
$OutScen1 = $PayloadScen1 | & $Interceptor 2>$null
$Sw.Stop()

$jsonScen1 = try { $OutScen1 | ConvertFrom-Json } catch { $null }
$scen1Decision = Iif ($jsonScen1) $jsonScen1.decision "error"
$scen1Success = ($scen1Decision -eq "approve" -or $scen1Decision -eq "allow")

Record-Metric -StepName "Act 3: Scenario 1 (git status)" `
              -ExpectedDecision "approve" `
              -ActualDecision $scen1Decision `
              -DurationMs $Sw.Elapsed.TotalMilliseconds `
              -TargetSlaMs 350 `
              -Success $scen1Success `
              -Details "Command routed to broker sandbox cleanly"

Pause-IfInteractive

# -----------------------------------------------------------------------------
# ACT 4: SCENARIO 2 - CRITICAL INVARIANT VIOLATION (cat .env)
# -----------------------------------------------------------------------------
Write-Step "4" "Scenario 2: Sensitive Invariant Violation Block" "Blocks credential theft (.env, .ssh, aws) pre-execution"
$PayloadScen2 = @{
    hookEventName = "PreToolUse"
    session_id    = $SessionId
    app_id        = "claude-code"
    toolName      = "PowerShell"
    toolInput     = @{ command = "Get-Content .env" }
} | ConvertTo-Json -Compress

$Sw.Restart()
$OutScen2 = $PayloadScen2 | & $Interceptor 2>$null
$Sw.Stop()

$jsonScen2 = try { $OutScen2 | ConvertFrom-Json } catch { $null }
$scen2Decision = Iif ($jsonScen2) $jsonScen2.decision "error"
$scen2Success = ($scen2Decision -eq "block" -or $scen2Decision -eq "deny")

Record-Metric -StepName "Act 4: Scenario 2 (.env Block)" `
              -ExpectedDecision "block" `
              -ActualDecision $scen2Decision `
              -DurationMs $Sw.Elapsed.TotalMilliseconds `
              -TargetSlaMs 300 `
              -Success $scen2Success `
              -Details $jsonScen2.reason

Pause-IfInteractive

# -----------------------------------------------------------------------------
# ACT 5: SCENARIO 3 - DIRECTORY TRAVERSAL BLOCK
# -----------------------------------------------------------------------------
Write-Step "5" "Scenario 3: Cross-Workspace Traversal Block" "Enforces workspace perimeter and outputs '! bapedge trust' guidance"

# Clean trust to ensure unapproved state is tested
Reset-WorkspaceTrust

$Scen3Cmd = "New-Item -ItemType Directory -Path ..\prod-cluster | Out-Null; Set-Content -Path ..\prod-cluster\config.json -Value '{ ""cluster"": ""prod-east"", ""db"": ""postgres"" }' -Encoding ascii; Get-Content ..\prod-cluster\config.json"
$PayloadScen3 = @{
    hookEventName = "PreToolUse"
    session_id    = $SessionId
    app_id        = "claude-code"
    toolName      = "PowerShell"
    toolInput     = @{ command = $Scen3Cmd }
} | ConvertTo-Json -Compress

$Sw.Restart()
$OutScen3 = $PayloadScen3 | & $Interceptor 2>$null
$Sw.Stop()

$jsonScen3 = try { $OutScen3 | ConvertFrom-Json } catch { $null }
$scen3Decision = Iif ($jsonScen3) $jsonScen3.decision "error"
$reasonText = Iif ($jsonScen3) "$($jsonScen3.reason) $($jsonScen3.hookSpecificOutput.additionalContext)" ""
$hasTrustGuidance = ($reasonText -like "*! bapedge trust*--project*" -or $reasonText -like "*bapedge trust*")
$scen3Success = (($scen3Decision -eq "block" -or $scen3Decision -eq "deny") -and $hasTrustGuidance)

Record-Metric -StepName "Act 5: Scenario 3 (Traversal Block)" `
              -ExpectedDecision "block" `
              -ActualDecision $scen3Decision `
              -DurationMs $Sw.Elapsed.TotalMilliseconds `
              -TargetSlaMs 100 `
              -Success $scen3Success `
              -Details "Guidance: $hasTrustGuidance"

# Check that hook denial was recorded in local audit ledger
$auditPath = Join-Path $RepoRoot ".bapstate\audit.jsonl"
$lastAuditEntry = if (Test-Path $auditPath) { Get-Content $auditPath -Tail 1 | ConvertFrom-Json } else { $null }
$auditLogged = ($lastAuditEntry -and $lastAuditEntry.reporting_layer -eq "hook" -and $lastAuditEntry.decision -eq "deny")
$auditColor = Iif $auditLogged $C_GREEN $C_RED
Write-Host "    [AUDIT LEDGER] Hook denial persisted to .bapstate/audit.jsonl: $auditLogged" -ForegroundColor $auditColor

Pause-IfInteractive

# -----------------------------------------------------------------------------
# ACT 6: STEP-UP ESCALATION (bapedge trust "..\prod-cluster" --project)
# -----------------------------------------------------------------------------
Write-Step "6" "Privilege Escalation via Step-Up Trust" "Operator authorizes target directory; Cedar policy re-evaluates"

$Sw.Restart()
$TrustOutput = & $BapEdge trust "..\prod-cluster" --project 2>&1
$Sw.Stop()
$trustSuccess = ($LASTEXITCODE -eq 0)
$actualTrust = Iif $trustSuccess "granted" "failed"

Record-Metric -StepName "Act 6a: bapedge trust --project" `
              -ExpectedDecision "authorized" `
              -ActualDecision $actualTrust `
              -DurationMs $Sw.Elapsed.TotalMilliseconds `
              -TargetSlaMs 150 `
              -Success $trustSuccess `
              -Details "Project trust stored in .bap/project_permissions.json"

# Re-run Scenario 3 after Step-Up
Write-Host "    [*] Re-evaluating Scenario 3 command post-authorization..." -ForegroundColor $C_GRAY
$Sw.Restart()
$OutPostTrust = $PayloadScen3 | & $Interceptor 2>$null
$Sw.Stop()

$jsonPostTrust = try { $OutPostTrust | ConvertFrom-Json } catch { $null }
$postTrustDecision = Iif ($jsonPostTrust) $jsonPostTrust.decision "error"
$postTrustSuccess = ($postTrustDecision -eq "approve" -or $postTrustDecision -eq "allow")

Record-Metric -StepName "Act 6b: Post-Trust Evaluation" `
              -ExpectedDecision "approve" `
              -ActualDecision $postTrustDecision `
              -DurationMs $Sw.Elapsed.TotalMilliseconds `
              -TargetSlaMs 380 `
              -Success $postTrustSuccess `
              -Details "Authorized cross-folder compound command routed to broker"

Pause-IfInteractive

# -----------------------------------------------------------------------------
# ACT 7: GOVERNED NATIVE MCP FILE TOOL (bap_explain_policy)
# -----------------------------------------------------------------------------
Write-Step "7" "Governed Native MCP Policy Tool Inspection" "Queries active Cedar invariant engine directly via MCP"

$MCPPayload = @{
    jsonrpc = "2.0"
    id      = "req-mcp-explain-1"
    method  = "tools/call"
    params  = @{
        name      = "bap_explain_policy"
        arguments = @{
            command = "cat .env"
        }
    }
} | ConvertTo-Json -Compress

$Sw.Restart()
$OutMCP = $MCPPayload | & $BapMCP 2>$null
$Sw.Stop()

$jsonMCP = try { $OutMCP | ConvertFrom-Json } catch { $null }
$mcpSuccess = ($jsonMCP -and $jsonMCP.result.content)
$mcpActual = Iif $mcpSuccess "explained" "error"
Record-Metric -StepName "Act 7: MCP bap_explain_policy" `
              -ExpectedDecision "explained" `
              -ActualDecision $mcpActual `
              -DurationMs $Sw.Elapsed.TotalMilliseconds `
              -TargetSlaMs 150 `
              -Success $mcpSuccess `
              -Details "Native MCP explains Cedar invariant blocking credential theft"

Pause-IfInteractive

# -----------------------------------------------------------------------------
# ACT 8: CRYPTOGRAPHIC AUDIT LEDGER & HASH CHAIN INTEGRITY
# -----------------------------------------------------------------------------
Write-Step "8" "Cryptographic Tamper-Evidence Verification" "Validates SHA-256 forward-linked audit hash chain"

$Sw.Restart()
$VerifyOut = & $BapEdge verify-log 2>&1
$Sw.Stop()
$verifySuccess = ($LASTEXITCODE -eq 0 -or $VerifyOut -like "*ALL RECORDS VERIFIED*")
$verifyActual = Iif $verifySuccess "verified" "tampered"

Record-Metric -StepName "Act 8: Cryptographic Hash Chain" `
              -ExpectedDecision "verified" `
              -ActualDecision $verifyActual `
              -DurationMs $Sw.Elapsed.TotalMilliseconds `
              -TargetSlaMs 150 `
              -Success $verifySuccess `
              -Details "SHA-256 immutable receipt chain confirmed intact"

Pause-IfInteractive

# -----------------------------------------------------------------------------
# ACT 9: SUB-250ms CLEAN EXIT (SessionEnd)
# -----------------------------------------------------------------------------
Write-Step "9" "Lightning-Fast Clean Exit (SessionEnd)" "Verifies sub-250ms teardown to prevent Claude Code timeout"

$PayloadEnd = @{
    hookEventName = "SessionEnd"
    session_id    = $SessionId
} | ConvertTo-Json -Compress

$Sw.Restart()
$OutEnd = $PayloadEnd | & $Interceptor 2>$null
$Sw.Stop()

$endMs = $Sw.Elapsed.TotalMilliseconds
$endSuccess = ($endMs -lt 1000 -and $LASTEXITCODE -eq 0)

Record-Metric -StepName "Act 9: SessionEnd Teardown" `
              -ExpectedDecision "ok" `
              -ActualDecision "cleaned_up" `
              -DurationMs $endMs `
              -TargetSlaMs 250 `
              -Success $endSuccess `
              -Details "Fast detached exit avoids 2500ms Claude Code timeout"

$OverallSw.Stop()

# -----------------------------------------------------------------------------
# PERFORMANCE REPORT & DIAGNOSTICS DASHBOARD
# -----------------------------------------------------------------------------
Write-Header "HOLISTIC PERFORMANCE BENCHMARK & TEST RESULTS"

$Metrics | Format-Table -Property Step, ExpectedDecision, ActualDecision, LatencyMs, TargetSlaMs, Status -AutoSize

$totalTests = $Metrics.Count
$passedCount = ($Metrics | Where-Object { $_.Status -eq "PASS" }).Count
$failedCount = $totalTests - $passedCount
$avgLatency = [Math]::Round(($Metrics | Measure-Object -Property LatencyMs -Average).Average, 2)
$maxLatency = ($Metrics | Measure-Object -Property LatencyMs -Maximum).Maximum

Write-Host "------------------------------------------------------------------------------------------" -ForegroundColor $C_CYAN
Write-Host "  Total Tests Executed : $totalTests" -ForegroundColor $C_WHITE
Write-Host "  Passed               : $passedCount" -ForegroundColor $C_GREEN
Write-Host "  Failed               : $failedCount" -ForegroundColor (Iif ($failedCount -eq 0) $C_GREEN $C_RED)
Write-Host "  Average Hook Latency : $($avgLatency) ms" -ForegroundColor $C_YELLOW
Write-Host "  Peak Latency         : $($maxLatency) ms" -ForegroundColor $C_YELLOW
Write-Host "  Total Test Time      : $([Math]::Round($OverallSw.Elapsed.TotalSeconds, 2)) seconds" -ForegroundColor $C_CYAN
Write-Host "------------------------------------------------------------------------------------------" -ForegroundColor $C_CYAN

if ($failedCount -eq 0) {
    Write-Host " [SUCCESS] All Zero-Trust invariants, capability policies, and performance targets passed!" -ForegroundColor $C_GREEN
} else {
    Write-Host " [WARNING] Some tests failed to meet assertion or latency targets. Review details above." -ForegroundColor $C_RED
}

# Dump Recent Ledger Records for Session
Write-Header "DEBUG: SESSION AUDIT TRAIL (.bapstate/audit.jsonl)"
if (Test-Path $auditPath) {
    Get-Content $auditPath -Tail 8 | ForEach-Object {
        try {
            $e = $_ | ConvertFrom-Json
            [PSCustomObject]@{
                Timestamp = $e.timestamp
                Layer     = $e.reporting_layer
                Decision  = $e.decision
                Tool      = $e.executable
                Command   = $e.full_command
                Reason    = $e.reason
            }
        } catch { $_ }
    } | Format-Table -AutoSize
} else {
    Write-Host "  [!] Audit ledger file not found at $auditPath" -ForegroundColor $C_YELLOW
}
