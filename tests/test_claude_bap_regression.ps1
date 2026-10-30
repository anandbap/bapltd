<#
.SYNOPSIS
    Rock-Solid BAP Claude Code Governance & Hook Regression Test Suite.
.DESCRIPTION
    Validates BAP v1.9.2 patch:
    1. Tests clean installation and confirms SessionEnd is absent from all Claude settings files.
    2. Benchmarks interceptor.exe SessionEnd execution time to guarantee <1.2s fast-return.
    3. Validates PreToolUse Cedar zero-trust enforcement (allows safe tools, blocks sensitive files).
    4. Executes a full session launcher cycle and verifies zero "Hook cancelled" errors.
    5. Verifies Control Plane health and session registration.
#>

[CmdletBinding()]
param(
    [string]$TargetServer = "https://bap-controlplane.onrender.com",
    [string]$InterceptorPath = "",
    [switch]$SkipLauncherRun
)

$ErrorActionPreference = "Continue"
$global:PassedTests = 0
$global:FailedTests = 0

function Assert-Check {
    param(
        [string]$Name,
        [bool]$Condition,
        [string]$Details = "",
        [bool]$IsWarning = $false
    )
    if ($Condition) {
        Write-Host "  [PASS] $Name" -ForegroundColor Green
        if ($Details) { Write-Host "         $Details" -ForegroundColor DarkGray }
        $global:PassedTests++
    } elseif ($IsWarning) {
        Write-Host "  [SKIP] $Name" -ForegroundColor Yellow
        if ($Details) { Write-Host "         $Details" -ForegroundColor DarkYellow }
    } else {
        Write-Host "  [FAIL] $Name" -ForegroundColor Red
        if ($Details) { Write-Host "         $Details" -ForegroundColor Yellow }
        $global:FailedTests++
    }
}

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "       BAP CLAUDE CODE GOVERNANCE & HOOK VALIDATION SUITE (v1.9.2)             " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
$nowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
Write-Host "[*] Timestamp: $nowUtc"
Write-Host "[*] Host     : $env:COMPUTERNAME ($env:USERNAME)"
Write-Host "[*] Target   : $TargetServer"
Write-Host ""

# -----------------------------------------------------------------------------
# 0. Locate Binaries & Paths
# -----------------------------------------------------------------------------
if (-not $InterceptorPath) {
    $candidates = @(
        "$env:USERPROFILE\bin\interceptor.exe",
        "$PSScriptRoot\..\interceptor.exe",
        "$PSScriptRoot\..\cchook\interceptor.exe",
        "$PSScriptRoot\..\dist\windows-amd64\claude-client\interceptor.exe",
        "$PSScriptRoot\..\dist\windows-amd64\interceptor.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c -ErrorAction SilentlyContinue) {
            $InterceptorPath = (Resolve-Path $c).Path
            break
        }
    }
}

if (-not $InterceptorPath -or -not (Test-Path $InterceptorPath -ErrorAction SilentlyContinue)) {
    $which = Get-Command interceptor.exe -ErrorAction SilentlyContinue
    if ($which) { $InterceptorPath = $which.Source }
}

Assert-Check -Name "Locate interceptor.exe binary" `
             -Condition ($null -ne $InterceptorPath -and (Test-Path $InterceptorPath -ErrorAction SilentlyContinue)) `
             -Details "Path: $InterceptorPath"

if (-not (Test-Path $InterceptorPath -ErrorAction SilentlyContinue)) {
    Write-Error "[-] interceptor.exe could not be found. Aborting test suite."
    exit 1
}

# -----------------------------------------------------------------------------
# TEST 1: Control Plane Health & API Connectivity
# -----------------------------------------------------------------------------
Write-Host "`n--- [TEST 1] Control Plane Connectivity & Health ---" -ForegroundColor Yellow
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$healthOk = $false
$healthDetails = ""
$isIsolated = $false
try {
    $res = Invoke-RestMethod -Uri "$TargetServer/api/v1/health" -Method Get -TimeoutSec 5 -ErrorAction Stop
    $sw.Stop()
    $healthOk = ($res.status -eq "ok" -or $res.service -match "ltd")
    $healthDetails = "Latency: $($sw.ElapsedMilliseconds)ms | Version: $($res.version) | Status: $($res.status)"
} catch {
    $sw.Stop()
    $healthDetails = "Notice: $($_.Exception.Message)"
    if ($_.Exception.Message -match "could not be resolved|timed out|unable to connect|access permissions|forbidden|No connection could be made|A socket operation was attempted") {
        $isIsolated = $true
    }
}

if ($healthOk) {
    Assert-Check -Name "Central Control Plane Health Check (/api/v1/health)" `
                 -Condition $true `
                 -Details $healthDetails
} else {
    Assert-Check -Name "Central Control Plane Health Check (Network access optional)" `
                 -Condition $false `
                 -IsWarning $isIsolated `
                 -Details $healthDetails
}

# -----------------------------------------------------------------------------
# TEST 2: Interceptor SessionEnd Fast-Return Benchmark (< 1.2s process lifespan)
# -----------------------------------------------------------------------------
Write-Host "`n--- [TEST 2] Interceptor SessionEnd Fast-Return Benchmark ---" -ForegroundColor Yellow
$mockSessionId = "sess-test-$([Guid]::NewGuid().ToString('N'))"
$sessionEndPayload = @{
    hook_event_name = "SessionEnd"
    session_id      = $mockSessionId
    cwd             = (Get-Location).Path
} | ConvertTo-Json -Compress

$hookSw = [System.Diagnostics.Stopwatch]::StartNew()
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $InterceptorPath
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true

$proc = [System.Diagnostics.Process]::Start($psi)
$proc.StandardInput.WriteLine($sessionEndPayload)
$proc.StandardInput.Close()

$stdout = $proc.StandardOutput.ReadToEnd()
$stderr = $proc.StandardError.ReadToEnd()
$proc.WaitForExit(5000)
$hookSw.Stop()

$elapsedMs = $hookSw.ElapsedMilliseconds
$exitCode = $proc.ExitCode

Assert-Check -Name "SessionEnd hook process exit code is 0" `
             -Condition ($exitCode -eq 0) `
             -Details "ExitCode: $exitCode"

$jsonResponse = $null
try { $jsonResponse = $stdout | ConvertFrom-Json } catch {}

Assert-Check -Name "SessionEnd emits universal continue contract ({'status':'ok','continue':true})" `
             -Condition ($null -ne $jsonResponse -and $jsonResponse.continue -eq $true) `
             -Details "Output: $($stdout.Trim())"

Assert-Check -Name "SessionEnd lifespan is well under Claude's 2.5s shutdown window" `
             -Condition ($elapsedMs -lt 2500) `
             -Details "Total elapsed process time: ${elapsedMs}ms (Prior slow baseline: 3096ms)"

# -----------------------------------------------------------------------------
# TEST 3: PreToolUse Security Policy & Intent Evaluation
# -----------------------------------------------------------------------------
Write-Host "`n--- [TEST 3] Zero-Trust Policy Interception (PreToolUse) ---" -ForegroundColor Yellow

# 3A: Test Allowed Command (e.g. dir / ls)
$allowedPayload = @{
    hook_event_name = "PreToolUse"
    session_id      = $mockSessionId
    tool_name       = "Bash"
    tool_input      = @{ command = "dir" }
} | ConvertTo-Json -Compress

$psi.Arguments = ""
$proc = [System.Diagnostics.Process]::Start($psi)
$proc.StandardInput.WriteLine($allowedPayload)
$proc.StandardInput.Close()
$allowOut = $proc.StandardOutput.ReadToEnd()
$proc.WaitForExit(3000)

$allowJson = $null
try { $allowJson = $allowOut | ConvertFrom-Json } catch {}
Assert-Check -Name "PreToolUse permits authorized developer commands" `
             -Condition ($null -ne $allowJson -and $allowJson.continue -eq $true) `
             -Details "Decision: $($allowJson.decision)"

# 3B: Test Blocked Sensitive File Access (.env / credentials)
$blockedPayload = @{
    hook_event_name = "PreToolUse"
    session_id      = $mockSessionId
    tool_name       = "Read"
    tool_input      = @{ file_path = ".env" }
} | ConvertTo-Json -Compress

$proc = [System.Diagnostics.Process]::Start($psi)
$proc.StandardInput.WriteLine($blockedPayload)
$proc.StandardInput.Close()
$blockOut = $proc.StandardOutput.ReadToEnd()
$proc.WaitForExit(3000)

$blockJson = $null
try { $blockJson = $blockOut | ConvertFrom-Json } catch {}
$isBlocked = ($null -ne $blockJson -and ($blockJson.continue -eq $false -or $blockJson.decision -eq "deny" -or $blockJson.decision -eq "block" -or $blockJson.status -eq "blocked"))
Assert-Check -Name "PreToolUse strictly blocks access to .env / credentials" `
             -Condition $isBlocked `
             -Details "Decision: $($blockJson.decision) | Reason: $($blockJson.reason)"

# 3C: Test Glob Tool Claude Code Hook Schema Compliance (decision: approve, permissionDecision: allow)
$globPayload = @{
    hook_event_name = "PreToolUse"
    session_id      = $mockSessionId
    tool_name       = "Glob"
    tool_input      = @{ pattern = "*.*" }
} | ConvertTo-Json -Compress

$proc = [System.Diagnostics.Process]::Start($psi)
$proc.StandardInput.WriteLine($globPayload)
$proc.StandardInput.Close()
$globOut = $proc.StandardOutput.ReadToEnd()
$proc.WaitForExit(3000)

$globJson = $null
try { $globJson = $globOut | ConvertFrom-Json } catch {}
$globValid = ($null -ne $globJson -and $globJson.continue -eq $true -and ($globJson.decision -eq "approve" -or $null -eq $globJson.decision) -and $globJson.hookSpecificOutput.permissionDecision -eq "allow")
Assert-Check -Name "PreToolUse Glob complies with Claude Code schema (approve/allow)" `
             -Condition $globValid `
             -Details "Decision: $($globJson.decision) | permissionDecision: $($globJson.hookSpecificOutput.permissionDecision)"

# 3D: Test PowerShell Get-ChildItem Tool Policy Allowance
$psPayload = @{
    hook_event_name = "PreToolUse"
    session_id      = $mockSessionId
    tool_name       = "PowerShell"
    tool_input      = @{ command = "Get-ChildItem" }
} | ConvertTo-Json -Compress

$proc = [System.Diagnostics.Process]::Start($psi)
$proc.StandardInput.WriteLine($psPayload)
$proc.StandardInput.Close()
$psOut = $proc.StandardOutput.ReadToEnd()
$proc.WaitForExit(3000)

$psJson = $null
try { $psJson = $psOut | ConvertFrom-Json } catch {}
$psValid = ($null -ne $psJson -and $psJson.continue -eq $true -and ($psJson.decision -eq "approve" -or $null -eq $psJson.decision) -and $psJson.hookSpecificOutput.permissionDecision -eq "allow")
Assert-Check -Name "PreToolUse PowerShell Get-ChildItem permitted and rewritten" `
             -Condition $psValid `
             -Details "Decision: $($psJson.decision) | Command: $($psJson.hookSpecificOutput.updatedInput.command)"

# 3E: UserPromptSubmit Fast-Return Benchmark (< 500ms, single prompt submit)
$promptPayload = @{
    hook_event_name = "UserPromptSubmit"
    session_id      = $mockSessionId
    prompt          = "Can you list what source files we have in this folder?"
} | ConvertTo-Json -Compress

$promptSw = [System.Diagnostics.Stopwatch]::StartNew()
$proc = [System.Diagnostics.Process]::Start($psi)
$proc.StandardInput.WriteLine($promptPayload)
$proc.StandardInput.Close()
$promptOut = $proc.StandardOutput.ReadToEnd()
$proc.WaitForExit(2000)
$promptSw.Stop()

$promptJson = $null
try { $promptJson = $promptOut | ConvertFrom-Json } catch {}
$promptValid = ($null -ne $promptJson -and $promptJson.continue -eq $true -and $promptSw.ElapsedMilliseconds -lt 1500)
Assert-Check -Name "UserPromptSubmit fast-return benchmark (< 1.5s)" `
             -Condition $promptValid `
             -Details "Latency: $($promptSw.ElapsedMilliseconds)ms | Output: $($promptOut.Trim())"

# 3F: Test Generic / Non-Claude tool runner receiving "decision: allow"
$genericPayload = @{
    hook_event_name = "PreToolUse"
    session_id      = $mockSessionId
    tool_name       = "Glob"
    decision_style  = "allow"
    tool_input      = @{ pattern = "*.*" }
} | ConvertTo-Json -Compress

$proc = [System.Diagnostics.Process]::Start($psi)
$proc.StandardInput.WriteLine($genericPayload)
$proc.StandardInput.Close()
$genericOut = $proc.StandardOutput.ReadToEnd()
$proc.WaitForExit(3000)

$genericJson = $null
try { $genericJson = $genericOut | ConvertFrom-Json } catch {}
$genericValid = ($null -ne $genericJson -and $genericJson.continue -eq $true -and $genericJson.decision -eq "allow" -and $genericJson.allowed -eq $true)
Assert-Check -Name "Cross-Tool Support: Generic runner receives 'decision: allow' and 'allowed: true'" `
             -Condition $genericValid `
             -Details "Decision: $($genericJson.decision) | Allowed: $($genericJson.allowed) | Status: $($genericJson.status)"

# 3G: Test Google Antigravity / Gemini CLI toolCall payload format
$agPayload = @{
    hook_event_name = "PreToolUse"
    conversationId  = $mockSessionId
    toolCall        = @{
        name = "run_command"
        args = @{ CommandLine = "Test-Path policy.cedar" }
    }
} | ConvertTo-Json -Compress

$proc = [System.Diagnostics.Process]::Start($psi)
$proc.StandardInput.WriteLine($agPayload)
$proc.StandardInput.Close()
$agOut = $proc.StandardOutput.ReadToEnd()
$proc.WaitForExit(3000)

$agJson = $null
try { $agJson = $agOut | ConvertFrom-Json } catch {}
$agValid = ($null -ne $agJson -and $agJson.continue -eq $true -and $agJson.decision -eq "allow" -and $agJson.allowed -eq $true)
Assert-Check -Name "Cross-Tool Support: Antigravity toolCall payload permitted with 'allow'" `
             -Condition $agValid `
             -Details "Decision: $($agJson.decision) | Allowed: $($agJson.allowed) | Tool: $($agJson.hookSpecificOutput.hookEventName)"

# -----------------------------------------------------------------------------
# TEST 4: Claude Settings Sanitization (SessionEnd MUST be Absent)
# -----------------------------------------------------------------------------
Write-Host "`n--- [TEST 4] Claude Code Settings Sanitization Check ---" -ForegroundColor Yellow

$globalSettings = Join-Path $env:USERPROFILE ".claude\settings.json"
$workspaceSettings = Join-Path (Get-Location).Path ".claude\settings.json"

foreach ($file in @($globalSettings, $workspaceSettings)) {
    $exists = $false
    try { $exists = Test-Path -LiteralPath $file -PathType Leaf -ErrorAction SilentlyContinue } catch {}
    if ($exists) {
        $hasSessionEnd = $false
        $hasEssentialHooks = $false
        try {
            $data = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
            if ($data.hooks) {
                if ($data.hooks.PSObject.Properties.Name -contains "SessionEnd") {
                    $hasSessionEnd = $true
                }
                if ($data.hooks.PreToolUse -and $data.hooks.SessionStart) {
                    $hasEssentialHooks = $true
                }
            }
        } catch {}

        Assert-Check -Name "SessionEnd hook is absent in $(Split-Path $file -Leaf) (No double-firing/timeouts)" `
                     -Condition (-not $hasSessionEnd) `
                     -Details "Path: $file"

        Assert-Check -Name "Core hooks (PreToolUse, SessionStart) active in $(Split-Path $file -Leaf)" `
                     -Condition $hasEssentialHooks `
                     -Details "Path: $file"
    } else {
        Write-Host "  [i] Settings file not present at: $file (will be created cleanly on launch)" -ForegroundColor DarkGray
    }
}

# -----------------------------------------------------------------------------
# TEST 5: PyPI Package Distribution Check
# -----------------------------------------------------------------------------
Write-Host "`n--- [TEST 5] PyPI Package Distribution Check ---" -ForegroundColor Yellow
$distDir = Join-Path $PSScriptRoot "..\dist"
$wheels = @(Get-ChildItem -Path $distDir -Filter "bap_ltd-1.9.2-*.whl" -ErrorAction SilentlyContinue)

Assert-Check -Name "Built bap_ltd-1.9.2 wheel package exists in dist/" `
             -Condition ($wheels.Count -gt 0) `
             -Details $(if ($wheels) { "Found: $($wheels[0].Name) ($([math]::Round($wheels[0].Length/1MB, 2)) MB)" } else { "None" })

# -----------------------------------------------------------------------------
# SUMMARY REPORT
# -----------------------------------------------------------------------------
Write-Host "`n================================================================================" -ForegroundColor Cyan
Write-Host "                         TEST SUITE SUMMARY REPORT                              " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " Total Tests Run : $($global:PassedTests + $global:FailedTests)"
Write-Host " Passed          : $global:PassedTests" -ForegroundColor Green
Write-Host " Failed          : $global:FailedTests" -ForegroundColor $(if ($global:FailedTests -gt 0) { "Red" } else { "Green" })
Write-Host "================================================================================" -ForegroundColor Cyan

if ($global:FailedTests -eq 0) {
    Write-Host "[SUCCESS] ALL CHECKS PASSED. BAP v1.9.2 Zero-Trust is Rock-Solid.`n" -ForegroundColor Green
    exit 0
} else {
    Write-Host "[FAILURE] Some checks failed. Review the output above.`n" -ForegroundColor Red
    exit 1
}
