<#
.SYNOPSIS
    BAP Zero-Trust Session Reviewer & Performance Inspector
.DESCRIPTION
    Lists recent AI agent sessions (Claude Code, Codex, Copilot, Antigravity)
    from the BAP audit ledger, allowing the developer to pick a session and inspect
    its policy decisions, execution latencies, security blocks, and performance.
.EXAMPLE
    .\review_session.ps1
    .\review_session.ps1 1
    .\review_session.ps1 sess-claude-holistic-737184700
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$TargetSession,

    [Parameter(Position = 1)]
    [string]$Path,

    [int]$Limit = 10,

    [switch]$NonInteractive,

    [switch]$Fix,

    [switch]$Json,

    [string]$JsonOut
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'session_calls.ps1')

function Iif($condition, $trueValue, $falseValue) {
    if ($condition) { return $trueValue } else { return $falseValue }
}

function Find-AuditLedgers {
    param([string]$ExplicitPath)

    $candidates = @()

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        if (Test-Path -LiteralPath $ExplicitPath) {
            $item = Get-Item -LiteralPath $ExplicitPath
            if ($item.PSIsContainer) {
                $candidates += (Join-Path $ExplicitPath ".bapstate\audit.jsonl")
                $candidates += (Join-Path $ExplicitPath "audit.jsonl")
            } else {
                $candidates += $ExplicitPath
            }
        }
    }

    if ($env:BAP_STATE_DIR) {
        $candidates += (Join-Path $env:BAP_STATE_DIR "audit.jsonl")
    }

    $candidates += @(
        (Join-Path (Get-Location) ".bapstate\audit.jsonl"),
        (Join-Path (Get-Location) "audit.jsonl"),
        (Join-Path (Get-Location) "ltd-audit.jsonl"),
        (Join-Path $env:USERPROFILE ".bapstate\audit.jsonl"),
        (Join-Path $env:USERPROFILE ".ltd\audit.jsonl")
    )

    # Search immediate sibling workspaces if current workspace has no records
    try {
        $siblingDirs = Get-ChildItem -Path ".." -Directory -ErrorAction SilentlyContinue | Select-Object -First 10
        foreach ($sd in $siblingDirs) {
            $candidates += (Join-Path $sd.FullName ".bapstate\audit.jsonl")
        }
    } catch {}

    $found = @()
    foreach ($c in $candidates) {
        try {
            if (Test-Path -LiteralPath $c -ErrorAction SilentlyContinue) {
                if (-not ($found -contains $c)) {
                    $found += $c
                }
            }
        } catch {}
    }
    return $found
}

function Load-SessionData {
    param([string[]]$LedgerPaths)

    $sessions = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[psobject]]]::new()

    # 1. Parse JSON lines from audit ledgers
    foreach ($p in $LedgerPaths) {
        try {
            $lines = [System.IO.File]::ReadAllLines($p)
            foreach ($line in $lines) {
                $trimmed = $line.Trim()
                if ($trimmed.Length -gt 2 -and $trimmed.StartsWith("{") -and $trimmed.EndsWith("}")) {
                    try {
                        $evt = $trimmed | ConvertFrom-Json
                        $sid = [string]$evt.session_id
                        if ([string]::IsNullOrWhiteSpace($sid)) {
                            if ($evt.receipt -and -not [string]::IsNullOrWhiteSpace($evt.receipt.session_id)) {
                                $sid = [string]$evt.receipt.session_id
                            } else {
                                $sid = "sess-adhoc-unassigned"
                            }
                        }
                        if (-not $sessions.ContainsKey($sid)) {
                            $sessions[$sid] = [System.Collections.Generic.List[psobject]]::new()
                        }
                        $sessions[$sid].Add($evt)
                    } catch {}
                }
            }
        } catch {}
    }

    # 2. Check hook-evidence spool directories for any undrained hook evidence
    $evidenceDirs = @(
        (Join-Path (Get-Location) ".bapstate\hook-evidence"),
        (Join-Path $env:USERPROFILE ".bapstate\hook-evidence")
    )
    if ($env:BAP_STATE_DIR) {
        $evidenceDirs = @((Join-Path $env:BAP_STATE_DIR "hook-evidence")) + $evidenceDirs
    }
    foreach ($ed in $evidenceDirs) {
        try {
            if (Test-Path -LiteralPath $ed -ErrorAction SilentlyContinue) {
                $evidenceFiles = Get-ChildItem -Path $ed -Filter "*.json" -ErrorAction SilentlyContinue
                foreach ($ef in $evidenceFiles) {
                    try {
                        $content = [System.IO.File]::ReadAllText($ef.FullName)
                        $evt = $content | ConvertFrom-Json
                        $sid = [string]$evt.session_id
                        if ([string]::IsNullOrWhiteSpace($sid)) { $sid = "sess-hook-spool" }
                        if (-not $sessions.ContainsKey($sid)) {
                            $sessions[$sid] = [System.Collections.Generic.List[psobject]]::new()
                        }
                        $sessions[$sid].Add($evt)
                    } catch {}
                }
            }
        } catch {}
    }

    return $sessions
}

function Format-Timestamp {
    param([string]$IsoString)
    if ([string]::IsNullOrWhiteSpace($IsoString)) { return "N/A" }
    try {
        $dto = [DateTimeOffset]::Parse($IsoString)
        return $dto.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss")
    } catch {
        if ($IsoString.Length -gt 19) { return $IsoString.Substring(0, 19).Replace("T", " ") }
        return $IsoString
    }
}

function Format-TimeOnly {
    param([string]$IsoString)
    if ([string]::IsNullOrWhiteSpace($IsoString)) { return "--:--:--" }
    try {
        $dto = [DateTimeOffset]::Parse($IsoString)
        return $dto.UtcDateTime.ToString("HH:mm:ss.ff")
    } catch {
        return $IsoString
    }
}

function Build-CallsReport {
    param([string]$SessionId, [string]$Agent, [psobject[]]$Events, [double]$AvgLatency, [double]$MaxLatency)

    $allowedCalls = @()
    $blockedCalls = @()
    $narrowedGrants = @()

    $zspNoGrant = 0
    $zspGrantsMinted = 0
    $zspNarrowed = 0
    $zspSingleUseBurn = 0
    $zspCredIsolation = 0
    $zspHighRiskOOB = 0

    foreach ($e in $Events) {
        $dec = ([string]$e.decision).ToLowerInvariant()
        $reason = [string]$e.reason
        $reasonLow = $reason.ToLowerInvariant()
        $isNarrowed = ($e.narrowing_applied -eq $true)
        $isDeny = ($dec -in @('deny', 'denied', 'block', 'blocked', 'forbidden'))
        $isAllow = ($e.outcome -in @('allowed', 'allowed_limited'))

        $concept = [string]$e.zsp_concept
        if ([string]::IsNullOrWhiteSpace($concept)) {
            if ($isNarrowed) { $concept = "ZSP_SCOPE_NARROWED" }
            elseif ($reasonLow -match "max uses exceeded|already burned") { $concept = "ZSP_SINGLE_USE_BURN" }
            elseif ($reasonLow -match "zero standing privileges") { $concept = "ZSP_DENY_NO_GRANT" }
            elseif ($reasonLow -match "credential|sensitive credential|\.env") { $concept = "CREDENTIAL_ISOLATION" }
            elseif ($reasonLow -match "out-of-band|high-risk|step-up|escapes_workspace") { $concept = "HIGH_RISK_OOB_GATE" }
        }

        switch ($concept) {
            "ZSP_DENY_NO_GRANT"    { $zspNoGrant++ }
            "ZSP_GRANT_MINTED"     { $zspGrantsMinted++ }
            "ZSP_SCOPE_NARROWED"   { $zspNarrowed++; $zspGrantsMinted++ }
            "ZSP_SINGLE_USE_BURN"  { $zspSingleUseBurn++ }
            "CREDENTIAL_ISOLATION" { $zspCredIsolation++ }
            "HIGH_RISK_OOB_GATE"   { $zspHighRiskOOB++ }
        }

        $callObj = [PSCustomObject]@{
            timestamp          = [string]$e.timestamp
            decision           = if ($isNarrowed -and $isAllow) { "ALLOWED-LIMITED" } elseif ($isDeny) { "BLOCKED" } elseif ($e.outcome -eq 'failed') { 'FAILED' } elseif ($e.outcome -eq 'unclassified') { 'UNCLASSIFIED' } else { "ALLOWED" }
            outcome            = $e.outcome
            raw_decision       = [string]$e.decision
            reporting_layer    = if ($e.reporting_layer) { [string]$e.reporting_layer } else { "hook" }
            tool               = [string]$e.executable
            command            = [string]$e.full_command
            reason             = $reason
            canonical_action   = [string]$e.canonical_action
            canonical_resource = [string]$e.canonical_resource
            grant_id           = [string]$e.grant_id
            narrowing_applied  = $isNarrowed
            narrowing_reason   = [string]$e.narrowing_reason
            requested_actions  = $e.requested_actions
            allowed_actions    = $e.allowed_actions
            zsp_concept        = $concept
        }

        if ($isNarrowed) { $narrowedGrants += $callObj }
        if ($isDeny) { $blockedCalls += $callObj }
        elseif ($isAllow -and -not $isNarrowed) { $allowedCalls += $callObj }
    }

    return [PSCustomObject]@{
        session_id = $SessionId
        agent      = $Agent
        summary    = [PSCustomObject]@{
            total_events          = $Events.Count
            allowed_count         = $allowedCalls.Count
            blocked_count         = $blockedCalls.Count
            narrowed_count        = $narrowedGrants.Count
            allowed_limited_count = $narrowedGrants.Count
            avg_latency_ms        = $AvgLatency
            max_latency_ms        = $MaxLatency
        }
        zsp_concepts = [PSCustomObject]@{
            zero_standing_privileges_blocks = $zspNoGrant
            task_grants_minted              = $zspGrantsMinted
            scope_narrowing_attenuations    = $zspNarrowed
            single_use_atomic_burns         = $zspSingleUseBurn
            credential_isolation_blocks     = $zspCredIsolation
            high_risk_oob_escalations       = $zspHighRiskOOB
        }
        allowed_calls         = $allowedCalls
        blocked_calls         = $blockedCalls
        narrowed_grants       = $narrowedGrants
        allowed_limited_calls = $narrowedGrants
    }
}

function Summarize-Session {
    param([string]$SessionId, [psobject[]]$Events)

    $rawEvents = $Events
    $Events = @(ConvertTo-LogicalCalls -Events $Events)
    if ($Events.Count -eq 0) { return }

    $first = $Events[0]
    $last = $Events[$Events.Count - 1]

    $allowed = 0
    $denied = 0
    $latencies = @()

    foreach ($e in $Events) {
        $dec = [string]$e.decision
        if ($e.outcome -eq 'allowed') {
            $allowed++
        } elseif ($dec -in @('deny', 'denied', 'block', 'blocked', 'forbidden')) {
            $denied++
        }

        if ($null -ne $e.duration_ms -and [double]$e.duration_ms -gt 0) {
            $latencies += [double]$e.duration_ms
        }
    }

    $agent = "unknown"
    if ($first.source) { $agent = [string]$first.source }
    elseif ($first.agent_id) { $agent = [string]$first.agent_id }

    if ($SessionId -match '^sess-claude') { $agent = "claude-code" }
    elseif ($SessionId -match '^sess-codex') { $agent = "codex" }
    elseif ($SessionId -match '^sess-copilot') { $agent = "copilot" }
    elseif ($SessionId -match '^sess-antigravity') { $agent = "antigravity" }

    $avgLatency = if ($latencies.Count -gt 0) {
        [Math]::Round(($latencies | Measure-Object -Average).Average, 1)
    } else {
        0.0
    }

    $minLatency = if ($latencies.Count -gt 0) { ($latencies | Measure-Object -Minimum).Minimum } else { 0.0 }
    $maxLatency = if ($latencies.Count -gt 0) { ($latencies | Measure-Object -Maximum).Maximum } else { 0.0 }

    $callsReport = Build-CallsReport -SessionId $SessionId -Agent $agent -Events $Events -AvgLatency $avgLatency -MaxLatency $maxLatency
    $rawActionCount = @($rawEvents | Where-Object { $_.full_command -notin @('USER_PROMPT_SUBMITTED', 'AGENT_RESPONSE') -and $_.executable -ne 'agent_response' }).Count
    $callsReport.summary | Add-Member -NotePropertyName raw_events -NotePropertyValue $rawActionCount
    $callsReport.summary | Add-Member -NotePropertyName failed_count -NotePropertyValue @($Events | Where-Object outcome -eq 'failed').Count
    $callsReport.summary | Add-Member -NotePropertyName unclassified_count -NotePropertyValue @($Events | Where-Object outcome -eq 'unclassified').Count

    $statusText = if ($callsReport.summary.failed_count -gt 0 -or $callsReport.summary.unclassified_count -gt 0) {
        '[REVIEW] Failed or unclassified actions'
    } elseif ($denied -eq 0 -and $callsReport.summary.narrowed_count -gt 0) {
        "[LIMITED] Scope Attenuated ($($callsReport.summary.narrowed_count))"
    } elseif ($denied -eq 0) {
        "[PASS] 100% Compliant (All Allowed)"
    } else {
        "[BLOCKED] $denied Invariant Blocks"
    }

    return [PSCustomObject]@{
        SessionId      = $SessionId
        Agent          = $agent
        StartTime      = $first.timestamp
        EndTime        = $last.timestamp
        LastActive     = Format-Timestamp $last.timestamp
        TotalEvents    = $Events.Count
        Allowed        = $allowed
        Denied         = $denied
        Narrowed       = $callsReport.summary.narrowed_count
        AllowedLimited = $callsReport.summary.narrowed_count
        AvgLatency     = $avgLatency
        MinLatency     = $minLatency
        MaxLatency     = $maxLatency
        StatusText     = $statusText
        CallsReport    = $callsReport
        RawEvents      = $rawEvents
    }
}

function Show-SessionList {
    param([array]$Summaries)

    try { Clear-Host } catch {}
    Write-Host ""
    Write-Host "========================================================================================================" -ForegroundColor Cyan
    Write-Host "  [BAP ZERO-TRUST] Session Reviewer and Performance Inspector" -ForegroundColor White
    Write-Host "========================================================================================================" -ForegroundColor Cyan
    Write-Host "  Audit Ledger: $($script:activeLedgers -join ', ')" -ForegroundColor Gray
    Write-Host "  Showing latest $($Summaries.Count) agent sessions recorded on this workstation:`n" -ForegroundColor Gray

    Write-Host ("  {0,-4} {1,-34} {2,-13} {3,-20} {4,-6} {5,-7} {6,-8} {7}" -f "#", "SESSION ID", "AGENT", "LATEST ACTIVITY (UTC)", "EVENTS", "ALLOW", "BLOCK", "SECURITY STATUS") -ForegroundColor Yellow
    Write-Host "  ------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGray

    for ($i = 0; $i -lt $Summaries.Count; $i++) {
        $s = $Summaries[$i]
        $num = "[$($i + 1)]"
        $sidShort = if ($s.SessionId.Length -gt 33) { $s.SessionId.Substring(0, 31) + ".." } else { $s.SessionId }

        $color = if ($s.Denied -gt 0) { "Red" } elseif ($s.Narrowed -gt 0) { "Yellow" } else { "Green" }
        if ($i -eq 0) {
            Write-Host ("  {0,-4} {1,-34} {2,-13} {3,-20} {4,-6} {5,-7} {6,-8} {7}" -f $num, $sidShort, $s.Agent, $s.LastActive, $s.TotalEvents, $s.Allowed, $s.Denied, $s.StatusText) -ForegroundColor $color
        } else {
            Write-Host ("  {0,-4} {1,-34} {2,-13} {3,-20} {4,-6} {5,-7} {6,-8} {7}" -f $num, $sidShort, $s.Agent, $s.LastActive, $s.TotalEvents, $s.Allowed, $s.Denied, $s.StatusText) -ForegroundColor Gray
        }
    }
    Write-Host "  ------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
}

function Show-SessionDetail {
    param([PSCustomObject]$Summary)

    try { Clear-Host } catch {}
    Write-Host ""
    Write-Host "========================================================================================================" -ForegroundColor Cyan
    Write-Host "  [BAP ZERO-TRUST] Session Performance and Governance Report" -ForegroundColor White
    Write-Host "========================================================================================================" -ForegroundColor Cyan
    Write-Host "  Session ID      : " -NoNewline; Write-Host $Summary.SessionId -ForegroundColor Yellow
    Write-Host "  AI Agent Client : " -NoNewline; Write-Host $Summary.Agent -ForegroundColor Cyan
    Write-Host "  Time Window     : $($Summary.StartTime)  -->  $($Summary.EndTime)" -ForegroundColor Gray

    Write-Host "  Health Verdict  : " -NoNewline
    if ($Summary.Denied -eq 0 -and $Summary.Narrowed -gt 0) {
        Write-Host ("[PASS] 100% COMPLIANT (ALLOWED-LIMITED) - {0} action(s) scope-narrowed to least privilege" -f $Summary.Narrowed) -ForegroundColor Yellow
    } elseif ($Summary.Denied -eq 0) {
        Write-Host "[PASS] 100% COMPLIANT - All agent operations permitted by Zero-Trust policy" -ForegroundColor Green
    } else {
        Write-Host ("[CONTAINED] ZERO-TRUST BOUNDARIES HELD - {0} unauthorized operation(s) blocked fail-closed" -f $Summary.Denied) -ForegroundColor Yellow
    }

    Write-Host "--------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  KEY PERFORMANCE AND SLA METRICS:" -ForegroundColor White
    Write-Host ("    * Total Evaluated Operations : {0}" -f $Summary.TotalEvents)
    Write-Host ("    * Permitted Actions          : {0}" -f $Summary.Allowed) -ForegroundColor Green
    Write-Host ("    * Blocked Security Actions   : {0}" -f $Summary.Denied) -ForegroundColor (Iif ($Summary.Denied -gt 0) "Red" "Gray")
    Write-Host ("    * Scope Attenuated (Limited) : {0}" -f $Summary.Narrowed) -ForegroundColor (Iif ($Summary.Narrowed -gt 0) "DarkYellow" "Gray")
    Write-Host ("    * Average Decision Latency   : {0} ms" -f $Summary.AvgLatency) -ForegroundColor Cyan
    Write-Host ("    * Peak Decision Latency      : {0} ms (Min: {1} ms)" -f $Summary.MaxLatency, $Summary.MinLatency) -ForegroundColor Gray
    
    $slaMet = if ($Summary.MaxLatency -le 350.0) { "[PASS] (< 350ms SLA Target Met)" } else { "[!] Latency spike observed" }
    Write-Host ("    * SLA Target Compliance      : {0}" -f $slaMet) -ForegroundColor Green
    Write-Host "--------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGray

    $zc = $Summary.CallsReport.zsp_concepts
    Write-Host "  ZERO-TRUST & ZSP CONCEPTS OBSERVED:" -ForegroundColor Cyan
    Write-Host ("    [1] Zero Standing Privileges (Ungranted Blocks) : {0}" -f $zc.zero_standing_privileges_blocks) -ForegroundColor (Iif ($zc.zero_standing_privileges_blocks -gt 0) "Red" "Gray")
    Write-Host ("    [2] 4-Tuple TaskGrant Minting                   : {0}" -f $zc.task_grants_minted) -ForegroundColor (Iif ($zc.task_grants_minted -gt 0) "Cyan" "Gray")
    Write-Host ("    [3] Monotonic Scope Attenuation (ALLOWED-LIMITED): {0}" -f $zc.scope_narrowing_attenuations) -ForegroundColor (Iif ($zc.scope_narrowing_attenuations -gt 0) "DarkYellow" "Gray")
    if ($Summary.CallsReport.narrowed_grants.Count -gt 0) {
        foreach ($ng in $Summary.CallsReport.narrowed_grants) {
            $reqAct = if ($ng.requested_actions) { ($ng.requested_actions -join ",") } else { "wildcard" }
            $alwAct = if ($ng.allowed_actions) { ($ng.allowed_actions -join ",") } else { "attenuated" }
            Write-Host ("        -> [ALLOWED-LIMITED] {0} | Requested [{1}] -> Granted [{2}]" -f $ng.grant_id, $reqAct, $alwAct) -ForegroundColor DarkYellow
        }
    }
    Write-Host ("    [4] Single-Use Atomic Grant Burn (Replay Block) : {0}" -f $zc.single_use_atomic_burns) -ForegroundColor (Iif ($zc.single_use_atomic_burns -gt 0) "Magenta" "Gray")
    Write-Host ("    [5] Credential Isolation (Invariant Blocks)     : {0}" -f $zc.credential_isolation_blocks) -ForegroundColor (Iif ($zc.credential_isolation_blocks -gt 0) "Red" "Gray")
    Write-Host ("    [6] Out-of-Band HITL Escalation Gate            : {0}" -f $zc.high_risk_oob_escalations) -ForegroundColor (Iif ($zc.high_risk_oob_escalations -gt 0) "Yellow" "Gray")
    Write-Host "--------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGray

    Write-Host "`n  CHRONOLOGICAL ACTION AND DECISION LEDGER:" -ForegroundColor Yellow
    Write-Host ("  {0,-3} {1,-12} {2,-15} {3,-7} {4,-12} {5,-34} {6}" -f "#", "TIME (UTC)", "DECISION", "LAYER", "TOOL", "COMMAND / OPERATION", "SECURITY REASON / DETAILS") -ForegroundColor Yellow
    Write-Host "  ------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGray

    $events = $Summary.RawEvents
    for ($i = 0; $i -lt $events.Count; $i++) {
        $e = $events[$i]
        $timeStr = Format-TimeOnly $e.timestamp
        $dec = [string]$e.decision
        $isNarrowed = ($e.narrowing_applied -eq $true)
        $decUpper = if ($isNarrowed -and ($dec -in @('allow', 'approved', 'approve', 'granted', 'ok', 'allowed-limited'))) { "ALLOWED-LIMITED" } elseif ($dec -in @('allow', 'approved', 'approve', 'granted', 'ok')) { "ALLOW" } else { "BLOCK" }
        $layer = if ($e.reporting_layer) { [string]$e.reporting_layer } else { "hook" }
        $tool = if ($e.executable) { [string]$e.executable } else { "-" }
        
        $cmdStr = if ($e.full_command) { [string]$e.full_command } else { "(empty tool input)" }
        $cmdShort = if ($cmdStr.Length -gt 33) { $cmdStr.Substring(0, 30) + "..." } else { $cmdStr }

        $reason = if ($e.narrowing_reason) { [string]$e.narrowing_reason } elseif ($e.reason) { [string]$e.reason } else { "Policy evaluated" }
        $reasonShort = if ($reason.Length -gt 45) { $reason.Substring(0, 42) + "..." } else { $reason }

        $rowColor = if ($decUpper -eq "ALLOWED-LIMITED") { "DarkYellow" } elseif ($decUpper -eq "ALLOW") { "Green" } else { "Red" }
        Write-Host ("  {0,-3} {1,-12} " -f ($i + 1), $timeStr) -NoNewline -ForegroundColor Gray
        Write-Host ("{0,-15} " -f $decUpper) -NoNewline -ForegroundColor $rowColor
        Write-Host ("{0,-7} {1,-12} {2,-34} {3}" -f $layer, $tool, $cmdShort, $reasonShort) -ForegroundColor White
    }

    Write-Host "  ------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGray

    Write-Host "`n  EXECUTIVE TAKEAWAY FOR END USERS:" -ForegroundColor Cyan
    if ($Summary.Denied -eq 0) {
        Write-Host "  [OK] No blocked logical actions were recorded in this session." -ForegroundColor Green
        Write-Host "       Review failed and unclassified outcomes, and verify boundary coverage separately.`n" -ForegroundColor Gray
    } else {
        Write-Host ("  [!] During this session, the agent attempted {0} action(s) blocked by enterprise invariants." -f $Summary.Denied) -ForegroundColor Yellow
        Write-Host "      Review the recorded reasons and execution results above. Missing latency is reported as zero.`n" -ForegroundColor Gray
    }
    Write-Host "========================================================================================================`n" -ForegroundColor Cyan
}

# --- Main Flow ---

$script:activeLedgers = Find-AuditLedgers -ExplicitPath $Path
if ($script:activeLedgers.Count -eq 0) {
    Write-Host "`n[!] No BAP audit ledger found. Have you executed any governed agent sessions?" -ForegroundColor Red
    Write-Host "    Expected locations: .bapstate\audit.jsonl or %USERPROFILE%\.bapstate\audit.jsonl`n" -ForegroundColor Gray
    exit 0
}

if ($Fix) {
    Write-Host "[*] Explicit --fix requested. Performing audit reconciliation and self-healing..." -ForegroundColor Cyan
    $spoolDirs = @(
        (Join-Path (Get-Location) ".bapstate\hook-evidence"),
        (Join-Path $env:USERPROFILE ".bapstate\hook-evidence")
    )
    $drained = 0
    foreach ($sd in $spoolDirs) {
        try {
            if (Test-Path -LiteralPath $sd -ErrorAction SilentlyContinue) {
                $files = Get-ChildItem -Path $sd -Filter "*.json" -ErrorAction SilentlyContinue
                foreach ($f in $files) {
                    try {
                        $jsonText = [System.IO.File]::ReadAllText($f.FullName)
                        if ($script:activeLedgers.Count -gt 0) {
                            [System.IO.File]::AppendAllText($script:activeLedgers[0], "`n" + $jsonText.Trim())
                            Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue
                            $drained++
                        }
                    } catch {}
                }
            }
        } catch {}
    }
    $recDirs = @(
        (Join-Path (Get-Location) ".bapstate"),
        (Join-Path (Get-Location) ".claude"),
        (Join-Path (Get-Location) ".codex")
    )
    $cleaned = 0
    foreach ($rd in $recDirs) {
        try {
            if (Test-Path -LiteralPath $rd -ErrorAction SilentlyContinue) {
                $recFiles = Get-ChildItem -Path $rd -Filter "*recovery*.json" -ErrorAction SilentlyContinue
                foreach ($rf in $recFiles) {
                    try {
                        $recData = Get-Content -LiteralPath $rf.FullName -Raw | ConvertFrom-Json
                        $alive = $false
                        if ($recData.launcher_pid) {
                            $p = Get-Process -Id ([int]$recData.launcher_pid) -ErrorAction SilentlyContinue
                            if ($p -and -not $p.HasExited) { $alive = $true }
                        }
                        if (-not $alive) {
                            Remove-Item -LiteralPath $rf.FullName -Force -ErrorAction SilentlyContinue
                            $cleaned++
                        }
                    } catch {}
                }
            }
        } catch {}
    }
    Write-Host "[+] Auto-remediation complete: $drained spool event(s) drained, $cleaned stale manifest(s) cleared.`n" -ForegroundColor Green
}

$sessionsDict = Load-SessionData -LedgerPaths $script:activeLedgers
if ($sessionsDict.Keys.Count -eq 0) {
    Write-Host "`n[*] Audit ledger found, but no sessions recorded yet." -ForegroundColor Yellow
    foreach ($al in $script:activeLedgers) {
        $fileSize = 0
        try { $fileSize = (Get-Item -LiteralPath $al).Length } catch {}
        Write-Host "    - Location: $al ($fileSize bytes)" -ForegroundColor DarkGray
    }
    Write-Host "`n  Why? This occurs on a fresh or newly upgraded installation where the BAP ledger" -ForegroundColor White
    Write-Host "  has been initialized cleanly, but no governed agent actions have been run yet." -ForegroundColor White
    Write-Host "`n  Run any of the following to produce your first governed session:" -ForegroundColor Cyan
    Write-Host "    1. bap claude (or bap codex)          - Launch an interactive governed agent session" -ForegroundColor Gray
    Write-Host "    2. bap exec `"git status`"               - Execute a command through the BAP Zero-Trust broker" -ForegroundColor Gray
    Write-Host "    3. powershell -File .\tests\test_claude_holistic.ps1  - Run the automated test suite" -ForegroundColor Gray
    Write-Host "`n  If you ran your agent in a specific workspace directory, specify it directly:" -ForegroundColor White
    Write-Host "     .\review_session.ps1 -Path `"C:\path\to\workspace`"`n" -ForegroundColor Cyan
    exit 0
}

# Sort sessions: prioritize active execution sessions (sess-*) over 1-event observation heartbeats (observed-*), then descending by latest event timestamp
$sortedSessionIds = $sessionsDict.Keys | Sort-Object `
    @{ Expression = { if ($_ -like 'observed-*' -and $sessionsDict[$_].Count -le 2) { 1 } else { 0 } }; Ascending = $true }, `
    @{ Expression = { $evts = $sessionsDict[$_]; [string]$evts[$evts.Count - 1].timestamp }; Descending = $true }

$summaries = @()
foreach ($sid in ($sortedSessionIds | Select-Object -First $Limit)) {
    $summaries += Summarize-Session -SessionId $sid -Events ($sessionsDict[$sid].ToArray())
}

# If TargetSession is specified directly, select it
if (-not [string]::IsNullOrWhiteSpace($TargetSession)) {
    $match = $null
    if ($TargetSession -match '^\d+$') {
        $idx = [int]$TargetSession - 1
        if ($idx -ge 0 -and $idx -lt $summaries.Count) {
            $match = $summaries[$idx]
        }
    } else {
        $match = $summaries | Where-Object { $_.SessionId -like "*$TargetSession*" } | Select-Object -First 1
    }

    if ($null -ne $match) {
        if (-not [string]::IsNullOrWhiteSpace($JsonOut)) {
            $match.CallsReport | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $JsonOut -Encoding UTF8
            Write-Host "[+] Exported allowed/blocked/narrowed calls JSON to $JsonOut" -ForegroundColor Green
            exit 0
        }
        if ($Json) {
            $match.CallsReport | ConvertTo-Json -Depth 6
            exit 0
        }
        Show-SessionDetail -Summary $match
        exit 0
    } else {
        Write-Host "`n[-] Specified session '$TargetSession' was not found in recent records.`n" -ForegroundColor Red
    }
}

if ($Json) {
    ($summaries | ForEach-Object { $_.CallsReport }) | ConvertTo-Json -Depth 6
    exit 0
}
if (-not [string]::IsNullOrWhiteSpace($JsonOut)) {
    ($summaries | ForEach-Object { $_.CallsReport }) | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $JsonOut -Encoding UTF8
    Write-Host "[+] Exported allowed/blocked/narrowed calls JSON to $JsonOut" -ForegroundColor Green
    exit 0
}

if ($NonInteractive) {
    Show-SessionList -Summaries $summaries
    exit 0
}

# Interactive loop
while ($true) {
    Show-SessionList -Summaries $summaries

    Write-Host "  Select a session [1-$($summaries.Count)], or press [Enter] for latest #1 (or 'q' to quit): " -NoNewline -ForegroundColor White
    $inputChoice = Read-Host

    if ([string]::IsNullOrWhiteSpace($inputChoice)) {
        $inputChoice = "1"
    }

    if ($inputChoice.Trim().ToLower() -in @('q', 'quit', 'exit')) {
        Write-Host "`nExiting session inspector. Stay safe!`n" -ForegroundColor Gray
        break
    }

    $selectedSummary = $null
    if ($inputChoice -match '^\d+$') {
        $idx = [int]$inputChoice - 1
        if ($idx -ge 0 -and $idx -lt $summaries.Count) {
            $selectedSummary = $summaries[$idx]
        }
    } else {
        $selectedSummary = $summaries | Where-Object { $_.SessionId -like "*$inputChoice*" } | Select-Object -First 1
    }

    if ($null -eq $selectedSummary) {
        Write-Host "`n[!] Invalid selection '$inputChoice'. Press [Enter] to try again..." -ForegroundColor Yellow
        Read-Host | Out-Null
        continue
    }

    Show-SessionDetail -Summary $selectedSummary

    Write-Host "  [Enter] Pick another session | [J] Allowed/Blocked Calls JSON | [D] Raw audit JSON | [Q] Quit: " -NoNewline -ForegroundColor White
    $actionChoice = (Read-Host).Trim().ToLower()

    if ($actionChoice -eq 'j') {
        Write-Host "`n--- ALLOWED / BLOCKED / NARROWED CALLS JSON ---" -ForegroundColor Cyan
        $selectedSummary.CallsReport | ConvertTo-Json -Depth 6
        Write-Host "`nPress [Enter] to return to session list..." -ForegroundColor Gray
        Read-Host | Out-Null
    } elseif ($actionChoice -eq 'd') {
        Write-Host "`n--- RAW SESSION AUDIT EVENT JSON ---" -ForegroundColor DarkGray
        $selectedSummary.RawEvents | ConvertTo-Json -Depth 5
        Write-Host "`nPress [Enter] to return to session list..." -ForegroundColor Gray
        Read-Host | Out-Null
    } elseif ($actionChoice -in @('q', 'quit', 'exit')) {
        Write-Host "`nExiting session inspector. Stay safe!`n" -ForegroundColor Gray
        break
    }
}
