# Logical action grouping mirrors control-plane calls_summary.go. The shared
# cross-language fixture is checked by both Go and Python/PowerShell tests.
function ConvertTo-LogicalCalls {
    param([psobject[]]$Events)
    $groups = [System.Collections.Generic.List[object]]::new()
    $acts = @($Events | Where-Object {
        $_.full_command -notin @('USER_PROMPT_SUBMITTED', 'AGENT_RESPONSE') -and $_.executable -ne 'agent_response'
    } | Sort-Object { try { [DateTimeOffset]::Parse($_.timestamp) } catch { [DateTimeOffset]::MinValue } })
    foreach ($e in $acts) {
        $key = (([string]$e.full_command).Trim() -replace '\s+', ' ').ToLowerInvariant()
        if ($key.Contains('zsp authorize')) {
            if ($key -match '--actions[ =]+"?([^"\s]+)') { $key = 'zsp-authorize:' + $Matches[1] }
            else { $key = 'zsp-authorize' }
        }
        try { $ts = [DateTimeOffset]::Parse($e.timestamp) } catch { $ts = [DateTimeOffset]::MinValue }
        $target = $null
        for ($i = $groups.Count - 1; $i -ge 0; $i--) {
            $g = $groups[$i]
            if ($g.key -eq $key -and ($ts - $g.last).TotalSeconds -le 20) { $target = $g; break }
            if (($ts - $g.last).TotalSeconds -gt 60) { break }
        }
        if ($null -eq $target) {
            $target = @{ key = $key; last = $ts; events = [System.Collections.Generic.List[object]]::new() }
            $groups.Add($target)
        }
        $target.events.Add($e)
        if ($ts -gt $target.last) { $target.last = $ts }
    }
    foreach ($g in $groups) {
        $deny = $null; $limited = $null; $failed = $null
        $rep = $g.events[$g.events.Count - 1]
        foreach ($e in $g.events) {
            $d = ([string]$e.decision).ToLowerInvariant()
            if ($d -match 'deny|denied|block|forbid') {
                if ($null -eq $deny -or ([string]$e.reason).Length -gt ([string]$deny.reason).Length) { $deny = $e }
            } elseif ($e.narrowing_applied -eq $true -or $d -match 'limit|narrow') { $limited = $e }
            elseif (([string]$e.reason).ToLowerInvariant().Contains('command execution failed') -or ($e.exit_code -and $e.exit_code -ne 0)) { $failed = $e }
            if ($e.grant_id -and -not $rep.grant_id) { $rep = $e }
        }
        $outcome = 'allowed'; $decision = 'allow'
        if ($null -ne $deny) { $outcome = 'blocked'; $decision = 'deny'; $rep = $deny }
        elseif ($null -ne $limited) { $outcome = 'allowed_limited'; $decision = 'ALLOWED-LIMITED'; $rep = $limited }
        elseif ($null -ne $failed) { $outcome = 'failed'; $decision = 'failed'; $rep = $failed }
        elseif (([string]$rep.decision).Trim().ToLowerInvariant() -notmatch '^allow|^(approve|approved|granted|ok|enrolled|restored)$') { $outcome = 'unclassified'; $decision = 'unclassified' }
        $concept = [string]$rep.zsp_concept
        if (-not $concept) {
            $r = ([string]$rep.reason).ToLowerInvariant()
            if ($r -match 'max uses exceeded|already burned') { $concept = 'ZSP_SINGLE_USE_BURN' }
            elseif ($r.Contains('wildcard permission is not permitted')) { $concept = 'ZSP_WILDCARD_REJECTED' }
            elseif ($r -match 'never grantable|permission policy denies') { $concept = 'ZSP_HARD_DENY' }
            elseif ($r.Contains('mint cap')) { $concept = 'ZSP_MINT_CAP' }
            elseif ($r -match 'zero standing privilege|zerostandingprivilege') { $concept = 'ZSP_DENY_NO_GRANT' }
            elseif ($r -match 'credential|\.env') { $concept = 'CREDENTIAL_ISOLATION' }
            elseif ($r -match 'out-of-band|high-risk') { $concept = 'HIGH_RISK_OOB_GATE' }
        }
        if (-not $concept) {
            foreach ($e in $g.events) { if ($e.zsp_concept) { $concept = [string]$e.zsp_concept; break } }
        }
        $authorize = ([string]$rep.full_command).ToLowerInvariant().Contains('zsp authorize')
        if ($concept -eq 'ZSP_GRANT_MINTED' -and -not $authorize) { $concept = 'ZSP_GRANT_USED' }
        if (-not $concept -and $outcome -eq 'allowed' -and $authorize -and $rep.grant_id) { $concept = 'ZSP_GRANT_MINTED' }
        if ($outcome -eq 'allowed_limited' -and $concept -in @('', 'ZSP_GRANT_MINTED')) { $concept = 'ZSP_SCOPE_NARROWED' }
        $copy = [ordered]@{}
        foreach ($p in $rep.PSObject.Properties) { $copy[$p.Name] = $p.Value }
        $copy['decision'] = $decision; $copy['outcome'] = $outcome; $copy['zsp_concept'] = $concept
        $copy['event_count'] = $g.events.Count
        $copy['narrowing_applied'] = ($outcome -eq 'allowed_limited')
        $copy['layers'] = @($g.events | ForEach-Object reporting_layer | Where-Object { $_ } | Sort-Object -Unique)
        [PSCustomObject]$copy
    }
}
