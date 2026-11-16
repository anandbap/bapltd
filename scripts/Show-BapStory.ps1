<#
.SYNOPSIS
    Presenter view of a governed agent session, organised by the demo scenes.
.DESCRIPTION
    Read-only. Reads the local BAP audit ledger and shows what the audience should see:

      Scene 1  The agent asks, policy answers: denied without a grant, a grant card,
               then each action as a one-sentence receipt that names the grant.
      Scene 2  The boundary holds: denied operations, the reason, and proof the target
               did not run, next to an allowed receipt.
      Scene 3  An administrator steps in: freeze / restriction events, if recorded.
      Coverage Which evidence layers were captured, and what is missing.

    Nothing is executed on the agent's behalf and nothing is written.
.EXAMPLE
    .\scripts\Show-BapStory.ps1
    .\scripts\Show-BapStory.ps1 -Scene 1 -Detail
    .\scripts\Show-BapStory.ps1 -SessionId e524bfb8-d23b-45ce-ba4f-d42f4ac5b30e -SinceMinutes 30
    .\scripts\Show-BapStory.ps1 -Json > story.json
#>
[CmdletBinding()]
param(
    [string]$SessionId,
    [ValidateSet('1', '2', '3', 'All')]
    [string]$Scene = 'All',
    [string]$LedgerPath,
    [int]$SinceMinutes = 0,
    [int]$Last = 3,
    [switch]$Detail,
    [switch]$IncludePlumbing,
    [switch]$Json,
    [switch]$NoColor
)

$ErrorActionPreference = 'Stop'
$script:UseColor = -not $NoColor -and -not $Json

# ----------------------------------------------------------------------------
# Output helpers
# ----------------------------------------------------------------------------
function Out-Line {
    param([string]$Text = '', [string]$Color = '')
    if ($Json) { return }
    if ($script:UseColor -and $Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}

function Out-Rule { param([string]$Char = '-') Out-Line ($Char * 98) 'DarkGray' }

function Limit-Text {
    param($Text, [int]$Max = 90)
    $s = ([string]$Text) -replace '\s+', ' '
    if ($s.Length -le $Max) { return $s.Trim() }
    return $s.Substring(0, $Max - 3).Trim() + '...'
}

function Get-Prop {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function ConvertTo-Utc {
    param($Value)
    if ($Value -is [datetime]) { return ([datetimeoffset]$Value).UtcDateTime }
    try { return [DateTimeOffset]::Parse([string]$Value).UtcDateTime } catch { return [datetime]::MinValue }
}

function Get-ShortId {
    param([string]$Id)
    if ([string]::IsNullOrWhiteSpace($Id)) { return 'none' }
    if ($Id.Length -le 14) { return $Id }
    return $Id.Substring(0, 6) + '..' + $Id.Substring($Id.Length - 6)
}

# ----------------------------------------------------------------------------
# Evidence loading (mirrors bapedge's state directory resolution)
# ----------------------------------------------------------------------------
function Get-LedgerCandidates {
    param([string]$Explicit)
    $c = New-Object System.Collections.Generic.List[string]
    if ($Explicit) {
        if (Test-Path -LiteralPath $Explicit -PathType Container) {
            $c.Add((Join-Path $Explicit 'audit.jsonl')); $c.Add((Join-Path $Explicit '.bapstate\audit.jsonl'))
        } else { $c.Add($Explicit) }
    }
    foreach ($v in 'BAP_AUDIT_LOG', 'LTD_AUDIT_LOG') {
        $val = [Environment]::GetEnvironmentVariable($v)
        if ($val) { $c.Add($val) }
    }
    if ($env:BAP_STATE_DIR) { $c.Add((Join-Path $env:BAP_STATE_DIR 'audit.jsonl')) }
    # bapedge's default state directory is <home>\bin\.bapstate (state.Dir in bap-edge).
    $c.Add((Join-Path $env:USERPROFILE 'bin\.bapstate\audit.jsonl'))
    $c.Add((Join-Path $env:USERPROFILE '.bapstate\audit.jsonl'))
    $c.Add((Join-Path $env:USERPROFILE '.ltd\audit.jsonl'))
    $c.Add((Join-Path (Get-Location) '.bapstate\audit.jsonl'))
    $c.Add((Join-Path (Get-Location) 'audit.jsonl'))
    $c.Add((Join-Path (Get-Location) 'ltd-audit.jsonl'))
    $c.Add((Join-Path ([IO.Path]::GetTempPath()) 'bapstate\audit.jsonl'))
    return $c
}

function Get-LedgerFiles {
    param([string]$Explicit)
    $found = New-Object System.Collections.Generic.List[string]
    $searched = New-Object System.Collections.Generic.List[string]
    foreach ($p in (Get-LedgerCandidates -Explicit $Explicit)) {
        $searched.Add($p)
        if (Test-Path -LiteralPath $p -PathType Leaf -ErrorAction SilentlyContinue) {
            if (-not $found.Contains($p)) { $found.Add($p) }
        }
        # Acknowledged records keep a full local copy in a recovery archive.
        foreach ($a in @(Get-ChildItem -Path ($p + '.recovery-*.jsonl') -ErrorAction SilentlyContinue)) {
            if (-not $found.Contains($a.FullName)) { $found.Add($a.FullName) }
        }
    }
    return [pscustomobject]@{ Found = @($found); Searched = @($searched) }
}

function Read-Events {
    param([string[]]$Files)
    $seen = @{}
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($f in $Files) {
        try { $lines = [IO.File]::ReadAllLines($f) } catch { continue }
        foreach ($line in $lines) {
            $t = $line.Trim()
            if ($t.Length -lt 3 -or -not $t.StartsWith('{')) { continue }
            try { $e = $t | ConvertFrom-Json } catch { continue }
            $inner = Get-Prop $e 'entry'
            if ($inner -and (Get-Prop $inner 'event_id')) { $e = $inner }
            $id = [string](Get-Prop $e 'event_id')
            if ($id) {
                if ($seen.ContainsKey($id)) { continue }
                $seen[$id] = $true
            }
            $e | Add-Member -NotePropertyName '_ledger' -NotePropertyValue $f -Force
            $all.Add($e)
        }
    }
    return @($all | Sort-Object { ConvertTo-Utc (Get-Prop $_ 'timestamp') })
}

# ----------------------------------------------------------------------------
# Classification
# ----------------------------------------------------------------------------
$GrantMintConcepts = @('ZSP_GRANT_MINTED', 'ZSP_APPROVED_GRANT_REUSED', 'ZSP_SCOPE_NARROWED', 'ZSP_DEV_OVERRIDE_GRANT')

function Test-Plumbing {
    param($E)
    $x = [string](Get-Prop $E 'executable')
    $c = [string](Get-Prop $E 'full_command')
    return ($x -match '^mcp__ccd_(turn|session|view|host)' -or $c -match '^mcp__ccd_(turn|session|view|host)')
}

function Test-Denied {
    param($E)
    return (([string](Get-Prop $E 'decision')).ToLowerInvariant() -match 'deny|denied|block|forbid')
}

function Test-GrantMint {
    param($E)
    $concept = [string](Get-Prop $E 'zsp_concept')
    $cmd = ([string](Get-Prop $E 'full_command')).ToLowerInvariant()
    return (($concept -in $GrantMintConcepts) -and (-not (Test-Denied $E)) -and $cmd.Contains('zsp authorize'))
}

function Get-ConceptFor {
    param($E)
    $c = [string](Get-Prop $E 'zsp_concept')
    if ($c) { return $c }
    $r = ([string](Get-Prop $E 'reason')).ToLowerInvariant()
    if ($r -match 'zero standing privilege|zerostandingprivilege') { return 'ZSP_DENY_NO_GRANT' }
    if ($r -match 'credential|\.env|secret') { return 'CREDENTIAL_ISOLATION' }
    if ($r -match 'out-of-band|high-risk') { return 'HIGH_RISK_OOB_GATE' }
    return ''
}

function Get-Operation {
    param($E)
    $cmd = [string](Get-Prop $E 'full_command')
    if ($cmd) { return $cmd }
    $x = [string](Get-Prop $E 'executable')
    return $x
}

# The hook, broker and interceptor can each record the same action. Merge identical
# commands seen within 20 seconds into one logical event (same idea as the dashboard's
# logical-call grouping) and keep the richest copy: denied first, then one with a
# process tree, then one carrying a grant.
function Merge-Logical {
    param([object[]]$Events)
    $groups = New-Object System.Collections.Generic.List[object]
    $sorted = @($Events | Sort-Object { ConvertTo-Utc (Get-Prop $_ 'timestamp') })
    foreach ($e in $sorted) {
        $key = (([string](Get-Prop $e 'full_command')) -replace '\s+', ' ').Trim().ToLowerInvariant()
        if (-not $key) {
            $key = 'meta:' + [string](Get-Prop $e 'executable') + ':' + [string](Get-Prop $e 'content_hash') + ':' + [string](Get-Prop $e 'event_id')
        }
        $ts = ConvertTo-Utc (Get-Prop $e 'timestamp')
        $target = $null
        for ($i = $groups.Count - 1; $i -ge 0; $i--) {
            $g = $groups[$i]
            if ($g.Key -eq $key -and ($ts - $g.Last).TotalSeconds -le 20) { $target = $g; break }
            if (($ts - $g.Last).TotalSeconds -gt 60) { break }
        }
        if ($null -eq $target) {
            $target = [pscustomobject]@{ Key = $key; Last = $ts; Events = (New-Object System.Collections.Generic.List[object]) }
            $groups.Add($target)
        }
        $target.Events.Add($e)
        if ($ts -gt $target.Last) { $target.Last = $ts }
    }
    foreach ($g in $groups) {
        $rep = $null
        foreach ($e in $g.Events) {
            if (Test-Denied $e) { $rep = $e; break }
        }
        if ($null -eq $rep) {
            $rep = $g.Events | Where-Object { @(@(Get-Prop $_ 'process_tree') | Where-Object { $_ }).Count -gt 0 } | Select-Object -Last 1
        }
        if ($null -eq $rep) { $rep = $g.Events | Where-Object { Get-Prop $_ 'grant_id' } | Select-Object -Last 1 }
        if ($null -eq $rep) { $rep = $g.Events[$g.Events.Count - 1] }
        # Fill gaps from the other copies instead of discarding their evidence. The copy
        # with the richest process data is not always the one that recorded the grant.
        foreach ($field in @('grant_id', 'duration_ms', 'process_tree', 'policy_eval_ms', 'pre_exec_ms', 'canonical_action', 'canonical_resource',
                             'spiffe_id', 'delegation', 'user_id', 'user_email', 'source', 'client_pid', 'lineage_tree', 'caller_binary',
                             'caller_hash', 'receipt_id', 'request_hash', 'policy_version', 'policy_hash', 'entry_hash', 'previous_hash')) {
            $have = Get-Prop $rep $field
            $missing = ($null -eq $have) -or (($have -is [string]) -and $have -eq '') -or (($have -is [array]) -and @($have | Where-Object { $_ }).Count -eq 0)
            if ($missing) {
                $src = $g.Events | Where-Object { $v = Get-Prop $_ $field; $null -ne $v -and "$v" -ne '' } | Select-Object -First 1
                if ($src) { $rep | Add-Member -NotePropertyName $field -NotePropertyValue (Get-Prop $src $field) -Force }
            }
        }
        $rep | Add-Member -NotePropertyName '_copies' -NotePropertyValue $g.Events.Count -Force
        $rep | Add-Member -NotePropertyName '_ledgers' -NotePropertyValue @($g.Events | ForEach-Object { Get-Prop $_ '_ledger' } | Sort-Object -Unique).Count -Force
        $rep
    }
}

function Get-PillarFields {
    param($E, [string]$Owner, [string]$Agent)
    $spiffe = [string](Get-Prop $E 'spiffe_id')
    $source = [string](Get-Prop $E 'source')
    $cpid = Get-Prop $E 'client_pid'
    $callerBin = [string](Get-Prop $E 'caller_binary')

    # 1. WHO (Initiator)
    $who = if ($spiffe) { $spiffe } elseif ($source) { "agent:$source" } else { $Agent }
    if ($callerBin) {
        $binLeaf = Split-Path $callerBin -Leaf
        $who += " via $binLeaf"
    }
    if ($cpid) { $who += " (PID $cpid)" }

    # 2. OBO (On Behalf Of whom / Delegation)
    $del = [string](Get-Prop $E 'delegation')
    $lin = [string](Get-Prop $E 'lineage_tree')
    $uid = [string](Get-Prop $E 'user_id')
    $obo = if ($del) { $del } elseif ($lin) { $lin } elseif ($uid) { "user:$uid -> agent:$source" } else { "user:$Owner" }

    # 3. WHAT (Action & Target Resource)
    $act = [string](Get-Prop $E 'canonical_action')
    $res = [string](Get-Prop $E 'canonical_resource')
    $cmd = Limit-Text (Get-Operation $E) 65
    $what = if ($act -and $res) { "$act on $res ($cmd)" } elseif ($act) { "$act ($cmd)" } else { $cmd }

    # 4. WHAT EXECUTED / STOPPED (Outcome)
    $denied = Test-Denied $E
    $dur = Get-Prop $E 'duration_ms'
    $exit = Get-Prop $E 'exit_code'
    $status = if ($denied) { 'STOPPED (DENIED)' } else { 'ALLOWED & EXECUTED' }
    $execDesc = if ($denied) {
        $r = Limit-Text (Get-Prop $E 'reason') 80
        "STOPPED before execution. Reason: $r"
    } else {
        $tail = @('EXECUTED')
        if ($null -ne $exit -and "$exit" -ne '') { $tail += "exit $exit" }
        if ($dur) { $tail += "$dur ms" }
        $tail -join ', '
    }

    # 5. PROVE (Non-Repudiation, Receipt & Hash Chain)
    $rcpt = [string](Get-Prop $E 'receipt_id')
    if (-not $rcpt) { $rcpt = [string](Get-Prop $E 'event_id') }
    $hash = [string](Get-Prop $E 'request_hash')
    if (-not $hash) { $hash = [string](Get-Prop $E 'entry_hash') }
    $pol = [string](Get-Prop $E 'policy_version')
    if (-not $pol) { $pol = [string](Get-Prop $E 'policy_hash') }
    $tree = @(@(Get-Prop $E 'process_tree') | Where-Object { $_ })
    $prove = "Receipt: $(Get-ShortId $rcpt)"
    if ($hash) { $prove += " | Hash: $(Get-ShortId $hash)" }
    if ($pol) { $prove += " | Policy: $(Get-ShortId $pol)" }
    if ($tree.Count -gt 0) { $prove += " | Tree: $($tree -join '>')" }

    return [pscustomobject]@{
        Who = $who
        Obo = $obo
        What = $what
        Status = $status
        ExecDesc = $execDesc
        Prove = $prove
        Denied = $denied
        Command = $cmd
        ReceiptId = $rcpt
    }
}

function New-Receipt {
    param($E, [string]$Owner, [string]$Agent, [switch]$Detailed)
    $p = Get-PillarFields -E $E -Owner $Owner -Agent $Agent
    $grant = [string](Get-Prop $E 'grant_id')

    if ($Detailed) {
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add("[$($p.Status)] $($p.Command)")
        $lines.Add("       • 1. WHO (Initiator) : $($p.Who)")
        $lines.Add("       • 2. OBO (Delegation): $($p.Obo)")
        $lines.Add("       • 3. WHAT (Action)   : $($p.What)")
        $lines.Add("       • 4. OUTCOME         : $($p.ExecDesc)")
        $lines.Add("       • 5. PROVE           : $($p.Prove)")
        return ($lines -join "`n")
    }

    $gText = if ($grant) { " [grant: $(Get-ShortId $grant)]" } else { '' }
    if ($p.Denied) {
        return "WHO: $($p.Who) | OBO: $($p.Obo) | WHAT: $($p.Command) -> $($p.ExecDesc) | PROVE: $(Get-ShortId $p.ReceiptId)"
    } else {
        return "WHO: $($p.Who) | OBO: $($p.Obo) | WHAT: $($p.Command)$gText -> $($p.ExecDesc) | PROVE: $(Get-ShortId $p.ReceiptId)"
    }
}

# ----------------------------------------------------------------------------
# Load
# ----------------------------------------------------------------------------
$ledger = Get-LedgerFiles -Explicit $LedgerPath
if ($ledger.Found.Count -eq 0) {
    Out-Line 'No audit ledger found. Searched:' 'Red'
    foreach ($s in $ledger.Searched) { Out-Line "  $s" 'DarkGray' }
    Out-Line 'Pass -LedgerPath, or set BAP_STATE_DIR / BAP_AUDIT_LOG.' 'Yellow'
    exit 2
}
$events = Read-Events -Files $ledger.Found
if ($events.Count -eq 0) { Out-Line 'Ledger is empty.' 'Yellow'; exit 2 }

if (-not $SessionId) {
    # Prefer the newest session that has broker or ZSP evidence; else the newest overall.
    $withZsp = @($events | Where-Object { (Get-Prop $_ 'zsp_concept') -or (Get-Prop $_ 'reporting_layer') -eq 'broker' })
    $pick = if ($withZsp.Count -gt 0) { $withZsp[-1] } else { $events[-1] }
    $SessionId = [string](Get-Prop $pick 'session_id')
}
$session = @($events | Where-Object { [string](Get-Prop $_ 'session_id') -eq $SessionId })
if ($SinceMinutes -gt 0) {
    $cut = [datetime]::UtcNow.AddMinutes(-$SinceMinutes)
    $session = @($session | Where-Object { (ConvertTo-Utc (Get-Prop $_ 'timestamp')) -ge $cut })
}
if ($session.Count -eq 0) {
    Out-Line "No events for session '$SessionId'." 'Yellow'
    exit 2
}

$agentRaw = [string](Get-Prop $session[0] 'source')
$Agent = if ($agentRaw -match 'claude') { 'Claude Code' } elseif ($agentRaw) { $agentRaw } else { 'The agent' }
$ownerEvt = $session | Where-Object { Get-Prop $_ 'user_id' } | Select-Object -First 1
$Owner = if ($ownerEvt) { [string](Get-Prop $ownerEvt 'user_id') } else { 'the signed-in user' }

$work = if ($IncludePlumbing) { $session } else { @($session | Where-Object { -not (Test-Plumbing $_) }) }
$hidden = $session.Count - $work.Count
$rawCount = $work.Count
$work = @(Merge-Logical $work)

# ----------------------------------------------------------------------------
# Build the story model
# ----------------------------------------------------------------------------
$mints = @($work | Where-Object { Test-GrantMint $_ })
$usesByGrant = @{}
foreach ($m in $mints) {
    $gid = [string](Get-Prop $m 'grant_id')
    if ($gid -and -not $usesByGrant.ContainsKey($gid)) {
        $usesByGrant[$gid] = @($work | Where-Object {
            ([string](Get-Prop $_ 'grant_id') -eq $gid) -and -not (Test-GrantMint $_)
        })
    }
}
# Wrap the whole expression: a one-element array assigned from an if-block is unrolled to a bare
# object, and .Count on that is empty in Windows PowerShell.
$shownMints = @(if ($Last -gt 0) { $mints | Select-Object -Last $Last } else { $mints })
$denials = @($work | Where-Object { Test-Denied $_ })
$noGrant = @($denials | Where-Object { (Get-ConceptFor $_) -eq 'ZSP_DENY_NO_GRANT' })
$boundary = @($denials | Where-Object { (Get-ConceptFor $_) -in @('CREDENTIAL_ISOLATION', 'ZSP_HARD_DENY', 'HIGH_RISK_OOB_GATE') })
$freezeEvts = @($work | Where-Object {
    ([string](Get-Prop $_ 'reason') + ' ' + [string](Get-Prop $_ 'full_command')) -match 'freez|frozen|session restricted|workstation restricted'
})
$allowedOps = @($work | Where-Object { -not (Test-Denied $_) -and -not (Test-GrantMint $_) })
$allowedCount = $allowedOps.Count
$withGrant = @($allowedOps | Where-Object { Get-Prop $_ 'grant_id' }).Count
$exempt = $allowedCount - $withGrant
$approvals = @($work | Where-Object { (Get-ConceptFor $_) -eq 'HIGH_RISK_OOB_GATE' -or (Get-ConceptFor $_) -eq 'ZSP_APPROVED_GRANT_REUSED' })
$layers = @($session | ForEach-Object { $l = [string](Get-Prop $_ 'reporting_layer'); if ($l) { $l } else { 'unlabelled' } } |
        Group-Object | Sort-Object Name)

$model = [ordered]@{
    session_id = $SessionId
    agent      = $Agent
    ledgers    = $ledger.Found
    summary    = [ordered]@{
        operations_shown   = $work.Count
        raw_events         = $rawCount
        allowed_with_grant = $withGrant
        allowed_no_grant_needed = $exempt
        plumbing_hidden    = $hidden
        grants_minted      = $mints.Count
        allowed_operations = $allowedCount
        denied_no_grant    = $noGrant.Count
        denied_boundary    = $boundary.Count
        human_approvals    = $approvals.Count
    }
    grants     = @($mints | ForEach-Object {
            $gid = [string](Get-Prop $_ 'grant_id')
            [ordered]@{
                grant_id = $gid; minted_utc = (ConvertTo-Utc (Get-Prop $_ 'timestamp')).ToString('o')
                actions  = @(Get-Prop $_ 'allowed_actions'); concept = (Get-Prop $_ 'zsp_concept')
                uses     = @($usesByGrant[$gid] | ForEach-Object { Get-Prop $_ 'event_id' })
            }
        })
}

if ($Json) { $model | ConvertTo-Json -Depth 6; exit 0 }

# ----------------------------------------------------------------------------
# Header & 5-Pillar Executive Summary
# ----------------------------------------------------------------------------
Out-Rule '='
Out-Line "  GOVERNED SESSION STORY — 5-PILLAR ZERO-TRUST AUDIT" 'Cyan'
Out-Rule '='
$s = $model.summary
$delEvt = $session | Where-Object { Get-Prop $_ 'delegation' } | Select-Object -First 1
$SessionDelegation = if ($delEvt) { [string](Get-Prop $delEvt 'delegation') } else { "user:$Owner -> agent:$($agentRaw)" }
Out-Line ("  1. WHO INITIATED       : {0} (Session: {1})" -f $Agent, (Get-ShortId $SessionId)) 'White'
Out-Line ("  2. ON BEHALF OF (OBO)  : {0}" -f $SessionDelegation) 'White'
Out-Line ("  3. WHAT WAS DONE       : {0} distinct actions ({1} raw events across layers)" -f $s.operations_shown, $s.raw_events) 'White'
Out-Line ("  4. EXECUTED vs STOPPED : {0} Allowed & Executed ({1} via grant, {2} read-exempt), {3} Stopped beyond grant, {4} Stopped at boundary" -f `
        $s.allowed_operations, $s.allowed_with_grant, $s.allowed_no_grant_needed, $s.denied_no_grant, $s.denied_boundary) 'White'
Out-Line ("  5. PROVE & INTEGRITY   : {0} grants minted, {1} ledgers read, tamper-evident hash chain active" -f $s.grants_minted, $ledger.Found.Count) 'White'
if ($hidden -gt 0) { Out-Line "  ($hidden app-plumbing events hidden; use -IncludePlumbing to show them.)" 'DarkGray' }
Out-Line ''

# ----------------------------------------------------------------------------
# Scene 1
# ----------------------------------------------------------------------------
if ($Scene -in @('1', 'All')) {
    Out-Line 'SCENE 1  The agent asks, policy answers' 'Cyan'
    Out-Rule
    if ($mints.Count -eq 0) {
        Out-Line '  No grant-minting events in this session. Run the Scene 1 prompt through the governed launcher first,' 'Yellow'
        Out-Line '  or see "Evidence coverage" below if you believe grants were minted.' 'Yellow'
    }
    if ($mints.Count -gt $shownMints.Count) {
        Out-Line ("  (showing the latest {0} of {1} grants; use -Last 0 for all)" -f $shownMints.Count, $mints.Count) 'DarkGray'
    }
    $n = 0
    $pairs = 0
    $anyBefore = $false
    foreach ($m in $shownMints) {
        $n++
        $gid = [string](Get-Prop $m 'grant_id')
        $mt = ConvertTo-Utc (Get-Prop $m 'timestamp')
        # Step 1: what the agent was refused immediately before asking for authority.
        $before = @($noGrant | Where-Object {
                $t = ConvertTo-Utc (Get-Prop $_ 'timestamp'); $t -le $mt -and ($mt - $t).TotalSeconds -le 180
            }) | Select-Object -Last 1
        Out-Line ("  Grant {0}" -f $n) 'White'
        if ($before) {
            $anyBefore = $true
            Out-Line ("    1. WITHOUT a grant   : {0}" -f (Limit-Text (Get-Operation $before) 70)) 'Red'
            Out-Line ("       result            : DENIED. {0}" -f (Limit-Text (Get-Prop $before 'reason') 80)) 'Red'
        } else {
            Out-Line '    1. WITHOUT a grant   : (none refused: the agent asked for the grant first)' 'DarkGray'
        }
        $acts = @(Get-Prop $m 'allowed_actions'); if ($acts.Count -eq 0) { $acts = @(Get-Prop $m 'requested_actions') }
        Out-Line ("    2. GRANT MINTED      : {0}  [{1}]" -f (Get-ShortId $gid), (Get-Prop $m 'zsp_concept')) 'Green'
        Out-Line ("       may do            : {0}" -f ($acts -join ', ')) 'Green'
        Out-Line ("       where / when      : workspace only, minted {0:HH:mm:ss}Z" -f $mt) 'Green'
        $uses = @($usesByGrant[$gid])
        if ($before -and $uses.Count -gt 0) { $pairs++ }
        if ($uses.Count -eq 0) {
            Out-Line '    3. WITH the grant    : minted but never consumed. Read-only commands need no grant by default' 'Yellow'
            Out-Line '                           (set BAP_ZSP_STRICT_READS=1 to require one), so use a write or test run for this scene.' 'Yellow'
        } else {
            Out-Line '    3. WITH the grant    : the same kind of command now runs' 'Green'
            foreach ($u in $uses) {
                Out-Line ('       RECEIPT  ' + (New-Receipt -E $u -Owner $Owner -Agent $Agent -Detailed:$Detail)) 'White'
                if ($Detail) {
                    Out-Line ("         event {0}  action {1}  resource {2}" -f (Get-Prop $u 'event_id'), (Get-Prop $u 'canonical_action'), (Get-Prop $u 'canonical_resource')) 'DarkGray'
                    Out-Line ("         process tree {0}  caller {1}" -f ((@(Get-Prop $u 'process_tree')) -join '>'), (Limit-Text (Get-Prop $u 'caller_binary') 60)) 'DarkGray'
                    Out-Line ("         entry hash {0}  prev {1}" -f (Get-ShortId (Get-Prop $u 'entry_hash')), (Get-ShortId (Get-Prop $u 'previous_hash'))) 'DarkGray'
                }
            }
        }
        Out-Line ''
    }
    if ($denials.Count -gt 0) {
        Out-Line '  Refused attempts this session (every one is recorded, whether or not it preceded a grant)' 'White'
        # Collapse repeats of the same refusal (the hook and broker both record each one).
        $refusalGroups = @($denials | Group-Object { (Get-ConceptFor $_) + '|' + (Limit-Text (Get-Prop $_ 'reason') 70) })
        foreach ($grp in @($refusalGroups | Select-Object -Last 6)) {
            $d = $grp.Group[$grp.Group.Count - 1]
            $times = if ($grp.Count -gt 1) { "x$($grp.Count)" } else { 'x1' }
            Out-Line ("    {0:HH:mm:ss}Z  {1,-3} [{2}]  {3}" -f (ConvertTo-Utc (Get-Prop $d 'timestamp')), $times, (Get-ConceptFor $d), (Limit-Text (Get-Operation $d) 55)) 'Red'
            Out-Line ("                  {0}" -f (Limit-Text (Get-Prop $d 'reason') 100)) 'DarkGray'
        }
        Out-Line '  Run with -Scene 2 for the full receipts.' 'DarkGray'
        Out-Line ''
    }
    $consumed = @($shownMints | Where-Object { @($usesByGrant[[string](Get-Prop $_ 'grant_id')]).Count -gt 0 }).Count
    if ($pairs -gt 0) {
        Out-Line '  Say: "Same command. Denied with no grant, allowed with one, and the receipt names the grant."' 'DarkGray'
    } elseif ($anyBefore) {
        Out-Line '  A refusal preceded a grant above, but no execution is linked to that grant yet. Run one governed write after the grant, then re-run this view.' 'Yellow'
    } elseif ($consumed -gt 0) {
        Out-Line '  No denied attempt was recorded before these grants, so lead with the grant card and the receipt that names it.' 'DarkGray'
    }
    Out-Line ''
}

# ----------------------------------------------------------------------------
# Scene 2
# ----------------------------------------------------------------------------
if ($Scene -in @('2', 'All')) {
    Out-Line 'SCENE 2  The boundary holds' 'Cyan'
    Out-Rule
    if ($denials.Count -eq 0) {
        Out-Line '  No denied operations in this session. Run the Scene 2 prompt to produce one.' 'Yellow'
    }
    foreach ($d in $denials) {
        $concept = Get-ConceptFor $d
        $label = switch ($concept) {
            'ZSP_DENY_NO_GRANT' { 'Beyond its grant' }
            'CREDENTIAL_ISOLATION' { 'Credential boundary' }
            'ZSP_HARD_DENY' { 'Never grantable' }
            'HIGH_RISK_OOB_GATE' { 'Needs a human' }
            default { 'Denied' }
        }
        Out-Line ("  [{0}] {1:HH:mm:ss}Z" -f $label, (ConvertTo-Utc (Get-Prop $d 'timestamp'))) 'Red'
        Out-Line ('    RECEIPT  ' + (New-Receipt -E $d -Owner $Owner -Agent $Agent -Detailed:$Detail)) 'White'
        if ($Detail) {
            Out-Line ("      event {0}  concept {1}  action {2}" -f (Get-Prop $d 'event_id'), $concept, (Get-Prop $d 'canonical_action')) 'DarkGray'
        }
    }
    $lastAllowed = $null
    foreach ($m in $mints) {
        $gid = [string](Get-Prop $m 'grant_id')
        if ($usesByGrant[$gid].Count -gt 0) { $lastAllowed = $usesByGrant[$gid][-1] }
    }
    if ($lastAllowed -and $denials.Count -gt 0) {
        Out-Line ''
        Out-Line '  Side by side (The 5 Core Pillars)' 'White'
        Out-Line ('    ALLOWED  ' + (New-Receipt -E $lastAllowed -Owner $Owner -Agent $Agent)) 'Green'
        Out-Line ('    DENIED   ' + (New-Receipt -E $denials[-1] -Owner $Owner -Agent $Agent)) 'Red'
        Out-Line '  5-Pillar check: 1. Who initiated? 2. OBO of whom? 3. What was done? 4. What executed vs stopped? 5. Prove it.' 'DarkGray'
    }
    Out-Line ''
}

# ----------------------------------------------------------------------------
# Scene 3
# ----------------------------------------------------------------------------
if ($Scene -in @('3', 'All')) {
    Out-Line 'SCENE 3  An administrator steps in' 'Cyan'
    Out-Rule
    if ($freezeEvts.Count -eq 0) {
        Out-Line '  No freeze or restriction events in the local ledger.' 'Yellow'
        Out-Line '  Freeze is an administrator action recorded by the control plane; show it on the dashboard row,' 'DarkGray'
        Out-Line '  then run any governed command here and re-run this view to show the resulting block.' 'DarkGray'
    }
    foreach ($f in $freezeEvts) {
        Out-Line ('  RECEIPT  ' + (New-Receipt -E $f -Owner $Owner -Agent $Agent -Detailed:$Detail)) 'White'
    }
    Out-Line ''
}

# ----------------------------------------------------------------------------
# Evidence coverage: tells the presenter whether the story above is complete.
# ----------------------------------------------------------------------------
function Get-Stats {
    param([double[]]$Values)
    $v = @($Values | Sort-Object)
    if ($v.Count -eq 0) { return $null }
    $i50 = [Math]::Max(0, [int][Math]::Ceiling(0.50 * $v.Count) - 1)
    $i95 = [Math]::Max(0, [int][Math]::Ceiling(0.95 * $v.Count) - 1)
    return [pscustomobject]@{ N = $v.Count; P50 = $v[$i50]; P95 = $v[$i95]; Max = $v[$v.Count - 1] }
}
function Format-Stats {
    param($S)
    if ($null -eq $S) { return 'no samples' }
    return ('n={0}   p50 {1:N0} ms   p95 {2:N0} ms   max {3:N0} ms' -f $S.N, $S.P50, $S.P95, $S.Max)
}

Out-Line 'LATENCY' 'Cyan'
Out-Rule
$brokerRaw = @($session | Where-Object {
        (Get-Prop $_ 'reporting_layer') -eq 'broker' -and
        -not (([string](Get-Prop $_ 'canonical_action')) -like 'zsp*') -and
        -not (([string](Get-Prop $_ 'full_command')) -match '^bapedge\s+zsp')
    })
$execd = @($brokerRaw | Where-Object { -not (Test-Denied $_) -and $null -ne (Get-Prop $_ 'duration_ms') })
$deniedB = @($brokerRaw | Where-Object { (Test-Denied $_) -and $null -ne (Get-Prop $_ 'duration_ms') })
$stTotal = Get-Stats @($execd | ForEach-Object { [double](Get-Prop $_ 'duration_ms') })
$stPolicy = Get-Stats @($brokerRaw | Where-Object { Get-Prop $_ 'policy_eval_ms' } | ForEach-Object { [double](Get-Prop $_ 'policy_eval_ms') })
$stPre = Get-Stats @($brokerRaw | Where-Object { Get-Prop $_ 'pre_exec_ms' } | ForEach-Object { [double](Get-Prop $_ 'pre_exec_ms') })
$stDenied = Get-Stats @($deniedB | ForEach-Object { [double](Get-Prop $_ 'duration_ms') })
$hookAll = @($session | Where-Object { (Get-Prop $_ 'reporting_layer') -eq 'hook' }).Count
$hookTimed = @($session | Where-Object { (Get-Prop $_ 'reporting_layer') -eq 'hook' -and (Get-Prop $_ 'duration_ms') }).Count
Out-Line ("  Whole brokered command (decision + sandbox + run) : {0}" -f (Format-Stats $stTotal)) 'White'
if ($stPolicy) {
    Out-Line ("  Policy decision only                              : {0}" -f (Format-Stats $stPolicy)) 'White'
} else {
    Out-Line '  Policy decision only                              : not recorded in this ledger (needs a bapedge build with policy_eval_ms)' 'Yellow'
}
if ($stPre) { Out-Line ("  Time until the command is ready to run            : {0}" -f (Format-Stats $stPre)) 'White' }
if ($stDenied) { Out-Line ("  Denied commands                                   : {0}" -f (Format-Stats $stDenied)) 'White' }
Out-Line ("  Hook-layer events with a duration                 : {0} of {1} (hook decisions are not timed)" -f $hookTimed, $hookAll) 'DarkGray'
if ($stPolicy) {
    $verdict = if ($stPolicy.P95 -lt 100) { 'under' } else { 'ABOVE' }
    Out-Line ("  100 ms target (BAP-1081)  : policy decision p95 is {0:N1} ms, {1} the target." -f $stPolicy.P95, $verdict) 'White'
} elseif ($stTotal) {
    Out-Line ("  100 ms target (BAP-1081)  : UNKNOWN for the policy decision. Whole-command p95 is {0:N0} ms, which includes sandbox setup and the command itself." -f $stTotal.P95) 'Yellow'
} else {
    Out-Line '  100 ms target (BAP-1081)  : UNKNOWN. No timed broker events in this session.' 'Yellow'
}
Out-Line '  (events, not distinct actions: the same action can be recorded by more than one component)' 'DarkGray'
Out-Line ''

Out-Line 'EVIDENCE COVERAGE' 'Cyan'
Out-Rule
Out-Line ("  Ledgers read : {0}" -f ($ledger.Found.Count)) 'White'
foreach ($f in $ledger.Found) { Out-Line "    $f" 'DarkGray' }
Out-Line ("  Layers       : {0}" -f (($layers | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join '  ')) 'White'
$byLedger = @($session | Group-Object { [string](Get-Prop $_ '_ledger') } | Sort-Object Count -Descending)
Out-Line '  Events for this session, per ledger:' 'White'
foreach ($g in $byLedger) { Out-Line ("    {0,5}  {1}" -f $g.Count, $g.Name) 'DarkGray' }
$warn = New-Object System.Collections.Generic.List[string]
$primary = @($byLedger | Where-Object { $_.Name -notmatch '\.recovery-' })
if ($primary.Count -gt 1) {
    $dups = @($session | Where-Object { $_._copies -gt 1 -or $_._ledgers -gt 1 }).Count
    $warn.Add("Session evidence is split across $($primary.Count) separate ledgers (separate hash chains). One chain cannot be verified end to end, and the same action can be recorded in more than one place. Point every component (hook, interceptor, broker) at one BAP_STATE_DIR.")
}
if (-not ($layers | Where-Object { $_.Name -eq 'broker' })) {
    $warn.Add('No broker-layer events: executed commands and grant minting are missing, so receipts cannot link to grants. Check that the broker state directory (<home>\bin\.bapstate or BAP_STATE_DIR) is the one being read.')
}
if ($mints.Count -gt 0 -and (@($usesByGrant.Values | ForEach-Object { $_.Count }) | Measure-Object -Sum).Sum -eq 0) {
    $warn.Add('Grants were minted but no execution event carries a grant_id. Broker exec events should record the consumed grant.')
}
$timedCandidates = @($brokerRaw)
$noDur = @($timedCandidates | Where-Object { $null -eq (Get-Prop $_ 'duration_ms') }).Count
if ($noDur -gt 0) { $warn.Add("$noDur broker event(s) have no duration, so latency is unknown, not zero.") }
$subMs = @($timedCandidates | Where-Object { $null -ne (Get-Prop $_ 'duration_ms') -and [double](Get-Prop $_ 'duration_ms') -eq 0 }).Count
if ($subMs -gt 0) { $warn.Add("$subMs broker event(s) show duration 0. That is a whole-millisecond truncation (finished in under 1 ms), not a missing measurement.") }
if (-not $stPolicy -and $execd.Count -gt 0) { $warn.Add('No policy-decision timing recorded. Rebuild and deploy bapedge with policy_eval_ms and pre_exec_ms, then re-run the session.') }
if ($warn.Count -eq 0) {
    Out-Line '  Capture looks complete for this session.' 'Green'
} else {
    foreach ($w in $warn) { Out-Line "  [!] $w" 'Yellow' }
}
Out-Line ''
