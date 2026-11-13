<#
.SYNOPSIS
    BAP Pilot Runner - non-interactive showcase and verification of every BAP feature.
.DESCRIPTION
    Runs, unattended and in order:
      1. Go unit tests (bap-edge, bap-controlplane, bap-gateway, cchook)
      2. Local Control Plane (:8080) and Gateway PEP (:9090) startup + health
      3. Feature checks through bapedge: policy explain, trust/untrust cycle,
         sandboxed exec, token containment, sweep, audit hash chain
      4. Native plugin probes and 5-layer matrix (bapedge plugin ...)
      5. Python integration suite (perf/load and adversarial suites excluded)
      6. Optional negative / red-team suites (-IncludeNegative)
      7. Teardown of everything it started
    Writes a pass/fail table to the console plus .bap\pilot\report-<timestamp>.json
    and .md. Exit code is 0 only if every executed check passed.

    Enforcement checks run with BAP_ENVIRONMENT=production so a live developer
    override can never mask a denial. The override is reported, never required.
.PARAMETER SkipGo          Skip Go unit tests.
.PARAMETER SkipPython      Skip the Python integration suite.
.PARAMETER SkipPlugins     Skip `bapedge plugin` probes.
.PARAMETER SkipServers     Do not start local Control Plane / Gateway (use configured ones).
.PARAMETER IncludeNegative Also run run_negative_testcases.bat (deny-path / red-team checks).
.PARAMETER Quick           Features + plugins only (no Go, no Python).
.EXAMPLE
    .\scripts\run_pilot.ps1
    .\scripts\run_pilot.ps1 -Quick
    .\scripts\run_pilot.ps1 -IncludeNegative
#>
[CmdletBinding()]
param(
    [switch]$SkipGo,
    [switch]$SkipPython,
    [switch]$SkipPlugins,
    [switch]$SkipServers,
    [switch]$IncludeNegative,
    [switch]$Quick
)

$ErrorActionPreference = 'Continue'
$repoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Set-Location $repoRoot
if ($Quick) { $SkipGo = $true; $SkipPython = $true }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $repoRoot '.bap\pilot'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$logDir = Join-Path $outDir "logs-$stamp"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$results = New-Object System.Collections.ArrayList
$started = New-Object System.Collections.ArrayList

function Add-Result {
    param([string]$Stage, [string]$Name, [string]$Status, [string]$Detail = '')
    [void]$results.Add([pscustomobject]@{ Stage = $Stage; Check = $Name; Status = $Status; Detail = $Detail })
    $color = 'Green'
    if ($Status -eq 'FAIL') { $color = 'Red' } elseif ($Status -eq 'SKIP') { $color = 'DarkYellow' }
    Write-Host ("  [{0}] {1} :: {2} {3}" -f $Status, $Stage, $Name, $Detail) -ForegroundColor $color
}

function Resolve-Exe {
    param([string[]]$Candidates)
    foreach ($c in $Candidates) {
        $p = Join-Path $repoRoot $c
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Invoke-Capture {
    # Runs an exe, returns @{ Code; Text } without throwing on non-zero exit.
    param([string]$Exe, [string[]]$ArgList, [int]$TimeoutSec = 120, [string]$WorkDir = $repoRoot, [string]$StdinFile = '')
    $so = Join-Path $logDir ([guid]::NewGuid().ToString('N') + '.out')
    $se = Join-Path $logDir ([guid]::NewGuid().ToString('N') + '.err')
    $sp = @{
        FilePath = $Exe; WorkingDirectory = $WorkDir; NoNewWindow = $true; PassThru = $true
        RedirectStandardOutput = $so; RedirectStandardError = $se
    }
    if ($ArgList -and $ArgList.Count -gt 0) {
        # Quote args containing spaces or shell metacharacters so Start-Process passes them intact.
        $sp.ArgumentList = @($ArgList | ForEach-Object { if ($_ -match '[\s&|<>^]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } })
    }
    if ($StdinFile) { $sp.RedirectStandardInput = $StdinFile }
    $p = Start-Process @sp
    $null = $p.Handle   # cache the handle, otherwise ExitCode is $null after WaitForExit
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch {}
        return @{ Code = -999; Text = 'TIMEOUT' }
    }
    $p.WaitForExit()
    $code = $p.ExitCode
    if ($null -eq $code) { $code = 0 }
    $text = ''
    if (Test-Path $so) { $text += (Get-Content $so -Raw -Encoding UTF8 -ErrorAction SilentlyContinue) }
    if (Test-Path $se) { $text += (Get-Content $se -Raw -Encoding UTF8 -ErrorAction SilentlyContinue) }
    return @{ Code = $code; Text = [string]$text }
}

function Test-Check {
    param([string]$Stage, [string]$Name, [hashtable]$Run, [string]$Expect = '', [int]$ExpectCode = 0, [string]$Reject = '')
    $ok = ($Run.Code -eq $ExpectCode)
    if ($ok -and $Expect -and ($Run.Text -notmatch $Expect)) { $ok = $false }
    if ($ok -and $Reject -and ($Run.Text -match $Reject)) { $ok = $false }
    if ($ok) { Add-Result $Stage $Name 'PASS' } else {
        $snippet = ($Run.Text -replace '\s+', ' ')
        if ($snippet.Length -gt 160) { $snippet = $snippet.Substring(0, 160) }
        Add-Result $Stage $Name 'FAIL' ("exit=$($Run.Code) $snippet")
    }
}

function Wait-Http {
    param([string]$Url, [int]$Seconds = 20)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
            if ($r.StatusCode -lt 500) { return $true }
        } catch {
            if ($_.Exception.Response) { return $true }
        }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

$cpUrl = 'http://localhost:8080'
$gwUrl = 'http://localhost:9090'

function Start-PilotServers {
    param([string]$Label)
    if (-not $cpExe -or -not $gwExe) {
        Add-Result 'servers' "$Label server binaries found" 'FAIL' 'bapcontrolplane/bapgateway missing in dist\windows-amd64'
        return $false
    }
    Get-Process -Name bapcontrolplane, bapgateway -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    $env:BAP_ADMIN_TOKEN = 'admin123'
    $cp = Start-Process -FilePath $cpExe -ArgumentList @('-port', '8080', '-admin-token', 'admin123', '-ttl', '30', '-trust-domain', 'bap.internal') `
        -WorkingDirectory $repoRoot -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $logDir "controlplane-$Label.out") -RedirectStandardError (Join-Path $logDir "controlplane-$Label.err")
    [void]$started.Add($cp)
    $cpOk = Wait-Http "$cpUrl/api/v1/health" 25
    if ($cpOk) { Add-Result 'servers' "control plane healthy on :8080 ($Label)" 'PASS' } else { Add-Result 'servers' "control plane healthy on :8080 ($Label)" 'FAIL' 'see logs' }
    $gw = Start-Process -FilePath $gwExe -ArgumentList @('-port', '9090', '-controlplane', $cpUrl) `
        -WorkingDirectory $repoRoot -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $logDir "gateway-$Label.out") -RedirectStandardError (Join-Path $logDir "gateway-$Label.err")
    [void]$started.Add($gw)
    $gwOk = Wait-Http "$gwUrl/health" 20
    if ($gwOk) { Add-Result 'servers' "gateway PEP healthy on :9090 ($Label)" 'PASS' } else { Add-Result 'servers' "gateway PEP healthy on :9090 ($Label)" 'FAIL' 'see logs' }
    $env:BAP_SERVER_URL = $cpUrl
    $env:BAP_CONTROL_PLANE_URL = $cpUrl
    $env:BAP_CONTROLPLANE_URL = $cpUrl
    return ($cpOk -and $gwOk)
}

function Stop-PilotServers {
    foreach ($p in $started) { try { if (-not $p.HasExited) { $p.Kill() } } catch {} }
    Get-Process -Name bapcontrolplane, bapgateway -ErrorAction SilentlyContinue | Where-Object { $started.Id -contains $_.Id } | Stop-Process -Force -ErrorAction SilentlyContinue
    $started.Clear()
}

Write-Host '===============================================================================' -ForegroundColor Cyan
Write-Host '  BAP PILOT RUNNER - unattended feature showcase and verification' -ForegroundColor Cyan
Write-Host "  Workspace: $repoRoot" -ForegroundColor Cyan
Write-Host '===============================================================================' -ForegroundColor Cyan

$bapedge = Resolve-Exe @('bapedge.exe', 'dist\windows-amd64\bapedge.exe')
$interceptor = Resolve-Exe @('dist\windows-amd64\interceptor.exe', 'interceptor.exe', 'cchook\interceptor.exe')
$cpExe = Resolve-Exe @('dist\windows-amd64\controlplane\bapcontrolplane.exe', 'bapcontrolplane.exe')
$gwExe = Resolve-Exe @('dist\windows-amd64\gateway\bapgateway.exe', 'bapgateway.exe')

$savedEnv = @{}
foreach ($k in 'BAP_ENVIRONMENT', 'BAP_DEV_OVERRIDE', 'BAP_DEV_MODE', 'BAP_ADMIN_TOKEN', 'BAP_SERVER_URL', 'BAP_CONTROL_PLANE_URL', 'BAP_CONTROLPLANE_URL', 'BAP_TEST_MODE', 'BAP_NON_INTERACTIVE') {
    $savedEnv[$k] = [Environment]::GetEnvironmentVariable($k, 'Process')
}

try {
    # -------------------------------------------------------------------------
    # Stage 0: environment
    # -------------------------------------------------------------------------
    Write-Host "`n[0] Environment" -ForegroundColor Yellow
    if ($bapedge) { Add-Result 'env' 'bapedge binary found' 'PASS' $bapedge } else { Add-Result 'env' 'bapedge binary found' 'FAIL' 'build with build_binaries.bat' }
    if ($interceptor) { Add-Result 'env' 'interceptor binary found' 'PASS' $interceptor } else { Add-Result 'env' 'interceptor binary found' 'FAIL' }
    if ($env:BAP_DEV_OVERRIDE -or (Test-Path (Join-Path $repoRoot '.bap\dev-override.json'))) {
        Write-Host '  note: developer override detected; enforcement checks below force production mode.' -ForegroundColor DarkYellow
    }

    # -------------------------------------------------------------------------
    # Stage 1: Go unit tests
    # -------------------------------------------------------------------------
    Write-Host "`n[1] Go unit tests" -ForegroundColor Yellow
    if ($SkipGo) { Add-Result 'go' 'unit tests' 'SKIP' 'requested' } else {
        foreach ($mod in 'bap-edge', 'bap-controlplane', 'bap-gateway', 'cchook') {
            $r = Invoke-Capture 'go' @('test', './...') 900 (Join-Path $repoRoot $mod)
            Test-Check 'go' "$mod go test ./..." $r
        }
    }

    # -------------------------------------------------------------------------
    # Stage 2: local servers
    # -------------------------------------------------------------------------
    Write-Host "`n[2] Control Plane and Gateway PEP" -ForegroundColor Yellow
    if ($SkipServers -or ($Quick -and $SkipPython)) {
        Add-Result 'servers' 'local control plane + gateway' 'SKIP' 'not required for this run'
    } elseif (-not $cpExe -or -not $gwExe) {
        Add-Result 'servers' 'server binaries found' 'FAIL' 'bapcontrolplane/bapgateway missing in dist\windows-amd64'
    } else {
        # Smoke check only: start, verify health, stop. The server-dependent pytest files get a
        # fresh pair in stage 5b, because other tests run `taskkill /IM bapcontrolplane.exe`.
        Start-PilotServers -Label 'smoke'
        Stop-PilotServers
    }

    # -------------------------------------------------------------------------
    # Stage 3: feature checks through bapedge (enforcement forced on)
    # -------------------------------------------------------------------------
    Write-Host "`n[3] Core feature checks (bapedge)" -ForegroundColor Yellow
    if (-not $bapedge) { Add-Result 'features' 'all' 'SKIP' 'bapedge missing' } else {
        $env:BAP_ENVIRONMENT = 'production'
        $env:BAP_DEV_OVERRIDE = ''
        $env:BAP_DEV_MODE = ''
        $env:BAP_NON_INTERACTIVE = '1'

        Test-Check 'features' 'version / build metadata' (Invoke-Capture $bapedge @('version')) '\d+\.\d+\.\d+'
        Test-Check 'features' 'workstation status' (Invoke-Capture $bapedge @('status'))
        Test-Check 'features' 'policy explain: safe command allowed' (Invoke-Capture $bapedge @('why', 'git status')) 'ALLOWED'
        Test-Check 'features' 'policy explain: sibling read allowed' (Invoke-Capture $bapedge @('why', 'dir ..\')) 'ALLOWED'

        # HITL / trust cycle on a throwaway sibling directory
        $sibling = Join-Path (Split-Path $repoRoot -Parent) 'bap-pilot-sibling'
        New-Item -ItemType Directory -Force -Path $sibling | Out-Null
        $copyCmd = "copy README.md ..\bap-pilot-sibling\README.md"
        $r = Invoke-Capture $bapedge @('why', $copyCmd)
        if ($r.Text -match 'DENIED|STEP-UP|HITL|trust') { Add-Result 'features' 'cross-folder write needs trust (step-up)' 'PASS' } else { Add-Result 'features' 'cross-folder write needs trust (step-up)' 'FAIL' (($r.Text -replace '\s+', ' ').Substring(0, [Math]::Min(120, $r.Text.Length))) }
        Test-Check 'features' 'trust sibling (project scope)' (Invoke-Capture $bapedge @('trust', '..\bap-pilot-sibling', '--project'))
        Test-Check 'features' 'permissions lists grant' (Invoke-Capture $bapedge @('permissions')) 'bap-pilot-sibling'
        Test-Check 'features' 'cross-folder write allowed after trust' (Invoke-Capture $bapedge @('why', $copyCmd)) 'ALLOWED'
        Test-Check 'features' 'sandboxed exec of trusted copy' (Invoke-Capture $bapedge @('exec', $copyCmd))
        Test-Check 'features' 'untrust revokes grant' (Invoke-Capture $bapedge @('untrust', '..\bap-pilot-sibling'))
        $r = Invoke-Capture $bapedge @('why', $copyCmd)
        if ($r.Text -match 'ALLOWED' -and $r.Text -match 'pre-authorized') { Add-Result 'features' 'write blocked again after untrust' 'FAIL' 'trust still active' } else { Add-Result 'features' 'write blocked again after untrust' 'PASS' }
        Remove-Item -Recurse -Force $sibling -ErrorAction SilentlyContinue

        # Windows restricted-token containment
        Test-Check 'features' 'sandboxed git status' (Invoke-Capture $bapedge @('exec', 'git status'))
        $r = Invoke-Capture $bapedge @('exec', 'whoami /priv')
        if ($r.Code -eq 0 -and $r.Text -notmatch 'SeDebugPrivilege\s+.*Enabled' -and $r.Text -notmatch 'SeTcbPrivilege') { Add-Result 'features' 'high privileges stripped in child' 'PASS' } else { Add-Result 'features' 'high privileges stripped in child' 'FAIL' "exit=$($r.Code)" }

        Test-Check 'features' 'crash sweep' (Invoke-Capture $bapedge @('sweep'))
        Test-Check 'features' 'audit hash-chain verification' (Invoke-Capture $bapedge @('verify-log'))
    }

    # Hook interceptor allow-path (deny-paths live in -IncludeNegative)
    if ($interceptor) {
        $payload = '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"}}'
        $pf = Join-Path $logDir 'hook-payload.json'
        Set-Content -Path $pf -Value $payload -Encoding ASCII
        # Zero standing privileges: with ZSP enforced and no task grant, even a benign call must be refused.
        $env:BAP_ZSP = 'enforce'
        $env:BAP_ZSP_ENABLED = '1'
        $env:BAP_SESSION_ID = "sess-pilot-$stamp"
        $r = Invoke-Capture $interceptor @() 60 $repoRoot $pf
        if ($r.Text -match 'ZeroStandingPrivilege|deny') { Add-Result 'features' 'ZSP: no grant -> hook refuses benign call' 'PASS' } else { Add-Result 'features' 'ZSP: no grant -> hook refuses benign call' 'FAIL' (($r.Text -replace '\s+', ' ').Substring(0, [Math]::Min(120, $r.Text.Length))) }
        # With ZSP disabled, the standard Cedar path must allow a benign call.
        $env:BAP_ZSP = 'off'
        $r = Invoke-Capture $interceptor @() 60 $repoRoot $pf
        if ($r.Text -match '"permissionDecision"\s*:\s*"allow"') { Add-Result 'features' 'Claude hook: benign tool call allowed (Cedar)' 'PASS' } else { Add-Result 'features' 'Claude hook: benign tool call allowed (Cedar)' 'FAIL' (($r.Text -replace '\s+', ' ').Substring(0, [Math]::Min(120, $r.Text.Length))) }
        foreach ($k in 'BAP_ZSP', 'BAP_ZSP_ENABLED', 'BAP_SESSION_ID') { [Environment]::SetEnvironmentVariable($k, $null, 'Process') }
    }

    # -------------------------------------------------------------------------
    # Stage 4: native plugins and 5-layer matrix
    # -------------------------------------------------------------------------
    Write-Host "`n[4] Native plugins and 5-layer defense matrix" -ForegroundColor Yellow
    if ($SkipPlugins -or -not $bapedge) { Add-Result 'plugins' 'plugin probes' 'SKIP' 'requested or bapedge missing' } else {
        Test-Check 'plugins' 'plugin status' (Invoke-Capture $bapedge @('plugin', 'status'))
        Test-Check 'plugins' 'plugin verify all (5 harnesses)' (Invoke-Capture $bapedge @('plugin', 'verify', 'all') 240) '' 0 'Fail\)|\[x\]|FAILED'
        Test-Check 'plugins' 'plugin layers matrix' (Invoke-Capture $bapedge @('plugin', 'layers'))
        Test-Check 'plugins' 'doctor' (Invoke-Capture $bapedge @('doctor'))
    }

    # -------------------------------------------------------------------------
    # Stage 5: Python integration suite
    # -------------------------------------------------------------------------
    Write-Host "`n[5] Python integration suite" -ForegroundColor Yellow
    if ($SkipPython) { Add-Result 'python' 'pytest suite' 'SKIP' 'requested' } else {
        $env:BAP_TEST_MODE = '1'
        $pyArgs = @('-m', 'pytest', 'tests', '-q', '-p', 'no:cacheprovider',
            '--ignore=tests/perf_test_50k.py', '--ignore=tests/perf_test_suite.py',
            '--ignore=tests/load_test_500_stateful.py', '--ignore=tests/load_test_1000_stateful.py',
            '--ignore=tests/test_bap714_containment_redteam.py',
            '--ignore=tests/test_python_agent.py', '--ignore=tests/test_gateway_pep.py')
        $r = Invoke-Capture 'python' $pyArgs 1500
        Set-Content -Path (Join-Path $logDir 'pytest.txt') -Value $r.Text -Encoding UTF8
        $summary = ($r.Text -split "`n" | Where-Object { $_ -match '\d+ passed|\d+ failed' } | Select-Object -Last 1)
        if ($r.Code -eq 0) { Add-Result 'python' 'pytest suite (self-contained tests)' 'PASS' ([string]$summary).Trim() } else { Add-Result 'python' 'pytest suite (self-contained tests)' 'FAIL' (([string]$summary).Trim() + " (see $logDir\pytest.txt)") }

        # 5b: server-dependent files get a fresh Control Plane + Gateway, started after the suite above
        # (some tests there kill bapcontrolplane.exe globally).
        if ($SkipServers) {
            Add-Result 'python' 'SDK + gateway PEP tests' 'SKIP' '-SkipServers'
        } else {
            $up = Start-PilotServers -Label 'pytest'
            if (-not $up) {
                Add-Result 'python' 'SDK + gateway PEP tests' 'FAIL' 'servers did not come up'
            } else {
                $r2 = Invoke-Capture 'python' @('-m', 'pytest', 'tests/test_python_agent.py', 'tests/test_gateway_pep.py', '-q', '-p', 'no:cacheprovider') 600
                Set-Content -Path (Join-Path $logDir 'pytest-servers.txt') -Value $r2.Text -Encoding UTF8
                $summary2 = ($r2.Text -split "`n" | Where-Object { $_ -match '\d+ passed|\d+ failed|\d+ error' } | Select-Object -Last 1)
                if ($r2.Code -eq 0) { Add-Result 'python' 'SDK + gateway PEP tests' 'PASS' ([string]$summary2).Trim() } else { Add-Result 'python' 'SDK + gateway PEP tests' 'FAIL' (([string]$summary2).Trim() + " (see $logDir\pytest-servers.txt)") }
            }
            Stop-PilotServers
        }
    }

    # -------------------------------------------------------------------------
    # Stage 6: negative / red-team (opt-in)
    # -------------------------------------------------------------------------
    Write-Host "`n[6] Negative / red-team suites" -ForegroundColor Yellow
    if (-not $IncludeNegative) {
        Add-Result 'negative' 'deny-path and red-team checks' 'SKIP' 'opt-in: -IncludeNegative (kept apart for corporate EDR hygiene)'
    } else {
        $neg = Join-Path $repoRoot 'run_negative_testcases.bat'
        if (Test-Path $neg) {
            $r = Invoke-Capture 'cmd.exe' @('/c', $neg) 900
            Test-Check 'negative' 'run_negative_testcases.bat' $r
        } else { Add-Result 'negative' 'run_negative_testcases.bat' 'FAIL' 'missing' }
        $r = Invoke-Capture 'python' @('-m', 'pytest', 'tests/test_bap714_containment_redteam.py', '-q', '-p', 'no:cacheprovider') 900
        Test-Check 'negative' 'red-team containment suite' $r
    }
}
finally {
    # -------------------------------------------------------------------------
    # Stage 7: teardown
    # -------------------------------------------------------------------------
    Write-Host "`n[7] Teardown" -ForegroundColor Yellow
    Stop-PilotServers
    foreach ($k in $savedEnv.Keys) { [Environment]::SetEnvironmentVariable($k, $savedEnv[$k], 'Process') }
    Write-Host '  servers stopped, environment restored.'
}

# -----------------------------------------------------------------------------
# Report
# -----------------------------------------------------------------------------
$pass = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
$fail = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$skip = @($results | Where-Object { $_.Status -eq 'SKIP' }).Count

Write-Host ''
Write-Host '===============================================================================' -ForegroundColor Cyan
Write-Host '  PILOT RESULTS' -ForegroundColor Cyan
Write-Host '===============================================================================' -ForegroundColor Cyan
$results | Format-Table Stage, Check, Status -AutoSize | Out-String | Write-Host
Write-Host ("  PASS={0}  FAIL={1}  SKIP={2}" -f $pass, $fail, $skip) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })

$jsonPath = Join-Path $outDir "report-$stamp.json"
$mdPath = Join-Path $outDir "report-$stamp.md"
[pscustomobject]@{ timestamp = $stamp; pass = $pass; fail = $fail; skip = $skip; results = $results } | ConvertTo-Json -Depth 4 | Set-Content -Path $jsonPath -Encoding UTF8
$md = @("# BAP Pilot Report $stamp", '', "PASS=$pass FAIL=$fail SKIP=$skip", '', '| Stage | Check | Status | Detail |', '| --- | --- | --- | --- |')
foreach ($r in $results) { $md += ('| {0} | {1} | {2} | {3} |' -f $r.Stage, $r.Check, $r.Status, (($r.Detail -replace '\|', '/') -replace '\s+', ' ')) }
Set-Content -Path $mdPath -Value $md -Encoding UTF8
Write-Host "  Report: $mdPath"
Write-Host "  Logs:   $logDir"

if ($fail -gt 0) { exit 1 }
exit 0
