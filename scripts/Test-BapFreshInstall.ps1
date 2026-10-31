# Windows PowerShell 5.1+; run after installation and interactive login.
# Does not install software, approve hooks, read credentials, or change policy.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BapEdgePath,
    [string]$ExpectedServer = 'https://bap-controlplane.onrender.com',
    [string]$BuildCommit = '',
    [string]$OutputDirectory = '',
    [ValidateRange(5, 120)][int]$ReportingTimeoutSeconds = 45,
    [switch]$SnapshotOnly
)

$ErrorActionPreference = 'Stop'
$runID = 'acceptance-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$report = [ordered]@{
    run_id = $runID; started_at = [DateTime]::UtcNow.ToString('o')
    expected_server = $ExpectedServer.TrimEnd('/'); operator_build_commit = $BuildCommit
    scope = 'Installed-client smoke checks; full acceptance requires the manual runbook'
    result = 'RUNNING'; checks = @(); snapshots = @{}
    manual_checks_required = @('Unapproved-hook agent discovery', 'Native prompt and file-hook evidence',
        'MCP and shim evidence', 'Latest-prompt decisions and risk pagination',
        'Session/workstation freeze isolation', 'Offline/restore/redeploy', 'Gateway PEP')
}
$exitCode = 1

# Windows native argument quoting, including embedded quotes and trailing slashes.
function ConvertTo-NativeArgument([string]$Value) {
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $slashes++; continue }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (2 * $slashes + 1)))
        } else { [void]$builder.Append(('\' * $slashes)) }
        [void]$builder.Append($character)
        $slashes = 0
    }
    [void]$builder.Append(('\' * (2 * $slashes)))
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-Edge {
    param([string[]]$Arguments, [string]$InputText = '', [int]$TimeoutSeconds = 20)
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $script:edge
    $info.Arguments = (($Arguments | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' ')
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.RedirectStandardInput = $true
    $info.EnvironmentVariables['BAP_USER_PROMPT'] = ''
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if ($InputText) { $process.StandardInput.Write($InputText) }
        $process.StandardInput.Close() # Never answer an interactive approval prompt.
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill()
            throw "Edge command exceeded ${TimeoutSeconds}s; inspect the client separately."
        }
        $process.WaitForExit()
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $stdout.Result;
            ErrorOutput = $stderr.Result; DurationMs = $timer.ElapsedMilliseconds }
    } finally { $process.Dispose() }
}

function Read-EdgeJSON([string[]]$Arguments) {
    $response = Invoke-Edge -Arguments $Arguments
    if ($response.ExitCode -ne 0) { throw "Edge diagnostic failed (exit $($response.ExitCode)); run the command interactively for details." }
    try { return ($response.Output | ConvertFrom-Json) }
    catch { throw 'Edge did not return valid JSON. Confirm that the installed artifact contains these fixes.' }
}

function Assert-Check([string]$Name, [bool]$Passed, [string]$Detail) {
    $report.checks += [ordered]@{ name = $Name; passed = $Passed; detail = $Detail }
    if (-not $Passed) { throw "${Name}: $Detail" }
    Write-Host "PASS  $Name"
}

try {
    $script:edge = (Resolve-Path -LiteralPath $BapEdgePath).Path
    if ([IO.Path]::GetExtension($script:edge) -ne '.exe') { throw 'Provide the full installed bapedge.exe path, not a Python or CMD shim.' }
    if (-not $OutputDirectory) { $OutputDirectory = Join-Path (Get-Location).Path ('.bap-acceptance\' + $runID) }
    [void][IO.Directory]::CreateDirectory($OutputDirectory)
    $reportPath = Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) 'smoke-report.json'
    $report.edge_path = $script:edge
    $stream = [IO.File]::OpenRead($script:edge)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $report.edge_sha256 = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $sha.Dispose() }
    $version = Invoke-Edge -Arguments @('version')
    Assert-Check 'Installed binary responds' ($version.ExitCode -eq 0) 'version command must succeed'
    $report.edge_version = $version.Output.Trim()

    $status = Read-EdgeJSON @('status', '--json')
    $daemon = Read-EdgeJSON @('daemon', 'status', '--json')
    $report.snapshots.before = @{
        enrolled = $status.enrollment.enrolled; agent_id = $status.enrollment.agent_id
        daemon_pid = $daemon.daemon.pid; control_plane = $daemon.control_plane
        telemetry = $daemon.telemetry; capabilities = $daemon.daemon.capabilities
    }
    if ($SnapshotOnly) {
        $report.result = 'SNAPSHOT_ONLY'; $exitCode = 0
    } else {
        Assert-Check 'Telemetry not suppressed by test environment' ($env:BAP_TEST_MODE -ne '1' -and $env:LTD_TEST -ne '1' -and $env:BAP_ENV -ne 'test') 'Run installed-client acceptance without test-mode telemetry suppression'
        Assert-Check 'Workstation enrolled' ($status.enrollment.enrolled -eq $true) 'Complete bap login before running smoke checks'
        Assert-Check 'Reporting daemon running' ($daemon.daemon.pid -gt 0) 'Install/login must start the daemon'
        Assert-Check 'Daemon uses enrolled server' ($daemon.control_plane.url -and $daemon.control_plane.url.TrimEnd('/') -eq $ExpectedServer.TrimEnd('/')) 'Daemon target must match the intended enrollment origin'
        $config = Invoke-Edge -Arguments @('config', 'show')
        Assert-Check 'Master enrollment configuration' ($config.ExitCode -eq 0 -and ($config.Output -match 'workstation_enrollment' -or $config.Output -match 'LOCKED by managed config')) 'Expected enrollment precedence or an administrator endpoint lock'

        $common = @('exec', '--source', 'cli', '--session-id', $runID,
            '--prompt=', '--mode', 'enforce', '--json')
        $allowed = Invoke-Edge -Arguments ($common + @('git --version')) -TimeoutSeconds 30
        $allowBody = $allowed.Output | ConvertFrom-Json
        Assert-Check 'Allowed command actually executes' ($allowed.ExitCode -eq 0 -and $allowBody.allowed -eq $true -and $allowBody.output -match 'git version') 'git --version must return real Git output'
        Assert-Check 'Allowed command retains session identity' ($allowBody.receipt.session_id -eq $runID) 'Receipt must contain this run ID'

        # A nonexistent, unapproved executable: no credential reads or risky commands.
        $probe = 'bap-unapproved-probe-' + [Guid]::NewGuid().ToString('N') + '.exe'
        $denied = Invoke-Edge -Arguments ($common + @('--stepup-decision', 'deny', $probe)) -TimeoutSeconds 30
        $denyBody = $denied.Output | ConvertFrom-Json
        Assert-Check 'Unapproved executable denied' ($denied.ExitCode -ne 0 -and $denyBody.allowed -eq $false -and $denyBody.decision -match 'deny|block') 'Policy must deny; an executable-not-found error alone is not a pass'
        Assert-Check 'Denial retains session identity' ($denyBody.receipt.session_id -eq $runID) 'Allowed and denied receipts must share the run ID'
        $report.broker = @{ session_id = $runID; allowed_receipt = $allowBody.receipt.receipt_id;
            denied_receipt = $denyBody.receipt.receipt_id; allowed_total_ms = $allowed.DurationMs;
            denied_total_ms = $denied.DurationMs; prompt_text_supplied = $false }

        # The broker supplies proof internally. No token is read or passed here.
        # A 200/alive for this unique ID proves that its reporting session arrived.
        $heartbeatBody = @{ session_id = $runID } | ConvertTo-Json -Compress
        $deadline = [DateTime]::UtcNow.AddSeconds($ReportingTimeoutSeconds)
        $seen = $false; $lastStatus = 0
        do {
            $reply = Invoke-Edge -Arguments @('session-telemetry', '--server', $ExpectedServer,
                '--kind', 'heartbeat') -InputText $heartbeatBody -TimeoutSeconds 8
            if ($reply.ExitCode -eq 0) {
                $envelope = $reply.Output | ConvertFrom-Json
                $lastStatus = $envelope.status_code
                if ($lastStatus -eq 200) {
                    $body = $envelope.body | ConvertFrom-Json
                    $seen = $body.status -in @('alive', 'active', 'ok')
                }
                if ($lastStatus -in @(401, 403)) { break }
            }
            if (-not $seen) { Start-Sleep -Milliseconds 1000 }
        } while (-not $seen -and [DateTime]::UtcNow -lt $deadline)
        Assert-Check 'Exact session reaches authenticated control plane' $seen "Expected authenticated heartbeat for $runID; last HTTP status $lastStatus"
        $after = Read-EdgeJSON @('daemon', 'status', '--json')
        $report.snapshots.after = @{ telemetry = $after.telemetry; control_plane = $after.control_plane }
        $report.result = 'AUTOMATED_SMOKE_PASS'; $exitCode = 0
    }
} catch {
    $report.result = 'FAIL'
    $report.failure = $_.Exception.Message
    Write-Host ('FAIL  ' + $report.failure) -ForegroundColor Red
} finally {
    $report.finished_at = [DateTime]::UtcNow.ToString('o')
    if ($reportPath) {
        $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reportPath -Encoding UTF8
        Write-Host "Report: $reportPath"
    }
}
if ($exitCode -eq 0 -and -not $SnapshotOnly) {
    Write-Host "AUTOMATED SMOKE PASS. In Live UI, verify $runID has both broker events and no supplied prompt."
    Write-Host 'Full acceptance still requires docs/FRESH_INSTALL_ACCEPTANCE.md.'
}
exit $exitCode
