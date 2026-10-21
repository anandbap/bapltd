<#
.SYNOPSIS
GitHub Copilot Terminal Execution Wrapper for PowerShell.
Routes Copilot commands through bapedge (LTD - Local Trusted Daemon) with Cedar security policies.
#>
[CmdletBinding()]
param (
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CommandArgs
)

$cmdString = $CommandArgs -join ' '
if ([string]::IsNullOrWhiteSpace($cmdString)) {
    Write-Error "[copilot-wrap.ps1] No command provided to execute."
    exit 1
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$interceptorExe = Join-Path $scriptDir "copilot_interceptor.exe"
$interceptorBin = Join-Path $scriptDir "copilot_interceptor"
$bapExe = Join-Path $scriptDir "bapedge.exe"
$ltdExe = Join-Path $scriptDir "ltd-agent.exe"

$parentBapExe = Join-Path (Split-Path $scriptDir) "bap-edge\bapedge.exe"

if (Test-Path $interceptorExe) {
    & $interceptorExe $cmdString
} elseif (Test-Path $interceptorBin) {
    & $interceptorBin $cmdString
} elseif (Test-Path $bapExe) {
    & $bapExe exec --source copilot --raw $cmdString
} elseif (Test-Path $parentBapExe) {
    & $parentBapExe exec --source copilot --raw $cmdString
} elseif (Test-Path $ltdExe) {
    & $ltdExe exec --source copilot --raw $cmdString
} else {
    & bapedge exec --source copilot --raw $cmdString
}

exit $LASTEXITCODE
