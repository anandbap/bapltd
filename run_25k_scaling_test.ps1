<#
.SYNOPSIS
    Bounded Authority Plane (BAP) - 25,000 Operation Remote Scalability Benchmark (PowerShell)
.DESCRIPTION
    Executes a high-throughput 25,000 operation scaling benchmark from a Python agent fleet
    against the remote Render Control Plane (or local control plane) with zero-loss proof.
.PARAMETER Url
    Custom Control Plane URL (defaults to https://bap-controlplane.onrender.com)
.PARAMETER TotalOps
    Total operations to dispatch (default: 25000)
.PARAMETER BatchSize
    Batch size for telemetry streaming (default: 250)
.PARAMETER Concurrency
    Number of parallel worker threads (default: 8)
.PARAMETER AllowRatio
    Ratio of allowed vs denied events (default: 0.90)
#>
[CmdletBinding()]
param(
    [string]$Url = '',
    [int]$TotalOps = 25000,
    [int]$BatchSize = 250,
    [int]$Concurrency = 4,
    [double]$AllowRatio = 0.90,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArgs
)

Set-Location $PSScriptRoot

Write-Host "=========================================================================================================" -ForegroundColor Cyan
Write-Host "              BOUNDED AUTHORITY PLANE (BAP) - 25,000 OPERATION REMOTE SCALING BENCHMARK" -ForegroundColor Cyan
Write-Host "                      Real-Time Multi-Agent Fleet Scalability & Zero-Loss Verification" -ForegroundColor Cyan
Write-Host "=========================================================================================================" -ForegroundColor Cyan
Write-Host ""

# Verify Python
$pyBin = "python"
$pyCheck = Get-Command python -ErrorAction SilentlyContinue
if (-not $pyCheck) {
    foreach ($cand in @("$env:LOCALAPPDATA\Programs\Python\Python312\python.exe", "$env:ProgramFiles\Python312\python.exe", "C:\Python312\python.exe")) {
        if (Test-Path $cand) {
            $pyBin = $cand
            break
        }
    }
}

$pyArgs = @('scripts/benchmark_25k_scaling.py')
if ($Url) { $pyArgs += @('--url', $Url) }
if ($TotalOps) { $pyArgs += @('--total-ops', $TotalOps.ToString()) }
if ($BatchSize) { $pyArgs += @('--batch-size', $BatchSize.ToString()) }
if ($Concurrency) { $pyArgs += @('--concurrency', $Concurrency.ToString()) }
if ($AllowRatio) { $pyArgs += @('--allow-ratio', $AllowRatio.ToString()) }
if ($RemainingArgs) { $pyArgs += $RemainingArgs }

& $pyBin @pyArgs
