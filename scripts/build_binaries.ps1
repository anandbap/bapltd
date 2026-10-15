$ErrorActionPreference = "Stop"
$rootDir = (Get-Item $PSScriptRoot).Parent.FullName
Set-Location $rootDir

$commit = try { (git rev-parse --short HEAD 2>$null) } catch { "dev" }
if (-not $commit) { $commit = "dev" }
$version = if ($env:BAP_VERSION) { $env:BAP_VERSION } else { "v1.0.0" }
$buildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

Write-Host "Building BAP Binaries (Version: $version, Commit: $commit, Date: $buildDate)..." -ForegroundColor Cyan

# 1. bapcontrolplane
Push-Location (Join-Path $rootDir "bap-controlplane")
try {
    $ld = "-s -w -X 'bap-controlplane/pkg/version.Version=$version' -X 'bap-controlplane/pkg/version.GitCommit=$commit' -X 'bap-controlplane/pkg/version.BuildDate=$buildDate'"
    go build -trimpath -ldflags $ld -o "$rootDir\bapcontrolplane.exe" ./cmd/server
    Write-Host "  [+] bapcontrolplane.exe" -ForegroundColor Green
    go build -trimpath -ldflags $ld -o "$rootDir\bapdashboard.exe" ./cmd/dashboard
    Write-Host "  [+] bapdashboard.exe" -ForegroundColor Green
} finally { Pop-Location }

# 2. bapedge
Push-Location (Join-Path $rootDir "bap-edge")
try {
    $ld = "-s -w -X 'bap-edge/pkg/version.Version=$version' -X 'bap-edge/pkg/version.GitCommit=$commit' -X 'bap-edge/pkg/version.BuildDate=$buildDate'"
    go build -trimpath -ldflags $ld -o "$rootDir\bapedge.new.exe" .
    if (Test-Path "$rootDir\bapedge.old") { Remove-Item -Force "$rootDir\bapedge.old" -ErrorAction SilentlyContinue }
    if (Test-Path "$rootDir\bapedge.exe") { Move-Item -Force "$rootDir\bapedge.exe" "$rootDir\bapedge.old" -ErrorAction SilentlyContinue }
    Move-Item -Force "$rootDir\bapedge.new.exe" "$rootDir\bapedge.exe"
    Copy-Item -Force "$rootDir\bapedge.exe" "$rootDir\bapmcp.exe"
    Write-Host "  [+] bapedge.exe and bapmcp.exe updated" -ForegroundColor Green
} finally { Pop-Location }

# 3. bapgateway
Push-Location (Join-Path $rootDir "bap-gateway")
try {
    $ld = "-s -w -X 'bap-gateway/pkg/version.Version=$version' -X 'bap-gateway/pkg/version.GitCommit=$commit' -X 'bap-gateway/pkg/version.BuildDate=$buildDate'"
    go build -trimpath -ldflags $ld -o "$rootDir\bapgateway.exe" .
    Write-Host "  [+] bapgateway.exe" -ForegroundColor Green
} finally { Pop-Location }

Write-Host "Build complete!" -ForegroundColor Cyan
