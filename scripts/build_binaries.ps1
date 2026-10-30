$ErrorActionPreference = "Stop"
if (-not $env:GIT_CONFIG_GLOBAL) { $env:GIT_CONFIG_GLOBAL = "nul" }
$rootDir = (Get-Item $PSScriptRoot).Parent.FullName
Set-Location $rootDir

$commit = try { (git rev-parse --short HEAD 2>$null) } catch { "dev" }
if (-not $commit) { $commit = "dev" }
$version = $env:BAP_VERSION
if (-not $version) {
    $pyproject = Join-Path $rootDir "pyproject.toml"
    if (Test-Path $pyproject) {
        $content = Get-Content $pyproject -Raw
        if ($content -match 'version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"') {
            $version = "v$($matches[1])"
        }
    }
}
if (-not $version) { $version = "v1.9.3" }
$buildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

Write-Host "Building BAP Binaries (Version: $version, Commit: $commit, Date: $buildDate)..." -ForegroundColor Cyan

# 1. bapcontrolplane
Push-Location (Join-Path $rootDir "bap-controlplane")
try {
    $ld = "-s -w -X 'bap-controlplane/pkg/version.Version=$version' -X 'bap-controlplane/pkg/version.GitCommit=$commit' -X 'bap-controlplane/pkg/version.BuildDate=$buildDate'"
    go build -trimpath -buildvcs=false -ldflags $ld -o "$rootDir\bapcontrolplane.exe" ./cmd/server
    if (Test-Path "$rootDir\dist\windows-amd64") {
        Copy-Item -Force "$rootDir\bapcontrolplane.exe" "$rootDir\dist\windows-amd64\bapcontrolplane.exe"
    }
    if (Test-Path "$rootDir\bap-controlplane") {
        Copy-Item -Force "$rootDir\bapcontrolplane.exe" "$rootDir\bap-controlplane\bapcontrolplane.exe"
    }
    Write-Host "  [+] bapcontrolplane.exe" -ForegroundColor Green
    go build -trimpath -buildvcs=false -ldflags $ld -o "$rootDir\bapdashboard.exe" ./cmd/dashboard
    if (Test-Path "$rootDir\dist\windows-amd64") {
        Copy-Item -Force "$rootDir\bapdashboard.exe" "$rootDir\dist\windows-amd64\bapdashboard.exe"
    }
    Write-Host "  [+] bapdashboard.exe" -ForegroundColor Green
} finally { Pop-Location }

# 2. bapedge
Push-Location (Join-Path $rootDir "bap-edge")
try {
    $ld = "-s -w -X 'bap-edge/pkg/version.Version=$version' -X 'bap-edge/pkg/version.GitCommit=$commit' -X 'bap-edge/pkg/version.BuildDate=$buildDate'"
    go build -trimpath -buildvcs=false -ldflags $ld -o "$rootDir\bapedge.new.exe" .
    if (Test-Path "$rootDir\bapedge.old") { Remove-Item -Force "$rootDir\bapedge.old" -ErrorAction SilentlyContinue }
    if (Test-Path "$rootDir\bapedge.exe") { Move-Item -Force "$rootDir\bapedge.exe" "$rootDir\bapedge.old" -ErrorAction SilentlyContinue }
    Move-Item -Force "$rootDir\bapedge.new.exe" "$rootDir\bapedge.exe"
    Copy-Item -Force "$rootDir\bapedge.exe" "$rootDir\bapmcp.exe"
    if (Test-Path "$rootDir\dist\windows-amd64") {
        Copy-Item -Force "$rootDir\bapedge.exe" "$rootDir\dist\windows-amd64\bapedge.exe"
        Copy-Item -Force "$rootDir\bapedge.exe" "$rootDir\dist\windows-amd64\bapmcp.exe"
    }
    if (Test-Path "$rootDir\dist\windows-amd64\claude-client") {
        Copy-Item -Force "$rootDir\bapedge.exe" "$rootDir\dist\windows-amd64\claude-client\bapedge.exe"
    }
    if (Test-Path "$rootDir\bap\bin\windows-amd64") {
        Copy-Item -Force "$rootDir\bapedge.exe" "$rootDir\bap\bin\windows-amd64\bapedge.exe"
        Copy-Item -Force "$rootDir\bapedge.exe" "$rootDir\bap\bin\windows-amd64\bapmcp.exe"
    }
    Write-Host "  [+] bapedge.exe and bapmcp.exe updated" -ForegroundColor Green
} finally { Pop-Location }

# 3. bapgateway
Push-Location (Join-Path $rootDir "bap-gateway")
try {
    $ld = "-s -w -X 'bap-gateway/pkg/version.Version=$version' -X 'bap-gateway/pkg/version.GitCommit=$commit' -X 'bap-gateway/pkg/version.BuildDate=$buildDate'"
    go build -trimpath -buildvcs=false -ldflags $ld -o "$rootDir\bapgateway.exe" .
    if (Test-Path "$rootDir\dist\windows-amd64") {
        Copy-Item -Force "$rootDir\bapgateway.exe" "$rootDir\dist\windows-amd64\bapgateway.exe"
    }
    Write-Host "  [+] bapgateway.exe" -ForegroundColor Green
} finally { Pop-Location }

# 4. cchook interceptor
Push-Location (Join-Path $rootDir "cchook")
try {
    $ld = "-s -w -X 'main.Version=$version' -X 'main.GitCommit=$commit' -X 'main.BuildDate=$buildDate'"
    go build -trimpath -buildvcs=false -ldflags $ld -o "$rootDir\cchook\interceptor.exe" .
    Copy-Item -Force "$rootDir\cchook\interceptor.exe" "$rootDir\cchook\cchook-interceptor.exe"
    Copy-Item -Force "$rootDir\cchook\interceptor.exe" "$rootDir\interceptor.exe"
    Copy-Item -Force "$rootDir\cchook\interceptor.exe" "$rootDir\cchook-interceptor.exe"
    if (Test-Path "$rootDir\.claude\hooks") {
        Copy-Item -Force "$rootDir\cchook\interceptor.exe" "$rootDir\.claude\hooks\interceptor.exe"
    }
    if (Test-Path "$rootDir\dist\windows-amd64") {
        Copy-Item -Force "$rootDir\cchook\interceptor.exe" "$rootDir\dist\windows-amd64\interceptor.exe"
        Copy-Item -Force "$rootDir\cchook\interceptor.exe" "$rootDir\dist\windows-amd64\cchook-interceptor.exe"
    }
    if (Test-Path "$rootDir\dist\windows-amd64\claude-client") {
        Copy-Item -Force "$rootDir\cchook\interceptor.exe" "$rootDir\dist\windows-amd64\claude-client\interceptor.exe"
    }
    if (Test-Path "$rootDir\bap\bin\windows-amd64") {
        Copy-Item -Force "$rootDir\cchook\interceptor.exe" "$rootDir\bap\bin\windows-amd64\interceptor.exe"
        Copy-Item -Force "$rootDir\cchook\interceptor.exe" "$rootDir\bap\bin\windows-amd64\cchook-interceptor.exe"
    }
    Write-Host "  [+] interceptor.exe and cchook-interceptor.exe updated" -ForegroundColor Green
} finally { Pop-Location }

Write-Host "Build complete!" -ForegroundColor Cyan
