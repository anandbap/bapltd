param(
    [string]$Version = "",
    [string]$AllowDevOverrides = "true"
)
$ErrorActionPreference = "Stop"
$rootDir = $PSScriptRoot
if (-not $rootDir) { $rootDir = (Get-Location).Path }
Set-Location $rootDir
$env:GOFLAGS = "-buildvcs=false"

if (-not $Version) {
    # Extract version from bap-edge/pkg/version/version.go
    if (Test-Path "bap-edge\pkg\version\version.go") {
        $vMatch = Select-String -Path "bap-edge\pkg\version\version.go" -Pattern 'Version\s*=\s*"(v?[0-9]+\.[0-9]+\.[0-9]+)"'
        if ($vMatch) { $Version = $vMatch.Matches[0].Groups[1].Value }
    }
    if (-not $Version) { $Version = "v1.1.0" }
}
if (-not $Version.StartsWith("v")) { $Version = "v$Version" }

$gitCommit = try { (git rev-parse --short HEAD 2>$null) } catch { "dev" }
if (-not $gitCommit) { $gitCommit = "dev" }
$buildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

Write-Host ">>> Compiling Windows AMD64 Binaries ($Version, Commit: $gitCommit)..." -ForegroundColor Cyan

# 1. Compile bapedge
Push-Location "bap-edge"
try {
    $ldflags = "-s -w -X bap-edge/pkg/version.Version=$Version -X bap-edge/pkg/version.GitCommit=$gitCommit -X bap-edge/pkg/version.BuildDate=$buildDate -X bap-edge/pkg/version.AllowDevOverrides=$AllowDevOverrides"
    Remove-Item -Force "bapedge.exe" -ErrorAction SilentlyContinue
    go build -ldflags $ldflags -o bapedge.exe .
} finally {
    Pop-Location
}

# 2. Compile bapcontrolplane and bapdashboard
Push-Location "bap-controlplane"
try {
    $ldflags = "-s -w -X bap-controlplane/pkg/version.Version=$Version -X bap-controlplane/pkg/version.GitCommit=$gitCommit -X bap-controlplane/pkg/version.BuildDate=$buildDate"
    go build -ldflags $ldflags -o bapcontrolplane.exe ./cmd/server
    go build -ldflags $ldflags -o bapdashboard.exe ./cmd/dashboard
} finally {
    Pop-Location
}

# 3. Compile bapgateway
Push-Location "bap-gateway"
try {
    $ldflags = "-s -w -X bap-gateway/pkg/version.Version=$Version -X bap-gateway/pkg/version.GitCommit=$gitCommit -X bap-gateway/pkg/version.BuildDate=$buildDate"
    go build -ldflags $ldflags -o bapgateway.exe .
} finally {
    Pop-Location
}

# 4. Safe copy function with file lock handling
function Safe-Copy($src, $dst) {
    if (-not (Test-Path $src)) { return }
    $dstDir = Split-Path -Parent $dst
    if ($dstDir -and -not (Test-Path $dstDir)) {
        New-Item -ItemType Directory -Path $dstDir -Force | Out-Null
    }
    try {
        Copy-Item -Force $src $dst
    } catch {
        # File might be locked by running process; try rename-and-replace
        $oldFile = "$dst.old"
        Remove-Item -Force $oldFile -ErrorAction SilentlyContinue
        try {
            Move-Item -Force $dst $oldFile -ErrorAction SilentlyContinue
            Copy-Item -Force $src $dst
        } catch {
            Write-Warning "Could not overwrite $dst (process may be locked)"
        }
    }
}

# 5. Rotate and update root binaries
Safe-Copy "bap-edge\bapedge.exe" "bapedge.exe"
Safe-Copy "bap-edge\bapedge.exe" "bapmcp.exe"
Safe-Copy "bap-edge\bapedge.exe" "ltd-agent.exe"
Safe-Copy "bap-controlplane\bapcontrolplane.exe" "bapcontrolplane.exe"
Safe-Copy "bap-controlplane\bapdashboard.exe" "bapdashboard.exe"
Safe-Copy "bap-gateway\bapgateway.exe" "bapgateway.exe"
if (Test-Path "cchook\interceptor.exe") {
    Safe-Copy "cchook\interceptor.exe" "interceptor.exe"
    Safe-Copy "cchook\interceptor.exe" "cchook-interceptor.exe"
}

# 6. Update dist/windows-amd64 binaries
if (Test-Path "dist\windows-amd64") {
    Safe-Copy "bap-edge\bapedge.exe" "dist\windows-amd64\bapedge.exe"
    Safe-Copy "bap-edge\bapedge.exe" "dist\windows-amd64\bapmcp.exe"
    Safe-Copy "bap-controlplane\bapcontrolplane.exe" "dist\windows-amd64\bapcontrolplane.exe"
    Safe-Copy "bap-controlplane\bapdashboard.exe" "dist\windows-amd64\bapdashboard.exe"
    Safe-Copy "bap-gateway\bapgateway.exe" "dist\windows-amd64\bapgateway.exe"
    Safe-Copy "policy.cedar" "dist\windows-amd64\policy.cedar"
    Safe-Copy "schema.json" "dist\windows-amd64\schema.json"
    Safe-Copy "bap-config.json" "dist\windows-amd64\bap-config.json"
    if (Test-Path "dist\windows-amd64\controlplane") {
        Safe-Copy "bap-controlplane\bapcontrolplane.exe" "dist\windows-amd64\controlplane\bapcontrolplane.exe"
    }
    if (Test-Path "dist\windows-amd64\dashboard") {
        Safe-Copy "bap-controlplane\bapdashboard.exe" "dist\windows-amd64\dashboard\bapdashboard.exe"
    }
    if (Test-Path "dist\windows-amd64\claude-client") {
        Safe-Copy "bap-edge\bapedge.exe" "dist\windows-amd64\claude-client\bapedge.exe"
        if (Test-Path "cchook\interceptor.exe") {
            Safe-Copy "cchook\interceptor.exe" "dist\windows-amd64\claude-client\interceptor.exe"
        }
    }
    if (Test-Path "cchook\interceptor.exe") {
        Safe-Copy "cchook\interceptor.exe" "dist\windows-amd64\interceptor.exe"
        Safe-Copy "cchook\interceptor.exe" "dist\windows-amd64\cchook-interceptor.exe"
    }
}

# 7. Update user PATH bin directory (%USERPROFILE%\bin) if present
$userBin = Join-Path $env:USERPROFILE "bin"
if (Test-Path $userBin) {
    Safe-Copy "bap-edge\bapedge.exe" (Join-Path $userBin "bapedge.exe")
    Safe-Copy "bap-edge\bapedge.exe" (Join-Path $userBin "bapmcp.exe")
    Safe-Copy "bap-controlplane\bapcontrolplane.exe" (Join-Path $userBin "bapcontrolplane.exe")
    Safe-Copy "bap-controlplane\bapdashboard.exe" (Join-Path $userBin "bapdashboard.exe")
    Safe-Copy "bap-gateway\bapgateway.exe" (Join-Path $userBin "bapgateway.exe")
    if (Test-Path "cchook\interceptor.exe") {
        Safe-Copy "cchook\interceptor.exe" (Join-Path $userBin "interceptor.exe")
    }
    Safe-Copy "policy.cedar" (Join-Path $userBin "policy.cedar")
    Safe-Copy "schema.json" (Join-Path $userBin "schema.json")
    Safe-Copy "bap-config.json" (Join-Path $userBin "bap-config.json")
}

# 8. Update Python wheel package staging directory if present
if (Test-Path "bap\bin\windows-amd64") {
    Safe-Copy "bap-edge\bapedge.exe" "bap\bin\windows-amd64\bapedge.exe"
    Safe-Copy "bap-edge\bapedge.exe" "bap\bin\windows-amd64\bapmcp.exe"
    Safe-Copy "bap-controlplane\bapcontrolplane.exe" "bap\bin\windows-amd64\bapcontrolplane.exe"
    Safe-Copy "bap-gateway\bapgateway.exe" "bap\bin\windows-amd64\bapgateway.exe"
    if (Test-Path "cchook\interceptor.exe") {
        Safe-Copy "cchook\interceptor.exe" "bap\bin\windows-amd64\interceptor.exe"
    }
    Safe-Copy "policy.cedar" "bap\bin\windows-amd64\policy.cedar"
    Safe-Copy "schema.json" "bap\bin\windows-amd64\schema.json"
    Safe-Copy "bap-config.json" "bap\bin\windows-amd64\bap-config.json"
}

# Purge any stale temporary backup files from root
Get-ChildItem -Path $rootDir -Filter "*.old" -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host ">>> Binaries successfully compiled and updated to version $Version." -ForegroundColor Green

