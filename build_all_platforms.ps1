# Bounded Authority Plane (BAP) - Multi-Platform Binary Builder & Packager
# Builds static, zero-dependency Go binaries and creates ready-to-deploy role packages
# for Windows, Linux (amd64 + arm64), and macOS (Intel + Apple Silicon).

param(
    [string]$DistDir = "dist",
    [switch]$Archive = $true,
    [switch]$ForceRegenCerts = $false,
    [string]$Domain = "a.b.com"
)

$ErrorActionPreference = "Stop"
$rootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $rootDir

function Safe-CopyItem {
    param($Source, $Destination)
    try {
        Microsoft.PowerShell.Management\Copy-Item -LiteralPath $Source -Destination $Destination -Force
    }
    catch [System.IO.IOException] {
        Write-Warning "File in use ($Destination); skipping overwrite."
    }
}


# Ensure BAP Root CA & TLS Certificates are provisioned and synchronized into client embed paths
Write-Host ">>> Ensuring BAP Root CA and TLS credentials (Domain: $Domain)..." -ForegroundColor Cyan
& (Join-Path $rootDir "scripts\ensure_certs.ps1") -ForceRegen:$ForceRegenCerts -AdditionalSAN $Domain -InstallToStore:$false


$env:CGO_ENABLED = "0"
$env:GOTOOLCHAIN = "auto"

$platforms = @(
    @{ Name = "windows-amd64"; OS = "windows"; Arch = "amd64"; Ext = ".exe" },
    @{ Name = "linux-amd64";   OS = "linux";   Arch = "amd64"; Ext = "" },
    @{ Name = "linux-arm64";   OS = "linux";   Arch = "arm64"; Ext = "" },
    @{ Name = "darwin-amd64";  OS = "darwin";  Arch = "amd64"; Ext = "" },
    @{ Name = "darwin-arm64";  OS = "darwin";  Arch = "arm64"; Ext = "" }
)

$components = @(
    @{ Dir = "bap-controlplane"; Pkg = "./cmd/server";            Name = "bapcontrolplane" },
    @{ Dir = "bap-controlplane"; Pkg = "./cmd/dashboard";         Name = "bapdashboard" },
    @{ Dir = "bap-edge";         Pkg = ".";                       Name = "bapedge" },
    @{ Dir = "bap-gateway";      Pkg = ".";                       Name = "bapgateway" },
    @{ Dir = "cchook";           Pkg = "interceptor.go";          Name = "cchook-interceptor" },
    @{ Dir = "copilot";          Pkg = "copilot_interceptor.go";  Name = "copilot-interceptor" }
)

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "   BAP MULTI-PLATFORM BINARY & DEPLOYMENT PACKAGER" -ForegroundColor Cyan
Write-Host "   Target Platforms: Windows, Linux (amd64, arm64), macOS (Intel, Apple Silicon)" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan

$distPath = Join-Path $rootDir $DistDir
if (!(Test-Path $distPath)) {
    New-Item -ItemType Directory -Path $distPath -Force | Out-Null
}

# Purge any stale tar.gz or zip files so only freshly built ones exist
if ($Archive) {
    Get-ChildItem -Path $distPath -Filter "*.tar.gz" -File -ErrorAction SilentlyContinue | Remove-Item -Force
    Get-ChildItem -Path $distPath -Filter "*.zip" -File -ErrorAction SilentlyContinue | Remove-Item -Force
    Get-ChildItem -Path $distPath -Include "*.db","*.log" -Recurse -File -ErrorAction SilentlyContinue | Remove-Item -Force
}

$startTime = Get-Date

foreach ($p in $platforms) {
    $platformDir = Join-Path $distPath $p.Name
    if (!(Test-Path $platformDir)) {
        New-Item -ItemType Directory -Path $platformDir -Force | Out-Null
    }

    Write-Host "`n>>> Compiling for $($p.Name) (OS: $($p.OS), ARCH: $($p.Arch))..." -ForegroundColor Yellow
    $env:GOOS = $p.OS
    $env:GOARCH = $p.Arch

    foreach ($c in $components) {
        $outFile = Join-Path $platformDir "$($c.Name)$($p.Ext)"
        $compDir = Join-Path $rootDir $c.Dir

        Push-Location $compDir
        try {
            go build -trimpath -ldflags "-s -w" -o $outFile $c.Pkg
            if ($LASTEXITCODE -ne 0) {
                throw "Compilation failed for $($c.Name) on $($p.Name)"
            }
            $size = (Get-Item $outFile).Length / 1MB
            Write-Host ("  [+] {0,-20} -> {1:N2} MB" -f "$($c.Name)$($p.Ext)", $size) -ForegroundColor Green
        }
        finally {
            Pop-Location
        }
    }

    # Root files for platform
    Safe-CopyItem (Join-Path $rootDir "bap-config.json") (Join-Path $platformDir "bap-config.json") -Force
    if (Test-Path (Join-Path $rootDir "policy.cedar")) {
        Safe-CopyItem (Join-Path $rootDir "policy.cedar") (Join-Path $platformDir "policy.cedar") -Force
    }
    if (Test-Path (Join-Path $rootDir "schema.json")) {
        Safe-CopyItem (Join-Path $rootDir "schema.json") (Join-Path $platformDir "schema.json") -Force
    }
    if (Test-Path (Join-Path $rootDir "inspector.html")) {
        Safe-CopyItem (Join-Path $rootDir "inspector.html") (Join-Path $platformDir "inspector.html") -Force
    }
    if (Test-Path (Join-Path $rootDir "inspector_v2.html")) {
        Safe-CopyItem (Join-Path $rootDir "inspector_v2.html") (Join-Path $platformDir "inspector_v2.html") -Force
    }

    # =========================================================================
    # ROLE PACKAGE 1: Control Plane (Central Server)
    # =========================================================================
    $cpDir = Join-Path $platformDir "controlplane"
    if (!(Test-Path $cpDir)) { New-Item -ItemType Directory -Path $cpDir -Force | Out-Null }
    Safe-CopyItem (Join-Path $platformDir "bapcontrolplane$($p.Ext)") (Join-Path $cpDir "bapcontrolplane$($p.Ext)") -Force
    if (Test-Path (Join-Path $rootDir "policy.cedar")) { Safe-CopyItem (Join-Path $rootDir "policy.cedar") (Join-Path $cpDir "policy.cedar") -Force }
    if (Test-Path (Join-Path $rootDir "schema.json")) { Safe-CopyItem (Join-Path $rootDir "schema.json") (Join-Path $cpDir "schema.json") -Force }
    if (Test-Path (Join-Path $rootDir "inspector.html")) { Safe-CopyItem (Join-Path $rootDir "inspector.html") (Join-Path $cpDir "inspector.html") -Force }
    if (Test-Path (Join-Path $rootDir "inspector_v2.html")) { Safe-CopyItem (Join-Path $rootDir "inspector_v2.html") (Join-Path $cpDir "inspector_v2.html") -Force }
    Safe-CopyItem (Join-Path $rootDir "bap-config.json") (Join-Path $cpDir "bap-config.json") -Force
    if (Test-Path (Join-Path $rootDir "controlplane-cert.pem")) { Safe-CopyItem (Join-Path $rootDir "controlplane-cert.pem") (Join-Path $cpDir "controlplane-cert.pem") -Force }
    if (Test-Path (Join-Path $rootDir "controlplane-key.pem")) { Safe-CopyItem (Join-Path $rootDir "controlplane-key.pem") (Join-Path $cpDir "controlplane-key.pem") -Force }
    if (Test-Path (Join-Path $rootDir "bap-root-ca.crt")) { Safe-CopyItem (Join-Path $rootDir "bap-root-ca.crt") (Join-Path $cpDir "bap-root-ca.crt") -Force }

    if ($p.OS -eq "windows") {
        $cpBat = @"
@echo off
cd /d "%~dp0"
echo ===============================================================================
echo   BAP CONTROL PLANE - CENTRAL SECURITY GOVERNANCE SERVER
echo ===============================================================================
echo [*] Starting BAP Control Plane on port 8080...
echo [*] Dashboard is a separate service. Start bapdashboard from its package.
echo.
bapcontrolplane.exe %*
"@
        Set-Content -Path (Join-Path $cpDir "start_controlplane.bat") -Value $cpBat -Encoding ASCII
    } else {
        $cpSh = @"
#!/usr/bin/env bash
set -e
cd "`$(dirname "`$0")"
chmod +x bapcontrolplane 2>/dev/null || true
echo "==============================================================================="
echo "  BAP CONTROL PLANE - CENTRAL SECURITY GOVERNANCE SERVER"
echo "==============================================================================="
echo "[*] Starting BAP Control Plane on port 8080..."
echo "[*] Dashboard is a separate service. Start bapdashboard from its package."
echo ""
exec ./bapcontrolplane "`$@"
"@
        Set-Content -Path (Join-Path $cpDir "start_controlplane.sh") -Value $cpSh -Encoding ASCII
    }

    $cpReadme = @"
================================================================================
  BAP CONTROL PLANE (CENTRAL GOVERNANCE SERVER)
================================================================================
This folder contains the complete standalone control plane service.

Quick Start:
  Windows: Double-click start_controlplane.bat (or run: bapcontrolplane.exe)
  Linux/Mac: Run ./start_controlplane.sh (or run: ./bapcontrolplane)

Dashboard:
  The UI is deliberately not hosted here. Start the separate bapdashboard package.

Persistence:
  Session history, active agent states, and audit records are automatically
  persisted to the embedded SQLite database (bap-controlplane.db).
================================================================================
"@
    Set-Content -Path (Join-Path $cpDir "README.txt") -Value $cpReadme -Encoding ASCII

    # =========================================================================
    # ROLE PACKAGE 2: Standalone HTTPS Dashboard
    # =========================================================================
    $dashDir = Join-Path $platformDir "dashboard"
    if (!(Test-Path $dashDir)) { New-Item -ItemType Directory -Path $dashDir -Force | Out-Null }
    Safe-CopyItem (Join-Path $platformDir "bapdashboard$($p.Ext)") (Join-Path $dashDir "bapdashboard$($p.Ext)") -Force
    if (Test-Path (Join-Path $rootDir "inspector.html")) { Safe-CopyItem (Join-Path $rootDir "inspector.html") (Join-Path $dashDir "inspector.html") -Force }
    if (Test-Path (Join-Path $rootDir "inspector_v2.html")) { Safe-CopyItem (Join-Path $rootDir "inspector_v2.html") (Join-Path $dashDir "inspector_v2.html") -Force }
    if (Test-Path (Join-Path $rootDir "controlplane-cert.pem")) { Safe-CopyItem (Join-Path $rootDir "controlplane-cert.pem") (Join-Path $dashDir "controlplane-cert.pem") -Force }
    if (Test-Path (Join-Path $rootDir "controlplane-key.pem")) { Safe-CopyItem (Join-Path $rootDir "controlplane-key.pem") (Join-Path $dashDir "controlplane-key.pem") -Force }
    if (Test-Path (Join-Path $rootDir "bap-root-ca.crt")) { Safe-CopyItem (Join-Path $rootDir "bap-root-ca.crt") (Join-Path $dashDir "bap-root-ca.crt") -Force }
    if ($p.OS -eq "windows") {
        Set-Content -Path (Join-Path $dashDir "start_dashboard.bat") -Encoding ASCII -Value '@echo off
cd /d "%~dp0"
bapdashboard.exe %*'
    } else {
        Set-Content -Path (Join-Path $dashDir "start_dashboard.sh") -Encoding ASCII -Value '#!/usr/bin/env sh
cd "$(dirname "$0")"
chmod +x ./bapdashboard
exec ./bapdashboard "$@"'
    }
    Set-Content -Path (Join-Path $dashDir "README.txt") -Encoding ASCII -Value @"
BAP STANDALONE DASHBOARD

Start this service only when the UI is required. By default it listens at:
  https://localhost:8444/dashboard/

and verifies the control plane at:
  https://localhost:8443

Use -control-plane and -ca-cert for another endpoint. For a control plane that
requires mutual TLS, also supply -client-cert and -client-key.
"@

    # =========================================================================
    # ROLE PACKAGE 3: claude-client / bapedge (Developer Machine Seat)
    # =========================================================================
    $clientDir = Join-Path $platformDir "claude-client"
    if (!(Test-Path $clientDir)) { New-Item -ItemType Directory -Path $clientDir -Force | Out-Null }
    Safe-CopyItem (Join-Path $platformDir "bapedge$($p.Ext)") (Join-Path $clientDir "bapedge$($p.Ext)") -Force
    if (Test-Path (Join-Path $rootDir "policy.cedar")) { Safe-CopyItem (Join-Path $rootDir "policy.cedar") (Join-Path $clientDir "policy.cedar") -Force }
    if (Test-Path (Join-Path $rootDir "schema.json")) { Safe-CopyItem (Join-Path $rootDir "schema.json") (Join-Path $clientDir "schema.json") -Force }
    Safe-CopyItem (Join-Path $rootDir "bap-config.json") (Join-Path $clientDir "bap-config.json") -Force

    # Place interceptor at root of claude-client and in cchook subfolder for full compatibility
    Safe-CopyItem (Join-Path $platformDir "cchook-interceptor$($p.Ext)") (Join-Path $clientDir "interceptor$($p.Ext)")
    $ccHookDir = Join-Path $clientDir "cchook"
    if (!(Test-Path $ccHookDir)) { New-Item -ItemType Directory -Path $ccHookDir -Force | Out-Null }
    Safe-CopyItem (Join-Path $platformDir "cchook-interceptor$($p.Ext)") (Join-Path $ccHookDir "interceptor$($p.Ext)")
    Remove-Item (Join-Path $clientDir "cchook-interceptor$($p.Ext)") -Force -ErrorAction SilentlyContinue

    # .claude hook settings
    $claudeSettingsDir = Join-Path $clientDir ".claude"
    if (!(Test-Path $claudeSettingsDir)) { New-Item -ItemType Directory -Path $claudeSettingsDir -Force | Out-Null }
    $hookCmd = if ($p.OS -eq "windows") { "interceptor.exe" } else { "interceptor" }
    $claudeSettings = @"
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "$hookCmd"
          }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "$hookCmd"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash|Read|View|Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "$hookCmd"
          }
        ]
      }
    ]
  }
}
"@
    Set-Content -Path (Join-Path $claudeSettingsDir "settings.json") -Value $claudeSettings -Encoding UTF8

    if ($p.OS -eq "windows") {
        if (Test-Path (Join-Path $rootDir "run_claude_bap.bat")) {
            Safe-CopyItem (Join-Path $rootDir "run_claude_bap.bat") (Join-Path $clientDir "run_claude_bap.bat") -Force
        }
        if (Test-Path (Join-Path $rootDir "run_claude_bap.ps1")) {
            Safe-CopyItem (Join-Path $rootDir "run_claude_bap.ps1") (Join-Path $clientDir "run_claude_bap.ps1") -Force
        }
    } else {
        $clientSh = @"
#!/usr/bin/env bash
set -e
SCRIPT_DIR="`$(cd "`$(dirname "`$0")" && pwd)"
chmod +x "`$SCRIPT_DIR/bapedge" "`$SCRIPT_DIR/cchook/interceptor" 2>/dev/null || true
export PATH="`$SCRIPT_DIR:`$SCRIPT_DIR/cchook:`$PATH"

SERVER_URL="`${1:-}"
if [ -z "`$SERVER_URL" ] && [ -f "bap-config.json" ]; then
    SERVER_URL=`$(grep -o '"controlplane_url": *"[^"]*"' bap-config.json | cut -d'"' -f4)
elif [ -z "`$SERVER_URL" ] && [ -f "`$SCRIPT_DIR/bap-config.json" ]; then
    SERVER_URL=`$(grep -o '"controlplane_url": *"[^"]*"' "`$SCRIPT_DIR/bap-config.json" | cut -d'"' -f4)
fi
if [ -z "`$SERVER_URL" ]; then
    SERVER_URL="http://localhost:8080"
fi

echo "==============================================================================="
echo "  CLAUDE CODE - BOUNDED AUTHORITY PLANE (BAP) GOVERNED CLIENT"
echo "  Working Directory: `$(pwd)"
echo "  Target Control Plane: `$SERVER_URL"
echo "==============================================================================="

export BAP_SESSION_ID="sess-claude-`$`$-`$(date +%s)"
export BAP_SERVER_URL="`$SERVER_URL"

# Start native detached bapedge session watcher
"`$SCRIPT_DIR/bapedge" watch --server "`$SERVER_URL" --session-id "`$BAP_SESSION_ID" --detach 2>/dev/null || true

# Execute Claude Code in current workspace directory
exec claude "`$@"
"@
        Set-Content -Path (Join-Path $clientDir "run_claude_bap.sh") -Value $clientSh -Encoding ASCII
    }

    $clientReadme = @"
================================================================================
  BAP EDGE - CLAUDE CODE GOVERNANCE PACKAGE
================================================================================
This folder contains everything needed to run Claude Code governed by BAP Zero-Trust.

Quick Start:
  1. Edit bap-config.json to point to your Linux control plane:
     "controlplane_url": "http://<LINUX_SERVER_IP>:8080"

  2. Run the launcher:
     Windows: run_claude_bap.bat http://<LINUX_SERVER_IP>:8080
     Linux/Mac: ./run_claude_bap.sh http://<LINUX_SERVER_IP>:8080

Features:
  - Sub-1.5ms local Cedar policy evaluation
  - Live workload chip on Central Radar
  - Background process watcher thread (auto-deregisters on exit or window close)
  - Instant remote kill-switch enforcement (< 20ms)
================================================================================
"@
    Set-Content -Path (Join-Path $clientDir "README.txt") -Value $clientReadme -Encoding ASCII

    # =========================================================================
    # ROLE PACKAGE 4: Gateway PEP
    # =========================================================================
    $gwDir = Join-Path $platformDir "gateway"
    if (!(Test-Path $gwDir)) { New-Item -ItemType Directory -Path $gwDir -Force | Out-Null }
    Safe-CopyItem (Join-Path $platformDir "bapgateway$($p.Ext)") (Join-Path $gwDir "bapgateway$($p.Ext)") -Force
    Safe-CopyItem (Join-Path $rootDir "bap-config.json") (Join-Path $gwDir "bap-config.json") -Force

    # Package zip/tar.gz archives (everything is packaged strictly from dist)
    if ($Archive) {
        if ($p.OS -eq "windows") {
            # 1. Complete platform package (all binaries, configs, and tools)
            Compress-Archive -Path "$platformDir\*" -DestinationPath (Join-Path $distPath "bap-$($p.Name).zip") -Force
            # 2. Standalone role packages
            Compress-Archive -Path "$cpDir\*" -DestinationPath (Join-Path $distPath "bap-controlplane-$($p.Name).zip") -Force
            Compress-Archive -Path "$dashDir\*" -DestinationPath (Join-Path $distPath "bap-dashboard-$($p.Name).zip") -Force
            Compress-Archive -Path "$clientDir\*" -DestinationPath (Join-Path $distPath "bap-claude-client-$($p.Name).zip") -Force
            Compress-Archive -Path "$gwDir\*" -DestinationPath (Join-Path $distPath "bap-gateway-$($p.Name).zip") -Force
            Write-Host "  [+] Packaged: bap-$($p.Name).zip, bap-controlplane-$($p.Name).zip, bap-dashboard-$($p.Name).zip, bap-claude-client-$($p.Name).zip, bap-gateway-$($p.Name).zip" -ForegroundColor Cyan
        } else {
            # 1. Complete platform package (all binaries, configs, and tools)
            tar -czf (Join-Path $distPath "bap-$($p.Name).tar.gz") -C $platformDir .
            # 2. Standalone role packages
            tar -czf (Join-Path $distPath "bap-controlplane-$($p.Name).tar.gz") -C $cpDir .
            tar -czf (Join-Path $distPath "bap-dashboard-$($p.Name).tar.gz") -C $dashDir .
            tar -czf (Join-Path $distPath "bap-claude-client-$($p.Name).tar.gz") -C $clientDir .
            tar -czf (Join-Path $distPath "bap-gateway-$($p.Name).tar.gz") -C $gwDir .
            Write-Host "  [+] Packaged: bap-$($p.Name).tar.gz, bap-controlplane-$($p.Name).tar.gz, bap-dashboard-$($p.Name).tar.gz, bap-claude-client-$($p.Name).tar.gz, bap-gateway-$($p.Name).tar.gz" -ForegroundColor Cyan
        }
    }
}

# Clean environment
Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue

# Verify asset synchronization across all platforms and packages
$checkScript = Join-Path $rootDir "scripts\check_stale_copies.ps1"
if (Test-Path $checkScript) {
    & $checkScript
}

$elapsed = (Get-Date) - $startTime
Write-Host "`n===============================================================================" -ForegroundColor Cyan
Write-Host ("   ALL PLATFORMS & ROLE PACKAGES BUILT IN {0:N1}s" -f $elapsed.TotalSeconds) -ForegroundColor Green
Write-Host "   Output Directory: $distPath" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
