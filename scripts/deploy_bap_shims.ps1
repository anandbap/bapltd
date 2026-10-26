# BAP Zero-Trust Global CLI Shim Deployer
# =========================================
# Deploys transparent Windows CMD (.cmd) and POSIX shims to ~/.bap/bin
# Enables zero-trust auto-binding across cmd.exe, Win+R Run dialog, Git Bash, and IDEs.

$bapBin = Join-Path $env:USERPROFILE ".bap\bin"
if (-not (Test-Path -LiteralPath $bapBin)) {
    New-Item -ItemType Directory -Path $bapBin -Force | Out-Null
}

$agents = @(
    @{
        Id       = "codex"
        CmdName  = "codex"
        RealPath = (Get-Command "codex.exe" -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
        Fallbacks = @(
            "$env:LOCALAPPDATA\Programs\OpenAI\Codex\bin\codex.exe",
            "$env:LOCALAPPDATA\Programs\codex\codex.exe",
            "$env:APPDATA\npm\codex.cmd"
        )
    },
    @{
        Id       = "claude-code"
        CmdName  = "claude"
        RealPath = (Get-Command "claude.exe" -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
        Fallbacks = @(
            "$env:USERPROFILE\.local\bin\claude.exe",
            "$env:APPDATA\npm\claude.cmd"
        )
    },
    @{
        Id       = "antigravity"
        CmdName  = "agy"
        RealPath = (Get-Command "agy.exe" -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
        Fallbacks = @(
            "$env:LOCALAPPDATA\agy\bin\agy.exe",
            "$env:APPDATA\Antigravity\bin\agy-node.cmd"
        )
    },
    @{
        Id       = "copilot"
        CmdName  = "copilot"
        RealPath = (Get-Command "copilot.exe" -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
        Fallbacks = @(
            (Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages\GitHub.Copilot_Microsoft.Winget.Source_8wekyb3d8bbwe\copilot.exe"),
            (Join-Path $env:LOCALAPPDATA "Programs\copilot\copilot.exe")
        )
    }
)

foreach ($a in $agents) {
    $realBin = $a.RealPath
    if ([string]::IsNullOrWhiteSpace($realBin)) {
        foreach ($fb in $a.Fallbacks) {
            if (Test-Path -LiteralPath $fb) {
                $realBin = $fb
                break
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace($realBin)) {
        continue
    }

    $cmdPath = Join-Path $bapBin "$($a.CmdName).cmd"
    $posixPath = Join-Path $bapBin $a.CmdName
    $agentId = $a.Id

    # 1. Generate Windows CMD shim
    $cmdContent = @"
@echo off
setlocal EnableExtensions
if "%BAP_SHIM_ACTIVE%"=="1" goto RUN_RAW
set "BAP_SHIM_ACTIVE=1"
set "LTD_SOURCE=$agentId"
if "%BAP_SESSION_ID%"=="" (
  set "BAP_SESSION_ID=sess-$agentId-cmd-%RANDOM%"
)
if exist "%~dp0bapedge.exe" (
  "%~dp0bapedge.exe" session-start --app-id $agentId --session-id %BAP_SESSION_ID% >nul 2>&1
)
:RUN_RAW
"$realBin" %*
set "EXIT_CODE=%ERRORLEVEL%"
if "%BAP_SHIM_ACTIVE%"=="1" (
  if exist "%~dp0bapedge.exe" (
    "%~dp0bapedge.exe" session-end --session-id %BAP_SESSION_ID% >nul 2>&1
  )
)
exit /b %EXIT_CODE%
"@

    [System.IO.File]::WriteAllText($cmdPath, $cmdContent, [System.Text.Encoding]::ASCII)
    Write-Host "[+] Deployed CMD shim: $cmdPath -> $realBin" -ForegroundColor Green

    # 2. Generate POSIX shell shim (for Git Bash / WSL)
    $posixRealBin = $realBin.Replace('\', '/')
    $posixContent = @"
#!/bin/sh
if [ "`$BAP_SHIM_ACTIVE" = "1" ]; then
    exec "$posixRealBin" "`$@"
fi
export BAP_SHIM_ACTIVE=1
export LTD_SOURCE="$agentId"
if [ -z "`$BAP_SESSION_ID" ]; then
    export BAP_SESSION_ID="sess-$agentId-bash-`$RANDOM"
fi
SCRIPT_DIR="`$(cd "`$(dirname "`$0")" && pwd)"
if [ -f "`$SCRIPT_DIR/bapedge.exe" ]; then
    "`$SCRIPT_DIR/bapedge.exe" session-start --app-id $agentId --session-id "`$BAP_SESSION_ID" >/dev/null 2>&1
fi
"$posixRealBin" "`$@"
EXIT_CODE=`$?
if [ -f "`$SCRIPT_DIR/bapedge.exe" ]; then
    "`$SCRIPT_DIR/bapedge.exe" session-end --session-id "`$BAP_SESSION_ID" >/dev/null 2>&1
fi
exit `$EXIT_CODE
"@

    [System.IO.File]::WriteAllText($posixPath, $posixContent, [System.Text.UTF8Encoding]::new($false))
    Write-Host "[+] Deployed POSIX shim: $posixPath -> $realBin" -ForegroundColor Green
}
