@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title BAP Zero-Trust Platform - Executive CIO Demonstration
mode con: cols=100 lines=38
color 0B

echo ====================================================================================================
echo               BOUNDED AUTHORITY PLANE (BAP) - EXECUTIVE DEMONSTRATION FOR THE CIO
echo                  Zero-Trust Pre-Execution Governance and Observability for AI Agents
echo ====================================================================================================
echo.
echo  Welcome! This demonstration showcases how BAP eliminates standing privileges for autonomous
echo  AI coding agents (Claude Code, GitHub Copilot) while preserving sub-2ms developer velocity.
echo.
echo  [*] Initializing pristine demonstration environment...
echo.

:: Parse CLI arguments (-local, --local, or explicit host)
set "FORCE_LOCAL=0"
if /i "%~1"=="-local" set "FORCE_LOCAL=1"
if /i "%~1"=="--local" set "FORCE_LOCAL=1"
if /i "%~1"=="local" set "FORCE_LOCAL=1"

:: Resolve Central Control Plane and Gateway URLs from environment or bap-config.json
set "CP_URL=%BAP_SERVER_URL%"
set "GW_URL=%BAP_GATEWAY_URL%"

if "!FORCE_LOCAL!"=="1" (
    echo  [*] Forced LOCAL demonstration mode requested via CLI flag.
    set "CP_URL=http://localhost:8080"
    set "GW_URL=http://localhost:9090"
) else (
    if "!CP_URL!"=="" (
        if exist "bap-config.json" (
            for /f "usebackq delims=" %%U in (`powershell -NoProfile -Command "(Get-Content bap-config.json -Raw | ConvertFrom-Json).controlplane_url"`) do set "CP_URL=%%U"
        )
    )
    if "!GW_URL!"=="" (
        if exist "bap-config.json" (
            for /f "usebackq delims=" %%U in (`powershell -NoProfile -Command "(Get-Content bap-config.json -Raw | ConvertFrom-Json).gateway_url"`) do set "GW_URL=%%U"
        )
    )
)

if "!CP_URL!"=="" set "CP_URL=http://localhost:8080"
if "!GW_URL!"=="" set "GW_URL=http://localhost:9090"

set "CP_IS_LOCAL=0"
echo !CP_URL! | findstr /i "localhost 127.0.0.1 ::1" >nul 2>&1
if !errorlevel! equ 0 set "CP_IS_LOCAL=1"

set "GW_IS_LOCAL=0"
echo !GW_URL! | findstr /i "localhost 127.0.0.1 ::1" >nul 2>&1
if !errorlevel! equ 0 set "GW_IS_LOCAL=1"

:: If configured for remote but remote is unreachable from current network, auto-fallback to local
if "!CP_IS_LOCAL!"=="0" (
    echo  [*] Checking remote Control Plane at !CP_URL!...
    curl.exe -s --max-time 2 --connect-timeout 2 -X GET "!CP_URL!/api/v1/health" >nul 2>&1
    if !errorlevel! neq 0 (
        echo  [-] Remote Control Plane at !CP_URL! is unreachable from current network.
        echo  [*] Auto-fallback: Switching to local demonstration daemons (localhost:8080, localhost:9090)...
        set "CP_URL=http://localhost:8080"
        set "GW_URL=http://localhost:9090"
        set "CP_IS_LOCAL=1"
        set "GW_IS_LOCAL=1"
    ) else (
        echo  [+] Connected to remote Control Plane at !CP_URL!
    )
)

echo  [*] Target Control Plane : !CP_URL! (local=!CP_IS_LOCAL!)
echo  [*] Target Gateway PEP   : !GW_URL! (local=!GW_IS_LOCAL!)
echo.

:: Resolve binary paths from dist or root
set "CP_BIN=%~dp0dist\windows-amd64\controlplane\bapcontrolplane.exe"
if not exist "!CP_BIN!" set "CP_BIN=%~dp0dist\windows-amd64\bapcontrolplane.exe"
if not exist "!CP_BIN!" set "CP_BIN=%~dp0bapcontrolplane.exe"

set "GW_BIN=%~dp0dist\windows-amd64\gateway\bapgateway.exe"
if not exist "!GW_BIN!" set "GW_BIN=%~dp0dist\windows-amd64\bapgateway.exe"
if not exist "!GW_BIN!" set "GW_BIN=%~dp0bapgateway.exe"

:: 0. Reset previous sessions and clear local audit log
if "!CP_IS_LOCAL!"=="1" type nul > "%~dp0ltd-audit.jsonl"
curl.exe -s --max-time 2 --connect-timeout 2 -X POST "!CP_URL!/api/v1/sessions/reset" >nul 2>&1

:: 1. Ensure Control Plane is available
if "!CP_IS_LOCAL!"=="1" (
    powershell -NoProfile -Command "if (Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"
    if !errorlevel! equ 0 (
        echo  [+] Local BAP Control Plane active on !CP_URL!
    ) else (
        echo  [*] Starting BAP Control Plane daemon on port 8080...
        start "BAP Control Plane (8080)" /min "!CP_BIN!" start -port 8080 -ttl 30 -trust-domain bap.internal -mode dev
        ping -n 3 127.0.0.1 >nul
        echo  [+] Control Plane started successfully.
    )
)

:: 2. Ensure Gateway is available
if "!GW_IS_LOCAL!"=="1" (
    powershell -NoProfile -Command "if (Get-NetTCPConnection -LocalPort 9090 -State Listen -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"
    if !errorlevel! equ 0 (
        echo  [+] Local BAP Gateway PEP active on !GW_URL!
    ) else (
        echo  [*] Starting BAP Gateway PEP daemon on port 9090...
        start "BAP Gateway PEP (9090)" /min "!GW_BIN!" start -port 9090 -controlplane !CP_URL!
        ping -n 2 127.0.0.1 >nul
        echo  [+] Gateway PEP started successfully.
    )
) else (
    echo  [*] Checking remote Gateway PEP at !GW_URL!...
    curl.exe -s --max-time 3 --connect-timeout 2 -X GET "!GW_URL!/health" >nul 2>&1
    if !errorlevel! equ 0 (
        echo  [+] Connected to remote Gateway PEP at !GW_URL!
    ) else (
        echo  [!] Warning: Could not reach remote Gateway PEP at !GW_URL!.
    )
)

:: 3. Act 1: Spin up 5 live Claude Code agent workloads across enterprise squads
echo.
echo  ====================================================================================================
echo   ACT 1: ENROLLING 5 LIVE CLAUDE CODE DEVELOPER AGENTS (DUAL IDENTITY and SPIFFE)
echo  ====================================================================================================
echo.
python scripts\launch_fleet.py --server %CP_URL% --count 5 --once

:: Resolve current shell PID so background daemon auto-deregisters if shell is closed
set "MY_PID="
for /f %%i in ('powershell -NoProfile -Command "$pid"') do set "MY_PID=%%i"

:: Start background heartbeat keepalive with auto-deregistration
taskkill /fi "WINDOWTITLE eq BAP-Fleet-Daemon*" /f >nul 2>&1
if "!MY_PID!"=="" (
    start "BAP-Fleet-Daemon" /min python scripts\launch_fleet.py --server %CP_URL% --count 5
) else (
    start "BAP-Fleet-Daemon" /min python scripts\launch_fleet.py --server %CP_URL% --count 5 --parent-pid !MY_PID!
)

:: 4. Launch browser inspector
echo.
echo  [*] Opening BAP Executive Cockpit and Live Fleet Radar in default browser...
start %CP_URL%/inspector?mode=live

echo.
echo ====================================================================================================
echo   SUCCESS! The BAP Executive Cockpit is now live on your screen.
echo.
echo   You can either:
echo   - Click the interactive hero buttons directly in your browser cockpit, OR
echo   - Press any of the 1-click options below in this terminal.
echo ====================================================================================================
echo.

:MENU_LOOP
echo ----------------------------------------------------------------------------------------------------
echo  EXECUTIVE INTERACTIVE ACTIONS:
echo   [1] [PASS]      Test Safe Multi-Stage Build (Sub-2ms Zero-Friction Pass)
echo   [2] [BLOCK]     Simulate Malicious Attack (Gateway PEP Dropped at Perimeter)
echo   [3] [SCALE]     Toggle Fleet Scale (5 Active Squads vs 25 Enterprise Nodes)
echo   [4] [KILL-ALL]  Toggle Global Emergency Kill-Switch (CISO Enterprise Override)
echo   [5] [REVOKE]    Targeted Agent Isolation (Revoke Access for 'Carol' Without Stopping Fleet)
echo   [6] [AUDIT]     Verify Cryptographic Audit Chain (100%% Anti-Tamper Merkle Proof)
echo   [7] [EXIT]      Exit Demonstration and Cleanly Deregister Fleet
echo ----------------------------------------------------------------------------------------------------
set /p OPT="Select action (1-7) [default: 1]: "
if "%OPT%"=="" set OPT=1

if "%OPT%"=="1" goto DO_SAFE
if "%OPT%"=="2" goto DO_ATTACK
if "%OPT%"=="3" goto DO_SCALE
if "%OPT%"=="4" goto DO_KILL
if "%OPT%"=="5" goto DO_KILL_ONE
if "%OPT%"=="6" goto DO_VERIFY
if "%OPT%"=="7" goto DO_EXIT
echo Invalid choice. Please enter 1-7.
goto MENU_LOOP

:DO_SAFE
echo.
python scripts\demo_actions.py safe
echo.
goto MENU_LOOP

:DO_ATTACK
echo.
python scripts\demo_actions.py attack
echo.
goto MENU_LOOP

:DO_SCALE
echo.
python scripts\demo_actions.py toggle-scale
echo.
goto MENU_LOOP

:DO_KILL
echo.
python scripts\demo_actions.py toggle-kill
echo.
goto MENU_LOOP

:DO_KILL_ONE
echo.
python scripts\demo_actions.py kill-agent --target carol
echo.
goto MENU_LOOP

:DO_VERIFY
echo.
python scripts\demo_actions.py verify
echo.
goto MENU_LOOP

:DO_EXIT
echo.
echo [*] Gracefully deregistering all agent workloads from Control Plane...
python scripts\demo_actions.py cleanup
taskkill /fi "WINDOWTITLE eq BAP-Fleet-Daemon*" /f >nul 2>&1
echo [+] All agent workloads cleanly deregistered from dashboard!
echo [+] Thank you for experiencing BAP!
timeout /t 2 >nul
endlocal
exit /b 0
