@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title BAP Zero-Trust Platform - CIO Autonomous Workforce Live Demonstration
color 0B

echo ====================================================================================================
echo               BOUNDED AUTHORITY PLANE (BAP) - EXECUTIVE CIO WORKFORCE DEMO
echo           15 Enterprise Teams ^| 75 Governed Autonomous Agents ^| 300 Dynamic Workloads
echo ====================================================================================================
echo.
echo  This demonstration showcases the real-time BAP Zero-Trust executive observability platform:
echo   - 15 Diverse Enterprise Teams (Payments, Core Banking, Fraud Ops, Cloud Infra, Security, etc.)
echo   - 5 Governed Autonomous Python Agents per Team (75 concurrent live agents)
echo   - 300 Real-world enterprise task catalog with live intent evaluation
echo   - 2 Distinct randomized tasks per team (every run executes different workloads)
echo   - Live session registration, intent streaming, heartbeat health, and sub-2ms policy evaluation
echo.

:: 1. Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [-] ERROR: Python is not detected in PATH. Please install Python 3.8+ to proceed.
    pause
    exit /b 1
)

:: 2. Check if Control Plane is running on port 8080
echo [*] Checking BAP Control Plane on http://127.0.0.1:8080/api/v1/health...
powershell -NoProfile -Command "try { $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8080/api/v1/health' -TimeoutSec 2 -UseBasicParsing; exit 0 } catch { exit 1 }" >nul 2>&1
if errorlevel 1 (
    echo [*] Control Plane is not running. Launching local control plane server...
    if exist "bapcontrolplane.exe" (
        start "BAP Control Plane" /min "bapcontrolplane.exe"
    ) else if exist "bap-controlplane\bapcontrolplane.exe" (
        start "BAP Control Plane" /min "bap-controlplane\bapcontrolplane.exe"
    ) else if exist "bap-controlplane.exe" (
        start "BAP Control Plane" /min "bap-controlplane.exe"
    ) else (
        pushd bap-controlplane
        start "BAP Control Plane" /min go run ./cmd/server
        popd
    )
    echo [*] Waiting for Control Plane to initialize...
    timeout /t 3 /nobreak >nul
) else (
    echo [+] Control Plane is active and healthy.
)

:: 3. Launch the CIO Live Executive Dashboard in browser
echo [*] Opening Executive CIO Dashboard in browser...
start http://127.0.0.1:8080/dashboard?persona=cio

:: 4. Run the 15-team 75-agent workforce script
echo.
echo [*] Starting autonomous workforce workload...
python demo_cio_workforce.py %*

echo.
echo ====================================================================================================
echo [+] CIO Autonomous Workforce demonstration session completed.
echo ====================================================================================================
pause
