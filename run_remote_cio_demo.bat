@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
cd /d "%~dp0"
title BAP Zero-Trust - Remote Agent Watch V3 CIO Demonstration
mode con: cols=105 lines=38
color 0B

echo =========================================================================================================
echo               BOUNDED AUTHORITY PLANE (BAP) - AGENT WATCH V3 REMOTE CIO DEMONSTRATION
echo                       Real-Time Multi-Agent Fleet Governance, Proof & HITL Control
echo =========================================================================================================
echo.

set REMOTE_URL=%1
if "%REMOTE_URL%"=="" (
    if defined BAP_CONTROL_PLANE_URL (
        set "REMOTE_URL=%BAP_CONTROL_PLANE_URL%"
    ) else if defined BAP_SERVER_URL (
        set "REMOTE_URL=%BAP_SERVER_URL%"
    ) else (
        set "REMOTE_URL=https://bap-controlplane.onrender.com"
    )
)

echo Target Control Plane URL : %REMOTE_URL%
echo Executive Dashboard (V3) : %REMOTE_URL%/dashboard/
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [-] Python 3 is not found in PATH. Please install Python 3.8+ to run this demo.
    pause
    exit /b 1
)

echo Launching Agent Watch V3 demonstration engine against remote cloud...
python demo_v3_cio.py --remote --url "%REMOTE_URL%" %*

echo.
echo Demonstration terminated cleanly.
pause
