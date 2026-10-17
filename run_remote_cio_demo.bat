@echo off
setlocal enabledelayedexpansion

echo ===============================================================================
echo   BOUNDED AUTHORITY PLANE (BAP): REMOTE CIO WORKFORCE DEMO LAUNCHER
echo ===============================================================================
echo.

set REMOTE_URL=%1
if "%REMOTE_URL%"=="" (
    if defined BAP_CONTROL_PLANE_URL (
        set REMOTE_URL=%BAP_CONTROL_PLANE_URL%
    ) else if defined BAP_SERVER_URL (
        set REMOTE_URL=%BAP_SERVER_URL%
    ) else (
        set REMOTE_URL=http://127.0.0.1:8080
    )
)

set DURATION=%2
if "%DURATION%"=="" set DURATION=180

echo Target Control Panel URL : %REMOTE_URL%
echo Planned Demo Duration    : %DURATION% seconds (or press Enter anytime to stop)
echo.
echo Launching Python demonstration engine...
python demo_remote_cio.py --url "%REMOTE_URL%" --duration %DURATION%

echo.
pause
