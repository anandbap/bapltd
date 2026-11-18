@echo off
setlocal

echo ===============================================================================
echo   Starting BAP Control Plane and Opening Activity Inspector Dashboard
echo ===============================================================================

set "CP_URL=%BAP_SERVER_URL%"
if "%CP_URL%"=="" (
    if exist "bap-config.json" (
        for /f "usebackq delims=" %%U in (`powershell -NoProfile -Command "(Get-Content bap-config.json -Raw | ConvertFrom-Json).controlplane_url"`) do set "CP_URL=%%U"
    )
)
if "%CP_URL%"=="" set CP_URL=http://localhost:8080

:: Check if CP_URL points to localhost
set "IS_LOCAL=0"
echo %CP_URL% | findstr /i "localhost 127.0.0.1 ::1" >nul 2>&1
if %errorlevel% equ 0 set "IS_LOCAL=1"
:: Determine port and HTTPS scheme
set "CP_PORT=8443"
set "CP_HTTPS=1"
echo %CP_URL% | findstr /i "http://" >nul 2>&1
if %errorlevel% equ 0 (
    set "CP_PORT=8080"
    set "CP_HTTPS=0"
)
echo %CP_URL% | findstr /i ":8080" >nul 2>&1
if %errorlevel% equ 0 (
    set "CP_PORT=8080"
    set "CP_HTTPS=0"
)
echo %CP_URL% | findstr /i ":8443" >nul 2>&1
if %errorlevel% equ 0 (
    set "CP_PORT=8443"
    set "CP_HTTPS=1"
)

if "%IS_LOCAL%"=="1" (
    :: Local mode: check or launch local daemon
    powershell -NoProfile -Command "if (Get-NetTCPConnection -LocalPort %CP_PORT% -State Listen -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"
    if %errorlevel% equ 0 (
        echo [*] Local bapcontrolplane is already running on %CP_URL%.
    ) else (
        echo [*] Launching local bapcontrolplane daemon on %CP_URL%...
        if "%CP_HTTPS%"=="1" (
            powershell -NoProfile -Command "$p = if (Test-Path '.\dist\windows-amd64\controlplane\bapcontrolplane.exe') { '.\dist\windows-amd64\controlplane\bapcontrolplane.exe' } elseif (Test-Path '.\dist\windows-amd64\bapcontrolplane.exe') { '.\dist\windows-amd64\bapcontrolplane.exe' } else { '.\bap-controlplane\bapcontrolplane.exe' }; Start-Process -FilePath $p -ArgumentList '-port %CP_PORT% -https -ttl 30 -trust-domain bap.internal' -WindowStyle Hidden"
        ) else (
            powershell -NoProfile -Command "$p = if (Test-Path '.\dist\windows-amd64\controlplane\bapcontrolplane.exe') { '.\dist\windows-amd64\controlplane\bapcontrolplane.exe' } elseif (Test-Path '.\dist\windows-amd64\bapcontrolplane.exe') { '.\dist\windows-amd64\bapcontrolplane.exe' } else { '.\bap-controlplane\bapcontrolplane.exe' }; Start-Process -FilePath $p -ArgumentList '-port %CP_PORT% -ttl 30 -trust-domain bap.internal' -WindowStyle Hidden"
        )
        ping -n 3 127.0.0.1 >nul
    )
) else (
    echo [*] Central Control Plane configured at: %CP_URL%
    echo [*] Verifying connection to remote control plane...
    curl.exe -s --max-time 3 --connect-timeout 2 -X GET "%CP_URL%/api/v1/health" >nul 2>&1
    if %errorlevel% equ 0 (
        echo [+] Remote Control Plane is reachable and healthy.
    ) else (
        echo [!] Warning: Could not reach remote Control Plane at %CP_URL%. Opening browser anyway.
    )
)

set "TARGET_PATH=/inspector"
if /i "%1"=="v2" set "TARGET_PATH=/inspector_v2"
if /i "%1"=="-v2" set "TARGET_PATH=/inspector_v2"
if /i "%1"=="--v2" set "TARGET_PATH=/inspector_v2"

set "ADMIN_TOK="
if exist ".bap-admin-token" (
    set /p ADMIN_TOK=<.bap-admin-token
)
REM The control plane no longer accepts the admin token in a URL (it lands in browser history, proxy
REM and access logs). Open the dashboard without it and paste the token at its admin login prompt.
echo [*] Opening Inspector Dashboard in your default browser (%TARGET_PATH%)...
start %CP_URL%%TARGET_PATH%
if not "%ADMIN_TOK%"=="" (
    echo [*] Admin token is in .bap-admin-token. Paste it at the dashboard's admin login prompt.
)

echo.
echo ===============================================================================
echo   Inspector is LIVE at: %CP_URL%%TARGET_PATH%
echo   (Tip: Run 'start_inspector.bat v2' to launch Inspector V2 Executive Cockpit)
if "%IS_LOCAL%"=="1" (
    echo   To stop local server anytime, run: stop_inspector.bat
)
echo ===============================================================================
endlocal
