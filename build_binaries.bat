@echo off
setlocal EnableDelayedExpansion

set "ROOT_DIR=%~dp0"
cd /d "%ROOT_DIR%"
set "GOTOOLCHAIN=auto"

if "%1"=="--all" goto :build_all
if "%1"=="-all" goto :build_all
echo [0/6] Ensuring BAP Root CA and TLS credentials...
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT_DIR%scripts\ensure_certs.ps1"
if %ERRORLEVEL% neq 0 (
    echo [WARNING] ensure_certs.ps1 failed, continuing build...
)

echo [1/6] Building bap-controlplane and standalone dashboard...
cd /d "%ROOT_DIR%bap-controlplane"
go build -trimpath -ldflags "-s -w" -o bapcontrolplane.exe ./cmd/server
if %ERRORLEVEL% neq 0 (
    echo Failed to build bapcontrolplane.exe
    exit /b 1
)
copy /y bapcontrolplane.exe "%ROOT_DIR%bapcontrolplane.exe" >nul
go build -trimpath -ldflags "-s -w" -o bapdashboard.exe ./cmd/dashboard
if %ERRORLEVEL% neq 0 (
    echo Failed to build bapdashboard.exe
    exit /b 1
)
copy /y bapdashboard.exe "%ROOT_DIR%bapdashboard.exe" >nul

echo [2/6] Building bap-edge...
cd /d "%ROOT_DIR%bap-edge"
go build -trimpath -ldflags "-s -w" -o bapedge.exe .
if %ERRORLEVEL% neq 0 (
    echo Failed to build bapedge.exe
    exit /b 1
)
copy /y bapedge.exe "%ROOT_DIR%bapedge.exe" >nul 2>&1
copy /y bapedge.exe "%ROOT_DIR%bapmcp.exe" >nul 2>&1

echo [3/6] Building bap-gateway...
cd /d "%ROOT_DIR%bap-gateway"
go build -trimpath -ldflags "-s -w" -o bapgateway.exe .
if %ERRORLEVEL% neq 0 (
    echo Failed to build bapgateway.exe
    exit /b 1
)
copy /y bapgateway.exe "%ROOT_DIR%bapgateway.exe" >nul

echo [4/6] Building cchook (Claude Code interceptor)...
cd /d "%ROOT_DIR%cchook"
go build -trimpath -ldflags "-s -w" -o interceptor.exe interceptor.go
if %ERRORLEVEL% neq 0 (
    echo Failed to build interceptor.exe
    exit /b 1
)

echo [5/6] Building copilot (GitHub Copilot interceptor)...
cd /d "%ROOT_DIR%copilot"
go build -trimpath -ldflags "-s -w" -o copilot_interceptor.exe copilot_interceptor.go
if %ERRORLEVEL% neq 0 (
    echo Failed to build copilot_interceptor.exe
    exit /b 1
)

echo [6/6] Synchronizing Inspector cockpits, dist role packages, and assets...
copy /y "%ROOT_DIR%inspector.html" "%ROOT_DIR%bap-controlplane\inspector.html" >nul
copy /y "%ROOT_DIR%inspector_v2.html" "%ROOT_DIR%bap-controlplane\inspector_v2.html" >nul
for /r "%ROOT_DIR%dist" %%F in (inspector.html) do if exist "%%F" copy /y "%ROOT_DIR%inspector.html" "%%F" >nul 2>&1
for /r "%ROOT_DIR%dist" %%F in (inspector_v2.html) do if exist "%%F" copy /y "%ROOT_DIR%inspector_v2.html" "%%F" >nul 2>&1

if exist "%ROOT_DIR%dist\windows-amd64" (
    copy /y "%ROOT_DIR%bapcontrolplane.exe" "%ROOT_DIR%dist\windows-amd64\bapcontrolplane.exe" >nul 2>&1
    copy /y "%ROOT_DIR%bapedge.exe" "%ROOT_DIR%dist\windows-amd64\bapedge.exe" >nul 2>&1
    copy /y "%ROOT_DIR%bapdashboard.exe" "%ROOT_DIR%dist\windows-amd64\bapdashboard.exe" >nul 2>&1
    copy /y "%ROOT_DIR%bapgateway.exe" "%ROOT_DIR%dist\windows-amd64\bapgateway.exe" >nul 2>&1
    copy /y "%ROOT_DIR%cchook\interceptor.exe" "%ROOT_DIR%dist\windows-amd64\cchook-interceptor.exe" >nul 2>&1
    copy /y "%ROOT_DIR%cchook\interceptor.exe" "%ROOT_DIR%dist\windows-amd64\interceptor.exe" >nul 2>&1
    copy /y "%ROOT_DIR%copilot\copilot_interceptor.exe" "%ROOT_DIR%dist\windows-amd64\copilot-interceptor.exe" >nul 2>&1
)
if exist "%ROOT_DIR%dist\windows-amd64\controlplane" (
    copy /y "%ROOT_DIR%bapcontrolplane.exe" "%ROOT_DIR%dist\windows-amd64\controlplane\bapcontrolplane.exe" >nul 2>&1
)
if exist "%ROOT_DIR%dist\windows-amd64\claude-client" (
    copy /y "%ROOT_DIR%bapedge.exe" "%ROOT_DIR%dist\windows-amd64\claude-client\bapedge.exe" >nul 2>&1
    copy /y "%ROOT_DIR%cchook\interceptor.exe" "%ROOT_DIR%dist\windows-amd64\claude-client\interceptor.exe" >nul 2>&1
    if not exist "%ROOT_DIR%dist\windows-amd64\claude-client\cchook" mkdir "%ROOT_DIR%dist\windows-amd64\claude-client\cchook"
    copy /y "%ROOT_DIR%cchook\interceptor.exe" "%ROOT_DIR%dist\windows-amd64\claude-client\cchook\interceptor.exe" >nul 2>&1
    if exist "%ROOT_DIR%dist\windows-amd64\claude-client\cchook-interceptor.exe" del /f /q "%ROOT_DIR%dist\windows-amd64\claude-client\cchook-interceptor.exe" >nul 2>&1
)
if exist "%ROOT_DIR%dist\windows-amd64\dashboard" (
    copy /y "%ROOT_DIR%bapdashboard.exe" "%ROOT_DIR%dist\windows-amd64\dashboard\bapdashboard.exe" >nul 2>&1
)
if exist "%ROOT_DIR%dist\windows-amd64\gateway" (
    copy /y "%ROOT_DIR%bapgateway.exe" "%ROOT_DIR%dist\windows-amd64\gateway\bapgateway.exe" >nul 2>&1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT_DIR%scripts\check_stale_copies.ps1"
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Stale asset audit detected mismatches!
    exit /b %ERRORLEVEL%
)

echo All Windows binaries built and synchronized successfully.
echo (Tip: Run 'build_binaries.bat --all' or 'build_all_platforms.bat' to build Linux and macOS binaries)
exit /b 0

:build_all
call "%ROOT_DIR%build_all_platforms.bat" %*
exit /b %ERRORLEVEL%
