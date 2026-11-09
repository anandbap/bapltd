@echo off
setlocal EnableDelayedExpansion

set "ROOT_DIR=%~dp0"
cd /d "%ROOT_DIR%"

for /f "tokens=*" %%i in ('git rev-parse --short HEAD 2^>nul') do set "GIT_COMMIT=%%i"
if "%GIT_COMMIT%"=="" set "GIT_COMMIT=dev"

if "%BAP_VERSION%"=="" (
    for /f "tokens=*" %%v in ('powershell -NoProfile -Command "(Get-Content '%ROOT_DIR%bap-edge\pkg\version\version.go' | Select-String 'Version =').Line.Split([char]34)[1]" 2^>nul') do set "BAP_VERSION=%%v"
)
if "%BAP_VERSION%"=="" (
    for /f "tokens=*" %%v in ('powershell -NoProfile -Command "(Get-Content '%ROOT_DIR%bap-controlplane\pkg\version\version.go' | Select-String 'Version =').Line.Split([char]34)[1]" 2^>nul') do set "BAP_VERSION=%%v"
)
if "%BAP_VERSION%"=="" (
    for /f "tokens=*" %%v in ('powershell -NoProfile -Command "(Get-Content '%ROOT_DIR%pyproject.toml' | Select-String 'version =').Line.Split([char]34)[1]" 2^>nul') do set "BAP_VERSION=%%v"
)
if not "%BAP_VERSION%"=="" if not "%BAP_VERSION:~0,1%"=="v" set "BAP_VERSION=v%BAP_VERSION%"
if "%BAP_VERSION%"=="" set "BAP_VERSION=v1.12.13"

echo ===============================================================================
echo   Bounded Authority Plane (BAP) - Cross-Platform Multi-OS Build
echo   Version: %BAP_VERSION% ^| Commit: %GIT_COMMIT%
echo   Building Windows, Linux (amd64 + arm64), and macOS (Intel + Apple Silicon)
echo ===============================================================================

powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT_DIR%build_all_platforms.ps1" -Version "%BAP_VERSION%" -Archive %*

if %ERRORLEVEL% neq 0 (
    echo [ERROR] Multi-platform compilation failed.
    exit /b %ERRORLEVEL%
)

echo [SUCCESS] Multi-platform build complete for %BAP_VERSION% (%GIT_COMMIT%). Binaries available in dist\
