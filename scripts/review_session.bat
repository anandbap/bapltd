@echo off
setlocal EnableExtensions
set "SCRIPT_DIR=%~dp0"
set "PS1_FILE=%SCRIPT_DIR%review_session.ps1"
if not exist "%PS1_FILE%" (
    set "PS1_FILE=%SCRIPT_DIR%..\review_session.ps1"
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1_FILE%" %*
exit /b %ERRORLEVEL%
