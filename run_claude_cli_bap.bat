@echo off
setlocal EnableExtensions
set "SCRIPT_DIR=%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%run_claude_cli_bap.ps1" %*
exit /b %ERRORLEVEL%
