@echo off
setlocal
:: GitHub Copilot Terminal Execution Wrapper for Windows
:: Routes Copilot commands through bapedge (LTD - Local Trusted Daemon) with Cedar security policies

set "SCRIPT_DIR=%~dp0"
if exist "%SCRIPT_DIR%copilot_interceptor.exe" (
    "%SCRIPT_DIR%copilot_interceptor.exe" %*
) else if exist "%SCRIPT_DIR%bapedge.exe" (
    "%SCRIPT_DIR%bapedge.exe" exec --source copilot --raw %*
) else if exist "%SCRIPT_DIR%..\bap-edge\bapedge.exe" (
    "%SCRIPT_DIR%..\bap-edge\bapedge.exe" exec --source copilot --raw %*
) else if exist "%SCRIPT_DIR%..\ltd-agent\bapedge.exe" (
    "%SCRIPT_DIR%..\ltd-agent\bapedge.exe" exec --source copilot --raw %*
) else if exist "%SCRIPT_DIR%..\ltd-agent\ltd-agent.exe" (
    "%SCRIPT_DIR%..\ltd-agent\ltd-agent.exe" exec --source copilot --raw %*
) else (
    bapedge.exe exec --source copilot --raw %*
)
exit /b %ERRORLEVEL%
