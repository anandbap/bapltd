@echo off
REM BAP Hook Adapter for Google Antigravity (Windows)
REM Routes Antigravity lifecycle and PreToolUse/PostToolUse hooks into bapedge.exe.

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "WORKSPACE_ROOT=%SCRIPT_DIR%..\..\..\"

set "BAPEDGE_BIN="
if defined BAPEDGE_PATH if exist "%BAPEDGE_PATH%" set "BAPEDGE_BIN=%BAPEDGE_PATH%"
if not defined BAPEDGE_BIN if exist "%WORKSPACE_ROOT%bapedge.exe" set "BAPEDGE_BIN=%WORKSPACE_ROOT%bapedge.exe"
if not defined BAPEDGE_BIN if exist "%USERPROFILE%\.bap\bin\bapedge.exe" set "BAPEDGE_BIN=%USERPROFILE%\.bap\bin\bapedge.exe"
if not defined BAPEDGE_BIN set "BAPEDGE_BIN=bapedge.exe"

"%BAPEDGE_BIN%" plugin adapter --client antigravity %*
exit /b %ERRORLEVEL%
