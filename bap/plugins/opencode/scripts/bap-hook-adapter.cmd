@echo off
REM BAP Hook Adapter for OpenCode (Windows)
REM Routes OpenCode tool.execute.before / after hooks into bapedge.exe.

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "WORKSPACE_ROOT=%SCRIPT_DIR%..\..\..\"

set "BAPEDGE_BIN="
if defined BAPEDGE_PATH if exist "%BAPEDGE_PATH%" set "BAPEDGE_BIN=%BAPEDGE_PATH%"
if not defined BAPEDGE_BIN if exist "%WORKSPACE_ROOT%bapedge.exe" set "BAPEDGE_BIN=%WORKSPACE_ROOT%bapedge.exe"
if not defined BAPEDGE_BIN if exist "%USERPROFILE%\.bap\bin\bapedge.exe" set "BAPEDGE_BIN=%USERPROFILE%\.bap\bin\bapedge.exe"
if not defined BAPEDGE_BIN set "BAPEDGE_BIN=bapedge.exe"

"%BAPEDGE_BIN%" plugin adapter --client opencode %*
exit /b %ERRORLEVEL%
