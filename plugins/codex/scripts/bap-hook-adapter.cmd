@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "PLUGIN_ROOT=%%~fI"

set "BAPEDGE_BIN=bapedge.exe"
if exist "%PLUGIN_ROOT%\..\..\bapedge.exe" (
    set "BAPEDGE_BIN=%PLUGIN_ROOT%\..\..\bapedge.exe"
) else (
    where bapedge.exe >nul 2>nul
    if %ERRORLEVEL% equ 0 (
        set "BAPEDGE_BIN=bapedge.exe"
    )
)

"%BAPEDGE_BIN%" plugin adapter --client codex
exit /b %ERRORLEVEL%
