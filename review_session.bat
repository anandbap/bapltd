@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem ==============================================================================
rem  BAP ZERO-TRUST SESSION REVIEWER & PERFORMANCE INSPECTOR
rem  Windows Batch Wrapper for review_session.ps1
rem
rem  Usage:
rem    review_session.bat           (Interactive session selector)
rem    review_session.bat 1         (View latest session #1 directly)
rem    review_session.bat <session> (View specific session ID)
rem ==============================================================================

set "SCRIPT_DIR=%~dp0"
set "PS1_FILE=%SCRIPT_DIR%review_session.ps1"

if not exist "%PS1_FILE%" (
    set "PS1_FILE=%SCRIPT_DIR%scripts\review_session.ps1"
)

if not exist "%PS1_FILE%" (
    echo [-] Error: review_session.ps1 could not be located in %SCRIPT_DIR% or %SCRIPT_DIR%scripts\
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1_FILE%" %*
exit /b %ERRORLEVEL%
