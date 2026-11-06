@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\check_stale_copies.ps1" %*
exit /b %ERRORLEVEL%
