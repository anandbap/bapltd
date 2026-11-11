@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0watch_session.ps1" %*
exit /b %ERRORLEVEL%
