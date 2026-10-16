@echo off
setlocal
set "ROOT_DIR=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT_DIR%scripts\run_adversarial_regression.ps1" %*
exit /b %ERRORLEVEL%
