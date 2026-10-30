@echo off
setlocal
cd /d "%~dp0"
title BAP Zero-Trust & Claude Code Live Showcase [v1.9.2]

echo Starting BAP Zero-Trust Interactive Showcase for Crowd Presentation...
echo Target Server: https://bap-controlplane.onrender.com
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tests\demo_claude_bap_showcase.ps1" %*

endlocal
