@echo off
setlocal
where bapedge.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    bapedge.exe plugin adapter --client copilot %*
    exit /b %ERRORLEVEL%
)

if exist "%~dp0..\..\..\bapedge.exe" (
    "%~dp0..\..\..\bapedge.exe" plugin adapter --client copilot %*
    exit /b %ERRORLEVEL%
)

if exist "%~dp0..\..\..\copilot\copilot_interceptor.exe" (
    "%~dp0..\..\..\copilot\copilot_interceptor.exe" %*
    exit /b %ERRORLEVEL%
)

echo {"allowed":false,"reason":"bapedge execution broker binary not found"}
exit /b 1
