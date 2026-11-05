@echo off
setlocal
where bapedge.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    bapedge.exe plugin adapter %*
    exit /b %ERRORLEVEL%
)

if exist "%~dp0..\..\..\bapedge.exe" (
    "%~dp0..\..\..\bapedge.exe" plugin adapter %*
    exit /b %ERRORLEVEL%
)

if exist "%~dp0..\..\..\cchook-interceptor.exe" (
    "%~dp0..\..\..\cchook-interceptor.exe" %*
    exit /b %ERRORLEVEL%
)

if exist "%~dp0..\..\..\cchook\interceptor.exe" (
    "%~dp0..\..\..\cchook\interceptor.exe" %*
    exit /b %ERRORLEVEL%
)

echo {"status":"deny","reason":"bapedge execution broker binary not found"}
exit /b 1
