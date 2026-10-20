@echo off
setlocal
set "ROOT_DIR=%~dp0"
cd /d "%ROOT_DIR%"
echo [*] Building BAP Python Wheel (.whl) with embedded Go binaries...
python "%ROOT_DIR%scripts\build_wheel.py" %*
exit /b %ERRORLEVEL%
