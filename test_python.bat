@echo off
setlocal
python "%~dp0scripts\run_python_tests.py" %*
exit /b %errorlevel%
