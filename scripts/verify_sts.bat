@echo off
setlocal
python "%~dp0verify_sts_obo_exchange.py" %*
exit /b %ERRORLEVEL%
