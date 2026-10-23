@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title BAP Zero-Trust - Executive CIO Demonstration Launcher
mode con: cols=105 lines=38
color 0B

echo =========================================================================================================
echo               BOUNDED AUTHORITY PLANE (BAP) - EXECUTIVE CIO DEMONSTRATION LAUNCHER
echo                       Real-Time Multi-Agent Fleet Governance, Proof & HITL Control
echo =========================================================================================================
echo.
echo  Welcome! This launcher provides access to the BAP Zero-Trust CIO demonstration suite:
echo   - [Default] Agent Watch V3 Executive Demonstration (Live multi-agent fleet simulation, Cedar policy,
echo               real-time HITL approvals, tamper-proof cryptographic receipts, instant fleet freeze)
echo   - [Workforce] 15 Enterprise Teams / 75 Governed AI Agents concurrent dynamic workloads
echo   - [Remote]    Remote Control Plane CIO Demonstration Engine
echo.

:: 1. Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [-] Python 3 is not found in PATH. Please install Python 3.8+ to run this demo.
    pause
    exit /b 1
)

:: 2. Check if a specific demo scenario was requested
if /i "%~1"=="workforce" goto :RUN_WORKFORCE
if /i "%~1"=="--workforce" goto :RUN_WORKFORCE
if /i "%~1"=="-workforce" goto :RUN_WORKFORCE
if /i "%~1"=="remote" goto :RUN_REMOTE
if /i "%~1"=="--remote" goto :RUN_REMOTE
if /i "%~1"=="-remote" goto :RUN_REMOTE
if /i "%~1"=="v3" goto :RUN_V3
if /i "%~1"=="--v3" goto :RUN_V3

:: Default: Agent Watch V3 Executive Demonstration
:RUN_V3
if /i "%~1"=="v3" shift
if /i "%~1"=="--v3" shift
python demo_v3_cio.py %*
goto :DONE

:RUN_WORKFORCE
shift
python demo_cio_workforce.py %*
goto :DONE

:RUN_REMOTE
shift
python demo_remote_cio.py %*
goto :DONE

:DONE
echo.
echo Demonstration session finished cleanly.
pause
