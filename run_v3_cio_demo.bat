@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title BAP Zero-Trust - Agent Watch V3 Executive Demonstration
mode con: cols=105 lines=38
color 0B

echo =========================================================================================================
echo               BOUNDED AUTHORITY PLANE (BAP) - AGENT WATCH V3 EXECUTIVE DEMONSTRATION
echo                       Real-Time Multi-Agent Fleet Governance, Proof & HITL Control
echo =========================================================================================================
echo.
echo  Welcome! This scenario demonstrates the new Agent Watch V3 Executive View:
echo   - Multi-agent live fleet visibility across 5 workstreams (Build, Operate, Analyze, Document, Support)
echo   - Immediate Cedar Zero-Trust prevention of credential harvesting with zero host side effects
echo   - Real-time Human-in-the-Loop (HITL) approval queue with one-click decision resolution
echo   - Cryptographically sealed anti-tamper receipts with verifiable Merkle / SHA-256 integrity
echo   - Instant fleet freeze kill-switch (sub-100ms fleet-wide pause)
echo.

:: 1. Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [-] Python 3 is not found in PATH. Please install Python 3.8+ to run this demo.
    pause
    exit /b 1
)

:: 2. Launch scenario script
python demo_v3_cio.py %*

echo.
echo Demonstration terminated cleanly.
pause
