@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title BAP Zero-Trust - 25K Operation Remote Scalability Benchmark
mode con: cols=105 lines=40
color 0B

echo =========================================================================================================
echo               BOUNDED AUTHORITY PLANE (BAP) - 25,000 OPERATION REMOTE SCALING BENCHMARK
echo                       Real-Time Multi-Agent Fleet Scalability & Zero-Loss Verification
echo =========================================================================================================
echo.

:: 1. Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [-] Python 3 is not found in PATH. Please install Python 3.8+ to run this benchmark.
    pause
    exit /b 1
)

:: 2. Launch benchmark script
python scripts\benchmark_25k_scaling.py %*

echo.
echo Benchmark run finished.
pause
