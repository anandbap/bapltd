@echo off
REM ==============================================================================
REM BAP Zero Trust Platform - 10-Pillar Vision Verification Demo Runner
REM ==============================================================================
setlocal enabledelayedexpansion

echo =====================================================================
echo  [BAP ZERO TRUST ARCHITECTURE] 10-Pillar Vision Verification Suite
echo =====================================================================
echo.
echo Launching automated lifecycle demonstration and adversarial verification...
echo.

python "%~dp0scripts\quickstart_vision_demo.py" %*
set EXIT_CODE=%ERRORLEVEL%

if %EXIT_CODE% EQU 0 (
    echo.
    echo =====================================================================
    echo  [SUCCESS] All 10 BAP Zero Trust pillars successfully validated!
    echo =====================================================================
) else (
    echo.
    echo =====================================================================
    echo  [FAILED] Vision demo exited with code %EXIT_CODE%.
    echo =====================================================================
)

exit /b %EXIT_CODE%

