@echo off
chcp 65001 >nul
cd /d "%~dp0"
python scripts/platform_acceptance.py --strict-baseline
echo.
pause
