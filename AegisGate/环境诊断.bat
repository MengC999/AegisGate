@echo off
setlocal
cd /d "%~dp0"
python --version >nul 2>nul
if errorlevel 1 goto failed
python scripts/environment_check.py
if errorlevel 1 goto failed
python scripts/launch_demo.py --health-check
if not errorlevel 1 goto ok
:failed
echo Python or the local health check failed.
echo Verify Python 3.10+, firewall settings, and the project files.
pause
exit /b 1
:ok
echo.
echo Diagnostics passed. The local web service is available.
pause
exit /b 0

