@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" scripts/launch_demo.py %*
) else (
  python scripts/launch_demo.py %*
)
if errorlevel 1 (
  echo Install Python and requirements.txt first. See README.md.
  pause
  exit /b 1
)
