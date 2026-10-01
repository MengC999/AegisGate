@echo off
setlocal
cd /d "%~dp0"
if not exist ".runtime\python\python.exe" (
  echo Please extract the entire ZIP first. The bundled Python runtime is missing.
  pause
  exit /b 1
)
".runtime\python\python.exe" -I -B -X utf8 -u "scripts\launch_demo.py" --runtime-dir "%~dp0runtime" %*
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" (
  echo Start failed. Run check.bat for diagnostics.
  pause
)
exit /b %EXIT_CODE%
