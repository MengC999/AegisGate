@echo off
setlocal
cd /d "%~dp0"
".runtime\python\python.exe" -I -B -X utf8 "scripts\check_portable.py"
set "EXIT_CODE=%ERRORLEVEL%"
if not "%~1"=="--no-pause" pause
exit /b %EXIT_CODE%
