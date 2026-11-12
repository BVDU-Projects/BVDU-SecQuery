@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\secquery.exe" (
  echo SecQuery is not installed in this folder yet.
  echo Run install.ps1 first, then double-click this launcher again.
  echo.
  pause
  exit /b 2
)

".venv\Scripts\secquery.exe"
set "SCAN_EXIT=%ERRORLEVEL%"
echo.
echo SecQuery finished with exit code %SCAN_EXIT%.
pause
exit /b %SCAN_EXIT%
