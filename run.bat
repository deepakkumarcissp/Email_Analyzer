@echo off
REM DKCISSP Email Analyzer -- one-click launcher (Windows)
REM Double-click this file and it will:
REM   1. Create a private virtual environment on first run (.venv)
REM   2. Install everything needed (first run only -- fast after that)
REM   3. Start the local web UI
REM   4. Open it in your default browser automatically
REM Nothing you paste into the tool ever leaves your machine.

setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo Python 3.9+ is required but was not found.
  echo Install it from https://www.python.org/downloads/ and run this again.
  echo IMPORTANT: on the Python installer, check "Add python.exe to PATH".
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo First-time setup -- this takes a minute...
  python -m venv .venv
  .venv\Scripts\python.exe -m pip install -q --upgrade pip
  .venv\Scripts\python.exe -m pip install -q -e ".[web]"
)

if "%PORT%"=="" set PORT=1008
start "" http://127.0.0.1:%PORT%

echo.
echo DKCISSP Email Analyzer is starting at http://127.0.0.1:%PORT%
echo Leave this window open while you use it. Close it when done.
echo.
.venv\Scripts\dkcissp-email-analyzer-web.exe
pause
