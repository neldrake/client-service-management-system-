@echo off
setlocal EnableExtensions
cd /d "%~dp0"

where py >nul 2>nul
if not errorlevel 1 (
  py -3 server.py serve
  if errorlevel 1 (
    echo.
    echo The CSU server could not start.
    pause
  )
  exit /b
)

where python >nul 2>nul
if errorlevel 1 (
  echo Python 3 is required. Install Python, then run this file again.
  pause
  exit /b 1
)

python server.py serve
if errorlevel 1 (
  echo.
  echo The CSU server could not start.
  pause
  exit /b 1
)
