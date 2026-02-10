@echo off
setlocal ENABLEEXTENSIONS
cd /d "%~dp0"

echo ========================================
echo GuardFlow Launcher
echo ========================================

REM Pick Python launcher if available, otherwise fallback to python.
where py >nul 2>&1
if %ERRORLEVEL%==0 (
  set "PY_CMD=py -3"
) else (
  set "PY_CMD=python"
)

%PY_CMD% --version >nul 2>&1
if not %ERRORLEVEL%==0 (
  echo [ERROR] Python 3 is not installed or not on PATH.
  echo Install Python 3.10+ and re-run this file.
  pause
  exit /b 1
)

REM Optional: try to start local MalwareZoo if Docker is present.
where docker >nul 2>&1
if %ERRORLEVEL%==0 (
  if exist "docker-compose.yml" (
    echo [INFO] Ensuring MalwareZoo container is running...
    docker compose up -d >nul 2>&1
  )
)

echo [INFO] Starting GuardFlow...
%PY_CMD% guardflow_app.py
set "EXITCODE=%ERRORLEVEL%"

if not "%EXITCODE%"=="0" (
  echo.
  echo [ERROR] GuardFlow exited with code %EXITCODE%.
  echo Check the output above, then press any key to close.
  pause >nul
)

endlocal
exit /b %EXITCODE%
