@echo off
cd /d "%~dp0"
echo ==========================================
echo       NetSage Network Intelligence
echo ==========================================
where py >nul 2>nul
if %errorlevel%==0 (set PY=py) else (set PY=python)
%PY% --version
if errorlevel 1 goto error
%PY% app.py
goto end
:error
echo Python was not found. Install Python 3.10 or newer and select Add Python to PATH.
pause
:end
