@echo off
title SC-200 Master Assessment Backend Server
cls
echo ==========================================================================
echo       Microsoft Security Operations Platform Master Assessment (SC-200)   
echo ==========================================================================
echo.
echo [+] Initializing SC-200 Server...

cd /d "%~dp0"

python server.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [+] Python server failed or not installed. Opening index.html directly...
    start "" index.html
)

pause
