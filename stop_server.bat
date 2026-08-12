@echo off
title Stop SC-200 Server
cls
echo ==========================================================================
echo               Stopping SC-200 Master Assessment Server                    
echo ==========================================================================
echo.
echo [+] Searching for process running on port 8080...

for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8080 ^| findstr LISTENING') do (
    echo [+] Terminating process PID %%a listening on port 8080...
    taskkill /F /PID %%a
)

echo.
echo [+] SC-200 Server closed successfully.
pause
