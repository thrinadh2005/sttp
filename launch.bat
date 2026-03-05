@echo off
echo ================================================
echo  SPTT - Secure Penetration Testing Toolkit
echo ================================================
echo.
echo Starting Web Interface...
echo.

cd /d "%~dp0"

start python web_app.py

timeout /t 3 /nobreak >nul

start http://localhost:5000

echo.
echo If browser doesn't open automatically, go to:
echo http://localhost:5000
echo.
echo Press Ctrl+C in this window to stop the server
echo.
pause
