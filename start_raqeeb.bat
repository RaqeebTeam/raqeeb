@echo off
title Raqeeb server
cd /d "%~dp0"
echo Starting Raqeeb... keep this window open. Press Ctrl+C to stop.
start "" cmd /c "timeout /t 4 >nul & start http://127.0.0.1:8000"
python -m uvicorn app:app --reload
echo.
echo Server stopped. If you saw an error above, send it to Claude.
pause
