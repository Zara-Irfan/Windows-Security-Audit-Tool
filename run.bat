@echo off
title SentinelScan — Security Dashboard
echo.
echo  ######################################
echo  #   SentinelScan Security Dashboard  #
echo  ######################################
echo.
echo  Starting on http://localhost:8501
echo  Press Ctrl+C to stop.
echo.

cd /d "%~dp0"
python -m streamlit run app.py --server.port 8501 --server.headless false --browser.gatherUsageStats false
pause
