@echo off
title PacketAnalyzer - Dashboard
cd /d "%~dp0"

echo 대시보드를 시작합니다... 잠시 후 브라우저가 자동으로 열립니다.
echo (종료: Ctrl+C 또는 창 닫기)

REM 서버가 뜰 시간을 준 뒤 브라우저를 연다
start "" cmd /c "timeout /t 4 /nobreak >nul & start http://localhost:8501"

".venv\Scripts\streamlit.exe" run index.py --server.headless true

echo.
echo 대시보드가 종료되었습니다.
pause
