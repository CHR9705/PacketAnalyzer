@echo off
title PacketAnalyzer - Launcher
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [오류] .venv 가상환경을 찾을 수 없습니다.
    echo        먼저 아래 명령으로 환경을 만들어 주세요:
    echo.
    echo        python -m venv .venv
    echo        .venv\Scripts\pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

echo [1/2] 패킷 캡처 엔진을 관리자 권한으로 시작합니다.
echo       UAC 창이 뜨면 "예"를 눌러 주세요.
powershell -NoProfile -Command "Start-Process -FilePath '%~dp0run_engine.bat' -Verb RunAs"

echo [2/2] 대시보드를 시작합니다.
start "PacketAnalyzer Dashboard" "%~dp0run_dashboard.bat"

echo.
echo 실행 완료. 열린 두 창을 닫으면 각 프로세스가 종료됩니다.
timeout /t 5 >nul
