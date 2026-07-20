@echo off
title PacketAnalyzer - Engine (관리자)
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
    echo [경고] 관리자 권한이 아닙니다. 패킷 캡처가 실패할 수 있습니다.
    echo         start_all.bat 으로 실행하거나, 이 파일을 우클릭 - "관리자 권한으로 실행" 하세요.
    echo.
)

echo 패킷 캡처 엔진을 시작합니다... (종료: Ctrl+C 또는 창 닫기)
".venv\Scripts\python.exe" main.py

echo.
echo 엔진이 종료되었습니다.
pause
