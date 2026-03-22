@echo off
echo === Building Overlord Desktop ===
cd /d "%~dp0Overlord-Desktop"
call npm install
call npm run build:win
echo === Done ===
pause
