@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0testnet-start.ps1" %*
set "node_exit_code=%ERRORLEVEL%"
if not "%node_exit_code%"=="0" pause
exit /b %node_exit_code%
