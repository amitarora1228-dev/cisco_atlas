@echo off
REM Capture Inspector - double-click launcher for the server control panel.
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0server-control.ps1"
