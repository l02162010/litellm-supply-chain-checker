@echo off
:: Double-click this file on Windows to run the checker in PowerShell.
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0check_litellm.ps1"
pause
