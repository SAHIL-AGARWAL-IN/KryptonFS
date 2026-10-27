@echo off
rem Double-click or run ".\run.cmd" to start the KryptonFS demo. Options: -Shell, -Dashboard, -Stop
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
if errorlevel 1 pause
