@echo off
setlocal
set "KIT=%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%KIT%stop-watch.ps1" %*
endlocal
