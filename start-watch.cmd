@echo off
setlocal
rem Start the no-admin OpenCode watcher. Window style comes from
rem %LOCALAPPDATA%\opencode-watch\trustbutverify.json (hidden by default).
rem Pass -Visible to show a minimized window and save that setting.
set "KIT=%~dp0"
if not exist "%LOCALAPPDATA%\opencode-watch" mkdir "%LOCALAPPDATA%\opencode-watch"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%KIT%start-watch.ps1" %*
endlocal
