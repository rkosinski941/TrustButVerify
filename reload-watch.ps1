# reload-watch.ps1
# Tells a running watch-opencode.ps1 to re-read
# %LOCALAPPDATA%\opencode-watch\trustbutverify.json.
# Signals the named event Local\TrustButVerify-Reload. The watcher
# checks that event in its existing loop (no per-poll file I/O).
# If the watcher is not running, the signal is harmless.

[CmdletBinding()]
param()

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "lib\WatchCommon.ps1")
. (Join-Path $PSScriptRoot "lib\TbvSettings.ps1")

$name = Get-TbvReloadEventName
try {
  $ev = New-Object System.Threading.EventWaitHandle($false, [System.Threading.EventResetMode]::AutoReset, $name)
  try {
    [void]$ev.Set()
  } finally {
    $ev.Dispose()
  }
} catch {
  throw ("Could not signal {0}: {1}" -f $name, $_.Exception.Message)
}

Write-Host ("Signaled the OpenCode watcher to reload settings ({0})." -f $name)
Write-Host "If it is running, it will log 'settings reloaded'. If it is not running, start it with start-watch.cmd; it will read the file once at startup."
