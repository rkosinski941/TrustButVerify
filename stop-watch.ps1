# stop-watch.ps1
# Stops a running watch-opencode.ps1 instance started by start-watch.cmd
# or by watch-opencode.ps1 in continuous mode. No admin required.
# Does not delete logs.

[CmdletBinding()]
param(
  [string]$LogDirectory = ""
)

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "lib\WatchCommon.ps1")

if ([string]::IsNullOrWhiteSpace($LogDirectory)) {
  $LogDirectory = Get-OpenCodeWatchLogDir
}

$pidFile = Join-Path $LogDirectory "watch.pid"
$stopped = $false

if (Test-Path -LiteralPath $pidFile) {
  $oldText = (Get-Content -LiteralPath $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
  $oldPid = 0
  if ($oldText) { [void][int]::TryParse($oldText.Trim(), [ref]$oldPid) }
  if ($oldPid -gt 0) {
    $alive = Get-Process -Id $oldPid -ErrorAction SilentlyContinue
    if ($alive) {
      Write-Host ("Stopping OpenCode watch PID {0} ({1})" -f $oldPid, $alive.ProcessName)
      Stop-Process -Id $oldPid -Force
      $stopped = $true
    } else {
      Write-Host ("PID file named {0}, but that process is not running." -f $oldPid)
    }
  }
  Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
}

# Fallback: find a powershell hosting watch-opencode.ps1
if (-not $stopped) {
  $candidates = @()
  try {
    $candidates = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe' OR Name='powershell' OR Name='pwsh'")
  } catch {
    $candidates = @()
  }
  foreach ($p in $candidates) {
    $cmd = [string]$p.CommandLine
    if ($cmd -and $cmd -match '(?i)watch-opencode\.ps1' -and $cmd -notmatch '(?i)stop-watch') {
      Write-Host ("Stopping PID {0}: {1}" -f $p.ProcessId, (Protect-SecretText $cmd))
      Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
      $stopped = $true
    }
  }
}

if ($stopped) {
  Write-Host "OpenCode watch stopped. Logs were left in place."
} else {
  Write-Host "No running OpenCode watch process was found."
}
