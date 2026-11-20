# unregister-nightly-summary.ps1
# Removes the nightly Sysmon summary scheduled task created by
# register-nightly-summary.ps1. The task uses RunLevel Limited, so
# admin is not required to remove it.

[CmdletBinding()]
param(
  [string]$TaskName = "OpenCodeWatch-SysmonSummary"
)

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "lib\WatchCommon.ps1")

if (-not (Test-IsWindowsOS)) {
  throw "unregister-nightly-summary.ps1 must run on Windows."
}

$useModule = $false
try {
  $null = Get-Command Unregister-ScheduledTask -ErrorAction Stop
  $useModule = $true
} catch {
  $useModule = $false
}

if ($useModule) {
  $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if (-not $task) {
    Write-Host ("No scheduled task named '{0}' was found." -f $TaskName)
    return
  }
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
  Write-Host ("Removed scheduled task '{0}'." -f $TaskName)
} else {
  $schtasks = Join-Path $env:WINDIR "System32\schtasks.exe"
  $null = Invoke-Native -FilePath $schtasks -ArgumentList @("/Delete", "/TN", $TaskName, "/F")
  Write-Host ("Removed scheduled task '{0}'." -f $TaskName)
}
