# register-nightly-summary.ps1
# Creates a daily scheduled task that runs sysmon-summary.ps1.
# The task is always registered with RunLevel Limited. Reading
# Microsoft-Windows-Sysmon/Operational is granted at install-sysmon
# time by adding the user to Event Log Readers and setting a channel
# ACL (wevtutil sl /ca). Sign out and back in after that grant so the
# Limited task can read the log. This script does not require admin.
#
# Default time is 03:00 local time. The task is StartWhenAvailable, so
# a missed run (laptop off overnight) should start when it next can.
# -DryRun prints the plan without writing the task.
# Remove the task with unregister-nightly-summary.ps1.

[CmdletBinding()]
param(
  [string]$TimeOfDay = "03:00",
  [switch]$AsAdmin,
  [switch]$DryRun,
  [string]$TaskName = "OpenCodeWatch-SysmonSummary",
  [int]$LastHours = 24
)

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "lib\WatchCommon.ps1")

# -AsAdmin is accepted for compatibility but is ignored. The task is
# always Limited so it does not run a user-writable script elevated.
$null = $AsAdmin

$summary = Join-Path $PSScriptRoot "sysmon-summary.ps1"
$plan = Get-SysmonSummaryTaskPlan -TaskName $TaskName -TimeOfDay $TimeOfDay -SummaryPath $summary -LastHours $LastHours

if ($DryRun) {
  Write-Host ("Would register scheduled task '{0}' daily at {1} local time." -f $plan.TaskName, $plan.TimeOfDay)
  Write-Host ("RunLevel: {0}" -f $plan.RunLevel)
  Write-Host ("Log read access: {0}" -f $plan.LogReadMethod)
  Write-Host "This task does not run elevated. install-sysmon.ps1 must have granted Event Log Readers / channel ACL access, and you must have signed out and back in."
  Write-Host "A real run writes nothing else in -DryRun. No task was created."
  return
}

if (-not (Test-IsWindowsOS)) {
  throw "register-nightly-summary.ps1 must run on Windows."
}

if (-not (Test-Path -LiteralPath $summary)) {
  throw "Missing $summary"
}

$psExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
if (-not (Test-Path -LiteralPath $psExe)) {
  throw "Could not find powershell.exe at $psExe"
}

$arg = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -LastHours {1}' -f $summary, $LastHours

$useModule = $false
try {
  $null = Get-Command Register-ScheduledTask -ErrorAction Stop
  $useModule = $true
} catch {
  $useModule = $false
}

if ($useModule) {
  $action = New-ScheduledTaskAction -Execute $psExe -Argument $arg
  $trigger = New-ScheduledTaskTrigger -Daily -At $TimeOfDay
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1)
  $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
} else {
  $tr = '"{0}" {1}' -f $psExe, $arg
  $cmdArgs = @(
    "/Create", "/TN", $TaskName, "/TR", $tr, "/SC", "DAILY", "/ST", $TimeOfDay, "/RL", "LIMITED", "/F"
  )
  $schtasks = Join-Path $env:WINDIR "System32\schtasks.exe"
  $null = Invoke-Native -FilePath $schtasks -ArgumentList $cmdArgs
}

Write-Host ("Registered scheduled task '{0}' daily at {1} local time, RunLevel Limited." -f $TaskName, $TimeOfDay)
Write-Host ("Action: {0} {1}" -f $psExe, $arg)
Write-Host "Reports go under %LOCALAPPDATA%\opencode-watch\reports\."
Write-Host "If sysmon-summary.ps1 cannot read the log, sign out and back in after install-sysmon.ps1 (Event Log Readers membership applies at the next logon)."
Write-Host "Remove the task with unregister-nightly-summary.ps1."
