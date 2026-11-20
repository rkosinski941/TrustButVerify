# uninstall.ps1
# Reverses install.ps1 for the current user:
#   - Stops the OpenCode watcher and removes its logon task
#   - Removes the guard plugin (kept as .removed-<stamp>) unless -KeepPlugin;
#     -ForcePluginRemoval removes an edited plugin file too
#   - Restores the latest OpenCode config backup (or removes a config
#     this kit created when none existed)
# Sysmon and the nightly summary task are left in place unless you pass
# -WithSysmon (needs an elevated window). Logs stay unless -RemoveLogs.
# The settings file is left in place unless you pass -RemoveSettings.

[CmdletBinding()]
param(
  [switch]$WithSysmon,
  [switch]$RemoveLogs,
  [switch]$RemoveSettings,
  [string]$ConfigPath = "",
  [string]$BackupPath = "",
  [switch]$KeepPlugin,
  [switch]$ForcePluginRemoval
)

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "lib\WatchCommon.ps1")
. (Join-Path $PSScriptRoot "lib\TbvSettings.ps1")

Write-Host "TrustButVerify uninstall"
Write-Host "------------------------"

$stop = Join-Path $PSScriptRoot "stop-watch.ps1"
if (Test-Path -LiteralPath $stop) {
  & $stop
}

$taskName = "OpenCodeWatch-Watcher"
$removedTask = $false
if (Test-IsWindowsOS) {
  try {
    $null = Get-Command Unregister-ScheduledTask -ErrorAction Stop
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
      Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
      $removedTask = $true
    }
  } catch {
    if ($env:WINDIR) {
      $schtasks = Join-Path $env:WINDIR "System32\schtasks.exe"
      if (Test-Path -LiteralPath $schtasks) {
        try {
          $null = Invoke-Native -FilePath $schtasks -ArgumentList @("/Delete", "/TN", $taskName, "/F")
          $removedTask = $true
        } catch {
          # no such task is fine
        }
      }
    }
  }
}
if ($removedTask) {
  Write-Host ("Removed scheduled task '{0}'." -f $taskName)
} else {
  Write-Host ("No scheduled task named '{0}' was found (that is fine)." -f $taskName)
}

if ($KeepPlugin) {
  Write-Host "Guard plugin left in place (-KeepPlugin)."
} else {
  $upArgs = @{ KitRoot = $PSScriptRoot }
  if ($ConfigPath) { $upArgs.ConfigPath = $ConfigPath }
  if ($ForcePluginRemoval) { $upArgs.Force = $true }
  try {
    & (Join-Path $PSScriptRoot "uninstall-plugin.ps1") @upArgs
  } catch {
    Write-Host ("Guard plugin: {0}" -f $_.Exception.Message)
  }
}

$revert = Join-Path $PSScriptRoot "revert-config.ps1"
$revertArgs = @{ KitRoot = $PSScriptRoot }
if ($ConfigPath) { $revertArgs.ConfigPath = $ConfigPath }
if ($BackupPath) { $revertArgs.BackupPath = $BackupPath }
try {
  & $revert @revertArgs
} catch {
  Write-Host ("Config revert: {0}" -f $_.Exception.Message)
}

if ($WithSysmon) {
  $unreg = Join-Path $PSScriptRoot "unregister-nightly-summary.ps1"
  if (Test-Path -LiteralPath $unreg) {
    try { & $unreg } catch { Write-Host ("Nightly task: {0}" -f $_.Exception.Message) }
  }
  $unsys = Join-Path $PSScriptRoot "uninstall-sysmon.ps1"
  if (Test-Path -LiteralPath $unsys) {
    & $unsys
  }
} else {
  Write-Host "Sysmon and the nightly summary task were left in place. Re-run with -WithSysmon from an elevated prompt to remove them."
}

if ($RemoveLogs) {
  if ($RemoveSettings) {
    & (Join-Path $PSScriptRoot "uninstall-watch.ps1") -RemoveLogs -RemoveSettings
  } else {
    & (Join-Path $PSScriptRoot "uninstall-watch.ps1") -RemoveLogs
  }
} else {
  Write-Host "Logs were left under %LOCALAPPDATA%\opencode-watch\ . Pass -RemoveLogs to delete them."
  if ($RemoveSettings) {
    & (Join-Path $PSScriptRoot "uninstall-watch.ps1") -RemoveSettings
  } else {
    Write-Host "Settings file was left in place. Pass -RemoveSettings to delete trustbutverify.json."
  }
}

Write-Host "Uninstall finished."
