# uninstall-watch.ps1
# Stops the no-admin OpenCode watcher. Does not uninstall Sysmon and does
# not remove the nightly summary task (use uninstall-sysmon.ps1 and
# unregister-nightly-summary.ps1 for those). Logs are kept unless you pass
# -RemoveLogs. -RemoveLogs keeps trustbutverify.json. Pass
# -RemoveSettings to delete the settings file.

[CmdletBinding()]
param(
  [switch]$RemoveLogs,
  [switch]$RemoveSettings,
  [string]$LogDirectory = ""
)

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "lib\WatchCommon.ps1")
. (Join-Path $PSScriptRoot "lib\TbvSettings.ps1")

& (Join-Path $PSScriptRoot "stop-watch.ps1") -LogDirectory $LogDirectory

if ([string]::IsNullOrWhiteSpace($LogDirectory)) {
  $LogDirectory = Get-OpenCodeWatchLogDir
}
$settingsName = Get-TbvSettingsFileName
$settingsPath = Join-Path $LogDirectory $settingsName

if ($RemoveLogs) {
  if (Test-Path -LiteralPath $LogDirectory) {
    Write-Host ("Removing log files under {0} (keeping {1} unless -RemoveSettings)" -f $LogDirectory, $settingsName)
    $items = @(Get-ChildItem -LiteralPath $LogDirectory -Force)
    foreach ($item in $items) {
      if ($item.Name -eq $settingsName) { continue }
      Remove-Item -LiteralPath $item.FullName -Recurse -Force
    }
  } else {
    Write-Host "No log directory to remove."
  }
} else {
  Write-Host "Logs were left in place. Re-run with -RemoveLogs if you want them deleted."
}

if ($RemoveSettings) {
  if (Test-Path -LiteralPath $settingsPath) {
    Remove-Item -LiteralPath $settingsPath -Force
    Write-Host ("Removed settings file {0}" -f $settingsPath)
  } else {
    Write-Host "No settings file to remove."
  }
  if (Test-Path -LiteralPath $LogDirectory) {
    $left = @(Get-ChildItem -LiteralPath $LogDirectory -Force)
    if ($left.Count -eq 0) {
      Remove-Item -LiteralPath $LogDirectory -Force
    }
  }
} elseif (-not $RemoveLogs) {
  Write-Host "Settings file was left in place. Pass -RemoveSettings to delete it."
}
