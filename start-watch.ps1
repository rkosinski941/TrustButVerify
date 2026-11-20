# start-watch.ps1
# Starts watch-opencode.ps1 using windowStyle from
# %LOCALAPPDATA%\opencode-watch\trustbutverify.json (hidden by default).
# -Visible overrides that, updates the settings file, and starts minimized.
# Settings are read once here, not in a loop.

[CmdletBinding()]
param(
  [switch]$Visible,
  [switch]$Once
)

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "lib\WatchCommon.ps1")
. (Join-Path $PSScriptRoot "lib\TbvSettings.ps1")

$settingsPath = Get-TbvSettingsPath
$null = Install-TbvSettingsFileIfMissing -KitRoot $PSScriptRoot -Path $settingsPath

if ($Visible) {
  $upd = Set-TbvSettingsWindowStyle -WindowStyle "minimized" -Path $settingsPath
  if (-not $upd.Updated) {
    Write-Host ("Could not update windowStyle in {0}: {1}" -f $settingsPath, $upd.Reason)
  }
}

$loaded = Read-TbvSettings -Path $settingsPath
$style = Get-TbvWindowStyleFromSettings $loaded
if ($Visible) { $style = "Minimized" }

$psExe = "powershell.exe"
if ($env:WINDIR) {
  $cand = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
  if (Test-Path -LiteralPath $cand) { $psExe = $cand }
}
$watch = Join-Path $PSScriptRoot "watch-opencode.ps1"
$argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", $style, "-File", $watch)
if ($Once) { $argList += "-Once" }

Start-Process -FilePath $psExe -ArgumentList $argList -WindowStyle $style | Out-Null
Write-Host ("Started OpenCode watch (windowStyle={0}). Stop it with stop-watch.cmd." -f $style)
