# install.ps1
# One-step TrustButVerify setup for the current Windows user.
#
# Default (no admin):
#   1. Merge OpenCode restriction rules into the user's config
#      (%USERPROFILE%\.config\opencode\opencode.jsonc or .json),
#      or create the example config if none exists.
#   2. Register a per-user logon task that starts the no-admin
#      OpenCode watcher, and start the watcher now.
#
# Sysmon is opt-in and needs an elevated window:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -WithSysmon
#
# -DryRun / -WhatIf prints the config diff and planned actions, and
# writes nothing. -NoWatcher skips the watcher task. -NoStart leaves
# the watcher unstarted after registering the task. The watcher runs hidden
# by default; -Visible shows it in a minimized console window and writes
# windowStyle=minimized to trustbutverify.json. If that settings file is
# missing, install creates it from trustbutverify.example.json and will
# not overwrite an existing one.

[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [switch]$WithSysmon,
  [switch]$WithNightlySummary,
  [switch]$NoWatcher,
  [switch]$NoStart,
  [switch]$Visible,
  [string]$ConfigPath = "",
  [string]$ExpectedSha256 = "",
  [string]$ExpectedMd5 = "",
  [switch]$Strict,
  [switch]$TakeOverSysmon,
  [switch]$ClaimFreshKitInstall,
  [string]$ExistingConfigPath = "",
  [switch]$DryRun
)

Set-StrictMode -Version 1
$global:LASTEXITCODE = 0
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "lib\WatchCommon.ps1")
. (Join-Path $PSScriptRoot "lib\MergeOpenCodeConfig.ps1")
. (Join-Path $PSScriptRoot "lib\TbvSettings.ps1")

$skipWrite = $false
if ($DryRun) { $skipWrite = $true }
if ($WhatIfPreference) { $skipWrite = $true }

if ($WithSysmon) { $WithNightlySummary = $true }

Write-Host "TrustButVerify install"
Write-Host "----------------------"

$apply = Join-Path $PSScriptRoot "apply-config.ps1"
$applyArgs = @{
  KitRoot = $PSScriptRoot
}
if ($ConfigPath) { $applyArgs.ConfigPath = $ConfigPath }
if ($ExpectedSha256) { $applyArgs.ExpectedSha256 = $ExpectedSha256 }
if ($ExpectedMd5) { $applyArgs.ExpectedMd5 = $ExpectedMd5 }
if ($Strict) { $applyArgs.Strict = $true }
if ($skipWrite) { $applyArgs.DryRun = $true }

& $apply @applyArgs
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
  throw "apply-config.ps1 failed with exit code $LASTEXITCODE"
}

$taskName = "OpenCodeWatch-Watcher"
$psExe = $null
if ($env:WINDIR) {
  $psExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
}
$watchScript = Join-Path $PSScriptRoot "watch-opencode.ps1"

# Settings file: create once, never overwrite. -Visible updates windowStyle only.
$settingsPath = Get-TbvSettingsPath
if ($skipWrite) {
  if (Test-Path -LiteralPath $settingsPath) {
    Write-Host ("Dry run: would leave existing settings file {0}" -f $settingsPath)
  } else {
    Write-Host ("Dry run: would create {0} from trustbutverify.example.json" -f $settingsPath)
  }
  if ($Visible) {
    Write-Host "Dry run: would set windowStyle to minimized in the settings file."
  }
} else {
  $created = Install-TbvSettingsFileIfMissing -KitRoot $PSScriptRoot -Path $settingsPath
  if ($created.Created) {
    Write-Host ("Created settings file {0}" -f $created.Path)
  } else {
    Write-Host ("Settings file already exists (left unchanged): {0}" -f $created.Path)
  }
  if ($Visible) {
    $upd = Set-TbvSettingsWindowStyle -WindowStyle "minimized" -Path $settingsPath
    if ($upd.Updated) {
      Write-Host "Set windowStyle=minimized in the settings file (-Visible)."
    } else {
      Write-Host ("Did not change windowStyle: {0}" -f $upd.Reason)
    }
  }
}

# Default: hidden. -Visible overrides the file and uses Minimized.
# Note: Windows may still flash a console for a moment at logon when hidden.
$winStyle = "Hidden"
if (-not $skipWrite -and (Test-Path -LiteralPath $settingsPath)) {
  $loaded = Read-TbvSettings -Path $settingsPath
  $winStyle = Get-TbvWindowStyleFromSettings $loaded
}
if ($Visible) { $winStyle = "Minimized" }
$watchArg = '-NoProfile -ExecutionPolicy Bypass -WindowStyle {0} -File "{1}"' -f $winStyle, $watchScript

if (-not $NoWatcher) {
  if ($skipWrite) {
    Write-Host ("Dry run: would register per-user logon task '{0}' to start:" -f $taskName)
    Write-Host ("  {0} {1}" -f $psExe, $watchArg)
  } else {
    if (-not (Test-IsWindowsOS)) {
      throw "install.ps1 can merge configs for a test, but registering the watcher task requires Windows."
    }
    $useModule = $false
    try {
      $null = Get-Command Register-ScheduledTask -ErrorAction Stop
      $useModule = $true
    } catch { $useModule = $false }

    if ($useModule) {
      $action = New-ScheduledTaskAction -Execute $psExe -Argument $watchArg
      $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
      $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
      $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
      Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    } else {
      $tr = '"{0}" {1}' -f $psExe, $watchArg
      $schtasks = Join-Path $env:WINDIR "System32\schtasks.exe"
      $null = Invoke-Native -FilePath $schtasks -ArgumentList @(
        "/Create", "/TN", $taskName, "/TR", $tr, "/SC", "ONLOGON", "/F"
      )
    }
    Write-Host ("Registered per-user logon task '{0}'." -f $taskName)

    if (-not $NoStart) {
      Start-Process -FilePath $psExe -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", $winStyle, "-File", $watchScript) -WindowStyle $winStyle | Out-Null
      Write-Host "Started the OpenCode watcher."
    }
  }
} else {
  Write-Host "Skipped the watcher task (-NoWatcher)."
}

if ($WithSysmon) {
  if ($skipWrite) {
    Write-Host "Dry run: would run install-sysmon.ps1 (needs Administrator; refuses a pre-existing unowned Sysmon unless -TakeOverSysmon or -ClaimFreshKitInstall) and register-nightly-summary.ps1 (RunLevel Limited). Sign out and back in after Sysmon install so Event Log Readers membership applies."
  } else {
    if (-not (Test-IsWindowsOS)) { throw "-WithSysmon requires Windows." }
    $wid = [Security.Principal.WindowsIdentity]::GetCurrent()
    $prin = New-Object Security.Principal.WindowsPrincipal($wid)
    if (-not $prin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
      throw "-WithSysmon must run in an elevated (Run as administrator) PowerShell window."
    }
    $sysArgs = @{}
    if ($TakeOverSysmon) { $sysArgs.TakeOverSysmon = $true }
    if ($ClaimFreshKitInstall) { $sysArgs.ClaimFreshKitInstall = $true }
    if ($ExistingConfigPath) { $sysArgs.ExistingConfigPath = $ExistingConfigPath }
    & (Join-Path $PSScriptRoot "install-sysmon.ps1") @sysArgs
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
      throw "install-sysmon.ps1 failed with exit code $LASTEXITCODE"
    }
    Write-Host "Sign out and back in so Event Log Readers membership applies before the nightly Limited task runs."
  }
} else {
  Write-Host "Sysmon was not installed (opt-in). To add it later, re-run from an elevated prompt with -WithSysmon."
}

if ($WithNightlySummary) {
  if ($skipWrite) {
    Write-Host "Dry run: would run register-nightly-summary.ps1 (RunLevel Limited; no admin). Sign out and back in first if install-sysmon.ps1 just granted Event Log Readers."
  } else {
    $reg = Join-Path $PSScriptRoot "register-nightly-summary.ps1"
    & $reg
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
      throw "register-nightly-summary.ps1 failed with exit code $LASTEXITCODE"
    }
  }
}

Write-Host ""
Write-Host "Live test (do this in OpenCode, do not approve the command):"
Write-Host "  Ask OpenCode to run:  curl.exe http://127.0.0.1:9222/json/list"
Write-Host "  It should be denied by the config. If you get an approval prompt instead, choose reject."
Write-Host ""
Write-Host "Logs and settings go under %LOCALAPPDATA%\opencode-watch\. After editing trustbutverify.json, run reload-watch.cmd. Uninstall with uninstall.ps1."
