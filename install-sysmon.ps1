# install-sysmon.ps1
# Downloads official Sysmon, verifies a Microsoft Authenticode signature,
# and installs sysmon-opencode.xml. MUST run in an elevated
# (Run as administrator) PowerShell window, except -DryRun.
# Accepts the Sysinternals EULA by passing -accepteula to Sysmon.
#
# If Sysmon is already installed and this kit does not own it, the
# script refuses unless you pass -TakeOverSysmon with -ExistingConfigPath
# (a restorable Sysmon XML file; a sysmon -c text dump is not enough),
# or -ClaimFreshKitInstall if this kit installed Sysmon earlier, before
# ownership markers existed.
#
# After a successful install or update, this script grants the current
# user Event Log Readers membership and adds a read ACE on
# Microsoft-Windows-Sysmon/Operational (wevtutil sl /ca). Sign out and
# back in so the group membership applies. The nightly summary task
# then runs as RunLevel Limited and does not need admin.
#
# The only network call is a download of
# https://download.sysinternals.com/files/Sysmon.zip
#
# Usage:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install-sysmon.ps1

[CmdletBinding()]
param(
  [string]$ConfigPath = "",
  [string]$DownloadDir = "",
  [switch]$SkipDownload,
  [switch]$TakeOverSysmon,
  [switch]$ClaimFreshKitInstall,
  [string]$ExistingConfigPath = "",
  [switch]$DryRun
)

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "lib\WatchCommon.ps1")
. (Join-Path $PSScriptRoot "lib\SysmonOwnership.ps1")

function Get-ExistingSysmonExe {
  $candidates = @(
    (Join-Path $env:WINDIR "Sysmon64.exe"),
    (Join-Path $env:WINDIR "Sysmon.exe"),
    (Join-Path $env:WINDIR "Sysmon64a.exe")
  )
  foreach ($c in $candidates) {
    if ($c -and (Test-Path -LiteralPath $c)) { return $c }
  }
  $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
  if (-not $svc) { $svc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }
  if ($svc) { return $true }
  return $null
}

function Get-SysmonExeFromDist {
  param([string]$ExtractDir)
  $arch = [string]$env:PROCESSOR_ARCHITECTURE
  $preferred = @()
  if ($arch -eq "ARM64") {
    $preferred = @("Sysmon64a.exe", "Sysmon64.exe", "Sysmon.exe")
  } elseif ($arch -eq "AMD64" -or $arch -eq "x64") {
    $preferred = @("Sysmon64.exe", "Sysmon.exe")
  } else {
    $preferred = @("Sysmon.exe", "Sysmon64.exe")
  }
  foreach ($name in $preferred) {
    $path = Join-Path $ExtractDir $name
    if (Test-Path -LiteralPath $path) { return $path }
  }
  throw ("No Sysmon exe found under {0}. Looked for: {1}" -f $ExtractDir, ($preferred -join ", "))
}

function Grant-TbvSysmonLogReadAccess {
  param([string]$UserSid)
  $channel = Get-SysmonOperationalChannelName
  $wevt = Join-Path $env:WINDIR "System32\wevtutil.exe"
  if (-not (Test-Path -LiteralPath $wevt)) {
    throw "wevtutil.exe was not found; cannot set the Sysmon channel ACL."
  }
  $gl = Invoke-Native -FilePath $wevt -ArgumentList @("gl", $channel)
  $current = Get-ChannelAccessFromWevtutil -Text ($gl -join "`n")
  if ([string]::IsNullOrWhiteSpace($current)) {
    throw "Could not read the current Sysmon channelAccess SDDL from wevtutil."
  }
  $plan = Build-SysmonChannelAccessSddl -CurrentSddl $current -UserSid $UserSid
  if ($plan.Changed) {
    $null = Invoke-Native -FilePath $wevt -ArgumentList @("sl", $channel, ("/ca:{0}" -f $plan.Sddl))
    Write-Host "Updated Microsoft-Windows-Sysmon/Operational channel ACL to allow Event Log Readers (and this user) to read the log."
  } else {
    Write-Host "Sysmon channel ACL already allows Event Log Readers (and this user) to read the log."
  }

  try {
    $sidObj = New-Object System.Security.Principal.SecurityIdentifier $UserSid
    $nt = $sidObj.Translate([System.Security.Principal.NTAccount])
    $member = [string]$nt.Value
    $added = $false
    try {
      Add-LocalGroupMember -SID (Get-EventLogReadersSid) -Member $member -ErrorAction Stop
      $added = $true
    } catch {
      $msg = [string]$_.Exception.Message
      if ($msg -match '(?i)already a member|already exists') {
        Write-Host ("User {0} is already in Event Log Readers." -f $member)
      } else {
        throw
      }
    }
    if ($added) {
      Write-Host ("Added {0} to Event Log Readers." -f $member)
    }
  } catch {
    throw ("Could not add this user to Event Log Readers: {0}" -f $_.Exception.Message)
  }
  Write-Host "Sign out and back in so Event Log Readers membership applies to new logons (including the nightly Limited task)."
}

$alreadyInstalled = $false
$existingExe = $null
$hasMarker = $false
$markerKind = ""
if (Test-IsWindowsOS) {
  if (Get-Command Get-Service -ErrorAction SilentlyContinue) {
    $existing = Get-ExistingSysmonExe
    if ($existing -is [string]) {
      $alreadyInstalled = $true
      $existingExe = $existing
    } elseif ($existing) {
      $alreadyInstalled = $true
    }
  }
}
if (Test-TbvSysmonKitOwned) {
  $hasMarker = $true
  $own = Read-TbvSysmonOwnership
  if ($own -and $own.PSObject.Properties["installKind"]) {
    $markerKind = [string]$own.installKind
  }
}

$plan = Get-TbvSysmonInstallPlan -AlreadyInstalled $alreadyInstalled -HasOwnershipMarker $hasMarker -InstallKind $markerKind -TakeOverSysmon:$TakeOverSysmon -ClaimFreshKitInstall:$ClaimFreshKitInstall -ExistingConfigPath $ExistingConfigPath

if ($DryRun) {
  Write-Host ("Would {0}: {1}" -f $plan.Action, $plan.Reason)
  Write-Host ("Allowed: {0}" -f $plan.Allowed)
  Write-Host ("Ownership kind: {0}" -f $plan.InstallKind)
  Write-Host ("Nightly task RunLevel: {0}" -f $plan.RunLevelForTask)
  Write-Host ("Log read access: {0}" -f $plan.LogReadMethod)
  Write-Host "A real run writes nothing else in -DryRun. No Sysmon or ACL changes were made."
  if (-not $plan.Allowed) { exit 2 }
  return
}

if (-not $plan.Allowed) {
  throw $plan.Reason
}

if (-not (Test-IsWindowsOS)) {
  throw "install-sysmon.ps1 must run on Windows."
}
if (-not (Test-IsAdmin)) {
  throw "install-sysmon.ps1 must run in an elevated (Run as administrator) PowerShell window."
}

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
  $ConfigPath = Join-Path $PSScriptRoot "sysmon-opencode.xml"
}
if (-not (Test-Path -LiteralPath $ConfigPath)) {
  throw "Sysmon config not found: $ConfigPath"
}

$previousBackup = ""
if ($plan.NeedsConfigBackup) {
  $previousBackup = Copy-TbvRestorableSysmonConfig -ExistingConfigPath $ExistingConfigPath
  Write-Host ("Saved restorable previous Sysmon config: {0}" -f $previousBackup)
}

$logDir = Ensure-OpenCodeWatchLogDir
if ([string]::IsNullOrWhiteSpace($DownloadDir)) {
  $DownloadDir = Join-Path $logDir "sysmon-dist"
}
if (-not (Test-Path -LiteralPath $DownloadDir)) {
  New-Item -ItemType Directory -Force -Path $DownloadDir | Out-Null
}

$zipUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$zipPath = Join-Path $DownloadDir "Sysmon.zip"
$extractDir = Join-Path $DownloadDir "extracted"

if ($plan.Action -eq "claim-fresh") {
  Write-Host $plan.Reason
} elseif (-not $SkipDownload) {
  Write-Host ("Downloading {0}" -f $zipUrl)
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
} elseif (-not (Test-Path -LiteralPath $zipPath)) {
  if ($plan.Action -eq "install-fresh" -or $plan.Action -eq "update-kit-owned" -or $plan.Action -eq "takeover") {
    throw "SkipDownload was set but $zipPath does not exist."
  }
}

$configSha = Get-FileHashHex -Path $ConfigPath -Algorithm SHA256
Write-Host ("Config SHA256     {0}" -f $configSha)
if (Test-Path -LiteralPath $zipPath) {
  Write-Host ("Sysmon.zip SHA256 {0}" -f (Get-FileHashHex -Path $zipPath -Algorithm SHA256))
}

$sysmonExe = $null
if (Test-Path -LiteralPath $zipPath) {
  if (Test-Path -LiteralPath $extractDir) {
    Remove-Item -LiteralPath $extractDir -Recurse -Force
  }
  New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
  Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir -Force
  $sysmonExe = Get-SysmonExeFromDist -ExtractDir $extractDir
  Write-Host ("Using {0}" -f $sysmonExe)
  Write-Host ("Sysmon exe SHA256 {0}" -f (Get-FileHashHex -Path $sysmonExe -Algorithm SHA256))
  Write-Host "Verifying Microsoft Authenticode signature..."
  $sig = Test-AuthenticodeMicrosoft -Path $sysmonExe
  $subject = ""
  if ($sig.SignerCertificate) { $subject = [string]$sig.SignerCertificate.Subject }
  Write-Host ("Signature Valid. Subject: {0}" -f $subject)
}

$dumpExe = $existingExe
if (-not $dumpExe) { $dumpExe = $sysmonExe }
if (-not $dumpExe) {
  throw "Could not find a Sysmon executable to install or update with."
}

if ($plan.Action -eq "install-fresh") {
  Write-Host "Installing Sysmon (this accepts the Sysinternals EULA)..."
  $null = Invoke-Native -FilePath $sysmonExe -ArgumentList @("-accepteula", "-i", $ConfigPath)
  Write-Host "Sysmon installed."
} elseif ($plan.Action -eq "claim-fresh") {
  Write-Host "Recording kit ownership of the existing Sysmon install and re-applying the kit config..."
  $null = Invoke-Native -FilePath $dumpExe -ArgumentList @("-c", $ConfigPath)
  Write-Host "Sysmon configuration updated."
} else {
  Write-Host "Updating Sysmon configuration..."
  $null = Invoke-Native -FilePath $dumpExe -ArgumentList @("-c", $ConfigPath)
  Write-Host "Sysmon configuration updated."
}

$ownKind = $plan.InstallKind
if ([string]::IsNullOrWhiteSpace($ownKind)) { $ownKind = "fresh" }
$markerPath = Write-TbvSysmonOwnership -InstallKind $ownKind -ConfigSha256 $configSha -PreviousConfigBackup $previousBackup
Write-Host ("Wrote ownership marker {0}" -f $markerPath)

$svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $svc) { $svc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }
if ($svc) {
  Write-Host ("Service {0} status: {1}" -f $svc.Name, $svc.Status)
} else {
  Write-Host "Install finished, but the Sysmon service was not found. Check the output above."
}

$userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Grant-TbvSysmonLogReadAccess -UserSid $userSid

Write-Host "Done. Events go to Applications and Services Logs / Microsoft / Windows / Sysmon / Operational."
Write-Host "After you sign out and back in, read events with sysmon-summary.ps1 (no admin). Register the nightly task with register-nightly-summary.ps1 (RunLevel Limited)."
