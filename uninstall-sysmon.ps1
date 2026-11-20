# uninstall-sysmon.ps1
# Reverses a TrustButVerify Sysmon install. MUST run in an elevated
# (Run as administrator) PowerShell window.
# - If the ownership marker says this was a kit-fresh install, the
#   Sysmon service and driver are removed.
# - If the marker says this was a takeover, the original Sysmon XML
#   config is restored and Sysmon is left running.
# - If there is no ownership marker, this script refuses to touch
#   Sysmon. It does not delete watch logs.

[CmdletBinding()]
param(
  [switch]$Force,
  [switch]$DryRun
)

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "lib\WatchCommon.ps1")
. (Join-Path $PSScriptRoot "lib\SysmonOwnership.ps1")

$hasMarker = Test-TbvSysmonKitOwned
$kind = ""
$backup = ""
if ($hasMarker) {
  $own = Read-TbvSysmonOwnership
  if ($own -and $own.PSObject.Properties["installKind"]) { $kind = [string]$own.installKind }
  if ($own -and $own.PSObject.Properties["previousConfigBackup"]) { $backup = [string]$own.previousConfigBackup }
}
$plan = Get-TbvSysmonUninstallPlan -HasOwnershipMarker $hasMarker -InstallKind $kind

if ($DryRun) {
  Write-Host ("Would {0}: {1}" -f $plan.Action, $plan.Reason)
  Write-Host ("Allowed: {0}" -f $plan.Allowed)
  if ($backup) { Write-Host ("Previous config backup: {0}" -f $backup) }
  Write-Host "A real run writes nothing else in -DryRun. Sysmon was not changed."
  if (-not $plan.Allowed) { exit 2 }
  return
}

if (-not $plan.Allowed) {
  throw $plan.Reason
}

if (-not (Test-IsWindowsOS)) {
  throw "uninstall-sysmon.ps1 must run on Windows."
}
if (-not (Test-IsAdmin)) {
  throw "uninstall-sysmon.ps1 must run in an elevated (Run as administrator) PowerShell window."
}

$candidates = @(
  (Join-Path $env:WINDIR "Sysmon64.exe"),
  (Join-Path $env:WINDIR "Sysmon64a.exe"),
  (Join-Path $env:WINDIR "Sysmon.exe")
)
$logDir = Get-OpenCodeWatchLogDir
$dist = Join-Path $logDir "sysmon-dist\extracted"
if (Test-Path -LiteralPath $dist) {
  $candidates += @(
    (Join-Path $dist "Sysmon64.exe"),
    (Join-Path $dist "Sysmon64a.exe"),
    (Join-Path $dist "Sysmon.exe")
  )
}

$exe = $null
foreach ($c in $candidates) {
  if ($c -and (Test-Path -LiteralPath $c)) { $exe = $c; break }
}
if (-not $exe) {
  throw "Could not find Sysmon64.exe or Sysmon.exe. If Sysmon is already gone, remove the ownership marker under %ProgramData%\\opencode-watch\\sysmon\\ if it is stale."
}

if ($plan.Action -eq "restore-previous") {
  if ([string]::IsNullOrWhiteSpace($backup) -or -not (Test-Path -LiteralPath $backup)) {
    throw "This was a kit takeover, but the restorable previous Sysmon XML backup is missing. Refusing to uninstall or overwrite. Look under %ProgramData%\\opencode-watch\\sysmon\\backup\\."
  }
  Write-Host ("Restoring previous Sysmon config from {0}" -f $backup)
  $null = Invoke-Native -FilePath $exe -ArgumentList @("-c", $backup)
  Write-Host "Original Sysmon configuration restored. The Sysmon service was left running."
  Remove-TbvSysmonOwnership
  Write-Host "Removed the TrustButVerify Sysmon ownership marker."
  return
}

Write-Host ("Uninstalling Sysmon with {0}" -f $exe)
if ($Force) {
  $null = Invoke-Native -FilePath $exe -ArgumentList @("-u", "force")
} else {
  $null = Invoke-Native -FilePath $exe -ArgumentList @("-u")
}

$svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $svc) { $svc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }
if ($svc) {
  Write-Host ("Service {0} is still present (status {1}). Try again with -Force." -f $svc.Name, $svc.Status)
} else {
  Remove-TbvSysmonOwnership
  Write-Host "Sysmon service removed. Watch logs were left in place. The ownership marker was removed."
}
