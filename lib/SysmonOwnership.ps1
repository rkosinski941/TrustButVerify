# SysmonOwnership.ps1
# Helpers for TrustButVerify Sysmon ownership, restorable config
# backups, and Sysmon/Operational log read access (Event Log Readers
# plus a one-time channel ACL). ASCII only. Dot-source after
# WatchCommon.ps1. These functions do not install or uninstall Sysmon.

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

function Get-TbvProgramDataRoot {
  param([string]$OverrideRoot = "")
  if (-not [string]::IsNullOrWhiteSpace($OverrideRoot)) {
    return $OverrideRoot
  }
  if (-not [string]::IsNullOrWhiteSpace($env:TBV_PROGRAMDATA)) {
    return (Join-Path $env:TBV_PROGRAMDATA "opencode-watch")
  }
  if (-not [string]::IsNullOrWhiteSpace($env:ProgramData)) {
    return (Join-Path $env:ProgramData "opencode-watch")
  }
  return (Join-Path (Get-OpenCodeWatchLogDir) "programdata")
}

function Get-TbvSysmonStateDir {
  param([string]$OverrideRoot = "")
  return (Join-Path (Get-TbvProgramDataRoot -OverrideRoot $OverrideRoot) "sysmon")
}

function Get-TbvSysmonOwnershipPath {
  param([string]$OverrideRoot = "")
  return (Join-Path (Get-TbvSysmonStateDir -OverrideRoot $OverrideRoot) "ownership.json")
}

function Get-TbvSysmonBackupDir {
  param([string]$OverrideRoot = "")
  return (Join-Path (Get-TbvSysmonStateDir -OverrideRoot $OverrideRoot) "backup")
}

function Get-EventLogReadersSid {
  return "S-1-5-32-573"
}

function Get-SysmonOperationalChannelName {
  return "Microsoft-Windows-Sysmon/Operational"
}

function New-EventLogReadAce {
  param([string]$Sid)
  if ([string]::IsNullOrWhiteSpace($Sid)) {
    throw "A SID is required for an event-log read ACE."
  }
  return ("(A;;0x1;;;{0})" -f $Sid.Trim())
}

function Get-ChannelAccessFromWevtutil {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
  foreach ($line in ($Text -split "`r?`n")) {
    if ($line -match '(?i)^\s*channelAccess:\s*(.*)\s*$') {
      return $Matches[1].Trim()
    }
  }
  return ""
}

function Add-SddlAceIfMissing {
  param(
    [string]$Sddl,
    [string]$Ace
  )
  if ([string]::IsNullOrWhiteSpace($Ace)) {
    return [pscustomobject]@{ Sddl = [string]$Sddl; Changed = $false }
  }
  $current = ""
  if ($Sddl) { $current = [string]$Sddl }
  if ($current.IndexOf($Ace, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
    return [pscustomobject]@{ Sddl = $current; Changed = $false }
  }
  if ([string]::IsNullOrWhiteSpace($current)) {
    return [pscustomobject]@{ Sddl = ("D:" + $Ace); Changed = $true }
  }
  $dAt = $current.IndexOf("D:")
  if ($dAt -lt 0) {
    return [pscustomobject]@{ Sddl = ($current + "D:" + $Ace); Changed = $true }
  }
  # After D:, skip flags, then skip each (ACE), then insert before a
  # following SACL (S:...) or at the end.
  $i = $dAt + 2
  while ($i -lt $current.Length) {
    if ($current[$i] -eq [char]"(") { break }
    if (($i + 1) -lt $current.Length -and $current.Substring($i, 2) -eq "S:") { break }
    $i++
  }
  while ($i -lt $current.Length -and $current[$i] -eq [char]"(") {
    $depth = 0
    while ($i -lt $current.Length) {
      if ($current[$i] -eq [char]"(") { $depth++ }
      elseif ($current[$i] -eq [char]")") { $depth-- }
      $i++
      if ($depth -le 0) { break }
    }
  }
  $newSddl = $current.Substring(0, $i) + $Ace + $current.Substring($i)
  return [pscustomobject]@{ Sddl = $newSddl; Changed = $true }
}

function Build-SysmonChannelAccessSddl {
  # Ensures Event Log Readers, and optionally a specific user SID, can
  # read the Sysmon operational channel. Does not remove existing ACEs.
  param(
    [string]$CurrentSddl,
    [string]$UserSid = ""
  )
  $sddl = [string]$CurrentSddl
  $changed = $false
  $readers = Add-SddlAceIfMissing -Sddl $sddl -Ace (New-EventLogReadAce -Sid (Get-EventLogReadersSid))
  $sddl = [string]$readers.Sddl
  if ($readers.Changed) { $changed = $true }
  if (-not [string]::IsNullOrWhiteSpace($UserSid)) {
    $user = Add-SddlAceIfMissing -Sddl $sddl -Ace (New-EventLogReadAce -Sid $UserSid)
    $sddl = [string]$user.Sddl
    if ($user.Changed) { $changed = $true }
  }
  return [pscustomobject]@{
    Sddl    = $sddl
    Changed = $changed
  }
}

function Get-TbvSysmonInstallPlan {
  # Pure decision helper used by install-sysmon.ps1 and tests.
  param(
    [bool]$AlreadyInstalled,
    [bool]$HasOwnershipMarker,
    [string]$InstallKind = "",
    [switch]$TakeOverSysmon,
    [switch]$ClaimFreshKitInstall,
    [string]$ExistingConfigPath = ""
  )
  $action = "install-fresh"
  $reason = "No Sysmon service is present. The kit will install Sysmon and record ownership."
  $allowed = $true
  $kind = "fresh"
  $needsBackup = $false

  if ($AlreadyInstalled -and $HasOwnershipMarker) {
    $action = "update-kit-owned"
    $kind = $InstallKind
    if ([string]::IsNullOrWhiteSpace($kind)) { $kind = "fresh" }
    $reason = "Sysmon is already owned by this kit. The kit config can be re-applied."
  } elseif ($AlreadyInstalled) {
    if ($ClaimFreshKitInstall) {
      $action = "claim-fresh"
      $kind = "fresh"
      $reason = "Sysmon is present with no ownership marker. -ClaimFreshKitInstall records it as a kit-fresh install (use only if this kit installed it earlier)."
    } elseif ($TakeOverSysmon) {
      if ([string]::IsNullOrWhiteSpace($ExistingConfigPath)) {
        $action = "refuse"
        $allowed = $false
        $kind = ""
        $reason = "Sysmon is already installed and is not marked as kit-owned. -TakeOverSysmon requires -ExistingConfigPath pointing at a restorable Sysmon XML config. A sysmon -c text dump is not enough."
      } else {
        $action = "takeover"
        $kind = "takeover"
        $needsBackup = $true
        $reason = "Sysmon is already installed. -TakeOverSysmon will copy the provided config, apply the kit config, and record ownership."
      }
    } else {
      $action = "refuse"
      $allowed = $false
      $kind = ""
      $reason = "Sysmon is already installed and is not marked as kit-owned. Refusing to take it over. Re-run with -TakeOverSysmon -ExistingConfigPath <original.xml> if you have a restorable XML backup, or -ClaimFreshKitInstall if this kit installed Sysmon earlier (before ownership markers existed)."
    }
  }

  return [pscustomobject]@{
    Allowed           = $allowed
    Action            = $action
    InstallKind       = $kind
    NeedsConfigBackup = $needsBackup
    Reason            = $reason
    RunLevelForTask   = "Limited"
    LogReadMethod     = "Event Log Readers and a Sysmon channel ACL (wevtutil sl /ca). Sign out and back in after install so group membership applies."
  }
}

function Get-TbvSysmonUninstallPlan {
  param(
    [bool]$HasOwnershipMarker,
    [string]$InstallKind = ""
  )
  if (-not $HasOwnershipMarker) {
    return [pscustomobject]@{
      Allowed = $false
      Action  = "refuse"
      Reason  = "No TrustButVerify Sysmon ownership marker was found. Refusing to remove or reconfigure a Sysmon install this kit does not own."
    }
  }
  if ($InstallKind -eq "takeover") {
    return [pscustomobject]@{
      Allowed = $true
      Action  = "restore-previous"
      Reason  = "Kit-owned takeover: restore the original Sysmon XML config and leave the Sysmon service running."
    }
  }
  return [pscustomobject]@{
    Allowed = $true
    Action  = "uninstall"
    Reason  = "Kit-owned fresh install: remove the Sysmon service and driver."
  }
}

function ConvertTo-TbvOwnershipJson {
  param($Object)
  $map = New-Object System.Collections.Specialized.OrderedDictionary
  foreach ($name in @("schema", "ownedBy", "installKind", "installedUtc", "configSha256", "previousConfigBackup")) {
    $val = ""
    if ($Object -is [System.Collections.IDictionary]) {
      if ($Object.Contains($name)) { $val = [string]$Object[$name] }
    } elseif ($Object.PSObject.Properties[$name]) {
      $val = [string]$Object.PSObject.Properties[$name].Value
    }
    $map[$name] = $val
  }
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine("{")
  $keys = @($map.Keys)
  for ($i = 0; $i -lt $keys.Count; $i++) {
    $k = $keys[$i]
    $v = [string]$map[$k]
    $escaped = $v.Replace("\", "\\").Replace('"', '\"')
    $comma = ","
    if ($i -eq ($keys.Count - 1)) { $comma = "" }
    if ([string]::IsNullOrEmpty($v)) {
      [void]$sb.AppendLine(('  "{0}": null{1}' -f $k, $comma))
    } else {
      [void]$sb.AppendLine(('  "{0}": "{1}"{2}' -f $k, $escaped, $comma))
    }
  }
  [void]$sb.Append("}")
  return $sb.ToString()
}

function Write-TbvSysmonOwnership {
  param(
    [string]$InstallKind,
    [string]$ConfigSha256 = "",
    [string]$PreviousConfigBackup = "",
    [string]$OverrideRoot = ""
  )
  $dir = Get-TbvSysmonStateDir -OverrideRoot $OverrideRoot
  if (-not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
  }
  $path = Get-TbvSysmonOwnershipPath -OverrideRoot $OverrideRoot
  $obj = [ordered]@{
    schema                = "tbv-sysmon-ownership-v1"
    ownedBy               = "TrustButVerify"
    installKind           = $InstallKind
    installedUtc          = (Get-Date).ToUniversalTime().ToString("o")
    configSha256          = $ConfigSha256
    previousConfigBackup  = $PreviousConfigBackup
  }
  $enc = New-Object System.Text.UTF8Encoding $false
  [System.IO.File]::WriteAllText($path, (ConvertTo-TbvOwnershipJson -Object $obj), $enc)
  return $path
}

function Read-TbvSysmonOwnership {
  param([string]$OverrideRoot = "")
  $path = Get-TbvSysmonOwnershipPath -OverrideRoot $OverrideRoot
  if (-not (Test-Path -LiteralPath $path)) { return $null }
  $text = [System.IO.File]::ReadAllText($path)
  $obj = $null
  try {
    $obj = ConvertFrom-Jsonc -Text $text
  } catch {
    return $null
  }
  return $obj
}

function Test-TbvSysmonKitOwned {
  param([string]$OverrideRoot = "")
  $own = Read-TbvSysmonOwnership -OverrideRoot $OverrideRoot
  if ($null -eq $own) { return $false }
  $by = ""
  if ($own -is [System.Collections.IDictionary]) {
    if ($own.Contains("ownedBy")) { $by = [string]$own["ownedBy"] }
  } elseif ($own.PSObject.Properties["ownedBy"]) {
    $by = [string]$own.ownedBy
  }
  return ($by -eq "TrustButVerify")
}

function Remove-TbvSysmonOwnership {
  param([string]$OverrideRoot = "")
  $path = Get-TbvSysmonOwnershipPath -OverrideRoot $OverrideRoot
  if (Test-Path -LiteralPath $path) {
    Remove-Item -LiteralPath $path -Force
  }
}

function Test-LooksLikeSysmonConfigXml {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
  if (-not (Test-Path -LiteralPath $Path)) { return $false }
  try {
    $text = [System.IO.File]::ReadAllText($Path)
  } catch {
    return $false
  }
  if ($text -match '(?i)<Sysmon\b' -and $text -match '(?i)<EventFiltering\b') {
    return $true
  }
  return $false
}

function Copy-TbvRestorableSysmonConfig {
  param(
    [string]$ExistingConfigPath,
    [string]$OverrideRoot = ""
  )
  if (-not (Test-LooksLikeSysmonConfigXml -Path $ExistingConfigPath)) {
    throw "ExistingConfigPath must be a restorable Sysmon XML file (a sysmon -c text dump is not enough)."
  }
  $dir = Get-TbvSysmonBackupDir -OverrideRoot $OverrideRoot
  if (-not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
  }
  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $dest = Join-Path $dir ("previous-config-{0}.xml" -f $stamp)
  [System.IO.File]::Copy($ExistingConfigPath, $dest, $true)
  return $dest
}
