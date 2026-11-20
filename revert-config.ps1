# revert-config.ps1
# Restore the latest timestamped OpenCode config backup created by
# apply-config.ps1 or install.ps1. If the latest action created a new
# config (no file existed before), this removes that created file.
# A safety copy of the current file is written first.
#
# Usage:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\revert-config.ps1
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\revert-config.ps1 -BackupPath "C:\path\to\opencode.jsonc.bak-20261120-153000"

[CmdletBinding()]
param(
  [string]$ConfigPath = "",
  [string]$BackupPath = "",
  [string]$KitRoot = ""
)

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($KitRoot)) { $KitRoot = $PSScriptRoot }
. (Join-Path $KitRoot "lib\WatchCommon.ps1")
. (Join-Path $KitRoot "lib\MergeOpenCodeConfig.ps1")

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
  $ConfigPath = Get-DefaultOpenCodeConfigPath
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$createdMarker = $null
$backup = $BackupPath

if ([string]::IsNullOrWhiteSpace($backup)) {
  $backup = Find-LatestConfigBackup -ConfigPath $ConfigPath
  $createdMarker = Find-LatestCreatedMarker -ConfigPath $ConfigPath
  if ($backup -and $createdMarker) {
    $bTime = [System.IO.File]::GetLastWriteTime($backup)
    $cTime = [System.IO.File]::GetLastWriteTime($createdMarker)
    if ($cTime -gt $bTime) { $backup = $null }
    else { $createdMarker = $null }
  }
}

if ($backup) {
  if (-not (Test-Path -LiteralPath $backup)) {
    throw "Backup not found: $backup"
  }
  if (Test-Path -LiteralPath $ConfigPath) {
    $safety = $ConfigPath + ".before-revert-" + $stamp
    [System.IO.File]::Copy($ConfigPath, $safety, $true)
    Write-Host ("Safety copy of current file: {0}" -f $safety)
    Write-Host ("Current SHA256: {0}" -f (Get-FileHashHex -Path $ConfigPath -Algorithm SHA256))
  }
  Write-Host ("Restoring {0}" -f $backup)
  Write-Host ("Backup SHA256: {0}" -f (Get-FileHashHex -Path $backup -Algorithm SHA256))
  $dir = Split-Path -Parent $ConfigPath
  if (-not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
  }
  [System.IO.File]::Copy($backup, $ConfigPath, $true)
  $text = [System.IO.File]::ReadAllText($ConfigPath)
  $null = ConvertFrom-Jsonc -Text $text
  Write-Host ("Restored {0}" -f $ConfigPath)
  Write-Host ("Restored SHA256: {0}" -f (Get-FileHashHex -Path $ConfigPath -Algorithm SHA256))
} elseif ($createdMarker) {
  if (Test-Path -LiteralPath $ConfigPath) {
    $safety = $ConfigPath + ".before-revert-" + $stamp
    [System.IO.File]::Copy($ConfigPath, $safety, $true)
    Write-Host ("Safety copy of current file: {0}" -f $safety)
    Remove-Item -LiteralPath $ConfigPath -Force
    Write-Host ("Removed {0} (it was created by this kit; no prior config to restore)." -f $ConfigPath)
  } else {
    Write-Host "Config file is already absent."
  }
  Remove-Item -LiteralPath $createdMarker -Force -ErrorAction SilentlyContinue
} else {
  throw ("No backup matching {0}.bak-* and no created-file marker were found. Pass -BackupPath to pick one." -f $ConfigPath)
}
