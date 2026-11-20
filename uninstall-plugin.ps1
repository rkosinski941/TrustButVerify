# uninstall-plugin.ps1
# Remove the TrustButVerify guard plugin from OpenCode's plugin folder.
# No admin. The removed file is kept as <name>.removed-<stamp> (not loaded
# by OpenCode). Refuses to remove a file whose hash is not a known kit
# build unless -Force. If install-plugin.ps1 had backed up a different file
# at the same path, that backup is restored.

[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$ConfigPath = "",
  [string]$KitRoot = "",
  [switch]$Force,
  [switch]$DryRun
)

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($KitRoot)) { $KitRoot = $PSScriptRoot }
. (Join-Path (Join-Path $KitRoot "lib") "WatchCommon.ps1")
. (Join-Path (Join-Path $KitRoot "lib") "MergeOpenCodeConfig.ps1")
. (Join-Path (Join-Path $KitRoot "lib") "TbvPlugin.ps1")

$skipWrite = [bool]($DryRun -or $WhatIfPreference)
$target = Get-TbvPluginInstallPath -ConfigPath $ConfigPath
$marker = $target + ".tbv-installed"
if (-not (Test-Path -LiteralPath $target)) {
  Write-Host ("No guard plugin at {0} (that is fine)." -f $target)
  if ((Test-Path -LiteralPath $marker) -and -not $skipWrite) { Remove-Item -LiteralPath $marker -Force }
  return
}
$sha = Get-FileHashHex -Path $target -Algorithm SHA256
Write-Host ("Installed plugin: {0}" -f $target)
Write-Host ("Installed SHA256: {0}" -f $sha)
$known = @(Get-TbvPluginKnownHashes -KitRoot $KitRoot)
if (Test-Path -LiteralPath $marker) {
  foreach ($line in @(Get-Content -LiteralPath $marker)) {
    $t = [string]$line
    if ($t.StartsWith("sha256=")) { $known += $t.Substring(7).Trim() }
  }
}
if (-not ($known -contains $sha) -and -not $Force) {
  throw "The installed plugin does not match a known TrustButVerify build (it may have been edited). Nothing was removed. Inspect it, then re-run with -Force."
}

$restore = ""
if (Test-Path -LiteralPath $marker) {
  $line = @(Get-Content -LiteralPath $marker | Where-Object { $_ -like "backup=*" }) | Select-Object -First 1
  if ($line) {
    $b = ([string]$line).Substring(7).Trim()
    if ($b -and (Test-Path -LiteralPath $b)) { $restore = $b }
  }
}

if ($skipWrite) {
  Write-Host "Dry run: would move the plugin aside as .removed-<stamp>."
  if ($restore) { Write-Host ("Dry run: would restore the pre-install file {0}" -f $restore) }
  return
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$aside = $target + ".removed-" + $stamp
if (Test-Path -LiteralPath $aside) { $aside = $aside + "-" + [guid]::NewGuid().ToString("N").Substring(0, 6) }
[System.IO.File]::Copy($target, $aside, $true)
if ((Get-FileHashHex -Path $aside -Algorithm SHA256) -ne $sha) { throw "Backup copy hash mismatch; nothing was removed." }
Remove-Item -LiteralPath $target -Force
Write-Host ("Removed the plugin. Backup: {0}" -f $aside)
if ($restore) {
  [System.IO.File]::Copy($restore, $target, $true)
  Write-Host ("Restored the file that was there before install: {0} (SHA256 {1})" -f $restore, (Get-FileHashHex -Path $target -Algorithm SHA256))
}
if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker -Force }
Write-Host "Restart OpenCode so it unloads the plugin."
