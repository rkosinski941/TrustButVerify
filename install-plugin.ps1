# install-plugin.ps1
# Install the TrustButVerify guard plugin into OpenCode's global plugin
# folder (%USERPROFILE%\.config\opencode\plugins\trustbutverify-guard.js).
# No admin. Same safety pattern as apply-config.ps1:
#   - prints the SHA-256 of any existing plugin file before touching it
#   - -ExpectedPluginSha256 refuses if the existing file does not match
#   - writes a timestamped backup (.bak-<stamp>, not loaded by OpenCode)
#   - writes to a temporary name first, checks the hash, then swaps it in,
#     and restores the backup if the final hash is wrong
# Skips the install on OpenCode older than 1.18.29 unless -ForcePlugin; the
# config rules from apply-config.ps1 still apply there.
# -DryRun / -WhatIf prints the plan and writes nothing.

[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$ConfigPath = "",
  [string]$KitRoot = "",
  [string]$ExpectedPluginSha256 = "",
  [string]$OpenCodePath = "",
  [switch]$ForcePlugin,
  [switch]$DryRun
)

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($KitRoot)) { $KitRoot = $PSScriptRoot }
. (Join-Path (Join-Path $KitRoot "lib") "WatchCommon.ps1")
. (Join-Path (Join-Path $KitRoot "lib") "MergeOpenCodeConfig.ps1")
. (Join-Path (Join-Path $KitRoot "lib") "TbvPlugin.ps1")

$skipWrite = [bool]($DryRun -or $WhatIfPreference)
$src = Get-TbvPluginSourcePath -KitRoot $KitRoot
if (-not (Test-Path -LiteralPath $src)) { throw "Plugin source not found: $src" }
$srcSha = Get-FileHashHex -Path $src -Algorithm SHA256
$target = Get-TbvPluginInstallPath -ConfigPath $ConfigPath
$dir = Split-Path -Parent $target

Write-Host ("Guard plugin source: {0}" -f $src)
Write-Host ("Guard plugin SHA256: {0}" -f $srcSha)
Write-Host ("Install target:      {0}" -f $target)

$ver = Get-OpenCodeVersionInfo -OpenCodePath $OpenCodePath
$sup = Test-TbvPluginSupported -Version $ver.Version
if ($ver.Found) {
  Write-Host ("OpenCode: {0} ({1})" -f $ver.Text, $sup.Reason)
} else {
  Write-Host "OpenCode was not found on PATH; installing the plugin anyway (it is inert until OpenCode loads it)."
}
if ($sup.Supported -eq $false -and -not $ForcePlugin) {
  Write-Host ("Skipping the plugin: {0}. The config rules still apply. Re-run with -ForcePlugin to install it anyway." -f $sup.Reason)
  return
}

$existed = Test-Path -LiteralPath $target
if ($existed) {
  $curSha = Get-FileHashHex -Path $target -Algorithm SHA256
  Write-Host ("Existing plugin SHA256: {0}" -f $curSha)
  if ($ExpectedPluginSha256) {
    $want = $ExpectedPluginSha256.Trim().ToLowerInvariant().Replace("-", "")
    if ($curSha -ne $want) {
      throw ("Existing plugin SHA256 {0} does not match -ExpectedPluginSha256 {1}. No files were changed." -f $curSha, $want)
    }
  }
  if ($curSha -eq $srcSha) {
    Write-Host "The installed plugin already matches this kit. Nothing to do."
    return
  }
} elseif ($ExpectedPluginSha256) {
  throw "-ExpectedPluginSha256 was set, but no plugin is installed at the target. No files were changed."
}

if ($skipWrite) {
  if ($existed) { Write-Host "Dry run: would back up the existing plugin and replace it." }
  else { Write-Host "Dry run: would create the plugins folder if needed and copy the plugin." }
  return
}

if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backup = ""
if ($existed) {
  $backup = $target + ".bak-" + $stamp
if (Test-Path -LiteralPath $backup) { $backup = $backup + "-" + [guid]::NewGuid().ToString("N").Substring(0, 6) }
  [System.IO.File]::Copy($target, $backup, $true)
  Write-Host ("Backup: {0}" -f $backup)
  Write-Host ("Backup SHA256: {0}" -f (Get-FileHashHex -Path $backup -Algorithm SHA256))
}

# Remember a pre-existing non-kit file so uninstall can put it back. A file
# that this kit installed earlier (marker sha, or a known kit hash) is not
# restored on uninstall.
$marker = $target + ".tbv-installed"
$userBackup = ""
$prevSha = ""
if (Test-Path -LiteralPath $marker) {
  foreach ($line in @(Get-Content -LiteralPath $marker)) {
    $t = [string]$line
    if ($t.StartsWith("backup=")) {
      $b = $t.Substring(7).Trim()
      if ($b -and (Test-Path -LiteralPath $b)) { $userBackup = $b }
    }
    if ($t.StartsWith("sha256=")) { $prevSha = $t.Substring(7).Trim() }
  }
}
if ($existed -and -not $userBackup) {
  $known = @(Get-TbvPluginKnownHashes -KitRoot $KitRoot)
  if ($curSha -ne $prevSha -and -not ($known -contains $curSha)) { $userBackup = $backup }
}

$tmp = $target + ".tbv-new"
[System.IO.File]::Copy($src, $tmp, $true)
$tmpSha = Get-FileHashHex -Path $tmp -Algorithm SHA256
if ($tmpSha -ne $srcSha) {
  Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  throw ("Copied plugin hash {0} does not match the source {1}. The existing plugin was left unchanged." -f $tmpSha, $srcSha)
}
[System.IO.File]::Copy($tmp, $target, $true)
Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
$finalSha = Get-FileHashHex -Path $target -Algorithm SHA256
if ($finalSha -ne $srcSha) {
  if ($backup) {
    [System.IO.File]::Copy($backup, $target, $true)
    Write-Host "Final hash check failed; restored the backup."
  } else {
    Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
    Write-Host "Final hash check failed; removed the new file."
  }
  throw ("Installed plugin hash {0} does not match the source {1}." -f $finalSha, $srcSha)
}
$enc = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($marker, ("sha256={0}`nstamp={1}`nbackup={2}`n" -f $srcSha, $stamp, $userBackup), $enc)
Write-Host ("Installed {0}" -f $target)
Write-Host ("Installed SHA256: {0}" -f $finalSha)
Write-Host "Restart OpenCode so it loads the plugin. doctor.ps1 checks that it loaded (plugin-heartbeat.json)."
