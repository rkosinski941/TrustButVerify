# update-manifest.ps1
# Regenerates kit-manifest.json (SHA-256 of each kit file, CRLF folded to
# LF) for doctor.ps1. Run after changing kit files, before committing.
# Keeps earlier guard plugin hashes in pluginHistory so uninstall-plugin.ps1
# can still recognise (and remove) an older kit build of the plugin.

[CmdletBinding()]
param([string]$KitRoot = "")

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($KitRoot)) { $KitRoot = $PSScriptRoot }
$lib = Join-Path $KitRoot "lib"
. (Join-Path $lib "WatchCommon.ps1")
. (Join-Path $lib "TbvDoctor.ps1")

$path = Join-Path $KitRoot "kit-manifest.json"
$history = New-Object System.Collections.Generic.List[string]
if (Test-Path -LiteralPath $path) {
  try {
    $old = ConvertFrom-Json ([System.IO.File]::ReadAllText($path))
    foreach ($h in @($old.pluginHistory)) { if ($h) { $history.Add([string]$h) } }
  } catch { }
}
$plugin = Join-Path (Join-Path $KitRoot "plugin") "trustbutverify-guard.js"
if (Test-Path -LiteralPath $plugin) { $history.Add((Get-FileHashHex -Path $plugin -Algorithm SHA256)) }
$m = New-TbvManifestObject -KitRoot $KitRoot -PluginHistory $history.ToArray()
$json = ($m | ConvertTo-Json -Depth 4) -replace "`r`n", "`n"
$enc = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($path, $json + "`n", $enc)
Write-Host ("Wrote {0} ({1} files)" -f $path, $m.files.Count)
