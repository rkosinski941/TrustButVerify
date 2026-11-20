# test-plugin-install.ps1
# Tests install-plugin.ps1 / uninstall-plugin.ps1 in a temp config folder,
# with a fake opencode that prints a chosen version. Run from the kit root:
#   pwsh -NoProfile -File tests/test-plugin-install.ps1

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

$kit = Split-Path -Parent $PSScriptRoot
. (Join-Path $kit "lib\WatchCommon.ps1")
. (Join-Path $kit "lib\MergeOpenCodeConfig.ps1")
. (Join-Path $kit "lib\TbvPlugin.ps1")

$failed = 0
$passed = 0
function Assert-True {
  param([bool]$Cond, [string]$Name, [string]$Detail = "")
  if ($Cond) { $script:passed++; Write-Host ("PASS  {0}" -f $Name) }
  else { $script:failed++; Write-Host ("FAIL  {0}" -f $Name); if ($Detail) { Write-Host ("      {0}" -f $Detail) } }
}

# Version helpers
Assert-True ((ConvertTo-TbvVersion "1.19.6") -eq [version]"1.19.6") "parse plain version"
Assert-True ((ConvertTo-TbvVersion "opencode v2.3.2`n") -eq [version]"2.3.2") "parse prefixed version"
Assert-True ($null -eq (ConvertTo-TbvVersion "garbage")) "unparseable version is null"
Assert-True ((Test-TbvPluginSupported ([version]"1.19.6")).Supported -eq $true) "1.19.6 supported"
Assert-True ((Test-TbvPluginSupported ([version]"1.18.29")).Supported -eq $true) "1.18.29 supported"
Assert-True ((Test-TbvPluginSupported ([version]"1.18.28")).Supported -eq $false) "1.18.28 not supported"
Assert-True ((Test-TbvPluginSupported ([version]"0.15.0")).Supported -eq $false) "0.x not supported"
Assert-True ($null -eq (Test-TbvPluginSupported $null).Supported) "unknown version is null"

$src = Get-TbvPluginSourcePath -KitRoot $kit
$srcSha = Get-FileHashHex -Path $src -Algorithm SHA256
$bytes = [System.IO.File]::ReadAllBytes($src)
Assert-True (@($bytes | Where-Object { $_ -gt 127 }).Count -eq 0) "plugin source is ASCII"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("tbv-plugin-test-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
  $cfg = Join-Path $tmp "opencode.jsonc"
  $fake = $null
  function New-FakeOpenCode([string]$Version) {
    if (Test-IsWindowsOS) {
      $p = Join-Path $tmp "opencode.cmd"
      [System.IO.File]::WriteAllText($p, "@echo $Version`r`n")
    } else {
      $p = Join-Path $tmp "opencode"
      [System.IO.File]::WriteAllText($p, "#!/bin/sh`necho $Version`n")
      $null = Invoke-Native -FilePath "chmod" -ArgumentList @("+x", $p)
    }
    return $p
  }
  $inst = Join-Path $kit "install-plugin.ps1"
  $unin = Join-Path $kit "uninstall-plugin.ps1"
  $target = Get-TbvPluginInstallPath -ConfigPath $cfg
  $marker = $target + ".tbv-installed"

  $fake = New-FakeOpenCode "1.19.6"
  Assert-True ((Get-OpenCodeVersionInfo -OpenCodePath $fake).Version -eq [version]"1.19.6") "fake opencode version read via Invoke-Native"

  # Dry run writes nothing
  & $inst -ConfigPath $cfg -KitRoot $kit -OpenCodePath $fake -DryRun | Out-Null
  Assert-True (-not (Test-Path -LiteralPath $target)) "dry run writes nothing"

  # Old version is skipped unless -ForcePlugin
  $old = New-FakeOpenCode "1.17.0"
  & $inst -ConfigPath $cfg -KitRoot $kit -OpenCodePath $old | Out-Null
  Assert-True (-not (Test-Path -LiteralPath $target)) "old OpenCode skips the plugin"
  & $inst -ConfigPath $cfg -KitRoot $kit -OpenCodePath $old -ForcePlugin | Out-Null
  Assert-True ((Test-Path -LiteralPath $target) -and ((Get-FileHashHex -Path $target -Algorithm SHA256) -eq $srcSha)) "-ForcePlugin installs on old OpenCode"
  & $unin -ConfigPath $cfg -KitRoot $kit | Out-Null
  Assert-True (-not (Test-Path -LiteralPath $target)) "uninstall removes the kit plugin"
  Assert-True (@(Get-ChildItem -LiteralPath (Split-Path $target) -Filter "*.removed-*").Count -ge 1) "uninstall keeps a .removed backup"
  Assert-True (-not (Test-Path -LiteralPath $marker)) "uninstall removes the marker"

  # Fresh install
  $fake = New-FakeOpenCode "1.19.6"
  & $inst -ConfigPath $cfg -KitRoot $kit -OpenCodePath $fake | Out-Null
  Assert-True ((Get-FileHashHex -Path $target -Algorithm SHA256) -eq $srcSha) "fresh install hash matches"
  Assert-True (Test-Path -LiteralPath $marker) "install writes marker"
  Assert-True (-not (Test-Path -LiteralPath ($target + ".tbv-new"))) "temp file cleaned up"
  $loaded = @(Get-ChildItem -LiteralPath (Split-Path $target) -File | Where-Object { $_.Name -match '\.(js|ts)$' })
  Assert-True ($loaded.Count -eq 1) "only one loadable plugin file in plugins/ (backups are not .js)" (($loaded | ForEach-Object Name) -join ",")

  # Re-run is a no-op
  $before = @(Get-ChildItem -LiteralPath (Split-Path $target)).Count
  & $inst -ConfigPath $cfg -KitRoot $kit -OpenCodePath $fake | Out-Null
  Assert-True (@(Get-ChildItem -LiteralPath (Split-Path $target)).Count -eq $before) "re-install of same build is a no-op"

  # Edited plugin: uninstall refuses without -Force
  [System.IO.File]::AppendAllText($target, "`n// local edit`n")
  $threw = $false
  try { & $unin -ConfigPath $cfg -KitRoot $kit | Out-Null } catch { $threw = $true }
  Assert-True $threw "uninstall refuses an edited plugin"
  Assert-True (Test-Path -LiteralPath $target) "edited plugin left in place"
  & $unin -ConfigPath $cfg -KitRoot $kit -Force | Out-Null
  Assert-True (-not (Test-Path -LiteralPath $target)) "uninstall -Force removes edited plugin"

  # Pre-existing user file at the same path: -ExpectedPluginSha256 guard, backup, restore
  $userText = "export default { id: 'someone-else' }`n"
  [System.IO.File]::WriteAllText($target, $userText)
  $userSha = Get-FileHashHex -Path $target -Algorithm SHA256
  $threw = $false
  try { & $inst -ConfigPath $cfg -KitRoot $kit -OpenCodePath $fake -ExpectedPluginSha256 ("0" * 64) | Out-Null } catch { $threw = $true }
  Assert-True $threw "wrong -ExpectedPluginSha256 refuses"
  Assert-True ((Get-FileHashHex -Path $target -Algorithm SHA256) -eq $userSha) "refused install leaves file unchanged"
  & $inst -ConfigPath $cfg -KitRoot $kit -OpenCodePath $fake -ExpectedPluginSha256 $userSha.ToUpperInvariant() | Out-Null
  Assert-True ((Get-FileHashHex -Path $target -Algorithm SHA256) -eq $srcSha) "matching -ExpectedPluginSha256 installs"
  $baks = @(Get-ChildItem -LiteralPath (Split-Path $target) -Filter "trustbutverify-guard.js.bak-*")
  Assert-True ($baks.Count -ge 1) "install backed up the existing file"
  & $unin -ConfigPath $cfg -KitRoot $kit | Out-Null
  Assert-True ((Test-Path -LiteralPath $target) -and ((Get-FileHashHex -Path $target -Algorithm SHA256) -eq $userSha)) "uninstall restores the pre-install user file"

  # Upgrade over an older kit build does not restore the old build on uninstall
  Remove-Item -LiteralPath $target -Force
  & $inst -ConfigPath $cfg -KitRoot $kit -OpenCodePath $fake | Out-Null
  $markerText = [System.IO.File]::ReadAllText($marker)
  [System.IO.File]::AppendAllText($target, "`n// older kit build`n")
  $olderSha = Get-FileHashHex -Path $target -Algorithm SHA256
  [System.IO.File]::WriteAllText($marker, ("sha256={0}`nstamp=x`nbackup=`n" -f $olderSha))
  & $inst -ConfigPath $cfg -KitRoot $kit -OpenCodePath $fake | Out-Null
  Assert-True ((Get-FileHashHex -Path $target -Algorithm SHA256) -eq $srcSha) "upgrade replaces older kit build"
  & $unin -ConfigPath $cfg -KitRoot $kit | Out-Null
  Assert-True (-not (Test-Path -LiteralPath $target)) "uninstall after upgrade does not resurrect the older build"
  $null = $markerText
} finally {
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("Plugin install tests: {0} passed, {1} failed" -f $passed, $failed)
if ($failed -gt 0) { exit 1 }
exit 0
