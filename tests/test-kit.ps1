# test-kit.ps1
# Parse-check every .ps1, reject non-ASCII (also in the plugin), then run
# redaction, merge, settings, Sysmon task, plugin install, doctor, allowlist,
# plugin unit (node or bun) and bypass-suite tests.
# Run from the kit root:
#   pwsh -NoProfile -File tests/test-kit.ps1

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

$kit = Split-Path -Parent $PSScriptRoot
. (Join-Path $kit "lib\WatchCommon.ps1")
$failed = 0
$passed = 0

function Assert-True {
  param([bool]$Cond, [string]$Name, [string]$Detail = "")
  if ($Cond) {
    $script:passed++
    Write-Host ("PASS  {0}" -f $Name)
  } else {
    $script:failed++
    Write-Host ("FAIL  {0}" -f $Name)
    if ($Detail) { Write-Host ("      {0}" -f $Detail) }
  }
}

$scripts = @(Get-ChildItem -LiteralPath $kit -Recurse -Filter "*.ps1" -File | Where-Object {
  $_.FullName -notmatch '[\\/]sysmon-dist[\\/]'
} | Sort-Object FullName)

Write-Host ("Found {0} PowerShell scripts" -f $scripts.Count)
foreach ($f in $scripts) {
  $rel = $f.FullName.Substring($kit.Length).TrimStart('\', '/')
  $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
  $nonAscii = @($bytes | Where-Object { $_ -gt 127 }).Count
  Assert-True ($nonAscii -eq 0) ("ASCII  {0}" -f $rel) ("non-ASCII bytes: $nonAscii")

  $tokens = $null
  $errors = $null
  $null = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
  $errCount = 0
  if ($errors) { $errCount = @($errors).Count }
  $detail = ""
  if ($errCount -gt 0) {
    $detail = ((@($errors) | ForEach-Object { $_.Message }) -join "; ")
  }
  Assert-True ($errCount -eq 0) ("PARSE {0}" -f $rel) $detail
}

Write-Host ""
Write-Host "Running redaction tests..."
$script:LASTEXITCODE = 0
& (Join-Path $PSScriptRoot "test-redaction.ps1")
if ($LASTEXITCODE -ne 0) { $failed++ }

Write-Host ""
Write-Host "Running merge/config tests..."
$script:LASTEXITCODE = 0
& (Join-Path $PSScriptRoot "test-merge-and-config.ps1")
if ($LASTEXITCODE -ne 0) { $failed++ }

Write-Host ""
Write-Host "Running settings tests..."
$script:LASTEXITCODE = 0
& (Join-Path $PSScriptRoot "test-settings.ps1")
if ($LASTEXITCODE -ne 0) { $failed++ }

Write-Host ""
Write-Host "Running Sysmon task tests..."
$script:LASTEXITCODE = 0
& (Join-Path $PSScriptRoot "test-sysmon-task.ps1")
if ($LASTEXITCODE -ne 0) { $failed++ }

foreach ($js in @(Get-ChildItem -LiteralPath (Join-Path $kit "plugin") -Filter "*.js" -File)) {
  $jb = [System.IO.File]::ReadAllBytes($js.FullName)
  Assert-True (@($jb | Where-Object { $_ -gt 127 }).Count -eq 0) ("ASCII  plugin/{0}" -f $js.Name)
}

foreach ($suite in @("test-plugin-install.ps1", "test-doctor.ps1", "test-allowlist.ps1", "test-bypass.ps1")) {
  Write-Host ""
  Write-Host ("Running {0}..." -f $suite)
  $script:LASTEXITCODE = 0
  & (Join-Path $PSScriptRoot $suite)
  if ($LASTEXITCODE -ne 0) { $failed++ }
}

Write-Host ""
Write-Host "Running plugin unit tests (node or bun)..."
$jsRunner = $null
foreach ($n in @("node", "bun")) {
  $c = Get-Command $n -ErrorAction SilentlyContinue
  if ($c) { $jsRunner = $c.Source; break }
}
if ($jsRunner) {
  $out = Invoke-Native -FilePath $jsRunner -ArgumentList @((Join-Path $PSScriptRoot "test-plugin.mjs")) -AllowFail
  $code = $LASTEXITCODE
  $out | ForEach-Object { Write-Host $_ }
  Assert-True ($code -eq 0) "plugin unit tests"
} else {
  Write-Host "SKIP  plugin unit tests: neither node nor bun is on PATH"
}

Write-Host ""
Write-Host ("Kit checks so far: {0} passed, {1} failed (plus any failures printed above)." -f $passed, $failed)
if ($failed -gt 0) { exit 1 }
exit 0
