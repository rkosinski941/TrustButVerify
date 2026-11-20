# test-kit.ps1
# Parse-check every .ps1, reject non-ASCII, then run redaction, merge, settings, and Sysmon task tests.
# Run from the kit root:
#   pwsh -NoProfile -File tests/test-kit.ps1

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

$kit = Split-Path -Parent $PSScriptRoot
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

Write-Host ""
Write-Host ("Kit checks so far: {0} passed, {1} failed (plus any failures printed above)." -f $passed, $failed)
if ($failed -gt 0) { exit 1 }
exit 0
