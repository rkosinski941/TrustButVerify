# test-settings.ps1
# Unit-style tests for TrustButVerify settings load, validation, and
# log retention. Run from the kit root:
#   pwsh -NoProfile -File tests/test-settings.ps1

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

$kit = Split-Path -Parent $PSScriptRoot
. (Join-Path $kit "lib\WatchCommon.ps1")
. (Join-Path $kit "lib\TbvSettings.ps1")

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

function Assert-Eq {
  param($Actual, $Expected, [string]$Name)
  if ($Actual -eq $Expected) {
    $script:passed++
    Write-Host ("PASS  {0}" -f $Name)
  } else {
    $script:failed++
    Write-Host ("FAIL  {0}" -f $Name)
    Write-Host ("      expected: {0}" -f $Expected)
    Write-Host ("      actual:   {0}" -f $Actual)
  }
}

# --- defaults ---

$d = Get-TbvDefaultSettings
Assert-Eq $d["windowStyle"] "hidden" "default windowStyle is hidden"
Assert-Eq ([int]$d["pollIntervalMs"]) 1000 "default pollIntervalMs is 1000"
Assert-Eq (@($d["allowedLoopbackPorts"]).Count) 0 "default allowedLoopbackPorts is empty"
Assert-Eq ([bool]$d["ignoreSelfLoopback"]) $true "default ignoreSelfLoopback is true"
Assert-Eq (@($d["extraAlertPatterns"]).Count) 0 "default extraAlertPatterns is empty"
Assert-True (("opencode" -in @($d["watchedProcessNames"])) -and ("node" -in @($d["watchedProcessNames"])) -and ("bun" -in @($d["watchedProcessNames"]))) "default watched names are opencode, node, bun"
Assert-Eq $d["logDir"] "" "default logDir is empty"
Assert-Eq ([int]$d["logRetentionDays"]) 30 "default logRetentionDays is 30"
Assert-Eq (Get-TbvSettingsMinPollIntervalMs) 250 "minimum poll interval is 250"
Assert-Eq (Get-TbvReloadEventName) "Local\TrustButVerify-Reload" "reload event name"
Assert-Eq (Get-TbvWindowStyleFromSettings $d) "Hidden" "default maps to Hidden for Start-Process"

# example file matches defaults
$examplePath = Join-Path $kit "trustbutverify.example.json"
Assert-True (Test-Path -LiteralPath $examplePath) "example settings file is in the repo"
$ex = Read-TbvSettings -Path $examplePath
Assert-Eq $ex["windowStyle"] "hidden" "example windowStyle"
Assert-Eq ([int]$ex["pollIntervalMs"]) 1000 "example pollIntervalMs"
Assert-Eq (@($ex["allowedLoopbackPorts"]).Count) 0 "example allowedLoopbackPorts empty"
Assert-Eq ([bool]$ex["ignoreSelfLoopback"]) $true "example ignoreSelfLoopback is true"
Assert-Eq ([int]$ex["logRetentionDays"]) 30 "example logRetentionDays"
Assert-Eq $ex["warnings"].Count 0 "example file loads with no warnings"

# --- invalid JSON falls back to defaults, does not throw ---

$bad = $null
$threw = $false
try {
  $bad = Read-TbvSettings -Text "{ this is not json"
} catch {
  $threw = $true
}
Assert-True (-not $threw -and $null -ne $bad) "invalid JSON does not throw"
Assert-Eq $bad["source"] "defaults" "invalid JSON uses defaults"
Assert-Eq $bad["windowStyle"] "hidden" "invalid JSON default windowStyle"
Assert-Eq ([int]$bad["pollIntervalMs"]) 1000 "invalid JSON default poll"
Assert-True ($bad["warnings"].Count -gt 0) "invalid JSON adds a warning" ("warnings=" + ($bad["warnings"] -join "; "))
Assert-True (([string]$bad["warnings"][0]) -match '(?i)invalid') "invalid JSON warning mentions invalid"

$missing = Read-TbvSettings -Path (Join-Path ([System.IO.Path]::GetTempPath()) "tbv-no-such-file-xyz.json")
Assert-Eq $missing["source"] "defaults" "missing file uses defaults"
Assert-True ($missing["warnings"].Count -gt 0) "missing file adds a warning"

# --- bad regex is skipped with a warning; valid ones are kept ---

$rxText = @'
{
  "extraAlertPatterns": [
    "[unterminated",
    "pastebin\\.com",
    "*not-a-valid("
  ]
}
'@
$rx = Read-TbvSettings -Text $rxText
Assert-True ((@($rx["extraAlertPatterns"]) -join ",") -match "pastebin") "valid extra pattern is kept"
Assert-Eq (@($rx["extraAlertPatterns"]).Count) 1 "only the valid regex is kept"
Assert-Eq (@($rx["extraAlertRegexes"]).Count) 1 "one compiled regex"
Assert-True ($rx["warnings"].Count -ge 2) "each bad regex produced a warning" ("warn count=" + $rx["warnings"].Count)
$joined = ($rx["warnings"] -join "; ")
Assert-True ($joined -match 'unterminated' -and $joined -match 'not-a-valid') "warnings name the bad patterns" $joined
$hit = Get-CommandLineAlertReasons -CommandLine "curl https://pastebin.com/raw/x" -ExtraRegexes $rx["extraAlertRegexes"]
Assert-True (($hit -join "; ") -match "pastebin") "compiled extra pattern alerts" ($hit -join "; ")
$miss = Get-CommandLineAlertReasons -CommandLine "git status" -ExtraRegexes $rx["extraAlertRegexes"]
Assert-True (($miss -join "; ") -notmatch "pastebin") "extra pattern does not fire on unrelated text"

# --- poll minimum ---

$low = Read-TbvSettings -Text '{ "pollIntervalMs": 100 }'
Assert-Eq ([int]$low["pollIntervalMs"]) 250 "pollIntervalMs 100 is clamped to 250"
Assert-True (($low["warnings"] -join "; ") -match "250") "clamp is logged as a warning"

$ok = Read-TbvSettings -Text '{ "pollIntervalMs": 500 }'
Assert-Eq ([int]$ok["pollIntervalMs"]) 500 "pollIntervalMs 500 is kept"
Assert-Eq $ok["warnings"].Count 0 "no warning for a legal poll interval"

# --- windowStyle validation ---

$vis = Read-TbvSettings -Text '{ "windowStyle": "minimized" }'
Assert-Eq $vis["windowStyle"] "minimized" "windowStyle minimized is kept"
Assert-Eq (Get-TbvWindowStyleFromSettings $vis) "Minimized" "minimized maps to Minimized"

$badStyle = Read-TbvSettings -Text '{ "windowStyle": "fullscreen" }'
Assert-Eq $badStyle["windowStyle"] "hidden" "invalid windowStyle falls back to hidden"
Assert-True ($badStyle["warnings"].Count -gt 0) "invalid windowStyle warns"

$ignOff = Read-TbvSettings -Text '{ "ignoreSelfLoopback": false }'
Assert-Eq ([bool]$ignOff["ignoreSelfLoopback"]) $false "ignoreSelfLoopback false is kept"
$ignOn = Read-TbvSettings -Text '{ "ignoreSelfLoopback": "yes" }'
Assert-Eq ([bool]$ignOn["ignoreSelfLoopback"]) $true "ignoreSelfLoopback yes is true"

# --- Install-TbvSettingsFileIfMissing does not overwrite ---

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("tbv-settings-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
try {
  $cfg = Join-Path $tempRoot "trustbutverify.json"
  $first = Install-TbvSettingsFileIfMissing -KitRoot $kit -Path $cfg
  Assert-True ($first.Created -eq $true) "missing settings file is created"
  Assert-True (Test-Path -LiteralPath $cfg) "created file exists"
  $marker = "do-not-overwrite-me"
  [System.IO.File]::WriteAllText($cfg, ('{ "windowStyle": "minimized", "pollIntervalMs": 2000, "marker": "' + $marker + '" }'))
  $second = Install-TbvSettingsFileIfMissing -KitRoot $kit -Path $cfg
  Assert-True ($second.Created -eq $false) "existing settings file is not created again"
  $text = [System.IO.File]::ReadAllText($cfg)
  Assert-True ($text.Contains($marker)) "existing settings file is not overwritten"

  $set = Set-TbvSettingsWindowStyle -WindowStyle "hidden" -Path $cfg
  Assert-True ($set.Updated -eq $true) "windowStyle update writes the file"
  $after = Read-TbvSettings -Path $cfg
  Assert-Eq $after["windowStyle"] "hidden" "windowStyle updated to hidden"
  Assert-Eq ([int]$after["pollIntervalMs"]) 2000 "windowStyle update keeps other settings"

  # --- retention ---
  $oldCsv = Join-Path $tempRoot "watch-20200101.csv"
  $oldLog = Join-Path $tempRoot "watch-20200101.log"
  $newCsv = Join-Path $tempRoot "watch-20990101.csv"
  $other = Join-Path $tempRoot "keep-me.txt"
  [System.IO.File]::WriteAllText($oldCsv, "old")
  [System.IO.File]::WriteAllText($oldLog, "old")
  [System.IO.File]::WriteAllText($newCsv, "new")
  [System.IO.File]::WriteAllText($other, "keep")
  $oldTime = (Get-Date).AddDays(-40)
  $newTime = Get-Date
  [System.IO.File]::SetLastWriteTime($oldCsv, $oldTime)
  [System.IO.File]::SetLastWriteTime($oldLog, $oldTime)
  [System.IO.File]::SetLastWriteTime($newCsv, $newTime)
  [System.IO.File]::SetLastWriteTime($other, $oldTime)
  $removed = @(Invoke-TbvLogRetention -LogDir $tempRoot -Days 30)
  Assert-True (("watch-20200101.csv" -in $removed) -and ("watch-20200101.log" -in $removed)) "old watch logs are pruned" ("removed=" + ($removed -join ","))
  Assert-True (-not (Test-Path -LiteralPath $oldCsv) -and -not (Test-Path -LiteralPath $oldLog)) "old watch files are gone"
  Assert-True (Test-Path -LiteralPath $newCsv) "recent watch csv is kept"
  Assert-True (Test-Path -LiteralPath $other) "non-watch files are not pruned"
  Assert-True (Test-Path -LiteralPath $cfg) "settings file is not pruned"
  $none = @(Invoke-TbvLogRetention -LogDir $tempRoot -Days 0)
  Assert-Eq $none.Count 0 "retention 0 does not prune"
} finally {
  Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("Settings tests: {0} passed, {1} failed" -f $passed, $failed)
if ($failed -gt 0) { exit 1 }
exit 0
