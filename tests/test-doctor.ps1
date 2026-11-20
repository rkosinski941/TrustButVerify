# test-doctor.ps1
# Tests for doctor.ps1 helpers (lib/TbvDoctor.ps1), the kit manifest, and
# a doctor.ps1 run against temp configs with -NoOpenCode. Run from the kit
# root:
#   pwsh -NoProfile -File tests/test-doctor.ps1

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

$kit = Split-Path -Parent $PSScriptRoot
. (Join-Path $kit "lib\WatchCommon.ps1")
. (Join-Path $kit "lib\MergeOpenCodeConfig.ps1")
. (Join-Path $kit "lib\TbvConfigMatcher.ps1")
. (Join-Path $kit "lib\TbvDoctor.ps1")

$failed = 0
$passed = 0
function Assert-True {
  param([bool]$Cond, [string]$Name, [string]$Detail = "")
  if ($Cond) { $script:passed++; Write-Host ("PASS  {0}" -f $Name) }
  else { $script:failed++; Write-Host ("FAIL  {0}" -f $Name); if ($Detail) { Write-Host ("      {0}" -f $Detail) } }
}
function New-Rule([string]$p, [string]$a) { return [pscustomobject]@{ Pattern = $p; Action = $a } }

# Exit codes
Assert-True ((Get-TbvDoctorExitCode @((New-TbvCheck "a" "PASS"), (New-TbvCheck "b" "SKIP"))) -eq 0) "exit 0 when all pass/skip"
Assert-True ((Get-TbvDoctorExitCode @((New-TbvCheck "a" "PASS"), (New-TbvCheck "b" "WARN"))) -eq 1) "exit 1 on warn"
Assert-True ((Get-TbvDoctorExitCode @((New-TbvCheck "a" "WARN"), (New-TbvCheck "b" "FAIL"))) -eq 2) "exit 2 on fail"
$tbl = Format-TbvDoctorTable @((New-TbvCheck "alpha" "PASS" "ok"), (New-TbvCheck "beta" "FAIL" "bad"))
Assert-True ($tbl.Count -eq 4 -and $tbl[0] -match 'STATUS' -and $tbl[3] -match '^FAIL') "table format"

# Rule order
$good = @((New-Rule "*" "ask"), (New-Rule "git status" "allow"), (New-Rule "*curl *" "deny"), (New-Rule "*printenv*" "deny"))
Assert-True ((Test-TbvRuleOrder $good).Status -eq "PASS") "good order passes"
$r = Test-TbvRuleOrder @((New-Rule "git status" "allow"), (New-Rule "*" "ask"), (New-Rule "*curl *" "deny"))
Assert-True ($r.Status -eq "FAIL" -and ($r.Problems -join " ") -match "not first") "catch-all not first fails"
$r = Test-TbvRuleOrder @((New-Rule "*" "ask"), (New-Rule "*curl *" "deny"), (New-Rule "curl https://example.com" "allow"))
Assert-True ($r.Status -eq "FAIL" -and ($r.Problems -join " ") -match "after a deny") "allow after deny fails"
$r = Test-TbvRuleOrder @((New-Rule "*" "ask"), (New-Rule "git *" "allow"), (New-Rule "*curl *" "deny"))
Assert-True ($r.Status -eq "FAIL" -and ($r.Problems -join " ") -match "wildcard allow") "wildcard allow fails"
$r = Test-TbvRuleOrder @((New-Rule "*" "allow"), (New-Rule "*curl *" "deny"))
Assert-True ($r.Status -eq "FAIL" -and ($r.Problems -join " ") -match "catch-all") "catch-all allow fails"
$r = Test-TbvRuleOrder @((New-Rule "*" "ask"))
Assert-True ($r.Status -eq "FAIL" -and ($r.Problems -join " ") -match "no deny") "no deny rules fails"
Assert-True ((Test-TbvRuleOrder @()).Status -eq "FAIL") "no rules fails"
Assert-True (@(ConvertTo-TbvRuleList "ask").Count -eq 1) "string permission becomes one rule"

# Kit config passes order and canaries
$kitCfg = ConvertFrom-Jsonc -Text (Get-OpenCodeEnvSubstitutedText -Text ([System.IO.File]::ReadAllText((Join-Path $kit "opencode.jsonc"))))
$kitRules = ConvertTo-TbvRuleList (Get-ObjectValue (Get-ObjectValue $kitCfg "permission") "bash")
$o = Test-TbvRuleOrder $kitRules
Assert-True ($o.Status -eq "PASS") "kit opencode.jsonc rule order passes" (($o.Problems) -join "; ")
$bad = @(Test-TbvCanaries $kitRules)
Assert-True ($bad.Count -eq 0) "kit opencode.jsonc canaries pass" ($bad -join "; ")
$weak = @((New-Rule "*" "ask"), (New-Rule "git status" "allow"))
Assert-True (@(Test-TbvCanaries $weak).Count -gt 0) "weak rules fail canaries"

# `opencode debug config` shapes: 1.x object, 2.x document list
$v1 = ConvertFrom-Jsonc -Text '{ "permission": { "bash": { "*": "ask", "git status": "allow", "*curl *": "deny" } }, "plugin": ["file:///x/plugins/trustbutverify-guard.js"] }'
$v1Rules = @(Get-TbvBashRulesFromDebugConfig -DebugConfig $v1)
Assert-True ($v1Rules.Count -eq 3 -and $v1Rules[2].Pattern -eq "*curl *" -and $v1Rules[2].Action -eq "deny") "1.x debug config rules"
Assert-True (Test-TbvPluginInDebugConfig -DebugConfig $v1) "1.x debug config lists plugin"
$v2 = ConvertFrom-Jsonc -Text '[ { "type": "document", "path": "/x/opencode.jsonc", "info": { "permissions": [ { "action": "edit", "resource": "*", "effect": "ask" }, { "action": "shell", "resource": "*", "effect": "ask" }, { "action": "shell", "resource": "*curl *", "effect": "deny" } ] } }, { "type": "directory", "path": "/nonexistent-tbv" } ]'
$v2Rules = @(Get-TbvBashRulesFromDebugConfig -DebugConfig $v2)
Assert-True ($v2Rules.Count -eq 2 -and $v2Rules[0].Pattern -eq "*" -and $v2Rules[1].Action -eq "deny") "2.x debug config shell rules in order"
Assert-True (-not (Test-TbvPluginInDebugConfig -DebugConfig $v2)) "2.x: plugin not found when the folder has none"

$masked = @((New-Rule "*" "ask"), (New-Rule "*credential*" "***"), (New-Rule "*other*" "***"))
$rr = Resolve-TbvRedactedRules -Rules $masked -FileRules @((New-Rule "*credential*" "deny"))
Assert-True ($rr.Redacted -eq 2 -and $rr.Unresolved -eq 1 -and $rr.Rules[1].Action -eq "deny" -and $rr.Rules[2].Action -eq "deny") "values masked by debug config are restored from the file"

# Heartbeat
$inst = [datetime]::UtcNow.AddMinutes(-10)
Assert-True ((Test-TbvPluginHeartbeat $null $inst "1.0.0").Status -eq "WARN") "no heartbeat warns"
$hb = [pscustomobject]@{ time = [datetime]::UtcNow.ToString("o"); api = "v1"; mode = "enforce"; version = "1.0.0"; optionsError = $false }
Assert-True ((Test-TbvPluginHeartbeat $hb $inst "1.0.0").Status -eq "PASS") "fresh heartbeat passes"
$hbDt = [pscustomobject]@{ time = [datetime]::Now; api = "v2"; mode = "enforce"; version = "1.0.0" }
Assert-True ((Test-TbvPluginHeartbeat $hbDt $inst "1.0.0").Status -eq "PASS") "heartbeat time as DateTime (pwsh 7 ConvertFrom-Json) passes"
$hbOld = [pscustomobject]@{ time = [datetime]::UtcNow.AddHours(-2).ToString("o"); api = "v1"; mode = "enforce"; version = "1.0.0" }
Assert-True ((Test-TbvPluginHeartbeat $hbOld $inst "1.0.0").Status -eq "WARN") "stale heartbeat warns"
$hbWarn = [pscustomobject]@{ time = [datetime]::UtcNow.ToString("o"); api = "v1"; mode = "warn"; version = "1.0.0" }
Assert-True ((Test-TbvPluginHeartbeat $hbWarn $inst "1.0.0").Detail -match "WARN mode") "warn-mode heartbeat warns"
$hbVer = [pscustomobject]@{ time = [datetime]::UtcNow.ToString("o"); api = "v1"; mode = "enforce"; version = "0.9.0" }
Assert-True ((Test-TbvPluginHeartbeat $hbVer $inst "1.0.0").Status -eq "WARN") "version mismatch warns"
$hbErr = [pscustomobject]@{ time = [datetime]::UtcNow.ToString("o"); api = "v1"; mode = "enforce"; version = "1.0.0"; optionsError = $true }
Assert-True ((Test-TbvPluginHeartbeat $hbErr $inst "1.0.0").Detail -match "invalid") "options error warns"
Assert-True ((Get-TbvPluginSourceVersion (Join-Path $kit "plugin\trustbutverify-guard.js")) -match '^\d+\.\d+\.\d+$') "plugin source version readable"

# Manifest
$manifestPath = Join-Path $kit "kit-manifest.json"
Assert-True (Test-Path -LiteralPath $manifestPath) "kit-manifest.json exists"
$manifest = ConvertFrom-Json ([System.IO.File]::ReadAllText($manifestPath))
$probs = @(Compare-TbvManifest -Manifest $manifest -KitRoot $kit)
Assert-True ($probs.Count -eq 0) "kit files match kit-manifest.json (run update-manifest.ps1 after edits)" (($probs | ForEach-Object { $_.Path + " " + $_.Problem }) -join "; ")
$srcSha = Get-FileHashHex -Path (Join-Path $kit "plugin\trustbutverify-guard.js") -Algorithm SHA256
Assert-True (@($manifest.pluginHistory) -contains $srcSha) "manifest pluginHistory has the current plugin hash"
$list = @(Get-TbvManifestFileList -KitRoot $kit)
Assert-True (($list -contains "doctor.ps1") -and ($list -contains "plugin/trustbutverify-guard.js") -and -not ($list | Where-Object { $_ -like "tests/*" })) "manifest covers kit files, not tests"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("tbv-doctor-test-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
  $a = Join-Path $tmp "a.txt"
  [System.IO.File]::WriteAllText($a, "x`r`ny`r`n")
  $b = Join-Path $tmp "b.txt"
  [System.IO.File]::WriteAllText($b, "x`ny`n")
  Assert-True ((Get-TbvNormalizedSha256 $a) -eq (Get-TbvNormalizedSha256 $b)) "CRLF and LF hash the same"

  # Tampered copy of the kit fails the manifest
  $copy = Join-Path $tmp "kit"
  New-Item -ItemType Directory -Force -Path $copy | Out-Null
  foreach ($rel in $list + @("kit-manifest.json")) {
    $dst = Join-Path $copy $rel
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
    Copy-Item -LiteralPath (Join-Path $kit $rel) -Destination $dst
  }
  [System.IO.File]::AppendAllText((Join-Path $copy "watch-opencode.ps1"), "`n# tampered`n")
  [System.IO.File]::WriteAllText((Join-Path $copy "extra.ps1"), "# extra`n")
  Remove-Item -LiteralPath (Join-Path $copy "stop-watch.cmd")
  $p2 = @(Compare-TbvManifest -Manifest $manifest -KitRoot $copy)
  $txt = ($p2 | ForEach-Object { $_.Path + ":" + $_.Problem }) -join ","
  Assert-True ($txt -match 'watch-opencode\.ps1:changed') "manifest detects a changed file" $txt
  Assert-True ($txt -match 'extra\.ps1:not in manifest') "manifest detects an unlisted file" $txt
  Assert-True ($txt -match 'stop-watch\.cmd:missing') "manifest detects a missing file" $txt

  # doctor.ps1 end to end (-NoOpenCode) against a good and a broken config
  $cfgDir = Join-Path $tmp "cfg"
  New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
  $goodCfg = Join-Path $cfgDir "opencode.jsonc"
  Copy-Item -LiteralPath (Join-Path $kit "opencode.jsonc") -Destination $goodCfg
  $settings = Join-Path $tmp "trustbutverify.json"
  Copy-Item -LiteralPath (Join-Path $kit "trustbutverify.example.json") -Destination $settings
  $doctor = Join-Path $kit "doctor.ps1"
  $pwsh = (Get-Process -Id $PID).Path
  $out = & $pwsh -NoProfile -File $doctor -ConfigPath $goodCfg -SettingsPath $settings -NoOpenCode -Json 2>&1
  $code = $LASTEXITCODE
  $j = ConvertFrom-Json (($out | ForEach-Object { "$_" }) -join "`n")
  $st = @{}
  foreach ($c in $j.checks) { $st[$c.Check] = $c.Status }
  Assert-True ($st["config file"] -eq "PASS") "doctor: kit config file passes"
  Assert-True ($st["bash rule order"] -eq "PASS") "doctor: rule order passes"
  Assert-True ($st["bash rule canaries"] -eq "PASS") "doctor: canaries pass"
  Assert-True ($st["settings file"] -eq "PASS") "doctor: settings file passes"
  Assert-True ($st["guard plugin file"] -eq "WARN") "doctor: missing plugin warns"
  Assert-True ($st["kit manifest"] -eq "PASS") "doctor: manifest passes"
  Assert-True ($code -eq 1 -and $j.exitCode -eq 1) "doctor: exit code 1 with warnings" ("code=$code")

  $brokenFixture = Join-Path $PSScriptRoot "fixtures\opencode.jsonc.broken-env-substitution"
  if (Test-Path -LiteralPath $brokenFixture) {
    Copy-Item -LiteralPath $brokenFixture -Destination $goodCfg -Force
    [System.IO.File]::WriteAllText($settings, "{ not json")
    $out = & $pwsh -NoProfile -File $doctor -ConfigPath $goodCfg -SettingsPath $settings -NoOpenCode -Json 2>&1
    $code = $LASTEXITCODE
    $j = ConvertFrom-Json (($out | ForEach-Object { "$_" }) -join "`n")
    $st = @{}
    foreach ($c in $j.checks) { $st[$c.Check] = $c.Status }
    Assert-True ($st["config file"] -eq "FAIL") "doctor: unclosed {env: config fails"
    Assert-True ($st["settings file"] -eq "FAIL") "doctor: invalid settings fails"
    Assert-True ($code -eq 2) "doctor: exit code 2 with failures" ("code=$code")
  }
} finally {
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("Doctor tests: {0} passed, {1} failed" -f $passed, $failed)
if ($failed -gt 0) { exit 1 }
exit 0
