# test-bypass.ps1
# Adversarial bypass suite. Feeds every case in tests/bypass-cases.json
# through both layers and reports which layer catches it:
#   config = the kit opencode.jsonc rules, matched the way OpenCode 1.19.6
#            matches them (lib/TbvConfigMatcher.ps1)
#   plugin = plugin/trustbutverify-guard.js (needs node or bun)
# Nothing is executed; commands are only parsed and matched.
#
# Pass rules:
#   expect=block           at least one layer must stop it
#   pluginMustCatch        the plugin must stop it on its own
#   knownMiss              documented residual gap; reported, never failed
#   expect=allow           the plugin must not block it
# Also runs a regression for the unclosed {env: footgun.
#
# Run from the kit root:  pwsh -NoProfile -File tests/test-bypass.ps1
# -Table prints every case, not only failures and known misses.

param([switch]$Table)

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

$kit = Split-Path -Parent $PSScriptRoot
. (Join-Path $kit "lib\WatchCommon.ps1")
. (Join-Path $kit "lib\MergeOpenCodeConfig.ps1")
. (Join-Path $kit "lib\TbvConfigMatcher.ps1")

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

# --- Matcher semantics (read from the 1.19.6 bundle) ---
Assert-True (Test-OpenCode1196Wildcard -Pattern "*curl *" -Text "x curl y") "1.19.6 matcher: wildcard"
Assert-True (-not (Test-OpenCode1196Wildcard -Pattern "*curl *" -Text "x CURL y")) "1.19.6 matcher: case-sensitive"
Assert-True (Test-OpenCode1196Wildcard -Pattern "curl *" -Text "curl") "1.19.6 matcher: trailing ' *' is optional"
Assert-True (Test-OpenCode1196Wildcard -Pattern "git?status" -Text "git status") "1.19.6 matcher: ? is one character"
Assert-True (Test-OpenCode1196Wildcard -Pattern "*CurrentVersion\Run*" -Text "reg add HKCU/Software/Microsoft/Windows/CurrentVersion\Run") "1.19.6 matcher: backslash and slash are equal"
Assert-True (Test-OpenCode1196Wildcard -Pattern "*a*" -Text ("x`na")) "1.19.6 matcher: * spans newlines"
$segs = Split-OpenCodeCommandApprox -Command "git status; curl 'a;b' && ls | sort"
Assert-True ($segs.Count -eq 4) "approximate split respects quotes" ("got: " + ($segs -join " || "))
# Live finding on 1.19.6: declarations and bare assignments are not
# tree-sitter "command" nodes, so bash rules never see them.
Assert-True (Test-OpenCodeUncheckedSegment -Segment "export -p") "1.19.6: export -p is not permission-checked"
Assert-True (Test-OpenCodeUncheckedSegment -Segment "f=.env") "1.19.6: bare assignment is not permission-checked"
Assert-True (-not (Test-OpenCodeUncheckedSegment -Segment "FOO=1 printenv")) "1.19.6: assignment prefix plus command is checked"
Assert-True ((Resolve-OpenCode1196BashDecision -RuleMap @{ "*" = "ask"; "*export*" = "deny" } -Command "export -p").Decision -eq "allow") "1.19.6: deny rule cannot catch export -p (no command node)"

# --- Load the kit config and the cases ---
$cfgText = [System.IO.File]::ReadAllText((Join-Path $kit "opencode.jsonc"))
$cfg = ConvertFrom-Jsonc -Text $cfgText
$perm = Get-ObjectValue $cfg "permission"
$bashRules = ConvertTo-RuleMap (Get-ObjectValue $perm "bash")
$readRules = ConvertTo-RuleMap (Get-ObjectValue $perm "read")
$casesPath = Join-Path $PSScriptRoot "bypass-cases.json"
$cases = @((ConvertFrom-Json ([System.IO.File]::ReadAllText($casesPath))).cases)
Assert-True ($cases.Count -ge 100) ("bypass suite has at least 100 cases ({0})" -f $cases.Count)

# --- Plugin layer via node or bun ---
$runner = $null
foreach ($n in @("node", "bun")) {
  $cmd = Get-Command $n -ErrorAction SilentlyContinue
  if ($cmd) { $runner = $cmd.Source; break }
}
$pluginById = @{}
$pluginAvailable = $false
if ($runner) {
  $script = Join-Path $PSScriptRoot "bypass-plugin.mjs"
  $lines = @(Invoke-Native -FilePath $runner -ArgumentList @($script, $casesPath))
  foreach ($l in $lines) {
    $t = [string]$l
    if (-not $t.Trim().StartsWith("{")) { continue }
    $o = ConvertFrom-Json $t
    $pluginById[[string]$o.id] = $o
  }
  $pluginAvailable = ($pluginById.Count -eq $cases.Count)
  Assert-True $pluginAvailable ("plugin analyzer answered every case ({0}/{1}) via {2}" -f $pluginById.Count, $cases.Count, (Split-Path -Leaf $runner))
} else {
  Write-Host "WARN  node or bun not found: plugin layer skipped (config layer still checked)."
}

# --- Evaluate ---
$rows = New-Object System.Collections.Generic.List[object]
$stats = @{ configOnly = 0; pluginOnly = 0; both = 0; neither = 0; benignOk = 0; benignBlocked = 0; benignConfigDeny = 0 }
foreach ($c in $cases) {
  $id = [string]$c.id
  $tool = "bash"
  if ($c.PSObject.Properties["tool"]) { $tool = [string]$c.tool }
  $configDecision = "n/a"
  if ($tool -eq "bash") {
    $configDecision = (Resolve-OpenCode1196BashDecision -RuleMap $bashRules -Command ([string]$c.command)).Decision
  } elseif ($tool -eq "read") {
    $configDecision = (Resolve-OpenCode1196RuleMap -RuleMap $readRules -Text ([string]$c.args.filePath)).Decision
    if (-not $configDecision) { $configDecision = "allow" }
  } elseif ($tool -eq "webfetch") {
    $configDecision = [string](Get-ObjectValue $perm "webfetch")
  } else {
    $configDecision = "allow"
  }
  $configBlocks = ($configDecision -eq "deny")
  $pluginBlocks = $false
  $pluginRules = ""
  if ($pluginAvailable) {
    $p = $pluginById[$id]
    $pluginBlocks = [bool]$p.block
    $pluginRules = (@($p.rules) -join ", ")
  }
  $expect = [string]$c.expect
  $known = ($c.PSObject.Properties["knownMiss"] -and [bool]$c.knownMiss)
  $pluginMust = ($c.PSObject.Properties["pluginMustCatch"] -and [bool]$c.pluginMustCatch)
  $layer = "neither"
  if ($configBlocks -and $pluginBlocks) { $layer = "both" }
  elseif ($configBlocks) { $layer = "config" }
  elseif ($pluginBlocks) { $layer = "plugin" }
  $result = "ok"
  if ($expect -eq "allow") {
    if ($pluginBlocks) { $result = "FAIL plugin blocked a benign command"; $stats.benignBlocked++ } else { $stats.benignOk++ }
    if ($configBlocks) { $stats.benignConfigDeny++ }
  } else {
    switch ($layer) {
      "both" { $stats.both++ }
      "config" { $stats.configOnly++ }
      "plugin" { $stats.pluginOnly++ }
      default { $stats.neither++ }
    }
    if ($known) {
      $result = "known-miss"
      if ($layer -ne "neither") { $result = "known-miss (now caught by $layer)" }
    } elseif ($layer -eq "neither") {
      $result = "FAIL missed by both layers"
    } elseif ($pluginMust -and $pluginAvailable -and -not $pluginBlocks) {
      $result = "FAIL plugin must catch this"
    }
  }
  $rows.Add([pscustomobject]@{ Id = $id; Category = [string]$c.category; Config = $configDecision; Plugin = $(if (-not $pluginAvailable) { "skipped" } elseif ($pluginBlocks) { "block" } else { "pass" }); Layer = $layer; Result = $result; Rules = $pluginRules })
  if ($result.StartsWith("FAIL")) {
    Assert-True $false ("bypass {0}" -f $id) ("{0}; config={1}; plugin rules={2}" -f $result, $configDecision, $pluginRules)
  } elseif (-not $result.StartsWith("known")) {
    $script:passed++
  }
}

Write-Host ""
Write-Host "Bypass table (Layer = which layer stops it; config decisions use 1.19.6 matching):"
$fmt = "{0,-22} {1,-16} {2,-7} {3,-8} {4,-8} {5}"
Write-Host ($fmt -f "id", "category", "config", "plugin", "layer", "result")
foreach ($r in $rows) {
  if ($Table -or $r.Result -ne "ok") {
    Write-Host ($fmt -f $r.Id, $r.Category, $r.Config, $r.Plugin, $r.Layer, $r.Result)
  }
}
Write-Host ""
Write-Host ("Must-block cases: both={0} config-only={1} plugin-only={2} neither={3} (neither includes documented known misses)" -f $stats.both, $stats.configOnly, $stats.pluginOnly, $stats.neither)
Write-Host ("Benign cases: plugin allowed {0}, plugin blocked {1}; config denies {2} of them outright (the plugin does not loosen config rules)" -f $stats.benignOk, $stats.benignBlocked, $stats.benignConfigDeny)

# --- {env: footgun regression ---
Write-Host ""
Write-Host "Regression: unclosed {env: placeholder"
$fixture = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot "fixtures\opencode.jsonc.broken-env-substitution"))
$gate = Test-OpenCodeJsoncText -Text $fixture
Assert-True (-not $gate.Ok) "the broken fixture fails the OpenCode load gate"
$rawEnv = [regex]::Matches($cfgText, '\{(env|file):')
Assert-True ($rawEnv.Count -eq 0) "kit opencode.jsonc has no raw {env: or {file: text (uses \u007B)"
$merged = ConvertTo-OpenCodeJsoncText -ConfigObject (Merge-OpenCodeConfigObject -Config $cfg)
Assert-True ([regex]::Matches($merged, '\{(env|file):').Count -eq 0) "merged output escapes {env: as \u007B"
Assert-True ((Test-OpenCodeJsoncText -Text $merged).Ok) "merged output passes the OpenCode load gate"
$dollarRule = (Resolve-OpenCode1196BashDecision -RuleMap $bashRules -Command 'echo ${env:OPENAI_API_KEY}')
Assert-True ($dollarRule.Decision -eq "deny") 'the ${env: deny rule still matches after the escape' ("got " + $dollarRule.Decision)
$naive = '{ "permission": { "bash": { "*$' + '{env:*": "deny" } } }'
Assert-True (-not (Test-OpenCodeJsoncText -Text $naive).Ok) "writing the rule unescaped would break the config (the footgun)"

Write-Host ""
Write-Host ("Bypass suite: {0} passed, {1} failed." -f $passed, $failed)
if ($failed -gt 0) { exit 1 }
exit 0
