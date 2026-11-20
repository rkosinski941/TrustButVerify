# test-merge-and-config.ps1
# Validate the example JSONC, merge behavior, and last-match rule order.
# Run from the kit root:  pwsh -NoProfile -File tests/test-merge-and-config.ps1

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

$kit = Split-Path -Parent $PSScriptRoot
. (Join-Path $kit "lib\WatchCommon.ps1")
. (Join-Path $kit "lib\MergeOpenCodeConfig.ps1")

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

# Example parses
$examplePath = Join-Path $kit "opencode.jsonc"
$exampleText = [System.IO.File]::ReadAllText($examplePath)
$example = ConvertFrom-Jsonc -Text $exampleText
Assert-True ($null -ne $example) "example opencode.jsonc parses"
Assert-True ($null -eq $example.PSObject.Properties["model"]) "example does not force a model"

$perm = $example.permission
$bash = ConvertTo-RuleMap $perm.bash
$keys = @($bash.Keys)
Assert-True ($keys[0] -eq "*") "example bash starts with *"
Assert-True ([string]$bash["*"] -eq "ask") "example bash * is ask"
Assert-True ([string]$bash["git diff"] -eq "allow") "example git diff allow"
Assert-True ([string]$bash["git log"] -eq "allow") "example git log allow"
Assert-True ([string]$bash["git diff *"] -eq "ask") "example git diff * ask"
Assert-True ([string]$bash["git log *"] -eq "ask") "example git log * ask"

$idxDiff = $keys.IndexOf("git diff")
$idxDiffStar = $keys.IndexOf("git diff *")
$idxLog = $keys.IndexOf("git log")
$idxLogStar = $keys.IndexOf("git log *")
Assert-True ($idxDiff -ge 0 -and $idxDiffStar -gt $idxDiff) "git diff * comes after git diff" ("idx diff=$idxDiff star=$idxDiffStar")
Assert-True ($idxLog -ge 0 -and $idxLogStar -gt $idxLog) "git log * comes after git log" ("idx log=$idxLog star=$idxLogStar")

# Every deny comes after * and after the ask-after-allow keys
$firstDeny = -1
$lastNonDeny = -1
for ($i = 0; $i -lt $keys.Count; $i++) {
  if ([string]$bash[$keys[$i]] -eq "deny") {
    if ($firstDeny -lt 0) { $firstDeny = $i }
  } else {
    $lastNonDeny = $i
  }
}
Assert-True ($firstDeny -gt $idxLogStar -and $firstDeny -gt $idxDiffStar) "first deny comes after git * ask rules" ("firstDeny=$firstDeny")
Assert-True ($lastNonDeny -lt $firstDeny) "no allow/ask rule appears after a deny in the example" ("lastNonDeny=$lastNonDeny firstDeny=$firstDeny")
Assert-True ([string]$bash["*--no-index*"] -eq "deny") "example has --no-index deny"
Assert-True ([string]$bash["*auth.json*"] -eq "deny") "example has auth.json deny"
Assert-True ([string]$bash["*printenv*"] -eq "deny") "example has printenv deny"
Assert-True ([string]$bash["*[Environment]::GetEnvironmentVariables*"] -eq "deny") "example has Environment API deny"

$read = ConvertTo-RuleMap $perm.read
$readKeys = @($read.Keys)
Assert-True ($readKeys[0] -eq "*") "example read starts with *"
$readFirstDeny = -1
$readLastOther = -1
for ($i = 0; $i -lt $readKeys.Count; $i++) {
  if ([string]$read[$readKeys[$i]] -eq "deny") {
    if ($readFirstDeny -lt 0) { $readFirstDeny = $i }
  } else {
    $readLastOther = $i
  }
}
Assert-True ($readLastOther -eq 0 -and $readFirstDeny -eq 1) "example read denies all come after *"
Assert-True ([string]$read["*auth.json*"] -eq "deny") "example read denies auth.json"
Assert-True ([string]$read["*.grok*"] -eq "deny") "example read denies .grok"
Assert-True ([string]$read["*.aws*"] -eq "deny") "example read denies .aws"
Assert-True ([string]$read["*.azure*"] -eq "deny") "example read denies .azure"
Assert-True ([string]$read["*.npmrc*"] -eq "deny") "example read denies .npmrc"
Assert-True ([string]$read["*.gitconfig*"] -eq "deny") "example read denies .gitconfig"
Assert-True ([string]$read["*ConsoleHost_history*"] -eq "deny") "example read denies ConsoleHost_history"

# Merge keeps model and user rules, forces git * to ask, denies last
$originalPath = Join-Path $PSScriptRoot "opencode.jsonc.original"
$originalText = [System.IO.File]::ReadAllText($originalPath)
$original = ConvertFrom-Jsonc -Text $originalText
Assert-True ([string]$original.model -eq "opencode/deepseek-v4.1-flash-free") "fixture model present"
$origBash = ConvertTo-RuleMap $original.permission.bash
Assert-True ([string]$origBash["git diff *"] -eq "allow") "fixture git diff * was allow before merge"

$mergedObj = Merge-OpenCodeConfigObject -Config $original
$mergedText = ConvertTo-OpenCodeJsoncText -ConfigObject $mergedObj
$reparsed = ConvertFrom-Jsonc -Text $mergedText
Assert-True ([string]$reparsed.model -eq "opencode/deepseek-v4.1-flash-free") "merge keeps model"
Assert-True ([string]$reparsed.small_model -eq "opencode/deepseek-v4.1-flash-free") "merge keeps small_model"
Assert-True ([string]$reparsed.'$schema' -eq "https://opencode.ai/config.json") "merge keeps schema"

$mb = ConvertTo-RuleMap $reparsed.permission.bash
$mk = @($mb.Keys)
Assert-True ([string]$mb["git diff"] -eq "allow") "merged git diff still allow"
Assert-True ([string]$mb["git log"] -eq "allow") "merged git log still allow"
Assert-True ([string]$mb["git diff *"] -eq "ask") "merged git diff * became ask"
Assert-True ([string]$mb["git log *"] -eq "ask") "merged git log * became ask"
Assert-True ($mk.IndexOf("git diff *") -gt $mk.IndexOf("git diff")) "merged git diff * after git diff"
Assert-True ($mk.IndexOf("git log *") -gt $mk.IndexOf("git log")) "merged git log * after git log"
Assert-True ($mk[0] -eq "*") "merged bash starts with *"

$mFirstDeny = -1
$mLastOther = -1
for ($i = 0; $i -lt $mk.Count; $i++) {
  if ([string]$mb[$mk[$i]] -eq "deny") {
    if ($mFirstDeny -lt 0) { $mFirstDeny = $i }
  } else {
    $mLastOther = $i
  }
}
Assert-True ($mFirstDeny -gt $mLastOther) "merged: all denies come after all allow/ask rules" ("firstDeny=$mFirstDeny lastOther=$mLastOther")
Assert-True ([string]$mb["*--no-index*"] -eq "deny") "merged adds --no-index deny"
Assert-True ($mk.IndexOf("*--no-index*") -gt $mk.IndexOf("git diff *")) "--no-index deny after git diff *"
Assert-True ([string]$mb["ls"] -eq "allow") "merged exact ls is allow"
Assert-True ([string]$mb["dir"] -eq "allow") "merged exact dir is allow"
Assert-True (-not $mb.Contains("ls *")) "merged config has no ls * allow"
Assert-True (-not $mb.Contains("dir *")) "merged config has no dir * allow"
Assert-True (-not $mb.Contains("git status *")) "merged config has no git status * allow"

# User custom allow and a custom setting are kept
$customText = @'
{
  "model": "provider/my-safe-model",
  "permission": {
    "bash": {
      "*": "ask",
      "echo hello": "allow",
      "git diff *": "allow"
    }
  }
}
'@
$custom = ConvertFrom-Jsonc -Text $customText
$cm = Merge-OpenCodeConfigObject -Config $custom
$cr = ConvertFrom-Jsonc -Text (ConvertTo-OpenCodeJsoncText -ConfigObject $cm)
Assert-True ([string]$cr.model -eq "provider/my-safe-model") "custom model kept"
$cb = ConvertTo-RuleMap $cr.permission.bash
$ck = @($cb.Keys)
Assert-True ([string]$cb["echo hello"] -eq "allow") "custom allow kept"
Assert-True ([string]$cb["git diff *"] -eq "ask") "custom git diff * forced to ask"
Assert-True ($ck.IndexOf("echo hello") -lt $ck.IndexOf("*--no-index*")) "custom allow stays before denies"

# Empty merge / create path: no model forced, denies last
$fresh = Merge-OpenCodeConfigObject -Config $null
$freshText = ConvertTo-OpenCodeJsoncText -ConfigObject $fresh
$fp = ConvertFrom-Jsonc -Text $freshText
Assert-True ($null -eq $fp.PSObject.Properties["model"] -or [string]$fp.model -eq "") "fresh merge does not set a model"
$fb = ConvertTo-RuleMap $fp.permission.bash
$fk = @($fb.Keys)
$fFirstDeny = -1
$fLastOther = -1
for ($i = 0; $i -lt $fk.Count; $i++) {
  if ([string]$fb[$fk[$i]] -eq "deny") {
    if ($fFirstDeny -lt 0) { $fFirstDeny = $i }
  } else { $fLastOther = $i }
}
Assert-True ($fFirstDeny -gt $fLastOther) "fresh merge denies last"


# Bare allows only: wildcard allows must not match compound commands
$freshRules = ConvertTo-RuleMap (Merge-OpenCodeConfigObject -Config $null).permission.bash
Assert-True (-not $freshRules.Contains("ls *")) "fresh merge has no ls * allow"
Assert-True ([string]$freshRules["ls"] -eq "allow") "fresh merge keeps exact ls allow"
function Assert-BashDecision {
  param([string]$Command, [string]$Expected, [string]$Name)
  $got = Resolve-OpenCodeBashPermission -RuleMap $freshRules -Command $Command
  Assert-True ($got.Decision -eq $Expected) $Name ("expected $Expected for [$Command], got $($got.Decision) via $($got.Pattern)")
}
Assert-BashDecision "ls" "allow" "exact ls is allow"
Assert-BashDecision "dir" "allow" "exact dir is allow"
Assert-BashDecision "pwd" "allow" "exact pwd is allow"
Assert-BashDecision "git status" "allow" "exact git status is allow"
Assert-BashDecision "ls foo; whoami" "ask" "ls foo; whoami is ask (separator)"
Assert-BashDecision "ls foo && whoami" "ask" "ls foo && whoami is ask"
Assert-BashDecision "ls foo | whoami" "ask" "ls foo | whoami is ask"
Assert-BashDecision "ls `$(whoami)" "ask" "ls subexpression is ask"
Assert-BashDecision "ls > out.txt" "ask" "ls redirection is ask"
Assert-BashDecision "ls 2>&1" "ask" "ls 2>&1 is ask"
Assert-BashDecision "ls foo; python -c Get-Secret" "ask" "ls then interpreter is ask"
Assert-BashDecision "dir /s | powershell -Command Get-Content env:PATH" "deny" "dir piped to interpreter hits env deny or ask"

# Loopback / CDP alternate forms are denied
Assert-BashDecision "curl.exe http://[::1]:9222/json/list" "deny" "::1 CDP URL is deny"
Assert-BashDecision "curl.exe http://::1:9222/json/list" "deny" "::1 without brackets is deny"
Assert-BashDecision "curl.exe http://localhost.:9222/json/list" "deny" "localhost. trailing-dot is deny"
Assert-BashDecision "curl.exe http://127.0.0.2:9222/json/list" "deny" "127.0.0.2 is deny"
Assert-BashDecision "curl.exe http://127.1:80/" "deny" "127.1 shorthand is deny"
Assert-BashDecision "curl.exe http://2130706433:9222/" "deny" "dword loopback is deny"
Assert-BashDecision "curl.exe http://0x7f000001:9222/" "deny" "hex loopback is deny"
Assert-BashDecision "curl.exe http://0177.0.0.1:9222/" "deny" "octal loopback is deny"
Assert-BashDecision "Get-Content `$env:OPENAI_API_KEY" "deny" "`$env: read is deny"
Assert-BashDecision "Get-Item env:OPENAI_API_KEY" "deny" "Get-Item env: is deny"

# Re-merge removes kit-added wildcard allows from an earlier config
$oldKitText = @'
{
  "permission": {
    "bash": {
      "*": "ask",
      "ls": "allow",
      "ls *": "allow",
      "dir *": "allow",
      "git status *": "allow",
      "echo hello": "allow"
    }
  }
}
'@
$oldKit = ConvertFrom-Jsonc -Text $oldKitText
$remerged = Merge-OpenCodeConfigObject -Config $oldKit
$rb = ConvertTo-RuleMap $remerged.permission.bash
Assert-True (-not $rb.Contains("ls *")) "re-merge removes ls * allow"
Assert-True (-not $rb.Contains("dir *")) "re-merge removes dir * allow"
Assert-True (-not $rb.Contains("git status *")) "re-merge removes git status * allow"
Assert-True ([string]$rb["ls"] -eq "allow") "re-merge keeps exact ls allow"
Assert-True ([string]$rb["echo hello"] -eq "allow") "re-merge keeps a user allow by default"
$flags = @(Get-TbvPreExistingAllowKeys -Existing (ConvertTo-RuleMap (ConvertFrom-Jsonc -Text $oldKitText).permission.bash))
Assert-True ($flags -contains "echo hello") "pre-existing allow echo hello is flagged"
Assert-True ($flags -notcontains "ls *") "retired ls * is not flagged as a kept allow"

$strictObj = Merge-OpenCodeConfigObject -Config $oldKit -Strict
$sbash = ConvertTo-RuleMap $strictObj.permission.bash
Assert-True ([string]$sbash["echo hello"] -eq "ask") "-Strict demotes pre-existing echo hello allow to ask"
Assert-True ([string]$sbash["ls"] -eq "allow") "-Strict keeps kit exact ls allow"

# V2 permissions get default "*": ask first, denies last
$v2text = @'
{
  "permissions": [
    { "action": "shell", "resource": "python *", "effect": "allow" }
  ]
}
'@
$v2 = Merge-OpenCodeConfigObject -Config (ConvertFrom-Jsonc -Text $v2text)
$v2list = @($v2["permissions"])
Assert-True ($v2list.Count -gt 2) "V2 merge keeps items and adds kit rules"
$first = $v2list[0]
Assert-True (([string](Get-V2ItemField $first "action") -eq "shell") -and ([string](Get-V2ItemField $first "resource") -eq "*") -and ([string](Get-V2ItemField $first "effect") -eq "ask")) "V2 default shell * is ask first"
$last = $v2list[$v2list.Count - 1]
Assert-True ([string](Get-V2ItemField $last "effect") -eq "deny") "V2 last rule is deny"
$v2strict = Merge-OpenCodeConfigObject -Config (ConvertFrom-Jsonc -Text $v2text) -Strict
$foundDemoted = $false
foreach ($item in @($v2strict["permissions"])) {
  if ((Get-V2ItemField $item "resource") -eq "python *" -and (Get-V2ItemField $item "effect") -eq "ask") { $foundDemoted = $true }
}
Assert-True $foundDemoted "V2 -Strict demotes python * allow to ask"

# apply-config DryRun against a temp copy should not write
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("tbv-test-" + [guid]::NewGuid().ToString("n"))
$configDir = Join-Path $tempRoot ".config"
$configDir = Join-Path $configDir "opencode"
New-Item -ItemType Directory -Force -Path $configDir | Out-Null
$cfg = Join-Path $configDir "opencode.jsonc"
[System.IO.File]::Copy($originalPath, $cfg, $true)
$beforeHash = Get-FileHashHex -Path $cfg -Algorithm MD5
$apply = Join-Path $kit "apply-config.ps1"
& $apply -ConfigPath $cfg -KitRoot $kit -DryRun | Out-Null
$afterHash = Get-FileHashHex -Path $cfg -Algorithm MD5
Assert-True ($beforeHash -eq $afterHash) "DryRun does not change the file"
$bak = @(Get-ChildItem -LiteralPath $configDir -Filter "opencode.jsonc.bak-*")
Assert-True ($bak.Count -eq 0) "DryRun does not write a backup"

# Real apply then revert
& $apply -ConfigPath $cfg -KitRoot $kit | Out-Null
$midHash = Get-FileHashHex -Path $cfg -Algorithm MD5
Assert-True ($midHash -ne $beforeHash) "apply writes a new file"
$applied = ConvertFrom-Jsonc -Text ([System.IO.File]::ReadAllText($cfg))
Assert-True ([string]$applied.model -eq "opencode/deepseek-v4.1-flash-free") "applied file kept fixture model"
Assert-True ([string](ConvertTo-RuleMap $applied.permission.bash)["git diff *"] -eq "ask") "applied file has git diff * ask"
$bak = @(Get-ChildItem -LiteralPath $configDir -Filter "opencode.jsonc.bak-*")
Assert-True ($bak.Count -eq 1) "apply wrote one backup"

$revert = Join-Path $kit "revert-config.ps1"
& $revert -ConfigPath $cfg -KitRoot $kit | Out-Null
$revHash = Get-FileHashHex -Path $cfg -Algorithm MD5
Assert-True ($revHash -eq $beforeHash) "revert restores original bytes"

# create-new path
$cfg2 = Join-Path $configDir "fresh.jsonc"
& $apply -ConfigPath $cfg2 -KitRoot $kit | Out-Null
Assert-True (Test-Path -LiteralPath $cfg2) "apply creates a missing file"
$created = ConvertFrom-Jsonc -Text ([System.IO.File]::ReadAllText($cfg2))
Assert-True ($null -eq $created.PSObject.Properties["model"]) "created example has no model"
& $revert -ConfigPath $cfg2 -KitRoot $kit | Out-Null
Assert-True (-not (Test-Path -LiteralPath $cfg2)) "revert removes a kit-created file"

# OpenCode 1.19.6 env substitution: example and merger output must load
$envKey = '*${env:*'
Assert-True $bash.Contains($envKey) 'example parses PowerShell env: key'
Assert-True ($exampleText -notmatch '\{env:') 'example JSONC has no raw env token'
Assert-True $exampleText.Contains('*$\u007Benv:*') 'example writes unclosed brace as unicode escape' 
$exampleGate = Test-OpenCodeJsoncText -Text $exampleText
Assert-True ([bool]$exampleGate.Ok) 'example passes OpenCode load-path check' $exampleGate.Reason

$mergedText = ConvertTo-OpenCodeJsoncText -ConfigObject (Merge-OpenCodeConfigObject -Config $example)
Assert-True ($mergedText -notmatch '\{env:') 'merger output has no raw env token'
Assert-True $mergedText.Contains('*$\u007Benv:*') 'merger writes unclosed brace as unicode escape' 
$mergedGate = Test-OpenCodeJsoncText -Text $mergedText
Assert-True ([bool]$mergedGate.Ok) 'merger output passes OpenCode load-path check' $mergedGate.Reason
$mergedParsed = ConvertFrom-Jsonc -Text $mergedText
$mergedBash = ConvertTo-RuleMap (Get-ObjectValue (Get-ObjectValue $mergedParsed "permission") "bash")
Assert-True $mergedBash.Contains($envKey) 'merged JSONC still has the env deny key'

# Well-formed env:NAME tokens in user config are preserved (not escaped)
$userEnvText = '{ "model": "{env:OPENCODE_MODEL}", "permission": { "bash": { "*": "allow" } } }'
$userMerged = ConvertTo-OpenCodeJsoncText -ConfigObject (Merge-OpenCodeConfigObject -Config (ConvertFrom-Jsonc -Text $userEnvText))
Assert-True $userMerged.Contains('{env:OPENCODE_MODEL}') 'well-formed env token is preserved'
Assert-True ($userMerged -notmatch '\\u007Benv:OPENCODE_MODEL') 'well-formed env token is not unicode-escaped'
$userGate = Test-OpenCodeJsoncText -Text $userMerged
Assert-True ([bool]$userGate.Ok) 'preserved env token still parses after substitution' $userGate.Reason

# Regression: an unclosed env token from an earlier kit build fails the gate; re-merge repairs it
$brokenList = New-Object System.Collections.Generic.List[string]
$brokenFixDir = Join-Path $PSScriptRoot "fixtures"
$brokenList.Add((Join-Path $brokenFixDir "opencode.jsonc.broken-env-substitution"))
foreach ($brokenPath in $brokenList) {
  $brokenText = [System.IO.File]::ReadAllText($brokenPath)
  $brokenGate = Test-OpenCodeJsoncText -Text $brokenText
  Assert-True (-not [bool]$brokenGate.Ok) ("broken file fails OpenCode load-path check: " + [IO.Path]::GetFileName($brokenPath))
  $repairedText = ConvertTo-OpenCodeJsoncText -ConfigObject (Merge-OpenCodeConfigObject -Config (ConvertFrom-Jsonc -Text $brokenText))
  $repairedGate = Test-OpenCodeJsoncText -Text $repairedText
  Assert-True ([bool]$repairedGate.Ok) ("re-merge of broken file passes load-path check: " + [IO.Path]::GetFileName($brokenPath)) $repairedGate.Reason
  $repairedBash = ConvertTo-RuleMap (Get-ObjectValue (Get-ObjectValue (ConvertFrom-Jsonc -Text $repairedText) "permission") "bash")
  Assert-True $repairedBash.Contains($envKey) ('re-merge keeps the env deny key: ' + [IO.Path]::GetFileName($brokenPath))
  Assert-True ($repairedText -notmatch '\{env:') ('re-merge has no raw env token: ' + [IO.Path]::GetFileName($brokenPath))
}

# ConvertFrom-Json fallback on the small fixture (no case-variant keys).
# The full kit config cannot use ConvertFrom-Json: it has both *devtools*
# and *DevTools*, and ConvertFrom-Json is case-insensitive.
$miniBroken = [System.IO.File]::ReadAllText((Join-Path $brokenFixDir "opencode.jsonc.broken-env-substitution"))
$miniBrokenExpand = Get-OpenCodeEnvSubstitutedText -Text $miniBroken
$miniBrokenJsonFailed = $false
try {
  $null = (Strip-JsoncComments -Text $miniBrokenExpand) | ConvertFrom-Json
} catch {
  $miniBrokenJsonFailed = $true
}
Assert-True $miniBrokenJsonFailed 'ConvertFrom-Json rejects the unclosed env fixture after substitution'
# Escape only the unclosed token; do not expand into the full kit deny
# list, which has *devtools* / *DevTools* and cannot use ConvertFrom-Json.
$miniRepaired = $miniBroken.Replace('"*${env:*"', '"*$\u007Benv:*"')
$miniRepairedExpand = Get-OpenCodeEnvSubstitutedText -Text $miniRepaired
$miniRepairedObj = $null
try {
  $miniRepairedObj = (Strip-JsoncComments -Text $miniRepairedExpand) | ConvertFrom-Json
} catch {
  $miniRepairedObj = $null
}
Assert-True ($null -ne $miniRepairedObj) 'ConvertFrom-Json accepts the repaired fixture after substitution'

# apply-config must refuse a broken example and leave the target untouched
$brokenExampleKit = Join-Path $tempRoot "broken-kit"
New-Item -ItemType Directory -Force -Path $brokenExampleKit | Out-Null
[System.IO.File]::Copy((Join-Path $brokenFixDir "opencode.jsonc.broken-env-substitution"), (Join-Path $brokenExampleKit "opencode.jsonc"), $true)
$refusedPath = Join-Path $configDir "must-not-write.jsonc"
$refusedThrew = $false
try {
  & $apply -ConfigPath $refusedPath -KitRoot $brokenExampleKit 2>&1 | Out-Null
} catch {
  $refusedThrew = $true
}
Assert-True $refusedThrew "apply-config throws when merged JSONC would not load in OpenCode"
Assert-True (-not (Test-Path -LiteralPath $refusedPath)) "apply-config does not write a file OpenCode would reject"
$createdMarkers = @(Get-ChildItem -LiteralPath $configDir -Filter "must-not-write.jsonc.tbv-created-*")
Assert-True ($createdMarkers.Count -eq 0) "apply-config does not write a created-new marker on a refused write"

# apply-config against the real kit example must write a file OpenCode can load
$okCfg = Join-Path $configDir "loadpath-ok.jsonc"
& $apply -ConfigPath $okCfg -KitRoot $kit | Out-Null
$appliedText = [System.IO.File]::ReadAllText($okCfg)
$appliedGate = Test-OpenCodeJsoncText -Text $appliedText
Assert-True ([bool]$appliedGate.Ok) "applied config passes OpenCode load-path check" $appliedGate.Reason
Assert-True $appliedText.Contains('*$\u007Benv:*') 'applied config writes unclosed brace as unicode escape' 

# Node jsonc-parser check (same parser OpenCode 1.19.6 uses) when node is present
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if ($null -ne $nodeCmd) {
  $checker = Join-Path $PSScriptRoot "check-opencode-jsonc.js"
  $parserPrefix = Join-Path $tempRoot "jsonc-parser-prefix"
  $parserReady = $false
  foreach ($modRoot in @($env:TBV_JSONC_PARSER_DIR, "/tmp/jsonc-check", $parserPrefix)) {
    if ([string]::IsNullOrWhiteSpace($modRoot)) { continue }
    $modJs = Join-Path $modRoot "node_modules"
    $modJs = Join-Path $modJs "jsonc-parser"
    if (Test-Path -LiteralPath $modJs) {
      $env:TBV_JSONC_PARSER_DIR = $modRoot
      $parserReady = $true
      break
    }
  }
  if (-not $parserReady) {
    $npmCmd = Get-Command npm -ErrorAction SilentlyContinue
    if ($null -ne $npmCmd) {
      New-Item -ItemType Directory -Force -Path $parserPrefix | Out-Null
      & $npmCmd.Source install --prefix $parserPrefix --silent --no-fund --no-audit jsonc-parser | Out-Null
      $modJs = Join-Path $parserPrefix "node_modules"
      $modJs = Join-Path $modJs "jsonc-parser"
      if (Test-Path -LiteralPath $modJs) {
        $env:TBV_JSONC_PARSER_DIR = $parserPrefix
        $parserReady = $true
      }
    }
  }
  if ($parserReady) {
    $prevNative = $PSNativeCommandUseErrorActionPreference
    $PSNativeCommandUseErrorActionPreference = $false
    try {
      & $nodeCmd.Source $checker $examplePath $okCfg | Out-Null
      Assert-True ($LASTEXITCODE -eq 0) 'node jsonc-parser accepts example and applied config after env substitution'
      $brokenNode = $brokenList[0]
      & $nodeCmd.Source $checker $brokenNode | Out-Null
      Assert-True ($LASTEXITCODE -ne 0) 'node jsonc-parser rejects the unclosed env fixture after substitution' 
    } finally {
      $PSNativeCommandUseErrorActionPreference = $prevNative
    }
  } else {
    Write-Host "SKIP  node jsonc-parser check (jsonc-parser module not installed)"
  }
} else {
  Write-Host "SKIP  node jsonc-parser check (node not on PATH)"
}

Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host ("Merge/config tests: {0} passed, {1} failed" -f $passed, $failed)
if ($failed -gt 0) { exit 1 }
exit 0
