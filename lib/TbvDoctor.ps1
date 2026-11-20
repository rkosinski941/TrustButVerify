# TbvDoctor.ps1
# Pure helpers for doctor.ps1 and update-manifest.ps1 (kept here so they
# can be unit tested on any OS). ASCII only. Dot-source after
# WatchCommon.ps1 and TbvConfigMatcher.ps1.

Set-StrictMode -Version 1

function New-TbvCheck {
  param([string]$Name, [ValidateSet("PASS", "WARN", "FAIL", "SKIP")][string]$Status, [string]$Detail = "")
  return [pscustomobject]@{ Check = $Name; Status = $Status; Detail = $Detail }
}

function Get-TbvDoctorExitCode {
  # 0 all PASS/SKIP, 1 at least one WARN, 2 at least one FAIL.
  param($Checks)
  $code = 0
  foreach ($c in @($Checks)) {
    if ($c.Status -eq "FAIL") { return 2 }
    if ($c.Status -eq "WARN") { $code = 1 }
  }
  return $code
}

function Format-TbvDoctorTable {
  param($Checks)
  $lines = New-Object System.Collections.Generic.List[string]
  $w = 10
  foreach ($c in @($Checks)) { if ($c.Check.Length -gt $w) { $w = $c.Check.Length } }
  $lines.Add(("{0}  {1}  {2}" -f "STATUS", "CHECK".PadRight($w), "DETAIL"))
  $lines.Add(("{0}  {1}  {2}" -f "------", ("-" * $w), "------"))
  foreach ($c in @($Checks)) {
    $lines.Add(("{0}  {1}  {2}" -f $c.Status.PadRight(6), $c.Check.PadRight($w), $c.Detail))
  }
  return ,$lines.ToArray()
}

# --- Kit manifest -----------------------------------------------------------

function Get-TbvManifestFileList {
  # Kit files whose hashes go in kit-manifest.json: everything a user runs
  # or installs. Tests, docs and the manifest itself are excluded.
  param([string]$KitRoot)
  $out = New-Object System.Collections.Generic.List[string]
  $root = (Resolve-Path -LiteralPath $KitRoot).Path
  $files = Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object {
    $rel = $_.FullName.Substring($root.Length).TrimStart('\', '/').Replace('\', '/')
    -not ($rel -match '^(tests|docs|sysmon-dist|reports|logs|LICENSES)/' -or $rel -match '^\.git/' -or $rel -match '(^|/)\.' -or
      $rel -eq "kit-manifest.json" -or $rel -match '\.(md|zip|bak-.*)$' -or $rel -eq "LICENSE")
  }
  foreach ($f in $files) {
    $rel = $f.FullName.Substring($root.Length).TrimStart('\', '/').Replace('\', '/')
    if ($rel -match '\.(ps1|cmd|js|jsonc|json|xml)$') { $out.Add($rel) }
  }
  return @($out | Sort-Object)
}

function Get-TbvNormalizedSha256 {
  # SHA-256 of the file with CRLF folded to LF, so a checkout with
  # different line endings (git autocrlf, zip download) still matches.
  param([string]$Path)
  $bytes = [System.IO.File]::ReadAllBytes($Path)
  $ms = New-Object System.IO.MemoryStream
  for ($i = 0; $i -lt $bytes.Length; $i++) {
    if ($bytes[$i] -eq 13 -and ($i + 1) -lt $bytes.Length -and $bytes[$i + 1] -eq 10) { continue }
    $ms.WriteByte($bytes[$i])
  }
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $h = $sha.ComputeHash($ms.ToArray())
  } finally {
    $sha.Dispose()
  }
  return (($h | ForEach-Object { $_.ToString("x2") }) -join "")
}

function New-TbvManifestObject {
  param([string]$KitRoot, [string[]]$PluginHistory = @())
  $files = [ordered]@{}
  foreach ($rel in (Get-TbvManifestFileList -KitRoot $KitRoot)) {
    $files[$rel] = Get-TbvNormalizedSha256 -Path (Join-Path $KitRoot $rel)
  }
  return [ordered]@{
    version       = 1
    algorithm     = "SHA256 of file content with CRLF folded to LF"
    files         = $files
    pluginHistory = @($PluginHistory | Where-Object { $_ } | Select-Object -Unique)
  }
}

function Compare-TbvManifest {
  # Returns objects {Path, Problem} for missing, changed, and unlisted files.
  param($Manifest, [string]$KitRoot)
  $problems = New-Object System.Collections.Generic.List[object]
  $listed = @{}
  foreach ($p in $Manifest.files.PSObject.Properties) {
    $listed[$p.Name] = $true
    $full = Join-Path $KitRoot $p.Name
    if (-not (Test-Path -LiteralPath $full)) {
      $problems.Add([pscustomobject]@{ Path = $p.Name; Problem = "missing" })
      continue
    }
    if ((Get-TbvNormalizedSha256 -Path $full) -ne ([string]$p.Value).ToLowerInvariant()) {
      $problems.Add([pscustomobject]@{ Path = $p.Name; Problem = "changed" })
    }
  }
  foreach ($rel in (Get-TbvManifestFileList -KitRoot $KitRoot)) {
    if (-not $listed.ContainsKey($rel)) { $problems.Add([pscustomobject]@{ Path = $rel; Problem = "not in manifest" }) }
  }
  return $problems.ToArray()
}

# --- Permission rules -------------------------------------------------------

function Get-TbvDoctorCanaries {
  # Commands with a known expected decision under the kit rules.
  return @(
    [pscustomobject]@{ Command = "curl http://127.0.0.1:4096/session"; Expect = "deny" },
    [pscustomobject]@{ Command = "curl.exe http://localhost:9222/json/list"; Expect = "deny" },
    [pscustomobject]@{ Command = "printenv"; Expect = "deny" },
    [pscustomobject]@{ Command = "cat ~/.ssh/id_rsa"; Expect = "deny" },
    [pscustomobject]@{ Command = "echo `${env:OPENAI_API_KEY}"; Expect = "deny" },
    [pscustomobject]@{ Command = "schtasks /create /tn x /tr calc"; Expect = "deny" },
    [pscustomobject]@{ Command = "npm run build"; Expect = "ask" },
    [pscustomobject]@{ Command = "git status"; Expect = "allow" }
  )
}

function Test-TbvRuleOrder {
  # Last matching rule wins in OpenCode 1.19.6, so the catch-all "*" must
  # come first and no allow may follow a deny. Allow rules must be exact
  # commands (no * or ?), because a wildcard allow can swallow a chained
  # command on shells the parser does not split.
  # $Rules: ordered list of {Pattern, Action}. Returns {Status, Problems}.
  param($Rules)
  $problems = New-Object System.Collections.Generic.List[string]
  $list = @($Rules)
  if ($list.Count -eq 0) {
    return [pscustomobject]@{ Status = "FAIL"; Problems = @("no bash rules found") }
  }
  if ($list[0].Pattern -ne "*") { $problems.Add("the catch-all '*' rule is not first") }
  $star = @($list | Where-Object { $_.Pattern -eq "*" })
  if ($star.Count -gt 0 -and $star[-1].Action -eq "allow") { $problems.Add("the catch-all '*' rule is allow") }
  $seenDeny = $false
  $denyCount = 0
  foreach ($r in $list) {
    if ($r.Action -eq "deny") { $seenDeny = $true; $denyCount++ }
    if ($r.Action -eq "allow") {
      if ($seenDeny) { $problems.Add(("allow rule after a deny rule: '{0}'" -f $r.Pattern)) }
      if ($r.Pattern -ne "*" -and ($r.Pattern.Contains("*") -or $r.Pattern.Contains("?"))) {
        $problems.Add(("wildcard allow rule: '{0}'" -f $r.Pattern))
      }
    }
  }
  if ($denyCount -eq 0) { $problems.Add("no deny rules found") }
  $status = "PASS"
  if ($problems.Count -gt 0) { $status = "FAIL" }
  return [pscustomobject]@{ Status = $status; Problems = $problems.ToArray(); DenyCount = $denyCount }
}

function ConvertTo-TbvRuleList {
  # PSCustomObject from ConvertFrom-Json(c) -> ordered {Pattern, Action}.
  param($Obj)
  $out = New-Object System.Collections.Generic.List[object]
  if ($null -eq $Obj) { return ,$out.ToArray() }
  if ($Obj -is [string]) {
    $out.Add([pscustomobject]@{ Pattern = "*"; Action = $Obj })
    return ,$out.ToArray()
  }
  if ($Obj -is [System.Collections.IDictionary]) {
    foreach ($k in $Obj.Keys) { $out.Add([pscustomobject]@{ Pattern = [string]$k; Action = [string]$Obj[$k] }) }
  } else {
    foreach ($p in $Obj.PSObject.Properties) { $out.Add([pscustomobject]@{ Pattern = $p.Name; Action = [string]$p.Value }) }
  }
  return ,$out.ToArray()
}

function Test-TbvCanaries {
  param($Rules)
  $map = [ordered]@{}
  foreach ($r in @($Rules)) { $map[$r.Pattern] = $r.Action }
  $bad = New-Object System.Collections.Generic.List[string]
  foreach ($c in (Get-TbvDoctorCanaries)) {
    $d = (Resolve-OpenCode1196BashDecision -RuleMap $map -Command $c.Command).Decision
    if ($d -ne $c.Expect) { $bad.Add(("'{0}' -> {1} (expected {2})" -f $c.Command, $d, $c.Expect)) }
  }
  return $bad.ToArray()
}

# --- Plugin heartbeat --------------------------------------------------------

function Test-TbvPluginHeartbeat {
  # $Heartbeat: parsed plugin-heartbeat.json or $null. $InstalledAt: the
  # plugin file's LastWriteTimeUtc. Returns {Status, Detail}.
  param($Heartbeat, [datetime]$InstalledAt, [string]$ExpectedVersion)
  if ($null -eq $Heartbeat) {
    return [pscustomobject]@{ Status = "WARN"; Detail = "no heartbeat yet: start OpenCode once, then re-run doctor" }
  }
  $t = [datetime]::MinValue
  $rawTime = $Heartbeat.time
  if ($rawTime -is [datetime]) {
    # PowerShell 7 ConvertFrom-Json turns ISO strings into DateTime already.
    $t = $rawTime.ToUniversalTime()
  } else {
    try {
      $t = ([datetimeoffset]::Parse([string]$rawTime, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)).UtcDateTime
    } catch { }
  }
  $api = [string]$Heartbeat.api
  $mode = [string]$Heartbeat.mode
  $ver = [string]$Heartbeat.version
  if ($t -lt $InstalledAt.AddSeconds(-5)) {
    return [pscustomobject]@{ Status = "WARN"; Detail = ("last heartbeat {0:u} is older than the installed plugin; restart OpenCode" -f $t) }
  }
  if ($ExpectedVersion -and $ver -ne $ExpectedVersion) {
    return [pscustomobject]@{ Status = "WARN"; Detail = ("heartbeat version {0} differs from kit plugin {1}; restart OpenCode" -f $ver, $ExpectedVersion) }
  }
  $hbOptErr = $false
  if ($Heartbeat.PSObject.Properties["optionsError"]) { $hbOptErr = [bool]$Heartbeat.optionsError }
  if ($hbOptErr) {
    return [pscustomobject]@{ Status = "WARN"; Detail = "plugin loaded, but trustbutverify-guard.json is invalid (defaults in use)" }
  }
  if ($mode -eq "warn") {
    return [pscustomobject]@{ Status = "WARN"; Detail = ("plugin loaded (api {0}) in WARN mode: it logs but does not block" -f $api) }
  }
  return [pscustomobject]@{ Status = "PASS"; Detail = ("plugin loaded (api {0}, mode {1}, {2:u})" -f $api, $mode, $t) }
}

function Get-TbvPluginSourceVersion {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return "" }
  $m = [regex]::Match([System.IO.File]::ReadAllText($Path), 'TBV_PLUGIN_VERSION\s*=\s*"([^"]+)"')
  if ($m.Success) { return $m.Groups[1].Value }
  return ""
}

# --- `opencode debug config` output ------------------------------------------
# OpenCode 1.x prints one merged config object (permission.bash is an
# ordered map). OpenCode 2.x prints a list of documents; each config
# document has info.permissions = [{action, resource, effect}] in order,
# with the bash tool's action named "shell".

function Get-TbvBashRulesFromDebugConfig {
  param($DebugConfig)
  $out = New-Object System.Collections.Generic.List[object]
  if ($null -eq $DebugConfig) { return $out.ToArray() }
  $isList = ($DebugConfig -is [System.Array]) -or ($DebugConfig -is [System.Collections.IList] -and -not ($DebugConfig -is [System.Collections.IDictionary]))
  if (-not $isList) {
    foreach ($r in (ConvertTo-TbvRuleList (Get-ObjectValue (Get-ObjectValue $DebugConfig "permission") "bash"))) { $out.Add($r) }
    return $out.ToArray()
  }
  foreach ($doc in @($DebugConfig)) {
    $info = Get-ObjectValue $doc "info"
    if ($null -eq $info) { continue }
    $perms = Get-ObjectValue $info "permissions"
    if ($null -eq $perms) { continue }
    foreach ($p in @($perms)) {
      $action = [string](Get-ObjectValue $p "action")
      if ($action -ne "shell" -and $action -ne "bash") { continue }
      $out.Add([pscustomobject]@{ Pattern = [string](Get-ObjectValue $p "resource"); Action = [string](Get-ObjectValue $p "effect") })
    }
  }
  return $out.ToArray()
}

function Test-TbvPluginInDebugConfig {
  # 1.x: the plugin array lists file:///.../plugins/trustbutverify-guard.js.
  # 2.x: a "directory" document names the config folder; the plugin is
  # picked up from its plugins/ subfolder.
  param($DebugConfig, [string]$FileName = "trustbutverify-guard.js")
  if ($null -eq $DebugConfig) { return $false }
  $isList = ($DebugConfig -is [System.Array]) -or ($DebugConfig -is [System.Collections.IList] -and -not ($DebugConfig -is [System.Collections.IDictionary]))
  if (-not $isList) {
    foreach ($p in @(Get-ObjectValue $DebugConfig "plugin")) {
      if (([string]$p).Replace('\', '/').EndsWith("/" + $FileName)) { return $true }
    }
    return $false
  }
  foreach ($doc in @($DebugConfig)) {
    if ([string](Get-ObjectValue $doc "type") -ne "directory") { continue }
    $dir = [string](Get-ObjectValue $doc "path")
    if (-not $dir) { continue }
    foreach ($sub in @("plugins", "plugin")) {
      if (Test-Path -LiteralPath (Join-Path (Join-Path $dir $sub) $FileName)) { return $true }
    }
  }
  return $false
}

function Resolve-TbvRedactedRules {
  # OpenCode 1.19.6 `debug config` masks values whose key looks secret
  # ("*credential*" -> "***"). Fill those from the config file's rules.
  # Returns {Rules, Redacted, Unresolved}.
  param($Rules, $FileRules)
  $fileMap = @{}
  foreach ($r in @($FileRules)) { $fileMap[[string]$r.Pattern] = [string]$r.Action }
  $out = New-Object System.Collections.Generic.List[object]
  $red = 0
  $unres = 0
  foreach ($r in @($Rules)) {
    if ($r.Action -eq "***") {
      $red++
      if ($fileMap.ContainsKey([string]$r.Pattern)) {
        $out.Add([pscustomobject]@{ Pattern = $r.Pattern; Action = $fileMap[[string]$r.Pattern] })
      } else {
        $unres++
        $out.Add([pscustomobject]@{ Pattern = $r.Pattern; Action = "deny" })
      }
    } else {
      $out.Add($r)
    }
  }
  return [pscustomobject]@{ Rules = $out.ToArray(); Redacted = $red; Unresolved = $unres }
}
