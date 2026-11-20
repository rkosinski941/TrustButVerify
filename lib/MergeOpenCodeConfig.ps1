# MergeOpenCodeConfig.ps1
# Merge TrustButVerify restriction rules into an OpenCode permission
# block. Works on Windows PowerShell 5.1 and PowerShell 7.
#
# OpenCode 1.19.x evaluates permission.bash and permission.read maps in
# written order; the LAST matching rule wins. This merger therefore:
#   1. Puts "*": "ask" first in bash (or keeps a user "*": "deny").
#   2. Puts exact bare allow rules next ("git status", "git diff",
#      "git log", "ls", "dir", "pwd"). Wildcard allows such as "ls *"
#      are not used: OpenCode matches the full command text, so "ls *"
#      would allow "ls foo; <anything>".
#   3. Puts "git diff *" and "git log *" as ask AFTER those allows.
#   4. Puts every deny rule last, so denies win.
#
# Tested against OpenCode 1.19.6 (last-match-wins), consistent with
# https://opencode.ai/docs/permissions/ and GitHub issues 24335 and 37935.
#
# The user's model and other settings are left unchanged. Existing user
# allow rules are kept by default and reported. Pass -Strict to demote
# those pre-existing allows to ask. Deny rules are appended last even
# if they also appear earlier, so the last copy wins. Re-merging removes
# retired kit wildcard allows ("ls *", "dir *", "git status *").

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"


function New-CaseSensitiveRuleMap {
  return New-Object System.Collections.Specialized.OrderedDictionary
}

function Set-RuleMapEntry {
  param($Map, [string]$Key, [string]$Value)
  if ($Map.Contains($Key)) { $Map.Remove($Key) }
  [void]$Map.Add($Key, $Value)
}

function Add-RulePairs {
  param($Map, [object[]]$Pairs)
  foreach ($p in $Pairs) {
    Set-RuleMapEntry -Map $Map -Key ([string]$p.K) -Value ([string]$p.V)
  }
  return $Map
}


function Copy-ToCaseSensitiveRuleMap {
  param($Source)
  $map = New-CaseSensitiveRuleMap
  if ($null -eq $Source) { return $map }
  foreach ($k in $Source.Keys) {
    Set-RuleMapEntry -Map $map -Key ([string]$k) -Value ([string]$Source[$k])
  }
  return $map
}

function Get-TbvBashAllowRules {
  $tmp = [ordered]@{
    "git status" = "allow"
    "git diff"   = "allow"
    "git log"    = "allow"
    "ls"         = "allow"
    "dir"        = "allow"
    "pwd"        = "allow"
  }
  return (Copy-ToCaseSensitiveRuleMap -Source $tmp)
}

function Get-TbvRetiredBashAllowRules {
  # Wildcard allows shipped in earlier kit builds. Re-merging removes
  # these keys unless the user set them to deny.
  $tmp = [ordered]@{
    "git status *" = "allow"
    "ls *"         = "allow"
    "dir *"        = "allow"
  }
  return (Copy-ToCaseSensitiveRuleMap -Source $tmp)
}

function Test-OpenCodeGlob {
  # OpenCode-style glob: "*" matches any substring. Matching is against
  # the complete command text. Case-insensitive, as on Windows.
  param([string]$Pattern, [string]$Text)
  if ($null -eq $Pattern) { $Pattern = "" }
  if ($null -eq $Text) { $Text = "" }
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.Append("^")
  foreach ($ch in $Pattern.ToCharArray()) {
    if ($ch -eq [char]"*") {
      [void]$sb.Append(".*")
    } else {
      [void]$sb.Append([regex]::Escape([string]$ch))
    }
  }
  [void]$sb.Append("$")
  return [regex]::IsMatch($Text, $sb.ToString(), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

function Resolve-OpenCodeBashPermission {
  # Last matching rule wins, matching OpenCode 1.19.6.
  param($RuleMap, [string]$Command)
  $decision = ""
  $matched = ""
  if ($null -eq $RuleMap) { return [pscustomobject]@{ Decision = ""; Pattern = "" } }
  foreach ($k in $RuleMap.Keys) {
    if (Test-OpenCodeGlob -Pattern ([string]$k) -Text $Command) {
      $decision = [string]$RuleMap[$k]
      $matched = [string]$k
    }
  }
  return [pscustomobject]@{ Decision = $decision; Pattern = $matched }
}

function Get-TbvPreExistingAllowKeys {
  param($Existing)
  $user = ConvertTo-RuleMap $Existing
  $kit = Get-TbvBashAllowRules
  $retired = Get-TbvRetiredBashAllowRules
  $askAfter = Get-TbvBashAskAfterAllowRules
  $flags = New-Object System.Collections.Generic.List[string]
  foreach ($k in $user.Keys) {
    if ([string]$user[$k] -ne "allow") { continue }
    if ($k -eq "*") { continue }
    if ($kit.Contains($k)) { continue }
    if ($retired.Contains($k)) { continue }
    if ($askAfter.Contains($k)) { continue }
    $flags.Add([string]$k)
  }
  return @($flags)
}


function Get-TbvBashAskAfterAllowRules {
  $tmp = [ordered]@{
    "git diff *" = "ask"
    "git log *"  = "ask"
  }
  return (Copy-ToCaseSensitiveRuleMap -Source $tmp)
}


function Get-TbvBashDenyRules {
  $map = New-CaseSensitiveRuleMap
  $keys = @(
    "*--remote-debugging*",
    "*remote-debugging*",
    "*9222*",
    "*9229*",
    "*9239*",
    "*json/list*",
    "*json/version*",
    "*devtools*",
    "*DevTools*",
    "*127.0.0.1:*",
    "*localhost:*",
    "*localhost.*",
    "*0.0.0.0:*",
    "*127.*",
    "*::1*",
    "*0x7f000001*",
    "*2130706433*",
    "*0177.*",
    "*::ffff:127.*",
    "*::ffff:7f00:*",
    "*ws://*",
    "*WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS*",
    "winget *",
    "*winget install*",
    "*winget.exe install*",
    "choco *",
    "*choco install*",
    "scoop install*",
    "*scoop install*",
    "npm install -g*",
    "*npm i -g*",
    "*npm install --global*",
    "pip install*",
    "*pip install*",
    "*pip3 install*",
    "*py -m pip install*",
    "*python -m pip install*",
    "*Login Data*",
    "*Cookies*",
    "*cookies*",
    "*cmdkey*",
    "*vaultcmd*",
    "*gh auth*",
    "*.env*",
    "*config.toml*",
    "*.ssh*",
    "*id_rsa*",
    "*id_ed25519*",
    "*EBWebView*",
    "*credential*",
    "*Credential*",
    "*.git-credentials*",
    "*.npmrc*",
    "*User Data*",
    "*Local State*",
    "*hosts.yml*",
    "*schtasks*",
    "*Register-ScheduledTask*",
    "*reg add*",
    "*reg.exe add*",
    "*Startup*",
    "*startup*",
    "*CurrentVersion\Run*",
    "*New-ItemProperty*",
    "*Set-ItemProperty*",
    "curl *",
    "*curl *",
    "*curl.exe*",
    "wget *",
    "*wget *",
    "*Invoke-WebRequest*",
    "*invoke-webrequest*",
    "iwr *",
    "*iwr *",
    "*Invoke-RestMethod*",
    "*invoke-restmethod*",
    "irm *",
    "*irm *",
    "*Net.WebClient*",
    "*Start-BitsTransfer*",
    "*certutil*",
    "*--no-index*",
    "*auth.json*",
    "*ConsoleHost_history*",
    "*.grok*",
    "*printenv*",
    "*Get-ChildItem env:*",
    "*gci env:*",
    "*dir env:*",
    "*ls env:*",
    "*[Environment]::GetEnvironmentVariables*",
    '*$env:*',
    # *${env:* catches PowerShell ${env:NAME}. The writer emits
    # \u007B for the unclosed { so OpenCode's {env:} substitution
    # does not eat the rest of the file (OpenCode 1.19.6).
    '*${env:*',
    "*Get-Item env:*",
    "*Get-Item Env:*",
    "*Get-Content env:*",
    "*Get-Content Env:*",
    "*gi env:*",
    "*gc env:*"
  )
  foreach ($k in $keys) {
    Set-RuleMapEntry -Map $map -Key $k -Value "deny"
  }
  return $map
}


function Get-TbvReadDenyRules {
  $tmp = [ordered]@{
    "*.env"                   = "deny"
    "*.env.*"                 = "deny"
    "*Login Data*"            = "deny"
    "*Cookies*"               = "deny"
    "*EBWebView*"             = "deny"
    "*config.toml"            = "deny"
    "*.ssh*"                  = "deny"
    "*credentials*"           = "deny"
    "*.git-credentials"       = "deny"
    "*hosts.yml"              = "deny"
    "*User Data*"             = "deny"
    "*auth.json*"             = "deny"
    "*ConsoleHost_history*"   = "deny"
    "*.npmrc*"                = "deny"
    "*.gitconfig*"            = "deny"
    "*.grok*"                 = "deny"
    "*.aws*"                  = "deny"
    "*.azure*"                = "deny"
  }
  return (Copy-ToCaseSensitiveRuleMap -Source $tmp)
}


function Get-TbvOtherPermissionDefaults {
  $tmp = [ordered]@{
    "edit"                = "ask"
    "webfetch"            = "ask"
    "websearch"           = "ask"
    "external_directory"  = "ask"
    "doom_loop"           = "ask"
  }
  return (Copy-ToCaseSensitiveRuleMap -Source $tmp)
}


function Get-ObjectKeys {
  param($Obj)
  if ($null -eq $Obj) { return @() }
  if ($Obj -is [System.Collections.IDictionary]) {
    return @($Obj.Keys)
  }
  return @($Obj.PSObject.Properties | ForEach-Object { $_.Name })
}

function Get-ObjectValue {
  param($Obj, [string]$Key)
  if ($null -eq $Obj) { return $null }
  if ($Obj -is [System.Collections.IDictionary]) {
    if ($Obj.Contains($Key)) { return $Obj[$Key] }
    return $null
  }
  $prop = $Obj.PSObject.Properties[$Key]
  if ($prop) { return $prop.Value }
  return $null
}

function ConvertTo-RuleMap {
  param($Obj)
  $map = New-CaseSensitiveRuleMap
  if ($null -eq $Obj) { return $map }
  if ($Obj -is [string]) {
    Set-RuleMapEntry -Map $map -Key "*" -Value ([string]$Obj)
    return $map
  }
  foreach ($k in (Get-ObjectKeys $Obj)) {
    $v = Get-ObjectValue $Obj $k
    if ($null -ne $v -and $v -isnot [string] -and $v -isnot [int] -and $v -isnot [bool]) {
      # Nested objects are left to the caller; skip non-scalar rule values here.
      continue
    }
    Set-RuleMapEntry -Map $map -Key ([string]$k) -Value ([string]$v)
  }
  return $map
}

function Merge-BashRules {
  param(
    $Existing,
    [switch]$Strict
  )
  $user = ConvertTo-RuleMap $Existing
  $allows = Get-TbvBashAllowRules
  $retired = Get-TbvRetiredBashAllowRules
  $askAfter = Get-TbvBashAskAfterAllowRules
  $denies = Get-TbvBashDenyRules
  $out = New-CaseSensitiveRuleMap

  # 1. Catch-all first. Keep a user deny for "*" because it is stricter.
  $star = "ask"
  if ($user.Contains("*") -and [string]$user["*"] -eq "deny") { $star = "deny" }
  $out["*"] = $star

  # 2. Allow rules: user first (in their order), then kit exact allows.
  #    Retired wildcard allows and git diff * / git log * stay out.
  foreach ($k in $user.Keys) {
    if ($k -eq "*") { continue }
    if ($askAfter.Contains($k)) { continue }
    if ($retired.Contains($k)) { continue }
    if ([string]$user[$k] -eq "allow") {
      if ($Strict -and -not $allows.Contains($k)) { continue }
      $out[$k] = "allow"
    }
  }
  foreach ($k in $allows.Keys) {
    if (-not $out.Contains($k)) { $out[$k] = $allows[$k] }
  }

  # 3. git diff * and git log * as ask, after the allows.
  foreach ($k in $askAfter.Keys) {
    if ($out.Contains($k)) { $out.Remove($k) }
    $out[$k] = "ask"
  }

  # 4. Other user ask rules, plus pre-existing allows demoted by -Strict.
  foreach ($k in $user.Keys) {
    if ($k -eq "*") { continue }
    if ($retired.Contains($k)) { continue }
    if ($askAfter.Contains($k)) { continue }
    if ($out.Contains($k)) { continue }
    if ([string]$user[$k] -eq "ask") { $out[$k] = "ask" }
    if ($Strict -and [string]$user[$k] -eq "allow" -and -not $allows.Contains($k)) {
      $out[$k] = "ask"
    }
  }

  # 5. User deny rules, then the full kit deny list last so kit denies win.
  foreach ($k in $user.Keys) {
    if ([string]$user[$k] -eq "deny") { $out[$k] = "deny" }
  }
  foreach ($k in $denies.Keys) {
    if ($out.Contains($k)) { $out.Remove($k) }
    $out[$k] = "deny"
  }

  return $out
}

function Merge-ReadRules {
  param($Existing)
  $user = ConvertTo-RuleMap $Existing
  $denies = Get-TbvReadDenyRules
  $out = New-CaseSensitiveRuleMap

  $star = "allow"
  if ($user.Contains("*")) { $star = [string]$user["*"] }
  $out["*"] = $star

  foreach ($k in $user.Keys) {
    if ($k -eq "*") { continue }
    $out[$k] = [string]$user[$k]
  }
  foreach ($k in $denies.Keys) {
    if ($out.Contains($k)) { $out.Remove($k) }
    $out[$k] = "deny"
  }
  return $out
}

function Merge-PermissionBlock {
  param(
    $Existing,
    [switch]$Strict
  )
  $out = New-CaseSensitiveRuleMap
  $defaults = Get-TbvOtherPermissionDefaults

  foreach ($k in (Get-ObjectKeys $Existing)) {
    if ($k -eq "bash" -or $k -eq "read") { continue }
    $out[$k] = Get-ObjectValue $Existing $k
  }
  foreach ($k in $defaults.Keys) {
    if (-not (Test-HasKey $out $k)) { $out[$k] = $defaults[$k] }
  }

  $existingBash = Get-ObjectValue $Existing "bash"
  $existingRead = Get-ObjectValue $Existing "read"
  $out["bash"] = Merge-BashRules -Existing $existingBash -Strict:$Strict
  $out["read"] = Merge-ReadRules -Existing $existingRead
  return $out
}

function Test-HasKey {
  param($Obj, [string]$Key)
  if ($null -eq $Obj) { return $false }
  if ($Obj -is [System.Collections.IDictionary]) { return $Obj.Contains($Key) }
  return ($null -ne $Obj.PSObject.Properties[$Key])
}

function Merge-OpenCodeConfigObject {
  param(
    $Config,
    [switch]$Strict
  )
  if ($null -eq $Config) {
    $Config = [pscustomobject]@{}
  }

  $keys = @(Get-ObjectKeys $Config)
  $out = New-CaseSensitiveRuleMap
  foreach ($k in $keys) {
    $out[$k] = Get-ObjectValue $Config $k
  }

  $perm = $null
  if (Test-HasKey $out "permission") {
    $perm = $out["permission"]
  }
  $out["permission"] = Merge-PermissionBlock -Existing $perm -Strict:$Strict

  # V2 permissions array: default "*": ask first, kit denies last.
  if (Test-HasKey $out "permissions") {
    $out["permissions"] = Add-V2KitDenyRules -Existing (Get-ObjectValue $out "permissions") -Strict:$Strict
  }

  return $out
}

function Get-V2ItemField {
  param($Item, [string]$Name)
  if ($null -eq $Item) { return "" }
  if ($Item -is [System.Collections.IDictionary]) {
    if ($Item.Contains($Name)) { return [string]$Item[$Name] }
    return ""
  }
  $prop = $Item.PSObject.Properties[$Name]
  if ($prop) { return [string]$prop.Value }
  return ""
}

function Add-V2KitDenyRules {
  param(
    $Existing,
    [switch]$Strict
  )
  $list = New-Object System.Collections.Generic.List[object]
  $list.Add([ordered]@{
    action   = "shell"
    resource = "*"
    effect   = "ask"
  })
  if ($Existing) {
    foreach ($item in @($Existing)) {
      $action = Get-V2ItemField $item "action"
      $resource = Get-V2ItemField $item "resource"
      $effect = Get-V2ItemField $item "effect"
      if ($action -eq "shell" -and $resource -eq "*" -and ($effect -eq "ask" -or $effect -eq "deny")) {
        # Default ask is already first. A user "*": deny is stricter
        # and is kept later so it still wins.
        if ($effect -eq "ask") { continue }
      }
      if ($Strict -and $effect -eq "allow") {
        $copy = [ordered]@{}
        foreach ($k in (Get-ObjectKeys $item)) {
          $copy[$k] = Get-ObjectValue $item $k
        }
        $copy["effect"] = "ask"
        $list.Add($copy)
        continue
      }
      $list.Add($item)
    }
  }
  $denies = Get-TbvBashDenyRules
  foreach ($k in $denies.Keys) {
    $list.Add([ordered]@{
      action   = "shell"
      resource = $k
      effect   = "deny"
    })
  }
  $readDenies = Get-TbvReadDenyRules
  foreach ($k in $readDenies.Keys) {
    $list.Add([ordered]@{
      action   = "read"
      resource = $k
      effect   = "deny"
    })
  }
  return $list
}

function Escape-JsonString {
  param([string]$Text)
  if ($null -eq $Text) { return "" }
  $sb = New-Object System.Text.StringBuilder
  $chars = $Text.ToCharArray()
  for ($i = 0; $i -lt $chars.Length; $i++) {
    $ch = $chars[$i]
    $code = [int]$ch
    # OpenCode 1.19.6 substitutes {env:NAME} in the raw file before
    # JSONC parse. An unclosed {env: or {file: in this string would
    # swallow the rest of the file. Escape that brace as \u007B so
    # the parsed key/value is unchanged but substitution does not fire.
    # Well-formed {env:NAME} / {file:path} (a closing } later in this
    # same string) are left as-is so user substitutions still work.
    if ($ch -eq [char]'{') {
      $rest = $Text.Substring($i)
      $isSub = $rest.StartsWith("{env:") -or $rest.StartsWith("{file:")
      if ($isSub -and $Text.IndexOf([char]'}', $i) -lt 0) {
        [void]$sb.Append('\u007B')
        continue
      }
    }
    if ($ch -eq [char]'"') { [void]$sb.Append('\"') }
    elseif ($ch -eq [char]'\') { [void]$sb.Append('\\') }
    elseif ($code -eq 8) { [void]$sb.Append('\b') }
    elseif ($code -eq 9) { [void]$sb.Append('\t') }
    elseif ($code -eq 10) { [void]$sb.Append('\n') }
    elseif ($code -eq 12) { [void]$sb.Append('\f') }
    elseif ($code -eq 13) { [void]$sb.Append('\r') }
    elseif ($code -lt 32) { [void]$sb.Append(('\u{0:x4}' -f $code)) }
    else { [void]$sb.Append($ch) }
  }
  return $sb.ToString()
}

function Get-OpenCodeEnvSubstitutedText {
  # Same first pass as OpenCode 1.19.6 ConfigVariable.substitute:
  # {env:NAME} is replaced with the environment value, or empty, in the
  # raw file text before JSONC is parsed. {file:path} is also
  # substituted by OpenCode; this helper only does the env pass, which
  # is enough to detect a broken file.
  param([string]$Text)
  if ($null -eq $Text) { return "" }
  return [regex]::Replace([string]$Text, '\{env:([^}]+)\}', {
    param($m)
    $name = $m.Groups[1].Value
    $v = [Environment]::GetEnvironmentVariable($name)
    if ($null -eq $v) { return "" }
    return [string]$v
  })
}

function Test-OpenCodeJsoncText {
  # Same load path as OpenCode 1.19.6: substitute {env:NAME} in the
  # raw text, then parse as JSONC. Returns Ok=false when OpenCode
  # would reject the file. Well-formed {env:NAME} tokens are allowed;
  # unclosed ones (a bug in an earlier kit build) make the expanded text invalid.
  param([string]$Text)
  if ($null -eq $Text) { $Text = "" }
  $expanded = Get-OpenCodeEnvSubstitutedText -Text $Text
  # ConvertFrom-Jsonc is case-sensitive, like OpenCode's jsonc-parser.
  # ConvertFrom-Json is not: this kit has both *devtools* and *DevTools*
  # deny keys, and ConvertFrom-Json would reject a valid file.
  try {
    $null = ConvertFrom-Jsonc -Text $expanded
  } catch {
    return [pscustomobject]@{
      Ok       = $false
      Reason   = ("Not valid JSON(C) after OpenCode {{env:}} substitution: {0}" -f $_.Exception.Message)
      Expanded = $expanded
    }
  }
  return [pscustomobject]@{
    Ok       = $true
    Reason   = "ok"
    Expanded = $expanded
  }
}

function ConvertTo-PrettyJson {
  param(
    $Value,
    [int]$Level = 0
  )
  $pad = " " * $Level
  $inner = " " * ($Level + 2)

  if ($null -eq $Value) { return "null" }

  if ($Value -is [bool]) {
    if ($Value) { return "true" } else { return "false" }
  }
  if ($Value -is [int] -or $Value -is [long] -or $Value -is [decimal] -or $Value -is [double]) {
    return ([string]$Value)
  }
  if ($Value -is [string]) {
    return ('"' + (Escape-JsonString $Value) + '"')
  }

  $isList = $false
  if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string] -and $Value -isnot [System.Collections.IDictionary]) {
    $isList = $true
    if ($Value -is [psobject] -and $Value.PSObject.Properties["Keys"] -and $Value.PSObject.Properties["Values"] -and -not ($Value -is [System.Array])) {
      # ordered dictionaries implement IEnumerable of keys; treat as object
      if ($Value -is [System.Collections.IDictionary]) { $isList = $false }
    }
  }
  if ($Value -is [System.Collections.IDictionary]) { $isList = $false }

  if ($isList) {
    $items = @($Value)
    if ($items.Count -eq 0) { return "[]" }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("[")
    for ($i = 0; $i -lt $items.Count; $i++) {
      $chunk = ConvertTo-PrettyJson -Value $items[$i] -Level ($Level + 2)
      $comma = ","
      if ($i -eq $items.Count - 1) { $comma = "" }
      [void]$sb.Append($inner)
      [void]$sb.Append($chunk)
      [void]$sb.AppendLine($comma)
    }
    [void]$sb.Append($pad)
    [void]$sb.Append("]")
    return $sb.ToString()
  }

  $pairs = New-Object System.Collections.Generic.List[object]
  if ($Value -is [System.Collections.IDictionary]) {
    foreach ($k in $Value.Keys) {
      $pairs.Add([pscustomobject]@{ K = [string]$k; V = $Value[$k] })
    }
  } else {
    foreach ($p in $Value.PSObject.Properties) {
      if ($p.Name -in @("Count", "Keys", "Values", "Length")) { continue }
      $pairs.Add([pscustomobject]@{ K = [string]$p.Name; V = $p.Value })
    }
  }

  if ($pairs.Count -eq 0) { return "{}" }
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine("{")
  for ($i = 0; $i -lt $pairs.Count; $i++) {
    $chunk = ConvertTo-PrettyJson -Value $pairs[$i].V -Level ($Level + 2)
    $comma = ","
    if ($i -eq $pairs.Count - 1) { $comma = "" }
    [void]$sb.Append($inner)
    [void]$sb.Append('"')
    [void]$sb.Append((Escape-JsonString $pairs[$i].K))
    [void]$sb.Append('": ')
    [void]$sb.Append($chunk)
    [void]$sb.AppendLine($comma)
  }
  [void]$sb.Append($pad)
  [void]$sb.Append("}")
  return $sb.ToString()
}

function New-JsoncHeader {
  return @(
    "// TrustButVerify OpenCode restrictions.",
    "// Tested against OpenCode 1.19.6. Last matching rule wins (see",
    "// https://opencode.ai/docs/permissions/ and issues 24335, 37935):",
    "// deny rules are last on purpose, and `"git diff *`" / `"git log *`"",
    "// are ask, placed after the bare git allow rules.",
    "// This kit is model-agnostic. Prefer a model you trust.",
    "// This merger does not change your model or other non-permission settings."
  ) -join "`n"
}

function ConvertTo-OpenCodeJsoncText {
  param($ConfigObject)
  $json = ConvertTo-PrettyJson -Value $ConfigObject -Level 0
  return ((New-JsoncHeader) + "`n" + $json + "`n")
}

function Get-DefaultOpenCodeConfigPath {
  $homeDir = $env:USERPROFILE
  if ([string]::IsNullOrWhiteSpace($homeDir)) { $homeDir = $env:HOME }
  $dir = Join-Path $homeDir ".config"
  $dir = Join-Path $dir "opencode"
  $jsonc = Join-Path $dir "opencode.jsonc"
  $json = Join-Path $dir "opencode.json"
  if (Test-Path -LiteralPath $jsonc) { return $jsonc }
  if (Test-Path -LiteralPath $json) { return $json }
  return $jsonc
}

function Get-ExampleOpenCodeConfigPath {
  param([string]$KitRoot)
  $p = Join-Path $KitRoot "opencode.jsonc"
  if (-not (Test-Path -LiteralPath $p)) {
    throw "Example config not found: $p"
  }
  return $p
}

function Get-LineDiffText {
  param(
    [string]$Before,
    [string]$After,
    [string]$FromLabel = "before",
    [string]$ToLabel = "after"
  )
  if ($null -eq $Before) { $Before = "" }
  if ($null -eq $After) { $After = "" }
  $a = $Before -split "`r?`n"
  $b = $After -split "`r?`n"
  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add(("--- {0}" -f $FromLabel))
  $lines.Add(("+++ {0}" -f $ToLabel))
  # Simple compare: show a unified-style view using Compare-Object when
  # lengths are modest; fall back to full after-text.
  $max = [Math]::Max($a.Count, $b.Count)
  for ($i = 0; $i -lt $max; $i++) {
    $left = ""
    $right = ""
    if ($i -lt $a.Count) { $left = $a[$i].TrimEnd("`r") }
    if ($i -lt $b.Count) { $right = $b[$i].TrimEnd("`r") }
    if ($left -eq $right) {
      $lines.Add((" {0}" -f $left))
    } else {
      if ($i -lt $a.Count) { $lines.Add(("-{0}" -f $left)) }
      if ($i -lt $b.Count) { $lines.Add(("+{0}" -f $right)) }
    }
  }
  return ($lines -join "`n")
}

function Find-LatestConfigBackup {
  param([string]$ConfigPath)
  $dir = Split-Path -Parent $ConfigPath
  if (-not (Test-Path -LiteralPath $dir)) { return $null }
  $name = [System.IO.Path]::GetFileName($ConfigPath)
  $pattern = $name + ".bak-*"
  $files = @(Get-ChildItem -LiteralPath $dir -File -Filter $pattern -ErrorAction SilentlyContinue | Sort-Object Name)
  if ($files.Count -eq 0) { return $null }
  return $files[-1].FullName
}

function Find-LatestCreatedMarker {
  param([string]$ConfigPath)
  $dir = Split-Path -Parent $ConfigPath
  if (-not (Test-Path -LiteralPath $dir)) { return $null }
  $name = [System.IO.Path]::GetFileName($ConfigPath)
  $pattern = $name + ".tbv-created-*"
  $files = @(Get-ChildItem -LiteralPath $dir -File -Filter $pattern -ErrorAction SilentlyContinue | Sort-Object Name)
  if ($files.Count -eq 0) { return $null }
  return $files[-1].FullName
}
