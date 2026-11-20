# TbvSettings.ps1
# Load, validate, and write TrustButVerify watcher settings.
# ASCII only. Works on Windows PowerShell 5.1 and PowerShell 7.
#
# The live file is %LOCALAPPDATA%\opencode-watch\trustbutverify.json.
# Callers must read it at startup or when a reload is signaled, never
# on every poll. Invalid JSON or a missing file returns defaults and a
# warning; these functions do not throw.

Set-StrictMode -Version 1

function Get-TbvReloadEventName {
  return "Local\TrustButVerify-Reload"
}

function Get-TbvSettingsFileName {
  return "trustbutverify.json"
}

function Get-TbvSettingsPath {
  return (Join-Path (Get-OpenCodeWatchLogDir) (Get-TbvSettingsFileName))
}

function Get-TbvDefaultSettings {
  $s = New-Object System.Collections.Specialized.OrderedDictionary
  [void]$s.Add("windowStyle", "hidden")
  [void]$s.Add("pollIntervalMs", 1000)
  [void]$s.Add("allowedLoopbackPorts", @())
  [void]$s.Add("ignoreSelfLoopback", $true)
  [void]$s.Add("extraAlertPatterns", @())
  [void]$s.Add("watchedProcessNames", @("opencode", "node", "bun"))
  [void]$s.Add("logDir", "")
  [void]$s.Add("logRetentionDays", 30)
  [void]$s.Add("alertOnUnlistedDestinations", $false)
  [void]$s.Add("allowlistPath", "")
  [void]$s.Add("extraAlertRegexes", @())
  [void]$s.Add("source", "defaults")
  [void]$s.Add("warnings", (New-Object System.Collections.Generic.List[string]))
  return $s
}

function Get-TbvSettingsMinPollIntervalMs {
  return 250
}


function Get-TbvObjectValue {
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

function ConvertTo-TbvStringArray {
  param($Value)
  $out = New-Object System.Collections.Generic.List[string]
  if ($null -eq $Value) { return @() }
  if ($Value -is [string]) {
    if (-not [string]::IsNullOrWhiteSpace($Value)) { $out.Add([string]$Value) }
    return $out.ToArray()
  }
  foreach ($item in @($Value)) {
    if ($null -eq $item) { continue }
    $text = [string]$item
    if (-not [string]::IsNullOrWhiteSpace($text)) { $out.Add($text) }
  }
  return $out.ToArray()
}

function Convert-TbvSettingsFromObject {
  param($Obj, [string]$Source)
  $s = Get-TbvDefaultSettings
  $s["source"] = $Source
  $warn = $s["warnings"]
  if ($null -eq $Obj) {
    [void]$warn.Add("settings object was empty; using defaults")
    return $s
  }

  $style = Get-TbvObjectValue $Obj "windowStyle"
  if ($null -ne $style -and [string]$style -ne "") {
    $st = ([string]$style).Trim().ToLowerInvariant()
    if ($st -eq "hidden" -or $st -eq "minimized") {
      $s["windowStyle"] = $st
    } else {
      $s["windowStyle"] = "hidden"
      [void]$warn.Add(("windowStyle '{0}' is not hidden or minimized; using hidden" -f $style))
    }
  }

  $poll = Get-TbvObjectValue $Obj "pollIntervalMs"
  if ($null -ne $poll -and [string]$poll -ne "") {
    $n = 0
    if ([int]::TryParse([string]$poll, [ref]$n)) {
      $min = Get-TbvSettingsMinPollIntervalMs
      if ($n -lt $min) {
        [void]$warn.Add(("pollIntervalMs {0} is below the minimum of {1}; using {1}" -f $n, $min))
        $n = $min
      }
      $s["pollIntervalMs"] = $n
    } else {
      [void]$warn.Add(("pollIntervalMs '{0}' is not an integer; using {1}" -f $poll, $s["pollIntervalMs"]))
    }
  }

  $portsRaw = Get-TbvObjectValue $Obj "allowedLoopbackPorts"
  if ($null -ne $portsRaw) {
    $ports = New-Object System.Collections.Generic.List[int]
    foreach ($item in @($portsRaw)) {
      $p = 0
      if ([int]::TryParse([string]$item, [ref]$p) -and $p -ge 0 -and $p -le 65535) {
        $ports.Add($p)
      } else {
        [void]$warn.Add(("skipping invalid allowedLoopbackPorts entry '{0}'" -f $item))
      }
    }
    $s["allowedLoopbackPorts"] = $ports.ToArray()
  }

  $ign = Get-TbvObjectValue $Obj "ignoreSelfLoopback"
  if ($null -ne $ign -and [string]$ign -ne "") {
    if ($ign -is [bool]) {
      $s["ignoreSelfLoopback"] = [bool]$ign
    } else {
      $txt = ([string]$ign).Trim()
      if ($txt -match '^(?i)(true|1|yes)$') {
        $s["ignoreSelfLoopback"] = $true
      } elseif ($txt -match '^(?i)(false|0|no)$') {
        $s["ignoreSelfLoopback"] = $false
      } else {
        [void]$warn.Add(("ignoreSelfLoopback '{0}' is not true or false; using {1}" -f $ign, $s["ignoreSelfLoopback"]))
      }
    }
  }

  $namesRaw = Get-TbvObjectValue $Obj "watchedProcessNames"
  if ($null -ne $namesRaw) {
    $s["watchedProcessNames"] = @(ConvertTo-TbvStringArray $namesRaw)
  }

  $logDir = Get-TbvObjectValue $Obj "logDir"
  if ($null -ne $logDir) {
    $s["logDir"] = [string]$logDir
  }

  $ret = Get-TbvObjectValue $Obj "logRetentionDays"
  if ($null -ne $ret -and [string]$ret -ne "") {
    $d = 0
    if ([int]::TryParse([string]$ret, [ref]$d)) {
      $s["logRetentionDays"] = $d
    } else {
      [void]$warn.Add(("logRetentionDays '{0}' is not an integer; using {1}" -f $ret, $s["logRetentionDays"]))
    }
  }

  # Opt-in, advisory: alert on TCP destinations missing from the approved
  # allowlist (see build-allowlist.ps1). Never blocks anything.
  $unl = Get-TbvObjectValue $Obj "alertOnUnlistedDestinations"
  if ($null -ne $unl -and [string]$unl -ne "") {
    if ($unl -is [bool]) {
      $s["alertOnUnlistedDestinations"] = [bool]$unl
    } else {
      $txt = ([string]$unl).Trim()
      if ($txt -match '^(?i)(true|1|yes)$') {
        $s["alertOnUnlistedDestinations"] = $true
      } elseif ($txt -match '^(?i)(false|0|no)$') {
        $s["alertOnUnlistedDestinations"] = $false
      } else {
        [void]$warn.Add(("alertOnUnlistedDestinations '{0}' is not true or false; using false" -f $unl))
      }
    }
  }
  $alp = Get-TbvObjectValue $Obj "allowlistPath"
  if ($null -ne $alp) {
    $s["allowlistPath"] = [string]$alp
  }

  $patsRaw = Get-TbvObjectValue $Obj "extraAlertPatterns"
  $validPats = New-Object System.Collections.Generic.List[string]
  $regexes = New-Object System.Collections.Generic.List[regex]
  if ($null -ne $patsRaw) {
    foreach ($pat in @(ConvertTo-TbvStringArray $patsRaw)) {
      try {
        $rx = New-Object System.Text.RegularExpressions.Regex($pat, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $validPats.Add($pat)
        $regexes.Add($rx)
      } catch {
        [void]$warn.Add(("skipping invalid extraAlertPatterns regex '{0}': {1}" -f $pat, $_.Exception.Message))
      }
    }
  }
  $s["extraAlertPatterns"] = $validPats.ToArray()
  $s["extraAlertRegexes"] = $regexes.ToArray()
  return $s
}

function Read-TbvSettings {
  param(
    [string]$Path = "",
    [string]$Text = ""
  )
  if ([string]::IsNullOrWhiteSpace($Path) -and [string]::IsNullOrWhiteSpace($Text)) {
    $Path = Get-TbvSettingsPath
  }

  if ([string]::IsNullOrWhiteSpace($Text)) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
      $s = Get-TbvDefaultSettings
      [void]$s["warnings"].Add(("settings file not found ({0}); using defaults" -f $Path))
      return $s
    }
    try {
      $Text = [System.IO.File]::ReadAllText($Path)
    } catch {
      $s = Get-TbvDefaultSettings
      [void]$s["warnings"].Add(("could not read settings file ({0}): {1}; using defaults" -f $Path, $_.Exception.Message))
      return $s
    }
  }

  if ([string]::IsNullOrWhiteSpace($Text)) {
    $s = Get-TbvDefaultSettings
    [void]$s["warnings"].Add("settings file was empty; using defaults")
    return $s
  }

  try {
    $obj = ConvertFrom-Jsonc -Text $Text
  } catch {
    $s = Get-TbvDefaultSettings
    [void]$s["warnings"].Add(("settings JSON is invalid ({0}); using defaults" -f $_.Exception.Message))
    return $s
  }

  $source = "text"
  if (-not [string]::IsNullOrWhiteSpace($Path)) { $source = $Path }
  try {
    return (Convert-TbvSettingsFromObject -Obj $obj -Source $source)
  } catch {
    $s = Get-TbvDefaultSettings
    [void]$s["warnings"].Add(("settings could not be applied ({0}); using defaults" -f $_.Exception.Message))
    return $s
  }
}

function Escape-TbvJsonString {
  param([string]$Text)
  if ($null -eq $Text) { return "" }
  $sb = New-Object System.Text.StringBuilder
  foreach ($ch in $Text.ToCharArray()) {
    $code = [int]$ch
    if ($ch -eq [char]'"') { [void]$sb.Append('\"') }
    elseif ($ch -eq [char]'\') { [void]$sb.Append('\\') }
    elseif ($code -eq 10) { [void]$sb.Append('\n') }
    elseif ($code -eq 13) { [void]$sb.Append('\r') }
    elseif ($code -eq 9) { [void]$sb.Append('\t') }
    elseif ($code -lt 32) { [void]$sb.Append(('\u{0:x4}' -f $code)) }
    else { [void]$sb.Append($ch) }
  }
  return $sb.ToString()
}

function ConvertTo-TbvSettingsJson {
  param($Settings)
  if ($null -eq $Settings) { $Settings = Get-TbvDefaultSettings }
  $style = [string]$Settings["windowStyle"]
  if ($style -ne "minimized") { $style = "hidden" }
  $poll = [int]$Settings["pollIntervalMs"]
  $days = [int]$Settings["logRetentionDays"]
  $logDir = [string]$Settings["logDir"]
  $ports = @($Settings["allowedLoopbackPorts"])
  $pats = @($Settings["extraAlertPatterns"])
  $names = @($Settings["watchedProcessNames"])

  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine("{")
  [void]$sb.AppendLine(('  "windowStyle": "{0}",' -f (Escape-TbvJsonString $style)))
  [void]$sb.AppendLine(('  "pollIntervalMs": {0},' -f $poll))
  if ($ports.Count -eq 0) {
    [void]$sb.AppendLine('  "allowedLoopbackPorts": [],')
  } else {
    [void]$sb.AppendLine('  "allowedLoopbackPorts": [')
    for ($i = 0; $i -lt $ports.Count; $i++) {
      $comma = ","
      if ($i -eq $ports.Count - 1) { $comma = "" }
      [void]$sb.AppendLine(("    {0}{1}" -f [int]$ports[$i], $comma))
    }
    [void]$sb.AppendLine('  ],')
  }
  $ignSelf = $true
  if ($Settings.Contains("ignoreSelfLoopback")) {
    $ignSelf = [bool]$Settings["ignoreSelfLoopback"]
  }
  if ($ignSelf) {
    [void]$sb.AppendLine('  "ignoreSelfLoopback": true,')
  } else {
    [void]$sb.AppendLine('  "ignoreSelfLoopback": false,')
  }
  if ($pats.Count -eq 0) {
    [void]$sb.AppendLine('  "extraAlertPatterns": [],')
  } else {
    [void]$sb.AppendLine('  "extraAlertPatterns": [')
    for ($i = 0; $i -lt $pats.Count; $i++) {
      $comma = ","
      if ($i -eq $pats.Count - 1) { $comma = "" }
      [void]$sb.AppendLine(('    "{0}"{1}' -f (Escape-TbvJsonString ([string]$pats[$i])), $comma))
    }
    [void]$sb.AppendLine('  ],')
  }
  if ($names.Count -eq 0) {
    [void]$sb.AppendLine('  "watchedProcessNames": [],')
  } else {
    [void]$sb.AppendLine('  "watchedProcessNames": [')
    for ($i = 0; $i -lt $names.Count; $i++) {
      $comma = ","
      if ($i -eq $names.Count - 1) { $comma = "" }
      [void]$sb.AppendLine(('    "{0}"{1}' -f (Escape-TbvJsonString ([string]$names[$i])), $comma))
    }
    [void]$sb.AppendLine('  ],')
  }
  [void]$sb.AppendLine(('  "logDir": "{0}",' -f (Escape-TbvJsonString $logDir)))
  [void]$sb.AppendLine(('  "logRetentionDays": {0},' -f $days))
  $unlisted = $false
  if ($Settings.Contains("alertOnUnlistedDestinations")) { $unlisted = [bool]$Settings["alertOnUnlistedDestinations"] }
  if ($unlisted) {
    [void]$sb.AppendLine('  "alertOnUnlistedDestinations": true,')
  } else {
    [void]$sb.AppendLine('  "alertOnUnlistedDestinations": false,')
  }
  $alPath = ""
  if ($Settings.Contains("allowlistPath")) { $alPath = [string]$Settings["allowlistPath"] }
  [void]$sb.AppendLine(('  "allowlistPath": "{0}"' -f (Escape-TbvJsonString $alPath)))
  [void]$sb.AppendLine("}")
  return $sb.ToString()
}

function Write-TbvSettingsFile {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    $Settings
  )
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
  }
  $text = ConvertTo-TbvSettingsJson -Settings $Settings
  $enc = New-Object System.Text.UTF8Encoding $false
  [System.IO.File]::WriteAllText($Path, $text, $enc)
}

function Install-TbvSettingsFileIfMissing {
  param(
    [string]$KitRoot = "",
    [string]$Path = ""
  )
  if ([string]::IsNullOrWhiteSpace($Path)) { $Path = Get-TbvSettingsPath }
  if (Test-Path -LiteralPath $Path) {
    return @{ Created = $false; Path = $Path }
  }
  if (-not [string]::IsNullOrWhiteSpace($KitRoot)) {
    $example = Join-Path $KitRoot "trustbutverify.example.json"
    if (Test-Path -LiteralPath $example) {
      $dir = Split-Path -Parent $Path
      if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
      }
      Copy-Item -LiteralPath $example -Destination $Path
      return @{ Created = $true; Path = $Path; From = $example }
    }
  }
  Write-TbvSettingsFile -Path $Path -Settings (Get-TbvDefaultSettings)
  return @{ Created = $true; Path = $Path; From = "defaults" }
}

function Set-TbvSettingsWindowStyle {
  param(
    [ValidateSet("hidden", "minimized")][string]$WindowStyle,
    [string]$Path = ""
  )
  if ([string]::IsNullOrWhiteSpace($Path)) { $Path = Get-TbvSettingsPath }
  $s = Get-TbvDefaultSettings
  if (Test-Path -LiteralPath $Path) {
    $loaded = Read-TbvSettings -Path $Path
    if ($loaded["source"] -ne "defaults") {
      $s = $loaded
    }
    # If the file exists but was invalid, source is defaults with a
    # warning: do not overwrite a file the user may be editing.
    $invalid = $false
    foreach ($w in @($loaded["warnings"])) {
      if ([string]$w -match '(?i)JSON is invalid|could not read|could not be applied') {
        $invalid = $true
      }
    }
    if ($invalid) {
      return @{ Updated = $false; Path = $Path; Reason = "existing file is invalid; left unchanged" }
    }
  } else {
    $null = Install-TbvSettingsFileIfMissing -Path $Path
    if (Test-Path -LiteralPath $Path) { $s = Read-TbvSettings -Path $Path }
  }
  $s["windowStyle"] = $WindowStyle
  Write-TbvSettingsFile -Path $Path -Settings $s
  return @{ Updated = $true; Path = $Path; WindowStyle = $WindowStyle }
}

function Invoke-TbvLogRetention {
  param(
    [string]$LogDir,
    [int]$Days
  )
  $removed = New-Object System.Collections.Generic.List[string]
  if ($Days -le 0) { return $removed.ToArray() }
  if ([string]::IsNullOrWhiteSpace($LogDir) -or -not (Test-Path -LiteralPath $LogDir)) {
    return $removed.ToArray()
  }
  $cutoff = (Get-Date).AddDays(-$Days)
  foreach ($filter in @("watch-*.csv", "watch-*.log")) {
    $files = @(Get-ChildItem -LiteralPath $LogDir -File -Filter $filter -ErrorAction SilentlyContinue)
    foreach ($f in $files) {
      if ($f.LastWriteTime -lt $cutoff) {
        Remove-Item -LiteralPath $f.FullName -Force
        $removed.Add($f.Name)
      }
    }
  }
  return $removed.ToArray()
}

function Get-TbvWindowStyleFromSettings {
  param($Settings)
  $style = "hidden"
  if ($Settings -and $Settings["windowStyle"]) {
    $style = [string]$Settings["windowStyle"]
  }
  if ($style -eq "minimized") { return "Minimized" }
  return "Hidden"
}
