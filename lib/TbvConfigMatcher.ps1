# TbvConfigMatcher.ps1
# Emulates how OpenCode 1.19.6 matches permission rules, for the bypass
# suite and doctor.ps1. ASCII only. Dot-source; do not run alone.
#
# Read from the 1.19.6 binary (Wildcard match, Si/VA in the bundle):
#   - backslashes become "/" in both the text and the pattern
#   - "*" matches any run of characters (including newlines), "?" one char
#   - a pattern ending in " *" also matches without the trailing part
#     ("curl *" matches "curl")
#   - matching is CASE-SENSITIVE ("*curl *" does not match "CURL x")
#   - the last matching rule wins
# The bash tool parses the command (tree-sitter) and checks each simple
# command separately; any deny denies the call. This file approximates
# that split with a quote-aware split on ; & && || | and newlines. The
# live harness in tests/live runs the real binary when exactness matters.
#
# The older Test-OpenCodeGlob in MergeOpenCodeConfig.ps1 is
# case-insensitive and is kept for the existing merge tests only.

Set-StrictMode -Version 1

function ConvertTo-OpenCode1196WildcardRegex {
  param([string]$Pattern)
  if ($null -eq $Pattern) { $Pattern = "" }
  $p = $Pattern.Replace('\', '/')
  $sb = New-Object System.Text.StringBuilder
  foreach ($ch in $p.ToCharArray()) {
    $c = [string]$ch
    if ('.+^${}()|[]\'.Contains($c)) {
      [void]$sb.Append('\').Append($c)
    } elseif ($c -eq '*') {
      [void]$sb.Append('.*')
    } elseif ($c -eq '?') {
      [void]$sb.Append('.')
    } else {
      [void]$sb.Append($c)
    }
  }
  $r = $sb.ToString()
  if ($r.EndsWith(' .*')) { $r = $r.Substring(0, $r.Length - 3) + '( .*)?' }
  return ('^' + $r + '$')
}

function Test-OpenCode1196Wildcard {
  param([string]$Pattern, [string]$Text)
  if ($null -eq $Text) { $Text = "" }
  $t = $Text.Replace('\', '/')
  $rx = ConvertTo-OpenCode1196WildcardRegex -Pattern $Pattern
  return [regex]::IsMatch($t, $rx, [System.Text.RegularExpressions.RegexOptions]::Singleline)
}

function Split-OpenCodeCommandApprox {
  param([string]$Command)
  $parts = New-Object System.Collections.Generic.List[string]
  if ($null -eq $Command) { $Command = "" }
  $cur = New-Object System.Text.StringBuilder
  $quote = [char]0
  $i = 0
  while ($i -lt $Command.Length) {
    $ch = $Command[$i]
    if ($quote -ne [char]0) {
      [void]$cur.Append($ch)
      if ($ch -eq $quote) { $quote = [char]0 }
      $i++
      continue
    }
    if ($ch -eq [char]39 -or $ch -eq [char]34) {
      $quote = $ch
      [void]$cur.Append($ch)
      $i++
      continue
    }
    if ($ch -eq ';' -or $ch -eq '|' -or $ch -eq '&' -or $ch -eq "`n" -or $ch -eq "`r") {
      $seg = $cur.ToString().Trim()
      if ($seg.Length -gt 0) { $parts.Add($seg) }
      [void]$cur.Clear()
      if (($ch -eq '|' -or $ch -eq '&') -and ($i + 1) -lt $Command.Length -and $Command[$i + 1] -eq $ch) { $i++ }
      $i++
      continue
    }
    [void]$cur.Append($ch)
    $i++
  }
  $last = $cur.ToString().Trim()
  if ($last.Length -gt 0) { $parts.Add($last) }
  if ($parts.Count -eq 0) { $parts.Add($Command.Trim()) }
  return ,$parts.ToArray()
}

function Resolve-OpenCode1196RuleMap {
  # Last matching rule wins for one text. Returns Decision="" if nothing matched.
  param($RuleMap, [string]$Text)
  $decision = ""
  $matched = ""
  if ($null -eq $RuleMap) { return [pscustomobject]@{ Decision = ""; Pattern = "" } }
  foreach ($k in $RuleMap.Keys) {
    if (Test-OpenCode1196Wildcard -Pattern ([string]$k) -Text $Text) {
      $decision = [string]$RuleMap[$k]
      $matched = [string]$k
    }
  }
  return [pscustomobject]@{ Decision = $decision; Pattern = $matched }
}

function Test-OpenCodeUncheckedSegment {
  # OpenCode 1.19.6 checks permissions per tree-sitter "command" node. A
  # bash declaration (export/declare/typeset/local/readonly ...) or a bare
  # assignment (NAME=value) is not a "command" node, so it is never matched
  # against the bash rules. Confirmed live: `export -p` runs with no prompt.
  param([string]$Segment)
  $t = $Segment.Trim()
  if ($t -match '^(export|declare|typeset|local|readonly)(\s|$)') { return $true }
  $words = @($t -split '\s+' | Where-Object { $_ })
  if ($words.Count -eq 0) { return $false }
  foreach ($w in $words) {
    if ($w -notmatch '^[A-Za-z_][A-Za-z0-9_]*=') { return $false }
  }
  return $true
}

function Resolve-OpenCode1196BashDecision {
  # Any checked segment deny -> deny; all allow (or nothing checked) ->
  # allow; otherwise ask.
  param($RuleMap, [string]$Command)
  $allSegs = Split-OpenCodeCommandApprox -Command $Command
  $segs = @($allSegs | Where-Object { -not (Test-OpenCodeUncheckedSegment -Segment $_) })
  $allAllow = $true
  foreach ($s in $segs) {
    $r = Resolve-OpenCode1196RuleMap -RuleMap $RuleMap -Text $s
    if ($r.Decision -eq "deny") {
      return [pscustomobject]@{ Decision = "deny"; Pattern = $r.Pattern; Segment = $s }
    }
    if ($r.Decision -ne "allow") { $allAllow = $false }
  }
  if ($allAllow) { return [pscustomobject]@{ Decision = "allow"; Pattern = ""; Segment = "" } }
  return [pscustomobject]@{ Decision = "ask"; Pattern = ""; Segment = "" }
}
