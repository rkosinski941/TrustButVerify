# apply-config.ps1
# Merge TrustButVerify restriction rules into the current user's OpenCode
# config. Does not replace the whole file: model and other settings are
# kept, existing rules are kept, and kit deny rules are written last so
# they win (OpenCode 1.19.x last-match-wins).
#
# Looks for:
#   %USERPROFILE%\.config\opencode\opencode.jsonc
#   %USERPROFILE%\.config\opencode\opencode.json
# If neither exists, creates opencode.jsonc from the example in this kit.
#
# Always prints the current file's SHA-256 before changing it, and writes
# a timestamped backup next to the file. Use -DryRun or -WhatIf to print a
# diff and skip writes. Pass -ExpectedSha256 to refuse if the current
# file does not match that hash. -ExpectedMd5 is still accepted for
# compatibility. Pass -Strict to demote pre-existing allow rules to ask.

[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$ConfigPath = "",
  [string]$ExpectedSha256 = "",
  [string]$ExpectedMd5 = "",
  [string]$KitRoot = "",
  [switch]$Strict,
  [switch]$DryRun
)

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($KitRoot)) { $KitRoot = $PSScriptRoot }
. (Join-Path $KitRoot "lib\WatchCommon.ps1")
. (Join-Path $KitRoot "lib\MergeOpenCodeConfig.ps1")

function Write-Utf8NoBom {
  param([string]$Path, [string]$Text)
  $enc = New-Object System.Text.UTF8Encoding $false
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
  }
  [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

function Read-TextFile {
  param([string]$Path)
  return [System.IO.File]::ReadAllText($Path)
}

$skipWrite = $false
if ($DryRun) { $skipWrite = $true }
if ($WhatIfPreference) { $skipWrite = $true }

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
  $ConfigPath = Get-DefaultOpenCodeConfigPath
}

$examplePath = Get-ExampleOpenCodeConfigPath -KitRoot $KitRoot
$existed = Test-Path -LiteralPath $ConfigPath
$beforeText = ""
$md5 = ""

if ($existed) {
  $beforeText = Read-TextFile -Path $ConfigPath
  $sha = Get-FileHashHex -Path $ConfigPath -Algorithm SHA256
  Write-Host ("Current config: {0}" -f $ConfigPath)
  Write-Host ("Current SHA256: {0}" -f $sha)
  if ($ExpectedSha256) {
    $want = $ExpectedSha256.Trim().ToLowerInvariant().Replace("-", "")
    if ($sha -ne $want) {
      throw ("Current SHA256 {0} does not match -ExpectedSha256 {1}. No files were changed. If this is the file you meant, re-run with -ExpectedSha256 {0} after you have inspected it." -f $sha, $want)
    }
  }
  if ($ExpectedMd5) {
    $md5 = Get-FileHashHex -Path $ConfigPath -Algorithm MD5
    $wantMd5 = $ExpectedMd5.Trim().ToLowerInvariant().Replace("-", "")
    if ($md5 -ne $wantMd5) {
      throw ("Current MD5 {0} does not match -ExpectedMd5 {1}. No files were changed. If this is the file you meant, re-run with -ExpectedMd5 {0} after you have inspected it." -f $md5, $wantMd5)
    }
  }
  $parsed = ConvertFrom-Jsonc -Text $beforeText
  $merged = Merge-OpenCodeConfigObject -Config $parsed -Strict:$Strict
  $afterText = ConvertTo-OpenCodeJsoncText -ConfigObject $merged
  $flagged = @(Get-TbvPreExistingAllowKeys -Existing (Get-ObjectValue (Get-ObjectValue $parsed "permission") "bash"))
  if ($flagged.Count -gt 0) {
    if ($Strict) {
      Write-Host ("-Strict: demoting pre-existing allow rules to ask: {0}" -f ($flagged -join ", "))
    } else {
      Write-Host ("Warning: pre-existing allow rules were kept: {0}" -f ($flagged -join ", "))
      Write-Host "Re-run with -Strict to demote those allows to ask."
    }
  }
} else {
  Write-Host ("No OpenCode config at {0}" -f $ConfigPath)
  if ($ExpectedSha256 -or $ExpectedMd5) {
    throw "A hash check was set, but the config file does not exist. No files were changed."
  }
  $beforeText = ""
  $afterText = Read-TextFile -Path $examplePath
  $null = ConvertFrom-Jsonc -Text $afterText
}

# Validate the result parses and has deny-last bash keys.
$check = ConvertFrom-Jsonc -Text $afterText
$perm = Get-ObjectValue $check "permission"
if ($null -eq $perm) { throw "Merged config is missing a permission block." }
$bash = ConvertTo-RuleMap (Get-ObjectValue $perm "bash")
$bashKeys = @($bash.Keys)
if ($bashKeys.Count -lt 3) { throw "Merged bash rule map looks empty." }
if ($bashKeys[0] -ne "*") {
  throw ("Merged bash rules must start with '*', started with '{0}'." -f $bashKeys[0])
}
$gitDiffStar = $bashKeys.IndexOf("git diff *")
$gitDiff = $bashKeys.IndexOf("git diff")
if ($gitDiffStar -ge 0 -and $gitDiff -ge 0 -and $gitDiffStar -lt $gitDiff) {
  throw "'git diff *' must come after 'git diff' so the last match can ask or deny."
}
$lastKey = $bashKeys[$bashKeys.Count - 1]
if ($bash[$lastKey] -ne "deny") {
  throw ("The last bash rule must be a deny (last match wins), got {0}={1}." -f $lastKey, $bash[$lastKey])
}

# OpenCode 1.19.6 substitutes {env:NAME} in the raw file before JSONC
# parse. Refuse to write (or report success on -DryRun) if the merged
# text would not load. The original file is left unchanged.
$gate = Test-OpenCodeJsoncText -Text $afterText
if (-not $gate.Ok) {
  throw ("Refusing to write the OpenCode config: {0} The original file was left unchanged." -f $gate.Reason)
}

Write-Host ""
Write-Host (Get-LineDiffText -Before $beforeText -After $afterText -FromLabel $ConfigPath -ToLabel "merged")
Write-Host ""

if ($skipWrite) {
  Write-Host "Dry run: no files were written."
  return
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$dir = Split-Path -Parent $ConfigPath
if (-not (Test-Path -LiteralPath $dir)) {
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

if ($existed) {
  $backupPath = $ConfigPath + ".bak-" + $stamp
  [System.IO.File]::Copy($ConfigPath, $backupPath, $true)
  Write-Host ("Backup: {0}" -f $backupPath)
  Write-Host ("Backup SHA256: {0}" -f (Get-FileHashHex -Path $backupPath -Algorithm SHA256))
} else {
  $marker = $ConfigPath + ".tbv-created-" + $stamp
  Write-Utf8NoBom -Path $marker -Text ("created " + $stamp + "`n")
  Write-Host ("Created-new marker: {0}" -f $marker)
}


Write-Utf8NoBom -Path $ConfigPath -Text $afterText
try {
  $written = Read-TextFile -Path $ConfigPath
  $null = ConvertFrom-Jsonc -Text $written
  $writtenGate = Test-OpenCodeJsoncText -Text $written
  if (-not $writtenGate.Ok) {
    throw $writtenGate.Reason
  }
} catch {
  if ($existed) {
    [System.IO.File]::Copy($backupPath, $ConfigPath, $true)
    Write-Host "Validation failed; restored the backup."
  } elseif (Test-Path -LiteralPath $ConfigPath) {
    Remove-Item -LiteralPath $ConfigPath -Force
    Write-Host "Validation failed; removed the file that was just created."
  }
  throw
}

Write-Host ("Wrote {0}" -f $ConfigPath)
Write-Host ("New SHA256: {0}" -f (Get-FileHashHex -Path $ConfigPath -Algorithm SHA256))
