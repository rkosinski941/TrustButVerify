# TbvPlugin.ps1
# Helpers for installing the TrustButVerify OpenCode guard plugin. ASCII
# only. Dot-source after WatchCommon.ps1 and MergeOpenCodeConfig.ps1.

Set-StrictMode -Version 1

function Get-TbvPluginFileName { return "trustbutverify-guard.js" }

# Oldest OpenCode 1.x that loads a {id, server()} default export (per the
# OpenCode "Migrate plugins from V1" docs). Verified live on 1.19.6 and 2.3.2.
function Get-TbvPluginMinOpenCodeVersion { return "1.18.29" }

function Get-TbvPluginSourcePath {
  param([string]$KitRoot)
  return (Join-Path (Join-Path $KitRoot "plugin") (Get-TbvPluginFileName))
}

function Get-TbvPluginDir {
  # OpenCode loads {plugin,plugins}/*.{js,ts} from its global config dir.
  param([string]$ConfigPath = "")
  if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $ConfigPath = Get-DefaultOpenCodeConfigPath }
  return (Join-Path (Split-Path -Parent $ConfigPath) "plugins")
}

function Get-TbvPluginInstallPath {
  param([string]$ConfigPath = "")
  return (Join-Path (Get-TbvPluginDir -ConfigPath $ConfigPath) (Get-TbvPluginFileName))
}

function ConvertTo-TbvVersion {
  # "opencode v2.3.2" / "1.19.6" -> [version]; $null if not parseable.
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
  $m = [regex]::Match($Text, '(\d+)\.(\d+)\.(\d+)')
  if (-not $m.Success) { return $null }
  return [version]("{0}.{1}.{2}" -f $m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value)
}

function Find-OpenCodeExe {
  param([string]$OpenCodePath = "")
  if ($OpenCodePath) {
    if (Test-Path -LiteralPath $OpenCodePath) { return $OpenCodePath }
    return ""
  }
  foreach ($n in @("opencode.exe", "opencode.cmd", "opencode")) {
    $c = Get-Command $n -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c -and $c.Source) { return [string]$c.Source }
  }
  return ""
}

function Get-OpenCodeVersionInfo {
  param([string]$OpenCodePath = "")
  $exe = Find-OpenCodeExe -OpenCodePath $OpenCodePath
  if (-not $exe) { return [pscustomobject]@{ Found = $false; Path = ""; Text = ""; Version = $null } }
  $text = ""
  try {
    $text = ((Invoke-Native -FilePath $exe -ArgumentList @("--version")) -join " ").Trim()
  } catch {
    $text = ""
  }
  return [pscustomobject]@{ Found = $true; Path = $exe; Text = $text; Version = (ConvertTo-TbvVersion $text) }
}

function Test-TbvPluginSupported {
  # Returns Supported=$true/$false/$null (unknown) and a reason.
  param($Version)
  if ($null -eq $Version) {
    return [pscustomobject]@{ Supported = $null; Reason = "OpenCode version unknown" }
  }
  $min = [version](Get-TbvPluginMinOpenCodeVersion)
  if ($Version -ge $min) {
    return [pscustomobject]@{ Supported = $true; Reason = ("OpenCode {0} >= {1}" -f $Version, $min) }
  }
  return [pscustomobject]@{ Supported = $false; Reason = ("OpenCode {0} is older than {1}; the plugin entrypoint may not load there" -f $Version, $min) }
}

function Get-TbvPluginKnownHashes {
  # Hashes of kit plugin builds this kit may remove without -Force:
  # the current source plus any listed in kit-manifest.json.
  param([string]$KitRoot)
  $list = New-Object System.Collections.Generic.List[string]
  $src = Get-TbvPluginSourcePath -KitRoot $KitRoot
  if (Test-Path -LiteralPath $src) { $list.Add((Get-FileHashHex -Path $src -Algorithm SHA256)) }
  $manifest = Join-Path $KitRoot "kit-manifest.json"
  if (Test-Path -LiteralPath $manifest) {
    try {
      $m = ConvertFrom-Json ([System.IO.File]::ReadAllText($manifest))
      if ($m.PSObject.Properties["pluginHistory"]) {
        foreach ($h in @($m.pluginHistory)) { if ($h) { $list.Add(([string]$h).ToLowerInvariant()) } }
      }
    } catch { }
  }
  return @($list | Select-Object -Unique)
}
