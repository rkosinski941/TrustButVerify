# doctor.ps1
# Health check for a TrustButVerify install. No admin needed. Prints a
# PASS / WARN / FAIL table and exits 0 (all pass), 1 (warnings) or
# 2 (failures). SKIP means the check does not apply (for example Sysmon
# on a machine where it was never installed).
#
# Checks:
#   - OpenCode is on PATH and its version supports the guard plugin
#   - `opencode debug config` loads the config (catches {env:} footguns)
#   - bash rules: catch-all first, no allow after a deny, no wildcard
#     allow, and canary commands get the expected decision
#   - the guard plugin is installed, matches the kit hash, is listed by
#     OpenCode, and has written a heartbeat since it was installed
#   - the watcher is running (watch.pid)
#   - trustbutverify.json is valid
#   - Sysmon service, driver, and event log are readable (if installed)
#   - the nightly summary task runs as RunLevel Limited (if registered)
#   - kit files match kit-manifest.json
#
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\doctor.ps1
#   ... -Json            machine-readable output
#   ... -NoOpenCode      skip running the opencode binary

[CmdletBinding()]
param(
  [string]$ConfigPath = "",
  [string]$OpenCodePath = "",
  [string]$KitRoot = "",
  [string]$SettingsPath = "",
  [switch]$NoOpenCode,
  [switch]$Json
)

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($KitRoot)) { $KitRoot = $PSScriptRoot }
$lib = Join-Path $KitRoot "lib"
. (Join-Path $lib "WatchCommon.ps1")
. (Join-Path $lib "MergeOpenCodeConfig.ps1")
. (Join-Path $lib "TbvSettings.ps1")
. (Join-Path $lib "TbvPlugin.ps1")
. (Join-Path $lib "TbvConfigMatcher.ps1")
. (Join-Path $lib "TbvDoctor.ps1")

$checks = New-Object System.Collections.Generic.List[object]
function Add-Check([string]$Name, [string]$Status, [string]$Detail) { $checks.Add((New-TbvCheck -Name $Name -Status $Status -Detail $Detail)) }

if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $ConfigPath = Get-DefaultOpenCodeConfigPath }

# 1. OpenCode version
$ver = $null
if ($NoOpenCode) {
  Add-Check "opencode version" "SKIP" "-NoOpenCode"
} else {
  $ver = Get-OpenCodeVersionInfo -OpenCodePath $OpenCodePath
  if (-not $ver.Found) {
    Add-Check "opencode version" "WARN" "opencode not found on PATH (pass -OpenCodePath)"
  } else {
    $sup = Test-TbvPluginSupported -Version $ver.Version
    if ($sup.Supported -eq $true) { Add-Check "opencode version" "PASS" $sup.Reason }
    else { Add-Check "opencode version" "WARN" $sup.Reason }
  }
}

# 2. Config loads in OpenCode
$debugCfg = $null
if (-not (Test-Path -LiteralPath $ConfigPath)) {
  Add-Check "config file" "FAIL" ("not found: {0}" -f $ConfigPath)
} else {
  $raw = [System.IO.File]::ReadAllText($ConfigPath)
  $gate = Test-OpenCodeJsoncText -Text $raw
  if ($gate.Ok) { Add-Check "config file" "PASS" "valid JSONC after {env:} substitution" }
  else { Add-Check "config file" "FAIL" "OpenCode would reject it: invalid after {env:} substitution (unclosed {env: in a rule?)" }
}
if ($ver -and $ver.Found) {
  $out = @()
  $code = 0
  $prev = $global:LASTEXITCODE
  try {
    $out = @(Invoke-Native -FilePath $ver.Path -ArgumentList @("debug", "config") -AllowFail)
    $code = $global:LASTEXITCODE
  } catch {
    $code = 1
  }
  $global:LASTEXITCODE = $prev
  $text = ($out -join "`n")
  $iObj = $text.IndexOf("{")
  $iArr = $text.IndexOf("[")
  $start = $iObj
  if ($iArr -ge 0 -and ($iObj -lt 0 -or $iArr -lt $iObj)) { $start = $iArr }
  if ($code -eq 0 -and $start -ge 0) {
    try {
      $debugCfg = ConvertFrom-Jsonc -Text $text.Substring($start)
      Add-Check "opencode debug config" "PASS" "OpenCode loaded the merged config"
    } catch {
      Add-Check "opencode debug config" "FAIL" "output was not JSON"
    }
  } else {
    Add-Check "opencode debug config" "FAIL" ("exit code {0}; OpenCode could not load the config" -f $code)
  }
} elseif (-not $NoOpenCode) {
  Add-Check "opencode debug config" "SKIP" "opencode not found"
}

# 3. Rules
$bashObj = $null
$rulesFrom = ""
$rules = @()
if ($debugCfg) {
  $rules = @(Get-TbvBashRulesFromDebugConfig -DebugConfig $debugCfg)
  $rulesFrom = "effective config"
}
if (@($rules).Count -gt 0) {
  $bashObj = $null
} elseif (Test-Path -LiteralPath $ConfigPath) {
  try {
    $fileCfg = ConvertFrom-Jsonc -Text (Get-OpenCodeEnvSubstitutedText -Text ([System.IO.File]::ReadAllText($ConfigPath)))
    $bashObj = Get-ObjectValue (Get-ObjectValue $fileCfg "permission") "bash"
    $rulesFrom = "config file"
  } catch { }
}
if (@($rules).Count -eq 0) { $rules = ConvertTo-TbvRuleList $bashObj }
$redNote = ""
if (@($rules | Where-Object { $_.Action -eq "***" }).Count -gt 0) {
  $fileRules = @()
  try {
    $fc = ConvertFrom-Jsonc -Text (Get-OpenCodeEnvSubstitutedText -Text ([System.IO.File]::ReadAllText($ConfigPath)))
    $fileRules = ConvertTo-TbvRuleList (Get-ObjectValue (Get-ObjectValue $fc "permission") "bash")
  } catch { }
  $rr = Resolve-TbvRedactedRules -Rules $rules -FileRules $fileRules
  $rules = $rr.Rules
  $redNote = ("; {0} value(s) masked by opencode debug config were read from the config file" -f $rr.Redacted)
  if ($rr.Unresolved -gt 0) { $redNote = $redNote + (" ({0} not found there, assumed deny)" -f $rr.Unresolved) }
}
$order = Test-TbvRuleOrder -Rules $rules
if ($order.Status -eq "PASS") {
  Add-Check "bash rule order" "PASS" (("{0} rules, {1} deny, from {2}" -f @($rules).Count, $order.DenyCount, $rulesFrom) + $redNote)
} else {
  Add-Check "bash rule order" "FAIL" (($order.Problems | Select-Object -First 3) -join "; ")
}
if (@($rules).Count -gt 0) {
  $bad = @(Test-TbvCanaries -Rules $rules)
  if ($bad.Count -eq 0) { Add-Check "bash rule canaries" "PASS" ("{0} canary commands decided as expected (1.19.6 matcher)" -f @(Get-TbvDoctorCanaries).Count) }
  else { Add-Check "bash rule canaries" "FAIL" (($bad | Select-Object -First 3) -join "; ") }
}

# 4. Plugin
$pluginPath = Get-TbvPluginInstallPath -ConfigPath $ConfigPath
$srcPath = Get-TbvPluginSourcePath -KitRoot $KitRoot
if (-not (Test-Path -LiteralPath $pluginPath)) {
  Add-Check "guard plugin file" "WARN" "not installed (install-plugin.ps1); only the config layer is active"
} else {
  $sha = Get-FileHashHex -Path $pluginPath -Algorithm SHA256
  $srcSha = ""
  if (Test-Path -LiteralPath $srcPath) { $srcSha = Get-FileHashHex -Path $srcPath -Algorithm SHA256 }
  if ($sha -eq $srcSha) { Add-Check "guard plugin file" "PASS" "installed and matches the kit build" }
  else { Add-Check "guard plugin file" "WARN" "installed but differs from this kit's build (edited or another version)" }
  if ($debugCfg) {
    if (Test-TbvPluginInDebugConfig -DebugConfig $debugCfg) { Add-Check "guard plugin listed" "PASS" "OpenCode lists the plugin" }
    else { Add-Check "guard plugin listed" "FAIL" "OpenCode does not list the plugin file" }
  }
  $stateDir = Get-OpenCodeWatchLogDir
  if ($env:TBV_PLUGIN_STATE_DIR) { $stateDir = $env:TBV_PLUGIN_STATE_DIR }
  $hbPath = Join-Path $stateDir "plugin-heartbeat.json"
  $hb = $null
  if (Test-Path -LiteralPath $hbPath) {
    try { $hb = ConvertFrom-Json ([System.IO.File]::ReadAllText($hbPath)) } catch { $hb = $null }
  }
  $installedAt = (Get-Item -LiteralPath $pluginPath).LastWriteTimeUtc
  $r = Test-TbvPluginHeartbeat -Heartbeat $hb -InstalledAt $installedAt -ExpectedVersion (Get-TbvPluginSourceVersion -Path $srcPath)
  Add-Check "guard plugin loaded" $r.Status $r.Detail
}

# 5. Settings
$settingsFile = $SettingsPath
if (-not $settingsFile) { $settingsFile = Get-TbvSettingsPath }
$settings = $null
if (-not (Test-Path -LiteralPath $settingsFile)) {
  Add-Check "settings file" "WARN" "trustbutverify.json not found; the watcher uses defaults"
  $settings = Read-TbvSettings -Path $settingsFile
} else {
  $settings = Read-TbvSettings -Path $settingsFile
  $warn = @($settings["warnings"])
  if ($warn.Count -eq 0) { Add-Check "settings file" "PASS" "trustbutverify.json is valid" }
  elseif (($warn -join " ") -match 'invalid|could not') { Add-Check "settings file" "FAIL" ($warn[0]) }
  else { Add-Check "settings file" "WARN" (($warn | Select-Object -First 2) -join "; ") }
}

# 6. Watcher
$logDir = Get-OpenCodeWatchLogDir
if ($settings -and $settings.Contains("logDir") -and $settings["logDir"]) { $logDir = [string]$settings["logDir"] }
$pidFile = Join-Path $logDir "watch.pid"
if (-not (Test-Path -LiteralPath $pidFile)) {
  Add-Check "watcher" "WARN" "not running (no watch.pid); start-watch.cmd starts it"
} else {
  $pidText = (Get-Content -LiteralPath $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
  $wpid = 0
  if ($pidText) { [void][int]::TryParse(([string]$pidText).Trim(), [ref]$wpid) }
  $proc = $null
  if ($wpid -gt 0) { $proc = Get-Process -Id $wpid -ErrorAction SilentlyContinue }
  if ($proc) { Add-Check "watcher" "PASS" ("running as PID {0}" -f $wpid) }
  else { Add-Check "watcher" "WARN" "watch.pid is stale; the watcher is not running" }
}

# 7. Sysmon (Windows only, optional)
if (-not (Test-IsWindowsOS)) {
  Add-Check "sysmon" "SKIP" "not Windows"
} else {
  $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
  if (-not $svc) { $svc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }
  if (-not $svc) {
    Add-Check "sysmon service" "SKIP" "Sysmon is not installed (optional; install-sysmon.ps1)"
  } else {
    if ([string]$svc.Status -eq "Running") { Add-Check "sysmon service" "PASS" ("{0} is running" -f $svc.Name) }
    else { Add-Check "sysmon service" "FAIL" ("{0} is {1}" -f $svc.Name, $svc.Status) }
    $drv = Get-Service -Name "SysmonDrv" -ErrorAction SilentlyContinue
    if ($drv -and [string]$drv.Status -eq "Running") { Add-Check "sysmon driver" "PASS" "SysmonDrv is running" }
    elseif ($drv) { Add-Check "sysmon driver" "FAIL" ("SysmonDrv is {0}" -f $drv.Status) }
    else { Add-Check "sysmon driver" "FAIL" "SysmonDrv not found" }
    try {
      $null = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction Stop
      Add-Check "sysmon log readable" "PASS" "this user can read Microsoft-Windows-Sysmon/Operational"
    } catch {
      if (Test-IsSysmonLogAccessError $_) { Add-Check "sysmon log readable" "WARN" "access denied: sign out and back in after install-sysmon.ps1 (Event Log Readers)" }
      else { Add-Check "sysmon log readable" "WARN" ("could not read: {0}" -f (Get-ErrorText $_)) }
    }
  }
  $task = $null
  try { $task = Get-ScheduledTask -TaskName "OpenCodeWatch-SysmonSummary" -ErrorAction Stop } catch { $task = $null }
  if (-not $task) {
    Add-Check "nightly task" "SKIP" "not registered (optional; register-nightly-summary.ps1)"
  } else {
    $rl = [string]$task.Principal.RunLevel
    if ($rl -eq "Limited") { Add-Check "nightly task" "PASS" "RunLevel Limited" }
    else { Add-Check "nightly task" "FAIL" ("RunLevel {0}; it must be Limited (re-register without admin)" -f $rl) }
  }
}

# 8. Kit manifest
$manifestPath = Join-Path $KitRoot "kit-manifest.json"
if (-not (Test-Path -LiteralPath $manifestPath)) {
  Add-Check "kit manifest" "WARN" "kit-manifest.json not found"
} else {
  try {
    $manifest = ConvertFrom-Json ([System.IO.File]::ReadAllText($manifestPath))
    $probs = @(Compare-TbvManifest -Manifest $manifest -KitRoot $KitRoot)
    if ($probs.Count -eq 0) { Add-Check "kit manifest" "PASS" ("{0} kit files match kit-manifest.json" -f @($manifest.files.PSObject.Properties).Count) }
    else { Add-Check "kit manifest" "FAIL" ((@($probs | Select-Object -First 3 | ForEach-Object { "{0} ({1})" -f $_.Path, $_.Problem }) -join "; ") + $(if ($probs.Count -gt 3) { "; ..." } else { "" })) }
  } catch {
    Add-Check "kit manifest" "FAIL" "kit-manifest.json is not valid JSON"
  }
}

$exit = Get-TbvDoctorExitCode -Checks $checks.ToArray()
if ($Json) {
  [pscustomobject]@{ exitCode = $exit; checks = $checks.ToArray() } | ConvertTo-Json -Depth 4
} else {
  Write-Host "TrustButVerify doctor"
  Write-Host "---------------------"
  foreach ($l in (Format-TbvDoctorTable -Checks $checks.ToArray())) { Write-Host $l }
  Write-Host ""
  $word = @("all checks passed", "warnings", "failures")[$exit]
  Write-Host ("Result: {0} (exit {1})" -f $word, $exit)
}
exit $exit
