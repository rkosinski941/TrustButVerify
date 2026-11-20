# build-allowlist.ps1
# Builds a PROPOSED network allowlist from traffic that OpenCode (and the
# node/bun processes it runs) already made:
#   - watcher CSV logs (watch-YYYYMMDD.csv) in the log folder
#   - Sysmon Event 3 (network connect) and Event 22 (DNS query), if Sysmon
#     is installed and this user can read its log
# Aggregates host / IP / port with counts and first/last seen, and writes
# proposed-allowlist-<stamp>.json and .md under <log folder>\reports\.
#
# ADVISORY MONITORING, NOT ENFORCEMENT. Nothing is blocked and nothing is
# applied automatically. To use a list for alerts, review it, delete what
# you do not recognise, copy it to the approved path (default
# %LOCALAPPDATA%\opencode-watch\approved-allowlist.json, or allowlistPath
# in trustbutverify.json), and set "alertOnUnlistedDestinations": true.
# No admin. No network calls.
#
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build-allowlist.ps1
#   ... -Days 14 -NoSysmon -OutputDirectory C:\somewhere

[CmdletBinding()]
param(
  [int]$Days = 7,
  [string]$LogDirectory = "",
  [string]$OutputDirectory = "",
  [string[]]$WatcherCsv = @(),
  [string[]]$ProcessNames = @(),
  [switch]$NoSysmon
)

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

$lib = Join-Path $PSScriptRoot "lib"
. (Join-Path $lib "WatchCommon.ps1")
. (Join-Path $lib "TbvSettings.ps1")
. (Join-Path $lib "TbvAllowlist.ps1")

if ($Days -lt 1) { $Days = 7 }
if (@($ProcessNames).Count -eq 0) { $ProcessNames = Get-TbvAllowlistProcessNames }
if ([string]::IsNullOrWhiteSpace($LogDirectory)) {
  $settings = Read-TbvSettings
  $LogDirectory = [string]$settings["logDir"]
  if ([string]::IsNullOrWhiteSpace($LogDirectory)) { $LogDirectory = Get-OpenCodeWatchLogDir }
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $LogDirectory "reports" }
if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null }

$since = (Get-Date).AddDays(-$Days)
$agg = New-TbvDestinationAggregator

# Sysmon first, so DNS answers can name the IPs in watcher rows.
$sysmonNote = "skipped (-NoSysmon)"
if (-not $NoSysmon) {
  if (-not (Test-IsWindowsOS)) {
    $sysmonNote = "skipped (not Windows)"
  } else {
    try {
      $events = @(Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-Sysmon/Operational"; Id = 3, 22; StartTime = $since } -ErrorAction Stop | Sort-Object TimeCreated)
      foreach ($ev in $events) {
        $map = @{}
        try {
          $xml = [xml]$ev.ToXml()
          foreach ($d in @($xml.Event.EventData.Data)) { if ($d.Name) { $map[[string]$d.Name] = [string]$d.'#text' } }
        } catch { continue }
        Add-TbvSysmonEvent -Agg $agg -Id ([int]$ev.Id) -Data $map -Time $ev.TimeCreated -ProcessNames $ProcessNames
      }
      $sysmonNote = ("{0} events read" -f $events.Count)
    } catch {
      $msg = [string]$_.Exception.Message
      if ($msg -match '(?i)No events|No matching events') { $sysmonNote = "no matching events" }
      elseif (Test-IsSysmonLogAccessError $_) { $sysmonNote = "not readable by this user (Event Log Readers; sign out and back in after install-sysmon.ps1)" }
      else { $sysmonNote = "not available (Sysmon not installed?)" }
    }
  }
}

$csvFiles = @($WatcherCsv)
if ($csvFiles.Count -eq 0 -and (Test-Path -LiteralPath $LogDirectory)) {
  $csvFiles = @(Get-ChildItem -LiteralPath $LogDirectory -Filter "watch-*.csv" -File | Where-Object { $_.LastWriteTime -ge $since } | Sort-Object Name | ForEach-Object { $_.FullName })
}
foreach ($f in $csvFiles) { Import-TbvWatcherCsv -Agg $agg -Path $f -ProcessNames $ProcessNames -Since $since }

$window = ("last {0} days ({1} to {2}); watcher CSV files: {3}; Sysmon: {4}" -f $Days, $since.ToString("yyyy-MM-dd HH:mm K"), (Get-Date).ToString("yyyy-MM-dd HH:mm K"), $csvFiles.Count, $sysmonNote)
$proposed = ConvertTo-TbvProposedAllowlist -Agg $agg -Window $window
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$jsonPath = Join-Path $OutputDirectory ("proposed-allowlist-{0}.json" -f $stamp)
$mdPath = Join-Path $OutputDirectory ("proposed-allowlist-{0}.md" -f $stamp)
$enc = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($jsonPath, (($proposed | ConvertTo-Json -Depth 6) -replace "`r`n", "`n") + "`n", $enc)
[System.IO.File]::WriteAllText($mdPath, (ConvertTo-TbvAllowlistMarkdown -Proposed $proposed), $enc)

Write-Host ("Destinations: {0}" -f @($proposed.destinations).Count)
Write-Host ("Window: {0}" -f $window)
Write-Host ("Wrote {0}" -f $jsonPath)
Write-Host ("Wrote {0}" -f $mdPath)
Write-Host ("Nothing was applied. To use it for alerts: review it, copy it to {0}," -f (Get-TbvDefaultApprovedAllowlistPath -LogDir $LogDirectory))
Write-Host "and set alertOnUnlistedDestinations to true in trustbutverify.json. Advisory monitoring only; nothing is blocked."
