# test-allowlist.ps1
# Tests for build-allowlist.ps1 and lib/TbvAllowlist.ps1: aggregation from
# watcher CSV and Sysmon 3/22 data, proposed JSON/markdown, approved-list
# matching, and the opt-in unlisted-destination alert. Run from the kit
# root:
#   pwsh -NoProfile -File tests/test-allowlist.ps1

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

$kit = Split-Path -Parent $PSScriptRoot
. (Join-Path $kit "lib\WatchCommon.ps1")
. (Join-Path $kit "lib\TbvSettings.ps1")
. (Join-Path $kit "lib\TbvAllowlist.ps1")

$failed = 0
$passed = 0
function Assert-True {
  param([bool]$Cond, [string]$Name, [string]$Detail = "")
  if ($Cond) { $script:passed++; Write-Host ("PASS  {0}" -f $Name) }
  else { $script:failed++; Write-Host ("FAIL  {0}" -f $Name); if ($Detail) { Write-Host ("      {0}" -f $Detail) } }
}

$csv = Join-Path $PSScriptRoot "fixtures\watch-allowlist-sample.csv"

# Sysmon data first (DNS names an IP the watcher saw without a host name)
$agg = New-TbvDestinationAggregator
$t0 = [datetime]"2026-11-02T09:59:00"
Add-TbvSysmonEvent -Agg $agg -Id 22 -Time $t0 -Data @{ Image = "C:\Tools\node.exe"; QueryName = "registry.example.org"; QueryResults = "type:  5 cdn.example.net;::ffff:198.51.100.7;" }
Add-TbvSysmonEvent -Agg $agg -Id 22 -Time $t0 -Data @{ Image = "C:\Tools\opencode.exe"; QueryName = "telemetry.example.io"; QueryResults = "::ffff:203.0.113.99;" }
Add-TbvSysmonEvent -Agg $agg -Id 3 -Time $t0.AddSeconds(30) -Data @{ Image = "C:\Tools\opencode.exe"; DestinationIp = "203.0.113.5"; DestinationPort = "443"; DestinationHostname = "api.example.com"; Initiated = "true" }
Add-TbvSysmonEvent -Agg $agg -Id 3 -Time $t0 -Data @{ Image = "C:\Tools\opencode.exe"; DestinationIp = "127.0.0.1"; DestinationPort = "4096"; Initiated = "true" }
Add-TbvSysmonEvent -Agg $agg -Id 3 -Time $t0 -Data @{ Image = "C:\Windows\explorer.exe"; DestinationIp = "203.0.113.50"; DestinationPort = "443"; Initiated = "true" }
Add-TbvSysmonEvent -Agg $agg -Id 3 -Time $t0 -Data @{ Image = "C:\Tools\opencode.exe"; DestinationIp = "203.0.113.51"; DestinationPort = "55000"; Initiated = "false" }
Import-TbvWatcherCsv -Agg $agg -Path $csv

$p = ConvertTo-TbvProposedAllowlist -Agg $agg -Window "test"
$d = @($p.destinations)
function Find-Dest([string]$h, [int]$port) { return @($d | Where-Object { $_.host -eq $h -and $_.port -eq $port }) }

$api = @(Find-Dest "api.example.com" 443)
Assert-True ($api.Count -eq 1) "api.example.com:443 aggregated into one entry"
Assert-True ($api[0].count -eq 3) "api.example.com count = 2 watcher + 1 sysmon" ("count=" + $api[0].count)
Assert-True (($api[0].sources -join ",") -eq "sysmon,watcher") "sources recorded" ($api[0].sources -join ",")
Assert-True ($api[0].firstSeen -like "2026-11-01T09:00:01*") "firstSeen from earliest row" $api[0].firstSeen
Assert-True ($api[0].lastSeen -like "2026-11-02T09:59:30*") "lastSeen from latest row" $api[0].lastSeen
Assert-True (@($api[0].ips) -contains "203.0.113.5") "IP recorded"
$reg = @(Find-Dest "registry.example.org" 443)
Assert-True ($reg.Count -eq 1 -and @($reg[0].processes) -contains "node") "watcher IP named via Sysmon DNS answer"
Assert-True (@(Find-Dest "registry.example.org" 0).Count -eq 0) "DNS-only row folded into the connection row"
Assert-True (@(Find-Dest "telemetry.example.io" 0).Count -eq 1) "DNS lookup without a captured connection is kept"
Assert-True (@($d | Where-Object { @($_.ips) -contains "127.0.0.1" }).Count -eq 0) "loopback excluded"
Assert-True (@($d | Where-Object { $_.host -eq "github.com" }).Count -eq 0) "non-opencode/node/bun process excluded (git)"
Assert-True (@($d | Where-Object { @($_.ips) -contains "203.0.113.50" }).Count -eq 0) "other process in Sysmon excluded"
Assert-True (@($d | Where-Object { @($_.ips) -contains "203.0.113.51" }).Count -eq 0) "inbound (Initiated=false) excluded"
Assert-True (@($d | Where-Object { $_.port -eq 4096 }).Count -eq 0) "listen row excluded"
$lan = @($d | Where-Object { @($_.ips) -contains "192.168.1.20" })
Assert-True ($lan.Count -eq 1 -and $lan[0].private -and @($lan[0].processes) -contains "bun") "private LAN destination flagged"
Assert-True ($p.advisory -eq $true -and $p.status -eq "proposed") "proposed list is marked advisory/proposed"
Assert-True ($p.counts.skippedLoopback -ge 2) "loopback skips counted"
$md = ConvertTo-TbvAllowlistMarkdown -Proposed $p
Assert-True ($md -match 'ADVISORY ONLY' -and $md -match 'api\.example\.com' -and $md -match 'private/LAN') "markdown report"
$bytes = [System.Text.Encoding]::UTF8.GetBytes($md)
Assert-True (@($bytes | Where-Object { $_ -gt 127 }).Count -eq 0) "markdown is ASCII"

# Since filter
$agg2 = New-TbvDestinationAggregator
Import-TbvWatcherCsv -Agg $agg2 -Path $csv -Since ([datetime]"2026-11-02T00:00:00")
$p2 = ConvertTo-TbvProposedAllowlist -Agg $agg2
Assert-True (@($p2.destinations | Where-Object { $_.host -eq "api.example.com" }).Count -eq 0) "-Since drops older rows"

# Approved list matching
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("tbv-allow-test-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
  $approved = Join-Path $tmp "approved-allowlist.json"
  [System.IO.File]::WriteAllText($approved, (($p | ConvertTo-Json -Depth 6)))
  $r = Read-TbvAllowlist -Path $approved
  Assert-True ($r.Ok -and @($r.Entries).Count -eq $d.Count) "proposed JSON round-trips as an approved list"
  $e = $r.Entries
  Assert-True (Test-TbvDestinationListed -Entries $e -HostName "api.example.com" -Ip "203.0.113.200" -Port 443) "listed by host"
  Assert-True (Test-TbvDestinationListed -Entries $e -HostName "" -Ip "203.0.113.5" -Port 443) "listed by IP"
  Assert-True (-not (Test-TbvDestinationListed -Entries $e -HostName "api.example.com" -Ip "203.0.113.5" -Port 8443)) "port must match"
  Assert-True (-not (Test-TbvDestinationListed -Entries $e -HostName "evil.example.com" -Ip "198.18.0.1" -Port 443)) "unknown destination not listed"
  Assert-True (Test-TbvDestinationListed -Entries $e -Ip "127.0.0.1" -Port 9222) "loopback is out of scope (existing loopback alerts cover it)"

  $hand = Join-Path $tmp "hand.jsonc"
  [System.IO.File]::WriteAllText($hand, "{ // hand-written`n `"destinations`": [ { `"host`": `"*.githubusercontent.com`" }, `"registry.npmjs.org:443`", { `"host`": `"203.0.113.9`", `"port`": 22 } ] }")
  $h = Read-TbvAllowlist -Path $hand
  Assert-True $h.Ok "hand-written JSONC allowlist loads"
  Assert-True (Test-TbvDestinationListed -Entries $h.Entries -HostName "raw.githubusercontent.com" -Port 443) "wildcard host, any port"
  Assert-True (-not (Test-TbvDestinationListed -Entries $h.Entries -HostName "githubusercontent.com.evil.test" -Port 443)) "wildcard does not match a lookalike suffix"
  Assert-True (-not (Test-TbvDestinationListed -Entries $h.Entries -HostName "githubusercontent.com" -Port 443)) "wildcard needs a subdomain"
  Assert-True (Test-TbvDestinationListed -Entries $h.Entries -HostName "registry.npmjs.org" -Port 443) "host:port string entry"
  Assert-True (Test-TbvDestinationListed -Entries $h.Entries -Ip "203.0.113.9" -Port 22) "IP literal host entry"
  Assert-True (-not (Read-TbvAllowlist -Path (Join-Path $tmp "missing.json")).Ok) "missing allowlist is not Ok"
  [System.IO.File]::WriteAllText((Join-Path $tmp "bad.json"), "{ nope")
  Assert-True (-not (Read-TbvAllowlist -Path (Join-Path $tmp "bad.json")).Ok) "invalid allowlist is not Ok"

  # Unlisted alert decision
  Assert-True ((Get-TbvUnlistedAlert -Enabled $false -Entries $e -HostName "evil.test" -Ip "198.18.0.1" -Port 443 -State "Established") -eq "") "off by default: no alert"
  $lab = Get-TbvUnlistedAlert -Enabled $true -Entries $e -HostName "evil.test" -Ip "198.18.0.1" -Port 443 -State "Established"
  Assert-True ($lab -like "ALERT: unlisted destination evil.test:443*advisory*") "unlisted destination alerts when enabled" $lab
  Assert-True ((Get-TbvUnlistedAlert -Enabled $true -Entries $e -HostName "api.example.com" -Ip "203.0.113.5" -Port 443 -State "Established") -eq "") "listed destination: no alert"
  Assert-True ((Get-TbvUnlistedAlert -Enabled $true -Entries $e -Ip "0.0.0.0" -Port 0 -State "Listen") -eq "") "listen rows never alert"
  Assert-True ((Join-TbvAlertLabel -Existing "ALERT: loopback destination port 1 (not on allowlist)" -Unlisted $lab) -match '^ALERT: loopback.*; unlisted') "labels combine"
  Assert-True ((Join-TbvAlertLabel -Existing "INFO: x" -Unlisted $lab) -match '^ALERT: unlisted.*; INFO: x$') "ALERT wins over INFO"

  # Settings and initialization
  $s = Get-TbvDefaultSettings
  Assert-True ($s["alertOnUnlistedDestinations"] -eq $false) "settings default: alertOnUnlistedDestinations=false"
  $s2 = Read-TbvSettings -Text ("{ `"alertOnUnlistedDestinations`": true, `"allowlistPath`": `"" + $approved.Replace('\', '\\') + "`" }")
  Assert-True ($s2["alertOnUnlistedDestinations"] -eq $true -and $s2["allowlistPath"] -eq $approved) "settings parse the new keys"
  $s3 = Read-TbvSettings -Text "{ `"alertOnUnlistedDestinations`": `"maybe`" }"
  Assert-True ($s3["alertOnUnlistedDestinations"] -eq $false -and @($s3["warnings"]).Count -ge 1) "invalid value warns and stays off"
  $json = ConvertTo-TbvSettingsJson -Settings $s2
  Assert-True ($json -match '"alertOnUnlistedDestinations": true' -and $json -match '"allowlistPath"') "settings writer keeps the new keys"
  $init = Initialize-TbvUnlistedAlerting -Settings $s2 -LogDir $tmp
  Assert-True ($init.Enabled -and @($init.Entries).Count -gt 0) "initialization loads the approved list"
  $s4 = Read-TbvSettings -Text "{ `"alertOnUnlistedDestinations`": true }"
  $init2 = Initialize-TbvUnlistedAlerting -Settings $s4 -LogDir (Join-Path $tmp "nowhere")
  Assert-True ((-not $init2.Enabled) -and $init2.Message -match 'OFF') "missing approved list turns alerts off with a message"
  $init3 = Initialize-TbvUnlistedAlerting -Settings (Get-TbvDefaultSettings) -LogDir $tmp
  Assert-True ((-not $init3.Enabled) -and -not $init3.Message) "feature off: silent"

  # build-allowlist.ps1 end to end, never touching the approved path
  $logDir = Join-Path $tmp "logs"
  New-Item -ItemType Directory -Force -Path $logDir | Out-Null
  $today = Join-Path $logDir ("watch-{0}.csv" -f (Get-Date -Format "yyyyMMdd"))
  $lines = [System.IO.File]::ReadAllLines($csv)
  $stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss zzz")
  $out = New-Object System.Collections.Generic.List[string]
  $out.Add($lines[0])
  foreach ($l in $lines[1..($lines.Count - 1)]) { $out.Add(($stamp + $l.Substring($l.IndexOf(",")))) }
  [System.IO.File]::WriteAllLines($today, $out.ToArray())
  $pwsh = (Get-Process -Id $PID).Path
  $res = & $pwsh -NoProfile -File (Join-Path $kit "build-allowlist.ps1") -LogDirectory $logDir -NoSysmon 2>&1
  $code = $LASTEXITCODE
  $jsonOut = @(Get-ChildItem -LiteralPath (Join-Path $logDir "reports") -Filter "proposed-allowlist-*.json")
  $mdOut = @(Get-ChildItem -LiteralPath (Join-Path $logDir "reports") -Filter "proposed-allowlist-*.md")
  Assert-True ($code -eq 0 -and $jsonOut.Count -eq 1 -and $mdOut.Count -eq 1) "build-allowlist.ps1 writes JSON and markdown" (($res | ForEach-Object { "$_" }) -join " | ")
  Assert-True (-not (Test-Path -LiteralPath (Join-Path $logDir "approved-allowlist.json"))) "build-allowlist.ps1 never writes the approved list"
  $pj = ConvertFrom-Json ([System.IO.File]::ReadAllText($jsonOut[0].FullName))
  Assert-True ($pj.status -eq "proposed" -and @($pj.destinations | Where-Object { $_.host -eq "api.example.com" }).Count -eq 1) "build-allowlist.ps1 output has the observed host"
  Assert-True ((($res | ForEach-Object { "$_" }) -join " ") -match 'Nothing was applied') "build-allowlist.ps1 says nothing was applied"
} finally {
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("Allowlist tests: {0} passed, {1} failed" -f $passed, $failed)
if ($failed -gt 0) { exit 1 }
exit 0
