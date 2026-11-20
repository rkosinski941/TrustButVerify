# TbvAllowlist.ps1
# Build a PROPOSED network allowlist from observed traffic (watcher CSV
# logs and Sysmon Event 3 / 22), and check destinations against an
# APPROVED allowlist for the opt-in "unlisted destination" alert.
#
# This is advisory monitoring, not enforcement: nothing here blocks a
# connection. A proposed list is never applied automatically; a person
# reviews it and copies it to the approved path. ASCII only. Dot-source
# after WatchCommon.ps1.

Set-StrictMode -Version 1

function Get-TbvAllowlistSchema { return "trustbutverify-allowlist/1" }

function Get-TbvDefaultApprovedAllowlistPath {
  param([string]$LogDir = "")
  if ([string]::IsNullOrWhiteSpace($LogDir)) { $LogDir = Get-OpenCodeWatchLogDir }
  return (Join-Path $LogDir "approved-allowlist.json")
}

function Get-TbvAllowlistProcessNames { return @("opencode", "node", "bun") }

function Test-TbvPrivateAddress {
  param([string]$Address)
  $a = Normalize-TbvIpAddress $Address
  if ($a -match '^10\.' -or $a -match '^192\.168\.' -or $a -match '^172\.(1[6-9]|2[0-9]|3[01])\.' -or
      $a -match '^169\.254\.' -or $a -match '^f[cd][0-9a-f]{2}:' -or $a -match '^fe80:') { return $true }
  return $false
}

function Test-TbvIpLiteral {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
  $ip = $null
  return [System.Net.IPAddress]::TryParse($Text.Trim().TrimStart('[').TrimEnd(']'), [ref]$ip)
}

function New-TbvDestinationAggregator {
  return @{
    Entries = @{}
    DnsMap  = @{}
    Counts  = @{ watcherRows = 0; sysmonNetwork = 0; sysmonDns = 0; skippedLoopback = 0; skippedOtherProcess = 0 }
  }
}

function Test-TbvWatchedProcess {
  param([string]$Name, [string[]]$ProcessNames)
  $b = Get-TbvProcessBaseName $Name
  if (-not $b) { return $false }
  foreach ($n in $ProcessNames) { if ($b -eq ([string]$n).ToLowerInvariant()) { return $true } }
  return $false
}

function Add-TbvDnsAnswer {
  # Sysmon Event 22: QueryResults look like "type:  5 a.example;::ffff:1.2.3.4;"
  param($Agg, [string]$QueryName, [string]$QueryResults)
  $q = ([string]$QueryName).Trim().TrimEnd('.').ToLowerInvariant()
  if (-not $q) { return }
  foreach ($part in ([string]$QueryResults -split '[;\s]+')) {
    $p = $part.Trim()
    if ($p -match '^(?i)::ffff:([0-9.]+)$') { $p = $Matches[1] }
    if (Test-TbvIpLiteral $p) { $Agg.DnsMap[(Normalize-TbvIpAddress $p)] = $q }
  }
}

function Add-TbvDestinationObservation {
  param(
    $Agg,
    [datetime]$Time,
    [string]$HostName = "",
    [string]$Ip = "",
    [int]$Port = 0,
    [string]$Process = "",
    [string]$Source = ""
  )
  $ipN = Normalize-TbvIpAddress $Ip
  $h = ([string]$HostName).Trim().TrimEnd('.').ToLowerInvariant()
  if ($h -and (Test-TbvIpLiteral $h)) {
    if (-not $ipN) { $ipN = Normalize-TbvIpAddress $h }
    $h = ""
  }
  if ($ipN -and ((Test-IsLoopbackAddress $ipN) -or (Test-IsUnspecifiedAddress $ipN))) { $Agg.Counts.skippedLoopback++; return }
  if ($h -eq "localhost" -or $h.EndsWith(".localhost")) { $Agg.Counts.skippedLoopback++; return }
  if (-not $h -and $ipN -and $Agg.DnsMap.ContainsKey($ipN)) { $h = [string]$Agg.DnsMap[$ipN] }
  if (-not $h -and -not $ipN) { return }
  $h = Protect-SecretText $h
  $keyHost = $h
  if (-not $keyHost) { $keyHost = "ip:" + $ipN }
  $key = "{0}|{1}" -f $keyHost, $Port
  if (-not $Agg.Entries.ContainsKey($key)) {
    $Agg.Entries[$key] = [pscustomobject]@{
      host      = $h
      ips       = New-Object System.Collections.Generic.List[string]
      port      = $Port
      count     = 0
      firstSeen = $Time
      lastSeen  = $Time
      processes = New-Object System.Collections.Generic.List[string]
      sources   = New-Object System.Collections.Generic.List[string]
      private   = $false
    }
  }
  $e = $Agg.Entries[$key]
  $e.count++
  if ($Time -lt $e.firstSeen) { $e.firstSeen = $Time }
  if ($Time -gt $e.lastSeen) { $e.lastSeen = $Time }
  if ($ipN -and -not $e.ips.Contains($ipN)) { $e.ips.Add($ipN) }
  if ($ipN -and (Test-TbvPrivateAddress $ipN)) { $e.private = $true }
  $pb = Get-TbvProcessBaseName $Process
  if ($pb -and -not $e.processes.Contains($pb)) { $e.processes.Add($pb) }
  if ($Source -and -not $e.sources.Contains($Source)) { $e.sources.Add($Source) }
}

function ConvertFrom-TbvWatchTime {
  param([string]$Text)
  $t = [datetime]::MinValue
  if ([datetime]::TryParse($Text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeLocal, [ref]$t)) { return $t }
  return [datetime]::MinValue
}

function Import-TbvWatcherCsv {
  # Watcher CSV rows: Time,Kind,Alert,Pid,Ppid,Name,LocalAddress,LocalPort,
  # RemoteAddress,RemotePort,RemoteHost,State,CommandLine
  param($Agg, [string]$Path, [string[]]$ProcessNames = (Get-TbvAllowlistProcessNames), [datetime]$Since = [datetime]::MinValue)
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $rows = @(Import-Csv -LiteralPath $Path)
  foreach ($r in $rows) {
    if ([string]$r.Kind -ne "tcp") { continue }
    $state = ([string]$r.State).ToLowerInvariant()
    if ($state -eq "listen" -or $state -eq "bound") { continue }
    $port = 0
    [void][int]::TryParse([string]$r.RemotePort, [ref]$port)
    if ($port -le 0) { continue }
    if (-not (Test-TbvWatchedProcess -Name ([string]$r.Name) -ProcessNames $ProcessNames)) { $Agg.Counts.skippedOtherProcess++; continue }
    $t = ConvertFrom-TbvWatchTime ([string]$r.Time)
    if ($t -lt $Since) { continue }
    $Agg.Counts.watcherRows++
    Add-TbvDestinationObservation -Agg $Agg -Time $t -HostName ([string]$r.RemoteHost) -Ip ([string]$r.RemoteAddress) -Port $port -Process ([string]$r.Name) -Source "watcher"
  }
}

function Add-TbvSysmonEvent {
  # $Data: EventData name -> value map (as from Get-EventDataMap).
  param($Agg, [int]$Id, $Data, [datetime]$Time, [string[]]$ProcessNames = (Get-TbvAllowlistProcessNames))
  $image = ""
  if ($Data.ContainsKey("Image")) { $image = [string]$Data["Image"] }
  if (-not (Test-TbvWatchedProcess -Name ([System.IO.Path]::GetFileName($image.Replace('\', '/'))) -ProcessNames $ProcessNames)) {
    $Agg.Counts.skippedOtherProcess++
    return
  }
  $proc = [System.IO.Path]::GetFileName($image.Replace('\', '/'))
  if ($Id -eq 22) {
    $q = ""
    $res = ""
    if ($Data.ContainsKey("QueryName")) { $q = [string]$Data["QueryName"] }
    if ($Data.ContainsKey("QueryResults")) { $res = [string]$Data["QueryResults"] }
    Add-TbvDnsAnswer -Agg $Agg -QueryName $q -QueryResults $res
    $Agg.Counts.sysmonDns++
    if ($q) { Add-TbvDestinationObservation -Agg $Agg -Time $Time -HostName $q -Port 0 -Process $proc -Source "sysmon-dns" }
    return
  }
  if ($Id -ne 3) { return }
  $init = ""
  if ($Data.ContainsKey("Initiated")) { $init = ([string]$Data["Initiated"]).ToLowerInvariant() }
  if ($init -eq "false") { return }
  $dst = ""
  $dhost = ""
  $port = 0
  if ($Data.ContainsKey("DestinationIp")) { $dst = [string]$Data["DestinationIp"] }
  if ($Data.ContainsKey("DestinationHostname")) { $dhost = [string]$Data["DestinationHostname"] }
  if ($Data.ContainsKey("DestinationPort")) { [void][int]::TryParse([string]$Data["DestinationPort"], [ref]$port) }
  $Agg.Counts.sysmonNetwork++
  Add-TbvDestinationObservation -Agg $Agg -Time $Time -HostName $dhost -Ip $dst -Port $port -Process $proc -Source "sysmon"
}

function Merge-TbvDnsOnlyEntries {
  # A DNS-only entry (port 0) whose host also appears with a port is
  # folded into the connection entries; DNS-only hosts are kept so the
  # reviewer sees lookups that never turned into a captured connection.
  param($Agg)
  $withPort = @{}
  foreach ($e in $Agg.Entries.Values) { if ($e.port -gt 0 -and $e.host) { $withPort[$e.host] = $true } }
  foreach ($k in @($Agg.Entries.Keys)) {
    $e = $Agg.Entries[$k]
    if ($e.port -eq 0 -and $e.host -and $withPort.ContainsKey($e.host)) { $Agg.Entries.Remove($k) }
  }
}

function ConvertTo-TbvProposedAllowlist {
  param($Agg, [string]$GeneratedBy = "build-allowlist.ps1", [string]$Window = "")
  Merge-TbvDnsOnlyEntries -Agg $Agg
  $list = New-Object System.Collections.Generic.List[object]
  foreach ($e in ($Agg.Entries.Values | Sort-Object @{ Expression = { -1 * $_.count } }, host, port)) {
    $list.Add([ordered]@{
      host      = $e.host
      ips       = @($e.ips | Sort-Object)
      port      = $e.port
      count     = $e.count
      firstSeen = $e.firstSeen.ToString("yyyy-MM-ddTHH:mm:sszzz")
      lastSeen  = $e.lastSeen.ToString("yyyy-MM-ddTHH:mm:sszzz")
      processes = @($e.processes | Sort-Object)
      sources   = @($e.sources | Sort-Object)
      private   = [bool]$e.private
    })
  }
  return [ordered]@{
    schema       = Get-TbvAllowlistSchema
    status       = "proposed"
    advisory     = $true
    note         = "Proposed from observed traffic. Review every entry before approving. This list is used for monitoring alerts only; it does not block any connection."
    generated    = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
    generatedBy  = $GeneratedBy
    window       = $Window
    counts       = $Agg.Counts
    destinations = $list.ToArray()
  }
}

function ConvertTo-TbvAllowlistMarkdown {
  param($Proposed)
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine("# Proposed OpenCode network allowlist")
  [void]$sb.AppendLine("")
  [void]$sb.AppendLine(("Generated: {0}. Window: {1}." -f $Proposed.generated, $Proposed.window))
  [void]$sb.AppendLine("")
  [void]$sb.AppendLine("ADVISORY ONLY. This was built from traffic that already happened. It is not applied")
  [void]$sb.AppendLine("automatically and it never blocks anything. Review each row; delete anything you do not")
  [void]$sb.AppendLine("recognise, then copy the JSON file to the approved path to enable unlisted-destination alerts.")
  [void]$sb.AppendLine("Loopback traffic is not listed here; the existing loopback alerts cover it.")
  [void]$sb.AppendLine("")
  $c = $Proposed.counts
  [void]$sb.AppendLine(("Inputs: watcher rows {0}, Sysmon network {1}, Sysmon DNS {2}; skipped loopback {3}, other processes {4}." -f $c.watcherRows, $c.sysmonNetwork, $c.sysmonDns, $c.skippedLoopback, $c.skippedOtherProcess))
  [void]$sb.AppendLine("")
  [void]$sb.AppendLine("| Host | IPs | Port | Count | First seen | Last seen | Processes | Sources | Note |")
  [void]$sb.AppendLine("|---|---|---|---|---|---|---|---|---|")
  foreach ($d in $Proposed.destinations) {
    $note = ""
    if ($d.private) { $note = "private/LAN address" }
    if ($d.port -eq 0) { $note = (($note + " DNS lookup only").Trim()) }
    $hostCell = $d.host
    if (-not $hostCell) { $hostCell = "(no name)" }
    $ips = (@($d.ips) | Select-Object -First 4) -join ", "
    if (@($d.ips).Count -gt 4) { $ips = $ips + ", ..." }
    $port = [string]$d.port
    if ($d.port -eq 0) { $port = "-" }
    [void]$sb.AppendLine(("| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} |" -f $hostCell, $ips, $port, $d.count, $d.firstSeen, $d.lastSeen, (@($d.processes) -join ", "), (@($d.sources) -join ", "), $note))
  }
  if (@($Proposed.destinations).Count -eq 0) { [void]$sb.AppendLine("| (none observed) | | | | | | | | |") }
  return $sb.ToString()
}

# --- Approved list -----------------------------------------------------------

function Read-TbvAllowlist {
  # Returns {Ok, Reason, Entries}. Entries: {host, ips, port}. host may be
  # "*.example.com". port 0 or missing = any port.
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
    return [pscustomobject]@{ Ok = $false; Reason = ("allowlist not found: {0}" -f $Path); Entries = @() }
  }
  try {
    $obj = ConvertFrom-Jsonc -Text ([System.IO.File]::ReadAllText($Path))
  } catch {
    return [pscustomobject]@{ Ok = $false; Reason = "allowlist is not valid JSON"; Entries = @() }
  }
  $dests = Get-TbvObjectValueSafe $obj "destinations"
  if ($null -eq $dests) {
    return [pscustomobject]@{ Ok = $false; Reason = "allowlist has no destinations array"; Entries = @() }
  }
  $out = New-Object System.Collections.Generic.List[object]
  foreach ($d in @($dests)) {
    if ($d -is [string]) {
      $parts = $d.Split(':')
      $p = 0
      if ($parts.Count -eq 2) { [void][int]::TryParse($parts[1], [ref]$p) }
      $out.Add([pscustomobject]@{ host = $parts[0].ToLowerInvariant(); ips = @(); port = $p })
      continue
    }
    $h = [string](Get-TbvObjectValueSafe $d "host")
    $ips = @(Get-TbvObjectValueSafe $d "ips") | Where-Object { $_ } | ForEach-Object { Normalize-TbvIpAddress ([string]$_) }
    $pv = Get-TbvObjectValueSafe $d "port"
    $p = 0
    if ($null -ne $pv) { [void][int]::TryParse([string]$pv, [ref]$p) }
    $out.Add([pscustomobject]@{ host = $h.ToLowerInvariant(); ips = @($ips); port = $p })
  }
  return [pscustomobject]@{ Ok = $true; Reason = "ok"; Entries = $out.ToArray() }
}

function Get-TbvObjectValueSafe {
  param($Obj, [string]$Key)
  if ($null -eq $Obj) { return $null }
  if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($Key)) { return $Obj[$Key] }; return $null }
  $prop = $Obj.PSObject.Properties[$Key]
  if ($prop) { return $prop.Value }
  return $null
}

function Test-TbvHostMatch {
  param([string]$Pattern, [string]$HostName)
  if (-not $Pattern -or -not $HostName) { return $false }
  $p = $Pattern.ToLowerInvariant().TrimEnd('.')
  $h = $HostName.ToLowerInvariant().TrimEnd('.')
  if ($p.StartsWith("*.")) { return ($h.EndsWith($p.Substring(1)) -and $h.Length -gt ($p.Length - 1)) }
  return ($p -eq $h)
}

function Test-TbvDestinationListed {
  # True when (host matches or IP is listed) and the port matches. Loopback
  # and unspecified addresses are not the allowlist's job: always "listed".
  param($Entries, [string]$HostName = "", [string]$Ip = "", [int]$Port = 0)
  $ipN = Normalize-TbvIpAddress $Ip
  if ($ipN -and ((Test-IsLoopbackAddress $ipN) -or (Test-IsUnspecifiedAddress $ipN))) { return $true }
  foreach ($e in @($Entries)) {
    if ($e.port -gt 0 -and $Port -gt 0 -and $e.port -ne $Port) { continue }
    if ($HostName -and (Test-TbvHostMatch -Pattern $e.host -HostName $HostName)) { return $true }
    if ($ipN -and (@($e.ips) -contains $ipN)) { return $true }
    if ($ipN -and $e.host -and (Test-TbvIpLiteral $e.host) -and ((Normalize-TbvIpAddress $e.host) -eq $ipN)) { return $true }
  }
  return $false
}

function Get-TbvUnlistedLabel {
  param([string]$HostName, [string]$Ip, [int]$Port)
  $who = $HostName
  if (-not $who) { $who = $Ip }
  return ("ALERT: unlisted destination {0}:{1} (not in approved allowlist; advisory)" -f $who, $Port)
}

function Get-TbvUnlistedAlert {
  # Returns an ALERT label for an outbound TCP destination that is not in
  # the approved allowlist, or "" when the feature is off, the row is not
  # an outbound connection, or the destination is listed.
  param(
    [bool]$Enabled,
    $Entries,
    [string]$HostName = "",
    [string]$Ip = "",
    [int]$Port = 0,
    [string]$State = ""
  )
  if (-not $Enabled) { return "" }
  if ($Port -le 0) { return "" }
  $st = ([string]$State).ToLowerInvariant()
  if ($st -eq "listen" -or $st -eq "bound") { return "" }
  if ((Test-IsLoopbackAddress $Ip) -or (Test-IsUnspecifiedAddress $Ip)) { return "" }
  if (Test-TbvDestinationListed -Entries $Entries -HostName $HostName -Ip $Ip -Port $Port) { return "" }
  return (Get-TbvUnlistedLabel -HostName $HostName -Ip $Ip -Port $Port)
}

function Join-TbvAlertLabel {
  # Combine an existing label ("", "INFO: ...", "ALERT: ...") with an
  # unlisted ALERT label.
  param([string]$Existing, [string]$Unlisted)
  if (-not $Unlisted) { return $Existing }
  if (-not $Existing) { return $Unlisted }
  if ($Existing.StartsWith("ALERT: ")) { return ($Existing + "; " + $Unlisted.Substring(7)) }
  return ($Unlisted + "; " + $Existing)
}

function Initialize-TbvUnlistedAlerting {
  # Returns {Enabled, Entries, Message}. Missing or invalid allowlist turns
  # the feature off with a message instead of alerting on everything.
  param($Settings, [string]$LogDir)
  $on = $false
  if ($Settings -and $Settings.Contains("alertOnUnlistedDestinations")) { $on = [bool]$Settings["alertOnUnlistedDestinations"] }
  if (-not $on) { return [pscustomobject]@{ Enabled = $false; Entries = @(); Message = "" } }
  $path = ""
  if ($Settings.Contains("allowlistPath")) { $path = [string]$Settings["allowlistPath"] }
  if ([string]::IsNullOrWhiteSpace($path)) { $path = Get-TbvDefaultApprovedAllowlistPath -LogDir $LogDir }
  $r = Read-TbvAllowlist -Path $path
  if (-not $r.Ok) {
    return [pscustomobject]@{ Enabled = $false; Entries = @(); Message = ("unlisted-destination alerts are OFF: {0}. Build one with build-allowlist.ps1, review it, and copy it there." -f $r.Reason) }
  }
  return [pscustomobject]@{ Enabled = $true; Entries = $r.Entries; Message = ("unlisted-destination alerts ON ({0} approved entries from {1}; advisory, nothing is blocked)" -f @($r.Entries).Count, $path) }
}
