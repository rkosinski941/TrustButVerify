# sysmon-summary.ps1
# Reads the last 24 hours of Sysmon Event 1, 3, and 22 and writes a
# redacted plain-text/markdown report under %LOCALAPPDATA%\opencode-watch\reports\.
# Command lines are passed through Protect-SecretText. Same ALERT rules as
# the PowerShell watcher.
#
# Reading Microsoft-Windows-Sysmon/Operational requires Event Log
# Readers membership (granted by install-sysmon.ps1) or an elevated
# prompt. Sign out and back in after that grant. If this script cannot
# read the log, it prints a clear message and stops. Register the
# nightly task with register-nightly-summary.ps1 (RunLevel Limited).
#
# No telemetry. No network calls (remote host comes from the event if
# Sysmon provided it).

[CmdletBinding()]
param(
  [int]$LastHours = 24,
  [string]$OutputPath = "",
  [int[]]$LoopbackAllowPorts = @(),
  [string]$LogDirectory = "",
  [bool]$IgnoreSelfLoopback = $true
)

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "lib\WatchCommon.ps1")

if ($LastHours -lt 1) { $LastHours = 24 }
if ($null -eq $LoopbackAllowPorts -or @($LoopbackAllowPorts).Count -eq 0) {
  $LoopbackAllowPorts = Get-DefaultLoopbackAllowPorts
}

function Get-EventDataMap {
  param($Event)
  $map = @{}
  try {
    $xml = [xml]$Event.ToXml()
    $nodes = $xml.Event.EventData.Data
    if ($nodes) {
      foreach ($d in @($nodes)) {
        $name = [string]$d.Name
        $val = [string]$d.'#text'
        if ($name) { $map[$name] = $val }
      }
    }
  } catch {
    # fall back to positional properties if XML parse fails
  }
  return $map
}

function Convert-ToIntOrZero {
  param($Value)
  if ($null -eq $Value -or $Value -eq "") { return 0 }
  $n = 0
  if ([int]::TryParse([string]$Value, [ref]$n)) { return $n }
  return 0
}

if ([string]::IsNullOrWhiteSpace($LogDirectory)) {
  $LogDirectory = Ensure-OpenCodeWatchLogDir
} elseif (-not (Test-Path -LiteralPath $LogDirectory)) {
  New-Item -ItemType Directory -Force -Path $LogDirectory | Out-Null
}

$reportDir = Join-Path $LogDirectory "reports"
if (-not (Test-Path -LiteralPath $reportDir)) {
  New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $OutputPath = Join-Path $reportDir ("sysmon-summary-{0}.md" -f $stamp)
}

$start = (Get-Date).AddHours(-$LastHours)
$end = Get-Date
Write-Host ("Reading Sysmon events from {0} to {1} (local time)." -f ($start.ToString("yyyy-MM-dd HH:mm:ss K")), ($end.ToString("yyyy-MM-dd HH:mm:ss K")))

$events = @()
try {
  $events = @(Get-WinEvent -FilterHashtable @{
    LogName   = "Microsoft-Windows-Sysmon/Operational"
    Id        = 1, 3, 22
    StartTime = $start
  } -ErrorAction Stop)
} catch {
  $msg = [string]$_.Exception.Message
  if ($msg -match '(?i)No events' -or $msg -match '(?i)No matching events') {
    $events = @()
  } elseif (Test-IsSysmonLogAccessError $_) {
    throw (Get-SysmonLogAdminMessage)
  } else {
    if (Test-IsSysmonLogAccessError $msg) {
      throw (Get-SysmonLogAdminMessage)
    }
    throw ("Failed to read the Sysmon log: {0}" -f $msg)
  }
}

# Get-WinEvent returns newest first. Reverse for chronological reports.
if ($events.Count -gt 1) {
  $events = @($events | Sort-Object TimeCreated)
}

$procLines = New-Object System.Collections.Generic.List[string]
$netLines = New-Object System.Collections.Generic.List[string]
$dnsLines = New-Object System.Collections.Generic.List[string]
$alertLines = New-Object System.Collections.Generic.List[string]
$seenLines = @{}
$procCount = 0
$netCount = 0
$dnsCount = 0
$alertCount = 0
$dupCount = 0

$listenPorts = New-OpenCodeListenPortSet
foreach ($ev in $events) {
  if ([int]$ev.Id -ne 3) { continue }
  $probe = Get-EventDataMap $ev
  $probeImage = ""
  $probeDst = ""
  $probeDstPort = 0
  $probeInit = ""
  if ($probe.ContainsKey("Image")) { $probeImage = [string]$probe["Image"] }
  if ($probe.ContainsKey("DestinationIp")) { $probeDst = [string]$probe["DestinationIp"] }
  if ($probe.ContainsKey("DestinationPort")) { $probeDstPort = Convert-ToIntOrZero $probe["DestinationPort"] }
  if ($probe.ContainsKey("Initiated")) { $probeInit = [string]$probe["Initiated"] }
  Add-OpenCodeListenPortFromSysmonNetwork -Image $probeImage -DestinationIp $probeDst -DestinationPort $probeDstPort -Initiated $probeInit -PortSet $listenPorts
}

foreach ($ev in $events) {
  $data = Get-EventDataMap $ev
  $id = [int]$ev.Id
  $when = $ev.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss K")
  $image = ""
  if ($data.ContainsKey("Image")) { $image = [string]$data["Image"] }
  $procId = ""
  if ($data.ContainsKey("ProcessId")) { $procId = [string]$data["ProcessId"] }

  if ($id -eq 1) {
    $cmd = ""
    $parentCmd = ""
    $parentImage = ""
    $parentProcId = ""
    if ($data.ContainsKey("CommandLine")) { $cmd = [string]$data["CommandLine"] }
    if ($data.ContainsKey("ParentCommandLine")) { $parentCmd = [string]$data["ParentCommandLine"] }
    if ($data.ContainsKey("ParentImage")) { $parentImage = [string]$data["ParentImage"] }
    if ($data.ContainsKey("ParentProcessId")) { $parentProcId = [string]$data["ParentProcessId"] }
    $safeCmd = Protect-SecretText $cmd
    $safeParent = Protect-SecretText $parentCmd
    $reasons = @(Get-CommandLineAlertReasons -CommandLine $cmd -Image $image)
    $alert = Format-AlertLabel -Reasons $reasons
    $line = "- {0} pid={1} image={2} parent_pid={3} parent={4} cmd={5}" -f $when, $procId, $image, $parentProcId, $parentImage, $safeCmd
    if ($safeParent) { $line = $line + " parent_cmd=" + $safeParent }
    if ($alert) { $line = $line + " **" + $alert + "**" }
    if (-not (Add-UniqueLogLine -List $procLines -Seen $seenLines -Line $line)) {
      $dupCount++
      continue
    }
    $procCount++
    if ($alert) {
      [void]$alertLines.Add($line)
      $alertCount++
    }
  } elseif ($id -eq 3) {
    $src = ""
    $dst = ""
    $srcPort = 0
    $dstPort = 0
    if ($data.ContainsKey("SourceIp")) { $src = [string]$data["SourceIp"] }
    if ($data.ContainsKey("DestinationIp")) { $dst = [string]$data["DestinationIp"] }
    if ($data.ContainsKey("SourcePort")) { $srcPort = Convert-ToIntOrZero $data["SourcePort"] }
    if ($data.ContainsKey("DestinationPort")) { $dstPort = Convert-ToIntOrZero $data["DestinationPort"] }
    $destHost = ""
    if ($data.ContainsKey("DestinationHostname")) { $destHost = [string]$data["DestinationHostname"] }
    $class = Get-SysmonNetworkClassification -Image $image -SourceIp $src -SourcePort $srcPort -DestinationIp $dst -DestinationPort $dstPort -OpenCodeListenPorts $listenPorts -LoopbackAllowPorts $LoopbackAllowPorts -IgnoreSelfLoopback $IgnoreSelfLoopback
    $line = "- {0} pid={1} image={2} {3}:{4} -> {5}:{6}" -f $when, $procId, $image, $src, $srcPort, $dst, $dstPort
    if ($destHost) { $line = $line + " host=" + $destHost }
    if ($class.Label) {
      if ($class.Severity -eq "ALERT") {
        $line = $line + " **" + $class.Label + "**"
      } else {
        $line = $line + " " + $class.Label
      }
    }
    if (-not (Add-UniqueLogLine -List $netLines -Seen $seenLines -Line $line)) {
      $dupCount++
      continue
    }
    $netCount++
    if ($class.Severity -eq "ALERT") {
      [void]$alertLines.Add($line)
      $alertCount++
    }
  } elseif ($id -eq 22) {
    $query = ""
    $results = ""
    if ($data.ContainsKey("QueryName")) { $query = [string]$data["QueryName"] }
    if ($data.ContainsKey("QueryResults")) { $results = [string]$data["QueryResults"] }
    $safeQuery = Protect-SecretText $query
    $safeResults = Protect-SecretText $results
    $line = "- {0} pid={1} image={2} query={3}" -f $when, $procId, $image, $safeQuery
    if ($safeResults) { $line = $line + " results=" + $safeResults }
    if (-not (Add-UniqueLogLine -List $dnsLines -Seen $seenLines -Line $line)) {
      $dupCount++
      continue
    }
    $dnsCount++
  }
}

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("# OpenCode Sysmon summary")
[void]$sb.AppendLine("")
[void]$sb.AppendLine(("Generated: {0} (local time)" -f (Get-StampNow)))
[void]$sb.AppendLine(("Window: last {0} hours, from {1} to {2}" -f $LastHours, $start.ToString("yyyy-MM-dd HH:mm:ss K"), $end.ToString("yyyy-MM-dd HH:mm:ss K")))
[void]$sb.AppendLine("")
[void]$sb.AppendLine("Command lines and query strings were redacted. Secret values are not written to this report.")
[void]$sb.AppendLine(("Loopback allowlist ports: {0}. Debug ports 9222, 9229, 9239 always alert. ignoreSelfLoopback={1}. OpenCode loopback connects to a known opencode listen port (default 4096) are INFO, not ALERT. Identical rows are omitted." -f (($LoopbackAllowPorts -join ", "), $IgnoreSelfLoopback)))
[void]$sb.AppendLine("")
[void]$sb.AppendLine("## Counts")
[void]$sb.AppendLine("")
[void]$sb.AppendLine(("- Process create (Event 1): {0}" -f $procCount))
[void]$sb.AppendLine(("- Network connect (Event 3): {0}" -f $netCount))
[void]$sb.AppendLine(("- DNS query (Event 22): {0}" -f $dnsCount))
[void]$sb.AppendLine(("- ALERT lines: {0}" -f $alertCount))
[void]$sb.AppendLine(("- Duplicate rows omitted: {0}" -f $dupCount))
[void]$sb.AppendLine("")
[void]$sb.AppendLine("## ALERT lines")
[void]$sb.AppendLine("")
if ($alertLines.Count -eq 0) {
  [void]$sb.AppendLine("No ALERT lines in this window.")
} else {
  foreach ($l in $alertLines) { [void]$sb.AppendLine($l) }
}
[void]$sb.AppendLine("")
[void]$sb.AppendLine("## Process create")
[void]$sb.AppendLine("")
if ($procLines.Count -eq 0) {
  [void]$sb.AppendLine("None.")
} else {
  foreach ($l in $procLines) { [void]$sb.AppendLine($l) }
}
[void]$sb.AppendLine("")
[void]$sb.AppendLine("## Network connect")
[void]$sb.AppendLine("")
if ($netLines.Count -eq 0) {
  [void]$sb.AppendLine("None.")
} else {
  foreach ($l in $netLines) { [void]$sb.AppendLine($l) }
}
[void]$sb.AppendLine("")
[void]$sb.AppendLine("## DNS query")
[void]$sb.AppendLine("")
if ($dnsLines.Count -eq 0) {
  [void]$sb.AppendLine("None.")
} else {
  foreach ($l in $dnsLines) { [void]$sb.AppendLine($l) }
}
[void]$sb.AppendLine("")

$text = $sb.ToString()
Set-Content -LiteralPath $OutputPath -Value $text -Encoding UTF8
Write-Host ("Wrote {0}" -f $OutputPath)
Write-Host ("Events: process={0} network={1} dns={2} alerts={3} duplicates_omitted={4}" -f $procCount, $netCount, $dnsCount, $alertCount, $dupCount)
