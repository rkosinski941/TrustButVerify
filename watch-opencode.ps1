# watch-opencode.ps1
# No-admin OpenCode process and TCP watcher for Windows.
#
# BLIND SPOT: this script polls on an interval (default 1000 ms, set in
# trustbutverify.json as pollIntervalMs). A process or TCP connection
# that lives for less than one interval can be missed. For complete process-create and network-connect logging, use the
# Sysmon kit in this folder instead.
#
# What it does: finds processes whose image name or command line is OpenCode
# (including "opencode acp" launched by another app) and every descendant of those
# processes. About once a second it records new descendant processes and new
# TCP connections those PIDs own. Remote IPs are reverse-DNS resolved
# best-effort. Lines are flagged ALERT for loopback debugging ports, sensitive
# file paths, env dumps, and persistence changes. Command lines are redacted
# before they are written.
#
# No telemetry. The only optional network activity is a best-effort reverse
# DNS lookup of remote IPs already present in this machine's TCP table.
# Logs go under %LOCALAPPDATA%\opencode-watch\, or logDir in the
# settings file. Settings are read once at startup from
# %LOCALAPPDATA%\opencode-watch\trustbutverify.json. To apply changes
# later, run reload-watch.cmd (a named event; no per-poll file reads).
#
# Usage (from this folder, in Windows PowerShell or pwsh):
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\watch-opencode.ps1
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\watch-opencode.ps1 -Once
# Or run start-watch.cmd / stop-watch.cmd / reload-watch.cmd.

[CmdletBinding()]
param(
  [switch]$Once,
  [int]$IntervalSeconds = 1,
  [int[]]$LoopbackAllowPorts = @(),
  [string]$LogDirectory = ""
)

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "lib\WatchCommon.ps1")
. (Join-Path $PSScriptRoot "lib\TbvSettings.ps1")

# In-memory settings. Loaded once at startup and only again when the
# reload event is signaled. The loop must not stat or read the settings
# file on each poll.
$script:TbvPollIntervalMs = 1000
$script:TbvAllowPorts = @()
$script:TbvIgnoreSelfLoopback = $true
$script:TbvWatchedNames = @("opencode", "node", "bun")
$script:TbvExtraRegexes = @()
$script:TbvLogDir = ""
$script:TbvRetentionDays = 30
$script:TbvLogDay = ""
$script:TbvCsvPath = ""
$script:TbvLogPath = ""

function Get-ProcessSnapshot {
  $rows = Get-CimInstance -ClassName Win32_Process -Property ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate
  $list = New-Object System.Collections.Generic.List[object]
  foreach ($p in $rows) {
    $exePath = ""
    try { if ($p.ExecutablePath) { $exePath = [string]$p.ExecutablePath } } catch { $exePath = "" }
    $list.Add([pscustomobject]@{
      ProcessId       = [int]$p.ProcessId
      ParentProcessId = [int]$p.ParentProcessId
      Name            = [string]$p.Name
      ExecutablePath  = $exePath
      CommandLine     = [string]$p.CommandLine
      CreationDate    = $p.CreationDate
    })
  }
  return $list
}

function Get-WatchedProcessMap {
  param($Snapshot)
  $byId = @{}
  foreach ($p in $Snapshot) {
    $byId[[int]$p.ProcessId] = $p
  }
  $seeds = @{}
  foreach ($p in $Snapshot) {
    if (Test-IsOpenCodeSeed -Name $p.Name -CommandLine $p.CommandLine -WatchedProcessNames $script:TbvWatchedNames) {
      $seeds[[int]$p.ProcessId] = $true
    }
  }
  $watched = @{}
  foreach ($p in $Snapshot) {
    $procId = [int]$p.ProcessId
    $cursor = $procId
    $guard = 0
    $hit = $false
    $chain = New-Object System.Collections.Generic.List[int]
    while ($cursor -gt 0 -and $guard -lt 64) {
      $guard++
      if ($seeds.ContainsKey($cursor) -or $watched.ContainsKey($cursor)) {
        $hit = $true
        break
      }
      $chain.Add($cursor)
      if (-not $byId.ContainsKey($cursor)) { break }
      $parent = [int]$byId[$cursor].ParentProcessId
      if ($parent -le 0 -or $parent -eq $cursor) { break }
      $cursor = $parent
    }
    if ($hit) {
      $watched[$procId] = $true
      foreach ($c in $chain) { $watched[$c] = $true }
    }
  }
  return @{ Map = $watched; Seeds = $seeds; ById = $byId }
}

function Get-ProcessKey {
  param($Proc)
  $created = ""
  if ($Proc.CreationDate) { $created = [string]$Proc.CreationDate }
  return ("{0}|{1}" -f $Proc.ProcessId, $created)
}

function Write-WatchRecord {
  param(
    [string]$CsvPath,
    [string]$LogPath,
    [string]$Time,
    [string]$Kind,
    [string]$Alert,
    $ProcId,
    $ParentProcId,
    [string]$Name,
    [string]$LocalAddress,
    $LocalPort,
    [string]$RemoteAddress,
    $RemotePort,
    [string]$RemoteHost,
    [string]$State,
    [string]$CommandLine
  )
  $safeCmd = Protect-SecretText $CommandLine
  $row = Format-WatchCsvRow -Time $Time -Kind $Kind -Alert $Alert -ProcId $ProcId -ParentProcId $ParentProcId -Name $Name -LocalAddress $LocalAddress -LocalPort $LocalPort -RemoteAddress $RemoteAddress -RemotePort $RemotePort -RemoteHost $RemoteHost -State $State -CommandLine $safeCmd
  Add-Content -LiteralPath $CsvPath -Value $row -Encoding UTF8
  if ($Kind -eq "process") {
    $line = "{0} PROCESS pid={1} ppid={2} name={3}" -f $Time, $ProcId, $ParentProcId, $Name
    if ($safeCmd) { $line = $line + " cmd=" + $safeCmd }
  } else {
    $line = "{0} TCP pid={1} name={2} {3}:{4} -> {5}:{6} state={7}" -f $Time, $ProcId, $Name, $LocalAddress, $LocalPort, $RemoteAddress, $RemotePort, $State
    if ($RemoteHost) { $line = $line + " host=" + $RemoteHost }
  }
  if ($Alert) { $line = $line + " " + $Alert }
  Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
  if ($Alert -and $Alert.StartsWith("ALERT")) {
    Write-Host $line
  }
}

function Initialize-LogFiles {
  param([string]$Dir)
  $day = Get-Date -Format "yyyyMMdd"
  $csvPath = Join-Path $Dir ("watch-{0}.csv" -f $day)
  $logPath = Join-Path $Dir ("watch-{0}.log" -f $day)
  if (-not (Test-Path -LiteralPath $csvPath)) {
    Set-Content -LiteralPath $csvPath -Value (Get-WatchCsvHeader) -Encoding UTF8
  }
  if (-not (Test-Path -LiteralPath $logPath)) {
    $hdr = "# OpenCode watch log started {0}. Command lines are redacted. BLIND SPOT: events shorter than the poll interval can be missed." -f (Get-StampNow)
    Set-Content -LiteralPath $logPath -Value $hdr -Encoding UTF8
  }
  return @{ CsvPath = $csvPath; LogPath = $logPath }
}

function Invoke-WatchTick {
  param(
    [hashtable]$SeenProcesses,
    [hashtable]$SeenConnections,
    [hashtable]$DnsCache,
    [int[]]$AllowPorts,
    [string]$CsvPath,
    [string]$LogPath,
    [bool]$LogAll
  )
  $now = Get-StampNow
  $snapshot = Get-ProcessSnapshot
  $watchInfo = Get-WatchedProcessMap -Snapshot $snapshot
  $watched = $watchInfo.Map
  $byId = $watchInfo.ById

  foreach ($p in $snapshot) {
    $procId = [int]$p.ProcessId
    if (-not $watched.ContainsKey($procId)) { continue }
    $key = Get-ProcessKey $p
    if (-not $LogAll -and $SeenProcesses.ContainsKey($key)) { continue }
    $SeenProcesses[$key] = $true
    $reasons = @(Get-CommandLineAlertReasons -CommandLine $p.CommandLine -Image $p.ExecutablePath -ExtraRegexes $script:TbvExtraRegexes)
    $alert = Format-AlertLabel -Reasons $reasons
    Write-WatchRecord -CsvPath $CsvPath -LogPath $LogPath -Time $now -Kind "process" -Alert $alert -ProcId $procId -ParentProcId $p.ParentProcessId -Name $p.Name -LocalAddress "" -LocalPort "" -RemoteAddress "" -RemotePort "" -RemoteHost "" -State "" -CommandLine $p.CommandLine
  }

  $conns = @()
  try {
    $conns = @(Get-NetTCPConnection -ErrorAction Stop)
  } catch {
    Write-Host ("Get-NetTCPConnection failed: {0}" -f $_.Exception.Message)
    $conns = @()
  }

  $procNames = @{}
  foreach ($pidKey in $byId.Keys) {
    $procNames[[int]$pidKey] = [string]$byId[$pidKey].Name
  }
  $ownerIndex = New-TcpPortOwnerIndex -Connections $conns -ProcessNames $procNames

  foreach ($c in $conns) {
    $owner = 0
    try { $owner = [int]$c.OwningProcess } catch { $owner = 0 }
    if ($owner -le 0 -or -not $watched.ContainsKey($owner)) { continue }
    $localAddr = [string]$c.LocalAddress
    $remoteAddr = [string]$c.RemoteAddress
    $localPort = [int]$c.LocalPort
    $remotePort = [int]$c.RemotePort
    $state = [string]$c.State
    $ckey = "{0}|{1}|{2}|{3}|{4}|{5}" -f $owner, $localAddr, $localPort, $remoteAddr, $remotePort, $state
    if (-not $LogAll -and $SeenConnections.ContainsKey($ckey)) { continue }
    $SeenConnections[$ckey] = $true
    $isSelf = Test-IsTcpSelfLoopback -LocalAddress $localAddr -LocalPort $localPort -RemoteAddress $remoteAddr -RemotePort $remotePort -OwnerIndex $ownerIndex -WatchedPids $watched
    $isOc = Test-IsOpenCodeServerLoopback -LocalAddress $localAddr -LocalPort $localPort -RemoteAddress $remoteAddr -RemotePort $remotePort -OwnerIndex $ownerIndex
    $class = Get-TcpWatchClassification -LocalAddress $localAddr -LocalPort $localPort -RemoteAddress $remoteAddr -RemotePort $remotePort -State $state -LoopbackAllowPorts $AllowPorts -IsSelfLoopback $isSelf -IsOpenCodeServerLoopback $isOc -IgnoreSelfLoopback $script:TbvIgnoreSelfLoopback
    $alert = [string]$class.Label
    $hostName = Resolve-RemoteHostBestEffort -Address $remoteAddr -Cache $DnsCache
    $procName = ""
    $parentId = ""
    $cmd = ""
    if ($byId.ContainsKey($owner)) {
      $procName = [string]$byId[$owner].Name
      $parentId = $byId[$owner].ParentProcessId
      $cmd = [string]$byId[$owner].CommandLine
    }
    Write-WatchRecord -CsvPath $CsvPath -LogPath $LogPath -Time $now -Kind "tcp" -Alert $alert -ProcId $owner -ParentProcId $parentId -Name $procName -LocalAddress $localAddr -LocalPort $localPort -RemoteAddress $remoteAddr -RemotePort $remotePort -RemoteHost $hostName -State $state -CommandLine $cmd
  }
}

# --- main ---

function Write-WatchLogLine {
  param([string]$Message, [string]$LogPath = "")
  $line = "{0} {1}" -f (Get-StampNow), $Message
  if ([string]::IsNullOrWhiteSpace($LogPath)) { $LogPath = $script:TbvLogPath }
  if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
    try { Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8 } catch { }
  }
  Write-Host $line
}

function Initialize-CurrentLogFiles {
  param([string]$Dir)
  $day = Get-Date -Format "yyyyMMdd"
  if ($day -eq $script:TbvLogDay -and $script:TbvCsvPath -and $script:TbvLogPath) {
    return @{ CsvPath = $script:TbvCsvPath; LogPath = $script:TbvLogPath }
  }
  $logs = Initialize-LogFiles -Dir $Dir
  $script:TbvLogDay = $day
  $script:TbvCsvPath = $logs.CsvPath
  $script:TbvLogPath = $logs.LogPath
  return $logs
}

function Apply-TbvWatchSettings {
  param($Settings, [string]$Reason)
  $script:TbvPollIntervalMs = [int]$Settings["pollIntervalMs"]
  $script:TbvAllowPorts = @($Settings["allowedLoopbackPorts"])
  $script:TbvIgnoreSelfLoopback = $true
  if ($Settings.Contains("ignoreSelfLoopback")) {
    $script:TbvIgnoreSelfLoopback = [bool]$Settings["ignoreSelfLoopback"]
  }
  $script:TbvWatchedNames = @($Settings["watchedProcessNames"])
  $script:TbvExtraRegexes = @($Settings["extraAlertRegexes"])
  $script:TbvRetentionDays = [int]$Settings["logRetentionDays"]
  $logDir = [string]$Settings["logDir"]
  if ($Reason -eq "startup") {
    if ([string]::IsNullOrWhiteSpace($script:TbvLogDir)) {
      if (-not [string]::IsNullOrWhiteSpace($logDir)) {
        $script:TbvLogDir = $logDir
      } else {
        $script:TbvLogDir = (Ensure-OpenCodeWatchLogDir)
      }
    }
  }
  $pruned = @(Invoke-TbvLogRetention -LogDir $script:TbvLogDir -Days $script:TbvRetentionDays)
  foreach ($w in @($Settings["warnings"])) {
    if ($w) { Write-WatchLogLine -Message ("settings: {0}" -f $w) }
  }
  if ($pruned.Count -gt 0) {
    Write-WatchLogLine -Message ("pruned {0} old log file(s) (retention {1} days)" -f $pruned.Count, $script:TbvRetentionDays)
  }
  if ($Reason -eq "reload") {
    Write-WatchLogLine -Message "settings reloaded"
  }
}

if (-not (Test-IsWindowsOS)) {
  throw "watch-opencode.ps1 is meant to run on Windows. Process and TCP snapshots use Win32_Process and Get-NetTCPConnection."
}

# Command-line overrides are applied after the one-time settings load.
if (-not [string]::IsNullOrWhiteSpace($LogDirectory)) {
  $script:TbvLogDir = $LogDirectory
}

$loaded = Read-TbvSettings
if ($PSBoundParameters.ContainsKey("IntervalSeconds") -and $IntervalSeconds -gt 0) {
  $ms = $IntervalSeconds * 1000
  $min = Get-TbvSettingsMinPollIntervalMs
  if ($ms -lt $min) { $ms = $min }
  $loaded["pollIntervalMs"] = $ms
}
if ($PSBoundParameters.ContainsKey("LoopbackAllowPorts")) {
  $loaded["allowedLoopbackPorts"] = @($LoopbackAllowPorts)
}

if ([string]::IsNullOrWhiteSpace($script:TbvLogDir)) {
  $fromFile = [string]$loaded["logDir"]
  if (-not [string]::IsNullOrWhiteSpace($fromFile)) {
    $script:TbvLogDir = $fromFile
  } else {
    $script:TbvLogDir = Ensure-OpenCodeWatchLogDir
  }
}
if (-not (Test-Path -LiteralPath $script:TbvLogDir)) {
  New-Item -ItemType Directory -Force -Path $script:TbvLogDir | Out-Null
}

$logs = Initialize-CurrentLogFiles -Dir $script:TbvLogDir
Apply-TbvWatchSettings -Settings $loaded -Reason "startup"

$pidFile = Join-Path $script:TbvLogDir "watch.pid"
if (-not $Once) {
  if (Test-Path -LiteralPath $pidFile) {
    $oldText = (Get-Content -LiteralPath $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
    $oldPid = 0
    if ($oldText) { [void][int]::TryParse($oldText.Trim(), [ref]$oldPid) }
    if ($oldPid -gt 0) {
      $alive = Get-Process -Id $oldPid -ErrorAction SilentlyContinue
      if ($alive) {
        throw ("Watcher already running as PID {0}. Run stop-watch.ps1 first." -f $oldPid)
      }
    }
  }
  Set-Content -LiteralPath $pidFile -Value $PID -Encoding ASCII
}

Write-Host ("OpenCode watch logging to {0} and {1}" -f $script:TbvCsvPath, $script:TbvLogPath)
Write-Host ("Poll interval {0} ms. BLIND SPOT: processes or TCP connections shorter than this interval can be missed." -f $script:TbvPollIntervalMs)
$portText = "(none; every loopback port alerts)"
if (@($script:TbvAllowPorts).Count -gt 0) { $portText = ($script:TbvAllowPorts -join ", ") }
Write-Host ("Loopback allowlist ports: {0}. Debug ports 9222, 9229, 9239 always alert. ignoreSelfLoopback={1} (OpenCode-server pairs only; other self-loopback is INFO). Wildcard and public listens ALERT." -f $portText, $script:TbvIgnoreSelfLoopback)
Write-Host ("Watched process names: {0}" -f ($script:TbvWatchedNames -join ", "))
Write-Host "Settings are held in memory. Run reload-watch.cmd after editing trustbutverify.json."

$seenProc = @{}
$seenConn = @{}
$dnsCache = @{}

$reloadEvent = $null
try {
  $reloadEvent = New-Object System.Threading.EventWaitHandle($false, [System.Threading.EventResetMode]::AutoReset, (Get-TbvReloadEventName))
} catch {
  Write-WatchLogLine -Message ("reload event unavailable: {0}. Use stop/start to apply settings changes." -f $_.Exception.Message)
}

try {
  if ($Once) {
    $dayLogs = Initialize-CurrentLogFiles -Dir $script:TbvLogDir
    Invoke-WatchTick -SeenProcesses $seenProc -SeenConnections $seenConn -DnsCache $dnsCache -AllowPorts $script:TbvAllowPorts -CsvPath $dayLogs.CsvPath -LogPath $dayLogs.LogPath -LogAll $true
    Write-Host "Once snapshot complete."
  } else {
    while ($true) {
      $dayLogs = Initialize-CurrentLogFiles -Dir $script:TbvLogDir
      Invoke-WatchTick -SeenProcesses $seenProc -SeenConnections $seenConn -DnsCache $dnsCache -AllowPorts $script:TbvAllowPorts -CsvPath $dayLogs.CsvPath -LogPath $dayLogs.LogPath -LogAll $false
      $signaled = $false
      if ($reloadEvent) {
        # WaitOne here is the poll sleep. A reload signal wakes it early
        # with no file I/O. WaitOne(0) is also checked so a signal that
        # arrived during the tick is not missed.
        if ($reloadEvent.WaitOne(0)) {
          $signaled = $true
        } else {
          $signaled = $reloadEvent.WaitOne([int]$script:TbvPollIntervalMs)
        }
      } else {
        Start-Sleep -Milliseconds $script:TbvPollIntervalMs
      }
      if ($signaled) {
        $reloaded = Read-TbvSettings
        Apply-TbvWatchSettings -Settings $reloaded -Reason "reload"
      }
    }
  }
} finally {
  if ($reloadEvent) {
    try { $reloadEvent.Dispose() } catch { }
  }
  if (-not $Once -and (Test-Path -LiteralPath $pidFile)) {
    $mine = (Get-Content -LiteralPath $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($mine -and $mine.Trim() -eq [string]$PID) {
      Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
    }
  }
}
