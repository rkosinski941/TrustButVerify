# WatchCommon.ps1
# Shared helpers for the OpenCode watch kit. ASCII only. Works on
# Windows PowerShell 5.1 and PowerShell 7. Dot-source this file; do not
# run it alone.
#
# Native executables must be started through Invoke-Native, which checks
# $LASTEXITCODE. These functions never write secrets: command lines and
# similar text must pass through Protect-SecretText before they are logged.

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

function Invoke-Native {
  param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [string[]]$ArgumentList = @(),
    [switch]$AllowFail
  )
  $prev = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $output = & $FilePath @ArgumentList 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $prev
  }
  if (-not $AllowFail -and $null -ne $code -and $code -ne 0) {
    if ($output) { $output | ForEach-Object { Write-Host $_ } }
    throw ("{0} exited with code {1}" -f $FilePath, $code)
  }
  return $output
}

function Get-OpenCodeWatchLogDir {
  $root = $env:LOCALAPPDATA
  if ([string]::IsNullOrWhiteSpace($root)) {
    if ($env:USERPROFILE) {
      $root = Join-Path $env:USERPROFILE "AppData\Local"
    } else {
      $root = Join-Path $env:HOME ".local"
    }
  }
  return (Join-Path $root "opencode-watch")
}

function Ensure-OpenCodeWatchLogDir {
  $dir = Get-OpenCodeWatchLogDir
  if (-not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
  }
  return $dir
}

function Get-FileHashHex {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [ValidateSet("MD5", "SHA256", "SHA1")][string]$Algorithm = "SHA256"
  )
  $h = Get-FileHash -LiteralPath $Path -Algorithm $Algorithm
  return $h.Hash.ToLowerInvariant()
}

function Protect-SecretText {
  param([string]$Text)
  if ($null -eq $Text -or $Text.Length -eq 0) {
    return $Text
  }
  $s = $Text

  # Known access-token prefixes. Keep a short type prefix so a report can
  # still say which kind of token was present, without keeping the secret.
  $prefixPattern = '(?i)\b((?:sk|xai)-[A-Za-z0-9_\-]{8,}|ghp_[A-Za-z0-9_]{8,}|gho_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,})'
  $s = [regex]::Replace($s, $prefixPattern, {
    param($m)
    $v = $m.Groups[1].Value
    $lower = $v.ToLowerInvariant()
    $keep = 4
    if ($lower.StartsWith("github_pat_")) {
      $keep = 11
    } elseif ($lower.StartsWith("ghp_") -or $lower.StartsWith("gho_")) {
      $keep = 4
    } elseif ($lower.StartsWith("sk-") -or $lower.StartsWith("xai-")) {
      $keep = $lower.IndexOf("-") + 1
    }
    if ($keep -gt $v.Length) { $keep = $v.Length }
    return ($v.Substring(0, $keep) + "[REDACTED]")
  })

  $s = [regex]::Replace($s, '(?i)(\bBearer)\s+[A-Za-z0-9\-._~+/]+=*', '${1} [REDACTED]')
  $s = [regex]::Replace($s, '(?i)(\bBasic)\s+[A-Za-z0-9+/=]+', '${1} [REDACTED]')

  $s = [regex]::Replace(
    $s,
    '(?i)(\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|secret|password|passwd|pwd|token|key)\s*[=:]\s*)([^\s"''&]+)',
    '${1}[REDACTED]'
  )

  # SHA-256 length and longer; leave short git SHAs alone.
  $s = [regex]::Replace($s, '(?i)\b[0-9a-f]{64,}\b', '[REDACTED-HEX]')

  # Do not treat a hex-only blob (for example a 40-char git SHA) as
  # base64. Those shorter than 64 hex chars are left alone; 64+ hex is
  # already redacted above.
  $s = [regex]::Replace(
    $s,
    '(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])',
    {
      param($m)
      $v = $m.Value
      if ($v -match '^[0-9a-fA-F]+$') { return $v }
      return '[REDACTED-B64]'
    }
  )

  return $s
}

function Get-DefaultLoopbackAllowPorts {
  # Shipped default is empty: any loopback port not listed here is an
  # ALERT. Debug ports 9222, 9229, and 9239 always alert, even if added.
  # Add common local-dev ports (80, 443, 3000, 5173, 8000, 8080) in
  # trustbutverify.json if you want those quiet.
  return @()
}

function Get-DebugLoopbackPorts {
  return @(9222, 9229, 9239)
}

function Test-IsLoopbackAddress {
  param([string]$Address)
  if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
  $a = $Address.Trim().TrimStart('[').TrimEnd(']')
  if ($a -eq "::1" -or $a -eq "localhost") { return $true }
  if ($a -like "127.*") { return $true }
  if ($a -match '(?i)^::ffff:127\.') { return $true }
  return $false
}

function Test-IsUnspecifiedAddress {
  param([string]$Address)
  if ([string]::IsNullOrWhiteSpace($Address)) { return $true }
  $a = $Address.Trim().TrimStart('[').TrimEnd(']')
  if ($a -eq "0.0.0.0" -or $a -eq "::" -or $a -eq "*" -or $a -eq "::ffff:0.0.0.0") { return $true }
  return $false
}

function Normalize-TbvIpAddress {
  param([string]$Address)
  if ([string]::IsNullOrWhiteSpace($Address)) { return "" }
  $a = $Address.Trim().TrimStart('[').TrimEnd(']').ToLowerInvariant()
  if ($a -eq "localhost") { return "127.0.0.1" }
  if ($a -match '^::ffff:(127\.[0-9.]+)$') { return $Matches[1] }
  if ($a -eq "::ffff:0.0.0.0") { return "0.0.0.0" }
  return $a
}

function New-TcpPortOwnerIndex {
  # In-memory index of LocalAddress:LocalPort -> owning PIDs, built from
  # one Get-NetTCPConnection snapshot. No file I/O. Optional ProcessNames
  # is a hashtable of PID -> image name from the same poll.
  param(
    $Connections,
    $ProcessNames = $null
  )
  $index = @{
    Exact = @{}
    ByPort = @{}
  }
  foreach ($c in @($Connections)) {
    $procId = 0
    try { $procId = [int]$c.OwningProcess } catch { $procId = 0 }
    if ($procId -le 0) { continue }
    $port = 0
    try { $port = [int]$c.LocalPort } catch { $port = 0 }
    if ($port -le 0) { continue }
    $addr = Normalize-TbvIpAddress ([string]$c.LocalAddress)
    $stateUp = ""
    try { if ($c.State) { $stateUp = ([string]$c.State).ToUpperInvariant() } } catch { }
    $image = ""
    if ($null -ne $ProcessNames) {
      if ($ProcessNames -is [System.Collections.IDictionary] -and $ProcessNames.Contains($procId)) {
        $image = [string]$ProcessNames[$procId]
      } elseif ($ProcessNames.ContainsKey($procId)) {
        $image = [string]$ProcessNames[$procId]
      }
    }
    $exactKey = "{0}|{1}" -f $addr, $port
    if (-not $index.Exact.ContainsKey($exactKey)) {
      $index.Exact[$exactKey] = New-Object System.Collections.Generic.List[int]
    }
    $index.Exact[$exactKey].Add($procId)
    if (-not $index.ByPort.ContainsKey($port)) {
      $index.ByPort[$port] = New-Object System.Collections.Generic.List[object]
    }
    $index.ByPort[$port].Add(@{
      Pid = $procId
      Addr = $addr
      Unspec = [bool](Test-IsUnspecifiedAddress $addr)
      Loopback = [bool](Test-IsLoopbackAddress $addr)
      State = $stateUp
      Image = $image
    })
  }
  return $index
}

function Test-IsOpenCodeImageName {
  param([string]$Name)
  if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
  $base = $Name.Trim().Trim('"')
  $cut = $base.LastIndexOfAny([char[]]@([char]'\', [char]'/'))
  if ($cut -ge 0) { $base = $base.Substring($cut + 1) }
  if ($base.EndsWith(".exe", [System.StringComparison]::OrdinalIgnoreCase)) {
    $base = $base.Substring(0, $base.Length - 4)
  }
  return ($base -eq "opencode")
}

function Test-IsOpenCodeListenOnPort {
  param(
    $OwnerIndex,
    [int]$Port,
    [string]$PeerAddress
  )
  if ($null -eq $OwnerIndex -or $Port -le 0) { return $false }
  if (-not $OwnerIndex.ByPort.ContainsKey($Port)) { return $false }
  $peer = Normalize-TbvIpAddress $PeerAddress
  $peerLoop = Test-IsLoopbackAddress $peer
  $peerUnspec = Test-IsUnspecifiedAddress $peer
  foreach ($row in $OwnerIndex.ByPort[$Port]) {
    if (-not (Test-IsOpenCodeImageName ([string]$row.Image))) { continue }
    $isListen = ([string]$row.State -eq "LISTEN")
    if (-not $isListen) { continue }
    if ($row.Unspec -and ($peerLoop -or $peerUnspec -or [string]::IsNullOrWhiteSpace($peer))) { return $true }
    if ($row.Loopback -and ($peerLoop -or $peerUnspec -or [string]::IsNullOrWhiteSpace($peer))) { return $true }
    $rowAddr = Normalize-TbvIpAddress ([string]$row.Addr)
    if ($rowAddr -and $peer -and $rowAddr -eq $peer) { return $true }
  }
  return $false
}

function Test-IsOpenCodeServerLoopback {
  # True when this loopback row is talking to (or is) a listen port
  # owned by an opencode process. Other watched-to-watched loopback
  # is not treated as OpenCode-server self-talk.
  param(
    [string]$LocalAddress,
    [int]$LocalPort,
    [string]$RemoteAddress,
    [int]$RemotePort,
    $OwnerIndex
  )
  if ($null -eq $OwnerIndex) { return $false }
  if (Test-IsOpenCodeListenOnPort -OwnerIndex $OwnerIndex -Port $RemotePort -PeerAddress $RemoteAddress) {
    return $true
  }
  if (Test-IsOpenCodeListenOnPort -OwnerIndex $OwnerIndex -Port $LocalPort -PeerAddress $LocalAddress) {
    return $true
  }
  return $false
}

function Get-ListenBindKind {
  param([string]$LocalAddress)
  if (Test-IsLoopbackAddress $LocalAddress) { return "loopback" }
  if (Test-IsUnspecifiedAddress $LocalAddress) { return "wildcard" }
  return "public"
}

function Test-IsTcpSelfLoopback {
  # True when the peer of this loopback row (the process whose LocalPort
  # is this row's RemotePort) is a watched process or one of its
  # descendants. Uses only the in-memory snapshot index.
  param(
    [string]$LocalAddress,
    [int]$LocalPort,
    [string]$RemoteAddress,
    [int]$RemotePort,
    $OwnerIndex,
    [hashtable]$WatchedPids
  )
  if ($null -eq $OwnerIndex -or $null -eq $WatchedPids) { return $false }
  $remoteAddr = Normalize-TbvIpAddress $RemoteAddress
  $pids = New-Object System.Collections.Generic.List[int]
  $exactKey = "{0}|{1}" -f $remoteAddr, $RemotePort
  if ($OwnerIndex.Exact.ContainsKey($exactKey)) {
    foreach ($procId in $OwnerIndex.Exact[$exactKey]) { $pids.Add([int]$procId) }
  }
  # A listen on 0.0.0.0:port or [::]:port is the peer of a connect to
  # 127.0.0.1:port or [::1]:port.
  if ($OwnerIndex.ByPort.ContainsKey($RemotePort)) {
    $remoteLoop = Test-IsLoopbackAddress $remoteAddr
    $remoteUnspec = Test-IsUnspecifiedAddress $remoteAddr
    foreach ($row in $OwnerIndex.ByPort[$RemotePort]) {
      if ($row.Unspec -and ($remoteLoop -or $remoteUnspec)) {
        $pids.Add([int]$row.Pid)
      } elseif ($remoteLoop -and $row.Loopback) {
        $pids.Add([int]$row.Pid)
      }
    }
  }
  foreach ($procId in $pids) {
    if ($WatchedPids.ContainsKey($procId)) { return $true }
  }
  return $false
}

function Get-TcpWatchClassification {
  # Classify a TCP row. Listen rows: loopback binds are INFO unless
  # they are a debug port (9222, 9229, 9239). Wildcard and public
  # binds ALERT. Debug ports always ALERT. OpenCode-server loopback
  # pairs are quiet when IgnoreSelfLoopback is true; other
  # watched-to-watched loopback is INFO. If either end is
  # allowlisted, the row is allowed. Debug ports still ALERT.
  param(
    [string]$LocalAddress,
    [int]$LocalPort,
    [string]$RemoteAddress,
    [int]$RemotePort,
    [string]$State,
    [int[]]$LoopbackAllowPorts,
    [bool]$IsSelfLoopback = $false,
    [bool]$IsOpenCodeServerLoopback = $false,
    [bool]$IgnoreSelfLoopback = $true
  )
  if ($null -eq $LoopbackAllowPorts) { $LoopbackAllowPorts = @() }
  $debugPorts = Get-DebugLoopbackPorts
  $stateUp = ""
  if ($State) { $stateUp = $State.ToUpperInvariant() }
  $listen = ($stateUp -eq "LISTEN")
  $localLoop = Test-IsLoopbackAddress $LocalAddress
  $remoteLoop = Test-IsLoopbackAddress $RemoteAddress
  $bindKind = Get-ListenBindKind $LocalAddress

  if ($listen) {
    if ($debugPorts -contains $LocalPort) {
      $reason = ("{0} debug port {1} (listen)" -f $bindKind, $LocalPort)
      return [pscustomobject]@{
        Severity = "ALERT"
        Reasons  = @($reason)
        Label    = "ALERT: $reason"
      }
    }
    if ($bindKind -eq "loopback") {
      $reason = "loopback listen port $LocalPort"
      return [pscustomobject]@{
        Severity = "INFO"
        Reasons  = @($reason)
        Label    = "INFO: $reason"
      }
    }
    $reason = ("{0} listen port {1}" -f $bindKind, $LocalPort)
    return [pscustomobject]@{
      Severity = "ALERT"
      Reasons  = @($reason)
      Label    = "ALERT: $reason"
    }
  }

  $debugHit = 0
  if ($debugPorts -contains $RemotePort) { $debugHit = $RemotePort }
  elseif ($debugPorts -contains $LocalPort) { $debugHit = $LocalPort }
  if ($debugHit -gt 0) {
    $isLoop = $localLoop -or $remoteLoop
    $reason = ("loopback debug port {0}" -f $debugHit)
    if (-not $isLoop) { $reason = ("debug port {0}" -f $debugHit) }
    return [pscustomobject]@{
      Severity = "ALERT"
      Reasons  = @($reason)
      Label    = "ALERT: $reason"
    }
  }

  $isLoop = $localLoop -or $remoteLoop
  if (-not $isLoop) {
    return [pscustomobject]@{ Severity = ""; Reasons = @(); Label = "" }
  }

  if ($IgnoreSelfLoopback -and $IsOpenCodeServerLoopback) {
    return [pscustomobject]@{ Severity = ""; Reasons = @(); Label = "" }
  }
  if ($IgnoreSelfLoopback -and $IsSelfLoopback) {
    $reason = "self-loopback port $RemotePort (not an OpenCode server pair)"
    return [pscustomobject]@{
      Severity = "INFO"
      Reasons  = @($reason)
      Label    = "INFO: $reason"
    }
  }

  if (($LoopbackAllowPorts -contains $LocalPort) -or ($LoopbackAllowPorts -contains $RemotePort)) {
    return [pscustomobject]@{ Severity = ""; Reasons = @(); Label = "" }
  }

  $reason = "loopback destination port $RemotePort (not on allowlist)"
  return [pscustomobject]@{
    Severity = "ALERT"
    Reasons  = @($reason)
    Label    = "ALERT: $reason"
  }
}

function Get-TcpAlertReasons {
  param(
    [string]$LocalAddress,
    [int]$LocalPort,
    [string]$RemoteAddress,
    [int]$RemotePort,
    [string]$State,
    [int[]]$LoopbackAllowPorts,
    [bool]$IsSelfLoopback = $false,
    [bool]$IsOpenCodeServerLoopback = $false,
    [bool]$IgnoreSelfLoopback = $true
  )
  $class = Get-TcpWatchClassification -LocalAddress $LocalAddress -LocalPort $LocalPort -RemoteAddress $RemoteAddress -RemotePort $RemotePort -State $State -LoopbackAllowPorts $LoopbackAllowPorts -IsSelfLoopback $IsSelfLoopback -IsOpenCodeServerLoopback $IsOpenCodeServerLoopback -IgnoreSelfLoopback $IgnoreSelfLoopback
  if ($class.Severity -eq "ALERT") { return @($class.Reasons) }
  return @()
}

function Get-OpenCodeDefaultListenPorts {
  # OpenCode's built-in HTTP server defaults to port 4096.
  return @(4096)
}

function New-OpenCodeListenPortSet {
  param([int[]]$ExtraPorts = @())
  $set = @{}
  foreach ($p in (Get-OpenCodeDefaultListenPorts)) { $set[[int]$p] = $true }
  foreach ($p in @($ExtraPorts)) {
    if ($p -gt 0) { $set[[int]$p] = $true }
  }
  return $set
}

function Test-IsSysmonInitiatedFalse {
  param([string]$Initiated)
  if ([string]::IsNullOrWhiteSpace($Initiated)) { return $false }
  return ($Initiated.Trim() -match '^(?i)(false|0|no)$')
}

function Add-OpenCodeListenPortFromSysmonNetwork {
  # Event 3 has no peer PID. An inbound (Initiated=false) connect to a
  # loopback port, owned by opencode.exe, is treated as a listen port.
  param(
    [string]$Image,
    [string]$DestinationIp,
    [int]$DestinationPort,
    [string]$Initiated,
    $PortSet
  )
  if ($null -eq $PortSet) { return }
  if (-not (Test-IsOpenCodeImageName $Image)) { return }
  if (-not (Test-IsLoopbackAddress $DestinationIp)) { return }
  if ($DestinationPort -le 0) { return }
  if (-not (Test-IsSysmonInitiatedFalse $Initiated)) { return }
  $PortSet[[int]$DestinationPort] = $true
}

function Test-IsSysmonOpenCodeSelfLoopback {
  # True when the image is opencode.exe, the destination is loopback,
  # and the destination (or source) port is a known OpenCode listen
  # port, including the 4096 default.
  param(
    [string]$Image,
    [string]$SourceIp,
    [int]$SourcePort,
    [string]$DestinationIp,
    [int]$DestinationPort,
    $OpenCodeListenPorts
  )
  if (-not (Test-IsOpenCodeImageName $Image)) { return $false }
  if (-not (Test-IsLoopbackAddress $DestinationIp)) { return $false }
  $ports = $OpenCodeListenPorts
  if ($null -eq $ports) { $ports = (New-OpenCodeListenPortSet) }
  if ($ports -is [hashtable] -or $ports -is [System.Collections.IDictionary]) {
    if ($ports.Contains([int]$DestinationPort) -or $ports.ContainsKey([int]$DestinationPort)) { return $true }
    if ($SourcePort -gt 0 -and (Test-IsLoopbackAddress $SourceIp) -and ($ports.Contains([int]$SourcePort) -or $ports.ContainsKey([int]$SourcePort))) { return $true }
    return $false
  }
  $list = @($ports)
  if ($list -contains [int]$DestinationPort) { return $true }
  if ($SourcePort -gt 0 -and (Test-IsLoopbackAddress $SourceIp) -and ($list -contains [int]$SourcePort)) { return $true }
  return $false
}

function Get-SysmonNetworkClassification {
  # Event 3 classification. No peer PID is available. OpenCode talking
  # to its own listen port (or 4096) on loopback is INFO when
  # IgnoreSelfLoopback is true. Debug ports still ALERT.
  param(
    [string]$Image,
    [string]$SourceIp,
    [int]$SourcePort,
    [string]$DestinationIp,
    [int]$DestinationPort,
    $OpenCodeListenPorts,
    [int[]]$LoopbackAllowPorts,
    [bool]$IgnoreSelfLoopback = $true
  )
  $class = Get-TcpWatchClassification -LocalAddress $SourceIp -LocalPort $SourcePort -RemoteAddress $DestinationIp -RemotePort $DestinationPort -State "Established" -LoopbackAllowPorts $LoopbackAllowPorts -IsSelfLoopback $false -IsOpenCodeServerLoopback $false -IgnoreSelfLoopback $false
  $debugPorts = Get-DebugLoopbackPorts
  if (($debugPorts -contains $DestinationPort) -or ($debugPorts -contains $SourcePort)) {
    return $class
  }
  if ($IgnoreSelfLoopback -and (Test-IsSysmonOpenCodeSelfLoopback -Image $Image -SourceIp $SourceIp -SourcePort $SourcePort -DestinationIp $DestinationIp -DestinationPort $DestinationPort -OpenCodeListenPorts $OpenCodeListenPorts)) {
    $reason = ("opencode self-loopback port {0}" -f $DestinationPort)
    return [pscustomobject]@{
      Severity = "INFO"
      Reasons  = @($reason)
      Label    = "INFO: $reason"
    }
  }
  return $class
}

function Get-CommandLineArgumentText {
  # Returns the command line with argv[0] (and an optional Image path
  # prefix) removed, so secret-path patterns can ignore the process's
  # own image path.
  param(
    [string]$CommandLine,
    [string]$Image = ""
  )
  if ([string]::IsNullOrWhiteSpace($CommandLine)) { return "" }
  $s = $CommandLine.TrimStart()
  if (-not [string]::IsNullOrWhiteSpace($Image)) {
    $img = $Image.Trim().Trim('"')
    if (-not [string]::IsNullOrWhiteSpace($img)) {
      $quoted = '"' + $img + '"'
      if ($s.StartsWith($quoted, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $s.Substring($quoted.Length).TrimStart()
      }
      if ($s.StartsWith($img, [System.StringComparison]::OrdinalIgnoreCase)) {
        if ($s.Length -eq $img.Length) { return "" }
        $next = $s[$img.Length]
        if ([char]::IsWhiteSpace($next) -or $next -eq [char]'"') {
          return $s.Substring($img.Length).TrimStart()
        }
      }
    }
  }
  if ($s.StartsWith('"')) {
    $end = $s.IndexOf('"', 1)
    if ($end -gt 0) { return $s.Substring($end + 1).TrimStart() }
    return ""
  }
  $m = [regex]::Match($s, '\s+')
  if (-not $m.Success) { return "" }
  return $s.Substring($m.Index).TrimStart()
}

function Add-UniqueLogLine {
  param(
    $List,
    $Seen,
    [string]$Line
  )
  if ($null -eq $List -or $null -eq $Seen) { return $false }
  if ($Seen.ContainsKey($Line)) { return $false }
  $Seen[$Line] = $true
  [void]$List.Add($Line)
  return $true
}

function Get-CommandLineAlertReasons {
  param(
    [string]$CommandLine,
    $ExtraRegexes = @(),
    [string]$Image = ""
  )
  $reasons = New-Object System.Collections.Generic.List[string]
  if ([string]::IsNullOrWhiteSpace($CommandLine)) {
    return @()
  }
  $c = $CommandLine
  $pathText = Get-CommandLineArgumentText -CommandLine $CommandLine -Image $Image

  $pathRules = @(
    @{ Re = '(?i)cookies'; Reason = "cookies" },
    @{ Re = '(?i)Login Data'; Reason = "Login Data" },
    @{ Re = '(?i)Local State'; Reason = "Local State" },
    @{ Re = '(?i)EBWebView'; Reason = "EBWebView" },
    @{ Re = '(?i)User Data'; Reason = "User Data" },
    @{ Re = '(?i)(^|[\\/\s"''])\.ssh\b'; Reason = ".ssh" },
    @{ Re = '(?i)\.env\b'; Reason = ".env" },
    @{ Re = '(?i)auth\.json'; Reason = "auth.json" },
    @{ Re = '(?i)credential'; Reason = "credential" },
    @{ Re = '(?i)ConsoleHost_history'; Reason = "ConsoleHost_history" },
    @{ Re = '(?i)(^|[\\/\s"''])\.grok\b'; Reason = ".grok" }
  )
  foreach ($r in $pathRules) {
    if (-not [string]::IsNullOrWhiteSpace($pathText) -and [regex]::IsMatch($pathText, $r.Re)) {
      $reasons.Add($r.Reason)
    }
  }

  if ([regex]::IsMatch($c, '(?i)\bgh(\.exe)?"?\s+auth\b')) {
    $reasons.Add("gh auth")
  }
  if ([regex]::IsMatch($c, '(?i)(^|[\s;&|])printenv(\s|$|[&|<>])')) {
    $reasons.Add("env dump (printenv)")
  }
  if ([regex]::IsMatch($c, '(?i)(?:Get-ChildItem|\bgci)\s+(?:-Path\s+)?Env:')) {
    $reasons.Add("env dump (Get-ChildItem env:)")
  }
  if ([regex]::IsMatch($c, '(?i)(^|[\s;&|])dir\s+Env:')) {
    $reasons.Add("env dump (dir env:)")
  }
  if ([regex]::IsMatch($c, '(?i)(^|[\s;&|])ls\s+Env:')) {
    $reasons.Add("env dump (ls env:)")
  }
  if ([regex]::IsMatch($c, '(?i)\[Environment\]::GetEnvironmentVariables')) {
    $reasons.Add("env dump ([Environment]::GetEnvironmentVariables)")
  }
  if ([regex]::IsMatch($c, '(?i)(^|[\s;&|])set\s*($|[&|<>])')) {
    $reasons.Add("env dump (set)")
  }
  if ([regex]::IsMatch($c, '(?i)(^|[\s;&|])env(\.exe)?\s*($|[&|<>])')) {
    $reasons.Add("env dump (env)")
  }

  if ([regex]::IsMatch($c, '(?i)\bschtasks(\.exe)?\b|\bRegister-ScheduledTask\b|\bNew-ScheduledTask\b')) {
    $reasons.Add("scheduled task")
  }
  if ([regex]::IsMatch($c, '(?i)CurrentVersion\\Run|\breg(\.exe)?\s+add\b')) {
    $reasons.Add("registry Run / reg add")
  }
  if ([regex]::IsMatch($c, '(?i)\b(New|Set)-ItemProperty\b')) {
    $reasons.Add("registry property change")
  }
  if ([regex]::IsMatch($c, '(?i)(\\Startup\b|\\Start Menu\\Programs\\Startup|shell:startup)')) {
    $reasons.Add("Startup folder")
  }

  foreach ($rx in @($ExtraRegexes)) {
    if ($null -eq $rx) { continue }
    try {
      if ($rx.IsMatch($c)) {
        $reasons.Add(("extra pattern: {0}" -f $rx.ToString()))
      }
    } catch {
      # already validated at load; never fail an alert check
    }
  }

  return $reasons.ToArray()
}

function Format-AlertLabel {
  param([string[]]$Reasons)
  if ($null -eq $Reasons -or $Reasons.Count -eq 0) { return "" }
  return ("ALERT: " + ($Reasons -join "; "))
}

function Get-TbvProcessBaseName {
  param([string]$Name)
  if ([string]::IsNullOrWhiteSpace($Name)) { return "" }
  $n = $Name.Trim().ToLowerInvariant()
  foreach ($ext in @(".exe", ".cmd", ".bat", ".ps1", ".com")) {
    if ($n.EndsWith($ext)) {
      return $n.Substring(0, $n.Length - $ext.Length)
    }
  }
  return $n
}

function Test-IsOpenCodeSeed {
  param(
    [string]$Name,
    [string]$CommandLine,
    [string[]]$WatchedProcessNames = @()
  )
  $n = Get-TbvProcessBaseName $Name
  $watch = @()
  if ($null -ne $WatchedProcessNames -and @($WatchedProcessNames).Count -gt 0) {
    $watch = @($WatchedProcessNames)
  }
  foreach ($w in $watch) {
    if ((Get-TbvProcessBaseName $w) -eq $n -and $n -ne "") { return $true }
  }
  if ($n -eq "opencode") { return $true }
  if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $false }
  if ([regex]::IsMatch($CommandLine, '(?i)(^|.*[\\/])opencode(\.exe|\.cmd|\.ps1)?(\s|"|''|$)')) {
    return $true
  }
  if ([regex]::IsMatch($CommandLine, '(?i)\bopencode\s+acp\b')) { return $true }
  if ([regex]::IsMatch($CommandLine, '(?i)[\\/]opencode[\\/]|opencode-ai')) { return $true }
  return $false
}

function ConvertTo-CsvField {
  param($Value)
  if ($null -eq $Value) { return "" }
  $s = "$Value"
  if ($s -match '[",\r\n]') {
    return ('"' + ($s -replace '"', '""') + '"')
  }
  return $s
}

function Get-WatchCsvHeader {
  return "Time,Kind,Alert,Pid,Ppid,Name,LocalAddress,LocalPort,RemoteAddress,RemotePort,RemoteHost,State,CommandLine"
}

function Format-WatchCsvRow {
  param(
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
  $fields = @(
    (ConvertTo-CsvField $Time),
    (ConvertTo-CsvField $Kind),
    (ConvertTo-CsvField $Alert),
    (ConvertTo-CsvField $ProcId),
    (ConvertTo-CsvField $ParentProcId),
    (ConvertTo-CsvField $Name),
    (ConvertTo-CsvField $LocalAddress),
    (ConvertTo-CsvField $LocalPort),
    (ConvertTo-CsvField $RemoteAddress),
    (ConvertTo-CsvField $RemotePort),
    (ConvertTo-CsvField $RemoteHost),
    (ConvertTo-CsvField $State),
    (ConvertTo-CsvField $CommandLine)
  )
  return ($fields -join ",")
}

function Get-StampNow {
  # Local time with offset, e.g. 2026-11-20 03:53:01 -05:00
  return (Get-Date -Format "yyyy-MM-dd HH:mm:ss K")
}

function Strip-JsoncComments {
  param([string]$Text)
  if ($null -eq $Text) { return "" }
  $sb = New-Object System.Text.StringBuilder
  $i = 0
  $n = $Text.Length
  $inString = $false
  $escape = $false
  while ($i -lt $n) {
    $ch = $Text[$i]
    if ($inString) {
      [void]$sb.Append($ch)
      if ($escape) {
        $escape = $false
      } elseif ($ch -eq [char]'\' ) {
        $escape = $true
      } elseif ($ch -eq [char]'"') {
        $inString = $false
      }
      $i++
      continue
    }
    if ($ch -eq [char]'"') {
      $inString = $true
      [void]$sb.Append($ch)
      $i++
      continue
    }
    if ($ch -eq [char]'/' -and ($i + 1) -lt $n) {
      $next = $Text[$i + 1]
      if ($next -eq [char]'/') {
        $i += 2
        while ($i -lt $n -and $Text[$i] -ne [char]"`n") { $i++ }
        continue
      }
      if ($next -eq [char]'*') {
        $i += 2
        while (($i + 1) -lt $n -and -not ($Text[$i] -eq [char]'*' -and $Text[$i + 1] -eq [char]'/')) {
          $i++
        }
        $i += 2
        continue
      }
    }
    [void]$sb.Append($ch)
    $i++
  }
  return $sb.ToString()
}

# Case-sensitive, order-preserving JSON parser. ConvertFrom-Json in
# PowerShell cannot store two keys that differ only by case (OpenCode
# configs often have both "*devtools*" and "*DevTools*"), and Windows
# PowerShell 5.1 also does not reliably keep key order, which matters
# because OpenCode uses last-match-wins.
function ConvertFrom-JsonText {
  param([Parameter(Mandatory = $true)][string]$Text)
  $script:JsonParseText = $Text
  $script:JsonParsePos = 0
  $len = $Text.Length

  function Get-JsonPeek {
    if ($script:JsonParsePos -ge $len) { return [char]0 }
    return $script:JsonParseText[$script:JsonParsePos]
  }

  function Skip-JsonWhitespace {
    while ($script:JsonParsePos -lt $len) {
      $ch = $script:JsonParseText[$script:JsonParsePos]
      if ($ch -eq [char]" " -or $ch -eq [char]"`t" -or $ch -eq [char]"`r" -or $ch -eq [char]"`n") {
        $script:JsonParsePos++
      } else {
        break
      }
    }
  }

  function Read-JsonChar {
    if ($script:JsonParsePos -ge $len) {
      throw "Unexpected end of JSON"
    }
    $ch = $script:JsonParseText[$script:JsonParsePos]
    $script:JsonParsePos++
    return $ch
  }

  function Read-JsonString {
    $open = Read-JsonChar
    if ($open -ne [char]'"') { throw "Expected string" }
    $sb = New-Object System.Text.StringBuilder
    while ($true) {
      $ch = Read-JsonChar
      if ($ch -eq [char]'"') { break }
      if ($ch -eq [char]'\') {
        $esc = Read-JsonChar
        switch ([string]$esc) {
          '"' { [void]$sb.Append([char]'"') }
          '\' { [void]$sb.Append([char]'\') }
          '/' { [void]$sb.Append([char]'/') }
          'b' { [void]$sb.Append([char]8) }
          'f' { [void]$sb.Append([char]12) }
          'n' { [void]$sb.Append([char]10) }
          'r' { [void]$sb.Append([char]13) }
          't' { [void]$sb.Append([char]9) }
          'u' {
            $hex = ""
            for ($i = 0; $i -lt 4; $i++) { $hex += [string](Read-JsonChar) }
            $code = [Convert]::ToInt32($hex, 16)
            [void]$sb.Append([char]$code)
          }
          default { throw ("Bad JSON escape \{0}" -f $esc) }
        }
      } else {
        [void]$sb.Append($ch)
      }
    }
    return $sb.ToString()
  }

  function Read-JsonValue {
    Skip-JsonWhitespace
    $ch = Get-JsonPeek
    if ($ch -eq [char]'"') { return (Read-JsonString) }
    if ($ch -eq [char]'{') { return (Read-JsonObject) }
    if ($ch -eq [char]'[') { return (Read-JsonArray) }
    if ($ch -eq [char]'t' -or $ch -eq [char]'f' -or $ch -eq [char]'n') {
      $word = ""
      while ($script:JsonParsePos -lt $len) {
        $c = Get-JsonPeek
        if (($c -ge [char]'a' -and $c -le [char]'z') -or ($c -ge [char]'A' -and $c -le [char]'Z')) {
          $word += [string](Read-JsonChar)
        } else { break }
      }
      if ($word -eq "true") { return $true }
      if ($word -eq "false") { return $false }
      if ($word -eq "null") { return $null }
      throw ("Bad JSON token {0}" -f $word)
    }
    # number
    $num = ""
    if ($ch -eq [char]'-') { $num += [string](Read-JsonChar) }
    $ch = Get-JsonPeek
    while ($ch -ge [char]'0' -and $ch -le [char]'9') {
      $num += [string](Read-JsonChar)
      $ch = Get-JsonPeek
    }
    if ($ch -eq [char]'.') {
      $num += [string](Read-JsonChar)
      $ch = Get-JsonPeek
      while ($ch -ge [char]'0' -and $ch -le [char]'9') {
        $num += [string](Read-JsonChar)
        $ch = Get-JsonPeek
      }
    }
    if ($ch -eq [char]'e' -or $ch -eq [char]'E') {
      $num += [string](Read-JsonChar)
      $ch = Get-JsonPeek
      if ($ch -eq [char]'+' -or $ch -eq [char]'-') { $num += [string](Read-JsonChar) }
      $ch = Get-JsonPeek
      while ($ch -ge [char]'0' -and $ch -le [char]'9') {
        $num += [string](Read-JsonChar)
        $ch = Get-JsonPeek
      }
    }
    if ($num -eq "" -or $num -eq "-") { throw "Bad JSON number" }
    if ($num -match '[\.eE]') { return [double]$num }
    $l = 0L
    if ([long]::TryParse($num, [ref]$l)) { return $l }
    return [double]$num
  }

  function Read-JsonObject {
    $open = Read-JsonChar
    if ($open -ne [char]'{') { throw "Expected object" }
    $map = New-Object System.Collections.Specialized.OrderedDictionary
    Skip-JsonWhitespace
    if ((Get-JsonPeek) -eq [char]'}') { [void](Read-JsonChar); return $map }
    while ($true) {
      Skip-JsonWhitespace
      $key = Read-JsonString
      Skip-JsonWhitespace
      $colon = Read-JsonChar
      if ($colon -ne [char]':') { throw "Expected colon" }
      $val = Read-JsonValue
      if ($map.Contains($key)) { $map.Remove($key) }
      [void]$map.Add($key, $val)
      Skip-JsonWhitespace
      $sep = Read-JsonChar
      if ($sep -eq [char]'}') { break }
      if ($sep -ne [char]',') { throw "Expected comma or end of object" }
      Skip-JsonWhitespace
      if ((Get-JsonPeek) -eq [char]'}') { [void](Read-JsonChar); break }
    }
    return $map
  }

  function Read-JsonArray {
    $open = Read-JsonChar
    if ($open -ne [char]'[') { throw "Expected array" }
    $list = New-Object System.Collections.Generic.List[object]
    Skip-JsonWhitespace
    if ((Get-JsonPeek) -eq [char]']') { [void](Read-JsonChar); return $list.ToArray() }
    while ($true) {
      $list.Add((Read-JsonValue))
      Skip-JsonWhitespace
      $sep = Read-JsonChar
      if ($sep -eq [char]']') { break }
      if ($sep -ne [char]',') { throw "Expected comma or end of array" }
      Skip-JsonWhitespace
      if ((Get-JsonPeek) -eq [char]']') { [void](Read-JsonChar); break }
    }
    return $list.ToArray()
  }

  Skip-JsonWhitespace
  $value = Read-JsonValue
  Skip-JsonWhitespace
  if ($script:JsonParsePos -lt $len) {
    throw ("Unexpected trailing JSON at position {0}" -f $script:JsonParsePos)
  }
  return $value
}

function ConvertFrom-Jsonc {
  param([Parameter(Mandatory = $true)][string]$Text)
  $stripped = Strip-JsoncComments $Text
  return (ConvertFrom-JsonText -Text $stripped)
}

function Test-IsWindowsOS {
  if ($env:OS -eq "Windows_NT") { return $true }
  if ($PSVersionTable.ContainsKey("Platform") -and $PSVersionTable.Platform -eq "Win32NT") { return $true }
  if ($PSVersionTable.PSEdition -eq "Desktop") { return $true }
  return $false
}

function Test-IsAdmin {
  try {
    $wid = [Security.Principal.WindowsIdentity]::GetCurrent()
    $prin = New-Object Security.Principal.WindowsPrincipal($wid)
    return $prin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

function Get-ErrorText {
  param($ErrorObject)
  if ($null -eq $ErrorObject) { return "" }
  $parts = New-Object System.Collections.Generic.List[string]
  try { if ($ErrorObject.ToString()) { $parts.Add([string]$ErrorObject) } } catch { }
  $ex = $null
  try { $ex = $ErrorObject.Exception } catch { }
  $guard = 0
  while ($null -ne $ex -and $guard -lt 6) {
    $guard++
    if ($ex.Message) { $parts.Add([string]$ex.Message) }
    if ($ex.GetType()) { $parts.Add([string]$ex.GetType().FullName) }
    try { $ex = $ex.InnerException } catch { $ex = $null }
  }
  return (($parts.ToArray()) -join " | ")
}

function Test-IsSysmonLogAccessError {
  param($ErrorObject)
  $text = Get-ErrorText $ErrorObject
  if ([string]::IsNullOrWhiteSpace($text) -and $ErrorObject -is [string]) {
    $text = [string]$ErrorObject
  }
  if ($text -match '(?i)unauthorized operation|unauthorized|access is denied|access denied|permission denied') {
    return $true
  }
  if ($text -match '(?i)UnauthorizedAccessException|SecurityException') {
    return $true
  }
  return $false
}

function Get-SysmonSummaryTaskPlan {
  # The nightly task uses RunLevel Limited. Reading the Sysmon log is
  # granted at install time via Event Log Readers and a channel ACL.
  # Registration does not require admin once that access is in place.
  param(
    [string]$TaskName = "OpenCodeWatch-SysmonSummary",
    [string]$TimeOfDay = "03:00",
    [string]$SummaryPath = "",
    [int]$LastHours = 24
  )
  return [pscustomobject]@{
    TaskName       = $TaskName
    TimeOfDay      = $TimeOfDay
    RunLevel       = "Limited"
    RequiresAdmin  = $false
    LastHours      = $LastHours
    SummaryPath    = $SummaryPath
    LogReadMethod  = "Event Log Readers and a Sysmon channel ACL. Sign out and back in after install-sysmon.ps1 so group membership applies."
  }
}

function Get-SysmonLogAdminMessage {
  return "needs permission to read Sysmon log. Reading Microsoft-Windows-Sysmon/Operational requires Event Log Readers membership (or an elevated window). If you just ran install-sysmon.ps1, sign out and back in, then retry. The nightly task is registered with RunLevel Limited and must not run as admin."
}

function Resolve-RemoteHostBestEffort {
  param(
    [string]$Address,
    [hashtable]$Cache
  )
  if ([string]::IsNullOrWhiteSpace($Address)) { return "" }
  $a = $Address.Trim().TrimStart('[').TrimEnd(']')
  if (Test-IsLoopbackAddress $a) { return "localhost" }
  if (Test-IsUnspecifiedAddress $a) { return "" }
  if ($null -ne $Cache -and $Cache.ContainsKey($a)) { return [string]$Cache[$a] }
  $name = ""
  try {
    $entry = [System.Net.Dns]::GetHostEntry($a)
    if ($entry -and $entry.HostName) { $name = [string]$entry.HostName }
  } catch {
    $name = ""
  }
  if ($null -ne $Cache) { $Cache[$a] = $name }
  return $name
}

function Test-AuthenticodeMicrosoft {
  param([Parameter(Mandatory = $true)][string]$Path)
  if (-not (Test-IsWindowsOS)) {
    throw "Authenticode checks can only run on Windows: $Path"
  }
  $sig = Get-AuthenticodeSignature -LiteralPath $Path
  if ($sig.Status -ne "Valid") {
    throw ("Authenticode status for {0} is {1}, expected Valid" -f $Path, $sig.Status)
  }
  $subject = ""
  if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject) {
    $subject = [string]$sig.SignerCertificate.Subject
  }
  $issuer = ""
  if ($sig.SignerCertificate -and $sig.SignerCertificate.Issuer) {
    $issuer = [string]$sig.SignerCertificate.Issuer
  }
  $ok = $false
  if ($subject -match 'O=Microsoft Corporation' -or $subject -match 'CN=Microsoft ') { $ok = $true }
  if ($issuer -match 'O=Microsoft Corporation' -and $subject -match 'Microsoft') { $ok = $true }
  if (-not $ok) {
    throw ("Authenticode signer for {0} is not Microsoft. Subject={1} Issuer={2}" -f $Path, $subject, $issuer)
  }
  return $sig
}
