# test-redaction.ps1
# Unit-style tests for Protect-SecretText and ALERT helpers.
# Run from the kit root:  pwsh -NoProfile -File tests/test-redaction.ps1

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"

$kit = Split-Path -Parent $PSScriptRoot
. (Join-Path $kit "lib\WatchCommon.ps1")

$failed = 0
$passed = 0

function Assert-True {
  param([bool]$Cond, [string]$Name)
  if ($Cond) {
    $script:passed++
    Write-Host ("PASS  {0}" -f $Name)
  } else {
    $script:failed++
    Write-Host ("FAIL  {0}" -f $Name)
  }
}

function Assert-Eq {
  param($Actual, $Expected, [string]$Name)
  if ($Actual -eq $Expected) {
    $script:passed++
    Write-Host ("PASS  {0}" -f $Name)
  } else {
    $script:failed++
    Write-Host ("FAIL  {0}" -f $Name)
    Write-Host ("      expected: {0}" -f $Expected)
    Write-Host ("      actual:   {0}" -f $Actual)
  }
}

function Assert-Contains {
  param([string]$Actual, [string]$Needle, [string]$Name)
  if ($Actual -and $Actual.Contains($Needle)) {
    $script:passed++
    Write-Host ("PASS  {0}" -f $Name)
  } else {
    $script:failed++
    Write-Host ("FAIL  {0}" -f $Name)
    Write-Host ("      missing:  {0}" -f $Needle)
    Write-Host ("      actual:   {0}" -f $Actual)
  }
}

function Assert-NotContains {
  param([string]$Actual, [string]$Needle, [string]$Name)
  if ($null -eq $Actual -or -not $Actual.Contains($Needle)) {
    $script:passed++
    Write-Host ("PASS  {0}" -f $Name)
  } else {
    $script:failed++
    Write-Host ("FAIL  {0}" -f $Name)
    Write-Host ("      should not contain: {0}" -f $Needle)
    Write-Host ("      actual:             {0}" -f $Actual)
  }
}

# --- redaction ---

Assert-Eq (Protect-SecretText "") "" "empty string"
Assert-Eq (Protect-SecretText $null) "" "null becomes empty string"

$sk = Protect-SecretText "Authorization: sk-abcdefghijklmnop"
Assert-Contains $sk "sk-[REDACTED]" "sk- prefix kept"
Assert-NotContains $sk "abcdefghijklmnop" "sk- body redacted"
$sk2 = Protect-SecretText "export KEY=sk-abcdefghijklmnop"
Assert-Contains $sk2 "KEY=[REDACTED]" "KEY=sk- caught by key= rule"
Assert-NotContains $sk2 "abcdefghijklmnop" "KEY=sk- body redacted"

$ghp = Protect-SecretText "Authorization: ghp_ABCDEFghijklmnop1234"
Assert-Contains $ghp "ghp_[REDACTED]" "ghp_ prefix kept"
Assert-NotContains $ghp "ABCDEFghijklmnop1234" "ghp_ body redacted"

$gho = Protect-SecretText "token gho_xxxxxxxxxxxxYYYYZZZZ"
Assert-Contains $gho "gho_[REDACTED]" "gho_ prefix kept"
Assert-NotContains $gho "xxxxxxxxxxxxYYYYZZZZ" "gho_ body redacted"

$pat = Protect-SecretText "GITHUB_TOKEN=github_pat_11AAAAAAA_0123456789abcdef"
Assert-Contains $pat "github_pat_[REDACTED]" "github_pat_ prefix kept"
Assert-NotContains $pat "11AAAAAAA_0123456789abcdef" "github_pat_ body redacted"

$xai = Protect-SecretText "XAI_API_KEY=xai-abcdefghijklmnopqrstuvwxyz012345"
Assert-Contains $xai "xai-[REDACTED]" "xai- prefix kept"
Assert-NotContains $xai "abcdefghijklmnopqrstuvwxyz012345" "xai- body redacted"

$bearer = Protect-SecretText "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
Assert-Contains $bearer "Bearer [REDACTED]" "Bearer redacted"
Assert-NotContains $bearer "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" "JWT body redacted"

$basic = Protect-SecretText "Authorization: Basic dXNlcjpwYXNz"
Assert-True ($basic -match "Basic") "Basic prefix kept"
Assert-True ($basic -notmatch "dXNlcjpwYXNz") "Basic body redacted"

$kv = Protect-SecretText "https://example.com/api?token=supersecret&x=1 password=hunter2 key=abc123"
Assert-Contains $kv "token=[REDACTED]" "token= redacted"
Assert-Contains $kv "password=[REDACTED]" "password= redacted"
Assert-Contains $kv "key=[REDACTED]" "key= redacted"
Assert-NotContains $kv "supersecret" "token value gone"
Assert-NotContains $kv "hunter2" "password value gone"
Assert-Contains $kv "x=1" "unrelated query kept"

$hex = "deadbeefcafebabe" * 4  # 64 hex chars
$hx = Protect-SecretText ("git show " + $hex)
Assert-Contains $hx "[REDACTED-HEX]" "long hex redacted"
Assert-NotContains $hx $hex "long hex body gone"

$shortSha = "git log abcdef1234567890abcdef1234567890abcdef12"
$ss = Protect-SecretText $shortSha
Assert-Eq $ss $shortSha "40-char git SHA left alone"

$b64raw = "A" * 40 + "=="
$b64 = Protect-SecretText ("data " + $b64raw)
Assert-Contains $b64 "[REDACTED-B64]" "long base64 redacted"
Assert-NotContains $b64 $b64raw "long base64 body gone"

$plain = "git status --short && ls src"
Assert-Eq (Protect-SecretText $plain) $plain "ordinary command line unchanged"

$multi = Protect-SecretText "sk-aaaaaaaabbbbbbbb ghp_ccccddddEEEEFFFF"
Assert-Contains $multi "sk-[REDACTED]" "multi sk"
Assert-Contains $multi "ghp_[REDACTED]" "multi ghp"
Assert-NotContains $multi "aaaaaaaabbbbbbbb" "multi sk body gone"
Assert-NotContains $multi "ccccddddEEEEFFFF" "multi ghp body gone"

# --- command-line alerts ---

function Assert-Alert {
  param([string]$Cmd, [string]$ReasonPart, [string]$Name)
  $reasons = @(Get-CommandLineAlertReasons -CommandLine $Cmd)
  $joined = $reasons -join "; "
  if ($joined -match [regex]::Escape($ReasonPart)) {
    $script:passed++
    Write-Host ("PASS  {0}" -f $Name)
  } else {
    $script:failed++
    Write-Host ("FAIL  {0}" -f $Name)
    Write-Host ("      expected reason containing: {0}" -f $ReasonPart)
    Write-Host ("      actual: {0}" -f $joined)
  }
}

function Assert-NoAlert {
  param([string]$Cmd, [string]$Name)
  $reasons = @(Get-CommandLineAlertReasons -CommandLine $Cmd)
  if ($reasons.Count -eq 0) {
    $script:passed++
    Write-Host ("PASS  {0}" -f $Name)
  } else {
    $script:failed++
    Write-Host ("FAIL  {0}" -f $Name)
    Write-Host ("      unexpected alerts: {0}" -f ($reasons -join "; "))
  }
}

Assert-Alert "type Cookies" "cookies" "alert cookies"
Assert-Alert "Get-Content 'Login Data'" "Login Data" "alert Login Data"
Assert-Alert "type 'Local State'" "Local State" "alert Local State"
Assert-Alert "dir EBWebView" "EBWebView" "alert EBWebView"
Assert-Alert "dir 'User Data'" "User Data" "alert User Data"
Assert-Alert "type %USERPROFILE%\.ssh\id_rsa" ".ssh" "alert .ssh"
Assert-Alert "type .env" ".env" "alert .env"
Assert-Alert "type auth.json" "auth.json" "alert auth.json"
Assert-Alert "type credential" "credential" "alert credential"
Assert-Alert "type ConsoleHost_history.txt" "ConsoleHost_history" "alert history"
Assert-Alert "dir %USERPROFILE%\.grok\bin" ".grok" "alert .grok"
Assert-Alert "gh auth status" "gh auth" "alert gh auth"
Assert-Alert '"C:\Program Files\GitHub CLI\gh.exe" auth status' "gh auth" "alert gh auth when gh is argv0"
Assert-Alert "printenv" "printenv" "alert printenv"
Assert-Alert "Get-ChildItem env:" "Get-ChildItem env:" "alert gci env"
Assert-Alert "gci env:" "Get-ChildItem env:" "alert gci alias"
Assert-Alert "dir env:" "dir env:" "alert dir env"
Assert-Alert "ls env:" "ls env:" "alert ls env"
Assert-Alert "[Environment]::GetEnvironmentVariables()" "GetEnvironmentVariables" "alert Environment API"
Assert-Alert "cmd /c set" "env dump (set)" "alert bare set"
Assert-Alert "env" "env dump (env)" "alert bare env"
Assert-Alert "schtasks /create /tn x" "scheduled task" "alert schtasks"
Assert-Alert "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /t REG_SZ /d y" "registry Run" "alert reg run"
Assert-Alert "Set-ItemProperty -Path HKCU:\...\Run -Name x -Value y" "registry property" "alert Set-ItemProperty"
Assert-Alert "copy x %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\x.cmd" "Startup folder" "alert Startup folder"

Assert-NoAlert "git status --short" "no alert git status"
Assert-NoAlert "ls src" "no alert ls src"
Assert-NoAlert "type settings.json" "no alert settings"
Assert-NoAlert "environment-config.md" "no alert environment word"

# --- TCP alerts ---

$allow = @(80, 443, 3000, 4173, 5173, 8000, 8080)

$r = @(Get-TcpAlertReasons -LocalAddress "127.0.0.1" -LocalPort 54321 -RemoteAddress "127.0.0.1" -RemotePort 9222 -State "Established" -LoopbackAllowPorts $allow)
Assert-True ($r -join ";" | Select-String -Pattern "9222" -Quiet) "alert loopback 9222"

$r = @(Get-TcpAlertReasons -LocalAddress "0.0.0.0" -LocalPort 9229 -RemoteAddress "0.0.0.0" -RemotePort 0 -State "Listen" -LoopbackAllowPorts $allow)
Assert-True ($r -join ";" | Select-String -Pattern "9229" -Quiet) "alert listen 9229"

$r = @(Get-TcpAlertReasons -LocalAddress "127.0.0.1" -LocalPort 12345 -RemoteAddress "127.0.0.1" -RemotePort 9999 -State "Established" -LoopbackAllowPorts $allow)
Assert-True ($r -join ";" | Select-String -Pattern "9999" -Quiet) "alert non-allowlisted loopback dest"

$r = @(Get-TcpAlertReasons -LocalAddress "127.0.0.1" -LocalPort 12345 -RemoteAddress "127.0.0.1" -RemotePort 3000 -State "Established" -LoopbackAllowPorts $allow)
Assert-True ($r.Count -eq 0) "allowlisted loopback 3000 is quiet"

$r = @(Get-TcpAlertReasons -LocalAddress "192.168.1.4" -LocalPort 55555 -RemoteAddress "1.2.3.4" -RemotePort 443 -State "Established" -LoopbackAllowPorts $allow)
Assert-True ($r.Count -eq 0) "ordinary outbound https is quiet"

# debug ports always alert even if allowlisted
$r = @(Get-TcpAlertReasons -LocalAddress "127.0.0.1" -LocalPort 1 -RemoteAddress "127.0.0.1" -RemotePort 9222 -State "Established" -LoopbackAllowPorts @(9222, 80))
Assert-True ($r -join ";" | Select-String -Pattern "9222" -Quiet) "9222 alerts even if allowlisted"

# --- Listen: loopback is INFO, wildcard/public ALERT; debug always ALERT ---
$c = Get-TcpWatchClassification -LocalAddress "127.0.0.1" -LocalPort 4096 -RemoteAddress "0.0.0.0" -RemotePort 0 -State "Listen" -LoopbackAllowPorts @()
Assert-Eq $c.Severity "INFO" "listen 4096 is INFO"
Assert-True ($c.Label.StartsWith("INFO:")) "listen 4096 label is INFO"
Assert-True ($c.Label -match "loopback") "listen 4096 label says loopback"
Assert-Eq (@(Get-TcpAlertReasons -LocalAddress "127.0.0.1" -LocalPort 4096 -RemoteAddress "0.0.0.0" -RemotePort 0 -State "Listen" -LoopbackAllowPorts @())).Count 0 "listen 4096 is not an ALERT"

$c = Get-TcpWatchClassification -LocalAddress "0.0.0.0" -LocalPort 4096 -RemoteAddress "0.0.0.0" -RemotePort 0 -State "Listen" -LoopbackAllowPorts @()
Assert-Eq $c.Severity "ALERT" "wildcard listen 4096 is ALERT"
Assert-True ($c.Label -match "wildcard") "wildcard listen label says wildcard"

$c = Get-TcpWatchClassification -LocalAddress "192.168.1.10" -LocalPort 4096 -RemoteAddress "0.0.0.0" -RemotePort 0 -State "Listen" -LoopbackAllowPorts @()
Assert-Eq $c.Severity "ALERT" "public listen 4096 is ALERT"
Assert-True ($c.Label -match "public") "public listen label says public"

$c = Get-TcpWatchClassification -LocalAddress "0.0.0.0" -LocalPort 9222 -RemoteAddress "0.0.0.0" -RemotePort 0 -State "Listen" -LoopbackAllowPorts @()
Assert-Eq $c.Severity "ALERT" "listen 9222 is still ALERT"

# --- Self-loopback: only OpenCode-server pairs are quiet ---
$selfConns = @(
  [pscustomobject]@{ LocalAddress = "127.0.0.1"; LocalPort = 4096; RemoteAddress = "0.0.0.0"; RemotePort = 0; State = "Listen"; OwningProcess = 100 },
  [pscustomobject]@{ LocalAddress = "127.0.0.1"; LocalPort = 60110; RemoteAddress = "127.0.0.1"; RemotePort = 4096; State = "Established"; OwningProcess = 100 },
  [pscustomobject]@{ LocalAddress = "127.0.0.1"; LocalPort = 4096; RemoteAddress = "127.0.0.1"; RemotePort = 60110; State = "Established"; OwningProcess = 100 }
)
$idx = New-TcpPortOwnerIndex -Connections $selfConns -ProcessNames @{ 100 = "opencode.exe" }
$watched = @{ 100 = $true }

$selfFwd = Test-IsTcpSelfLoopback -LocalAddress "127.0.0.1" -LocalPort 60110 -RemoteAddress "127.0.0.1" -RemotePort 4096 -OwnerIndex $idx -WatchedPids $watched
$selfRev = Test-IsTcpSelfLoopback -LocalAddress "127.0.0.1" -LocalPort 4096 -RemoteAddress "127.0.0.1" -RemotePort 60110 -OwnerIndex $idx -WatchedPids $watched
Assert-True $selfFwd "60110 -> 4096 is self-loopback"
Assert-True $selfRev "4096 -> 60110 (reverse) is self-loopback"
Assert-True (Test-IsOpenCodeServerLoopback -LocalAddress "127.0.0.1" -LocalPort 60110 -RemoteAddress "127.0.0.1" -RemotePort 4096 -OwnerIndex $idx) "60110 -> 4096 is an OpenCode server pair"
Assert-True (Test-IsOpenCodeServerLoopback -LocalAddress "127.0.0.1" -LocalPort 4096 -RemoteAddress "127.0.0.1" -RemotePort 60110 -OwnerIndex $idx) "reverse row is an OpenCode server pair"

$c = Get-TcpWatchClassification -LocalAddress "127.0.0.1" -LocalPort 60110 -RemoteAddress "127.0.0.1" -RemotePort 4096 -State "Established" -LoopbackAllowPorts @() -IsSelfLoopback $true -IsOpenCodeServerLoopback $true -IgnoreSelfLoopback $true
Assert-Eq $c.Severity "" "OpenCode-server 60110 -> 4096 is quiet when ignoreSelfLoopback is true"
$c = Get-TcpWatchClassification -LocalAddress "127.0.0.1" -LocalPort 4096 -RemoteAddress "127.0.0.1" -RemotePort 60110 -State "Established" -LoopbackAllowPorts @() -IsSelfLoopback $true -IsOpenCodeServerLoopback $true -IgnoreSelfLoopback $true
Assert-Eq $c.Severity "" "OpenCode-server reverse 4096 -> 60110 is quiet when ignoreSelfLoopback is true"

$c = Get-TcpWatchClassification -LocalAddress "127.0.0.1" -LocalPort 60110 -RemoteAddress "127.0.0.1" -RemotePort 4096 -State "Established" -LoopbackAllowPorts @() -IsSelfLoopback $true -IsOpenCodeServerLoopback $false -IgnoreSelfLoopback $true
Assert-Eq $c.Severity "INFO" "other self-loopback is INFO when ignoreSelfLoopback is true"
Assert-True ($c.Label.StartsWith("INFO:")) "other self-loopback label is INFO"

$c = Get-TcpWatchClassification -LocalAddress "127.0.0.1" -LocalPort 60110 -RemoteAddress "127.0.0.1" -RemotePort 4096 -State "Established" -LoopbackAllowPorts @() -IsSelfLoopback $true -IsOpenCodeServerLoopback $true -IgnoreSelfLoopback $false
Assert-Eq $c.Severity "ALERT" "self 60110 -> 4096 ALERTs when ignoreSelfLoopback is false"

# descendant peer (client pid 200, server pid 100, both watched)
$treeConns = @(
  [pscustomobject]@{ LocalAddress = "127.0.0.1"; LocalPort = 4096; RemoteAddress = "0.0.0.0"; RemotePort = 0; State = "Listen"; OwningProcess = 100 },
  [pscustomobject]@{ LocalAddress = "127.0.0.1"; LocalPort = 60111; RemoteAddress = "127.0.0.1"; RemotePort = 4096; State = "Established"; OwningProcess = 200 }
)
$treeIdx = New-TcpPortOwnerIndex -Connections $treeConns -ProcessNames @{ 100 = "opencode.exe"; 200 = "node.exe" }
$treeWatched = @{ 100 = $true; 200 = $true }
Assert-True (Test-IsTcpSelfLoopback -LocalAddress "127.0.0.1" -LocalPort 60111 -RemoteAddress "127.0.0.1" -RemotePort 4096 -OwnerIndex $treeIdx -WatchedPids $treeWatched) "descendant talking to watched parent is self-loopback"
Assert-True (Test-IsOpenCodeServerLoopback -LocalAddress "127.0.0.1" -LocalPort 60111 -RemoteAddress "127.0.0.1" -RemotePort 4096 -OwnerIndex $treeIdx) "descendant to opencode listen is an OpenCode server pair"
$outside = @{ 200 = $true }
Assert-True (-not (Test-IsTcpSelfLoopback -LocalAddress "127.0.0.1" -LocalPort 60111 -RemoteAddress "127.0.0.1" -RemotePort 4096 -OwnerIndex $treeIdx -WatchedPids $outside)) "peer not in the watched tree is not self-loopback"

# Listen on 0.0.0.0:4096 still matches a connect to 127.0.0.1:4096
$unspec = @(
  [pscustomobject]@{ LocalAddress = "0.0.0.0"; LocalPort = 4096; RemoteAddress = "0.0.0.0"; RemotePort = 0; State = "Listen"; OwningProcess = 100 },
  [pscustomobject]@{ LocalAddress = "127.0.0.1"; LocalPort = 60110; RemoteAddress = "127.0.0.1"; RemotePort = 4096; State = "Established"; OwningProcess = 100 }
)
$uIdx = New-TcpPortOwnerIndex -Connections $unspec -ProcessNames @{ 100 = "opencode.exe" }
Assert-True (Test-IsTcpSelfLoopback -LocalAddress "127.0.0.1" -LocalPort 60110 -RemoteAddress "127.0.0.1" -RemotePort 4096 -OwnerIndex $uIdx -WatchedPids $watched) "connect to 127.0.0.1:4096 matches a 0.0.0.0:4096 listen"
Assert-True (Test-IsOpenCodeServerLoopback -LocalAddress "127.0.0.1" -LocalPort 60110 -RemoteAddress "127.0.0.1" -RemotePort 4096 -OwnerIndex $uIdx) "0.0.0.0 opencode listen is still an OpenCode server pair"

# A watched node listening on a local port is NOT an OpenCode server pair
$nodeConns = @(
  [pscustomobject]@{ LocalAddress = "127.0.0.1"; LocalPort = 3000; RemoteAddress = "0.0.0.0"; RemotePort = 0; State = "Listen"; OwningProcess = 300 },
  [pscustomobject]@{ LocalAddress = "127.0.0.1"; LocalPort  = 60112; RemoteAddress = "127.0.0.1"; RemotePort = 3000; State = "Established"; OwningProcess = 301 }
)
$nIdx = New-TcpPortOwnerIndex -Connections $nodeConns -ProcessNames @{ 300 = "node.exe"; 301 = "node.exe" }
Assert-True (Test-IsTcpSelfLoopback -LocalAddress "127.0.0.1" -LocalPort 60112 -RemoteAddress "127.0.0.1" -RemotePort 3000 -OwnerIndex $nIdx -WatchedPids @{ 300 = $true; 301 = $true }) "node-to-node is self-loopback"
Assert-True (-not (Test-IsOpenCodeServerLoopback -LocalAddress "127.0.0.1" -LocalPort 60112 -RemoteAddress "127.0.0.1" -RemotePort 3000 -OwnerIndex $nIdx)) "node-to-node is not an OpenCode server pair"

# Debug ports always ALERT, even when self or allowlisted
$c = Get-TcpWatchClassification -LocalAddress "127.0.0.1" -LocalPort 60110 -RemoteAddress "127.0.0.1" -RemotePort 9222 -State "Established" -LoopbackAllowPorts @(9222) -IsSelfLoopback $true -IgnoreSelfLoopback $true
Assert-Eq $c.Severity "ALERT" "9222 ALERTs even when self-loopback and allowlisted"
$c = Get-TcpWatchClassification -LocalAddress "127.0.0.1" -LocalPort 9239 -RemoteAddress "127.0.0.1" -RemotePort 60110 -State "Established" -LoopbackAllowPorts @() -IsSelfLoopback $true -IgnoreSelfLoopback $true
Assert-Eq $c.Severity "ALERT" "reverse row with local 9239 still ALERTs"

# Either end allowlisted counts as allowed (so the reverse row is quiet)
$c = Get-TcpWatchClassification -LocalAddress "127.0.0.1" -LocalPort 60110 -RemoteAddress "127.0.0.1" -RemotePort 4096 -State "Established" -LoopbackAllowPorts @(4096) -IsSelfLoopback $false -IgnoreSelfLoopback $true
Assert-Eq $c.Severity "" "allowlisted destination 4096 is quiet"
$c = Get-TcpWatchClassification -LocalAddress "127.0.0.1" -LocalPort 4096 -RemoteAddress "127.0.0.1" -RemotePort 60110 -State "Established" -LoopbackAllowPorts @(4096) -IsSelfLoopback $false -IgnoreSelfLoopback $true
Assert-Eq $c.Severity "" "reverse row is quiet when the other end (4096) is allowlisted"
$c = Get-TcpWatchClassification -LocalAddress "127.0.0.1" -LocalPort 60110 -RemoteAddress "127.0.0.1" -RemotePort 9999 -State "Established" -LoopbackAllowPorts @(4096) -IsSelfLoopback $false
Assert-Eq $c.Severity "ALERT" "unrelated loopback dest still ALERTs when not allowlisted"


# --- secret-path patterns ignore the process image / argv[0] ---
$grokImg = "C:\Users\user\.grok\bin\grok.exe"
Assert-Eq (Get-CommandLineArgumentText -CommandLine $grokImg) "" "argv[0] only is empty arguments"
Assert-Eq (Get-CommandLineArgumentText -CommandLine ('"' + $grokImg + '"')) "" "quoted argv[0] only is empty arguments"
Assert-Eq (Get-CommandLineArgumentText -CommandLine ($grokImg + " serve") -Image $grokImg) "serve" "arguments after image path"
Assert-NoAlert $grokImg "no alert for grok.exe whose path contains .grok"
Assert-NoAlert ('"' + $grokImg + '"') "no alert for quoted grok.exe path"
$r = @(Get-CommandLineAlertReasons -CommandLine ($grokImg + " serve") -Image $grokImg)
Assert-True ($r.Count -eq 0) "no alert when .grok is only in the image path" ($r -join "; ")
$r = @(Get-CommandLineAlertReasons -CommandLine ($grokImg + " C:\Users\user\.grok\config.toml") -Image $grokImg)
Assert-True (($r -join "; ") -match "\.grok") "alert when an argument is under .grok" ($r -join "; ")
Assert-Alert "type %USERPROFILE%\.grok\secrets" ".grok" "alert when .grok is in the arguments"
Assert-NoAlert "C:\Users\user\.env\bin\tool.exe" "no alert for .env only in the image path"
Assert-Alert "type C:\proj\.env" ".env" "alert when .env is in the arguments"

# --- Sysmon Event 3: OpenCode self-loopback is INFO; debug still ALERT ---
$ocImg = "C:\Program Files\opencode\opencode.exe"
$ports = New-OpenCodeListenPortSet
Assert-True ($ports.ContainsKey(4096) -or $ports.Contains(4096)) "default listen set includes 4096"
Add-OpenCodeListenPortFromSysmonNetwork -Image $ocImg -DestinationIp "127.0.0.1" -DestinationPort 5555 -Initiated "true" -PortSet $ports
Assert-True (-not ($ports.ContainsKey(5555) -or $ports.Contains(5555))) "initiated=true does not add a listen port"
Add-OpenCodeListenPortFromSysmonNetwork -Image $ocImg -DestinationIp "127.0.0.1" -DestinationPort 5555 -Initiated "false" -PortSet $ports
Assert-True ($ports.ContainsKey(5555) -or $ports.Contains(5555)) "initiated=false loopback opencode dest is a listen port"
Add-OpenCodeListenPortFromSysmonNetwork -Image "C:\Windows\System32\node.exe" -DestinationIp "127.0.0.1" -DestinationPort 6000 -Initiated "false" -PortSet $ports
Assert-True (-not ($ports.ContainsKey(6000) -or $ports.Contains(6000))) "non-opencode image does not add a listen port"

$c = Get-SysmonNetworkClassification -Image $ocImg -SourceIp "127.0.0.1" -SourcePort 60110 -DestinationIp "127.0.0.1" -DestinationPort 4096 -OpenCodeListenPorts $ports -LoopbackAllowPorts @() -IgnoreSelfLoopback $true
Assert-Eq $c.Severity "INFO" "opencode 60110 -> 4096 is INFO when ignoreSelfLoopback is true"
Assert-True ($c.Label.StartsWith("INFO:")) "opencode 4096 self-talk label is INFO"
$c = Get-SysmonNetworkClassification -Image $ocImg -SourceIp "127.0.0.1" -SourcePort 60110 -DestinationIp "127.0.0.1" -DestinationPort 4096 -OpenCodeListenPorts $ports -LoopbackAllowPorts @() -IgnoreSelfLoopback $false
Assert-Eq $c.Severity "ALERT" "opencode 60110 -> 4096 ALERTs when ignoreSelfLoopback is false"
$c = Get-SysmonNetworkClassification -Image $ocImg -SourceIp "127.0.0.1" -SourcePort 4096 -DestinationIp "127.0.0.1" -DestinationPort 60110 -OpenCodeListenPorts $ports -LoopbackAllowPorts @() -IgnoreSelfLoopback $true
Assert-Eq $c.Severity "INFO" "reverse opencode 4096 -> 60110 is INFO"
$c = Get-SysmonNetworkClassification -Image $ocImg -SourceIp "127.0.0.1" -SourcePort 60111 -DestinationIp "127.0.0.1" -DestinationPort 5555 -OpenCodeListenPorts $ports -LoopbackAllowPorts @() -IgnoreSelfLoopback $true
Assert-Eq $c.Severity "INFO" "opencode connect to a discovered listen port is INFO"
$c = Get-SysmonNetworkClassification -Image $ocImg -SourceIp "127.0.0.1" -SourcePort 60110 -DestinationIp "127.0.0.1" -DestinationPort 9222 -OpenCodeListenPorts $ports -LoopbackAllowPorts @() -IgnoreSelfLoopback $true
Assert-Eq $c.Severity "ALERT" "debug port 9222 still ALERTs for opencode self-loopback"
$c = Get-SysmonNetworkClassification -Image "C:\Program Files\nodejs\node.exe" -SourceIp "127.0.0.1" -SourcePort 60110 -DestinationIp "127.0.0.1" -DestinationPort 4096 -OpenCodeListenPorts $ports -LoopbackAllowPorts @() -IgnoreSelfLoopback $true
Assert-Eq $c.Severity "ALERT" "node talking to 4096 is still ALERT"
$c = Get-SysmonNetworkClassification -Image $ocImg -SourceIp "127.0.0.1" -SourcePort 60110 -DestinationIp "127.0.0.1" -DestinationPort 9999 -OpenCodeListenPorts $ports -LoopbackAllowPorts @() -IgnoreSelfLoopback $true
Assert-Eq $c.Severity "ALERT" "opencode loopback to an unknown port is still ALERT"

# --- identical summary rows are omitted ---
$lines = New-Object System.Collections.Generic.List[string]
$seen = @{}
$row = "- 2026-11-20 05:00:00 -05:00 pid=100 image=C:\opencode.exe 127.0.0.1:60110 -> 127.0.0.1:4096"
Assert-True (Add-UniqueLogLine -List $lines -Seen $seen -Line $row) "first identical row is kept"
Assert-True (-not (Add-UniqueLogLine -List $lines -Seen $seen -Line $row)) "duplicate identical row is omitted"
Assert-Eq $lines.Count 1 "dedupe keeps a single copy"

Write-Host ""
Write-Host ("Redaction/alert tests: {0} passed, {1} failed" -f $passed, $failed)
if ($failed -gt 0) { exit 1 }
exit 0
