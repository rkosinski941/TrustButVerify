# test-sysmon-task.ps1
# Checks that the nightly Sysmon summary is planned as RunLevel Limited,
# that Event Log Readers / channel ACL SDDL is built correctly, that
# ownership/takeover rules refuse an unowned Sysmon, and that
# register-nightly-summary.ps1 -DryRun and install-sysmon.ps1 -DryRun
# print the plan without making changes.
# Run from the kit root:
#   pwsh -NoProfile -File tests/test-sysmon-task.ps1

Set-StrictMode -Version 1
$ErrorActionPreference = "Stop"
$global:LASTEXITCODE = 0

$kit = Split-Path -Parent $PSScriptRoot
. (Join-Path $kit "lib\WatchCommon.ps1")
. (Join-Path $kit "lib\SysmonOwnership.ps1")

$failed = 0
$passed = 0

function Assert-True {
  param([bool]$Cond, [string]$Name, [string]$Detail = "")
  if ($Cond) {
    $script:passed++
    Write-Host ("PASS  {0}" -f $Name)
  } else {
    $script:failed++
    Write-Host ("FAIL  {0}" -f $Name)
    if ($Detail) { Write-Host ("      {0}" -f $Detail) }
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

$plan = Get-SysmonSummaryTaskPlan
Assert-Eq $plan.RunLevel "Limited" "task plan RunLevel is Limited"
Assert-Eq $plan.RequiresAdmin $false "task plan does not require an elevated task"
Assert-Eq $plan.TaskName "OpenCodeWatch-SysmonSummary" "default task name"
Assert-True ($plan.LogReadMethod -match "Event Log Readers") "task plan mentions Event Log Readers" $plan.LogReadMethod

$plan2 = Get-SysmonSummaryTaskPlan -TaskName "DemoTask" -TimeOfDay "04:15" -LastHours 12
Assert-Eq $plan2.TaskName "DemoTask" "custom task name"
Assert-Eq $plan2.TimeOfDay "04:15" "custom time of day"
Assert-Eq $plan2.LastHours 12 "custom last hours"
Assert-Eq $plan2.RunLevel "Limited" "custom plan is still Limited"

Assert-True (Test-IsSysmonLogAccessError "Attempted to perform an unauthorized operation") "unauthorized operation is an access error"
Assert-True (Test-IsSysmonLogAccessError "Access is denied") "access is denied is an access error"
Assert-True (-not (Test-IsSysmonLogAccessError "No events found")) "no-events is not an access error"

$adminMsg = Get-SysmonLogAdminMessage
Assert-True ($adminMsg -match 'needs permission to read Sysmon log|needs admin to read Sysmon log') "access message is clear" $adminMsg
Assert-True ($adminMsg -match 'Event Log Readers') "access message mentions Event Log Readers" $adminMsg

$regSrc = [System.IO.File]::ReadAllText((Join-Path $kit "register-nightly-summary.ps1"))
Assert-True ($regSrc -match 'RunLevel Limited') "register script uses RunLevel Limited"
Assert-True ($regSrc -match '/RL", "LIMITED"') "schtasks fallback uses /RL LIMITED"
Assert-True ($regSrc -notmatch 'RunLevel Highest') "register script never uses RunLevel Highest"
Assert-True ($regSrc -match '\[switch\]\$DryRun') "register script has a -DryRun switch"

# Channel ACL / SDDL
Assert-Eq (Get-EventLogReadersSid) "S-1-5-32-573" "Event Log Readers SID"
$ace = New-EventLogReadAce -Sid (Get-EventLogReadersSid)
Assert-Eq $ace "(A;;0x1;;;S-1-5-32-573)" "Event Log Readers read ACE"
$sample = "O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)"
$built = Build-SysmonChannelAccessSddl -CurrentSddl $sample -UserSid "S-1-5-21-100-200-300-400"
Assert-True $built.Changed "SDDL plan changes a default DACL"
Assert-True ($built.Sddl -match [regex]::Escape("(A;;0x1;;;S-1-5-32-573)")) "SDDL adds Event Log Readers"
Assert-True ($built.Sddl -match [regex]::Escape("(A;;0x1;;;S-1-5-21-100-200-300-400)")) "SDDL adds the user SID"
$again = Build-SysmonChannelAccessSddl -CurrentSddl $built.Sddl -UserSid "S-1-5-21-100-200-300-400"
Assert-True (-not $again.Changed) "SDDL plan is idempotent"
$withSacl = Add-SddlAceIfMissing -Sddl "O:BAG:SYD:(A;;0x7;;;BA)S:(NL;;;AN)" -Ace "(A;;0x1;;;S-1-5-32-573)"
Assert-True ($withSacl.Sddl.Contains("S:(NL;;;AN)")) "SDDL insert keeps a trailing SACL"
Assert-True ($withSacl.Sddl.Contains("(A;;0x1;;;S-1-5-32-573)S:")) "read ACE is inserted before the SACL"
$gl = "name: Microsoft-Windows-Sysmon/Operational`nchannelAccess: O:BAG:SYD:(A;;0x7;;;BA)`n"
Assert-Eq (Get-ChannelAccessFromWevtutil -Text $gl) "O:BAG:SYD:(A;;0x7;;;BA)" "wevtutil parser reads channelAccess"

# Ownership plans
$fresh = Get-TbvSysmonInstallPlan -AlreadyInstalled $false -HasOwnershipMarker $false
Assert-Eq $fresh.Action "install-fresh" "no Sysmon: install fresh"
Assert-True $fresh.Allowed "fresh install is allowed"
Assert-Eq $fresh.RunLevelForTask "Limited" "install plan nightly task is Limited"

$refuse = Get-TbvSysmonInstallPlan -AlreadyInstalled $true -HasOwnershipMarker $false
Assert-Eq $refuse.Action "refuse" "existing unowned Sysmon is refused"
Assert-True (-not $refuse.Allowed) "unowned takeover without flags is not allowed"

$noXml = Get-TbvSysmonInstallPlan -AlreadyInstalled $true -HasOwnershipMarker $false -TakeOverSysmon
Assert-Eq $noXml.Action "refuse" "takeover without ExistingConfigPath is refused"

$take = Get-TbvSysmonInstallPlan -AlreadyInstalled $true -HasOwnershipMarker $false -TakeOverSysmon -ExistingConfigPath "C:\configs\prior-sysmon.xml"
Assert-Eq $take.Action "takeover" "takeover with XML path is allowed"
Assert-True $take.NeedsConfigBackup "takeover requires a restorable backup"

$claim = Get-TbvSysmonInstallPlan -AlreadyInstalled $true -HasOwnershipMarker $false -ClaimFreshKitInstall
Assert-Eq $claim.Action "claim-fresh" "claim-fresh is allowed for a prior kit install"
Assert-Eq $claim.InstallKind "fresh" "claim-fresh records kind fresh"

$owned = Get-TbvSysmonInstallPlan -AlreadyInstalled $true -HasOwnershipMarker $true -InstallKind "fresh"
Assert-Eq $owned.Action "update-kit-owned" "kit-owned Sysmon can be updated"

$unRefuse = Get-TbvSysmonUninstallPlan -HasOwnershipMarker $false
Assert-True (-not $unRefuse.Allowed) "uninstall refuses unowned Sysmon"
Assert-Eq $unRefuse.Action "refuse" "uninstall unowned action is refuse"

$unFresh = Get-TbvSysmonUninstallPlan -HasOwnershipMarker $true -InstallKind "fresh"
Assert-Eq $unFresh.Action "uninstall" "uninstall kit-fresh removes Sysmon"

$unTake = Get-TbvSysmonUninstallPlan -HasOwnershipMarker $true -InstallKind "takeover"
Assert-Eq $unTake.Action "restore-previous" "uninstall takeover restores the previous config"

# Ownership marker + restorable XML copy (temp ProgramData)
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("tbv-own-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
$env:TBV_PROGRAMDATA = $tempRoot
Assert-True (-not (Test-TbvSysmonKitOwned)) "no marker yet"
$marker = Write-TbvSysmonOwnership -InstallKind "fresh" -ConfigSha256 "abc"
Assert-True (Test-Path -LiteralPath $marker) "ownership marker was written"
Assert-True (Test-TbvSysmonKitOwned) "marker is kit-owned"
$read = Read-TbvSysmonOwnership
Assert-Eq ([string]$read.installKind) "fresh" "marker installKind is fresh"
Assert-Eq ([string]$read.ownedBy) "TrustButVerify" "marker ownedBy is TrustButVerify"
Remove-TbvSysmonOwnership
Assert-True (-not (Test-TbvSysmonKitOwned)) "marker can be removed"

$xml = Join-Path $tempRoot "prior.xml"
[System.IO.File]::WriteAllText($xml, "<Sysmon schemaversion=`"4.90`"><EventFiltering></EventFiltering></Sysmon>")
Assert-True (Test-LooksLikeSysmonConfigXml -Path $xml) "sample file looks like Sysmon XML"
$txt = Join-Path $tempRoot "dump.txt"
[System.IO.File]::WriteAllText($txt, "Current configuration:`r`n- RuleGroup")
Assert-True (-not (Test-LooksLikeSysmonConfigXml -Path $txt)) "sysmon -c text dump is not restorable XML"
$copied = Copy-TbvRestorableSysmonConfig -ExistingConfigPath $xml
Assert-True (Test-Path -LiteralPath $copied) "restorable XML was copied"
Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item Env:TBV_PROGRAMDATA -ErrorAction SilentlyContinue

$reg = Join-Path $kit "register-nightly-summary.ps1"
$dryOut = & $reg -DryRun *>&1 | Out-String
$dryCode = $LASTEXITCODE
if ($null -eq $dryCode) { $dryCode = 0 }
Assert-Eq $dryCode 0 "register-nightly-summary.ps1 -DryRun exits 0"
Assert-True ($dryOut -match 'RunLevel: Limited') "dry-run prints RunLevel Limited" $dryOut
Assert-True ($dryOut -match 'Event Log Readers') "dry-run mentions Event Log Readers" $dryOut
Assert-True ($dryOut -match 'No task was created') "dry-run does not create a task" $dryOut

$inst = Join-Path $kit "install-sysmon.ps1"
$instOut = & $inst -DryRun *>&1 | Out-String
$instCode = $LASTEXITCODE
if ($null -eq $instCode) { $instCode = 0 }
Assert-Eq $instCode 0 "install-sysmon.ps1 -DryRun exits 0 when Sysmon is absent"
Assert-True ($instOut -match 'install-fresh|Would') "install dry-run prints a plan" $instOut
Assert-True ($instOut -match 'Limited') "install dry-run mentions Limited" $instOut
Assert-True ($instOut -match 'Event Log Readers') "install dry-run mentions Event Log Readers" $instOut
Assert-True ($instOut -match 'No Sysmon or ACL changes were made') "install dry-run makes no changes" $instOut

$un = Join-Path $kit "uninstall-sysmon.ps1"
$unOut = & $un -DryRun *>&1 | Out-String
# No marker: should exit 2 in DryRun
Assert-True ($unOut -match 'refuse|not marked|does not own|Allowed: False') "uninstall dry-run refuses unowned Sysmon" $unOut

Write-Host ""
Write-Host ("Sysmon task tests: {0} passed, {1} failed." -f $passed, $failed)
if ($failed -gt 0) { exit 1 }
exit 0
