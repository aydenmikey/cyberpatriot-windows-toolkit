# Original OKCUP Round 1 Windows 11 toolkit

This Markdown file contains the corresponding PowerShell script as a fenced code block for easy reading and versioning. To run the toolkit, use the `.ps1` file, not this `.md` file.

## Safety notes

- Read the CyberPatriot README and Desktop Forensics Questions before applying changes.
- Run in an elevated PowerShell session.
- Start in audit-only mode and review each finding.
- Use `-Apply` only after confirming that each proposed change matches the competition scenario.
- Keep the score engine and required services/apps intact. Do not remove authorized accounts or their home directories.
- The script has not been executed in a PowerShell environment as part of preparing this Markdown copy.

## Usage

Audit only:

```powershell
.\CyberPatriot-Toolkit-OKCUP-R1.ps1
```

Apply supported remediations with confirmation prompts:

```powershell
.\CyberPatriot-Toolkit-OKCUP-R1.ps1 -Apply
```

Force audit-only behavior even when `-Apply` is supplied:

```powershell
.\CyberPatriot-Toolkit-OKCUP-R1.ps1 -Apply -CheckOnly
```

## PowerShell source

```powershell
# CyberPatriot Windows 11 Toolkit - OKCUP Round 1 additions
# Default mode is AUDIT ONLY. Run in an elevated PowerShell window.
# Review the Desktop Forensics Questions BEFORE using -Apply.
# This script never edits/deletes the forensics question files and never stops ScoreEngine.
# Destructive removals require explicit confirmation. Check every result against the current README.
#
# Audit:
#   .\CyberPatriot-Toolkit-OKCUP-R1.ps1
# Apply selected settings and prompt for requested removals/password change:
#   .\CyberPatriot-Toolkit-OKCUP-R1.ps1 -Apply
# Audit only even if -Apply is present:
#   .\CyberPatriot-Toolkit-OKCUP-R1.ps1 -Apply -CheckOnly

[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Continue'
$script:Results = [System.Collections.Generic.List[object]]::new()
$script:DoApply = $Apply -and -not $CheckOnly

function Add-Result {
    param([string]$Name, [string]$Status, [string]$Details)
    $script:Results.Add([pscustomobject]@{ Check = $Name; Status = $Status; Details = $Details })
    Write-Host ("[{0}] {1} - {2}" -f $Status, $Name, $Details)
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Confirm-Action {
    param([string]$Prompt, [string]$Expected = 'YES')
    $answer = Read-Host "$Prompt Type $Expected to confirm"
    return $answer -ceq $Expected
}

function Get-InstalledApp {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($path in $paths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, QuietUninstallString
    }
}

function Get-PolicyExport {
    $cfg = Join-Path $env:TEMP ("cp-policy-{0}.cfg" -f [guid]::NewGuid().ToString('N'))
    & secedit.exe /export /cfg $cfg /areas SECURITYPOLICY /quiet 2>$null | Out-Null
    if (Test-Path -LiteralPath $cfg) {
        return [pscustomobject]@{ Path = $cfg; Content = Get-Content -LiteralPath $cfg -ErrorAction SilentlyContinue }
    }
    return $null
}

function Set-LocalSecurityPolicies {
    Write-Host "`n--- Password complexity and administrator lockout policy ---" -ForegroundColor Cyan
    $policy = Get-PolicyExport
    if ($policy) {
        foreach ($entry in @(@{Key='PasswordComplexity'; Label='Password complexity'}, @{Key='AllowAdministratorLockout'; Label='Administrator account lockout'})) {
            $line = $policy.Content | Where-Object { $_ -match ( '^\s*' + $entry.Key + '\s*=' ) } | Select-Object -First 1
            if ($line) {
                $value = ($line -split '=', 2)[1].Trim()
                if ($value -eq '1') { Add-Result $entry.Label 'PASS' "Exported policy $($entry.Key)=1." }
                elseif ($script:DoApply) {
                    $inf = Join-Path $env:TEMP ("cp-apply-{0}.inf" -f [guid]::NewGuid().ToString('N'))
                    $db = Join-Path $env:TEMP ("cp-apply-{0}.sdb" -f [guid]::NewGuid().ToString('N'))
                    @('[Unicode]','Unicode=yes','[Version]','signature="$CHICAGO$"','Revision=1','[System Access]',"$($entry.Key) = 1") | Set-Content -LiteralPath $inf -Encoding Unicode
                    & secedit.exe /configure /db $db /cfg $inf /areas SECURITYPOLICY /quiet 2>$null | Out-Null
                    $verify = Get-PolicyExport
                    $verifyLine = if ($verify) { $verify.Content | Where-Object { $_ -match ( '^\s*' + $entry.Key + '\s*=' ) } | Select-Object -First 1 } else { $null }
                    if ($verifyLine -and (($verifyLine -split '=', 2)[1].Trim() -eq '1')) { Add-Result $entry.Label 'FIXED' "Set $($entry.Key)=1 and verified by policy export." }
                    else { Add-Result $entry.Label 'MANUAL' "Attempted to set $($entry.Key)=1; verify in secpol.msc because this Windows build may not expose this policy." }
                    if ($verify) { Remove-Item -LiteralPath $verify.Path -Force -ErrorAction SilentlyContinue }
                    Remove-Item -LiteralPath $inf,$db -Force -ErrorAction SilentlyContinue
                } else { Add-Result $entry.Label 'CHECK' "Exported policy $($entry.Key)=$value; expected 1." }
            } elseif ($script:DoApply) {
                $inf = Join-Path $env:TEMP ("cp-apply-{0}.inf" -f [guid]::NewGuid().ToString('N'))
                $db = Join-Path $env:TEMP ("cp-apply-{0}.sdb" -f [guid]::NewGuid().ToString('N'))
                @('[Unicode]','Unicode=yes','[Version]','signature="$CHICAGO$"','Revision=1','[System Access]',"$($entry.Key) = 1") | Set-Content -LiteralPath $inf -Encoding Unicode
                & secedit.exe /configure /db $db /cfg $inf /areas SECURITYPOLICY /quiet 2>$null | Out-Null
                Add-Result $entry.Label 'ATTEMPTED' "Submitted $($entry.Key)=1 to secedit; verify manually in secpol.msc."
                Remove-Item -LiteralPath $inf,$db -Force -ErrorAction SilentlyContinue
            } else { Add-Result $entry.Label 'MANUAL' "Could not find $($entry.Key) in the policy export. Inspect Local Security Policy manually." }
        }
        Remove-Item -LiteralPath $policy.Path -Force -ErrorAction SilentlyContinue
    } else {
        Add-Result 'Password complexity and administrator lockout' 'MANUAL' 'Could not export local security policy. Inspect secpol.msc > Account Policies.'
    }
}

function Set-CtrlAltDeletePolicy {
    Write-Host "`n--- Secure sign-in (CTRL+ALT+DEL) ---" -ForegroundColor Cyan
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    try { $value = (Get-ItemProperty -Path $path -Name DisableCAD -ErrorAction Stop).DisableCAD } catch { $value = $null }
    if ($value -eq 0) { Add-Result 'Require CTRL+ALT+DEL' 'PASS' 'DisableCAD=0, so secure sign-in is required.'; return }
    if ($script:DoApply) {
        try {
            if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
            New-ItemProperty -Path $path -Name DisableCAD -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            Add-Result 'Require CTRL+ALT+DEL' 'FIXED' 'Set DisableCAD=0.'
        } catch { Add-Result 'Require CTRL+ALT+DEL' 'ERROR' $_.Exception.Message }
    } else { Add-Result 'Require CTRL+ALT+DEL' 'CHECK' "DisableCAD is currently $value (missing is treated as not explicitly configured). Expected 0." }
}

function Set-FirewallProfiles {
    Write-Host "`n--- Windows Firewall ---" -ForegroundColor Cyan
    try {
        $profiles = Get-NetFirewallProfile -Profile Domain,Private,Public -ErrorAction Stop
        foreach ($profile in $profiles) {
            if ($profile.Enabled) { Add-Result "Firewall $($profile.Name)" 'PASS' 'Enabled.' }
            elseif ($script:DoApply) {
                try { Set-NetFirewallProfile -Profile $profile.Name -Enabled True -ErrorAction Stop; Add-Result "Firewall $($profile.Name)" 'FIXED' 'Enabled.' }
                catch { Add-Result "Firewall $($profile.Name)" 'ERROR' $_.Exception.Message }
            } else { Add-Result "Firewall $($profile.Name)" 'CHECK' 'Disabled; expected enabled.' }
        }
    } catch { Add-Result 'Windows Firewall' 'ERROR' $_.Exception.Message }
}

function Set-RemoteAssistance {
    Write-Host "`n--- Remote Assistance ---" -ForegroundColor Cyan
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
    try { $value = (Get-ItemProperty -Path $path -Name fAllowToGetHelp -ErrorAction Stop).fAllowToGetHelp } catch { $value = $null }
    if ($value -eq 0) { Add-Result 'Remote Assistance' 'PASS' 'Incoming Remote Assistance is disabled.'; return }
    if ($script:DoApply) {
        try {
            if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
            New-ItemProperty -Path $path -Name fAllowToGetHelp -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            Add-Result 'Remote Assistance' 'FIXED' 'Set fAllowToGetHelp=0.'
        } catch { Add-Result 'Remote Assistance' 'ERROR' $_.Exception.Message }
    } else { Add-Result 'Remote Assistance' 'CHECK' "fAllowToGetHelp is $value or missing; expected 0." }
}

function Set-RemoteRegistry {
    Write-Host "`n--- Remote Registry service ---" -ForegroundColor Cyan
    $svc = Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue
    if (-not $svc) { Add-Result 'Remote Registry' 'PASS' 'Service is not present.'; return }
    $start = (Get-CimInstance Win32_Service -Filter "Name='RemoteRegistry'" -ErrorAction SilentlyContinue).StartMode
    if ($svc.Status -ne 'Running' -and $start -eq 'Disabled') { Add-Result 'Remote Registry' 'PASS' 'Stopped and disabled.'; return }
    if ($script:DoApply) {
        try {
            if ($svc.Status -eq 'Running') { Stop-Service -Name RemoteRegistry -Force -ErrorAction Stop }
            Set-Service -Name RemoteRegistry -StartupType Disabled -ErrorAction Stop
            Add-Result 'Remote Registry' 'FIXED' 'Stopped if running and disabled startup.'
        } catch { Add-Result 'Remote Registry' 'ERROR' $_.Exception.Message }
    } else { Add-Result 'Remote Registry' 'CHECK' "Status=$($svc.Status), startup=$start; expected stopped and disabled." }
}

function Set-ActionCenter {
    Write-Host "`n--- Action Center / notifications ---" -ForegroundColor Cyan
    $paths = @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer','HKCU:\Software\Policies\Microsoft\Windows\Explorer')
    $bad = @()
    foreach ($path in $paths) {
        try { $v = (Get-ItemProperty -Path $path -Name DisableNotificationCenter -ErrorAction Stop).DisableNotificationCenter; if ($v -eq 1) { $bad += $path } } catch { }
    }
    if ($bad.Count -eq 0) { Add-Result 'Action Center' 'PASS' 'No policy disabling the notification center was found in the checked policy locations.'; return }
    if ($script:DoApply) {
        foreach ($path in $bad) {
            try { Set-ItemProperty -Path $path -Name DisableNotificationCenter -Value 0 -ErrorAction Stop }
            catch { Add-Result 'Action Center' 'ERROR' "Could not update $path : $($_.Exception.Message)" }
        }
        Add-Result 'Action Center' 'FIXED' 'Set DisableNotificationCenter=0 where the policy value was found disabled.'
    } else { Add-Result 'Action Center' 'CHECK' ('Notification Center is disabled by policy at: ' + ($bad -join '; ')) }
}

function Check-RdpAndScoreEngine {
    Write-Host "`n--- Required services: Remote Desktop and ScoreEngine ---" -ForegroundColor Cyan
    $rdp = Get-CimInstance Win32_Service -Filter "Name='TermService'" -ErrorAction SilentlyContinue
    if (-not $rdp) { Add-Result 'Remote Desktop service' 'MANUAL' 'TermService not found; verify this is the expected Windows image.' }
    elseif ($rdp.StartMode -eq 'Disabled') {
        if ($script:DoApply) { try { Set-Service -Name TermService -StartupType Manual -ErrorAction Stop; Add-Result 'Remote Desktop service' 'FIXED' 'Changed startup from Disabled to Manual so Windows can start the service when needed.' } catch { Add-Result 'Remote Desktop service' 'ERROR' $_.Exception.Message } }
        else { Add-Result 'Remote Desktop service' 'CHECK' 'TermService is disabled. README says Remote Desktop is critical; do not disable it.' }
    } else { Add-Result 'Remote Desktop service' 'PASS' "TermService startup is $($rdp.StartMode); left unchanged." }
    $score = Get-Service -Name ScoreEngine -ErrorAction SilentlyContinue
    if ($score) { Add-Result 'ScoreEngine' 'INFO' "Current status is $($score.Status); script deliberately does not stop or disable it." }
    else { Add-Result 'ScoreEngine' 'MANUAL' 'ScoreEngine service was not found by this name. Do not stop or disable the competition score engine/process.' }
}

function Set-ArcadePasswordExpiry {
    Write-Host "`n--- Arcade password expiration ---" -ForegroundColor Cyan
    try {
        $user = Get-LocalUser -Name 'arcade' -ErrorAction Stop
        if (-not $user.PasswordNeverExpires) { Add-Result 'arcade password expires' 'PASS' 'PasswordNeverExpires is false.'; return }
        if ($script:DoApply) {
            Set-LocalUser -Name 'arcade' -PasswordNeverExpires $false -ErrorAction Stop
            Add-Result 'arcade password expires' 'FIXED' 'Set PasswordNeverExpires to false.'
        } else { Add-Result 'arcade password expires' 'CHECK' 'PasswordNeverExpires is true; expected false.' }
    } catch { Add-Result 'arcade password expires' 'ERROR' $_.Exception.Message }
}

function Set-BennyPassword {
    Write-Host "`n--- Benny password ---" -ForegroundColor Cyan
    try { $null = Get-LocalUser -Name 'benny' -ErrorAction Stop } catch { Add-Result 'benny password' 'ERROR' 'Local account benny was not found.'; return }
    if (-not $script:DoApply) { Add-Result 'benny password' 'MANUAL' 'When applying, enter the approved password from the round README at the secure prompt; it is never stored in this script.'; return }
    if (-not (Confirm-Action 'Change benny password to the password specified by the round README?' 'YES')) { Add-Result 'benny password' 'SKIPPED' 'Password change declined.'; return }
    try {
        $secure = Read-Host 'Enter the required benny password from the README' -AsSecureString
        Set-LocalUser -Name 'benny' -Password $secure -ErrorAction Stop
        Add-Result 'benny password' 'FIXED' 'Submitted the new password for benny. Verify against the round requirements.'
    } catch { Add-Result 'benny password' 'ERROR' $_.Exception.Message }
}

function Set-ExpectedUserRoles {
    Write-Host "`n--- User auditing ---" -ForegroundColor Cyan
    foreach ($name in @('boone','veronica')) {
        try {
            $members = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Where-Object { $_.Name -match ('\\' + [regex]::Escape($name) + '$') -or $_.Name -eq $name })
            if ($members.Count -eq 0) { Add-Result "$name is not an administrator" 'PASS' 'Not found in local Administrators group.' }
            elseif ($script:DoApply) {
                try { Remove-LocalGroupMember -Group 'Administrators' -Member $members[0].Name -Confirm:$false -ErrorAction Stop; Add-Result "$name is not an administrator" 'FIXED' 'Removed from local Administrators group; account remains.' }
                catch { Add-Result "$name is not an administrator" 'ERROR' $_.Exception.Message }
            } else { Add-Result "$name is not an administrator" 'CHECK' 'Found in local Administrators group.' }
        } catch { Add-Result "$name is not an administrator" 'MANUAL' $_.Exception.Message }
    }

    foreach ($name in @('legate','cookcook')) {
        try { $user = Get-LocalUser -Name $name -ErrorAction Stop }
        catch { Add-Result "Unauthorized user $name" 'PASS' 'Account not found.'; continue }
        if (-not $script:DoApply) { Add-Result "Unauthorized user $name" 'CHECK' 'Account exists. Apply mode will ask before removing the account.'; continue }
        if (Confirm-Action "Remove unauthorized local account '$name'? This removes the account, not its profile folder." 'REMOVE') {
            try { Remove-LocalUser -Name $name -ErrorAction Stop; Add-Result "Unauthorized user $name" 'FIXED' 'Removed local account; profile/home folder was not explicitly deleted.' }
            catch { Add-Result "Unauthorized user $name" 'ERROR' $_.Exception.Message }
        } else { Add-Result "Unauthorized user $name" 'SKIPPED' 'Account removal declined.' }
    }
}

function Remove-TargetMp3 {
    Write-Host "`n--- Prohibited MP3 file ---" -ForegroundColor Cyan
    $file = 'C:\Users\courier\Music\*.mp3'
    $items = @(Get-ChildItem -Path $file -File -ErrorAction SilentlyContinue)
    if ($items.Count -eq 0) { Add-Result 'Prohibited MP3 in courier Music' 'PASS' 'No .mp3 files found at the specified path.'; return }
    foreach ($item in $items) {
        if ($script:DoApply -and (Confirm-Action "Delete prohibited file $($item.FullName)?" 'DELETE')) {
            try { Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop; Add-Result 'Prohibited MP3 in courier Music' 'FIXED' "Deleted $($item.Name)." }
            catch { Add-Result 'Prohibited MP3 in courier Music' 'ERROR' $_.Exception.Message }
        } elseif ($script:DoApply) { Add-Result 'Prohibited MP3 in courier Music' 'SKIPPED' "Kept $($item.FullName)." }
        else { Add-Result 'Prohibited MP3 in courier Music' 'CHECK' "Found $($item.FullName)." }
    }
}

function Invoke-AppRemoval {
    param([string]$DisplayNameRegex, [string]$Label, [string]$WingetName)
    $apps = @(Get-InstalledApp | Where-Object { $_.DisplayName -match $DisplayNameRegex })
    if ($apps.Count -eq 0) { Add-Result $Label 'PASS' 'No matching installed application was found.'; return }
    foreach ($app in $apps) { Write-Host ("  Found: {0} {1}" -f $app.DisplayName, $app.DisplayVersion) }
    if (-not $script:DoApply) { Add-Result $Label 'CHECK' 'Application is installed; Apply mode will ask before attempting uninstall.'; return }
    if (-not (Confirm-Action "Uninstall $Label using winget?" 'REMOVE')) { Add-Result $Label 'SKIPPED' 'Uninstall declined.'; return }
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) { Add-Result $Label 'MANUAL' 'winget is unavailable. Uninstall via Settings > Apps > Installed apps.'; return }
    try {
        & winget.exe uninstall --name $WingetName --exact --accept-source-agreements
        if ($LASTEXITCODE -eq 0) { Add-Result $Label 'ATTEMPTED' 'winget uninstall completed; verify the application is gone.' }
        else { Add-Result $Label 'MANUAL' "winget returned exit code $LASTEXITCODE. Use Settings > Apps > Installed apps and verify removal." }
    } catch { Add-Result $Label 'ERROR' $_.Exception.Message }
}

function Invoke-ProhibitedApps {
    Write-Host "`n--- Prohibited applications ---" -ForegroundColor Cyan
    Invoke-AppRemoval -DisplayNameRegex '(^|\s)Everything(\s|$)' -Label 'Everything search utility' -WingetName 'Everything'
    Invoke-AppRemoval -DisplayNameRegex 'AnyDesk' -Label 'AnyDesk' -WingetName 'AnyDesk'
    # Do not uninstall Edge, Notepad++, or Evernote. The README permits/requires them.
}

function Invoke-NetcatBackdoorCheck {
    Write-Host "`n--- Netcat / Ncat suspicious executable check ---" -ForegroundColor Cyan
    $roots = @('C:\Users','C:\ProgramData','C:\Windows\Temp') | Where-Object { Test-Path -LiteralPath $_ }
    $candidates = @()
    foreach ($root in $roots) {
        $candidates += Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^(nc|netcat|ncat)(\.exe)?$' }
    }
    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(nc|netcat|ncat)(\.exe)?$' })
    if ($candidates.Count -eq 0 -and $procs.Count -eq 0) { Add-Result 'Netcat backdoor' 'PASS' 'No obvious nc/netcat/ncat executable was found in the searched locations or process list.'; return }
    foreach ($p in $procs) { Write-Host ("  Running process: {0}, PID={1}, Path={2}" -f $p.Name,$p.ProcessId,$p.ExecutablePath) }
    foreach ($f in $candidates) { Write-Host ("  File candidate: {0}" -f $f.FullName) }
    if (-not $script:DoApply) { Add-Result 'Netcat backdoor' 'CHECK' 'Candidate found. Verify the path against the Desktop Forensics Questions/README before removing it.'; return }
    foreach ($f in $candidates) {
        if (Confirm-Action "Remove this candidate only after confirming it is the prohibited backdoor: $($f.FullName)" 'DELETE') {
            try {
                foreach ($p in $procs | Where-Object { $_.ExecutablePath -eq $f.FullName }) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
                Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
                Add-Result 'Netcat backdoor' 'FIXED' "Removed confirmed candidate $($f.FullName)."
            } catch { Add-Result 'Netcat backdoor' 'ERROR' $_.Exception.Message }
        } else { Add-Result 'Netcat backdoor' 'SKIPPED' "Kept $($f.FullName)." }
    }
    if ($candidates.Count -eq 0 -and $procs.Count -gt 0) { Add-Result 'Netcat backdoor' 'MANUAL' 'A netcat-like process is running but no matching file was found in the searched folders. Inspect its executable path and the forensic question before removal.' }
}

function Invoke-AppUpdates {
    Write-Host "`n--- Chrome and Evernote updates ---" -ForegroundColor Cyan
    $apps = Get-InstalledApp
    foreach ($target in @(@{Regex='Google Chrome'; Id='Google.Chrome'; Label='Google Chrome update'}, @{Regex='Evernote'; Id='Evernote.Evernote'; Label='Evernote update'})) {
        $found = @($apps | Where-Object { $_.DisplayName -match $target.Regex })
        if ($found.Count -eq 0) { Add-Result $target.Label 'MANUAL' 'Application not found in the installed-app registry; confirm it is installed per the README.'; continue }
        foreach ($app in $found) { Write-Host ("  Installed: {0} {1}" -f $app.DisplayName,$app.DisplayVersion) }
        if (-not $script:DoApply) { Add-Result $target.Label 'CHECK' 'Check for updates. Apply mode will attempt winget upgrade if available.'; continue }
        if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) { Add-Result $target.Label 'MANUAL' 'winget unavailable; update through the app itself or its official updater.'; continue }
        try {
            & winget.exe upgrade --id $target.Id --exact --accept-source-agreements --accept-package-agreements
            if ($LASTEXITCODE -eq 0) { Add-Result $target.Label 'ATTEMPTED' 'winget upgrade completed; reopen the app and verify its version.' }
            else { Add-Result $target.Label 'MANUAL' "winget returned exit code $LASTEXITCODE. Update in the application and verify the version." }
        } catch { Add-Result $target.Label 'ERROR' $_.Exception.Message }
    }
}

Write-Host 'CyberPatriot Windows Security Toolkit - OKCUP Round 1' -ForegroundColor Green
if ($script:DoApply) { Write-Host 'Mode: APPLY selected remediations (confirmations required for removals)' -ForegroundColor Yellow }
else { Write-Host 'Mode: AUDIT ONLY' -ForegroundColor Yellow }
if (-not (Test-IsAdmin)) { Write-Warning 'Not running as Administrator. Some checks/fixes will fail.' }
Write-Warning 'Read both Desktop Forensics Questions before making changes. Do not disable ScoreEngine.'

Set-LocalSecurityPolicies
Set-CtrlAltDeletePolicy
Set-FirewallProfiles
Set-RemoteAssistance
Set-RemoteRegistry
Set-ActionCenter
Check-RdpAndScoreEngine
Set-ArcadePasswordExpiry
Set-BennyPassword
Set-ExpectedUserRoles
Remove-TargetMp3
Invoke-ProhibitedApps
Invoke-NetcatBackdoorCheck
Invoke-AppUpdates

Write-Host "`n--- Summary ---" -ForegroundColor Cyan
$script:Results | Format-Table -AutoSize -Wrap
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$report = Join-Path $PSScriptRoot "CyberPatriot-Report-$stamp.csv"
try { $script:Results | Export-Csv -LiteralPath $report -NoTypeInformation -Encoding UTF8; Write-Host "`nReport saved to: $report" -ForegroundColor Green }
catch { Write-Warning "Could not save CSV report: $($_.Exception.Message)" }
Write-Host 'Review all CHECK/MANUAL/ATTEMPTED results against the round README and scoreboard.' -ForegroundColor Yellow
```
