# Expanded OKCUP Round 1 Windows 11 toolkit

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
.\CyberPatriot-Toolkit-OKCUP-R1-Expanded.ps1
```

Apply supported remediations with confirmation prompts:

```powershell
.\CyberPatriot-Toolkit-OKCUP-R1-Expanded.ps1 -Apply
```

Force audit-only behavior even when `-Apply` is supplied:

```powershell
.\CyberPatriot-Toolkit-OKCUP-R1-Expanded.ps1 -Apply -CheckOnly
```

## PowerShell source

```powershell
# CyberPatriot Windows 11 Toolkit - OKCUP Round 1 additions
# Default mode is AUDIT ONLY. Run in an elevated PowerShell window.
# Review the Desktop Forensics Questions BEFORE using -Apply.
# This script never edits/deletes the forensics question files and never stops ScoreEngine.
# Windows-only implementation: Linux PAM/UFW/auditd/file-permission items are not applicable here.
# It audits persistence, ports, shares and update state; review suspicious findings before action.
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
    Write-Host "`n--- Password complexity, length, and account lockout policy ---" -ForegroundColor Cyan
    # Baseline targets from the supplied checklist. If the round README specifies
    # a different value, follow the README instead. Minimum length is 8 here.
    $targets = @(
        @{ Key='PasswordComplexity'; Label='Password complexity'; Expected='1' },
        @{ Key='MinimumPasswordLength'; Label='Minimum password length'; Expected='8' },
        @{ Key='AllowAdministratorLockout'; Label='Administrator account lockout allowed'; Expected='1' },
        @{ Key='LockoutBadCount'; Label='Account lockout threshold'; Expected='5' },
        @{ Key='LockoutDuration'; Label='Account lockout duration (minutes)'; Expected='30' },
        @{ Key='ResetLockoutCount'; Label='Reset lockout counter (minutes)'; Expected='30' }
    )
    $policy = Get-PolicyExport
    if (-not $policy) {
        Add-Result 'Local security policies' 'MANUAL' 'Could not export local security policy. Inspect secpol.msc > Account Policies.'
        return
    }

    $needsChange = $false
    foreach ($target in $targets) {
        $line = $policy.Content | Where-Object { $_ -match ('^\s*' + [regex]::Escape($target.Key) + '\s*=') } | Select-Object -First 1
        if ($line) {
            $value = ($line -split '=', 2)[1].Trim()
            if ($value -eq $target.Expected) { Add-Result $target.Label 'PASS' "Current value is $value." }
            elseif ($script:DoApply) { $needsChange = $true }
            else { Add-Result $target.Label 'CHECK' "Current value is $value; checklist target is $($target.Expected)." }
        } elseif ($script:DoApply) { $needsChange = $true }
        else { Add-Result $target.Label 'MANUAL' 'Setting was not exposed in the policy export; verify in secpol.msc.' }
    }

    if ($script:DoApply -and $needsChange) {
        $inf = Join-Path $env:TEMP ("cp-apply-{0}.inf" -f [guid]::NewGuid().ToString('N'))
        $db = Join-Path $env:TEMP ("cp-apply-{0}.sdb" -f [guid]::NewGuid().ToString('N'))
        $lines = @('[Unicode]','Unicode=yes','[Version]','signature="$CHICAGO$"','Revision=1','[System Access]')
        foreach ($target in $targets) { $lines += ("{0} = {1}" -f $target.Key, $target.Expected) }
        try {
            $lines | Set-Content -LiteralPath $inf -Encoding Unicode
            & secedit.exe /configure /db $db /cfg $inf /areas SECURITYPOLICY /quiet 2>$null | Out-Null
            $verify = Get-PolicyExport
            foreach ($target in $targets) {
                $line = if ($verify) { $verify.Content | Where-Object { $_ -match ('^\s*' + [regex]::Escape($target.Key) + '\s*=') } | Select-Object -First 1 } else { $null }
                if ($line -and (($line -split '=', 2)[1].Trim() -eq $target.Expected)) {
                    Add-Result $target.Label 'FIXED' "Verified value $($target.Expected)."
                } else {
                    Add-Result $target.Label 'MANUAL' "Could not verify target $($target.Expected); inspect secpol.msc manually."
                }
            }
            if ($verify) { Remove-Item -LiteralPath $verify.Path -Force -ErrorAction SilentlyContinue }
        } catch { Add-Result 'Local security policy remediation' 'ERROR' $_.Exception.Message }
        finally { Remove-Item -LiteralPath $inf,$db -Force -ErrorAction SilentlyContinue }
    }
    Remove-Item -LiteralPath $policy.Path -Force -ErrorAction SilentlyContinue
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
    Write-Host "`n--- User auditing and administrator membership ---" -ForegroundColor Cyan
    $authorizedUsers = @('courier','mrhouse','benny','yesman','victor','cass','arcade','veronica','boone','raul','lily','doc','sunny','trudy','ringo','manny','swank','cachino','pacer','ede')
    $systemNames = @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount')
    $builtInRids = @('-500$','-501$','-503$','-504$')

    # Verify the specifically required non-admin accounts.
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

    # Audit every local account against the round's authorized list. Preserve Windows
    # built-in/system-managed accounts; the separate built-in account check handles Guest/Administrator.
    try {
        foreach ($user in Get-LocalUser -ErrorAction Stop) {
            $rid = [string]$user.SID.Value
            $isBuiltIn = ($systemNames -contains $user.Name) -or (($builtInRids | Where-Object { $rid -match $_ }).Count -gt 0)
            if (($authorizedUsers -contains $user.Name) -or $isBuiltIn) { continue }
            if (-not $script:DoApply) {
                Add-Result "Unauthorized local user $($user.Name)" 'CHECK' 'Account is not on the README authorized-user list; confirm before removal.'
            } elseif (Confirm-Action "Remove unauthorized local account '$($user.Name)'? This does not delete its profile folder." 'REMOVE') {
                try { Remove-LocalUser -Name $user.Name -ErrorAction Stop; Add-Result "Unauthorized local user $($user.Name)" 'FIXED' 'Removed local account; profile folder was not explicitly deleted.' }
                catch { Add-Result "Unauthorized local user $($user.Name)" 'ERROR' $_.Exception.Message }
            } else { Add-Result "Unauthorized local user $($user.Name)" 'SKIPPED' 'Account removal declined.' }
        }
    } catch { Add-Result 'Local user inventory' 'ERROR' $_.Exception.Message }

    # Check all local Administrators members. The built-in Administrator is retained
    # as a Windows system account; disable it only if enabled and separately confirmed.
    $authorizedAdmins = @('courier','mrhouse','benny','yesman','victor')
    try {
        foreach ($member in Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop) {
            $leaf = ($member.Name -split '\\')[-1]
            if ($authorizedAdmins -contains $leaf) {
                Add-Result "Administrator membership: $leaf" 'PASS' 'Listed as an authorized administrator in the README.'
            } elseif ($leaf -ieq 'Administrator') {
                Add-Result 'Built-in Administrator group membership' 'INFO' 'Windows built-in account retained; check whether the account itself is disabled below.'
            } elseif ($script:DoApply -and (Confirm-Action "Remove unapproved member '$($member.Name)' from local Administrators?" 'REMOVE')) {
                try { Remove-LocalGroupMember -Group 'Administrators' -Member $member.Name -Confirm:$false -ErrorAction Stop; Add-Result "Unapproved administrator $($member.Name)" 'FIXED' 'Removed from local Administrators group; account was not deleted.' }
                catch { Add-Result "Unapproved administrator $($member.Name)" 'ERROR' $_.Exception.Message }
            } else {
                Add-Result "Unapproved administrator $($member.Name)" 'CHECK' 'Not on the README authorized-administrator list; review and remove if unauthorized.'
            }
        }
    } catch { Add-Result 'Administrators group audit' 'ERROR' $_.Exception.Message }
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
    Invoke-AppRemoval -DisplayNameRegex 'CCleaner' -Label 'CCleaner candidate (verify README)' -WingetName 'CCleaner'
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


function Set-BuiltInAccounts {
    Write-Host "`n--- Built-in Guest and Administrator accounts ---" -ForegroundColor Cyan
    try {
        $users = @(Get-LocalUser -ErrorAction Stop)
        $guest = $users | Where-Object { $_.SID.Value -match '-501$' } | Select-Object -First 1
        if (-not $guest) { Add-Result 'Built-in Guest account' 'MANUAL' 'Could not identify the built-in Guest account by SID.' }
        elseif (-not $guest.Enabled) { Add-Result 'Built-in Guest account' 'PASS' 'Already disabled.' }
        elseif ($script:DoApply) {
            try { Disable-LocalUser -Name $guest.Name -ErrorAction Stop; Add-Result 'Built-in Guest account' 'FIXED' 'Disabled built-in Guest account.' }
            catch { Add-Result 'Built-in Guest account' 'ERROR' $_.Exception.Message }
        } else { Add-Result 'Built-in Guest account' 'CHECK' 'Enabled; checklist recommends disabling it.' }

        $builtinAdmin = $users | Where-Object { $_.SID.Value -match '-500$' } | Select-Object -First 1
        if (-not $builtinAdmin) { Add-Result 'Built-in Administrator account' 'MANUAL' 'Could not identify the built-in Administrator account by SID.'; return }
        if (-not $builtinAdmin.Enabled) { Add-Result 'Built-in Administrator account' 'PASS' 'Already disabled.'; return }
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        if ($currentSid -eq $builtinAdmin.SID.Value) {
            Add-Result 'Built-in Administrator account' 'MANUAL' 'This is the current logon account. Do not disable it during this session.'
        } elseif ($script:DoApply -and (Confirm-Action 'Built-in Administrator is enabled. Disable it now? Confirm you have another working authorized administrator account.' 'DISABLE')) {
            try { Disable-LocalUser -Name $builtinAdmin.Name -ErrorAction Stop; Add-Result 'Built-in Administrator account' 'FIXED' 'Disabled built-in Administrator account.' }
            catch { Add-Result 'Built-in Administrator account' 'ERROR' $_.Exception.Message }
        } else { Add-Result 'Built-in Administrator account' 'CHECK' 'Enabled. Disable only after confirming another authorized administrator can sign in.' }
    } catch { Add-Result 'Built-in account audit' 'ERROR' $_.Exception.Message }
}

function Invoke-AuditPolicyCheck {
    Write-Host "`n--- Windows advanced audit policy ---" -ForegroundColor Cyan
    $subcategories = @('Logon','Account Lockout','User Account Management','Security Group Management','File System','Registry','File Share')
    if (-not (Get-Command auditpol.exe -ErrorAction SilentlyContinue)) { Add-Result 'Advanced audit policy' 'MANUAL' 'auditpol.exe is unavailable.'; return }
    foreach ($subcategory in $subcategories) {
        if ($script:DoApply) {
            & auditpol.exe /set ("/subcategory:{0}" -f $subcategory) /success:enable /failure:enable 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { Add-Result "Audit policy: $subcategory" 'ATTEMPTED' 'Enabled success and failure auditing; verify with auditpol /get /category:*.' }
            else { Add-Result "Audit policy: $subcategory" 'MANUAL' 'Could not configure this subcategory; verify its localized name with auditpol /list /subcategory:*.' }
        } else {
            $out = & auditpol.exe /get ("/subcategory:{0}" -f $subcategory) 2>&1
            if ($LASTEXITCODE -eq 0) { Add-Result "Audit policy: $subcategory" 'INFO' (($out | Out-String).Trim() -replace '\s+',' ') }
            else { Add-Result "Audit policy: $subcategory" 'MANUAL' 'Could not query this subcategory; inspect auditpol /get /category:*.' }
        }
    }
}

function Invoke-NetworkAndServiceAudit {
    Write-Host "`n--- Listening ports and potentially unauthorized services ---" -ForegroundColor Cyan
    try {
        $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
        foreach ($listener in $listeners) {
            $proc = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
            Write-Host ("  TCP {0}:{1} PID={2} Process={3}" -f $listener.LocalAddress,$listener.LocalPort,$listener.OwningProcess,$proc.ProcessName)
        }
        Add-Result 'Listening TCP ports' 'INFO' ("Found {0} listening TCP endpoint(s); review the printed process/port list." -f $listeners.Count)
    } catch { Add-Result 'Listening TCP ports' 'MANUAL' $_.Exception.Message }

    $pattern = 'FTP|Telnet|VNC|torrent|P2P|AnyDesk|TeamViewer'
    $matches = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { ($_.Name + ' ' + $_.DisplayName) -match $pattern -and $_.Name -ne 'ScoreEngine' -and $_.Name -ne 'TermService' })
    if ($matches.Count -eq 0) { Add-Result 'Potentially unauthorized services' 'PASS' 'No services matching FTP/Telnet/VNC/P2P/remote-control patterns were found.'; return }
    foreach ($svc in $matches) {
        Write-Host ("  Service: {0} ({1}), State={2}, Startup={3}" -f $svc.Name,$svc.DisplayName,$svc.State,$svc.StartMode)
        if ($script:DoApply -and (Confirm-Action "Stop and disable service '$($svc.Name)'? Confirm it is unauthorized under this round's README." 'DISABLE')) {
            try {
                if ($svc.State -eq 'Running') { Stop-Service -Name $svc.Name -Force -ErrorAction Stop }
                Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
                Add-Result "Service $($svc.Name)" 'FIXED' 'Stopped if running and disabled startup.'
            } catch { Add-Result "Service $($svc.Name)" 'ERROR' $_.Exception.Message }
        } else { Add-Result "Service $($svc.Name)" 'CHECK' 'Review against README; do not disable critical or authorized services.' }
    }
}

function Invoke-ShareAudit {
    Write-Host "`n--- SMB shared folders ---" -ForegroundColor Cyan
    if (-not (Get-Command Get-SmbShare -ErrorAction SilentlyContinue)) { Add-Result 'SMB shares' 'MANUAL' 'Get-SmbShare is unavailable on this Windows edition.'; return }
    $shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(ADMIN\$|C\$|D\$|IPC\$|print\$)$' })
    if ($shares.Count -eq 0) { Add-Result 'Non-default SMB shares' 'PASS' 'No non-default SMB shares found.'; return }
    foreach ($share in $shares) {
        Write-Host ("  Share: {0}; Path={1}; Description={2}" -f $share.Name,$share.Path,$share.Description)
        if ($script:DoApply -and (Confirm-Action "Remove SMB share '$($share.Name)'? Confirm it is unauthorized." 'REMOVE')) {
            try { Remove-SmbShare -Name $share.Name -Force -ErrorAction Stop; Add-Result "SMB share $($share.Name)" 'FIXED' 'Removed share; underlying files were not deleted.' }
            catch { Add-Result "SMB share $($share.Name)" 'ERROR' $_.Exception.Message }
        } else { Add-Result "SMB share $($share.Name)" 'CHECK' 'Review access/authorization; share left unchanged.' }
    }
}

function Invoke-StartupPersistenceAudit {
    Write-Host "`n--- Startup entries and scheduled tasks (audit only) ---" -ForegroundColor Cyan
    $runPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    )
    $count = 0
    foreach ($path in $runPaths) {
        if (Test-Path $path) {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            foreach ($prop in $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
                $count++; Write-Host ("  Run key: {0} => {1}" -f $prop.Name,$prop.Value)
            }
        }
    }
    $taskCount = 0
    try {
        foreach ($task in Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }) {
            $taskCount++; Write-Host ("  Scheduled task: {0}{1} State={2}" -f $task.TaskPath,$task.TaskName,$task.State)
        }
    } catch { Add-Result 'Scheduled task inventory' 'MANUAL' $_.Exception.Message }
    Add-Result 'Startup Run keys' 'INFO' ("Printed {0} Run-key startup entry/entries. Review unknown commands/paths." -f $count)
    Add-Result 'Non-Microsoft scheduled tasks' 'INFO' ("Printed {0} non-Microsoft scheduled task(s). Review task actions and authors; no tasks were changed." -f $taskCount)
}

function Invoke-WindowsUpdateAudit {
    Write-Host "`n--- Windows Update status ---" -ForegroundColor Cyan
    $svc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($svc) { Add-Result 'Windows Update service' 'INFO' ("Status=$($svc.Status). Check Settings > Windows Update for security/quality updates.") }
    try {
        $hotfix = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($hotfix) { Add-Result 'Latest installed hotfix' 'INFO' ("$($hotfix.HotFixID) installed $($hotfix.InstalledOn).") }
        else { Add-Result 'Latest installed hotfix' 'MANUAL' 'No hotfix data returned.' }
    } catch { Add-Result 'Latest installed hotfix' 'MANUAL' $_.Exception.Message }
    Add-Result 'Windows Update action' 'MANUAL' 'Install only appropriate security/quality updates through Settings. Do not install Feature Updates or Insider Preview builds for this round.'
}

function Invoke-AdditionalMediaAudit {
    Write-Host "`n--- Additional user media files (.mp4, .avi, .jpg) ---" -ForegroundColor Cyan
    $extensions = @('*.mp4','*.avi','*.jpg','*.jpeg')
    $found = @()
    $profileRoots = @(Get-ChildItem -LiteralPath 'C:\Users' -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') })
    foreach ($profile in $profileRoots) {
        foreach ($folderName in @('Music','Videos','Pictures','Downloads','Desktop','Documents')) {
            $folder = Join-Path $profile.FullName $folderName
            if (Test-Path -LiteralPath $folder) {
                foreach ($extension in $extensions) {
                    $found += Get-ChildItem -LiteralPath $folder -Filter $extension -File -Recurse -ErrorAction SilentlyContinue
                }
            }
        }
    }
    $found = @($found | Sort-Object -Property FullName -Unique)
    if ($found.Count -eq 0) { Add-Result 'Additional user media files' 'PASS' 'No .mp4/.avi/.jpg/.jpeg files found in common user folders.'; return }
    foreach ($file in $found) {
        Write-Host ("  Candidate media file: {0}" -f $file.FullName)
        if ($script:DoApply -and (Confirm-Action "Delete this media file? Only confirm if prohibited by the README: $($file.FullName)" 'DELETE')) {
            try { Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop; Add-Result 'Additional user media files' 'FIXED' "Deleted $($file.FullName)." }
            catch { Add-Result 'Additional user media files' 'ERROR' $_.Exception.Message }
        } else { Add-Result 'Additional user media files' 'CHECK' 'Candidate reported and left unchanged unless explicitly confirmed.' }
    }
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
Set-BuiltInAccounts
Set-ArcadePasswordExpiry
Set-BennyPassword
Set-ExpectedUserRoles
Invoke-AuditPolicyCheck
Invoke-NetworkAndServiceAudit
Invoke-ShareAudit
Invoke-StartupPersistenceAudit
Invoke-WindowsUpdateAudit
Remove-TargetMp3
Invoke-AdditionalMediaAudit
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
