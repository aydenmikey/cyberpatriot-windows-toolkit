# Windows Firewall and Microsoft Defender

## Firewall audit

```powershell
Get-NetFirewallProfile | Format-List Name,Enabled,DefaultInboundAction,DefaultOutboundAction,NotifyOnListen,LogFileName,LogMaxSizeKilobytes,LogBlocked,LogAllowed
```

Show firewall rules:

```powershell
Get-NetFirewallRule | Select-Object DisplayName,Enabled,Direction,Action,Profile
```

## Firewall remediation examples

Only apply these after confirming the scenario permits them and required network functionality will remain available.

Enable all profiles:

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
```

Set default inbound action to block:

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block
```

Example Private/Public logging settings:

```powershell
Set-NetFirewallProfile -Profile Private,Public -LogMaxSizeKilobytes 16384 -LogBlocked True -LogAllowed True
```

Verify:

```powershell
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,LogMaxSizeKilobytes,LogBlocked,LogAllowed
```

## Defender audit

```powershell
Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled
```

```powershell
Get-MpPreference | Select-Object DisableRemovableDriveScanning,DisableEmailScanning,PUAProtection,ExclusionPath,ExclusionProcess,ExclusionExtension
```

Example: enable removable-drive scanning if it is disabled and the scenario allows it:

```powershell
Set-MpPreference -DisableRemovableDriveScanning $false
```

Example: enable email scanning if it is disabled and the scenario allows it:

```powershell
Set-MpPreference -DisableEmailScanning $false
```

## Safeguards

- Preserve scenario-required Defender exclusions and competition-client files.
- Do not indiscriminately remove exclusions or quarantine unknown competition files.
- Do not delete firewall rules in bulk.
- Verify the resulting configuration and the scoring report.
