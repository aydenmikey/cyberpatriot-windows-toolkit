# Final Verification Checklist

- [ ] Scenario README and scoring requirements reviewed.
- [ ] Initial score/report recorded.
- [ ] Authorized users and administrators verified.
- [ ] Required accounts, home directories, and auto-login account preserved.
- [ ] Password and lockout policy verified with `net accounts` and policy export.
- [ ] Guest and unknown accounts reviewed against the scenario.
- [ ] Firewall profiles and logging verified.
- [ ] Defender status and exclusions verified.
- [ ] SMB client/server settings and shares verified.
- [ ] Services reviewed against scenario requirements.
- [ ] Advanced audit policy verified with `auditpol /get /category:*`.
- [ ] Required software, versions, and installation paths verified.
- [ ] Prohibited software/files handled only after confirmation.
- [ ] Competition scoring client remains operational.
- [ ] Each change documented in the change log.
- [ ] Final score/report saved.
- [ ] No unnecessary changes made after reaching the target score.

## Closeout commands

```powershell
net accounts
```

```powershell
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction
```

```powershell
Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled
```

```powershell
auditpol /get /category:*
```

```powershell
Get-Service | Where-Object {$_.Name -match "CCS|CyberPatriot"} | Select-Object Name,Status,StartType
```

The last command is a discovery aid only; service names may differ. Use the competition README to identify the exact client service.
