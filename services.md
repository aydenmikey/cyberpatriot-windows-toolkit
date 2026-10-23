# Windows Services

## Inventory common security-sensitive services

```powershell
Get-Service Spooler,RemoteRegistry,TermService,SessionEnv,UmRdpService,LanmanServer,RemoteAccess,W3SVC,sshd,SNMP,FTPSVC -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType
```

Find running automatic services:

```powershell
Get-CimInstance Win32_Service | Where-Object {$_.State -eq "Running" -and $_.StartMode -eq "Auto"} | Select-Object Name,DisplayName,StartMode,StartName
```

## Review before remediation

A generic baseline may recommend disabling services such as Print Spooler, Remote Desktop Services, Server, or SSH Server. Do not disable them solely because they appear on a list. Check:

- Does the scenario require printing, file sharing, remote access, or a specific application?
- Is the service explicitly listed as prohibited or unnecessary?
- Is it part of the competition client or required software?
- Will disabling it disrupt scoring or system functionality?

## Example: disable Remote Registry only when confirmed unnecessary

```powershell
Stop-Service -Name RemoteRegistry -Force
```

```powershell
Set-Service -Name RemoteRegistry -StartupType Disabled
```

Verify:

```powershell
Get-Service -Name RemoteRegistry | Select-Object Name,Status,StartType
```

## Competition client

Never stop, disable, or remove the competition scoring client unless official competition instructions explicitly direct you to do so. Preserve its required services and exclusions.
