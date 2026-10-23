# Network, SMB, and Shares

## SMB audit

```powershell
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EnableSecuritySignature
```

```powershell
Get-SmbClientConfiguration | Select-Object RequireSecuritySignature,EnableSecuritySignature,EnableInsecureGuestLogons
```

```powershell
Get-SmbShare | Select-Object Name,Path,Description
```

## Example SMB remediation

Use only when compatible with the scenario and required legacy systems.

Disable SMB1 server protocol:

```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
```

Disable insecure guest logons on the client:

```powershell
Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -Force
```

Require SMB signing on the server:

```powershell
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
```

Require SMB signing on the client:

```powershell
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
```

Verify:

```powershell
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,RequireSecuritySignature
```

```powershell
Get-SmbClientConfiguration | Select-Object EnableInsecureGuestLogons,RequireSecuritySignature
```

## Group Policy review

```powershell
gpresult /r
```

```powershell
reg query HKLM\\SOFTWARE\\Policies
```

Open Local Group Policy Editor:

```powershell
gpedit.msc
```

Review the scenario-relevant policies for SMB1, insecure guest logons, Hardened UNC Paths, and process-creation command-line auditing.

## Safeguards

- Do not disable `LanmanServer` automatically; it supports Windows file sharing.
- Do not remove shares without verifying their purpose and scenario requirements.
- SMB server settings and SMB client settings are separate. Verify both.
