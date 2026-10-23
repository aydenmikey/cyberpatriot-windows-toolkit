# Accounts and Password Policy

Run PowerShell as Administrator where required. These first commands are read-only.

## Inventory

```powershell
Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,PasswordExpires,PasswordNeverExpires,LastLogon
```

```powershell
Get-LocalGroupMember -Group "Administrators"
```

```powershell
net user
```

```powershell
net localgroup
```

```powershell
net localgroup administrators
```

```powershell
net accounts
```

## Export local security policy for inspection

```powershell
secedit /export /cfg "$env:TEMP\cyberpatriot-audit.cfg"
```

```powershell
Select-String -Path "$env:TEMP\cyberpatriot-audit.cfg" -Pattern "MinimumPasswordAge|MaximumPasswordAge|MinimumPasswordLength|PasswordComplexity|PasswordHistorySize|ClearTextPassword|LockoutBadCount|ResetLockoutCount|LockoutDuration"
```

## Example local password/lockout settings

**Only apply values required by the scenario or approved checklist.** The values below are an example baseline, not a universal answer for every image.

```powershell
net accounts /minpwlen:14
net accounts /minpwage:1
net accounts /maxpwage:30
net accounts /uniquepw:24
net accounts /lockoutthreshold:5
net accounts /lockoutduration:15
net accounts /lockoutwindow:15
```

Verify:

```powershell
net accounts
```

Password complexity and reversible encryption are not fully verified by `net accounts`; inspect the exported policy and Local Security Policy.

## Guest account

Inspect:

```powershell
Get-LocalUser -Name "Guest" | Select-Object Name,Enabled
```

If the scenario requires Guest disabled, confirm that requirement before changing it. Example command:

```powershell
Disable-LocalUser -Name "Guest"
```

## Important safeguards

- Compare users and groups with the scenario's authorized list.
- Do not remove an unfamiliar account until its purpose is established.
- Preserve required accounts, home directories, and any designated auto-login account.
- Do not set or disclose passwords in a public repository.
- Avoid pasting real credentials into logs or GitHub.
