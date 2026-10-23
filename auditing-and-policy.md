# Audit Policy and Local Security Policy

## Current advanced audit policy

```powershell
auditpol /get /category:*
```

List supported subcategory names:

```powershell
auditpol /list /subcategory:*
```

Example audit settings from a common baseline. Confirm the scenario and local subcategory names first:

```powershell
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
```

```powershell
auditpol /set /subcategory:"Security Group Management" /success:enable
```

```powershell
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
```

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

```powershell
auditpol /set /subcategory:"Account Lockout" /failure:enable
```

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

```powershell
auditpol /set /subcategory:"Audit Policy Change" /success:enable
```

Verify after changes:

```powershell
auditpol /get /category:*
```

If a subcategory name is rejected, use the exact name returned by `auditpol /list /subcategory:*`. Names can vary by Windows version and language.

## Local Security Policy

```powershell
secpol.msc
```

Review relevant settings under Account Policies and Local Policies → Security Options, including password/lockout policy, LAN Manager authentication, anonymous enumeration, blank passwords, and UAC.

## Group Policy report

```powershell
gpresult /r
```

Optional HTML report:

```powershell
gpresult /h "$env:USERPROFILE\Desktop\gpresult.html"
```

Refresh policy only when appropriate:

```powershell
gpupdate /force
```

## Notes

- Domain policy may override local settings.
- Enabling additional auditing can increase event-log volume.
- Check the resulting state after applying policy.
