# Installed Software and File Review

## Installed application inventory

```powershell
Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,
HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* |
Select-Object DisplayName,DisplayVersion,Publisher,InstallLocation |
Where-Object DisplayName |
Sort-Object DisplayName
```

## Common user profile locations

```powershell
Get-ChildItem C:\\Users -Force | Select-Object Name,FullName,LastWriteTime
```

Search common media extensions in user folders:

```powershell
Get-ChildItem C:\\Users -Recurse -File -ErrorAction SilentlyContinue -Include *.mp3,*.mp4,*.avi,*.mkv,*.mov | Select-Object FullName,Length,LastWriteTime
```

This search can take time. Review results before deleting anything.

## Check startup commands

```powershell
Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User
```

## Check scheduled tasks

```powershell
Get-ScheduledTask | Select-Object TaskName,TaskPath,State
```

## Safe software-removal process

1. Compare each application with the README's required/prohibited software list.
2. Verify the exact product and installation path.
3. Preserve required software and dependencies.
4. Use the application's supported uninstaller when removal is explicitly authorized.
5. Recheck the installed-app inventory and competition score.

Do not delete tools, archives, or files solely because their names look suspicious. Confirm scenario requirements first. Never remove required Wireshark dependencies or the competition client.
