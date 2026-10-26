# CyberPatriot Windows 11 Application Update Commands

These commands update the specified applications through Windows Package
Manager (`winget`). Open **PowerShell as Administrator** and run them
individually.

## 1. Refresh Winget sources

``` powershell
winget source update
```

## 2. Google Chrome

``` powershell
winget upgrade --id Google.Chrome --exact --accept-source-agreements --accept-package-agreements
```

## 3. Notepad++

``` powershell
winget upgrade --id Notepad++.Notepad++ --exact --accept-source-agreements --accept-package-agreements
```

## 4. Evernote

``` powershell
winget upgrade --id Evernote.Evernote --exact --accept-source-agreements --accept-package-agreements
```

## 5. Wireshark

**Caution:** The supplied OKCUP Round 1 README does not list Wireshark
as authorized software, and it prohibits hacking tools. Do not install
or update Wireshark for this competition unless the scoring instructions
or competition staff explicitly confirm it is allowed. If it is
authorized and already installed, use:

``` powershell
winget upgrade --id WiresharkFoundation.Wireshark --exact --accept-source-agreements --accept-package-agreements
```

## If Winget reports no applicable upgrade

The application may already be current, or Winget may not recognize the
installed copy. Check what Winget detects:

``` powershell
winget list --id Google.Chrome --exact
winget list --id Notepad++.Notepad++ --exact
winget list --id Evernote.Evernote --exact
winget list --id WiresharkFoundation.Wireshark --exact
```

## Competition reminders

-   The README requires Chrome, Notepad++, and Evernote to remain
    installed and up to date.
-   Keep Microsoft Edge installed.
-   These commands update applications only; they do not install Windows
    Feature Updates.
-   Avoid `winget upgrade --all` so you can control which applications
    are changed.
-   If an app is not found or an upgrade fails, update it through its
    official in-app updater or website and verify the installed version.
