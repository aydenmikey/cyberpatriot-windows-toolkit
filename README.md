# CyberPatriot Windows 10/11 Toolkit

A checklist-and-command reference for auditing and hardening Windows 10/11 practice images.

## Purpose

This repository organizes repeatable **read-only audits**, scenario review checklists, and individually applied remediation commands. It is designed to support competition preparation, not to guarantee a particular score.

## Workflow

1. Read the image's README/scenario and scoring instructions.
2. Record required accounts, software, services, files, and exceptions.
3. Run the read-only commands in `checks/`.
4. Compare findings with the scenario and applicable checklist.
5. Apply only approved changes, one at a time.
6. Verify the setting after each change and check the scoring report.
7. Preserve a copy of the final report and notes.

## Contents

- `checklists/scenario-review.md` — capture requirements and exceptions before changing the image.
- `checks/accounts-and-passwords.md` — accounts, group membership, password policy.
- `checks/firewall-and-defender.md` — firewall profiles and Defender status.
- `checks/network-and-smb.md` — SMB, shares, and network policy.
- `checks/services.md` — service inventory and safe review.
- `checks/auditing-and-policy.md` — audit policy, security policy export, and Group Policy.
- `checks/software-and-files.md` — installed software and suspicious-file review.
- `checklists/final-verification.md` — post-change verification and closeout.
- `templates/change-log.md` — document each change.

## Safety rules

- The scenario README takes precedence over a generic hardening checklist.
- Do not remove or disable accounts, software, services, shares, or files until you confirm they are not required.
- Preserve the competition scoring client and its required exclusions/services.
- Do not change the designated auto-login account if the scenario prohibits it.
- Do not assume a successful command earns points. Verify the resulting state and scoring report.
- Avoid bulk remediation. Make one change at a time and keep a record.
- Run administrative commands only on systems you are authorized to administer.

## Notes

Some settings vary by Windows edition, build, language, and domain policy. If a command reports an error, inspect the local policy UI and command help instead of guessing a replacement.
