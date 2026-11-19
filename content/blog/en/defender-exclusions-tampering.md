---
title: "Defender Exclusions and Tampering: Finding the Traces"
description: "How intruders weaken Microsoft Defender with exclusions, Set-MpPreference and MpCmdRun, and where it shows: 5001, 5007, 5013, the registry, PowerShell."
date: "2026-11-19"
author: "Florian Amette"
tags: ["defender", "defense-evasion", "registry", "powershell", "threat-hunting"]
series: "defender-investigations"
seriesTitle: "Investigating with Defender artifacts"
seriesOrder: 2
faq:
  - question: "Where are Defender exclusions stored in the registry?"
    answer: "Locally set exclusions are under HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions, in subkeys such as Paths, Extensions and Processes; each exclusion is a value whose name is the excluded item. Exclusions set by Group Policy are under HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions. On devices managed with Defender for Endpoint security settings management, Microsoft stopped storing readable exclusion values in the registry from platform 4.18.25110.6."
  - question: "Can I tell when an exclusion was added?"
    answer: "The last write time of the Paths, Processes or Extensions key gives the time of the last change to that key, not to one value. Event 5007 gives the time of each change with the value that was written. Use both: the key time dates the last change, the 5007 events date each addition while the log still holds them."
  - question: "Does tamper protection stop attackers from adding exclusions?"
    answer: "Only under conditions Microsoft lists: platform 4.18.2211.5 or later, DisableLocalAdminMerge enabled, a device managed only by Intune or only by Configuration Manager with the Defender for Endpoint sensor on, and exclusions managed centrally. A TPExclusions value of 1 under HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features confirms it. Elsewhere, a local administrator can add exclusions while tamper protection is on."
  - question: "Why is there a 5013 event but no 5001?"
    answer: "Because tamper protection refused the change. 5013 names the setting someone tried to change; real-time protection stayed on, so no 5001 was written. It shows intent and failure. Check the setting and the time, since management tools can also produce 5013 events."
---

**TL;DR.** Intruders with administrator rights weaken Defender in a few ways: switch off real-time protection with `Set-MpPreference`, add **exclusions** with `Add-MpPreference`, write policy values in the registry, let threats through with default actions, or use `MpCmdRun.exe` to strip signatures, download files or restore quarantined malware. Each leaves a trace. **5001** says protection went off, **5007** records every setting written with its old and new value, **5013** records a change that **tamper protection** refused, and the **Exclusions** keys in the `SOFTWARE` hive keep the current list with a last write time per key. Tamper protection does not protect exclusions on unmanaged or Group Policy-managed machines. No Defender event names the person: that comes from PowerShell logs, PSReadLine history and logon sessions. [Defender Parser](/en#tool) shows the protection changes on one timeline and flags exclusions worth a look.

## Techniques and their traces

| Goal | Typical command | Defender trace | Other traces |
| --- | --- | --- | --- |
| Switch off real-time protection | `Set-MpPreference -DisableRealtimeMonitoring $true` | 5001 if it worked; 5013 if tamper protection refused it | PowerShell logs, PSReadLine history |
| Exclude a folder, process or extension | `Add-MpPreference -ExclusionPath C:\ProgramData\Intel` | 5007 with the new value; last write of the `Exclusions` subkey; `[Exclusion]` lines in MPLog | PowerShell logs, PSReadLine history |
| Write policy values directly | `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\..."` | 5007, or 5013 when tamper protection refuses it | Key last write times, process creation |
| Let detections through | `Set-MpPreference -ThreatIDDefaultAction_Ids <id> -ThreatIDDefaultAction_Actions Allow`, or a severity default action of Allow or None | 5007 for the setting. With None, a 1116 then a 1117 with action Allow; with Allow, Microsoft says ongoing detection events are suppressed | Microsoft: not configurable while tamper protection is on |
| Hide the exclusions | Policy *Control whether or not exclusions are visible to Local Admins* | 5007 | `Get-MpPreference` no longer shows them |
| Remove signatures | `MpCmdRun.exe -RemoveDefinitions -All` | `MpCmdRun.log`; signature versions in later 1151 health events | Process creation |
| Download a file | `MpCmdRun.exe -DownloadFile -url <url> -path <file>` | `MpCmdRun.log` | Process creation, proxy logs |
| Get a sample back | `MpCmdRun.exe -Restore -Name <threat>`, or Windows Security | 1009 | |
| Clear Protection history | Windows Security, deleting DetectionHistory files | 1013 | Missing DetectionHistory files |
| Turn tamper protection off | Windows Security or a management console | 5007 on `TamperProtection` | Management logs |

The `-DownloadFile` option is not in Microsoft's [MpCmdRun reference](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus); the [LOLBAS entry](https://lolbas-project.github.io/lolbas/Binaries/MpCmdRun/) documents it, including a variant that writes to an alternate data stream.

## What tamper protection blocks

Microsoft's [tamper protection overview](https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-overview) lists what stays locked when it is on: real-time protection, behaviour monitoring, IOAV, cloud protection, security intelligence updates, automatic actions on threats, notifications, archive scanning, and changes to Defender settings through the registry. Changes pushed by Group Policy may appear to succeed and still be blocked. A blocked change writes **5013**.

Exclusions are a special case. They appear in that list, but Microsoft's [exclusion protection page](https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-antivirus-exclusions) sets conditions:

- platform version 4.18.2211.5 or later;
- `DisableLocalAdminMerge` enabled, so that local exclusions are not merged with managed ones;
- the device managed only by Intune or only by Configuration Manager, with the Defender for Endpoint sensor enabled: `ManagedDefenderProductType` under `HKLM\SOFTWARE\Microsoft\Windows Defender` is 6 (Intune) or 7 with `EnrollmentStatus` 4 under `HKLM\SOFTWARE\Microsoft\SenseCM` (Configuration Manager);
- exclusions managed in Intune or Configuration Manager.

`TPExclusions` under `HKLM\SOFTWARE\Microsoft\Windows Defender\Features` is 1 when exclusions are protected and 0 when they are not. On a standalone workstation, or one managed by Group Policy, a local administrator can add exclusions while tamper protection is on. Bhabesh Raj [reported in 2020](https://bhabeshraj.com/post/tampering-with-microsoft-defenders-tamper-protection) that tamper protection did not protect exclusions, before the conditional protection existed. So the pattern "5013 for real-time protection, then 5007 for an exclusion a minute later" is not a contradiction: the intruder tried a protected setting first and an unprotected one next.

## Reading 5007

Two real 5007 events from the [Sigma regression data](https://github.com/SigmaHQ/sigma/tree/master/regression_data/rules/windows/builtin/windefend), recorded in 2026:

| Change | Old Value | New Value |
| --- | --- | --- |
| Exclusion added | (empty) | `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\AtomicRedTeam = 0x0` |
| Setting changed | `Default\SpyNet\DisableBlockAtFirstSeen = 0x0` | `HKLM\SOFTWARE\Microsoft\Windows Defender\SpyNet\DisableBlockAtFirstSeen = 0x1` |

- The new value is a registry path: the subkey says what kind of exclusion, the last element is the excluded item, and `= 0x0` is the value's data.
- `Default\` in the old value means the setting was at its default.
- The event's security user ID is `S-1-5-18`. Defender's service writes it; the event never says who made the change.
- Bhabesh Raj filters for an old value ending in `TamperProtection = 0x5` and a new value ending in `TamperProtection = 0x4` to catch tamper protection being switched off. Microsoft does not document those values.

## Reading 5013

5013 names the registry value and data that were refused, for example a value ending in `\Real-Time Protection\DisableRealtimeMonitoring`, which is what the [Sigma rule](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/windefend/win_defender_tamper_protection_trigger.yml) looks for. In a [Tech Community thread](https://techcommunity.microsoft.com/discussions/microsoftdefenderatp/enabling-tamper-protection-with-tenant-attach/3255236), an administrator produced 5013 with `Set-MpPreference -DisableRealtimeMonitoring $true` and with `-DisableIOAVProtection`, and found that `MpCmdRun.exe -RemoveDefinitions -All` on the same tamper-protected machine returned an error and wrote no event at all. The same administrator saw about 25 benign 5013 at each Group Policy refresh, from Configuration Manager rewriting protected values under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`. A 5013 for a `Policies` value at a regular interval is management noise; a single 5013 for `DisableRealtimeMonitoring` minutes after a detection is not.

A 5013 with no 5001 after it means the change failed. Confirm with the next 1151 health report, which states the real-time protection state.

## The registry

| Key | Content |
| --- | --- |
| `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`, `\Processes`, `\Extensions` and others | Local exclusions: one value per excluded item, named after it |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\...` | Exclusions set by Group Policy |
| `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection` and the `Policies` equivalent | Settings such as `DisableRealtimeMonitoring` |
| `HKLM\SOFTWARE\Microsoft\Windows Defender\Features` | `TamperProtection`, `TPExclusions` |

Points that matter in an investigation:

- **Last write times are per key.** All path exclusions share one `Paths` key, so its last write time is the time of the latest change to any of them, as Dissect's [`defender.exclusions`](https://docs.dissect.tools/en/latest/plugins/defender.exclusions.html) plugin points out. An exclusion added a year ago and one added yesterday show yesterday's time. The 5007 events date each one.
- **Local and managed lists are merged** by default ([Microsoft](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-overview)). Read both keys.
- **Managed devices may show nothing.** From platform 4.18.25110.6, devices managed with Defender for Endpoint security settings management no longer keep readable exclusion values in the registry ([Microsoft 365 message MC1227621](https://mc.merill.net/message/MC1227621), rolled out in March 2026). There, `Get-MpPreference` on the live host is the source.
- **Reading the key needs administrator rights.** Since the February 2022 updates, the `Exclusions` key no longer grants read access to everyone ([Neowin](https://www.neowin.net/news/microsoft-finally-makes-bypassing-defender-scans-harder-by-changing-exclusions-permission/)). The *visible to Local Admins* policy goes further and hides the list from `Get-MpPreference`; Jonathan Johnson at Huntress found that it hides it from PowerShell queries run as SYSTEM too, while administrators and SYSTEM can still read the values in the registry ([Huntress](https://www.huntress.com/blog/you-can-run-but-you-cant-hide-defender-exclusions)). A saved hive read offline shows them.

### What each exclusion type does

Microsoft's [exclusions overview](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-overview) is precise, and the difference matters when you explain what an intruder gained:

- A **path** exclusion skips scanning of the file or of everything under the folder. An executable in an excluded folder is not scanned when it is written or run.
- A **process** exclusion skips the files that the process opens. It does not exclude the process's own executable; that needs a path exclusion. A process exclusion given as a bare image name, such as `m64.exe`, applies to any process with that name, wherever it runs from, including removable media.
- An **extension** exclusion applies to every file with that extension, anywhere.

A path exclusion on a folder and a process exclusion on the image name of a tool inside it, together, mean the tool is not scanned and neither is any file it opens.

## Who did it

No Defender event identifies the account behind a configuration change. Look elsewhere:

- **PowerShell.** `Set-MpPreference` and `Add-MpPreference` are cmdlets over the WMI class `MSFT_MpPreference`; they do not start `MpCmdRun.exe`, so `MpCmdRun.log` has nothing. Look in the `Microsoft-Windows-PowerShell/Operational` log ([Microsoft](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)) for script block (4104) and module (4103) events, which carry the user, in transcripts if enabled, and in each user's PSReadLine history, `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`. The history has one command per line and [no timestamps](https://learn.microsoft.com/en-us/powershell/module/psreadline/about/about_psreadline); the Defender events give the times.
- **Process creation.** Security event 4688 or Sysmon event 1, if enabled, for `reg.exe`, `MpCmdRun.exe` and `powershell.exe` with their command lines.
- **Logon sessions.** Who was logged on, interactively or over RDP, at the time of the 5007.
- **Defender for Endpoint**, where deployed: tampering attempts are in the `DeviceEvents` table with `ActionType == "TamperingAttempt"`.

## MpCmdRun.log

`MpCmdRun.exe` appends a block to `MpCmdRun.log` for each run. Defender's own scheduled runs are in `C:\Windows\Temp\MpCmdRun.log`. LOLBAS points to `%USERPROFILE%\AppData\Local\Temp\MpCmdRun.log` when a user runs the tool, and Dissect's [`defender.mpcmdrun`](https://docs.dissect.tools/en/latest/plugins/defender.mpcmdrun.html) plugin looks in `C:\Windows\Temp`, `C:\Windows.old\Windows\Temp` and every profile's `AppData\Local\Temp`. Collect all of them.

The file is UTF-16LE. Each block sits between lines of dashes, as in Dissect's test file (shortened):

```text
-------------------------------------------------------------------------------------
MpCmdRun: Command Line: "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2203.5-0\MpCmdRun.exe" -EnableService
 Start Time: Mon Nov 03 2025 13:08:19

EnableService(1, 3)
Starting WinDefend ...
MpCmdRun: End Time: Mon Nov 03 2025 13:08:20
-------------------------------------------------------------------------------------
```

- The times are local, without a zone, and the real file has invisible left-to-right marks around each part of the date. Dissect strips them and applies the machine's time zone. Some blocks have no start time.
- Most blocks are Defender's own: `SignatureUpdate -ScheduleJob`, `-EnableService` and similar.
- Worth a look: `-RemoveDefinitions`, `-Restore`, `-DownloadFile`, `-CheckExclusion` (someone testing whether a path is excluded), `-AddDynamicSignature`, and any run from an unusual path or a copy of the binary under another name, which is the LOLBAS bypass.
- `-GetFiles` is usually the responder: it writes `MpSupportFiles.cab` into the Support folder.

## On FIN-WKS-07

In the fictional case used on this site, an attempt to switch off real-time protection is refused (5013), and less than a minute later two 5007 events add `C:\ProgramData\Intel` as a path exclusion and `m64.exe` as a process exclusion. Both `Exclusions` subkeys have a last write time of 10:08:12 UTC, and the implant runs from the excluded folder at 10:09:44 without a detection. The [walk-through](/en/blog/defender-investigation-walkthrough) follows it source by source.

## Checklist

1. List every value under both `Exclusions` keys from the saved `SOFTWARE` hive, with each subkey's last write time.
2. List every 5007, 5001, 5010, 5012 and 5013 in the Operational log, with old and new values.
3. Read the `[Exclusion]` lists and RTP perf logs in [MPLog](/en/blog/mplog-defender-support-logs) to see which exclusions were in effect, and from when.
4. Read `TPExclusions` and `ManagedDefenderProductType` to know whether tamper protection covered exclusions, and the 1151 health reports for the real-time protection state.
5. Read every `MpCmdRun.log`.
6. Match each change to a PowerShell event, a history line or a process creation, and to a logon session.
7. List the files under every excluded path and check them in Amcache, Prefetch and the file system: an exclusion is there to protect something.

## FAQ

### Where are Defender exclusions stored in the registry?

Locally set exclusions are under HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions, in subkeys such as Paths, Extensions and Processes; each exclusion is a value whose name is the excluded item. Exclusions set by Group Policy are under HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions. On devices managed with Defender for Endpoint security settings management, Microsoft stopped storing readable exclusion values in the registry from platform 4.18.25110.6.

### Can I tell when an exclusion was added?

The last write time of the Paths, Processes or Extensions key gives the time of the last change to that key, not to one value. Event 5007 gives the time of each change with the value that was written. Use both: the key time dates the last change, the 5007 events date each addition while the log still holds them.

### Does tamper protection stop attackers from adding exclusions?

Only under conditions Microsoft lists: platform 4.18.2211.5 or later, DisableLocalAdminMerge enabled, a device managed only by Intune or only by Configuration Manager with the Defender for Endpoint sensor on, and exclusions managed centrally. A TPExclusions value of 1 under HKLM\SOFTWARE\Microsoft\Windows Defender\Features confirms it. Elsewhere, a local administrator can add exclusions while tamper protection is on.

### Why is there a 5013 event but no 5001?

Because tamper protection refused the change. 5013 names the setting someone tried to change; real-time protection stayed on, so no 5001 was written. It shows intent and failure. Check the setting and the time, since management tools can also produce 5013 events.

## Related articles

- [The Defender Operational event IDs that matter](/en/blog/defender-operational-event-ids)
- [Investigating an intrusion with Defender artifacts](/en/blog/defender-investigation-walkthrough)
- [Collecting Microsoft Defender artifacts](/en/blog/collect-defender-artifacts)
