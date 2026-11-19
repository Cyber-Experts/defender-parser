---
title: "Investigating an Intrusion with Defender Artifacts"
description: "A worked case: a quarantined backdoor, a refused attempt to stop real-time protection, two exclusions and an AMSI detection, joined across Defender sources."
date: "2026-11-19"
author: "Florian Amette"
tags: ["defender", "incident-response", "timeline", "defense-evasion"]
series: "defender-investigations"
seriesTitle: "Investigating with Defender artifacts"
seriesOrder: 1
faq:
  - question: "Which Defender source should I read first?"
    answer: "The Operational log, in time order: it gives the detections, the actions and the configuration changes with their times. Then expand each detection with its DetectionHistory file and quarantine entry, check every configuration change against the SOFTWARE hive, and finish with MPLog for what Defender saw but did not detect."
  - question: "If Defender quarantined the malware, is the incident over?"
    answer: "No. A detection shows what the intruder brought, not what they did next. On FIN-WKS-07, m64.exe was quarantined at 10:06:52, then unpacked again from the same archive into an excluded folder and running three minutes later. After a detection, read every configuration change that follows it and every program that runs from an excluded path."
  - question: "How do I show that a file in an excluded folder is the malware Defender caught earlier?"
    answer: "Compare hashes. The DetectionHistory file gives the SHA-1 and SHA-256 of the detected file, and the copy recovered from the quarantine can be hashed in a lab. Amcache (SHA-1), the file itself or a copy from a shadow copy gives the hash of the file in the excluded folder. Equal hashes make it the same file; different ones make it a different build to analyse."
  - question: "Does a 5013 event mean real-time protection stayed on?"
    answer: "It means that one change was refused. Check that no 5001 follows, that the next 1151 health report shows real-time protection enabled, and that the SOFTWARE hive does not hold the setting. Then look for what the intruder tried next: on FIN-WKS-07, an exclusion."
---

**TL;DR.** On FIN-WKS-07, Defender caught the intruder's backdoor, and the intruder worked around it. Real-time protection detected and quarantined `m64.exe` twelve seconds after 7-Zip opened `tools.zip` (1116 and 1117, with a DetectionHistory file and a quarantine entry; the quarantined content carries no `Zone.Identifier`). Tamper protection then refused an attempt to switch real-time protection off (5013). Less than a minute later, two exclusions went in without resistance (two 5007 at 10:08:12, matching the last write time of the `Exclusions` keys), and the implant ran from the excluded folder at 10:09:44 with no detection. At 10:12:03 AMSI caught an AMSI bypass string in PowerShell. The method: read the Operational log in time order, expand each detection with DetectionHistory and the quarantine, check each configuration change against the hive, then look for what Defender did not detect. [Defender Parser](/en#tool) joins these sources and builds the timeline.

## The case

FIN-WKS-07 is a fictional Windows 11 workstation. The people, accounts, files, URLs, threat names and times are synthetic, and match the other examples on this site; the threat names are invented families written in Defender's naming format. All times are UTC.

What other artifacts already established, before Defender is opened:

- alice ran `C:\Users\alice\Downloads\Invoice_2026-0914.pdf.exe` at 09:12:07.
- A local account, svc_backup, was created at 09:57:41 and logged on over RDP at 09:59:28.
- A PowerShell download cradle ran at 10:02:11, and `http://files.example/tools.zip` was saved to `C:\Users\svc_backup\Downloads\tools.zip` at 10:03:05.
- 7-Zip opened `tools.zip` at 10:06:40.
- `C:\ProgramData\Intel\m64.exe` first ran at 10:09:44, and rclone at 10:47:12.

The responder collected the Defender folders, the Operational log, every `MpCmdRun.log`, the SOFTWARE and SYSTEM hives and the PowerShell logs and history at 10:55:12, as described in [collecting Defender artifacts](/en/blog/collect-defender-artifacts).

## Step 1: read the Operational log in time order

| Time | ID | Content |
| --- | --- | --- |
| 10:06:51 | 1116 | `Backdoor:Win64/Gfxhelp.A`, resource `file:_C:\Users\svc_backup\Downloads\tools\m64.exe`, source real-time protection |
| 10:06:52 | 1117 | Same detection ID, action Quarantine |
| 10:07:36 | 5013 | Tamper protection refused a change to a value ending in `\Real-Time Protection\DisableRealtimeMonitoring` |
| 10:08:12 | 5007 | New value `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\ProgramData\Intel = 0x0` |
| 10:08:12 | 5007 | New value `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes\m64.exe = 0x0` |
| 10:12:03 | 1116 | `Trojan:PowerShell/AmsiBypass.SY`, source AMSI, an `amsi:` resource naming the PowerShell host process |
| 10:12:03 | 1117 | Same detection ID, the content blocked |

There is no 5001, 5010 or 5012: protection was never switched off. There is no detection between 10:08:12 and the AMSI event, although the implant ran in between. Seven events, and the story is already visible: a detection, a refused attempt to stop protection, exclusions covering the name of the very file that was detected, then silence. What each event means is in [the Defender Operational event IDs](/en/blog/defender-operational-event-ids).

## Step 2: expand the first detection

### The 1116

- **The name** follows Microsoft's [naming scheme](https://learn.microsoft.com/en-us/defender-xdr/malware-naming): type `Backdoor`, platform `Win64`, family `Gfxhelp`, variant `A`. It is Defender's verdict on the file, not an attribution.
- **The source** is real-time protection: the file was scanned on access, when it was written or opened.
- **The timing** is twelve seconds after 7-Zip opened `tools.zip`, for a file in `Downloads\tools\`. That fits a detection during extraction, before anything ran. `Process Name` helps: if it names the archiver, the file was most likely caught as it was written. A 1116 does not prove execution, and here the sequence argues against it.

### The DetectionHistory file

Its name is the 1116's Detection ID. It adds what the event lacks: the MD5, SHA-1 and SHA-256 of `m64.exe`, its size, the status Quarantined, the initial detection and remediation times, and a user and process for the detection. Compare the user with the logon sessions of 10:06 rather than take it as proof. Keep the hashes for step 4. The format is described in [DetectionHistory files](/en/blog/defender-detectionhistory-files).

### The quarantine entry

The Entries file names the same threat, the original path `\\?\C:\Users\svc_backup\Downloads\tools\m64.exe`, the file's size and its creation, last access and last write times, which belong in the timeline next to the 7-Zip launch. Decrypted, the quarantined content holds the file's data and its security descriptor, and nothing else: no `Zone.Identifier` stream. Defender Parser hands the file over only as a ZIP encrypted with the password `infected`.

The missing Mark of the Web is expected here, and it is not evidence that the file was made on the host. `tools.zip` was saved by `Invoke-WebRequest`, which is not known to write a `Zone.Identifier`, and 7-Zip copies an archive's Mark of the Web to extracted files only when its *Propagate Zone.Id stream* option is set, which is off by default ([SANS ISC](https://isc.sans.edu/diary/28810)); `WriteZoneIdExtract` under `Software\7-Zip\Options` in svc_backup's NTUSER.DAT tells you which. The link between the binary and the download comes from elsewhere: the extraction path under `Downloads\tools`, the 7-Zip launch at 10:06:40 and the PowerShell download at 10:03:05. Handling the recovered file is covered in [the quarantine article](/en/blog/defender-quarantine-file-recovery).

## Step 3: the attempt to stop Defender, then the exclusions

### 10:07:36: refused

The 5013 names `DisableRealtimeMonitoring`. svc_backup's PSReadLine history contains `Set-MpPreference -DisableRealtimeMonitoring $true`, the command that would set it. The history has no timestamps; the 5013 gives the time. No 5001 follows, so real-time protection stayed on, as the next 1151 health report would confirm.

### 10:08:12: accepted

Two 5007 events in the same second, and the SOFTWARE hive agrees with them:

| Key | Value | Last write |
| --- | --- | --- |
| `Microsoft\Windows Defender\Exclusions\Paths` | `C:\ProgramData\Intel` | 10:08:12 |
| `Microsoft\Windows Defender\Exclusions\Processes` | `m64.exe` | 10:08:12 |

The events date each addition; the hive shows both were still in place at collection. A key's last write time covers the whole key, so on its own it would only say that the last change to `Paths` was at 10:08:12.

Tamper protection is on in the hive, yet the exclusions went in. That is consistent with Microsoft's documentation: tamper protection protects exclusions only on devices managed only by Intune or only by Configuration Manager, with `DisableLocalAdminMerge` and centrally managed exclusions ([Microsoft](https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-antivirus-exclusions)). Read `TPExclusions` under `Microsoft\Windows Defender\Features` and quote its value in the report, so nobody argues that tamper protection failed.

The same history contains `Add-MpPreference -ExclusionPath C:\ProgramData\Intel`, which accounts for the path exclusion. **Nothing in it accounts for the process exclusion.** Write that down as an open question and look for it in the PowerShell Operational log around 10:08:12 and in any transcript.

### What the two exclusions give the intruder

From Microsoft's [exclusions overview](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-overview): the path exclusion stops Defender scanning anything under `C:\ProgramData\Intel`, including `m64.exe` itself. The process exclusion, given as a bare image name, stops it scanning the files opened by any process named `m64.exe`, wherever it runs from. Together, the implant and every file it opens are out of reach of antivirus scanning. Microsoft adds that excluded files can still raise EDR and behavioural detections. The wider picture is in [Defender exclusions and tampering](/en/blog/defender-exclusions-tampering).

## Step 4: the implant runs where Defender does not look

`C:\ProgramData\Intel\m64.exe` first ran at 10:09:44, a minute and a half after the exclusions, and no Defender event mentions it. That silence is the expected result of the exclusion, not evidence that the file is harmless.

- **How it got there.** svc_backup's PSReadLine history also has `Expand-Archive C:\Users\svc_backup\Downloads\tools.zip C:\ProgramData\Intel`: the same archive, unpacked again into the folder that was now excluded.
- **Is it the same file?** Compare the SHA-1 and SHA-256 from the DetectionHistory file with the hash of `C:\ProgramData\Intel\m64.exe` from Amcache or from the file. Equal hashes make it the very file Defender quarantined at 10:06:52; anything else is a second build to analyse.
- **MPLog.** If an `[Exclusion]` list written after 10:08:12 names `C:\ProgramData\Intel`, it dates when the real-time exclusion list took the change. Expect nothing about the excluded `m64.exe` after that. See [MPLog files](/en/blog/mplog-defender-support-logs).

## Step 5: the AMSI detection

At 10:12:03, Defender detected `Trojan:PowerShell/AmsiBypass.SY` with source AMSI and blocked it. An AMSI detection is about content passed to the scan interface, here by PowerShell, not about a file: the resource is the host process, and there is no file to quarantine. The PowerShell Operational log has a warning-level script block (4104) with an AMSI bypass string in the same second, and that event, unlike the 1116, names the user.

What it shows: the bypass attempt itself was caught, AMSI was working in that PowerShell session at 10:12:03, and the intruder was still trying to blind Defender four minutes after the exclusions. The process exclusion for `m64.exe` does not cover PowerShell.

## Step 6: what Defender did not detect

- **The invoice.** alice's `Invoice_2026-0914.pdf.exe` ran at 09:12:07 and has no 1116, no DetectionHistory file and no quarantine entry. MPLog is the only Defender source that mentions it: the engine scanned it and found nothing. That proves the file was there and was looked at; Defender's verdict at the time was clean.
- **rclone** at 10:47:12. A legitimate file transfer tool, and Defender raised no detection for it. The exfiltration has to be shown from other artifacts.
- **The implant after 10:08:12**, as above.

## The timeline

| Time (UTC) | Event | Source |
| --- | --- | --- |
| 09:12:07 | alice runs `Invoice_2026-0914.pdf.exe`; the engine scans it, no detection | Other artifacts; MPLog |
| 09:57:41 | Local account svc_backup created | Security log (4720) |
| 09:59:28 | svc_backup logs on over RDP | Security log (4624) |
| 10:02:11 | PowerShell download cradle | PowerShell Operational (4104) |
| 10:03:05 | `tools.zip` saved to svc_backup's Downloads | PowerShell Operational (4103) |
| 10:06:40 | 7-Zip opens `tools.zip` | Windows Timeline |
| 10:06:52 | `Downloads\tools\m64.exe` detected as `Backdoor:Win64/Gfxhelp.A` and quarantined | 1116, 1117, DetectionHistory, quarantine entry |
| 10:07:36 | Attempt to switch off real-time protection refused | 5013; PSReadLine history (no time) |
| 10:08:12 | Exclusions added: path `C:\ProgramData\Intel`, process `m64.exe` | 5007 ×2; `Exclusions` keys' last write |
| 10:09:44 | `C:\ProgramData\Intel\m64.exe` first runs, no detection | Other artifacts |
| 10:12:03 | AMSI bypass string detected and blocked | 1116, 1117; PowerShell Operational (4104) |
| 10:47:12 | rclone runs | Other artifacts |
| 10:55:12 | Collection | Responder's notes |

## How the sources join

| Join | Key |
| --- | --- |
| 1116 ↔ 1117 | Detection ID |
| 1116 ↔ DetectionHistory | Detection ID, which is the file name |
| 1116 ↔ quarantine entry | Threat ID and name, original path, time |
| DetectionHistory ↔ the excluded copy | SHA-1 and SHA-256 |
| 5007 ↔ SOFTWARE hive | Registry path and value, last write time |
| 5013, 5007 ↔ PowerShell | Time and command; PSReadLine has no times |
| AMSI 1116 ↔ 4104 | Time, host process |

Defender Parser does the Defender side of this table: it reads the quarantine, DetectionHistory, MPLog, the Operational log, `MpCmdRun.log` and the SOFTWARE hive's Defender keys, joins each detection across them, shows the protection changes and a timeline, and flags the exclusions and events worth a look. The result exports to CSV, JSON or Markdown for the report.

## Writing it up

- State what each source shows: "The Defender Operational log on FIN-WKS-07 records a real-time detection of `C:\Users\svc_backup\Downloads\tools\m64.exe` as `Backdoor:Win64/Gfxhelp.A` at 10:06:51 UTC and its quarantine at 10:06:52." Not "svc_backup ran a backdoor at 10:06".
- Say that 5007 and 5013 do not name a user, and where the attribution comes from instead.
- Quote `TPExclusions` when you explain why tamper protection did not stop the exclusions.
- List the open questions: where the process exclusion came from, whether the downloaded archive ever carried a Mark of the Web, and whether the implant's hash matches the quarantined file's.

## FAQ

### Which Defender source should I read first?

The Operational log, in time order: it gives the detections, the actions and the configuration changes with their times. Then expand each detection with its DetectionHistory file and quarantine entry, check every configuration change against the SOFTWARE hive, and finish with MPLog for what Defender saw but did not detect.

### If Defender quarantined the malware, is the incident over?

No. A detection shows what the intruder brought, not what they did next. On FIN-WKS-07, m64.exe was quarantined at 10:06:52, then unpacked again from the same archive into an excluded folder and running three minutes later. After a detection, read every configuration change that follows it and every program that runs from an excluded path.

### How do I show that a file in an excluded folder is the malware Defender caught earlier?

Compare hashes. The DetectionHistory file gives the SHA-1 and SHA-256 of the detected file, and the copy recovered from the quarantine can be hashed in a lab. Amcache (SHA-1), the file itself or a copy from a shadow copy gives the hash of the file in the excluded folder. Equal hashes make it the same file; different ones make it a different build to analyse.

### Does a 5013 event mean real-time protection stayed on?

It means that one change was refused. Check that no 5001 follows, that the next 1151 health report shows real-time protection enabled, and that the SOFTWARE hive does not hold the setting. Then look for what the intruder tried next: on FIN-WKS-07, an exclusion.

## Related articles

- [Defender exclusions and tampering: finding the traces](/en/blog/defender-exclusions-tampering)
- [Collecting Microsoft Defender artifacts](/en/blog/collect-defender-artifacts)
- [The Defender Operational event IDs that matter](/en/blog/defender-operational-event-ids)
