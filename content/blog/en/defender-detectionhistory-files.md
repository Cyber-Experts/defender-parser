---
title: "Defender DetectionHistory Files: What They Hold"
description: "How to read Microsoft Defender's DetectionHistory files: threat, status, resources, hashes, user, process and times, and how they join 1116 and the quarantine."
date: "2026-11-19"
author: "Florian Amette"
tags: ["defender", "detection-history", "hashes", "dfir"]
series: "defender-fundamentals"
seriesTitle: "Microsoft Defender Antivirus artifacts"
seriesOrder: 3
faq:
  - question: "Where are the Defender DetectionHistory files?"
    answer: "In C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Service\\DetectionHistory\\, in numbered subfolders, one file per detection. Each file is named after the detection's GUID, the Detection ID that also appears in events 1116 and 1117. Reading the folder requires administrator rights."
  - question: "Which hashes does a DetectionHistory file contain?"
    answer: "For a detected file, the tracking data holds ThreatTrackingSha256, ThreatTrackingSha1 and ThreatTrackingMD5, with ThreatTrackingSize. ThreatTrackingSigSha is the hash of the signature that matched, not of the file. Use the file hashes to search Amcache, MPLog and threat intelligence, and to check a file recovered from the quarantine."
  - question: "Does a DetectionHistory file show which user was involved?"
    answer: "It keeps a user and a process per detection, which WMI exposes as DomainUser and ProcessName; Microsoft describes DomainUser as the user who requested remediation. In Orange Cyberdefense's public sample, the user is the account that ran PowerShell, where the 1116 event often shows SYSTEM. Treat it as a lead and confirm it with logon sessions and per-user artifacts."
  - question: "Can I read DetectionHistory on a live system without parsing the files?"
    answer: "Yes. Get-MpThreatDetection, or the WMI class MSFT_MpThreatDetection in root\\Microsoft\\Windows\\Defender, returns the same detections with their status, resources, user, process and times. It does not return the hashes, so collect the files as well."
---

**TL;DR.** Microsoft Defender writes one binary file per detection under `C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\`, in numbered subfolders. The file is named after the **Detection ID**, the GUID of events 1116 and 1117. It holds the threat ID and name, the **threat status** (detected, quarantined, removed, allowed...), the **resources** with **tracking data** (MD5, SHA-1, SHA-256, size, start time), the **user** and **process**, and the initial detection, remediation and last status change **times** in UTC. It is what Windows Security shows as Protection history, and `Get-MpThreatDetection` reads the same records. It survives a rolled-over event log, not a deletion. The format is undocumented: research by Jordan Klepser and Orange Cyberdefense names part of it, and many values are still unnamed. [Defender Parser](/en#tool) reads the files and joins them to the events and the quarantine.

## Where they are and when they are written

`C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\<n>\<GUID>`, one file per detection, readable by administrators and SYSTEM.

Jordan Klepser, who wrote [DHParser](https://github.com/jklepsercyber/defender-detectionhistory-parser) and described it on the [SANS blog](https://www.sans.org/blog/uncovering-windows-defender-real-time-protection-history-with-dhparser/), found the files on Windows 10 and documented these points:

- A file is created when real-time or cloud-delivered protection blocks a threat. Whether the user then runs the file makes no difference to its creation.
- The Windows Security app's Protection history lists the detections from these files. Deleting a file removes the entry from Protection history.
- On a live host, the WMI class [MSFT_MpThreatDetection](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mpthreatdetection), which `Get-MpThreatDetection` queries, shows the same data.

Orange Cyberdefense's [wddh](https://github.com/cert-orangecyberdefense/wddh-parser) confirmed that the file name is the Detection ID: in their public sample, file `94BBE9CF-CDEB-4885-9178-CC93FB10822D` is the detection WMI reports as `{94BBE9CF-CDEB-4885-9178-CC93FB10822D}`.

## The format

Orange Cyberdefense describes the file as a list of typed values: a length, a type, the data, then padding to an 8-byte boundary. The types seen are 32- and 64-bit integers, FILETIMEs, UTF-16 strings, GUIDs and a key-value block they call a dictionary. They split the file into eight sections, analysed against Defender 4.18.24090.11 on Windows 10, and they matched values against what WMI returns for the same detection. Their [format notes](https://github.com/cert-orangecyberdefense/wddh-parser/blob/main/doc.md), Klepser's README, the [libyal dtformats documentation](https://github.com/libyal/dtformats/blob/main/documentation/Windows%20Defender%20scan%20DetectionHistory%20file%20format.asciidoc) and plaso's [`windefender_history` parser](https://github.com/log2timeline/plaso/blob/main/plaso/parsers/windefender_history.py) are the public references. Microsoft documents only the WMI view.

| Section (wddh) | What it holds | Known from |
| --- | --- | --- |
| 1, header | Threat ID, Detection ID, an optional `Magic.Version:1.2` string (absent in some Windows Server 2016 samples), the threat name | wddh, DHParser |
| 2, flags | A list of 32-bit values, one of them the threat status ID; the others are not named | wddh |
| 3, resources | For each resource: a type (`file`, `behaviour`, `internalbehavior`...), a location, and a block of tracking data | wddh, DHParser |
| 4, status | Last threat status change time, threat status error code | wddh, against WMI |
| 6, context | User, process, initial detection time, remediation time, and a second account name | wddh, against WMI |
| 5, 7, 8 | Optional block, repeated resources, footer | Mostly unknown |

Many values in sections 2, 4, 6 and 8 have no known meaning. A parser that reads them all, as wddh does, keeps them as numbered unknowns. Do not build a finding on a value nobody has named.

### Tracking data

The block attached to each resource is a list of named keys. Klepser's list, which wddh's sample also shows:

| Key | Content |
| --- | --- |
| `ThreatTrackingSha256`, `ThreatTrackingSha1`, `ThreatTrackingMD5` | Hashes of the detected file |
| `ThreatTrackingSize` | Its size in bytes |
| `ThreatTrackingStartTime` | A FILETIME in UTC |
| `ThreatTrackingThreatId`, `ThreatTrackingThreatName` | The threat |
| `ThreatTrackingSigSeq`, `ThreatTrackingSigSha` | The signature that matched; `SigSha` is not a hash of the file |
| `ThreatTrackingScanSource`, `ThreatTrackingScanType`, `ThreatTrackingScanFlags`, `ThreatTrackingIsEsuSig` | Scan context, values undocumented |
| `ThreatTrackingId` | A GUID |
| `regkey`, `uninstall` | Seen for potentially unwanted applications: registry locations, sometimes with a user SID |

In wddh's sample, `ThreatTrackingStartTime` is within a millisecond of the initial detection time.

### Threat status

The status is the `ThreatStatusID` enumeration of MSFT_MpThreatDetection. Klepser notes that Defender updates it in the file as actions are taken.

| Value | Status |
| --- | --- |
| 0 | Unknown |
| 1 | Detected |
| 2 | Cleaned |
| 3 | Quarantined |
| 4 | Removed |
| 5 | Allowed |
| 6 | Blocked |
| 102 | QuarantineFailed |
| 103 | RemoveFailed |
| 104 | AllowFailed |
| 105 | Abandoned |
| 107 | BlockedFailed |

Microsoft's page also lists *CleanFailed*, with a garbled value; Velociraptor's artifact maps it to 7. **Allowed** and the failed statuses are the ones to chase: the threat was left in place.

## A public example

Orange Cyberdefense's sample, as WMI and wddh read it:

| Field | Value |
| --- | --- |
| Threat | `HackTool:Win32/Mimikatz`, threat ID 2147686744 |
| Status | Quarantined |
| Resource | `file`, `C:\Users\RaptorSniper\Downloads\a.zip` |
| User | `DESKTOP-O8964S4\RaptorSniper` |
| Second account | `NT AUTHORITY\SYSTEM` |
| Process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Initial detection | 2025-01-28 16:44:51 UTC |
| Remediation | 2025-01-28 16:45:06 UTC |
| Detection source (WMI) | 3, real-time |

Three things the event log would not have given as cleanly: the hashes, a real user account, and the process that touched the archive. What the second account name means is not established. DHParser labels it a security group, by guess.

## What it adds to the event log

- **Hashes and size** of the detected file. 1116 has none.
- **A user.** Microsoft's WMI documentation describes `DomainUser` as the user who requested remediation. In the sample above it is the account that ran PowerShell, where 1116's `Detection User` is often SYSTEM. It is still a lead, not proof.
- **Status over time.** The file is updated when the threat is quarantined, removed, restored or allowed.
- **Longer life.** The files are independent of the Operational log's size. They do not last forever: Microsoft's default for removing items from the scan history is 30 days ([remediation settings](https://learn.microsoft.com/en-us/defender-endpoint/configure-remediation-microsoft-defender-antivirus)), and the DetectionHistory folder sits under `Scans\History`. Check the configured value before you explain a gap.

## Joining it with the rest

| Key | DetectionHistory | Elsewhere |
| --- | --- | --- |
| Detection ID | File name, section 1 | [1116 and 1117](/en/blog/defender-operational-event-ids) |
| Threat ID | Section 1, tracking data | 1116, [quarantine entry](/en/blog/defender-quarantine-file-recovery), MPLog blocks |
| SHA-1 | Tracking data | Amcache; `File to act on SHA1` in MPLog's threat action blocks |
| SHA-256 | Tracking data | Event 2050; the file recovered from the quarantine; threat intelligence |
| Path and time | Resource, initial detection time | 1116 `Path` and `Detection Time`; MPLog `DETECTIONEVENT` lines |

The SHA-256 is also how you check that a file still on disk, or one found later in an excluded folder, is the same file Defender caught.

## What it does not prove

- **Execution.** Klepser is explicit that the file is created whether or not the detected executable runs. MSFT_MpThreatDetection has a `CurrentThreatExecutionStatusID` (Unknown, Blocked, Allowed, Executing, NotExecuting); in Orange's sample it is 1, Blocked. Which bytes of the file hold it is not established.
- **Completeness.** A missing file can be a detection that never happened, one older than the retention, or one deleted from Protection history. Event 1013 records deleted history, including routine purges.

## Parsers

| Tool | Approach | Notes |
| --- | --- | --- |
| [DHParser](https://github.com/jklepsercyber/defender-detectionhistory-parser) (Jordan Klepser) | Finds known markers and key-value pairs in the bytes; JSON output | Version 1.0.1, 2022; ships a KAPE target and module |
| [wddh](https://github.com/cert-orangecyberdefense/wddh-parser) (Orange Cyberdefense) | Reads every typed value in order; named fields checked against WMI | Many values left as unknown flags |
| plaso `windefender_history` | Part of plaso's timeline | Threat, status, file, container and web file names, user, process, SHA-256, the three times |
| [Velociraptor `Windows.Applications.DefenderHistory`](https://docs.velociraptor.app/exchange/artifacts/pages/windows.applications.defenderhistory/) | Fixed offsets in the first part of the file | Exchange artifact, on the endpoint |
| [Velociraptor `Windows.Applications.DefenderDHParser`](https://docs.velociraptor.app/exchange/artifacts/pages/defenderdhparser/) | Runs DHParser on the endpoint | Exchange artifact |
| Defender Parser | Reads the files and joins them with the events and the quarantine | In the browser |

Dissect's Defender plugin does not read DetectionHistory files.

## FAQ

### Where are the Defender DetectionHistory files?

In C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\, in numbered subfolders, one file per detection. Each file is named after the detection's GUID, the Detection ID that also appears in events 1116 and 1117. Reading the folder requires administrator rights.

### Which hashes does a DetectionHistory file contain?

For a detected file, the tracking data holds ThreatTrackingSha256, ThreatTrackingSha1 and ThreatTrackingMD5, with ThreatTrackingSize. ThreatTrackingSigSha is the hash of the signature that matched, not of the file. Use the file hashes to search Amcache, MPLog and threat intelligence, and to check a file recovered from the quarantine.

### Does a DetectionHistory file show which user was involved?

It keeps a user and a process per detection, which WMI exposes as DomainUser and ProcessName; Microsoft describes DomainUser as the user who requested remediation. In Orange Cyberdefense's public sample, the user is the account that ran PowerShell, where the 1116 event often shows SYSTEM. Treat it as a lead and confirm it with logon sessions and per-user artifacts.

### Can I read DetectionHistory on a live system without parsing the files?

Yes. Get-MpThreatDetection, or the WMI class MSFT_MpThreatDetection in root\Microsoft\Windows\Defender, returns the same detections with their status, resources, user, process and times. It does not return the hashes, so collect the files as well.

## Related articles

- [The Defender Operational event IDs that matter](/en/blog/defender-operational-event-ids)
- [Defender quarantine: format and safe file recovery](/en/blog/defender-quarantine-file-recovery)
- [MPLog files: reading Defender's support logs](/en/blog/mplog-defender-support-logs)
