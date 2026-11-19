---
title: "Defender Operational Log: The Event IDs That Matter"
description: "Which Microsoft Defender Antivirus events to read in an investigation: 1116 and 1117 with their fields, failed actions, quarantine, history and tampering."
date: "2026-11-19"
author: "Florian Amette"
tags: ["defender", "event-logs", "evtx", "incident-response"]
series: "defender-fundamentals"
seriesTitle: "Microsoft Defender Antivirus artifacts"
seriesOrder: 1
faq:
  - question: "What is the difference between event 1116 and event 1117?"
    answer: "1116 is the detection: Defender found malware or unwanted software, and the event gives the threat name, the path, the detection source and the process. 1117 is the action Defender then took on it, such as Quarantine, Remove, Clean, Block or Allow. A 1116 followed by 1118 or 1119 instead means the action failed, and the threat may still be on the machine."
  - question: "Does a 1116 event prove that the malware ran?"
    answer: "No. Many detections happen when a file is written, extracted or downloaded, before anything runs. Use the detection source and the timing as leads, and prove execution with Prefetch, Amcache, process creation events or EDR data."
  - question: "Why does the Detection User field say SYSTEM?"
    answer: "The field does not always name the person behind the file. Public samples, including Microsoft's own AMSI demonstration, show NT AUTHORITY\\SYSTEM. Take the user from the path, from the DetectionHistory file, from logon sessions and from per-user artifacts."
  - question: "Which event shows that someone added a Defender exclusion?"
    answer: "5007, configuration changed. Its New Value field holds the registry value that was written, for example a value under HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths. The event does not say who made the change: look at PowerShell logs and history for that."
---

**TL;DR.** The Defender Operational log, `Microsoft-Windows-Windows Defender/Operational`, is the first Defender source to read. **1116** is a detection and **1117** the action taken on it; **1118** and **1119** mean the action failed. **1009**, **1011** and **1013** record a restore from quarantine, a deletion from quarantine and deleted detection history. **5001**, **5010** and **5012** record protection being switched off, **5007** any configuration change with the old and new registry value, and **5013** a change that tamper protection blocked. Filter on the numeric IDs, not on the names, which are in the system's language. The detection user is often SYSTEM, and no event says who changed a setting. [Defender Parser](/en#tool) reads the log together with the other Defender artifacts and joins them per detection.

## Where the log is

- **Channel:** `Microsoft-Windows-Windows Defender/Operational`, provider `Microsoft-Windows-Windows Defender`.
- **File:** `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx`. A second Defender channel, `Microsoft-Windows-Windows Defender%4WHC.evtx`, sits next to it.
- **Event Viewer:** Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational.
- **Reference:** Microsoft lists every ID with its symbolic name and fields in [Microsoft Defender Antivirus event IDs and error codes](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus). It is a troubleshooting page. What each event means for an investigation is this article's reading, not Microsoft's.

The log rolls over at its maximum size, and routine events such as signature updates fill it. Check the oldest event before you conclude that something is absent. The [DetectionHistory files](/en/blog/defender-detectionhistory-files) and the [MPLog files](/en/blog/mplog-defender-support-logs) are kept separately and often reach further back.

## The events worth reading

| ID | Meaning | Why it matters |
| --- | --- | --- |
| 1116 | Malware or unwanted software detected | The detection: threat, path, source, process |
| 1117 | Action taken on a detection | Quarantine, Remove, Clean, Block, Allow... |
| 1118 | Action failed, not critical | The threat may still be present |
| 1119 | Action failed critically | Microsoft notes that the endpoint might not be protected |
| 1006, 1007, 1008 | Detected, action taken, action failed | A second family with the same three steps; Microsoft documents both, so search for both |
| 1015 | Suspicious behaviour detected | Behaviour detections, with a target file name |
| 1120 | Hashes deduced for a threat resource | Only when the `ThreatFileHashLogging` policy is set |
| 1121 | An attack surface reduction rule fired in block mode | ASR blocks, with the path |
| 1009, 1010 | Item restored from quarantine, restore failed | Someone wanted the file back |
| 1011, 1012 | Item deleted from quarantine, delete failed | The sample may be gone from the quarantine |
| 1013, 1014 | Detection history deleted, delete failed | Routine purge or cleanup, see below |
| 5000, 5001 | Real-time protection enabled, disabled | 5001 in an incident window is a lead |
| 5004 | A real-time protection feature's configuration changed | Feature-level changes |
| 5007 | Configuration changed, with old and new value | Exclusions and every other setting |
| 5009, 5010 | Scanning for malware and unwanted software enabled, disabled | Protection switched off |
| 5011, 5012 | Scanning for viruses enabled, disabled | Protection switched off |
| 5013 | Tamper protection blocked a change | An attempt that failed |
| 1150 | Service healthy | Hourly heartbeat, where reported |
| 1151 | Health report | Versions, signature age, protection states, last scans |
| 3002, 3007 | A real-time protection feature failed, recovered | Gaps in protection |
| 5008 | Engine failure (crash or hang) | Gaps in protection |
| 2000, 2001 | Signatures updated, update failed | Signature versions before and after |
| 2010 | Cloud protection delivered extra security intelligence | Signatures that arrived outside the regular updates |
| 2050 | File submitted for sample analysis | Full path and SHA-256 of the file |
| 1000, 1001, 1002 | Scan started, finished, stopped | Scan type and user |

## 1116 and 1117: the detection and the action

Microsoft's page describes the fields in prose. The names below are the `EventData` names as they appear in a 1116 recorded in 2026 for the [Sigma project's regression tests](https://github.com/SigmaHQ/sigma/tree/master/regression_data/rules/windows/builtin/windefend), which is also what EvtxECmd, Dissect and most SIEM pipelines expose.

| Field | What it holds |
| --- | --- |
| `Detection ID` | A GUID for this detection. The same value appears in 1117 and names the [DetectionHistory file](/en/blog/defender-detectionhistory-files) |
| `Detection Time` | When the threat was detected, ISO 8601 in UTC with a `Z`. In the Sigma sample it is 20 ms before the event's own time |
| `Threat ID`, `Threat Name` | A numeric ID and a name such as `Trojan:Win32/CryptInject!MSR` |
| `Severity ID`, `Severity Name` | Low, Moderate, High, Severe |
| `Category ID`, `Category Name` | Trojan, Tool, Virus... |
| `Source ID`, `Source Name` | What triggered the scan: user, system, real-time, IOAV (downloads and attachments), NIS, IEPROTECT, ELAM, remote attestation, AMSI, UAC |
| `Process Name` | Microsoft describes it only as the process in the PID. It can be `Unknown` |
| `Detection User` | Often `NT AUTHORITY\SYSTEM`, see below |
| `Path` | The detected resources, each with a type prefix |
| `Origin ID`, `Origin Name` | Local computer, network share, internet, incoming or outgoing traffic, unknown |
| `Execution ID`, `Execution Name` | Not explained on Microsoft's event page |
| `Type ID`, `Type Name` | Heuristics, generic, concrete, dynamic signature |
| `Action ID`, `Action Name` | In 1117: what Defender did |
| `Error Code`, `Error Description` | An HRESULT, `0x00000000` on success |
| `Additional Actions ID`, `Additional Actions String` | Further steps still needed; `No additional actions required` in the Sigma sample |
| `Remediation User` | Not explained on Microsoft's event page; empty in the Sigma sample |
| `Security intelligence Version`, `Engine Version` | Signature and engine versions at detection time |

Fields named `Unused` to `Unused6` are empty placeholders.

### Reading the Path field

The path carries a type prefix. In the Sigma 1116 sample it is `file:_C:\Users\...\svchost.exe`. A detection can cover several resources separated by `; `: the Sigma 1009 sample has a `file:_` resource followed by a `service:_` resource holding a PowerShell command line. An AMSI detection has no file at all: Microsoft's [AMSI demonstration](https://learn.microsoft.com/en-us/defender-endpoint/mde-demonstration-amsi) shows an `amsi:` resource naming the host process, `\Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`. Strip the prefix before you match paths against other artifacts.

### Names are translated, IDs are not

The Sigma samples were recorded on a French Windows: `Category Name` reads `Cheval de Troie`, `Source Name` reads `Système`, `Action Name` reads `Non applicable`. A filter on `Source Name = System` finds nothing on that host. Filter on the ID fields, and keep the names for display.

### Detection source

`Source Name` tells you how the file reached the engine: real-time protection on access, a user or scheduled scan, IOAV for downloads and attachments, AMSI for script content. Do not rely on it alone. In Microsoft's AMSI demonstration, the test detection is reported with `Detection Source: System`, while its path has the `amsi:` prefix. Check both.

### Detection User and Process Name

Both are leads, not attribution. `Detection User` is `NT AUTHORITY\SYSTEM` in Microsoft's AMSI demonstration, where an administrator runs the test script, and its French equivalent in the Sigma sample. `Process Name` is `Unknown` in the Sigma sample. Take the user from the path when it is inside a profile, from the DetectionHistory file, which keeps a user per detection, and from logon sessions.

### A detection is not an execution

A 1116 shows that Defender saw the content, not that it ran. Real-time protection scans files when they are written and opened, and IOAV scans downloads. `Execution Name` is not documented on the event page; the WMI class behind `Get-MpThreatDetection` has a similar enumeration, `CurrentThreatExecutionStatusID` (Unknown, Blocked, Allowed, Executing, NotExecuting), described in [MSFT_MpThreatDetection](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mpthreatdetection). Treat it as a hint and prove execution elsewhere.

### The action in 1117

Microsoft lists the actions as Clean, Quarantine, Remove, Allow, User defined, No action and Block. **Allow**, **No action** and **None** do not remediate. When the default action for a severity is set to None, Defender writes the 1116 and then a 1117 with **Allow**: the threat was seen and left in place. Microsoft adds that these actions cannot be configured while tamper protection is on, so a 1117 Allow on a tamper-protected host deserves a question.

### When the action fails

1118 and 1119 carry an `Error Code`. Microsoft's page lists the Defender-specific values, for example `0x80508022` (a reboot is required to complete removal), `0x80508023` (the threat is no longer present, or malware is preventing the scan) and `0x80508026` (removal inside this container type is not supported). Any failed action means the file, or the process, may still be there.

## Quarantine and history events

- **1009, restored from quarantine.** Someone used Windows Security or `MpCmdRun.exe -Restore` to get the item back. In the Sigma 1009 sample, the event carries `Domain`, `User` and `SID` fields naming an account. A restore in an incident window is worth a full look.
- **1011, deleted from quarantine.** The sample is no longer in the [quarantine folder](/en/blog/defender-quarantine-file-recovery). Its hashes may still be in the DetectionHistory file, and an older copy of the folder may survive in a Volume Shadow Copy.
- **1013, history deleted.** Microsoft's own description gives a purge of the history as an example of when it fires, and Defender removes scan history items after 30 days by default ([Microsoft](https://learn.microsoft.com/en-us/defender-endpoint/configure-remediation-microsoft-defender-antivirus)). A 1013 alone is not anti-forensics. A 1013 minutes after a detection, with an interactive account in its user field, deserves the attention you would give a cleared log.

## Protection state and configuration

- **5001, 5010, 5012**: real-time protection, malware scanning or virus scanning turned off. Look for the matching 5000, 5009 or 5011 that turned it back on.
- **5007**: every configuration change, with `Old Value` and `New Value` holding a registry path and a value. In the Sigma samples, an added exclusion reads `New Value: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\AtomicRedTeam = 0x0` with an empty `Old Value`, and a cloud setting change reads from `Default\SpyNet\DisableBlockAtFirstSeen = 0x0` to `HKLM\SOFTWARE\Microsoft\Windows Defender\SpyNet\DisableBlockAtFirstSeen = 0x1`. The event's security user ID is `S-1-5-18`, the service itself: 5007 never names the person.
- **5013**: tamper protection blocked a change, and the event's `Value` names the registry value and the data that was refused. The [Sigma rule](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/windefend/win_defender_tamper_protection_trigger.yml) matches values ending in `\Real-Time Protection\DisableRealtimeMonitoring`, `\Real-Time Protection\DisableBehaviorMonitoring`, `\Windows Defender\DisableAntiSpyware` and similar. In a [Microsoft Tech Community thread](https://techcommunity.microsoft.com/discussions/microsoftdefenderatp/enabling-tamper-protection-with-tenant-attach/3255236), an administrator confirmed that `Set-MpPreference -DisableRealtimeMonitoring $true` produces a 5013 on a tamper-protected host, and also found about 25 of them at each Group Policy refresh: Configuration Manager policies rewriting protected values under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`, even when the data did not change. Read the setting, the data and the timing before you call a 5013 an attack.

Bhabesh Raj's [2020 write-up](https://bhabeshraj.com/post/tampering-with-microsoft-defenders-tamper-protection) searches for a 5007 whose old value ends in `TamperProtection = 0x5` and new value in `TamperProtection = 0x4`, as the trace of tamper protection being switched off. Microsoft does not document these values; read them as on and off with that caveat. The attacker side of all this is in [Defender exclusions and tampering](/en/blog/defender-exclusions-tampering).

## Health, failures and gaps

- **1150**: Microsoft describes it as reported every hour when the antimalware platform reports its status to a monitoring platform. Where a host writes it, a gap of several hours on a machine that was running points to a stopped service, a cleared log or a machine that was off: check the System log for uptime and for event 104, which records a cleared log.
- **1151** is a health report that includes the real-time protection, on-access, IOAV and behaviour monitoring states, the signature versions and age, and the last quick and full scan times. A state that changes between two reports is a pointer to the 5000-series events around it.
- **3002, 3007, 5008**: a real-time protection feature failed or recovered, or the engine crashed or hung. Microsoft recommends a full scan after 3002 and 3007, because the system may not have been protected for some time.
- **2050**: a file sent to Microsoft for analysis, with its full path and SHA-256. It is one of the few places where the log itself gives a hash.

## Joining the log with the other Defender sources

| Key | In the Operational log | Elsewhere |
| --- | --- | --- |
| Detection ID | 1116, 1117 | [DetectionHistory](/en/blog/defender-detectionhistory-files) file name; `Get-MpThreatDetection` on a live host |
| Threat ID | 1116, 1117, 1009, 1011 | [Quarantine](/en/blog/defender-quarantine-file-recovery) entry; resource scan and threat action blocks in [MPLog](/en/blog/mplog-defender-support-logs) |
| Path and time | 1116 | `DETECTIONEVENT` and `DETECTION_ADD` lines in MPLog; quarantine entry |
| SHA-256 | 2050 | DetectionHistory tracking data |
| Registry value | 5007, 5013 | `SOFTWARE` hive, with the key's last write time |

## Tools

- **EvtxECmd** has [maps](https://github.com/EricZimmerman/evtx/tree/master/evtx/Maps) for 1116, 1117, 5001, 5007 and other Defender events.
- **Dissect**'s [`defender.evtx`](https://docs.dissect.tools/en/latest/plugins/defender.evtx.html) plugin returns every field listed above.
- **Sigma** has [rules](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/builtin/windefend) for AMSI detections, added exclusions, tamper protection triggers, restored quarantine files and deleted history.
- **Defender Parser** reads the EVTX with the quarantine, DetectionHistory, MPLog, `MpCmdRun.log` and the `SOFTWARE` hive, joins the detections across them, and shows protection changes on one timeline.

## Pitfalls

- **Time zones.** The event time is stored in UTC; Event Viewer displays it in the analyst's local time. `Detection Time` is UTC with a `Z`.
- **Translated names.** Filter on IDs.
- **The user.** Neither 1116 nor 5007 reliably names the person.
- **Absence.** A missing 1116 can mean an excluded path, real-time protection off, a rolled-over log or a file Defender does not detect. Each has its own trace.

## FAQ

### What is the difference between event 1116 and event 1117?

1116 is the detection: Defender found malware or unwanted software, and the event gives the threat name, the path, the detection source and the process. 1117 is the action Defender then took on it, such as Quarantine, Remove, Clean, Block or Allow. A 1116 followed by 1118 or 1119 instead means the action failed, and the threat may still be on the machine.

### Does a 1116 event prove that the malware ran?

No. Many detections happen when a file is written, extracted or downloaded, before anything runs. Use the detection source and the timing as leads, and prove execution with Prefetch, Amcache, process creation events or EDR data.

### Why does the Detection User field say SYSTEM?

The field does not always name the person behind the file. Public samples, including Microsoft's own AMSI demonstration, show NT AUTHORITY\SYSTEM. Take the user from the path, from the DetectionHistory file, from logon sessions and from per-user artifacts.

### Which event shows that someone added a Defender exclusion?

5007, configuration changed. Its New Value field holds the registry value that was written, for example a value under HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths. The event does not say who made the change: look at PowerShell logs and history for that.

## Related articles

- [Defender DetectionHistory files: what they hold](/en/blog/defender-detectionhistory-files)
- [Defender exclusions and tampering: finding the traces](/en/blog/defender-exclusions-tampering)
- [Investigating an intrusion with Defender artifacts](/en/blog/defender-investigation-walkthrough)
