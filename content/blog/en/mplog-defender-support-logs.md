---
title: "MPLog Files: Reading Defender's Support Logs"
description: "What Microsoft Defender's MPLog-*.log files record: SDN queries, ProcessImageName lines, detections, exclusions and multi-line blocks, with their time zones."
date: "2026-11-19"
author: "Florian Amette"
tags: ["defender", "mplog", "evidence-of-execution", "dfir"]
series: "defender-fundamentals"
seriesTitle: "Microsoft Defender Antivirus artifacts"
seriesOrder: 4
faq:
  - question: "Where are the MPLog files and who can read them?"
    answer: "In C:\\ProgramData\\Microsoft\\Windows Defender\\Support\\, named MPLog-YYYYMMDD-HHMMSS.log, next to MPDetection logs and trace files. The folder is restricted to administrators and SYSTEM. Public samples are UTF-16LE with a byte order mark; Dissect and Velociraptor also accept UTF-8."
  - question: "Are MPLog timestamps in UTC?"
    answer: "Not all of them. Single lines that start with an ISO 8601 time ending in Z are UTC. The service header's Started On line and the multi-line blocks such as Resource Scan, threat actions and BM telemetry use month-day-year times in local time, as public samples show by giving both for the same event. Newer platform versions write the ISO times without the Z; tools assume UTC, and you can check it against the header's Current time line, which states UTC."
  - question: "Can MPLog prove that a file existed even if Defender detected nothing?"
    answer: "It can show that the engine handled a file at a given path at a given time: an SDN query line names it, a Mini-filter line names it with the process that opened it, and a ProcessImageName line names a running process and the file that took longest to scan for it. That is evidence of presence, and for ProcessImageName of a running process, not of what the program did. Corroborate it."
  - question: "Do SDN lines always contain hashes?"
    answer: "No. CrowdStrike's examples show SDN events with the file's SHA-1 and SHA-256, but a public MPLog from Windows Server 2022, written in 2023, has SDN query lines with the path only. Expect both forms, and take hashes from DetectionHistory, Amcache or the file when MPLog has none."
---

**TL;DR.** `C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log` is Defender's troubleshooting log, written by the engine. Investigators read it because it records files and processes the engine **handled**, not only those it detected: **SDN** lines (cloud lookups for a file, with SHA-1 and SHA-256 in some versions), **ProcessImageName** lines (a process, how many files it caused to be scanned, and the slowest one), **Mini-filter** lines (a file and the process that opened it), **DETECTIONEVENT** and **DETECTION_ADD** lines, command lines reported as **lowfi** or **threat**, **[Exclusion]** lists, and multi-line **Resource Scan**, **threat actions** and **BM telemetry** blocks. Watch the time zones: single lines ending in `Z` are UTC, blocks and the service header are local time, and recent versions drop the `Z`. Microsoft does not document the format. [Defender Parser](/en#tool) reads MPLog with the other Defender sources.

## What MPLog is

The Support folder holds Defender's own diagnostic logs: `MPLog-*.log`, `MPDetection-*.log`, trace files such as `MpWppTracing-*.bin`, and others. MPLog is the one investigators use. CrowdStrike's James Lovato described it in January 2022 in [Mind the MPLog](https://www.crowdstrike.com/en-us/blog/how-to-use-microsoft-protection-logging-for-forensic-investigations/), with a case where it showed which files rclone had touched. Intrinsec's CERT published a [line-by-line description in September 2022](https://web.archive.org/web/20250703213902/https://www.intrinsec.com/hunt-mplogs/) (the original address now redirects to a marketing page) along with [mplog_parser](https://github.com/Intrinsec/mplog_parser).

Observed in public samples from Andrew Rathbun's [DFIRArtifactMuseum](https://github.com/AndrewRathbun/DFIRArtifactMuseum/tree/main/Windows/WindowsDefender), one from a Belkasoft CTF image (Windows build 17763, 2020) and one from a Windows Server 2022 test machine (2023):

- The files are UTF-16LE with a byte order mark and CRLF line endings.
- A file can hold several service starts. Each starts with a header: the product and `Service Log`, `Started On` in local time, `OS install time` and `Current time` in UTC.
- The date and time in the file name are local time, close to the first `Started On` in the file.
- Defender rotates the files; how many it keeps, and for how long, is not documented. Collect the folder early.

## The lines worth reading

| Line | Example or form | What it gives |
| --- | --- | --- |
| ProcessImageName | `ProcessImageName: svchost.exe, Pid: 1064, TotalTime: 700, Count: 8, MaxTime: 640, MaxTimeFile: \Device\HarddiskVolume2\Users\User\AppData\Local\Temp\GUM8420.tmp\GoogleUpdateSetup.exe, EstimatedImpact: 0%` | A process that ran and caused scans |
| SDN | `Issuing SDN query for \Device\HarddiskVolume3\Temp\...\cactus.js (...)`, then `SDN query completed: 00000000` | A file the engine looked up in the cloud |
| Mini-filter | `[Mini-filter] Blocked file: <path>. Process: \Device\HarddiskVolume3\Windows\explorer.exe, Status: ...` | A blocked or unscanned file and the process that opened it |
| DETECTIONEVENT | `DETECTIONEVENT MPSOURCE_REALTIME Trojan:JS/SharpShooter.A file:C:\Temp\...\cactus.js;` | A detection, its source and its resource |
| DETECTION_ADD | `DETECTION_ADD#1 Trojan:JS/SharpShooter.A file:C:\Temp\...\cactus.js` | One line per resource of a detection |
| lowfi, threat | `Engine:command line reported as lowfi: <command line>` | Command lines the engine flagged, per Intrinsec |
| EMS | `Engine:EMS scan for process: <name> pid: <pid>, ...` and `EMS detection: ...` | Memory scans; CrowdStrike reads detections here as possible injection |
| Exclusion | `[Exclusion] <path> -> <device path>`, between `BEGIN` and `END` lines | The real-time exclusion list as Defender built it |
| Original file name | `Setting original file name "UNPShared.dll" for "c:\windows\system32\upshared.dll", hr=0x0` | A name the engine associates with a path, presumably the file's original name from its version information; not documented |

The ProcessImageName, SDN, Mini-filter, detection and original file name examples come from the two public samples, with folders shortened; the other forms follow Intrinsec's description. The fields of a ProcessImageName line are defined by CrowdStrike and by Intrinsec, who cite Microsoft's performance troubleshooting documentation; the current version of that page no longer has the table:

| Field | Meaning |
| --- | --- |
| `ProcessImageName`, `Pid` | The process and its ID |
| `TotalTime` | Milliseconds spent scanning files this process accessed |
| `Count` | Number of scanned files this process accessed |
| `MaxTime`, `MaxTimeFile` | The longest single scan and the file it was for |
| `EstimatedImpact` | Share of the process's scan-active period spent in scans |

### Multi-line blocks

| Block | Starts and ends with | Content |
| --- | --- | --- |
| Resource scan | `Begin Resource Scan` … `End Scan` | Scan ID, scan source, start and end time, the resource, threat name, ID, severity, and the resources it covered, with `SigSeq` and `SigSha` |
| Threat actions | `Beginning threat actions` … `Finished threat actions` | Each action (quarantine, removal) per resource, results, and `File to act on SHA1:` with the file's SHA-1 |
| BM telemetry | `BEGIN BM telemetry` … `END BM telemetry` | Behaviour monitoring: signature ID, process ID and creation time (FILETIME), image path, an `ImagePathHash`, and a `Taint Info` line listing parent processes |
| RTP perf log | `RTP Perf Log` lines | Real-time protection start, plugin states, and the process, path and extension exclusions in effect |

The BM telemetry block in the Server 2022 sample has `ImagePath:C:\Windows\System32\cmd.exe` with `Parents: C:\Windows\System32\runonce.exe:4032:1`: a parent-child link that the event logs keep only when process creation auditing is on.

## Time zones

This is where MPLog misleads. One detection in the Server 2022 sample is written twice:

```text
2023-10-18T02:50:46.945Z DETECTIONEVENT MPSOURCE_REALTIME Trojan:JS/SharpShooter.A file:C:\Temp\APTSimulator-master\APTSimulator-master\download\cactus.js;
Begin Resource Scan
Scan ID:{A17CBE22-6345-46C6-B9F3-7144A8C1115B}
Scan Source:3
Start Time:10-17-2023 22:50:46
```

The single line is UTC; the block's `Start Time` is the same moment in the machine's local time, four hours behind. The header confirms it: `Started On 10-17-2023 22:44:43` above `Current time: 10/18/2023 02:44:43.48863800 UTC`. The same holds in the threat actions block that follows (`Start time:10-17-2023 22:51:02`, right after a line stamped `2023-10-18T02:51:02.805Z`) and in the BM telemetry block, whose `CreationTime` is local while `ProcessCreationTime` is a FILETIME in UTC.

Three caveats:

- **Lines without a zone.** Velociraptor's new [`Windows.Forensics.MPLog`](https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Windows/Forensics/MPLog.yaml) artifact, merged in November 2026 after the 0.77.3 release, notes that platform versions 4.18.2608x write the ISO times without the `Z`, and treats both forms as UTC. Dissect does the same for unsuffixed times and also accepts an explicit offset such as `+02:00`. No public test shows which zone the unsuffixed times are in. Check it yourself: compare the header's `Current time ... UTC` with the first timed line under it. If they agree within seconds, the lines are UTC.
- **Blocks need the machine's time zone.** Dissect parses block times in the target's configured zone. Read `TimeZoneInformation` from the SYSTEM hive, and do not assume the offset is fixed: in the Server 2022 sample, the first header has local time seven hours behind UTC and the next one, a minute later, four hours.
- **Sources disagree.** The DFIR Spot's [2024 post](https://www.thedfirspot.com/post/windows-defender-mp-logs-a-story-of-artifacts) says MPLog timestamps are in the system's local time; CrowdStrike says the ProcessImageName times are UTC. Each is right for some of the lines.

## Proving a file existed when nothing was detected

The value of MPLog is that the engine writes about files it found clean. A file Defender never flagged can still appear in:

- an **SDN** line, when the engine asked the cloud about it;
- a **Mini-filter** line, with the process that opened it;
- a **ProcessImageName** line, as the process itself or as its `MaxTimeFile`;
- an **Original file name** line.

Each shows that a file with that path was there when the line was written. A ProcessImageName line also shows that a process with that image name was running and causing scans. None shows what the program did: in CrowdStrike's case, the `Count` of files scanned for `rclone.exe` showed files it accessed, not that they were exfiltrated.

Absence has a common cause: exclusions. Microsoft explains that an excluded file gets only a minimal evaluation and no scan ([exclusions overview](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-overview)), so a tool running from an excluded folder may leave nothing in MPLog after the exclusion was added. The `[Exclusion]` list and the RTP perf log show which exclusions were in effect, which helps date them. See [Defender exclusions and tampering](/en/blog/defender-exclusions-tampering).

In the FIN-WKS-07 case used on this site, alice's `Invoice_2026-0914.pdf.exe` was never detected, and MPLog is the only Defender source that shows the engine scanning it. The [walk-through](/en/blog/defender-investigation-walkthrough) uses it.

## SDN lines and hashes

CrowdStrike's examples show SDN events carrying the file path with its SHA-1 and SHA-256. The Server 2022 sample from 2023 has SDN query lines with the path, twice, and no hash. Which versions write hashes is not documented. When the line has hashes, use them; when it does not, take them from [DetectionHistory](/en/blog/defender-detectionhistory-files), the `File to act on SHA1` line of a threat action block, Amcache or the file.

## Tools

| Tool | What it reads | Caveats |
| --- | --- | --- |
| [mplog_parser](https://github.com/Intrinsec/mplog_parser) (Intrinsec) | One CSV per line type and block type | Last updated 2022. Its patterns require timestamps ending in `Z`, its DETECTIONEVENT pattern matches `MPSOURCE_SYSTEM` only, and it has no SDN rule |
| Dissect [`defender.mplog`](https://docs.dissect.tools/en/latest/plugins/defender.mplog.html) | Line types and blocks, based on mplog_parser | Its current DETECTIONEVENT pattern only matches `HackTool:` names; no SDN rule |
| Velociraptor `Windows.Forensics.MPLog` | Lines and blocks, extracts any SHA-1 or SHA-256 in a line, SDN rule | Not yet in a release at the time of writing |
| KAPE modules `Mplog-Parser`, `PowerShell_ConvertWindowsDefenderMPLogTo-CSV` | Run on collected files | |
| `findstr`, `grep`, `Select-String` | Any text | Read as UTF-16 |

Read the raw lines around anything a parser returns: the context, such as the `SDN:` marker on its own line or the `FP supression checks` before a block, is often what explains it.

## FAQ

### Where are the MPLog files and who can read them?

In C:\ProgramData\Microsoft\Windows Defender\Support\, named MPLog-YYYYMMDD-HHMMSS.log, next to MPDetection logs and trace files. The folder is restricted to administrators and SYSTEM. Public samples are UTF-16LE with a byte order mark; Dissect and Velociraptor also accept UTF-8.

### Are MPLog timestamps in UTC?

Not all of them. Single lines that start with an ISO 8601 time ending in Z are UTC. The service header's Started On line and the multi-line blocks such as Resource Scan, threat actions and BM telemetry use month-day-year times in local time, as public samples show by giving both for the same event. Newer platform versions write the ISO times without the Z; tools assume UTC, and you can check it against the header's Current time line, which states UTC.

### Can MPLog prove that a file existed even if Defender detected nothing?

It can show that the engine handled a file at a given path at a given time: an SDN query line names it, a Mini-filter line names it with the process that opened it, and a ProcessImageName line names a running process and the file that took longest to scan for it. That is evidence of presence, and for ProcessImageName of a running process, not of what the program did. Corroborate it.

### Do SDN lines always contain hashes?

No. CrowdStrike's examples show SDN events with the file's SHA-1 and SHA-256, but a public MPLog from Windows Server 2022, written in 2023, has SDN query lines with the path only. Expect both forms, and take hashes from DetectionHistory, Amcache or the file when MPLog has none.

## Related articles

- [The Defender Operational event IDs that matter](/en/blog/defender-operational-event-ids)
- [Defender exclusions and tampering: finding the traces](/en/blog/defender-exclusions-tampering)
- [Collecting Microsoft Defender artifacts](/en/blog/collect-defender-artifacts)
