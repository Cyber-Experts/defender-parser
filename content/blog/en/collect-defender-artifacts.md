---
title: "Collecting Microsoft Defender Artifacts"
description: "How to collect Defender's Operational log, MPLog, DetectionHistory, quarantine, MpCmdRun.log and SOFTWARE hive with robocopy /B, wevtutil, KAPE or Velociraptor."
date: "2026-11-19"
author: "Florian Amette"
tags: ["defender", "acquisition", "kape", "velociraptor", "dfir"]
series: "defender-investigations"
seriesTitle: "Investigating with Defender artifacts"
seriesOrder: 3
howto:
  name: "Collect the Microsoft Defender artifacts from a live Windows system"
  description: "Copy Defender's ProgramData folder, export the Operational log, gather every MpCmdRun.log, save the SOFTWARE hive, hash the result and load it in Defender Parser."
  totalTime: "PT15M"
  tool: ["An elevated PowerShell prompt", "robocopy, wevtutil and reg.exe (built in)", "Defender Parser (browser)"]
  yield: "A folder or zip with Defender's folders, the Operational log, every MpCmdRun.log and the SOFTWARE hive, plus SHA-256 hashes."
  steps:
    - name: "Open an elevated prompt"
      text: "Start PowerShell as administrator, note the time, and do not start a scan or add an exclusion for your tools before you have collected."
    - name: "Copy Defender's ProgramData folder"
      text: "Copy C:\\ProgramData\\Microsoft\\Windows Defender with robocopy in backup mode, excluding the Definition Updates folder. It brings the Support folder with MPLog, the DetectionHistory files and the Quarantine folder."
    - name: "Export the Operational log"
      text: "Export Microsoft-Windows-Windows Defender/Operational with wevtutil epl, since the event log service keeps the file open."
    - name: "Copy every MpCmdRun.log"
      text: "Copy MpCmdRun.log from C:\\Windows\\Temp and from the AppData\\Local\\Temp folder of every profile."
    - name: "Save the hives"
      text: "Save HKLM\\SOFTWARE, which holds the exclusions and Defender settings, and HKLM\\SYSTEM, which holds the time zone, with reg save."
    - name: "Hash, archive and load"
      text: "Compute SHA-256 hashes of every file, keep them outside the case folder, zip the folder, and drop it on Defender Parser."
faq:
  - question: "Do I need administrator rights to collect the Defender artifacts?"
    answer: "Yes. The folders under C:\\ProgramData\\Microsoft\\Windows Defender are restricted to administrators and SYSTEM, robocopy's backup mode needs the backup privilege, saving the SOFTWARE hive needs administrator rights, and the Exclusions key has been readable by administrators only since February 2022."
  - question: "Why exclude the Definition Updates folder?"
    answer: "It holds the signature and engine files Defender downloads: large, identical on every machine with the same version, and not a record of what happened on the host. The evidence is in Support, Scans and Quarantine. Note the signature and engine versions from the events or Get-MpComputerStatus instead."
  - question: "Does KAPE collect everything Defender Parser reads?"
    answer: "Almost. The WindowsDefender target takes the Defender event logs, the Support folder, MpCmdRun.log from C:\\Windows\\Temp, the DetectionHistory files and the quarantine. Add RegistryHivesSystem for the SOFTWARE hive, and copy the MpCmdRun.log files in user profiles' Temp folders yourself, because the target does not include them."
  - question: "Is it safe to copy the quarantine folder?"
    answer: "Copying it is: the files are RC4-obfuscated and nothing in them can run as it is. Decrypting them gives live malware, so do that only in a lab, and keep the collection archive with the same care as any malware sample."
---

**TL;DR.** From an elevated prompt, copy `C:\ProgramData\Microsoft\Windows Defender\` with backup semantics, leaving out `Definition Updates`: that brings MPLog, the DetectionHistory files and the quarantine. Export the **Operational log** with `wevtutil epl`. Copy **every `MpCmdRun.log`**: `C:\Windows\Temp` and each profile's `AppData\Local\Temp`. Save the **SOFTWARE** hive for the exclusions and settings, and SYSTEM for the time zone. For attribution, add the PowerShell Operational log and each user's PSReadLine history. KAPE's `WindowsDefender` target and Velociraptor's `Windows.Triage.Targets` do most of this, but not the per-user `MpCmdRun.log`. Before anything, avoid creating Defender events yourself: no scan, no exclusion for your tools. Then drop the folder or archive on [Defender Parser](/en#tool); the home page has a [guide to getting your data](/en#collect).

## What to collect

| Item | Path | Why |
| --- | --- | --- |
| Operational log | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx` | Detections, actions, configuration changes, tamper protection ([event IDs](/en/blog/defender-operational-event-ids)) |
| Support folder | `C:\ProgramData\Microsoft\Windows Defender\Support\` | [MPLog](/en/blog/mplog-defender-support-logs), MPDetection logs |
| DetectionHistory | `...\Windows Defender\Scans\History\Service\DetectionHistory\` | One [record per detection](/en/blog/defender-detectionhistory-files), with hashes |
| Quarantine | `...\Windows Defender\Quarantine\` (`Entries`, `ResourceData`, `Resources`) | The [quarantined files](/en/blog/defender-quarantine-file-recovery) and their metadata |
| `MpCmdRun.log` | `C:\Windows\Temp\`, each `C:\Users\<user>\AppData\Local\Temp\`, `C:\Windows.old\Windows\Temp\` | What was run with `MpCmdRun.exe` |
| SOFTWARE hive | `C:\Windows\System32\config\SOFTWARE` | Exclusions, Defender settings, tamper protection values |
| SYSTEM hive | `C:\Windows\System32\config\SYSTEM` | Time zone, for MPLog blocks and `MpCmdRun.log` |
| PowerShell | `Microsoft-Windows-PowerShell%4Operational.evtx`; each user's `AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | Who ran `Set-MpPreference` and `Add-MpPreference` |

Copying the whole Defender folder, rather than the four subfolders, also brings files whose value is still being worked out, such as `Scans\mpenginedb.db`. KAPE added it to its target in November 2026 after [Protokol-7's research](https://protokol-7.github.io/dfir/2026/11/10/defenders-hidden-flight-recorder-mpenginedb.html) showed it is an RC4-encrypted SQLite database that Defender's engine keeps. It is not one of the sources Defender Parser reads, but it costs nothing to keep. KAPE's target also takes `C:\ProgramData\Microsoft\Microsoft AntiMalware\Support\`, the equivalent folder of the older Microsoft Security Essentials.

## Before you start: your own traces

Defender records what you do too.

- **Do not start a scan** before collecting. It writes 1000 and 1001 events, and if it finds something, new detections, DetectionHistory files and quarantine entries.
- **Do not add an exclusion for your tools.** It writes a 5007 that someone will later read as the intruder's. Velociraptor's artifact exchange even has one for it, [`Windows.Utils.DefenderExclusion`](https://docs.velociraptor.app/exchange/artifacts/pages/defenderexclusion/), which adds a process exclusion for the Velociraptor client and reapplies it every minute. If you must use it, write down when.
- **Prefer copying to `MpCmdRun.exe -GetFiles`.** That command builds `MpSupportFiles.cab` inside the Support folder you are collecting, and adds a block to `MpCmdRun.log`.
- **Read-only queries are fine**: `Get-MpComputerStatus`, `Get-MpPreference`, `Get-MpThreatDetection`. Save their output; it is the live state to compare with the files.
- **Note the time, the tools and the account you used.**

## Privileges and locked files

- **Run elevated.** The Defender folders are restricted to administrators and SYSTEM, and some files may refuse even an administrator; robocopy's `/B` switch uses the backup privilege to read them. DHParser's author warns of permission errors on the DetectionHistory folder for the same reason.
- **The EVTX is open.** The event log service holds it; export it with `wevtutil epl`, or use a tool that reads NTFS directly.
- **SOFTWARE is always loaded.** Save it with `reg save`, or copy it with its `.LOG1` and `.LOG2` files from a Volume Shadow Copy or with a raw-copy tool.
- **The `Exclusions` key** has been readable by administrators only since the February 2022 updates. A saved hive is what you will parse anyway.

## Live collection by hand

In an elevated PowerShell prompt:

```powershell
$case = 'E:\case\FIN-WKS-07'
New-Item -ItemType Directory -Force -Path "$case\Defender", "$case\evtx", "$case\MpCmdRun", "$case\PSReadLine", "$case\hives", "$case\live" | Out-Null

# 1. Defender's ProgramData folder in backup mode, without the signature files
robocopy "C:\ProgramData\Microsoft\Windows Defender" "$case\Defender" /E /COPY:DAT /DCOPY:T /B /R:1 /W:1 /XD "Definition Updates"

# 2. Event logs, exported while the service holds them open
wevtutil epl "Microsoft-Windows-Windows Defender/Operational" "$case\evtx\Microsoft-Windows-Windows Defender%4Operational.evtx"
wevtutil epl "Microsoft-Windows-PowerShell/Operational" "$case\evtx\Microsoft-Windows-PowerShell%4Operational.evtx"

# 3. Every MpCmdRun.log and PSReadLine history: SYSTEM's temp folder, then each profile
robocopy C:\Windows\Temp "$case\MpCmdRun\Windows-Temp" "MpCmdRun.log*" /COPY:DAT /B /R:1 /W:1
Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special } | ForEach-Object {
  $name = Split-Path $_.LocalPath -Leaf
  robocopy "$($_.LocalPath)\AppData\Local\Temp" "$case\MpCmdRun\$name" "MpCmdRun.log*" /COPY:DAT /B /R:1 /W:1
  robocopy "$($_.LocalPath)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine" "$case\PSReadLine\$name" "*_history.txt" /COPY:DAT /B /R:1 /W:1
}

# 4. SOFTWARE (exclusions, settings) and SYSTEM (time zone)
reg save HKLM\SOFTWARE "$case\hives\SOFTWARE" /y
reg save HKLM\SYSTEM "$case\hives\SYSTEM" /y

# 5. The live view, for comparison
Get-MpComputerStatus | Format-List * | Out-File "$case\live\MpComputerStatus.txt"
Get-MpPreference | Format-List * | Out-File "$case\live\MpPreference.txt"
Get-MpThreatDetection | Format-List * | Out-File "$case\live\MpThreatDetection.txt"

# 6. Hashes outside the case folder, then an archive
Get-ChildItem $case -Recurse -File -Force | Get-FileHash -Algorithm SHA256 |
  Export-Csv "$case.sha256.csv" -NoTypeInformation
tar.exe -a -c -f "$case.zip" -C $case .
```

Keep one folder per profile name for `MpCmdRun.log` and PSReadLine: the folder is what tells you whose file it is. `Get-MpPreference` may not list exclusions on a host where the *visible to Local Admins* policy is set; the saved hive still has them.

## KAPE

The [`WindowsDefender` target](https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Antivirus/WindowsDefender.tkape) takes:

- `Microsoft-Windows-Windows Defender*.evtx`, from `C:\Windows` and `C:\Windows.old`;
- the Support folder, and the older `Microsoft AntiMalware\Support` folder;
- `MpCmdRun.log` from `C:\Windows\Temp` and `C:\Windows.old\Windows\Temp`;
- the DetectionHistory folders, the Quarantine folder, `Scans\History\Service\Detections.log` and `Scans\mpenginedb.db*`.

[`WinDefendDetectionHist`](https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/Antivirus/WinDefendDetectionHist.tkape), by DHParser's author, takes the DetectionHistory folders only. `WindowsDefender` is part of the `Antivirus` compound target, which `KapeTriage` and `!SANS_Triage` include. For a focused collection:

```cmd
kape.exe --tsource C: --tdest E:\case\FIN-WKS-07 --target WindowsDefender,RegistryHivesSystem,EventLogs,PowerShellConsole
```

`RegistryHivesSystem` brings SOFTWARE and SYSTEM with their transaction logs, `EventLogs` the PowerShell logs, `PowerShellConsole` the PSReadLine history files. KAPE reads locked files from NTFS directly. What it misses is `MpCmdRun.log` in user profiles' Temp folders: copy them by hand, or add a target for `C:\Users\%user%\AppData\Local\Temp\MpCmdRun.log*`.

## Velociraptor

[`Windows.Triage.Targets`](https://triage.velocidex.com/docs/windows.triage.targets/) uses the same target definitions. Select `WindowsDefender`, `RegistryHivesSystem`, `EventLogs` and `PowerShellConsole`, run it on the endpoint or as an offline collector, and export the collection as a ZIP for Defender Parser. The same gap applies to per-user `MpCmdRun.log`.

Artifacts that parse on the endpoint instead:

| Artifact | What it does |
| --- | --- |
| [`Windows.Applications.DefenderHistory`](https://docs.velociraptor.app/exchange/artifacts/pages/windows.applications.defenderhistory/) | Parses DetectionHistory files at fixed offsets |
| [`Windows.Applications.DefenderDHParser`](https://docs.velociraptor.app/exchange/artifacts/pages/defenderdhparser/) | Runs DHParser on the endpoint |
| [`Windows.Applications.DefenderQuarantineExtract`](https://docs.velociraptor.app/exchange/artifacts/pages/defenderquarantineextract/) | Decrypts the quarantine on the endpoint; can upload the samples |
| [`Windows.Registry.DefenderConfig`](https://docs.velociraptor.app/exchange/artifacts/pages/defenderconfig/) | Reads Defender settings; by default the `Policies` key only |
| `Windows.Forensics.MPLog` | Parses MPLog; in Velociraptor's main branch since November 2026 |

They are useful for hunting across many hosts. Collect the raw files as well: a parser on the endpoint decides what you keep, and the files let you check it later.

## From a disk image

Mount the Windows volume read-only and copy the same paths relative to its root: `ProgramData\Microsoft\Windows Defender\` (without `Definition Updates`), `Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx`, `Windows\Temp\MpCmdRun.log*`, `Users\*\AppData\Local\Temp\MpCmdRun.log*`, `Windows\System32\config\SOFTWARE*` and `SYSTEM*`. Nothing is locked in an image. Volume Shadow Copies inside it can hold older MPLog files, DetectionHistory files and quarantine entries that have since been purged, and older SOFTWARE hives with exclusions that were later removed. [Disk Image Parser](https://www.diskimageparser.com) can hand the Defender files and the SOFTWARE hive found in an image straight to Defender Parser, in the browser.

## Handling the copies

- **Hash on collection** and work on copies.
- **The quarantine is malware.** The collected files are inert while encrypted. Anyone who decrypts them gets the samples. Store and share the archive as you would a sample, and read [how to recover a file safely](/en/blog/defender-quarantine-file-recovery).
- **Record the time zone.** MPLog blocks and `MpCmdRun.log` use local time; the SYSTEM hive's `TimeZoneInformation` key gives it.
- **Write down your own actions**: commands, times, any exclusion or scan you could not avoid.

What to do with the result is in [investigating an intrusion with Defender artifacts](/en/blog/defender-investigation-walkthrough).

## FAQ

### Do I need administrator rights to collect the Defender artifacts?

Yes. The folders under C:\ProgramData\Microsoft\Windows Defender are restricted to administrators and SYSTEM, robocopy's backup mode needs the backup privilege, saving the SOFTWARE hive needs administrator rights, and the Exclusions key has been readable by administrators only since February 2022.

### Why exclude the Definition Updates folder?

It holds the signature and engine files Defender downloads: large, identical on every machine with the same version, and not a record of what happened on the host. The evidence is in Support, Scans and Quarantine. Note the signature and engine versions from the events or Get-MpComputerStatus instead.

### Does KAPE collect everything Defender Parser reads?

Almost. The WindowsDefender target takes the Defender event logs, the Support folder, MpCmdRun.log from C:\Windows\Temp, the DetectionHistory files and the quarantine. Add RegistryHivesSystem for the SOFTWARE hive, and copy the MpCmdRun.log files in user profiles' Temp folders yourself, because the target does not include them.

### Is it safe to copy the quarantine folder?

Copying it is: the files are RC4-obfuscated and nothing in them can run as it is. Decrypting them gives live malware, so do that only in a lab, and keep the collection archive with the same care as any malware sample.

## Related articles

- [Investigating an intrusion with Defender artifacts](/en/blog/defender-investigation-walkthrough)
- [Defender quarantine: format and safe file recovery](/en/blog/defender-quarantine-file-recovery)
- [MPLog files: reading Defender's support logs](/en/blog/mplog-defender-support-logs)
