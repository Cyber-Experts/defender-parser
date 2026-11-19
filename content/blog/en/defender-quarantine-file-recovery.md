---
title: "Defender Quarantine: Format and Safe File Recovery"
description: "How Microsoft Defender stores quarantined files in Entries and ResourceData, what the RC4 layer hides, and how to get a sample back without running it."
date: "2026-11-19"
author: "Florian Amette"
tags: ["defender", "quarantine", "malware-analysis", "dfir"]
series: "defender-fundamentals"
seriesTitle: "Microsoft Defender Antivirus artifacts"
seriesOrder: 2
howto:
  name: "Recover a file from the Microsoft Defender quarantine safely"
  description: "Copy the quarantine folder from the suspect host, identify the entry, recover the file as a password-protected ZIP and analyse it in an isolated lab."
  totalTime: "PT20M"
  tool: ["An elevated prompt on the suspect host", "robocopy (built in)", "Defender Parser (browser)", "An isolated analysis machine"]
  yield: "The quarantined file in a ZIP encrypted with the password infected, with its original path, times and threat name."
  steps:
    - name: "Copy the quarantine folder"
      text: "From an elevated prompt, copy C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine with robocopy in backup mode, keeping Entries, ResourceData and Resources together, and hash the copy."
    - name: "Leave the suspect host alone"
      text: "Do not restore the item with Windows Security or MpCmdRun -Restore on the suspect system. Both act on the live machine, and a plain restore puts the malware back where it was."
    - name: "Identify the entry"
      text: "Load the copied folder in Defender Parser and match the entry to the detection by threat name, original path and time, and to the 1116 and 1117 events."
    - name: "Recover it as an encrypted ZIP"
      text: "Ask Defender Parser for the file. It is delivered only as a ZIP encrypted with the password infected, so the sample never reaches your disk in the clear."
    - name: "Analyse it in isolation"
      text: "Move the ZIP to an isolated analysis machine or sandbox, extract it there, hash it, and never run it on a production system."
faq:
  - question: "Is the Defender quarantine encrypted?"
    answer: "It is obfuscated with RC4 under one key that is hard-coded in Defender's engine and the same on every machine. The key was first published by the Cuckoo project and every public tool uses it. The layer stops the file being detected or run by accident; it does not protect the content from anyone who has a copy of the folder."
  - question: "What is the name of a ResourceData file?"
    answer: "Forty hexadecimal characters, in a subfolder named after the first two. ERNW wrote that it is unknown how the names are generated. On the one real public sample checked for this article, the name is the SHA-1 of the decrypted ResourceData content, not of the original file, so do not look it up as a file hash. Take the file's hashes from DetectionHistory or compute them on the recovered file."
  - question: "Can I recover a quarantined file without restoring it on the suspect machine?"
    answer: "Yes. Copy the Quarantine folder and decrypt it elsewhere, with Dissect's defender.recover, defender-dump or Defender Parser, which hands the file over as a ZIP encrypted with the password infected. MpCmdRun -Restore works on the live system and, without -Path, removes the item from quarantine and puts it back where it was."
  - question: "Why does a recovered quarantine file have a Zone.Identifier?"
    answer: "Defender stores the output of the Windows BackupRead function, which carries the file's alternate data streams and security descriptor along with its content. If the file had a Zone.Identifier stream when it was quarantined, the stream is in the quarantine too, with the zone and, when the downloading program wrote them, the download URLs."
---

**TL;DR.** The Defender quarantine is `C:\ProgramData\Microsoft\Windows Defender\Quarantine\`. **Entries** holds one metadata file per quarantine, named after a GUID: the threat name and ID, a timestamp, and for each resource its original path, size and file times. **ResourceData** holds the content, in subfolders named after the first two characters of a 40-character hex name. **Resources** links the two. Every part is RC4 with one public, hard-coded key, so this is obfuscation, not protection. Decrypted, a ResourceData file is the output of Windows `BackupRead`: security descriptor, data and alternate data streams, including the `Zone.Identifier` that says where the file came from. What you recover is live malware. [Defender Parser](/en#tool) reads the quarantine in the browser and gives a file back only as a ZIP encrypted with the password `infected`.

## Where it is and what it holds

| Folder | Content | Name |
| --- | --- | --- |
| `Quarantine\Entries\` | Metadata: when, what threat, which resources | `{GUID}` |
| `Quarantine\ResourceData\<xx>\` | The quarantined content, one file per resource | 40 hex characters, `<xx>` being the first two |
| `Quarantine\Resources\<xx>\` | A small record linking a ResourceData name to its Entries file | Same name as the ResourceData file |

The folder is readable by administrators and SYSTEM only; [collect it](/en/blog/collect-defender-artifacts) with backup semantics.

The format is not documented by Microsoft. Three public analyses describe it, and they agree on the essentials:

- Florian Bausch's [ERNW documentation](https://github.com/ernw/quarantine-formats/blob/master/docs/Windows_Defender.md), with Kaitai Struct definitions;
- Nikola Knežević's [2021 post](https://reversingfun.com/posts/how-to-extract-quarantine-files-from-windows-defender/) and his [defender-dump](https://github.com/knez/defender-dump) script;
- Max Groot and Erik Schamper's [December 2023 research for Fox-IT](https://www.nccgroup.com/us/research-blog/reverse-reveal-recover-windows-defender-quarantine-forensics/), which became Dissect's [`defender.quarantine`](https://docs.dissect.tools/en/latest/plugins/defender.quarantine.html) and [`defender.recover`](https://docs.dissect.tools/en/latest/plugins/defender.recover.html) plugins.

## The RC4 layer

Every part is encrypted with RC4 and a 256-byte key hard-coded in `mpengine.dll`. Fox-IT credits the [Cuckoo project](https://github.com/brad-sp/cuckoo-modified/blob/master/lib/cuckoo/common/quarantine.py) with first publishing it; ERNW, defender-dump, Dissect and the Velociraptor artifact all use the same bytes. An Entries file is encrypted in three pieces, each starting the RC4 stream again: a 60-byte header, then two sections whose sizes the header gives. A ResourceData file is decrypted in one pass.

The effect of the layer is that the quarantine never holds a working copy of the file: nothing in it can be started by accident or looks like the original to a scanner. Anyone with the folder can undo it.

## Entries: the metadata

| Part | Content |
| --- | --- |
| Header | Magic bytes `DB E8 C5 01`, the sizes of the two sections |
| Section 1 | Quarantine ID (equal to the file name in the sample below), scan ID, a timestamp (FILETIME), the threat ID, the threat name |
| Section 2 | A list of resources. For each: the original path, a type, and typed fields |

The fields of a `file` resource, as Dissect names them, are a resource ID (the ResourceData name), `CreationTime`, `LastAccessTime`, `LastWriteTime` and `FileSize`. The types Dissect knows are `file`, `regkey`, `runkey`, `startup`, `taskscheduler` and `internalbehavior`: one quarantine can list a file next to the Run value or the scheduled task that started it. Knežević also notes that one entry can cover several files.

A public example: the [maldump](https://github.com/NUKIB/maldump) project's test folder has a real entry for the EICAR test file. Decrypted, its file name `{80008A1B-0000-0000-7065-3EA2B161B275}` equals the quarantine ID in section 1, the threat name is `Virus:DOS/EICAR_Test_File`, the resource path is `\\?\C:\Windows\Temp\eicar.com` of type `file`, and the timestamp is 2022-01-18 13:44:00 UTC. The first eight bytes of the GUID, `0x80008A1B`, are the threat ID, 2147519003, which fits ERNW's observation that the two four-digit groups of the name are always `0000`.

What the timestamp marks exactly is not stated by any of the three analyses; tools report it as the quarantine time. Check it against the 1117 event for the same threat.

## ResourceData: the file and its streams

Fox-IT found that a decrypted ResourceData file is the output of the Windows `BackupRead` function: a sequence of `WIN32_STREAM_ID` records, each with a stream type, a size and, for named streams, a name. In practice:

| Stream | What it is |
| --- | --- |
| Security data | The file's security descriptor: owner SID and permissions |
| Data | The file's content |
| Alternate data | Named streams, such as `:Zone.Identifier:$DATA` |

The EICAR sample holds a security descriptor and the data, nothing else. A file downloaded from the internet usually also carries its `Zone.Identifier`, the Mark of the Web, with `ZoneId=3` for the Internet zone and, when the downloading program wrote them, `ReferrerUrl` and `HostUrl`. ERNW and defender-dump read only the security descriptor and the data that follows it; Dissect writes every stream to its own file.

**The name.** ERNW says the names look like SHA-1 values and that how they are generated is unknown; Knežević calls them a custom hash. On the maldump sample, the name `F7054EAE579A87B7DE9B39B7E0C7ACBDF0C8FBC8` is the SHA-1 of the whole decrypted ResourceData content, security descriptor included, not of the EICAR file, whose SHA-1 is `3395856CE81F2B7382DEE72602F798B642F14140`. That is one sample, but it shows that the name is not simply the file's SHA-1: do not search it as a file hash.

## Resources: the link

According to ERNW, a Resources file uses the same header as an Entries file. Its first section holds the resource ID, its second the GUID of the Entries file. Fox-IT and Knežević both skip it because the Entries file already lists its resources. Its use is the other direction: given a ResourceData file, find the entry it belongs to without decrypting every entry.

## What an entry tells you

- **The original path.** Where the file was when Defender acted, in `\\?\C:\...` form.
- **The original file times.** Creation, last access and last write, as FILETIME in UTC, recorded when the file was quarantined. They go into the timeline like any file system times.
- **The owner.** The owner SID in the security descriptor often points to the account that created the file. It is a lead to the user, to be confirmed.
- **The origin.** The `Zone.Identifier`, when present, gives the zone and the download URL. A file extracted from an archive carries the archive's Mark of the Web only if the extracting program copied it; 7-Zip, for example, does that only when its *Propagate Zone.Id stream* option is set, which is off by default ([SANS ISC](https://isc.sans.edu/diary/28810)).
- **Everything that was cleaned.** The list of resources: a registry key or a scheduled task next to the file can show how the malware meant to persist.
- **The sample.** Its hash, its strings, its configuration, once recovered in a lab.

The entry has no user and no process. Those are in the [1116 event](/en/blog/defender-operational-event-ids) and in the [DetectionHistory file](/en/blog/defender-detectionhistory-files) of the same detection.

## How long items stay

Microsoft gives 90 days as the default for *Configure removal of items from Quarantine folder* when the policy is not configured ([remediation settings](https://learn.microsoft.com/en-us/defender-endpoint/configure-remediation-microsoft-defender-antivirus)). The [Set-MpPreference reference](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference) says instead that with no value or zero, `QuarantinePurgeItemsAfterDelay` keeps items indefinitely. Read the effective value from the host rather than assume either. A deletion from quarantine writes event 1011; a restore writes 1009.

## Recovering a file safely

What comes out of the quarantine is the malware itself.

- **Do not restore on the suspect host.** Windows Security and [`MpCmdRun.exe -Restore`](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus) act on the live system. Without `-Path`, the item goes back to its original location and leaves the quarantine.
- **Copy the folder, decrypt elsewhere.** The encrypted files are inert; decrypt them on the analysis side.
- **Never write the sample in the clear to a workstation.** defender-dump puts what it extracts in a tar archive for that reason, to avoid triggering real-time protection. The convention between analysts is a ZIP encrypted with the password `infected`, which mail filters and antivirus engines cannot look inside.
- **Extract only in an isolated lab** or a sandbox, hash the file first, and keep the hash in your notes.

Defender Parser follows that convention: it decrypts the quarantine in the browser and gives a file back only as a ZIP encrypted with the password `infected`.

## Tools

| Tool | What it does | Limits |
| --- | --- | --- |
| [Dissect](https://github.com/fox-it/dissect.target/tree/main/dissect/target/plugins/os/windows/defender) `defender.quarantine`, `defender.recover` | Lists entries and their resources; writes every stream of every file resource | Writes the sample in the clear, named after its resource ID |
| [defender-dump](https://github.com/knez/defender-dump) | Lists file entries, exports the data stream into a tar | `file` entries only, data stream only |
| [maldump](https://github.com/NUKIB/maldump) | Several antivirus quarantine formats, Defender included | |
| [Velociraptor `DefenderQuarantineExtract`](https://docs.velociraptor.app/exchange/artifacts/pages/defenderquarantineextract/) | Decrypts ResourceData files on the endpoint, parses PEs, can upload them | Exchange artifact; runs on the live host |
| Defender Parser | Reads Entries, ResourceData and Resources, joins entries to detections, recovers a file as a ZIP with password `infected` | |

## FAQ

### Is the Defender quarantine encrypted?

It is obfuscated with RC4 under one key that is hard-coded in Defender's engine and the same on every machine. The key was first published by the Cuckoo project and every public tool uses it. The layer stops the file being detected or run by accident; it does not protect the content from anyone who has a copy of the folder.

### What is the name of a ResourceData file?

Forty hexadecimal characters, in a subfolder named after the first two. ERNW wrote that it is unknown how the names are generated. On the one real public sample checked for this article, the name is the SHA-1 of the decrypted ResourceData content, not of the original file, so do not look it up as a file hash. Take the file's hashes from DetectionHistory or compute them on the recovered file.

### Can I recover a quarantined file without restoring it on the suspect machine?

Yes. Copy the Quarantine folder and decrypt it elsewhere, with Dissect's defender.recover, defender-dump or Defender Parser, which hands the file over as a ZIP encrypted with the password infected. MpCmdRun -Restore works on the live system and, without -Path, removes the item from quarantine and puts it back where it was.

### Why does a recovered quarantine file have a Zone.Identifier?

Defender stores the output of the Windows BackupRead function, which carries the file's alternate data streams and security descriptor along with its content. If the file had a Zone.Identifier stream when it was quarantined, the stream is in the quarantine too, with the zone and, when the downloading program wrote them, the download URLs.

## Related articles

- [Defender DetectionHistory files: what they hold](/en/blog/defender-detectionhistory-files)
- [Collecting Microsoft Defender artifacts](/en/blog/collect-defender-artifacts)
- [Investigating an intrusion with Defender artifacts](/en/blog/defender-investigation-walkthrough)
