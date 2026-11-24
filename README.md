# Defender Parser

**Microsoft Defender Antivirus artifact viewer that runs entirely in the browser.**
Drop Defender's folders from `C:\ProgramData\Microsoft\Windows Defender`
(Quarantine, `Scans\History\Service\DetectionHistory`, Support), the exported
`Microsoft-Windows-Windows Defender%4Operational.evtx`, `MpCmdRun.log` and the
`SOFTWARE` hive, or a folder / `.zip` / `.tar.gz` collection of them (KAPE
`WindowsDefender` + `RegistryHivesSystem`, Velociraptor), and get one row per
detection with every source that speaks of it: the event log's 1116/1117
events, the DetectionHistory file, the quarantine entry and its content's
hashes, the MPLog lines; next to them every protection change (exclusions,
switches turned off, tamper protection, quarantine restores, MpCmdRun
commands) and flags when something deserves a look. Everything runs in a Web
Worker; nothing is uploaded. The files come from machines under
investigation, so every decoder is bounded against hostile input and fuzzed.

Quarantined files are live malware. The tool decrypts a ResourceData file
only to describe it (streams, size, hashes, owner, Zone.Identifier); it never
shows its bytes and never offers a raw download. The only way out is a ZIP
encrypted with the password `infected`, built on an explicit click after a
warning.

Live at [defenderparser.com](https://www.defenderparser.com). Sister of
[Windows Persistence](https://www.windowspersistence.com) and the in-browser
parser series. English only.

> Defender Parser is an independent project. It is not affiliated with,
> sponsored or endorsed by Microsoft. Microsoft, Windows and Microsoft Defender
> are trademarks of the Microsoft group of companies.

## Engine (`lib/defender/`)

| Module | Does |
|---|---|
| `quarantine.ts` | RC4 with Defender's published 256-byte key, each part decrypted on its own. `Entries\{GUID}`: 60-byte header (magic `DB E8 C5 01` / `DB E8 C5 02`, section sizes, CRC-32 of each section, accepted with or without the final inversion), section 1 (entry ID, scan ID, time, threat ID, threat name), section 2 (resources: path, type, fields by ID: resource ID, flags, physical path, detection context, times, size). `Resources\xx\<ID>`: the resource's IDs. `ResourceData\xx\<ID>`: BackupRead streams (data, security descriptor with owner and group, alternate streams such as `Zone.Identifier`, sparse) or a registry hive; recovered size, SHA-256, SHA-1, MD5 and whether the file name is the SHA-1 of the decrypted blob. Writers for the sample and tests. Limits: 4 MB an entry, 256 MB a ResourceData file |
| `history.ts` | DetectionHistory files: size/type/value records (u32, i32, u64, FILETIME, UTF-16, GUID, tracking blob) read into the documented sections (threat, severity, category, status, quarantine GUID, user, source, process, initial detection, remediation, count) and each resource's tracking pairs (`ThreatTrackingSha256`, `…Sha1`, `…MD5`, `…Size`, `…StartTime`…). Writer. Limits: 4 MB, 50,000 values, 2,000 resources |
| `evtx.ts` | The Operational log through EVTX Parser's vendored WebAssembly reader (`vendor/evtx`, 256 MB, 300,000 records): 1006/1007/1008/1015/1116/1117/1118/1119 detections and actions, 5000/5001/5004/5007/5010/5012/5013 changes, 1013/1014 history deletions, 1009–1012 quarantine restores and deletes, scans and signature updates for context; `%%NNN` message references named from documented tables; 5007 `Old Value`/`New Value` and 5013 values parsed into key, name and number |
| `mplog.ts` | `MPLog-*.log` and `MPDetection-*.log` (UTF-16LE or not): SDN queries with SHA-1 and SHA-256, process image names, DETECTION_ADD / DETECTIONEVENT / DETECTION_CLEANEVENT, low-fidelity and threat lines, EMS, mini-filter, exclusion and RTP config lines, service start/stop, threat-action blocks. A time with `Z` or an offset is UTC; any other is marked "no zone" and kept off the joins |
| `mpcmdrun.ts` | `MpCmdRun.log`: runs with their command line, start and end (local time, no zone), and the commands that matter (`-RemoveDefinitions`, `-Restore`, dynamic signatures, platform reset or revert, `-DownloadFile`, `-GetFiles`, scans) |
| `registry.ts`, `regf.ts`, `winbin.ts` | Bounded hive reader (from Windows Persistence); only `Microsoft\Windows Defender` and its `Policies` copy: exclusions (Paths, Extensions, Processes, IpAddresses, TemporaryPaths), Real-Time Protection, Spynet, Features (TamperProtection), the root switches, each with its key's LastWrite time |
| `paths.ts` | Host placement (drive folders `C/`, `C%3A/`, a host folder above them), roles by location, users from profile paths, `%VAR%` expansion, path keys for joining |
| `heuristics.ts` | Staging folders, Downloads, user-writable folders, broad extensions, script hosts, whether an exclusion covers a detection (folder, file, wildcard, extension, process by name or path) |
| `engine.ts` | Places files on hosts (loose files by name or content), joins the sources per detection (Detection ID, DetectionHistory file name, quarantine GUID, threat + path + time within 15 min, MPLog within 5 min and UTC only, SDN lines on the same path within 10 min), picks hashes (quarantine, then history, then MPLog; disagreements kept), builds the protection changes, sets the flags |
| `view.ts`, `dict.ts` | Findings, filters, timeline, CSV (formula-safe), JSON, Markdown report; UI strings |
| `zip.ts`, `recover.ts` | ZIP writer with traditional PKWARE encryption (ZipCrypto, STORE) and the recovery archive: the file, its alternate streams as `.ads`, a `README.txt` warning |
| `hash.ts`, `text.ts` | MD5, SHA-1, SHA-256, CRC-32; encoding detection and bounded line splitting (128 MB, 2,000,000 lines, 8,192 characters a line) |

### Flags

| Code | Severity | When |
|---|---|---|
| `action_failed` | high | The remediation failed (1118/1119, a failed status in DetectionHistory) |
| `action_allowed` | high | The detection was allowed rather than remediated |
| `exclusion_nearby` / `exclusion_near_detection` | high | An exclusion that covers the detection added within an hour of it (by its 5007 event or its key's LastWrite) |
| `exclusion_drive_root` | high | A path exclusion of a whole drive or `*` |
| `exclusion_writable` | high | A path or process exclusion under a user-writable folder (Users, ProgramData, temp folders, Downloads, AppData) |
| `exclusion_broad_ext` | high | An extension exclusion of `exe`, `dll`, `ps1`, `bat`, `js`, `hta`… |
| `exclusion_script_host` | high | A process exclusion of PowerShell, cmd, wscript, mshta, rundll32, regsvr32, msbuild… |
| `rtp_off` | high | Real-time protection disabled (5001) |
| `scanning_off` | high | Antivirus or antispyware disabled (5010, 5012) |
| `setting_off` | high | A `Disable*` value set to 1 (5007 or the hive) |
| `quarantine_restored` | high | A quarantined item restored (1009, `MpCmdRun -Restore`) |
| `remove_definitions` | high | `MpCmdRun -RemoveDefinitions` |
| `staging_path` | medium | Detected file in a temp folder, `Users\Public`, `$Recycle.Bin`, `PerfLogs`, `\Temp` or a first-level ProgramData folder |
| `amsi` | medium | Detected in memory or script content through AMSI |
| `same_hash` | medium | The same hash detected at several paths |
| `exclusion_process_name` | medium | A process exclusion by bare name (matches any program of that name) |
| `tamper_off` | medium | TamperProtection value 4 or 0 (off) |
| `tamper_blocked` | medium | Tamper protection blocked a change (5013) |
| `quarantine_deleted` | medium | A quarantined item deleted (1011) |
| `history_deleted` | medium | Detection history deleted (1013) |
| `mpcmdrun_tamper` | medium | Dynamic signatures added or removed, platform reset or reverted, `-DownloadFile` |
| `downloads` | low | Detected file in a Downloads folder |
| `maps_off` | low | Cloud protection (MAPS) off |
| `exclusion_other` | low | Any other exclusion |
| `recent` | low | Within 7 days of the host's newest event |

## The site

- Intake (`lib/intake`): files, folders, ZIP (ZIP64, percent-encoded
  Velociraptor paths, backslash names) and TAR / TAR.GZ. In a collection only
  the quarantine, DetectionHistory and Support folders, the Defender event
  logs, `MpCmdRun.log` from the temp folders and SOFTWARE are opened (and
  Defender files collected out of their folders, by name); the rest is
  counted. `mpenginedb.db` is listed as not read.
- Workspace (`components/defender`): full screen on results; Findings,
  Detections (sortable), Quarantine (entries, resources, content facts, the
  recovery box), Protection changes, MPLog (lines, files seen, processes
  seen), Timeline and Files tabs; detail sheet with every source of a
  detection, how each was joined, and the raw record; exports (CSV, JSON,
  Markdown; never file bytes).
- "Collect Defender's files and keys" (`#collect`): robocopy `/B` and
  wevtutil, KAPE, Velociraptor, PowerShell, where everything is.
- Home: the tool (`#tool`), then the reference (what Defender leaves behind,
  the artifacts, what they prove and do not, how the tool reads them, limits,
  FAQ) and the latest posts. Blog in `content/blog` (English; no glossary);
  `sitemapFrom` in a page's frontmatter keeps it out of `sitemap.xml` until
  that date (`lib/release.ts`, hourly sitemap).

Files can also arrive from [Disk Image Parser](https://www.diskimageparser.com)
tab to tab with [tab-handoff](https://github.com/Cyber-Experts/tab-handoff)
(`lib/intake/handoff.ts`, sender `disk-image-parser`): one message, only from
the tab that opened this one and from Disk Image Parser's exact origin
(`http://localhost:3000` in development), within set limits; nothing is
uploaded and the URL carries nothing about the files.

## Format notes and sources

- Quarantine: the RC4 key and entry layout from cuckoo-modified's
  `quarantine.py` and Fox-IT's Dissect (`dissect.target` Defender plugin, with
  its test entries); magic numbers and CRCs from Yamato Security's
  ys-defender-history-parser (`src/quarantine.rs`); the ResourceData name as
  the SHA-1 of the whole decrypted blob from Yamato and maldump, seen on one
  real sample, so a mismatch is reported, not called tampering.
- DetectionHistory: Orange Cyberdefense's DHParser notes (`doc.md`) for the
  record layout and sections; ys-defender-history-parser for the field
  mapping.
- Operational log: Microsoft's "Microsoft Defender Antivirus event IDs and
  error codes" page; data names checked against EvtxECmd's example maps; ID
  tables from the `MSFT_MpThreat`, `MSFT_MpThreatDetection` WMI classes and
  `Get-MpThreatCatalog`. The raw `Source Name`, `Action Name` and similar
  fields hold `%%NNN` references; the tool names the ID from the tables.
- MPLog: Intrinsec's mplog_parser, ys-defender-history-parser
  (`src/mplog.rs`) and CrowdStrike's write-up on Microsoft Protection Logging
  for the SDN, process image and detection lines; SDN lines carry hashes only
  on some platform versions.
- TamperProtection 5 = on, 4 = off: one public source (Bhabesh Raj); not
  documented by Microsoft.
- Since March 2026, devices managed by Microsoft Defender for Endpoint no
  longer keep readable exclusions in the registry: an empty `Exclusions` key
  is not proof that there are none.

## Samples (`npm run samples`)

`scripts/make-samples.ts` builds, deterministically, FIN-WKS-07 (the
Windows 11 workstation of the svc_backup story, 2026-09-14) on the Windows
Persistence SOFTWARE hive pinned in `scripts/sample-src/SOURCES.md`, with an
Operational log written by `scripts/evtx-writer.ts`:

- `public/samples/FIN-WKS-07.zip`: the Defender folders, the Operational log,
  `Windows\Temp\MpCmdRun.log` and SOFTWARE in KAPE's `C/…` layout.
  `Backdoor:Win64/Gfxhelp.A` on `C:\Users\svc_backup\Downloads\tools\m64.exe`
  (1116 at 10:06:51, quarantined, 1117 at 10:06:52), tamper protection
  blocking a change (5013, 10:07:36), the exclusions `C:\ProgramData\Intel`
  and `m64.exe` (two 5007 at 10:08:12), `Trojan:PowerShell/AmsiBypass.SY`
  blocked through AMSI (10:12:03); alice's undetected
  `Invoice_2026-0914.pdf.exe`, seen only in an MPLog SDN line with its hashes
  (09:12:06); an older `PUA:Win32/Convertly` in alice's Downloads
  (2026-06-30), quarantined with its Zone.Identifier stream.
- `public/samples/FIN-WKS-07/…` and `manifest.json`: the same files, loose, for
  Disk Image Parser's sample disk.

The quarantined "files" are benign placeholder text (no EICAR string, no
executable header). `tests/sample.test.ts` checks the generator output byte
for byte, the pinned hashes and what is flagged.

## Development

```bash
npm ci
npm run dev -- -p 3001 # Disk Image Parser runs on 3000
npm test               # Vitest: decoders, ZIP, engine, intake, sample, views, release, fuzz
npm run samples
npm run typecheck
npm run lint
npm run build
```

## Limits

- Microsoft documents the events, not the files: the quarantine,
  DetectionHistory and MPLog layouts come from public research and may change
  with Defender's platform versions. Unknown values are shown, not guessed.
- MPLog lines without a zone are not placed on the UTC timeline's joins;
  `MpCmdRun.log` times are local.
- `mpenginedb.db` is not read, hive transaction logs are not replayed, sparse
  quarantined files are not rebuilt.
- A flag is a reason to look, not a verdict.

## License

[MIT](LICENSE), except the vendored EVTX reader (`vendor/evtx/`,
`public/evtx_wasm_bg.wasm`), which comes from
[EVTX Parser](https://github.com/Cyber-Experts/evtx-parser) under the
[Elastic License 2.0](vendor/evtx/LICENSE).
