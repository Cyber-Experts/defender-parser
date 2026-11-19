/**
 * The "Try a sample" collection: FIN-WKS-07, the Windows 11 workstation of
 * the svc_backup story (2026-09-14, UTC), with what KAPE's WindowsDefender and
 * RegistryHivesSystem targets collect, in KAPE's layout (C\…):
 *
 *   public/samples/FIN-WKS-07.zip               what "Try a sample" opens
 *   public/samples/FIN-WKS-07/… + manifest.json  the same files, loose, for
 *                                               Disk Image Parser's sample disk
 *
 * The story, as the sister sites tell it. svc_backup (created 09:57:41, RDP
 * logon 09:59:28) runs a PowerShell download cradle at 10:02:11;
 * Invoke-WebRequest saves http://files.example/tools.zip to its Downloads at
 * 10:03:05; 7-Zip opens it at 10:06:40 and extracts tools\m64.exe, which
 * real-time protection detects at 10:06:51 (Backdoor:Win64/Gfxhelp.A) and
 * quarantines at 10:06:52. The quarantined copy has no Zone.Identifier
 * stream: Invoke-WebRequest is not known to mark what it saves, and 7-Zip
 * copies an archive's mark to extracted files only when told to. At 10:07:36
 * `Set-MpPreference -DisableRealtimeMonitoring $true` is blocked by tamper
 * protection (5013). At 10:08:12 the exclusions C:\ProgramData\Intel (path)
 * and m64.exe (process) are added (two 5007 events, the hive's key times).
 * C:\ProgramData\Intel\m64.exe first runs at 10:09:44, unseen. At 10:12:03
 * AMSI detects the PowerShell AMSI-bypass script block and blocks it
 * (Trojan:PowerShell/AmsiBypass.SY). alice's Invoice_2026-0914.pdf.exe ran at
 * 09:12:07 and was not detected: MPLog still has its cloud (SDN) query with
 * its hashes. Before that, months of ordinary activity: signature updates, two
 * scheduled scans, and a PUA alice downloaded in Edge on 2026-06-30,
 * quarantined with the Zone.Identifier stream the browser wrote.
 *
 * Synthetic: threat names follow Defender's naming with made-up families;
 * threat IDs, GUIDs and versions are made up. The quarantined "malware" is
 * benign text: m64.exe is Disk Image Parser's placeholder (same bytes, same
 * hashes, scripts/sample-src/SOURCES.md), the PUA a placeholder of the same
 * kind. No EICAR string, no real program. The SOFTWARE hive is Windows
 * Persistence's, unchanged. MpCmdRun.log and MPLog's block times are written
 * in the machine's local time (UTC+02:00, Windows Persistence's SYSTEM hive):
 * the tool shows them as written. Deterministic: fixed contents and times.
 */

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { buildEvtx, type EvtxEvent } from "./evtx-writer";
import { writeHistory, type HistorySpec } from "../lib/defender/history";
import { securityDescriptor, writeEntry, writeResourceData, writeResourceRecord } from "../lib/defender/quarantine";
import { sidBytes } from "../lib/defender/winbin";
import { writeZip, type ZipItem } from "../lib/defender/zip";

const SRC = join(process.cwd(), "scripts/sample-src/windows-persistence");
const OUT = process.env.SAMPLES_OUT ?? join(process.cwd(), "public/samples");
const HOST = "FIN-WKS-07";
const T = (iso: string) => Date.parse(iso);
/** FIN-WKS-07 runs at UTC+02:00 in summer (Romance Standard Time). */
const LOCAL = 2 * 3_600_000;

const MACHINE = "S-1-5-21-3623811015-3361044348-30300820";
const SVC = `${MACHINE}-1119`;
const ALICE = `${MACHINE}-1104`;
const SYSTEM = "S-1-5-18";
const ADMINS = "S-1-5-32-544";

// ---------------------------------------------------------------------------
// The benign placeholders standing in for the quarantined files.

/** Disk Image Parser's placeholder(): readable filler standing in for a binary that must not ship. */
function placeholder(name: string, size: number, site = "Disk Image Parser"): Uint8Array {
  const head = `SYNTHETIC PLACEHOLDER for ${name}\r\n${site} demo sample (fictional FIN-WKS-07 intrusion).\r\nThis is not an executable and contains no real tooling.\r\n`;
  const line = `-- ${name} placeholder padding --\r\n`;
  let s = head;
  while (s.length < size) s += line;
  return new TextEncoder().encode(s.slice(0, size));
}

export const M64 = placeholder("m64.exe", 9_216);
export const PUA = placeholder("ConvertlyPDF_Setup.exe", 6_144, "Defender Parser");
export const INVOICE = placeholder("Invoice_2026-0914.pdf.exe", 7_168, "Defender Parser");
const hash = (alg: string, b: Uint8Array) => createHash(alg).update(b).digest("hex");

// ---------------------------------------------------------------------------
// Threats (synthetic families).

export const THREATS = {
  m64: { name: "Backdoor:Win64/Gfxhelp.A", id: 2147958211, severity: 5, category: 6 },
  amsi: { name: "Trojan:PowerShell/AmsiBypass.SY", id: 2147958233, severity: 5, category: 8 },
  pua: { name: "PUA:Win32/Convertly", id: 2147958190, severity: 1, category: 27 },
};

const M64_PATH = "C:\\Users\\svc_backup\\Downloads\\tools\\m64.exe";
const PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const PUA_PATH = "C:\\Users\\alice\\Downloads\\ConvertlyPDF_Setup.exe";

const IDS = {
  m64Detection: "{3C9B6E14-7A2D-4F81-9C3E-5B0D2A7F1E68}",
  amsiDetection: "{A71F0C55-2E9B-4D36-8B4A-6C1E9D03F2B7}",
  puaDetection: "{5E2D8A40-91C7-4B3F-A6D2-0F7B3C9E4A15}",
  m64Scan: "{D41C77E2-0B6A-4E59-93F1-2A8C5E7B0D34}",
  puaScan: "{0B83E5D1-6F2A-4C97-B1E4-7D9A2C5F3E80}",
};
/** A quarantine entry's GUID starts with the threat ID's low 32 bits, as in Fox-IT's test entries ({800362A7-…} for threat 2147705511). */
const entryGuid = (threatId: number, tail: string) => `{${(threatId >>> 0).toString(16).toUpperCase().padStart(8, "0")}-0000-0000-${tail}}`;
export const ENTRY_M64 = entryGuid(THREATS.m64.id, "6A3C-1F82D4E0B917");
export const ENTRY_PUA = entryGuid(THREATS.pua.id, "2E07-94B1C6A3D85F");

// ---------------------------------------------------------------------------
// The Operational log.

const DEFENDER = "Microsoft-Windows-Windows Defender";
const CHANNEL = "Microsoft-Windows-Windows Defender/Operational";
const PRODUCT = "4.18.25070.5";
const ENGINE = "1.1.25070.4";
const iso = (ms: number) => new Date(ms).toISOString();
const sig = (n: number) => `1.437.${n}.0`;

interface Ev {
  time: number;
  id: number;
  level?: number;
  data: [string, string][];
}

/** 1116 / 1117: the field order of EvtxECmd's example events. Names are written as words (real logs hold %%NNN references there). */
function threatEvent(id: 1116 | 1117, t: { name: string; id: number; severity: number; category: number }, o: { detectionId: string; detected: number; sourceId: number; sourceName: string; process: string; user: string; path: string; actionId: number; actionName: string; signature: string; categoryName: string; severityName: string }): [string, string][] {
  return [
    ["Product Name", "Microsoft Defender Antivirus"],
    ["Product Version", PRODUCT],
    ["Detection ID", o.detectionId],
    ["Detection Time", iso(o.detected)],
    ["Unused", ""],
    ["Unused2", ""],
    ["Threat ID", String(t.id)],
    ["Threat Name", t.name],
    ["Severity ID", String(t.severity)],
    ["Severity Name", o.severityName],
    ["Category ID", String(t.category)],
    ["Category Name", o.categoryName],
    ["FWLink", `https://go.microsoft.com/fwlink/?linkid=37020&name=${t.name}&threatid=${t.id}&enterprise=0`],
    ["Status Code", id === 1116 ? "1" : "3"],
    ["Status Description", ""],
    ["State", id === 1116 ? "1" : "2"],
    ["Source ID", String(o.sourceId)],
    ["Source Name", o.sourceName],
    ["Process Name", o.process],
    ["Detection User", o.user],
    ["Unused3", ""],
    ["Path", o.path],
    ["Origin ID", "1"],
    ["Origin Name", "Local machine"],
    ["Execution ID", "0"],
    ["Execution Name", "Unknown"],
    ["Type ID", "0"],
    ["Type Name", "Concrete"],
    ["Pre Execution Status", "0"],
    ["Action ID", id === 1116 ? "9" : String(o.actionId)],
    ["Action Name", id === 1116 ? "Not Applicable" : o.actionName],
    ["Unused4", ""],
    ["Error Code", "0x00000000"],
    ["Error Description", "The operation completed successfully. "],
    ["Unused5", ""],
    ["Post Clean Status", "0"],
    ["Additional Actions ID", "0"],
    ["Additional Actions String", "No additional actions required"],
    ["Remediation User", id === 1117 ? "NT AUTHORITY\\SYSTEM" : ""],
    ["Unused6", ""],
    ["Security intelligence Version", `AV: ${o.signature}, AS: ${o.signature}, NIS: ${o.signature}`],
    ["Engine Version", `AM: ${ENGINE}, NIS: ${ENGINE}`],
  ];
}

const sigUpdate = (time: number, prev: number, cur: number): Ev => ({
  time,
  id: 2000,
  data: [
    ["Product Name", "Microsoft Defender Antivirus"],
    ["Product Version", PRODUCT],
    ["Current Signature Version", sig(cur)],
    ["Previous Signature Version", sig(prev)],
    ["Unused", ""],
    ["Unused2", ""],
    ["Unused3", ""],
    ["Domain", "NT AUTHORITY"],
    ["User", "SYSTEM"],
    ["SID", SYSTEM],
    ["Signature Type Index", "1"],
    ["Signature Type", "AntiVirus"],
    ["Update Type Index", "2"],
    ["Update Type", "Delta"],
    ["Current Engine Version", ENGINE],
    ["Previous Engine Version", ENGINE],
  ],
});

const scan = (start: number, end: number, scanId: string): Ev[] => {
  const common: [string, string][] = [
    ["Product Name", "Microsoft Defender Antivirus"],
    ["Product Version", PRODUCT],
    ["Scan ID", scanId],
    ["Scan Type Index", "1"],
    ["Scan Type", "Antimalware"],
    ["Scan Parameters Index", "1"],
    ["Scan Parameters", "Quick Scan"],
    ["Domain", "NT AUTHORITY"],
    ["User", "SYSTEM"],
    ["SID", SYSTEM],
  ];
  const s = Math.round((end - start) / 1000);
  return [
    { time: start, id: 1000, data: [...common, ["Scan Resources", ""]] },
    { time: end, id: 1001, data: [...common, ["Scan Time Hours", "0"], ["Scan Time Minutes", String(Math.floor(s / 60))], ["Scan Time Seconds", String(s % 60)]] },
  ];
};

const config = (time: number, oldValue: string, newValue: string): Ev => ({
  time,
  id: 5007,
  data: [
    ["Product Name", "Microsoft Defender Antivirus"],
    ["Product Version", PRODUCT],
    ["Old Value", oldValue],
    ["New Value", newValue],
  ],
});

export function operationalEvents(): EvtxEvent[] {
  const evs: Ev[] = [];
  // Install day: real-time protection on, first updates.
  evs.push({ time: T("2025-11-03T09:52:10.204Z"), id: 5000, data: [["Product Name", "Microsoft Defender Antivirus"], ["Product Version", PRODUCT]] });
  const updates: [string, number][] = [
    ["2025-11-03T10:05:31.512Z", 380],
    ["2025-12-01T08:03:12.004Z", 382],
    ["2026-01-05T08:02:44.310Z", 387],
    ["2026-02-02T08:04:09.871Z", 392],
    ["2026-03-02T08:03:57.118Z", 398],
    ["2026-04-06T08:02:21.640Z", 404],
    ["2026-05-04T08:05:02.233Z", 410],
    ["2026-06-01T08:03:48.902Z", 415],
    ["2026-07-06T08:04:30.457Z", 421],
    ["2026-08-03T08:04:13.716Z", 427],
    ["2026-09-07T08:04:42.390Z", 433],
    ["2026-09-14T08:05:11.027Z", 437],
  ];
  let prev = 376;
  for (const [t, n] of updates) {
    evs.push(sigUpdate(T(t), prev, n));
    prev = n;
  }
  evs.push(...scan(T("2026-08-02T03:12:04.551Z"), T("2026-08-02T03:21:40.093Z"), "{7E0A3C21-5D84-4B6F-9E12-3A6C8F0D4B57}"));
  evs.push(...scan(T("2026-09-06T03:10:15.338Z"), T("2026-09-06T03:18:51.762Z"), "{C2F49B08-1A3E-4D75-8C60-9E2B7F4A1D36}"));
  // 2026-06-30: alice downloads a PUA in Edge; quarantined.
  const pua = { detectionId: IDS.puaDetection, detected: T("2026-06-30T14:22:04.871Z"), sourceId: 4, sourceName: "IOAV", process: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", user: "FIN-WKS-07\\alice", path: `file:_${PUA_PATH}`, actionId: 2, actionName: "Quarantine", signature: sig(415), categoryName: "Potentially Unwanted Software", severityName: "Low" };
  evs.push({ time: T("2026-06-30T14:22:05.316Z"), id: 1116, level: 3, data: threatEvent(1116, THREATS.pua, pua) });
  evs.push({ time: T("2026-06-30T14:22:07.142Z"), id: 1117, level: 4, data: threatEvent(1117, THREATS.pua, pua) });
  // 2026-09-14.
  const m64 = { detectionId: IDS.m64Detection, detected: T("2026-09-14T10:06:51.388Z"), sourceId: 3, sourceName: "Real-Time Protection", process: "C:\\Program Files\\7-Zip\\7zFM.exe", user: "FIN-WKS-07\\svc_backup", path: `file:_${M64_PATH}`, actionId: 2, actionName: "Quarantine", signature: sig(437), categoryName: "Backdoor", severityName: "Severe" };
  evs.push({ time: T("2026-09-14T10:06:51.611Z"), id: 1116, level: 3, data: threatEvent(1116, THREATS.m64, m64) });
  evs.push({ time: T("2026-09-14T10:06:52.904Z"), id: 1117, level: 4, data: threatEvent(1117, THREATS.m64, m64) });
  evs.push({
    time: T("2026-09-14T10:07:36.120Z"),
    id: 5013,
    level: 3,
    data: [
      ["Product Name", "Microsoft Defender Antivirus"],
      ["Product Version", PRODUCT],
      ["Value", "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring = 0x1"],
    ],
  });
  evs.push(config(T("2026-09-14T10:08:12.457Z"), "", "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\ProgramData\\Intel = 0x0"));
  evs.push(config(T("2026-09-14T10:08:12.771Z"), "", "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes\\m64.exe = 0x0"));
  const amsi = { detectionId: IDS.amsiDetection, detected: T("2026-09-14T10:12:03.215Z"), sourceId: 10, sourceName: "AMSI", process: PS, user: "FIN-WKS-07\\svc_backup", path: `amsi:_${PS}`, actionId: 10, actionName: "Block", signature: sig(437), categoryName: "Trojan", severityName: "Severe" };
  evs.push({ time: T("2026-09-14T10:12:03.402Z"), id: 1116, level: 3, data: threatEvent(1116, THREATS.amsi, amsi) });
  evs.push({ time: T("2026-09-14T10:12:03.880Z"), id: 1117, level: 4, data: threatEvent(1117, THREATS.amsi, amsi) });
  evs.sort((a, b) => a.time - b.time);
  return evs.map((e, i) => ({ recordId: i + 1, time: e.time, provider: DEFENDER, providerGuid: "{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}", eventId: e.id, level: e.level ?? 4, channel: CHANNEL, computer: HOST, user: SYSTEM, data: e.data }));
}

// ---------------------------------------------------------------------------
// The quarantine.

const ZONE_PUA = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://convertly.example/download\r\nHostUrl=https://downloads.convertly.example/ConvertlyPDF_Setup.exe\r\n";

function content(data: Uint8Array, owner: string, zone?: string) {
  const sd = securityDescriptor(sidBytes(owner), sidBytes(owner), [sidBytes(SYSTEM), sidBytes(ADMINS), sidBytes(owner)]);
  return writeResourceData([{ kind: 3, data: sd }, { kind: 1, data }, ...(zone ? [{ kind: 4, name: ":Zone.Identifier:$DATA", data: new TextEncoder().encode(zone) }] : [])]);
}

export function quarantine() {
  const m64 = content(M64, SVC);
  const pua = content(PUA, ALICE, ZONE_PUA);
  const m64Entry = writeEntry({
    guid: ENTRY_M64,
    scanId: IDS.m64Scan,
    time: T("2026-09-14T10:06:52.710Z"),
    threatId: THREATS.m64.id,
    threatName: THREATS.m64.name,
    resources: [{ path: `\\\\?\\${M64_PATH}`, physicalPath: M64_PATH, resourceId: m64.id, attributes: 0x20, created: T("2026-09-14T10:06:50.204Z"), accessed: T("2026-09-14T10:06:50.204Z"), written: T("2026-09-01T20:40:12Z"), size: M64.length }],
  });
  const puaEntry = writeEntry({
    guid: ENTRY_PUA,
    scanId: IDS.puaScan,
    time: T("2026-06-30T14:22:06.950Z"),
    threatId: THREATS.pua.id,
    threatName: THREATS.pua.name,
    resources: [{ path: `\\\\?\\${PUA_PATH}`, physicalPath: PUA_PATH, resourceId: pua.id, attributes: 0x20, created: T("2026-06-30T14:22:03.512Z"), accessed: T("2026-06-30T14:22:04.101Z"), written: T("2026-06-30T14:22:04.087Z"), size: PUA.length }],
  });
  return {
    m64: { entry: m64Entry, data: m64.bytes, id: m64.id, record: writeResourceRecord(m64.bytes.length, m64.id, [ENTRY_M64]) },
    pua: { entry: puaEntry, data: pua.bytes, id: pua.id, record: writeResourceRecord(pua.bytes.length, pua.id, [ENTRY_PUA]) },
  };
}

// ---------------------------------------------------------------------------
// DetectionHistory.

export function historyFiles(): { name: string; folder: string; bytes: Uint8Array; mtime: number }[] {
  const m64: HistorySpec = {
    threatId: THREATS.m64.id,
    detectionId: IDS.m64Detection,
    threatName: THREATS.m64.name,
    severityId: THREATS.m64.severity,
    categoryId: THREATS.m64.category,
    threatStatusId: 3,
    list: [3],
    resources: [
      {
        kind: "file",
        location: M64_PATH,
        tracking: [
          ["ThreatTrackingStartTime", { time: T("2026-09-14T10:06:51.388Z") }],
          ["ThreatTrackingSha256", { str: hash("sha256", M64).toUpperCase() }],
          ["ThreatTrackingSha1", { str: hash("sha1", M64).toUpperCase() }],
          ["ThreatTrackingMD5", { str: hash("md5", M64).toUpperCase() }],
          ["ThreatTrackingSize", { u64: M64.length }],
          ["ThreatTrackingThreatId", { u32: THREATS.m64.id >>> 0 }],
          ["ThreatTrackingScanSource", { u32: 3 }],
        ],
      },
    ],
    statusChanged: T("2026-09-14T10:06:52.710Z"),
    quarantineId: ENTRY_M64,
    executionStatusId: 4,
    user: "FIN-WKS-07\\svc_backup",
    sourceTypeId: 3,
    process: "C:\\Program Files\\7-Zip\\7zFM.exe",
    initialDetection: T("2026-09-14T10:06:51.388Z"),
    remediation: T("2026-09-14T10:06:52.710Z"),
  };
  const amsi: HistorySpec = {
    threatId: THREATS.amsi.id,
    detectionId: IDS.amsiDetection,
    threatName: THREATS.amsi.name,
    severityId: THREATS.amsi.severity,
    categoryId: THREATS.amsi.category,
    threatStatusId: 6,
    list: [6],
    resources: [{ kind: "amsi", location: PS, tracking: [["ThreatTrackingStartTime", { time: T("2026-09-14T10:12:03.215Z") }], ["ThreatTrackingScanSource", { u32: 10 }]] }],
    statusChanged: T("2026-09-14T10:12:03.861Z"),
    executionStatusId: 1,
    user: "FIN-WKS-07\\svc_backup",
    sourceTypeId: 10,
    process: PS,
    initialDetection: T("2026-09-14T10:12:03.215Z"),
    remediation: T("2026-09-14T10:12:03.861Z"),
  };
  const bare = (g: string) => g.replace(/[{}]/g, "");
  return [
    { name: bare(IDS.m64Detection), folder: "07", bytes: writeHistory(m64), mtime: T("2026-09-14T10:06:52.950Z") },
    { name: bare(IDS.amsiDetection), folder: "08", bytes: writeHistory(amsi), mtime: T("2026-09-14T10:12:03.905Z") },
  ];
}

// ---------------------------------------------------------------------------
// MPLog, MPDetection, MpCmdRun.log (UTF-16LE with a BOM, CRLF).

function utf16(text: string): Uint8Array {
  const out = new Uint8Array(2 + text.length * 2);
  out.set([0xff, 0xfe]);
  for (let i = 0; i < text.length; i++) {
    out[2 + i * 2] = text.charCodeAt(i) & 0xff;
    out[3 + i * 2] = text.charCodeAt(i) >> 8;
  }
  return out;
}
const crlf = (lines: string[]) => `${lines.join("\r\n")}\r\n`;
/** "09-14-2026 12:06:53": MPLog's block time, written in local time. */
const usLocal = (utc: number) => {
  const d = new Date(utc + LOCAL);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}-${d.getUTCFullYear()} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
};
const dev = (p: string) => p.replace(/^C:/i, "\\Device\\HarddiskVolume3");
const sdn = (t: string, path: string, data: Uint8Array) => `${t} SDN:Issuing SDN query for ${path} (${dev(path)}) (sha1=${hash("sha1", data)}, sha2=${hash("sha256", data)})`;

export function mplogText(): string {
  const started = T("2026-09-01T10:15:32.104Z");
  return crlf([
    "Microsoft Defender Antivirus (77BDAF73-B396-481F-9042-AD358843EC24) Service Log",
    `Started On ${usLocal(started)}`,
    `Current time: 09/01/2026 10:15:32.104 UTC (48211 ms since boot)`,
    "2026-09-01T10:15:33.880Z ProcessImageName: MsMpEng.exe, Pid: 3536, TotalTime: 4210, Count: 1802, MaxTime: 312, MaxTimeFile: \\Device\\HarddiskVolume3\\Windows\\System32\\config\\SOFTWARE, EstimatedImpact: 3%",
    "2026-09-03T09:41:07.552Z ProcessImageName: OUTLOOK.EXE, Pid: 8124, TotalTime: 1984, Count: 61, MaxTime: 402, MaxTimeFile: \\Device\\HarddiskVolume3\\Users\\alice\\AppData\\Local\\Microsoft\\Olk\\Attachments\\Q3_forecast.xlsx, EstimatedImpact: 6%",
    "2026-09-10T16:02:44.190Z ProcessImageName: msedge.exe, Pid: 6212, TotalTime: 2733, Count: 140, MaxTime: 261, MaxTimeFile: \\Device\\HarddiskVolume3\\Users\\alice\\Downloads\\Q3_forecast_final.pdf, EstimatedImpact: 4%",
    sdn("2026-09-14T09:12:06.934Z", "C:\\Users\\alice\\Downloads\\Invoice_2026-0914.pdf.exe", INVOICE),
    "2026-09-14T09:12:07.221Z SDN:SDN query completed: 00000000",
    "2026-09-14T09:20:11.502Z ProcessImageName: Invoice_2026-0914.pdf.exe, Pid: 4412, TotalTime: 318, Count: 9, MaxTime: 140, MaxTimeFile: \\Device\\HarddiskVolume3\\Users\\alice\\Downloads\\Invoice_2026-0914.pdf.exe, EstimatedImpact: 12%",
    "2026-09-14T10:05:09.640Z ProcessImageName: powershell.exe, Pid: 5120, TotalTime: 2210, Count: 37, MaxTime: 980, MaxTimeFile: \\Device\\HarddiskVolume3\\Users\\svc_backup\\Downloads\\tools.zip, EstimatedImpact: 22%",
    sdn("2026-09-14T10:06:51.104Z", M64_PATH, M64),
    `2026-09-14T10:06:51.388Z DETECTIONEVENT MPSOURCE_REALTIME ${THREATS.m64.name} file:${M64_PATH}`,
    `2026-09-14T10:06:51.388Z DETECTION_ADD#1 ${THREATS.m64.name} file:${M64_PATH}`,
    `2026-09-14T10:06:52.402Z [RTP] [Mini-filter] Blocked file(#12): ${dev(M64_PATH)}. Process: \\Device\\HarddiskVolume3\\Program Files\\7-Zip\\7zFM.exe, Status: 0x0, State: 0, ScanRequest #9184, FileId: 0x2000000031a2f, Reason: OnClose, IoStatusBlockForNewFile: 0x2, DesiredAccess:0x40000000, FileAttributes:0x20, ScanAttributes:0x10, AccessStateFlags:0x800, BackingFileInfo: 0x0, 0x0, 0x0:0\\0x0:0`,
    "Beginning threat actions",
    `Start time:${usLocal(T("2026-09-14T10:06:52Z"))}`,
    `Threat Name:${THREATS.m64.name}`,
    `Threat ID:${THREATS.m64.id}`,
    "Action:quarantine",
    "Schema:file",
    `Path:${M64_PATH}`,
    "Result:0x00000000",
    `Finished threat ID:${THREATS.m64.id}`,
    "Threat result:0x00000000",
    "Finished threat actions",
    "2026-09-14T10:08:13.020Z [RTP] [Exclusion] C:\\ProgramData\\Intel -> \\Device\\HarddiskVolume3\\ProgramData\\Intel",
    "2026-09-14T10:15:42.118Z ProcessImageName: 7zFM.exe, Pid: 7344, TotalTime: 1630, Count: 214, MaxTime: 412, MaxTimeFile: \\Device\\HarddiskVolume3\\Users\\svc_backup\\Downloads\\tools.zip, EstimatedImpact: 41%",
  ]);
}

export function mpdetectionText(): string {
  return crlf([
    "2026-09-01T10:15:33.210Z Service started - Microsoft Defender Antivirus (77BDAF73-B396-481F-9042-AD358843EC24)",
    `2026-09-01T10:15:33.214Z Version: Product: ${PRODUCT}, Service: ${PRODUCT}, Engine: ${ENGINE}, AS: ${sig(433)}, AV: ${sig(433)}`,
  ]);
}

/** MpCmdRun.log: the scheduled signature updates, times in local time with left-to-right marks, as Dissect's test file has them. */
export function mpcmdrunText(): string {
  const day = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const stamp = (utc: number) => {
    const d = new Date(utc + LOCAL);
    const p = (n: number) => String(n).padStart(2, "0");
    return `\u200e${day[d.getUTCDay()]} \u200e${mon[d.getUTCMonth()]} \u200e${p(d.getUTCDate())} \u200e${d.getUTCFullYear()} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
  };
  const sep = "-".repeat(85);
  const lines: string[] = [];
  for (const [start, end] of [
    ["2026-08-03T08:04:09Z", "2026-08-03T08:04:14Z"],
    ["2026-09-07T08:04:38Z", "2026-09-07T08:04:43Z"],
    ["2026-09-14T08:05:06Z", "2026-09-14T08:05:12Z"],
  ]) {
    lines.push(sep, `MpCmdRun: Command Line: "C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\${PRODUCT}-0\\MpCmdRun.exe" SignatureUpdate -ScheduleJob -RestrictPrivileges`, ` Start Time: ${stamp(T(start))}`, "", `MpCmdRun: End Time: ${stamp(T(end))}`, sep);
  }
  return crlf(lines);
}

// ---------------------------------------------------------------------------

export interface SampleFile {
  path: string;
  bytes: Uint8Array;
  mtime: number;
}

const DEF = "ProgramData/Microsoft/Windows Defender";

export function sampleFiles(): SampleFile[] {
  const files: SampleFile[] = [];
  const add = (path: string, bytes: Uint8Array, mtime: number) => files.push({ path: `${HOST}/C/${path}`, bytes, mtime });
  const q = quarantine();
  const evtx = buildEvtx(operationalEvents());
  add("Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx", evtx, T("2026-09-14T10:12:04Z"));
  add(`${DEF}/Quarantine/Entries/${ENTRY_M64}`, q.m64.entry, T("2026-09-14T10:06:52.722Z"));
  add(`${DEF}/Quarantine/ResourceData/${q.m64.id.slice(0, 2)}/${q.m64.id}`, q.m64.data, T("2026-09-14T10:06:52.716Z"));
  add(`${DEF}/Quarantine/Resources/${q.m64.id.slice(0, 2)}/${q.m64.id}`, q.m64.record, T("2026-09-14T10:06:52.720Z"));
  add(`${DEF}/Quarantine/Entries/${ENTRY_PUA}`, q.pua.entry, T("2026-06-30T14:22:06.962Z"));
  add(`${DEF}/Quarantine/ResourceData/${q.pua.id.slice(0, 2)}/${q.pua.id}`, q.pua.data, T("2026-06-30T14:22:06.955Z"));
  add(`${DEF}/Quarantine/Resources/${q.pua.id.slice(0, 2)}/${q.pua.id}`, q.pua.record, T("2026-06-30T14:22:06.960Z"));
  for (const h of historyFiles()) add(`${DEF}/Scans/History/Service/DetectionHistory/${h.folder}/${h.name}`, h.bytes, h.mtime);
  add(`${DEF}/Support/MPLog-20260901-121532.log`, utf16(mplogText()), T("2026-09-14T10:15:43Z"));
  add(`${DEF}/Support/MPDetection-20260901-121532.log`, utf16(mpdetectionText()), T("2026-09-01T10:15:34Z"));
  add("Windows/Temp/MpCmdRun.log", utf16(mpcmdrunText()), T("2026-09-14T08:05:12Z"));
  add("Windows/System32/config/SOFTWARE", new Uint8Array(readFileSync(join(SRC, "C/Windows/System32/config/SOFTWARE"))), T("2026-09-14T10:55:12Z"));
  return files.sort((a, b) => a.path.localeCompare(b.path));
}

export const sampleZip = (files: SampleFile[]) => writeZip(files as ZipItem[]);

function main() {
  const files = sampleFiles();
  rmSync(join(OUT, HOST), { recursive: true, force: true });
  mkdirSync(OUT, { recursive: true });
  writeFileSync(join(OUT, `${HOST}.zip`), sampleZip(files));
  const manifest = files.map((f) => {
    const dest = join(OUT, f.path);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, f.bytes);
    utimesSync(dest, f.mtime / 1000, f.mtime / 1000);
    return { file: f.path, path: f.path.slice(`${HOST}/C/`.length), mtime: f.mtime };
  });
  writeFileSync(join(OUT, "manifest.json"), `${JSON.stringify(manifest, null, 1)}\n`);
  console.log(`${files.length} files → ${join(OUT, `${HOST}.zip`)}`);
}

// Run as a script (npm run samples), not when the tests import it.
if (process.argv[1] && /make-samples\.ts$/.test(process.argv[1])) main();
