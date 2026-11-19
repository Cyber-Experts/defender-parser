// Each decoder on hand-made input: the quarantine with its RC4 layer (entries,
// Resources records, ResourceData streams), DetectionHistory, MPLog lines in
// both encodings, MpCmdRun.log, the Defender registry keys, and Operational
// events through the vendored WebAssembly reader.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { field, named, parseIsoUtc, parseRegChange, parseResources, SOURCES } from "@/lib/defender/evtx";
import { crc32, md5, sha1, sha256 } from "@/lib/defender/hash";
import { readHistory, sniffHistory, trackingValue, writeHistory } from "@/lib/defender/history";
import { cmdTime, commandKind, parseMpCmdRun } from "@/lib/defender/mpcmdrun";
import { classify, parseMpLog } from "@/lib/defender/mplog";
import { backupStreams, QuarantineError, rc4, readEntry, readResourceData, readResourceRecord, recoverFileData, securityDescriptor, sniffQuarantine, writeEntry, writeResourceData, writeResourceRecord } from "@/lib/defender/quarantine";
import { dword, openHive, sz } from "@/lib/defender/regf";
import { readDefenderKeys } from "@/lib/defender/registry";
import { sidBytes } from "@/lib/defender/winbin";
import { buildEvtx } from "@/scripts/evtx-writer";
import { T, enc, evtxReader, hive, oplog, threat, utf16 } from "./helpers";

const nodeHash = (alg: string, b: Uint8Array) => createHash(alg).update(b).digest("hex");

describe("hashes", () => {
  it("match Node's for every length around a block", () => {
    for (let n = 0; n < 200; n += 7) {
      const b = Uint8Array.from({ length: n }, (_, i) => (i * 31 + n) & 0xff);
      expect(md5(b)).toBe(nodeHash("md5", b));
      expect(sha1(b)).toBe(nodeHash("sha1", b));
      expect(sha256(b)).toBe(nodeHash("sha256", b));
    }
    expect(crc32(enc.encode("123456789"))).toBe(0xcbf43926);
  });
});

/** RC4 as dissect.target's rc4_crypt writes it, for an independent check. */
function dissectRc4(data: Uint8Array): Uint8Array {
  // prettier-ignore
  const key = [0x1E,0x87,0x78,0x1B,0x8D,0xBA,0xA8,0x44,0xCE,0x69,0x70,0x2C,0x0C,0x78,0xB7,0x86,0xA3,0xF6,0x23,0xB7,0x38,0xF5,0xED,0xF9,0xAF,0x83,0x53,0x0F,0xB3,0xFC,0x54,0xFA,0xA2,0x1E,0xB9,0xCF,0x13,0x31,0xFD,0x0F,0x0D,0xA9,0x54,0xF6,0x87,0xCB,0x9E,0x18,0x27,0x96,0x97,0x90,0x0E,0x53,0xFB,0x31,0x7C,0x9C,0xBC,0xE4,0x8E,0x23,0xD0,0x53,0x71,0xEC,0xC1,0x59,0x51,0xB8,0xF3,0x64,0x9D,0x7C,0xA3,0x3E,0xD6,0x8D,0xC9,0x04,0x7E,0x82,0xC9,0xBA,0xAD,0x97,0x99,0xD0,0xD4,0x58,0xCB,0x84,0x7C,0xA9,0xFF,0xBE,0x3C,0x8A,0x77,0x52,0x33,0x55,0x7D,0xDE,0x13,0xA8,0xB1,0x40,0x87,0xCC,0x1B,0xC8,0xF1,0x0F,0x6E,0xCD,0xD0,0x83,0xA9,0x59,0xCF,0xF8,0x4A,0x9D,0x1D,0x50,0x75,0x5E,0x3E,0x19,0x18,0x18,0xAF,0x23,0xE2,0x29,0x35,0x58,0x76,0x6D,0x2C,0x07,0xE2,0x57,0x12,0xB2,0xCA,0x0B,0x53,0x5E,0xD8,0xF6,0xC5,0x6C,0xE7,0x3D,0x24,0xBD,0xD0,0x29,0x17,0x71,0x86,0x1A,0x54,0xB4,0xC2,0x85,0xA9,0xA3,0xDB,0x7A,0xCA,0x6D,0x22,0x4A,0xEA,0xCD,0x62,0x1D,0xB9,0xF2,0xA2,0x2E,0xD1,0xE9,0xE1,0x1D,0x75,0xBE,0xD7,0xDC,0x0E,0xCB,0x0A,0x8E,0x68,0xA2,0xFF,0x12,0x63,0x40,0x8D,0xC8,0x08,0xDF,0xFD,0x16,0x4B,0x11,0x67,0x74,0xCD,0x0B,0x9B,0x8D,0x05,0x41,0x1E,0xD6,0x26,0x2E,0x42,0x9B,0xA4,0x95,0x67,0x6B,0x83,0x98,0xDB,0x2F,0x35,0xD3,0xC1,0xB9,0xCE,0xD5,0x26,0x36,0xF2,0x76,0x5E,0x1A,0x95,0xCB,0x7C,0xA4,0xC3,0xDD,0xAB,0xDD,0xBF,0xF3,0x82,0x53];
  const s = Array.from({ length: 256 }, (_, i) => i);
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + key[i]) % 256;
    [s[i], s[j]] = [s[j], s[i]];
  }
  const out = new Uint8Array(data.length);
  let i = 0;
  j = 0;
  for (let k = 0; k < data.length; k++) {
    i = (i + 1) % 256;
    j = (j + s[i]) % 256;
    [s[i], s[j]] = [s[j], s[i]];
    out[k] = s[(s[i] + s[j]) % 256] ^ data[k];
  }
  return out;
}

const ENTRY = "{800362A7-0000-0000-FB11-12639186E0D6}";
const SCAN = "{CDBE4600-E43A-964B-8DC2-416B0EF7A207}";

describe("quarantine", () => {
  it("uses Defender's RC4 key as Dissect does, the key stream restarting at each part", () => {
    const data = Uint8Array.from({ length: 1000 }, (_, i) => (i * 7) & 0xff);
    expect(rc4(data)).toEqual(dissectRc4(data));
    expect(rc4(rc4(data))).toEqual(data);
  });

  it("reads back an entry: header, both sections, aligned fields", () => {
    const bytes = writeEntry({
      guid: ENTRY,
      scanId: SCAN,
      time: T("2022-12-02T10:11:12.345Z"),
      threatId: 2147705511,
      threatName: "HackTool:Win64/Synthetic!dha",
      resources: [
        { path: "\\\\?\\C:\\Users\\user\\Downloads\\x\\odd.dll", physicalPath: "C:\\Users\\user\\Downloads\\x\\odd.dll", resourceId: "A6C8322B8A19AEED96EFBD045206966DA4C9619D", attributes: 0x20, created: T("2022-12-02T10:00:00Z"), accessed: T("2022-12-02T10:01:00Z"), written: T("2022-12-01T09:00:00Z"), size: 37376 },
        { kind: "regkey", path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\x" },
      ],
    });
    expect(sniffQuarantine(bytes)).toBe("entry");
    const e = readEntry(bytes);
    expect(e).toMatchObject({ guid: ENTRY.slice(1, -1), scanId: SCAN.slice(1, -1), time: T("2022-12-02T10:11:12.345Z"), threatId: "2147705511", one: 1, threatName: "HackTool:Win64/Synthetic!dha", magic: true, crc: ["ok", "ok"], problems: [] });
    expect(e.resources).toHaveLength(2);
    expect(e.resources[0]).toMatchObject({ kind: "file", path: "\\\\?\\C:\\Users\\user\\Downloads\\x\\odd.dll", physicalPath: "C:\\Users\\user\\Downloads\\x\\odd.dll", resourceId: "A6C8322B8A19AEED96EFBD045206966DA4C9619D", attributes: 0x20, size: 37376, created: T("2022-12-02T10:00:00Z"), written: T("2022-12-01T09:00:00Z"), problems: [] });
    expect(e.resources[0].fields.map((f) => [f.id, f.type, f.name])).toEqual([
      [0x02, 4, "ResourceId"],
      [0x0a, 3, "Flags"],
      [0x0c, 2, "PhysicalPath"],
      [0x0f, 6, "CreationTime"],
      [0x10, 6, "LastAccessTime"],
      [0x11, 6, "LastWriteTime"],
      [0x12, 6, "FileSize"],
    ]);
    expect(e.resources[1]).toMatchObject({ kind: "regkey", path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\x", fields: [] });
    // Each part is encrypted on its own: the first section decrypts with a fresh key stream.
    const s1size = rc4(bytes.subarray(0, 60))[40];
    expect(new TextDecoder("latin1").decode(rc4(bytes.subarray(60, 60 + s1size)).subarray(52))).toBe("HackTool:Win64/Synthetic!dha\0");
  });

  it("reports damage instead of throwing", () => {
    const good = writeEntry({ guid: ENTRY, scanId: SCAN, time: T("2022-12-02T10:11:12Z"), threatId: 1, threatName: "X", resources: [{ path: "C:\\a.exe" }] });
    // A changed byte in section 2: its CRC no longer matches.
    const bad = good.slice();
    bad[bad.length - 3] ^= 0xff;
    expect(readEntry(bad).crc).toEqual(["ok", "mismatch"]);
    // Cut: the second section is short.
    expect(readEntry(good.subarray(0, good.length - 5)).crc).toEqual(["ok", "cut"]);
    expect(() => readEntry(new Uint8Array(30))).toThrow(QuarantineError);
    expect(() => readEntry(new Uint8Array(200))).toThrow(QuarantineError);
  });

  it("reads back a Resources record", () => {
    const r = readResourceRecord(writeResourceRecord(9550, "C975E0D6E49C1A5414F27E21E9F1364B782E43CB", [ENTRY]));
    expect(r).toMatchObject({ dataSize: 9550, resourceId: "C975E0D6E49C1A5414F27E21E9F1364B782E43CB", entries: [ENTRY.slice(1, -1)], magic: true, crc: ["ok", "ok"] });
    expect(sniffQuarantine(writeResourceRecord(1, "00".repeat(20), []))).toBe("record");
  });

  it("describes a ResourceData file: streams, the file's hashes, owner, Zone.Identifier", () => {
    const data = enc.encode("SYNTHETIC test content, not a program.\r\n");
    const zone = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://www.example/page\r\nHostUrl=https://dl.example/a.zip\r\nLastWriterPackageFamilyName=Example.App\r\n";
    const owner = "S-1-5-21-1-2-3-1001";
    const { bytes, id } = writeResourceData([
      { kind: 3, data: securityDescriptor(sidBytes(owner), sidBytes("S-1-5-18"), [sidBytes(owner)]) },
      { kind: 1, data },
      { kind: 4, name: ":Zone.Identifier:$DATA", data: enc.encode(zone) },
    ]);
    const r = readResourceData(bytes);
    expect(r.contentSha1).toBe(id);
    expect(r.contentSha1).not.toBe(sha1(data).toUpperCase());
    expect(r.streams.map((s) => [s.kind, s.name, s.size])).toEqual([
      [3, "", r.streams[0].size],
      [1, "", data.length],
      [4, ":Zone.Identifier:$DATA", zone.length],
    ]);
    expect(r.file).toEqual({ size: data.length, md5: md5(data), sha1: sha1(data), sha256: sha256(data) });
    expect(r.zone).toMatchObject({ zoneId: "3", referrerUrl: "https://www.example/page", hostUrl: "https://dl.example/a.zip", other: [["LastWriterPackageFamilyName", "Example.App"]] });
    expect(r).toMatchObject({ owner, group: "S-1-5-18", hive: false, sparse: false, problems: [] });
    const rec = recoverFileData(bytes)!;
    expect(rec.data).toEqual(data);
    expect(rec.ads.map((a) => a.name)).toEqual([":Zone.Identifier:$DATA"]);
  });

  it("knows a hive, a sparse file and damaged streams", () => {
    expect(readResourceData(rc4(hive({ A: [sz("x", "y")] }))).hive).toBe(true);
    expect(recoverFileData(rc4(hive({ A: [] })))).toBeNull();
    const sparse = rc4(backupStreams([{ kind: 1, data: new Uint8Array(4), attributes: 0x08 }, { kind: 9, data: new Uint8Array(12) }]));
    expect(readResourceData(sparse).sparse).toBe(true);
    expect(recoverFileData(sparse)).toBeNull();
    const cut = backupStreams([{ kind: 1, data: new Uint8Array(100) }]).subarray(0, 60);
    expect(readResourceData(rc4(cut)).problems).toEqual(["stream_cut"]);
    expect(readResourceData(rc4(Uint8Array.of(99, 0, 0, 0, ...new Uint8Array(30)))).problems).toEqual(["stream_kind"]);
  });
});

describe("DetectionHistory", () => {
  const spec = {
    threatId: 2147958211,
    detectionId: "{3C9B6E14-7A2D-4F81-9C3E-5B0D2A7F1E68}",
    threatName: "Backdoor:Win64/Synthetic.A",
    severityId: 5,
    categoryId: 6,
    threatStatusId: 3,
    list: [3, 6],
    resources: [
      {
        kind: "file",
        location: "C:\\Users\\u\\Downloads\\t.exe",
        tracking: [
          ["ThreatTrackingStartTime", { time: T("2026-09-14T10:06:51.388Z") }],
          ["ThreatTrackingSha256", { str: "AB".repeat(32) }],
          ["ThreatTrackingSize", { u64: 9216 }],
          ["ThreatTrackingIsEsuSig", { bool: true }],
          ["ThreatTrackingResearchData", { ascii: "TTData={}" }],
          ["ThreatTrackingScanSource", { u32: 3 }],
        ] as Parameters<typeof writeHistory>[0]["resources"][0]["tracking"],
      },
    ],
    statusChanged: T("2026-09-14T10:06:52.710Z"),
    quarantineId: "{80073DC3-0000-0000-6A3C-1F82D4E0B917}",
    executionStatusId: 4,
    user: "H\\u",
    sourceTypeId: 3,
    process: "C:\\Program Files\\7-Zip\\7zFM.exe",
    initialDetection: T("2026-09-14T10:06:51.388Z"),
    remediation: T("2026-09-14T10:06:52.710Z"),
  };

  it("reads back every named value, section by section", () => {
    const b = writeHistory(spec);
    expect(sniffHistory(b)).toBe(true);
    const h = readHistory(b);
    expect(h).toMatchObject({
      threatId: "2147958211",
      detectionId: "3C9B6E14-7A2D-4F81-9C3E-5B0D2A7F1E68",
      version: "Magic.Version:1.2",
      threatName: "Backdoor:Win64/Synthetic.A",
      severityId: 5,
      categoryId: 6,
      threatStatusId: 3,
      list: [3, 6],
      statusChanged: T("2026-09-14T10:06:52.710Z"),
      statusErrorCode: 0,
      quarantineId: "80073DC3-0000-0000-6A3C-1F82D4E0B917",
      executionStatusId: 4,
      user: "H\\u",
      sourceTypeId: 3,
      process: "C:\\Program Files\\7-Zip\\7zFM.exe",
      initialDetection: T("2026-09-14T10:06:51.388Z"),
      remediation: T("2026-09-14T10:06:52.710Z"),
      problems: [],
    });
    expect(h.resources).toEqual([
      {
        kind: "file",
        location: "C:\\Users\\u\\Downloads\\t.exe",
        flags: 0,
        tracking: [
          ["ThreatTrackingStartTime", "2026-09-14T10:06:51.388Z"],
          ["ThreatTrackingSha256", "AB".repeat(32)],
          ["ThreatTrackingSize", "9216"],
          ["ThreatTrackingIsEsuSig", "true"],
          ["ThreatTrackingResearchData", "TTData={}"],
          ["ThreatTrackingScanSource", "3"],
        ],
      },
    ]);
    expect(trackingValue(h, "ThreatTrackingSha256")).toBe("AB".repeat(32));
  });

  it("reads tracking data behind a header, a file without Magic.Version, and a zero quarantine GUID", () => {
    const b = writeHistory({ ...spec, quarantineId: undefined });
    expect(readHistory(b).quarantineId).toBeUndefined();
    // Drop the first Magic.Version value (40 bytes: 8 + 34 + 6 padding... its size is read from the file).
    const sepSize = new DataView(b.buffer).getUint32(40, true);
    const cut = (8 + sepSize + 7) & ~7;
    const noVersion = new Uint8Array([...b.subarray(0, 40), ...b.subarray(40 + cut)]);
    const h = readHistory(noVersion);
    expect(h.version).toBeUndefined();
    expect(h.threatName).toBe("Backdoor:Win64/Synthetic.A");
    expect(h.problems).toEqual([]);
  });

  it("keeps what it can of a damaged file", () => {
    const b = writeHistory(spec);
    const h = readHistory(b.subarray(0, 300));
    expect(h.threatName).toBe("Backdoor:Win64/Synthetic.A");
    expect(h.problems.length).toBeGreaterThan(0);
    expect(readHistory(new Uint8Array(10)).problems).toContain("not_history_start");
  });
});

const MPLOG = [
  "Microsoft Defender Antivirus (77BDAF73-B396-481F-9042-AD358843EC24) Service Log",
  "Started On 09-01-2026 12:15:32",
  "Current time: 09/01/2026 10:15:32.104 UTC (48211 ms since boot)",
  "2022-11-23T09:10:55.472Z ProcessImageName: svchost.exe, Pid: 7836, TotalTime: 6070, Count: 24, MaxTime: 828, MaxTimeFile: \\Device\\HarddiskVolume1\\Downloads\\a, b.exe, EstimatedImpact: 100%",
  "2023-12-18T18:41:02.861Z SDN:Issuing SDN query for C:\\Program Files (x86)\\x\\b.exe (\\Device\\HarddiskVolume3\\Program Files (x86)\\x\\b.exe) (sha1=" + "a".repeat(40) + ", sha2=" + "b".repeat(64) + ")",
  "2023-12-18T18:41:03.000Z SDN:Issuing SDN query for C:\\nohash.exe (\\Device\\HarddiskVolume3\\nohash.exe)",
  "2022-12-15T11:24:18.854Z DETECTIONEVENT MPSOURCE_REALTIME HackTool:MSIL/Synthetic!MSR file:C:\\Users\\u\\Videos\\binary.exe",
  "2022-12-15T11:24:18.854Z DETECTION_ADD#1 HackTool:MSIL/Synthetic!MSR file:C:\\Users\\u\\Videos\\binary.exe PropBag [length: 0, data: (null)]",
  "2021-07-22T15:38:04.557Z DETECTION_ADD Ransom:Win32/Synthetic.ZA process:pid:100128,ProcessStart:132696072639875080",
  "2022-12-15T11:25:01.549Z DETECTION_CLEANEVENT MPSOURCE_REALTIME MP_THREAT_ACTION_QUARANTINE 0x80508033 HackTool:MSIL/Synthetic!MSR",
  "2022-12-15T11:24:29.026Z [RTP] [Mini-filter] Blocked file(#74): \\Device\\HarddiskVolume2\\Users\\u\\Videos\\binary.exe. Process: \\Device\\HarddiskVolume2\\x.exe, Status: 0x0, State: 0, ScanRequest #9184, FileId: 0x1, Reason: OnOpen, IoStatusBlockForNewFile: 0x2, DesiredAccess:0x1, FileAttributes:0x20, ScanAttributes:0x10, AccessStateFlags:0x800, BackingFileInfo: 0x0, 0x0, 0x0:0\\0x0:0",
  "2022-12-14T10:55:21.580Z Engine:command line reported as lowfi: C:\\Windows\\System32\\reg.exe(reg add HKLM\\x /v y /d 1 /f)",
  "2023-11-24T06:19:53.270Z Engine:EMS detection: HackTool:MSIL/Synthetic!MSR, sigseq=0x0000123456789B73, pid=1254",
  "2023-11-24T06:19:50.000Z Engine:EMS scan for process: My App pid: 42, sigseq: 0x0, sendMemoryScanReport: 0, source: 1",
  "2022-10-24T17:56:18.140Z Engine:Setting original file name \"psexec.c\" for \"c:\\users\\u\\videos\\binary.exe\", hr=0x0",
  "2024-01-26T22:46:35.043Z [RTP] [Exclusion] C:\\ProgramData\\Intel -> \\Device\\HarddiskVolume3\\ProgramData\\Intel",
  "2022-05-17T09:22:32.600Z Filter caching disabled for C:\\x\\PsExec.exe (runtime MpDisableCaching from 0x0)",
  "2024-05-06T13:20:45.250+02:00 Service started - Microsoft Defender Antivirus (77BDAF73-B396-481F-9042-AD358843EC24)",
  "2024-05-06T13:20:45.250 SDN:Issuing SDN query for C:\\local.exe (\\Device\\HarddiskVolume3\\local.exe)",
  "2024-05-06T13:20:46.000Z Something new the tool does not name",
  "Beginning threat actions",
  "Start time:12-15-2022 11:24:33",
  "Threat Name:HackTool:MSIL/Synthetic!MSR",
  "Action:quarantine",
  "Finished threat actions",
  "a line with no time",
  "2022-13-45T99:99:99.000Z broken time",
];

describe("MPLog", () => {
  for (const [label, bytes] of [
    ["UTF-16LE with a BOM", utf16(MPLOG.join("\r\n"))],
    ["UTF-16LE without a BOM", utf16(MPLOG.join("\r\n"), false)],
    ["UTF-8", enc.encode(MPLOG.join("\n"))],
  ] as const) {
    it(`reads every line type (${label}), keeping the raw text`, () => {
      const r = parseMpLog(bytes);
      expect(r.encoding).toBe(label === "UTF-8" ? "ascii" : "utf-16le");
      const kinds = r.entries.map((e) => e.kind);
      expect(kinds).toEqual(["header", "impact", "sdn", "sdn", "detection_event", "detection_add", "detection_add", "detection_clean", "blocked_file", "lowfi", "ems_detection", "ems_scan", "original_name", "exclusion", "filter_caching", "service_started", "sdn", "other", "threat_actions"]);
      const by = (i: number) => r.entries[i];
      expect(by(0)).toMatchObject({ time: T("2026-09-01T10:15:32.104Z"), zone: "utc", fields: { Service: "Microsoft Defender Antivirus", Id: "77BDAF73-B396-481F-9042-AD358843EC24", StartedOn: "09-01-2026 12:15:32", MsSinceBoot: "48211" }, span: 3 });
      expect(by(1).fields).toMatchObject({ ProcessImageName: "svchost.exe", Pid: "7836", MaxTimeFile: "\\Device\\HarddiskVolume1\\Downloads\\a, b.exe", EstimatedImpact: "100%" });
      expect(by(2).fields).toEqual({ Path: "C:\\Program Files (x86)\\x\\b.exe", DevicePath: "\\Device\\HarddiskVolume3\\Program Files (x86)\\x\\b.exe", Sha1: "a".repeat(40), Sha256: "b".repeat(64) });
      expect(by(3).fields).toEqual({ Path: "C:\\nohash.exe", DevicePath: "\\Device\\HarddiskVolume3\\nohash.exe" });
      expect(by(4).fields).toMatchObject({ Source: "MPSOURCE_REALTIME", ThreatName: "HackTool:MSIL/Synthetic!MSR", Schema: "file", Path: "C:\\Users\\u\\Videos\\binary.exe" });
      expect(by(5).fields.Path).toBe("C:\\Users\\u\\Videos\\binary.exe");
      expect(by(6).fields).toMatchObject({ Schema: "process", Pid: "100128" });
      expect(by(7).fields).toEqual({ Source: "MPSOURCE_REALTIME", Action: "MP_THREAT_ACTION_QUARANTINE", Hr: "0x80508033", ThreatName: "HackTool:MSIL/Synthetic!MSR" });
      expect(by(8).fields).toMatchObject({ Path: "\\Device\\HarddiskVolume2\\Users\\u\\Videos\\binary.exe", Process: "\\Device\\HarddiskVolume2\\x.exe", Reason: "OnOpen" });
      expect(by(11).fields).toMatchObject({ Process: "My App", pid: "42" });
      expect(by(12).fields).toEqual({ OriginalFileName: "psexec.c", Path: "c:\\users\\u\\videos\\binary.exe", Hr: "0x0" });
      expect(by(13).fields).toEqual({ Path: "C:\\ProgramData\\Intel", DevicePath: "\\Device\\HarddiskVolume3\\ProgramData\\Intel" });
      // Zones: Z and offsets are UTC; a time without a zone is kept as written.
      expect(by(15)).toMatchObject({ time: T("2024-05-06T11:20:45.250Z"), zone: "utc" });
      expect(by(16)).toMatchObject({ time: null, zone: "none", stamp: "2024-05-06T13:20:45.250", wall: T("2024-05-06T13:20:45.250Z") });
      expect(by(18)).toMatchObject({ time: null, zone: "none", stamp: "12-15-2022 11:24:33", fields: { "Threat Name": "HackTool:MSIL/Synthetic!MSR", Action: "quarantine" }, span: 5 });
      expect(r.other).toBe(1);
      expect(r.unparsedCount).toBe(2);
      expect(r.unparsed.map((u) => u.reason)).toEqual(["no_time", "bad_time"]);
      expect(r.entries.every((e) => e.raw.length > 0)).toBe(true);
    });
  }

  it("classifies a message alone", () => {
    expect(classify("Version: Product: 4.18.1, Service: 4.18.1, Engine: 1.1.2, AS: 1.4.3, AV: 1.4.3")).toEqual({ kind: "version", fields: { Product: "4.18.1", Service: "4.18.1", Engine: "1.1.2", AS: "1.4.3", AV: "1.4.3" } });
    expect(classify("Service stopped with exit code 0x0").kind).toBe("service_stopped");
  });
});

describe("MpCmdRun.log", () => {
  const sep = "-".repeat(85);
  const text = [
    sep,
    'MpCmdRun: Command Line: "C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\4.18.2203.5-0\\MpCmdRun.exe" -EnableService',
    " Start Time: \u200eMon \u200eNov \u200e03 \u200e2025 13:08:19",
    "",
    "MpEnsureProcessMitigationPolicy: hr = 0x0",
    "MpCmdRun: End Time: \u200eMon \u200eNov \u200e03 \u200e2025 13:08:20",
    sep,
    'MpCmdRun: Command Line: "C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -RemoveDefinitions -All',
    sep,
    'MpCmdRun: Command Line: "C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\4.18.2203.5-0\\MpCmdRun.exe" SignaturesUpdateService -ScheduleJob -UncDownload',
    sep,
  ].join("\r\n");

  it("reads each run: command line, start and end as written (no zone)", () => {
    const r = parseMpCmdRun(utf16(text));
    expect(r.encoding).toBe("utf-16le");
    expect(r.runs.map((x) => [x.kind, x.startText, x.start, x.end])).toEqual([
      ["other", "Mon Nov 03 2025 13:08:19", T("2025-11-03T13:08:19Z"), T("2025-11-03T13:08:20Z")],
      ["remove_definitions", undefined, null, null],
      ["signature_update", undefined, null, null],
    ]);
    expect(r.runs[0].detail).toEqual(["MpEnsureProcessMitigationPolicy: hr = 0x0"]);
    expect(r.runs[1].command).toBe('"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -RemoveDefinitions -All');
  });

  it("names the options that matter", () => {
    expect(commandKind("MpCmdRun.exe -Restore -Name X")).toBe("restore");
    expect(commandKind("MpCmdRun.exe -DownloadFile -url https://x.example/a -path c:\\a")).toBe("download_file");
    expect(commandKind("MpCmdRun.exe -AddDynamicSignature -Path x.vdm")).toBe("add_dynamic_signature");
    expect(commandKind("MpCmdRun.exe -Scan -ScanType 1")).toBe("scan");
    expect(cmdTime("Feb 30 2025 10:00:00")).toBeNull();
  });
});

describe("SOFTWARE hive", () => {
  it("reads only the Defender keys, with their times and sourced meanings", () => {
    const D = "Microsoft\\Windows Defender";
    const P = "Policies\\Microsoft\\Windows Defender";
    const h = openHive(
      hive({
        [`${D}\\Exclusions\\Paths`]: [[dword("C:\\ProgramData\\Intel", 0)], T("2026-09-14T10:08:12Z")],
        [`${D}\\Exclusions\\Extensions`]: [[], T("2026-09-02T08:00:00Z")],
        [`${D}\\Features`]: [[dword("TamperProtection", 5)], T("2026-09-01T03:12:00Z")],
        [`${D}\\Real-Time Protection`]: [[dword("DisableRealtimeMonitoring", 1)], T("2026-09-14T10:07:00Z")],
        [`${D}\\Spynet`]: [[dword("SpynetReporting", 0), dword("SubmitSamplesConsent", 2)], T("2026-01-01T00:00:00Z")],
        [`${P}\\Exclusions\\Processes`]: [[sz("powershell.exe", "0")], T("2026-09-14T10:09:00Z")],
        [`${P}`]: [[dword("DisableAntiSpyware", 1)], T("2026-09-14T10:09:30Z")],
        ["Microsoft\\Other"]: [[sz("x", "y")], T("2026-01-01T00:00:00Z")],
      }),
    );
    const r = readDefenderKeys(h);
    expect(r.absent).toBe(false);
    const k = (path: string) => r.keys.find((x) => x.keyPath === path)!;
    expect(k(`${D}\\Exclusions\\Paths`)).toMatchObject({ group: "exclusion", exclusionKind: "Paths", policy: false, lastWrite: T("2026-09-14T10:08:12Z"), values: [{ name: "C:\\ProgramData\\Intel", typeName: "REG_DWORD", text: "0" }] });
    expect(k(`${D}\\Exclusions\\Extensions`)).toMatchObject({ values: [], lastWrite: T("2026-09-02T08:00:00Z") });
    expect(k(`${D}\\Features`).values[0]).toMatchObject({ name: "TamperProtection", num: 5, meaning: "tamper_on" });
    expect(k(`${D}\\Real-Time Protection`).values[0]).toMatchObject({ meaning: "switched_off" });
    expect(k(`${D}\\Spynet`).values.map((v) => v.meaning)).toEqual(["maps_off", "samples_never"]);
    expect(k(`${P}\\Exclusions\\Processes`)).toMatchObject({ policy: true, exclusionKind: "Processes", values: [{ name: "powershell.exe" }] });
    expect(k(P).values[0]).toMatchObject({ name: "DisableAntiSpyware", meaning: "switched_off" });
    expect(r.keys.some((x) => /Other/.test(x.keyPath))).toBe(false);
    expect(readDefenderKeys(openHive(hive({ "Microsoft\\Windows NT\\CurrentVersion": [] }))).absent).toBe(true);
  });
});

describe("Operational log", () => {
  it("is read by the vendored reader from what the sample's writer produces, chunk after chunk", async () => {
    const read = await evtxReader();
    const events: [number, number, [string, string][]][] = Array.from({ length: 60 }, (_, i) => [T("2026-09-14T10:00:00Z") + i * 1000, 1116, threat({ time: T("2026-09-14T10:00:00Z"), name: `Trojan:Win32/Synthetic.${i}`, path: `file:_C:\\x${i}.exe` })]);
    const bytes = oplog(events);
    expect(bytes.length).toBeGreaterThan(4096 + 65536);
    const r = read("x.evtx", bytes);
    expect(r.error).toBeUndefined();
    expect(r.total).toBe(60);
    expect(r.records.map((x) => x.recordId)).toEqual(Array.from({ length: 60 }, (_, i) => i + 1));
    const first = r.records[0];
    expect(first).toMatchObject({ eventId: 1116, level: 4, provider: "Microsoft-Windows-Windows Defender", channel: "Microsoft-Windows-Windows Defender/Operational", computer: "H" });
    expect(parseIsoUtc(first.timestamp)).toBe(T("2026-09-14T10:00:00Z"));
    expect(field(first.data, "Threat Name")).toBe("Trojan:Win32/Synthetic.0");
    expect(field(first.data, "Source Name")).toBe("%%818");
    expect(first.xml).toMatch(/<Security UserID="S-1-5-18"/);
  });

  it("reports a damaged or foreign file instead of throwing", async () => {
    const read = await evtxReader();
    expect(read("x.evtx", new Uint8Array(100)).error).toMatch(/too small/i);
    expect(read("x.evtx", new Uint8Array(5000)).error).toMatch(/signature/i);
    const ok = buildEvtx([{ recordId: 1, time: T("2026-01-01T00:00:00Z"), provider: "P", eventId: 1, level: 4, channel: "C", computer: "H", data: [] }]);
    const broken = ok.slice();
    broken.fill(0xff, 4096 + 512, 4096 + 700);
    const r = read("x.evtx", broken);
    expect(r.records.length).toBeLessThanOrEqual(1);
  });

  it("names IDs from the event's own text, else from documented tables, and says which", () => {
    expect(named("3", "Real-Time Protection", SOURCES)).toEqual({ id: 3, name: "Real-Time Protection", from: "event" });
    expect(named("3", "%%818", SOURCES)).toEqual({ id: 3, name: "Real-time", from: "table", ref: "%%818" });
    expect(named("10", "%%999", SOURCES)).toMatchObject({ name: "AMSI", from: "inferred" });
    expect(named("4", "%%845", {})).toEqual({ id: 4, name: null, from: null, ref: "%%845" });
  });

  it("reads 5007 and 5013 values and multi-resource paths", () => {
    expect(parseRegChange("HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\ProgramData\\Intel = 0x0")).toMatchObject({ exclusionKind: "Paths", name: "C:\\ProgramData\\Intel", value: "0x0", policy: false, key: "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths" });
    expect(parseRegChange("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring = 0x1")).toMatchObject({ name: "DisableRealtimeMonitoring", value: "0x1", policy: true, key: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" });
    expect(parseRegChange("HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\a = b = 0x0")).toMatchObject({ name: "C:\\a = b", value: "0x0" });
    expect(parseResources("file:_C:\\a.exe; webfile:_C:\\a.exe|https://x.example/a.exe|pid:12; amsi:_C:\\ps.exe")).toEqual([
      { schema: "file", location: "C:\\a.exe" },
      { schema: "webfile", location: "C:\\a.exe|https://x.example/a.exe|pid:12" },
      { schema: "amsi", location: "C:\\ps.exe" },
    ]);
  });
});

describe("vendored reader", () => {
  it("is the build SOURCES.md pins", () => {
    const src = readFileSync(join(process.cwd(), "vendor/evtx/SOURCES.md"), "utf8");
    const pins = [...src.matchAll(/\| `([^`]+)` \| `([0-9a-f]{64})` \|/g)];
    expect(pins.length).toBe(3);
    for (const [, path, hash] of pins) expect(nodeHash("sha256", readFileSync(join(process.cwd(), path))), path).toBe(hash);
  });
});
