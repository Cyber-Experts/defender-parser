// The engine on hand-made inputs: joins across sources with their evidence,
// every flag, per-host recency, host placement and the file reports.
import { describe, expect, it } from "vitest";
import { sniffLoose } from "@/lib/defender/engine";
import { md5, sha1, sha256 } from "@/lib/defender/hash";
import { writeHistory, type HistorySpec } from "@/lib/defender/history";
import { exclusionCovers, exclusionRisks, stagingPlace } from "@/lib/defender/heuristics";
import { securityDescriptor, writeEntry, writeResourceData, writeResourceRecord } from "@/lib/defender/quarantine";
import { dword } from "@/lib/defender/regf";
import type { Analysis, Change, Detection } from "@/lib/defender/types";
import { sidBytes } from "@/lib/defender/winbin";
import { T, analyzeAll, enc, hive, input, oplog, threat, utf16 } from "./helpers";

const DEF = "C/ProgramData/Microsoft/Windows Defender";
const LOG = "C/Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx";
const D = (n: number) => `{0000000${n}-AAAA-BBBB-CCCC-DDDDDDDDDDDD}`;
const at = (m: number) => T("2026-09-14T10:00:00Z") + m * 60_000;
const codes = (x: { flags: { code: string; severity: string }[] }) => x.flags.map((f) => `${f.code}:${f.severity}`).sort();
const det = (a: Analysis, threatName: string): Detection => {
  const d = a.detections.find((x) => x.threatName === threatName);
  if (!d) throw new Error(`no detection ${threatName}: ${a.detections.map((x) => x.threatName).join(", ")}`);
  return d;
};
const chg = (a: Analysis, f: (c: Change) => boolean): Change => {
  const c = a.changes.find(f);
  if (!c) throw new Error(`no change: ${a.changes.map((x) => `${x.what} ${JSON.stringify(x.params)}`).join("; ")}`);
  return c;
};

const CONTENT = enc.encode("synthetic content");
const SHA = sha256(CONTENT);
const history = (s: Partial<HistorySpec> & Pick<HistorySpec, "detectionId" | "threatName">): Uint8Array =>
  writeHistory({ threatId: 2147900001, severityId: 5, categoryId: 8, threatStatusId: 3, resources: [], statusChanged: at(0), executionStatusId: 0, user: "H\\u", sourceTypeId: 3, process: "C:\\x.exe", initialDetection: at(0), ...s });

async function scenario() {
  const TEMP = "C:\\Users\\u\\AppData\\Local\\Temp\\a.exe";
  const content = writeResourceData([
    { kind: 3, data: securityDescriptor(sidBytes("S-1-5-21-1-2-3-1001"), sidBytes("S-1-5-18"), []) },
    { kind: 1, data: CONTENT },
  ]);
  const log = oplog([
    [at(0), 1116, threat({ id: D(1), time: at(0), name: "Trojan:Win32/Alpha.A", path: `file:_${TEMP}` })],
    [at(0.1), 1117, threat({ id: D(1), time: at(0), name: "Trojan:Win32/Alpha.A", path: `file:_${TEMP}`, action: ["2", "%%809"] })],
    [at(1), 1116, threat({ id: D(2), time: at(1), name: "Trojan:Win32/Beta.B", path: "file:_C:\\Tools\\b.exe" })],
    [at(1.1), 1118, threat({ id: D(2), time: at(1), name: "Trojan:Win32/Beta.B", path: "file:_C:\\Tools\\b.exe", action: ["3", "Remove"], error: "0x80508023" })],
    [at(2), 1116, threat({ id: D(3), time: at(2), name: "HackTool:Win32/Gamma", path: "file:_C:\\Tools\\c.exe" })],
    [at(2.1), 1117, threat({ id: D(3), time: at(2), name: "HackTool:Win32/Gamma", path: "file:_C:\\Tools\\c.exe", action: ["6", "Allow"] })],
    [at(3), 1116, threat({ id: D(4), time: at(3), name: "Trojan:PowerShell/Delta.A", path: "amsi:_C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", source: ["10", "%%999"] })],
    [at(4), 1116, threat({ id: D(6), time: at(4), name: "Trojan:Win32/Zeta.Z", path: "file:_C:\\Users\\u\\Desktop\\z.exe" })],
    [at(5), 5001, []],
    [at(5.1), 5010, []],
    [at(5.2), 5012, []],
    [at(6), 5013, [["Value", "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring = 0x1"]]],
    [at(7), 5007, [["Old Value", ""], ["New Value", "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Users\\u\\AppData\\Local\\Temp = 0x0"]]],
    [at(7.1), 5007, [["Old Value", ""], ["New Value", "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions\\.ps1 = 0x0"]]],
    [at(7.2), 5007, [["Old Value", ""], ["New Value", "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes\\powershell.exe = 0x0"]]],
    [at(7.3), 5007, [["Old Value", "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableBehaviorMonitoring = 0x0"], ["New Value", "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableBehaviorMonitoring = 0x1"]]],
    [at(7.4), 5007, [["Old Value", "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\D:\\Old = 0x0"], ["New Value", ""]]],
    [at(8), 1009, [["Threat Name", "Trojan:Win32/Alpha.A"], ["Path", `file:_${TEMP}`], ["Domain", "H"], ["User", "u"]]],
    [at(8.1), 1011, [["Threat Name", "Trojan:Win32/Alpha.A"], ["Path", `file:_${TEMP}`], ["Domain", "H"], ["User", "u"]]],
    [at(8.2), 1013, [["Timestamp", "09/14/2026 12:08:12 PM"], ["Domain", "H"], ["User", "u"]]],
    // Sixty days earlier: not recent.
    [at(-60 * 24 * 60), 1116, threat({ id: D(9), time: at(-60 * 24 * 60), name: "PUA:Win32/Old", path: "file:_C:\\Users\\u\\Downloads\\old.exe" })],
  ]);
  const mplog = utf16(
    [
      `${new Date(at(-0.5)).toISOString()} SDN:Issuing SDN query for ${TEMP} (\\Device\\HarddiskVolume3\\Users\\u\\AppData\\Local\\Temp\\a.exe) (sha1=${"d".repeat(40)}, sha2=${SHA})`,
      `${new Date(at(0)).toISOString()} DETECTION_ADD#1 Trojan:Win32/Alpha.A file:${TEMP}`,
      `${new Date(at(30)).toISOString()} DETECTION_ADD Trojan:Win32/Eta.E file:C:\\PerfLogs\\e.exe`,
      `${new Date(at(30.2)).toISOString()} DETECTIONEVENT MPSOURCE_REALTIME Trojan:Win32/Eta.E file:C:\\PerfLogs\\e.exe`,
    ].join("\r\n"),
  );
  const sep = "-".repeat(85);
  const cmd = utf16(
    [sep, 'MpCmdRun: Command Line: "C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -RemoveDefinitions -All', " Start Time: \u200eMon \u200eSep \u200e14 \u200e2026 12:20:00", sep, 'MpCmdRun: Command Line: "MpCmdRun.exe" -Restore -Name Trojan:Win32/Alpha.A', sep, 'MpCmdRun: Command Line: "MpCmdRun.exe" -DownloadFile -url https://x.example/a -path C:\\Users\\Public\\a', sep].join("\r\n"),
  );
  const RD = content.id;
  return analyzeAll([
    input(`H/${LOG}`, log),
    input(`H/${DEF}/Scans/History/Service/DetectionHistory/01/${D(1).slice(1, -1)}`, history({ detectionId: D(1), threatName: "Trojan:Win32/Alpha.A", quarantineId: "{11111111-0000-0000-0000-000000000001}", resources: [{ kind: "file", location: TEMP, tracking: [["ThreatTrackingSha256", { str: SHA }]] }] })),
    input(`H/${DEF}/Scans/History/Service/DetectionHistory/02/${D(5).slice(1, -1)}`, history({ detectionId: D(5), threatName: "Trojan:Win32/Epsilon.E", threatStatusId: 103, initialDetection: at(9), resources: [{ kind: "file", location: "C:\\Users\\Public\\e.exe", tracking: [["ThreatTrackingSha256", { str: SHA.toUpperCase() }]] }] })),
    input(`H/${DEF}/Quarantine/Entries/{11111111-0000-0000-0000-000000000001}`, writeEntry({ guid: "{11111111-0000-0000-0000-000000000001}", scanId: D(0), time: at(0.05), threatId: 1, threatName: "Trojan:Win32/Alpha.A", resources: [{ path: `\\\\?\\${TEMP}`, physicalPath: TEMP, resourceId: RD, size: 17 }] })),
    input(`H/${DEF}/Quarantine/ResourceData/${RD.slice(0, 2)}/${RD}`, content.bytes),
    input(`H/${DEF}/Quarantine/Resources/${RD.slice(0, 2)}/${RD}`, writeResourceRecord(content.bytes.length, RD, ["{11111111-0000-0000-0000-000000000001}"])),
    input(`H/${DEF}/Quarantine/Entries/{22222222-0000-0000-0000-000000000002}`, writeEntry({ guid: "{22222222-0000-0000-0000-000000000002}", scanId: D(0), time: at(4.2), threatId: 2, threatName: "Trojan:Win32/Zeta.Z", resources: [{ path: "\\\\?\\C:\\Users\\u\\Desktop\\z.exe", physicalPath: "C:\\Users\\u\\Desktop\\z.exe" }] })),
    input(`H/${DEF}/Support/MPLog-20260901-000000.log`, mplog),
    input("H/C/Windows/Temp/MpCmdRun.log", cmd),
    input(
      "H/C/Windows/System32/config/SOFTWARE",
      hive({
        "Microsoft\\Windows Defender\\Exclusions\\Paths": [[dword("C:\\", 0)], at(-30 * 24 * 60)],
        "Microsoft\\Windows Defender\\Exclusions\\Processes": [[dword("m.exe", 0)], at(-30 * 24 * 60)],
        "Microsoft\\Windows Defender\\Exclusions\\Extensions": [[dword(".log", 0)], at(-30 * 24 * 60)],
        "Microsoft\\Windows Defender\\Features": [[dword("TamperProtection", 4)], at(-30 * 24 * 60)],
        "Microsoft\\Windows Defender\\Spynet": [[dword("SpynetReporting", 0)], at(-30 * 24 * 60)],
        "Microsoft\\Windows Defender\\Real-Time Protection": [[dword("DisableRealtimeMonitoring", 1)], at(5)],
      }),
    ),
  ]);
}

describe("joins", () => {
  it("ties the events, the history file, the quarantine entry and MPLog of one detection, with evidence", async () => {
    const a = await scenario();
    const d = det(a, "Trojan:Win32/Alpha.A");
    expect(d.events.map((e) => e.eventId)).toEqual([1116, 1117]);
    expect(d.history).toHaveLength(1);
    expect(d.quarantine).toHaveLength(1);
    expect(d.mplog.map((m) => m.kind).sort()).toEqual(["detection_add", "sdn"]);
    expect(d.joins.map((j) => j.how)).toEqual(["same_detection_id", "history_detection_id", "history_quarantine_id", "mplog_threat_path_time", "sdn_same_path"]);
    expect(d).toMatchObject({ detectionId: D(1).slice(1, -1), time: at(0), timeFrom: "event", path: "C:\\Users\\u\\AppData\\Local\\Temp\\a.exe", user: "H\\alice", result: "done", quarantined: true });
    expect(d.action).toEqual({ id: 2, name: "Quarantine", from: "table", ref: "%%809" });
    expect(d.source).toEqual({ id: 3, name: "Real-time", from: "table", ref: "%%818" });
    // The content's own hashes; MPLog's SDN line gives another SHA-1, so it is listed as differing.
    expect(d.hashes).toEqual({ sha256: SHA, sha1: sha1(CONTENT), md5: md5(CONTENT), from: ["quarantine", "history"], differs: ["mplog"] });
    const res = d.quarantine[0].resources[0];
    expect(res.data).toMatchObject({ nameMatches: "content", owner: "S-1-5-21-1-2-3-1001", recovered: { size: 17 } });
    expect(res.record?.entries).toEqual(["11111111-0000-0000-0000-000000000001"]);
  });

  it("joins an entry without a history file by threat, path and time; keeps what nothing ties", async () => {
    const a = await scenario();
    expect(det(a, "Trojan:Win32/Zeta.Z").joins.map((j) => [j.how, j.params?.seconds])).toEqual([["quarantine_threat_path_time", "12"]]);
    const eps = det(a, "Trojan:Win32/Epsilon.E");
    expect(eps).toMatchObject({ timeFrom: "history", result: "failed", status: "Remove failed", events: [] });
    // An MPLog-only detection: two lines of the same threat and path make one.
    const eta = det(a, "Trojan:Win32/Eta.E");
    expect(eta).toMatchObject({ timeFrom: "mplog", time: at(30), path: "C:\\PerfLogs\\e.exe" });
    expect(eta.mplog).toHaveLength(2);
    expect(a.detections).toHaveLength(8);
  });
});

describe("flags", () => {
  it("flags detections", async () => {
    const a = await scenario();
    expect(codes(det(a, "Trojan:Win32/Alpha.A"))).toEqual(["exclusion_nearby:high", "recent:low", "same_hash:medium", "staging_path:medium"]);
    expect(codes(det(a, "Trojan:Win32/Beta.B"))).toEqual(["action_failed:high", "recent:low"]);
    expect(codes(det(a, "HackTool:Win32/Gamma"))).toEqual(["action_allowed:high", "recent:low"]);
    // powershell.exe, the process AMSI caught, is excluded 4 minutes later.
    expect(codes(det(a, "Trojan:PowerShell/Delta.A"))).toEqual(["amsi:medium", "exclusion_nearby:high", "recent:low"]);
    expect(det(a, "Trojan:PowerShell/Delta.A").source).toMatchObject({ id: 10, name: "AMSI", from: "inferred" });
    expect(codes(det(a, "Trojan:Win32/Epsilon.E"))).toEqual(["action_failed:high", "recent:low", "same_hash:medium", "staging_path:medium"]);
    expect(codes(det(a, "Trojan:Win32/Eta.E"))).toEqual(["recent:low", "staging_path:medium"]);
    expect(codes(det(a, "PUA:Win32/Old"))).toEqual(["downloads:low"]);
  });

  it("flags protection changes from events, the hive and MpCmdRun.log", async () => {
    const a = await scenario();
    const ev = (id: number) => chg(a, (c) => c.event?.eventId === id && c.what !== "exclusion_added" && c.what !== "setting_changed" && c.what !== "exclusion_removed");
    expect(codes(ev(5001))).toEqual(["recent:low", "rtp_off:high"]);
    expect(codes(ev(5010))).toEqual(["recent:low", "scanning_off:high"]);
    expect(codes(ev(5012))).toEqual(["recent:low", "scanning_off:high"]);
    expect(codes(ev(5013))).toEqual(["recent:low", "tamper_blocked:medium"]);
    expect(codes(ev(1009))).toEqual(["quarantine_restored:high", "recent:low"]);
    expect(codes(ev(1011))).toEqual(["quarantine_deleted:medium", "recent:low"]);
    expect(codes(ev(1013))).toEqual(["history_deleted:medium", "recent:low"]);
    const added = (v: string) => chg(a, (c) => c.what === "exclusion_added" && c.params.value === v);
    expect(codes(added("C:\\Users\\u\\AppData\\Local\\Temp"))).toEqual(["exclusion_near_detection:high", "exclusion_writable:high", "recent:low"]);
    expect(added("C:\\Users\\u\\AppData\\Local\\Temp").flags.find((f) => f.code === "exclusion_near_detection")!.params).toMatchObject({ threat: "Trojan:Win32/Alpha.A", when: "after", minutes: "7" });
    expect(codes(added(".ps1"))).toEqual(["exclusion_broad_ext:high", "recent:low"]);
    expect(codes(added("powershell.exe"))).toEqual(["exclusion_near_detection:high", "exclusion_process_name:medium", "exclusion_script_host:high", "recent:low"]);
    expect(chg(a, (c) => c.what === "exclusion_removed").params).toMatchObject({ kind: "Paths", value: "D:\\Old" });
    expect(codes(chg(a, (c) => c.what === "setting_changed"))).toEqual(["recent:low", "setting_off:high"]);
    const reg = (v: string) => chg(a, (c) => c.source === "registry" && (c.params.value === v || c.params.name === v));
    expect(codes(reg("C:\\"))).toEqual(["exclusion_drive_root:high"]);
    expect(codes(reg("m.exe"))).toEqual(["exclusion_process_name:medium"]);
    expect(codes(reg(".log"))).toEqual(["exclusion_other:low"]);
    expect(codes(reg("TamperProtection"))).toEqual(["tamper_off:medium"]);
    expect(codes(reg("SpynetReporting"))).toEqual(["maps_off:low"]);
    expect(codes(reg("DisableRealtimeMonitoring"))).toEqual(["recent:low", "setting_off:high"]);
    const cmd = (k: string) => chg(a, (c) => c.source === "command" && c.params.kind === k);
    expect(codes(cmd("remove_definitions"))).toEqual(["remove_definitions:high"]);
    expect(codes(cmd("restore"))).toEqual(["quarantine_restored:high"]);
    expect(codes(cmd("download_file"))).toEqual(["mpcmdrun_tamper:medium"]);
    expect(cmd("remove_definitions")).toMatchObject({ time: null, localTime: "Mon Sep 14 2026 12:20:00" });
  });

  it("judges recency per host, against that host's newest UTC time", async () => {
    const a = await scenario();
    expect(a.hosts.map((h) => [h.name, h.newest])).toEqual([["H", at(30.2)]]);
    const old = oplog([[T("2026-01-01T00:00:00Z"), 1116, threat({ time: T("2026-01-01T00:00:00Z"), name: "Trojan:Win32/Lone", path: "file:_C:\\Users\\Public\\x.exe" })]]);
    const two = await analyzeAll([input(`A/${LOG}`, old), input(`B/${LOG}`, oplog([[at(0), 1116, threat({ time: at(0), name: "Trojan:Win32/Other", path: "file:_C:\\x.exe" })]]))]);
    expect(two.hosts.map((h) => h.name)).toEqual(["A", "B"]);
    // Alone on its host, the January detection is the newest record there: recent.
    expect(codes(det(two, "Trojan:Win32/Lone"))).toEqual(["recent:low", "staging_path:medium"]);
  });
});

describe("rules", () => {
  it("knows staging locations and risky exclusions", () => {
    expect(stagingPlace("C:\\ProgramData\\Intel\\m64.exe")).toEqual({ code: "staging_path", folder: "ProgramData\\Intel" });
    expect(stagingPlace("\\\\?\\C:\\Windows\\Temp\\x.exe")).toEqual({ code: "staging_path", folder: "Windows\\Temp" });
    expect(stagingPlace("C:\\Program Files\\x\\x.exe")).toBeNull();
    expect(exclusionRisks("Paths", "%ProgramData%\\Intel")).toEqual(["exclusion_writable"]);
    expect(exclusionRisks("Paths", "C:\\Program Files\\Vendor")).toEqual([]);
    expect(exclusionRisks("Paths", "D:")).toEqual(["exclusion_drive_root"]);
    expect(exclusionRisks("Paths", "*.exe")).toEqual(["exclusion_broad_ext"]);
    expect(exclusionRisks("Paths", "C:\\*")).toEqual(["exclusion_drive_root"]);
    expect(exclusionRisks("Processes", "C:\\Users\\u\\AppData\\Local\\x.exe")).toEqual(["exclusion_writable"]);
    expect(exclusionCovers("Paths", "C:\\ProgramData\\Intel", "C:\\ProgramData\\Intel\\m64.exe")).toBe(true);
    expect(exclusionCovers("Paths", "C:\\ProgramData\\Intel", "C:\\ProgramData\\Intel2\\m64.exe")).toBe(false);
    expect(exclusionCovers("Paths", "C:\\Users\\*\\Downloads", "C:\\Users\\bob\\Downloads\\x.exe")).toBe(true);
    expect(exclusionCovers("Processes", "m64.exe", "C:\\Users\\u\\Downloads\\tools\\m64.exe")).toBe(true);
    expect(exclusionCovers("Processes", "7zFM.exe", "C:\\a\\b.exe", "C:\\Program Files\\7-Zip\\7zFM.exe")).toBe(true);
    expect(exclusionCovers("Extensions", ".exe", "C:\\a\\b.EXE")).toBe(true);
  });
});

describe("placement and files", () => {
  it("recognises loose files by content and puts them with the only host", async () => {
    const entry = writeEntry({ guid: D(1), scanId: D(0), time: at(0), threatId: 1, threatName: "X", resources: [] });
    expect(sniffLoose(input("whatever", entry))).toBe("entry");
    expect(sniffLoose(input("x", history({ detectionId: D(1), threatName: "X" })))).toBe("history");
    expect(sniffLoose(input("Defender-Operational.evtx", oplog([[at(0), 5000, []]])))).toBe("evtx");
    expect(sniffLoose(input("log.txt", utf16("2026-09-14T10:00:00.000Z SDN:Issuing SDN query for C:\\a.exe (\\Device\\HarddiskVolume3\\a.exe)\r\n")))).toBe("mplog");
    expect(sniffLoose(input("t.log", utf16("MpCmdRun: Command Line: x\r\n")))).toBe("mpcmdrun");
    expect(sniffLoose(input("n.txt", "hello"))).toBeNull();
    const a = await analyzeAll([input("H/C/Windows/System32/config/SOFTWARE", hive({ "Microsoft\\Windows Defender\\Features": [dword("TamperProtection", 5)] })), input("Defender-Operational.evtx", oplog([[at(0), 5000, []]]))]);
    expect(a.hosts.map((h) => h.name)).toEqual(["H"]);
    expect(a.files.map((f) => [f.role, f.status, f.host]).sort()).toEqual([
      ["evtx", "parsed", "H"],
      ["software", "parsed", "H"],
    ]);
  });

  it("reports what it cannot read, file by file, without throwing", async () => {
    const a = await analyzeAll([
      input(`H/${DEF}/Quarantine/Entries/{X}`, new Uint8Array(10)),
      input(`H/${DEF}/Quarantine/ResourceData/AB/AB${"0".repeat(38)}`, new Uint8Array([1, 2, 3])),
      input(`H/${DEF}/Scans/History/Service/DetectionHistory/01/X`, new Uint8Array(100)),
      input(`H/${LOG}`, new Uint8Array(5000)),
      input("H/C/Windows/System32/config/SOFTWARE", new Uint8Array(100)),
      input(`H/${DEF}/Support/MpWppTracing-x.bin`, new Uint8Array(3)),
    ]);
    const by = (role: string) => a.files.find((f) => f.role === role)!;
    expect(by("entry").status).toBe("error");
    expect(by("evtx").status).toBe("error");
    expect(by("software").status).toBe("error");
    expect(by("history").status).toBe("unrecognised");
    expect(by("resourcedata")).toMatchObject({ status: "parsed", notes: expect.arrayContaining([{ code: "rd_no_entry" }]) });
    expect(a.files.find((f) => f.path.endsWith("MpWppTracing-x.bin"))).toMatchObject({ role: "defender-other", status: "not-read" });
  });
});
