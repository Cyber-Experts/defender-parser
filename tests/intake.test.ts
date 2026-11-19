// What the intake opens: collections (zip, tar.gz, folders) and loose files,
// what it lists as not read, and how sure it is of each file's time.
import { describe, expect, it } from "vitest";
import { collect, wantedInCollection } from "@/lib/intake/collect";
import { HANDOFF_SENDERS } from "@/lib/intake/handoff";
import { listZip } from "@/lib/intake/unzip";
import { writeZip } from "@/lib/defender/zip";
import { file, gzip, tar } from "./helpers";

const D = "x/C/ProgramData/Microsoft/Windows Defender";

describe("intake", () => {
  it("knows Defender's files and the SOFTWARE hive", () => {
    expect(wantedInCollection(`${D}/Quarantine/Entries/{800362A7-0000-0000-FB11-12639186E0D6}`)).toBe("defender");
    expect(wantedInCollection(`${D}/Quarantine/ResourceData/A6/A6C8322B8A19AEED96EFBD045206966DA4C9619D`)).toBe("defender");
    expect(wantedInCollection(`${D}/Quarantine/Resources/A6/A6C8322B8A19AEED96EFBD045206966DA4C9619D`)).toBe("defender");
    expect(wantedInCollection(`${D}/Scans/History/Service/DetectionHistory/02/6AFE33A0-19BA-4FFF-892F-B700539D7D63`)).toBe("defender");
    expect(wantedInCollection(`${D}/Support/MPLog-20231219-093000.log`)).toBe("defender");
    expect(wantedInCollection(`${D}/Support/MPDetection-20231219-093000.log`)).toBe("defender");
    expect(wantedInCollection("uploads/auto/C%3A/Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx")).toBe("defender");
    expect(wantedInCollection("case/H/C/Defender-Operational.evtx")).toBe("defender");
    expect(wantedInCollection("x/C/Windows/Temp/MpCmdRun.log")).toBe("defender");
    expect(wantedInCollection("x/C/Users/bob/AppData/Local/Temp/MpCmdRun.log")).toBe("defender");
    expect(wantedInCollection("x/C/Windows/System32/config/SOFTWARE")).toBe("hive");
    expect(wantedInCollection(`${D}/Scans/mpenginedb.db`)).toBe("noted");
    expect(wantedInCollection(`${D}/Definition Updates/{X}/mpavbase.vdm`)).toBeNull();
    expect(wantedInCollection("x/C/Windows/System32/winevt/Logs/Security.evtx")).toBeNull();
    expect(wantedInCollection("x/C/Windows/System32/config/SYSTEM")).toBeNull();
  });

  it("opens a zip and keeps only what it reads; mpenginedb.db is listed as not read", async () => {
    const t = Date.UTC(2026, 8, 14, 10, 47, 13);
    const zip = writeZip([
      { path: "H/C/Windows/Temp/MpCmdRun.log", bytes: new TextEncoder().encode("MpCmdRun: Command Line: x\r\n"), mtime: t },
      { path: "H/C/ProgramData/Microsoft/Windows Defender/Scans/mpenginedb.db", bytes: new Uint8Array(10), mtime: t },
      { path: "H/C/Windows/Prefetch/A.EXE-12345678.pf", bytes: new Uint8Array(10), mtime: t },
    ]);
    const c = await collect([file("H.zip", zip)]);
    expect(c.artifacts.map((a) => [a.path, a.kind, a.file.lastModified, a.mtimeApprox])).toEqual([["H.zip/H/C/Windows/Temp/MpCmdRun.log", "defender", t, undefined]]);
    expect(c.skipped.map((s) => [s.path.split("/").pop(), s.code])).toEqual([["mpenginedb.db", "notRead"]]);
    expect(c.ignored).toBe(1);
  });

  it("marks a zip entry whose only time is the DOS field", async () => {
    const name = "MpCmdRun.log";
    const zip = writeZip([{ path: name, bytes: new TextEncoder().encode("x"), mtime: Date.UTC(2026, 8, 14, 10, 0, 0) }]);
    const cd = zip.length - 22 - (46 + name.length + 9);
    const bad = zip.slice();
    bad[cd + 46 + name.length] = 0x99;
    const [entry] = await listZip(new Blob([bad]));
    expect(entry.mtimeApprox).toBe(true);
  });

  it("opens a .tar.gz", async () => {
    const tgz = await gzip(
      tar([
        { name: "WS/C/ProgramData/Microsoft/Windows Defender/Support/MPLog-20260901-121532.log", data: "x", mtime: 1789380902 },
        { name: "WS/C/Windows/System32/config/SOFTWARE", data: "x" },
        { name: "WS/C/Windows/System32/winevt/Logs/Security.evtx", data: "x" },
      ]),
    );
    const c = await collect([file("ws.tar.gz", tgz)]);
    expect(c.artifacts.map((a) => [a.path, a.kind])).toEqual([
      ["ws.tar.gz/WS/C/ProgramData/Microsoft/Windows Defender/Support/MPLog-20260901-121532.log", "defender"],
      ["ws.tar.gz/WS/C/Windows/System32/config/SOFTWARE", "hive"],
    ]);
    expect(c.artifacts[0].file.lastModified).toBe(1789380902000);
    expect(c.ignored).toBe(1);
  });

  it("hands loose files to the engine and explains what it skips", async () => {
    const c = await collect([file("anything.bin", "x"), file("empty.txt", "")]);
    expect(c.artifacts.map((a) => [a.path, a.kind])).toEqual([["anything.bin", "defender"]]);
    expect(c.skipped).toEqual([{ path: "empty.txt", code: "empty" }]);
  });

  it("reports a damaged archive and refuses a password-protected one", async () => {
    const c = await collect([file("broken.tar.gz", new Uint8Array([0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]))]);
    expect(c.skipped.map((s) => s.code)).toEqual(["tarError"]);
    const locked = writeZip([{ path: "MpCmdRun.log", bytes: new Uint8Array(30), mtime: 0 }], { password: "infected" });
    expect((await collect([file("locked.zip", locked)])).skipped.map((s) => s.code)).toEqual(["zipError"]);
  });

  it("accepts handoffs only from Disk Image Parser's exact origins", () => {
    expect(Object.keys(HANDOFF_SENDERS)).toEqual(["disk-image-parser"]);
    expect(HANDOFF_SENDERS["disk-image-parser"].origins).toEqual(["https://www.diskimageparser.com", "https://diskimageparser.com"]);
  });
});
