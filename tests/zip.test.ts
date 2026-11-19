// The ZIP writer: plain entries read back by the intake's reader, and
// ZipCrypto-encrypted entries opened by independent readers (Info-ZIP unzip
// and Python's zipfile, when present) with the password "infected" only.
// Then the recovery ZIP of a quarantined file.
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { sha256 } from "@/lib/defender/hash";
import { rc4, securityDescriptor, writeResourceData } from "@/lib/defender/quarantine";
import { buildRecoveryZip, RECOVERY_PASSWORD, safeName } from "@/lib/defender/recover";
import { sidBytes } from "@/lib/defender/winbin";
import { writeZip } from "@/lib/defender/zip";
import { listZip } from "@/lib/intake/unzip";
import { enc, hive } from "./helpers";

const dir = mkdtempSync(join(tmpdir(), "defender-zip-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const has = (cmd: string, args: string[]) => spawnSync(cmd, args, { encoding: "utf8" }).status === 0;
const UNZIP = has("unzip", ["-v"]);
const PYTHON = has("python3", ["-I", "-c", "import zipfile"]);

/** Fixed "random" bytes so the archive is deterministic in tests. */
const fixed = (n: number) => Uint8Array.from({ length: n }, (_, i) => (i * 37 + 11) & 0xff);
const DATA = enc.encode("SYNTHETIC test payload, not a program.\r\n".repeat(40));
const items = [
  { path: "payload.bin", bytes: DATA, mtime: Date.UTC(2026, 8, 14, 10, 6, 50) },
  { path: "empty.txt", bytes: new Uint8Array(), mtime: Date.UTC(2026, 8, 14) },
  { path: "dir/nested name.txt", bytes: enc.encode("nested"), mtime: Date.UTC(2026, 8, 14) },
];

describe("ZIP writer", () => {
  it("writes plain entries the intake reads back, with exact UTC times", async () => {
    const z = writeZip(items);
    const entries = await listZip(new Blob([z as BlobPart]));
    expect(entries.map((e) => [e.path, e.size, e.mtimeApprox])).toEqual([
      ["payload.bin", DATA.length, false],
      ["empty.txt", 0, false],
      ["dir/nested name.txt", 6, false],
    ]);
    expect(new Uint8Array(await (await entries[0].file()).arrayBuffer())).toEqual(DATA);
    expect((await entries[0].file()).lastModified).toBe(Date.UTC(2026, 8, 14, 10, 6, 50));
  });

  it("encrypts with ZipCrypto: the bytes never appear in the archive, and the intake refuses it", async () => {
    const z = writeZip(items, { password: RECOVERY_PASSWORD, random: fixed });
    const text = new TextDecoder("latin1").decode(z);
    expect(text).not.toContain("SYNTHETIC test payload");
    expect(z[6] & 1).toBe(1);
    await expect(listZip(new Blob([z as BlobPart]))).rejects.toThrow(/password-protected/);
    // Deterministic with fixed header bytes; different with real random ones.
    expect(writeZip(items, { password: RECOVERY_PASSWORD, random: fixed })).toEqual(z);
    expect(writeZip(items, { password: RECOVERY_PASSWORD })).not.toEqual(z);
  });

  it.runIf(UNZIP)("opens with unzip -P infected, and not with another password", () => {
    const path = join(dir, "u.zip");
    writeFileSync(path, writeZip(items, { password: RECOVERY_PASSWORD }));
    const ok = spawnSync("unzip", ["-p", "-P", RECOVERY_PASSWORD, path, "payload.bin"]);
    expect(ok.status).toBe(0);
    expect(new Uint8Array(ok.stdout)).toEqual(DATA);
    const test = spawnSync("unzip", ["-t", "-P", RECOVERY_PASSWORD, path], { encoding: "utf8" });
    expect(test.status).toBe(0);
    expect(test.stdout).toMatch(/No errors detected/);
    const bad = spawnSync("unzip", ["-t", "-P", "wrong", path], { encoding: "utf8" });
    expect(bad.status).not.toBe(0);
  });

  it.runIf(PYTHON)("opens with Python's zipfile and the password", () => {
    const path = join(dir, "p.zip");
    writeFileSync(path, writeZip(items, { password: RECOVERY_PASSWORD }));
    const script = "import sys,zipfile,hashlib\nz=zipfile.ZipFile(sys.argv[1])\nfor i in z.infolist(): print(i.filename, i.flag_bits & 1, hashlib.sha256(z.read(i, pwd=b'infected')).hexdigest())\n";
    const r = spawnSync("python3", ["-I", "-c", script, path], { encoding: "utf8" });
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout.trim().split("\n")).toEqual([`payload.bin 1 ${sha256(DATA)}`, `empty.txt 1 ${sha256(new Uint8Array())}`, `dir/nested name.txt 1 ${sha256(enc.encode("nested"))}`]);
  });

  it("is checked by at least one independent reader on this machine", () => {
    expect(UNZIP || PYTHON).toBe(true);
  });
});

describe("recovery ZIP", () => {
  const owner = "S-1-5-21-1-2-3-1119";
  const zone = "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=http://files.example/tools.zip\r\n";
  const { bytes } = writeResourceData([
    { kind: 3, data: securityDescriptor(sidBytes(owner), sidBytes(owner), [sidBytes(owner)]) },
    { kind: 1, data: DATA },
    { kind: 4, name: ":Zone.Identifier:$DATA", data: enc.encode(zone) },
  ]);

  it("holds the file, its streams and a README, encrypted; no plain byte of the file", () => {
    const r = buildRecoveryZip(bytes, { host: "H", path: "C:\\Users\\u\\Downloads\\tools\\m64.exe", threatName: "Backdoor:Win64/Synthetic.A", quarantined: Date.UTC(2026, 8, 14, 10, 6, 52), written: Date.UTC(2026, 8, 1, 20, 40, 12), resourceData: "ResourceData/C9/X" }, fixed)!;
    expect(r).toMatchObject({ sha256: sha256(DATA), size: DATA.length });
    expect(r.name).toBe(`m64.exe.${sha256(DATA).slice(0, 12)}.infected.zip`);
    expect(new TextDecoder("latin1").decode(r.zip)).not.toContain("SYNTHETIC test payload");
    if (UNZIP) {
      const path = join(dir, "r.zip");
      writeFileSync(path, r.zip);
      const list = spawnSync("unzip", ["-Z1", path], { encoding: "utf8" });
      expect(list.stdout.trim().split("\n")).toEqual(["m64.exe", "m64.exe_Zone.Identifier.ads", "README.txt"]);
      expect(new Uint8Array(spawnSync("unzip", ["-p", "-P", RECOVERY_PASSWORD, path, "m64.exe"]).stdout)).toEqual(DATA);
      expect(spawnSync("unzip", ["-p", "-P", RECOVERY_PASSWORD, path, "m64.exe_Zone.Identifier.ads"], { encoding: "utf8" }).stdout).toBe(zone);
      const readme = spawnSync("unzip", ["-p", "-P", RECOVERY_PASSWORD, path, "README.txt"], { encoding: "utf8" }).stdout;
      expect(readme).toMatch(/^LIVE MALWARE/);
      expect(readme).toContain(`SHA-256:         ${sha256(DATA)}`);
    }
  });

  it("refuses a hive or a content without data, and makes names safe", () => {
    expect(buildRecoveryZip(rc4(hive({ A: [] })), { host: "H", path: "x", resourceData: "y" })).toBeNull();
    expect(buildRecoveryZip(writeResourceData([]).bytes, { host: "H", path: "x", resourceData: "y" })).toBeNull();
    expect(safeName("C:\\a\\in\u202Ecod.exe")).toBe("in_cod.exe");
    expect(safeName("C:\\a\\..")).toBe("_");
    expect(safeName("")).toBe("file");
  });
});
