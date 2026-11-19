// Hostile input: the files come from machines under investigation.
// Corrupted copies of every sample file (event log, quarantine entries and
// contents, DetectionHistory, MPLog, MpCmdRun.log, the hive), random bytes
// under every name the tool reads, and crafted sizes and long lines go
// through the whole engine (the event log through the WebAssembly reader):
// it must report damage per file and never throw or hang.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseMpCmdRun } from "@/lib/defender/mpcmdrun";
import { parseMpLog } from "@/lib/defender/mplog";
import { readEntry, readResourceData, rc4 } from "@/lib/defender/quarantine";
import { readHistory } from "@/lib/defender/history";
import type { InputFile } from "@/lib/defender/types";
import { buildTimeline, changesCsv, computeFindings, detectionsCsv, toJson, toMarkdown } from "@/lib/defender/view";
import { analyzeAll, rng, utf16 } from "./helpers";

const DIR = join(process.cwd(), "public/samples");
const manifest = JSON.parse(readFileSync(join(DIR, "manifest.json"), "utf8")) as { file: string; mtime: number }[];
const original: InputFile[] = manifest.map((m) => ({ path: m.file, bytes: new Uint8Array(readFileSync(join(DIR, m.file))), mtime: m.mtime }));

/** Structure-aware poison: cuts, random bytes, size-like values at their extremes, text separators, odd UTF-16 halves. */
function mutate(b: Uint8Array, r: () => number): Uint8Array {
  const out = b.slice();
  const kind = r();
  if (kind < 0.12) return out.slice(0, Math.floor(r() * out.length));
  const n = 1 + Math.floor(r() * 24);
  for (let i = 0; i < n; i++) {
    const at = Math.floor(r() * out.length);
    if (kind < 0.45) out[at] = Math.floor(r() * 256);
    else if (kind < 0.7) out[at] = [0x7c, 0x0a, 0x0d, 0x00, 0x3a, 0x5c, 0xd8, 0xdc, 0xff, 0xfe, 0x20][Math.floor(r() * 11)];
    else out.fill([0, 0xff, 0x7f, 0x80][Math.floor(r() * 4)], at, Math.min(out.length, at + 4));
  }
  return out;
}

/** Quarantine parts are RC4 streams: poison the plain text, then encrypt again, so damage lands in the structure. */
function mutatePlain(b: Uint8Array, r: () => number, header = false): Uint8Array {
  if (!header) return rc4(mutate(rc4(b), r));
  const out = b.slice();
  out.set(rc4(mutate(rc4(b.subarray(0, 60)), r).subarray(0, 60)), 0);
  return out;
}

const labels = { finding: (f: { code: string }) => f.code, flag: (f: { code: string }) => f.code, why: (c: string) => c, item: (x: { id: string }) => x.id };

describe("hostile files", () => {
  it("survives hundreds of corrupted collections", async () => {
    const r = rng(20260914);
    const started = Date.now();
    const seen = { evtxMutated: 0, evtxRecords: 0, evtxErrors: 0, quarantineErrors: 0, quarantineRead: 0 };
    for (let round = 0; round < 600; round++) {
      const inputs = original.map((f) => {
        if (r() >= 0.6) return f;
        const quarantine = /Quarantine\/(?:Entries|Resources)\//.test(f.path);
        const content = /Quarantine\/ResourceData\//.test(f.path);
        return { ...f, bytes: quarantine ? mutatePlain(f.bytes, r, r() < 0.5) : content ? mutatePlain(f.bytes, r) : mutate(f.bytes, r) };
      });
      const a = await analyzeAll(inputs);
      expect(a.files.length).toBe(inputs.length);
      const ev = a.files.find((f) => f.role === "evtx")!;
      if (inputs.find((f) => f.path === ev.path) !== original.find((f) => f.path === ev.path)) {
        seen.evtxMutated++;
        if (ev.status === "error") seen.evtxErrors++;
        else seen.evtxRecords += ev.records;
      }
      for (const f of a.files.filter((x) => x.role === "entry")) {
        if (f.status === "error") seen.quarantineErrors++;
        else seen.quarantineRead++;
      }
      computeFindings([...a.detections, ...a.changes]);
      buildTimeline(a);
      if (round % 30 === 0) {
        detectionsCsv(a.detections);
        changesCsv(a.changes);
        toJson(a);
        toMarkdown(a, labels);
      }
    }
    // The damage reached every reader: corrupted logs still read in part, some refused; entries both.
    expect(seen.evtxMutated).toBeGreaterThan(300);
    expect(seen.evtxRecords).toBeGreaterThan(1000);
    expect(seen.evtxErrors).toBeGreaterThan(0);
    expect(seen.quarantineRead).toBeGreaterThan(100);
    expect(seen.quarantineErrors).toBeGreaterThan(10);
    expect(Date.now() - started).toBeLessThan(90_000);
  }, 180_000);

  it("survives random bytes under every name it reads", async () => {
    const r = rng(7);
    for (let round = 0; round < 120; round++) {
      const len = Math.floor(r() * 9000);
      const bytes = new Uint8Array(len).map(() => Math.floor(r() * 256));
      if (round % 4 === 0 && len > 8) bytes.set(new TextEncoder().encode("ElfFile\0"));
      if (round % 4 === 1 && len > 4) bytes.set([0x72, 0x65, 0x67, 0x66]);
      if (round % 4 === 2 && len > 60) bytes.set(rc4(Uint8Array.of(0xdb, 0xe8, 0xc5, 0x01, ...new Uint8Array(52), 0xdb, 0xe8, 0xc5, 0x02)));
      const a = await analyzeAll(original.map((f) => ({ ...f, bytes })));
      expect(a.files.length).toBe(original.length);
      expect((await analyzeAll([{ path: "x.bin", bytes, mtime: null }])).files).toHaveLength(1);
    }
  }, 120_000);
});

describe("crafted sizes and text", () => {
  it("does not stall or allocate on huge declared sizes", () => {
    const started = Date.now();
    // A quarantine header declaring 4 GB sections; a ResourceData stream declaring 2^53 bytes.
    const head = new Uint8Array(60);
    head.set([0xdb, 0xe8, 0xc5, 0x01]);
    head.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 40);
    head.set([0xdb, 0xe8, 0xc5, 0x02], 56);
    const e = readEntry(new Uint8Array([...rc4(head), ...new Uint8Array(100)]));
    expect(e.crc).toEqual(["cut", "cut"]);
    const stream = new Uint8Array(40);
    stream.set([1, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0]);
    expect(readResourceData(rc4(stream)).problems).toEqual(["stream_cut"]);
    // A DetectionHistory value declaring 4 GB, and a count of a billion resources.
    const h = new Uint8Array(64);
    new DataView(h.buffer).setUint32(0, 0xffffffff, true);
    expect(readHistory(h).problems).toContain("value_past_end");
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it("does not stall on long lines, many lines or unterminated blocks", () => {
    const started = Date.now();
    parseMpLog(utf16(`2026-01-01T00:00:00.000Z SDN:Issuing SDN query for ${"(".repeat(200_000)}\r\n${"x".repeat(3_000_000)}\r\n`));
    const block = parseMpLog(new TextEncoder().encode(`Beginning threat actions\n${"Start time:x\n".repeat(5000)}`));
    expect(block.entries[0].fields._unterminated).toBe("yes");
    const many = parseMpLog(new TextEncoder().encode("2026-01-01T00:00:00.000Z Something\n".repeat(400_000)));
    expect(many.entries.length + many.dropped).toBe(400_000);
    parseMpCmdRun(utf16(`MpCmdRun: Command Line: ${"a".repeat(100_000)}\r\n`.repeat(50)));
    expect(Date.now() - started).toBeLessThan(30_000);
  }, 60_000);

  it("keeps lines not understood bounded", () => {
    const r = parseMpLog(new TextEncoder().encode("garbage line\n".repeat(50_000)));
    expect(r.unparsedCount).toBe(50_000);
    expect(r.unparsed.length).toBe(200);
  });
});
