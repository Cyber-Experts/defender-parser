// Test helpers: engine inputs, text in each encoding, hives from a key map,
// the vendored EVTX reader, a minimal ustar writer, gzip and File wrappers.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { readEvtx, type EvtxFileRaw } from "@/lib/defender/evtx";
import { analyze } from "@/lib/defender/engine";
import { type WKey, type WValue, writeHive } from "@/lib/defender/regf";
import type { InputFile } from "@/lib/defender/types";
import { buildEvtx, type EvtxEvent } from "@/scripts/evtx-writer";

export const enc = new TextEncoder();
export const T = (iso: string) => Date.parse(iso);

export const input = (path: string, data: string | Uint8Array, mtime: number | null = null): InputFile => ({ path, bytes: typeof data === "string" ? enc.encode(data) : data, mtime });

/** UTF-16LE, with or without a BOM. */
export function utf16(s: string, bom = true): Uint8Array {
  const out = new Uint8Array((bom ? 2 : 0) + s.length * 2);
  let o = 0;
  if (bom) {
    out.set([0xff, 0xfe]);
    o = 2;
  }
  for (let i = 0; i < s.length; i++) {
    out[o + i * 2] = s.charCodeAt(i) & 0xff;
    out[o + i * 2 + 1] = s.charCodeAt(i) >> 8;
  }
  return out;
}

// --- The vendored EVTX reader, loaded synchronously from public/.
let evtxModule: typeof import("@/vendor/evtx/evtx_wasm.js") | null = null;
export async function evtxReader() {
  if (!evtxModule) {
    const m = await import("@/vendor/evtx/evtx_wasm.js");
    m.initSync({ module: readFileSync(join(process.cwd(), "public/evtx_wasm_bg.wasm")) });
    evtxModule = m;
  }
  const m = evtxModule;
  return (path: string, bytes: Uint8Array): EvtxFileRaw => readEvtx(path, bytes, (b) => new m.EvtxHandle(b));
}

/** The engine with every EVTX input read by the vendored reader, as the worker does. */
export async function analyzeAll(inputs: InputFile[]) {
  const read = await evtxReader();
  const logs = inputs.filter((i) => /\.evtx$/i.test(i.path) || (i.bytes.length >= 8 && String.fromCharCode(...i.bytes.subarray(0, 7)) === "ElfFile")).map((i) => read(i.path, i.bytes));
  return analyze(inputs, logs);
}

export const DEFENDER = "Microsoft-Windows-Windows Defender";
export const CHANNEL = "Microsoft-Windows-Windows Defender/Operational";

/** An Operational log from [time, event ID, data] triples. */
export function oplog(events: [number, number, [string, string][]][]): Uint8Array {
  return buildEvtx(events.map(([time, eventId, data], i): EvtxEvent => ({ recordId: i + 1, time, provider: DEFENDER, eventId, level: 4, channel: CHANNEL, computer: "H", user: "S-1-5-18", data })));
}

/** A 1116 / 1117 data list. */
export function threat(o: { id?: string; time: number; name: string; threatId?: number; path: string; source?: [string, string]; action?: [string, string]; user?: string; process?: string; error?: string; severity?: [string, string] }): [string, string][] {
  return [
    ["Product Name", "%%827"],
    ["Detection ID", o.id ?? "{11111111-2222-3333-4444-555555555555}"],
    ["Detection Time", new Date(o.time).toISOString()],
    ["Threat ID", String(o.threatId ?? 2147900000)],
    ["Threat Name", o.name],
    ["Severity ID", o.severity?.[0] ?? "5"],
    ["Severity Name", o.severity?.[1] ?? "Severe"],
    ["Category ID", "8"],
    ["Category Name", "Trojan"],
    ["Source ID", o.source?.[0] ?? "3"],
    ["Source Name", o.source?.[1] ?? "%%818"],
    ["Process Name", o.process ?? "C:\\Windows\\explorer.exe"],
    ["Detection User", o.user ?? "H\\alice"],
    ["Path", o.path],
    ["Origin ID", "1"],
    ["Origin Name", "%%845"],
    ["Action ID", o.action?.[0] ?? "9"],
    ["Action Name", o.action?.[1] ?? "%%887"],
    ["Error Code", o.error ?? "0x00000000"],
    ["Error Description", "The operation completed successfully."],
  ];
}

/** A hive holding each key path with its values (key time `time`, or per key `[values, time]`). */
export function hive(keys: Record<string, WValue[] | [WValue[], number]>, time = T("2026-09-14T10:00:00Z")): Uint8Array {
  const root: WKey = { name: "ROOT", lastWrite: time, subkeys: [] };
  for (const [path, spec] of Object.entries(keys)) {
    const [values, t] = Array.isArray(spec[0]) || spec.length === 0 ? (spec as [WValue[], number]) : [spec as WValue[], time];
    let k = root;
    const parts = path.split("\\");
    parts.forEach((p, i) => {
      let s = k.subkeys!.find((x) => x.name.toLowerCase() === p.toLowerCase());
      if (!s) k.subkeys!.push((s = { name: p, lastWrite: time, subkeys: [], values: [] }));
      if (i === parts.length - 1) {
        s.values = [...(s.values ?? []), ...(Array.isArray(values) ? values : [])];
        s.lastWrite = typeof t === "number" ? t : time;
      }
      k = s;
    });
  }
  return writeHive(root, { lastWrite: time });
}

/** A File for the intake. */
export const file = (path: string, bytes: Uint8Array | string, mtime = 0) => ({
  path,
  file: new File([typeof bytes === "string" ? enc.encode(bytes) : (bytes as BlobPart)], path.split("/").pop()!, { lastModified: mtime }),
});

export interface TarItem {
  name: string;
  data: Uint8Array | string;
  mtime?: number;
}

export function tar(entries: TarItem[]): Uint8Array {
  const blocks: Uint8Array[] = [];
  for (const e of entries) {
    const h = new Uint8Array(512);
    const put = (s: string, at: number) => h.set(enc.encode(s), at);
    const data = typeof e.data === "string" ? enc.encode(e.data) : e.data;
    put(e.name, 0);
    put("0000644\0", 100);
    put("0000000\0", 108);
    put("0000000\0", 116);
    put(data.length.toString(8).padStart(11, "0") + "\0", 124);
    put((e.mtime ?? 1789380000).toString(8).padStart(11, "0") + "\0", 136);
    h[156] = "0".charCodeAt(0);
    put("ustar\0", 257);
    put("00", 263);
    h.fill(32, 148, 156);
    const sum = h.reduce((a, b) => a + b, 0);
    put(sum.toString(8).padStart(6, "0") + "\0 ", 148);
    blocks.push(h);
    const padded = new Uint8Array(Math.ceil(data.length / 512) * 512);
    padded.set(data);
    blocks.push(padded);
  }
  blocks.push(new Uint8Array(1024));
  const out = new Uint8Array(blocks.reduce((n, b) => n + b.length, 0));
  let o = 0;
  for (const b of blocks) {
    out.set(b, o);
    o += b.length;
  }
  return out;
}

export async function gzip(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([bytes as BlobPart]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Small deterministic PRNG (mulberry32). */
export function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
