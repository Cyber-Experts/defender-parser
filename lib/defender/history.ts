// DetectionHistory files (ProgramData\Microsoft\Windows Defender\Scans\
// History\Service\DetectionHistory\<nn>\<GUID>): one per detection.
//
// Layout from Orange Cyberdefense's analysis of mpsvc.dll and mpengine.dll
// (wddh-parser, doc.md: sections 1 to 8), cross-read with libyal's dtformats
// ("Windows Defender scan DetectionHistory file format") and Yamato Security's
// ys-defender-history-parser (src/history.rs), which named the values against
// what Defender itself reports through WMI (MSFT_MpThreatDetection). DHParser
// and Velociraptor's Windows.Applications.DefenderDHParser scan the file for
// strings rather than reading its structure.
//
// The file is a list of values: size (u32), type (u32), data, zero padding to
// 8 bytes. Types: 0x00/0x06 u32, 0x05 i32, 0x08 u64, 0x0A FILETIME, 0x15
// UTF-16 string, 0x1E GUID, 0x28 tracking data (keys and typed values).
// Values whose meaning is not known are kept by section and position.

import { fromFiletime } from "./quarantine";
import { guidString } from "./winbin";

export const MAX_HISTORY_BYTES = 4 * 1024 * 1024;
const MAX_VALUES = 50_000;
const MAX_RESOURCES = 2_000;
const MAX_PAIRS = 512;
const SEPARATOR = "Magic.Version:1.2";

const T_U32 = [0x00, 0x06];
const T_I32 = 0x05;
const T_U64 = 0x08;
const T_TIME = 0x0a;
const T_STR = 0x15;
const T_GUID = 0x1e;
const T_BLOB = 0x28;

interface Raw {
  at: number;
  type: number;
  size: number;
  /** Number (u32, i32, u64 as text when large), string, GUID or hex. */
  num?: number;
  big?: string;
  text?: string;
  bytes?: Uint8Array;
}

export interface HistoryResource {
  /** file, containerfile, webfile, process, regkeyvalue, service, CmdLine, behavior, amsi, … */
  kind: string;
  location: string;
  flags?: number;
  /** Tracking data, as key and value text (ThreatTrackingSha256, ThreatTrackingStartTime, …). */
  tracking: [string, string][];
}

export interface HistoryRaw {
  threatId?: string;
  /** The detection's GUID (also the file's name). */
  detectionId?: string;
  version?: string;
  threatName?: string;
  severityId?: number;
  categoryId?: number;
  threatStatusId?: number;
  list: number[];
  resources: HistoryResource[];
  statusChanged: number | null;
  statusErrorCode?: number;
  /** The quarantine entry's GUID (Entries\{GUID}); absent when zero. */
  quarantineId?: string;
  executionStatusId?: number;
  user?: string;
  sourceTypeId?: number;
  process?: string;
  initialDetection: number | null;
  remediation: number | null;
  unknown: [string, string][];
  problems: string[];
}

const u32 = (b: Uint8Array, o: number) => (o + 4 <= b.length ? (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0 : undefined);
const u64 = (b: Uint8Array, o: number) => (o + 8 <= b.length ? u32(b, o + 4)! * 4294967296 + u32(b, o)! : undefined);
const u64Text = (b: Uint8Array, o: number) => (o + 8 <= b.length ? new DataView(b.buffer, b.byteOffset + o, 8).getBigUint64(0, true).toString() : undefined);
const hex = (b: Uint8Array) => Array.from(b.subarray(0, 256), (x) => x.toString(16).padStart(2, "0")).join("");

function utf16(b: Uint8Array): string {
  const s = new TextDecoder("utf-16le").decode(b.subarray(0, Math.min(b.length, 65_536) & ~1));
  const nul = s.indexOf("\0");
  return nul < 0 ? s : s.slice(0, nul);
}

function ascii(b: Uint8Array): string {
  const s = new TextDecoder("windows-1252").decode(b.subarray(0, 65_536));
  const nul = s.indexOf("\0");
  return nul < 0 ? s : s.slice(0, nul);
}

/** Whether `head` starts like a DetectionHistory file: a u64 threat ID, a GUID, then a string. */
export function sniffHistory(head: Uint8Array): boolean {
  return u32(head, 0) === 8 && u32(head, 4) === T_U64 && u32(head, 0x10) === 16 && u32(head, 0x14) === T_GUID && u32(head, 0x2c) === T_STR;
}

function values(data: Uint8Array, problems: string[]): Raw[] {
  const out: Raw[] = [];
  let at = 0;
  while (at < data.length && out.length < MAX_VALUES) {
    const size = u32(data, at);
    const type = u32(data, at + 4);
    if (size === undefined || type === undefined) {
      problems.push("value_cut");
      break;
    }
    const start = at + 8;
    if (start + size > data.length) {
      problems.push("value_past_end");
      break;
    }
    const d = data.subarray(start, start + size);
    const r: Raw = { at, type, size };
    if (T_U32.includes(type) && size === 4) r.num = u32(d, 0);
    else if (type === T_I32 && size === 4) r.num = u32(d, 0)! | 0;
    else if (type === T_U64 && size === 8) r.big = u64Text(d, 0);
    else if (type === T_TIME && size === 8) r.num = u64(d, 0);
    else if (type === T_STR) r.text = utf16(d);
    else if (type === T_GUID && size === 16) r.text = guidString(d, 0)!.slice(1, -1);
    else r.bytes = d;
    out.push(r);
    at = (start + size + 7) & ~7;
  }
  if (out.length >= MAX_VALUES && at < data.length) problems.push("too_many_values");
  return out;
}

const show = (r: Raw): string => (r.text ?? r.big ?? (r.type === T_TIME ? timeText(r.num) : r.num !== undefined ? String(r.num) : r.bytes ? hex(r.bytes) : ""));
const timeText = (ticks: number | undefined) => {
  const t = fromFiletime(ticks);
  return t === null ? String(ticks ?? "") : new Date(t).toISOString();
};

/** Tracking data: an optional header (1, header size, pairs size, whole size, 0) or a size, then key / type / value pairs. */
function tracking(data: Uint8Array, problems: string[]): [string, string][] {
  const out: [string, string][] = [];
  if (!data.length) return out;
  const first = u32(data, 0);
  if (first === undefined) return out;
  let at: number;
  let end: number;
  if (first === 1) {
    const header = u32(data, 4) ?? 0;
    const pairs = u32(data, 8) ?? 0;
    if (header < 20 || header > data.length) {
      problems.push("tracking_header");
      return out;
    }
    if (pairs === 0) return out;
    at = header + 4;
    end = Math.min(data.length, header + pairs);
  } else {
    at = 4;
    end = Math.min(data.length, first);
  }
  while (at + 8 <= end && out.length < MAX_PAIRS) {
    const keySize = u32(data, at)!;
    if (keySize > 1024 || at + 4 + keySize + 4 > end) {
      problems.push("tracking_cut");
      break;
    }
    const key = utf16(data.subarray(at + 4, at + 4 + keySize));
    at += 4 + keySize;
    const type = u32(data, at)!;
    at += 4;
    let value: string;
    if (type === 3) {
      value = String(u32(data, at) ?? "");
      at += 4;
    } else if (type === 4) {
      const n = u64(data, at);
      value = /Time$/.test(key) && fromFiletime(n) !== null ? timeText(n) : (u64Text(data, at) ?? "");
      at += 8;
    } else if (type === 5) {
      value = data[at] ? "true" : "false";
      at += 1;
    } else if (type === 6 || type === 7) {
      const size = u32(data, at) ?? 0;
      if (at + 4 + size > end) {
        problems.push("tracking_cut");
        break;
      }
      const b = data.subarray(at + 4, at + 4 + size);
      value = type === 6 ? utf16(b) : ascii(b);
      at += 4 + size;
    } else {
      out.push([key, hex(data.subarray(at, end))]);
      problems.push("tracking_type");
      break;
    }
    if (at > end) {
      problems.push("tracking_cut");
      break;
    }
    out.push([key, value]);
  }
  return out;
}

export function readHistory(data: Uint8Array): HistoryRaw {
  const h: HistoryRaw = { list: [], resources: [], statusChanged: null, initialDetection: null, remediation: null, unknown: [], problems: [] };
  if (data.length > MAX_HISTORY_BYTES) {
    h.problems.push("too_large");
    return h;
  }
  if (!sniffHistory(data)) h.problems.push("not_history_start");
  const vals = values(data, h.problems);
  let i = 0;
  let ended = false;
  const take = (): Raw | undefined => {
    const r = vals[i];
    if (!r) {
      if (!ended) h.problems.push("values_end_early");
      ended = true;
      return undefined;
    }
    i++;
    return r;
  };
  const keep = (key: string) => {
    const r = take();
    if (r) h.unknown.push([key, show(r)]);
    return r;
  };
  const want = (key: string, ok: (r: Raw) => boolean): Raw | undefined => {
    const r = take();
    if (!r) return undefined;
    if (ok(r)) return r;
    h.unknown.push([key, show(r)]);
    h.problems.push(`type_${key}`);
    return undefined;
  };
  const isU32 = (r: Raw) => T_U32.includes(r.type) && r.num !== undefined;
  const isStr = (r: Raw) => r.type === T_STR;
  const atSep = () => vals[i]?.type === T_STR && vals[i].text === SEPARATOR;
  const count = (key: string, each: number): number | undefined => {
    const r = want(key, isU32);
    if (!r) return undefined;
    if (r.num! * each > vals.length - i) {
      h.problems.push(`count_${key}`);
      return undefined;
    }
    return r.num;
  };
  const resource = (section: string): boolean => {
    if (atSep()) i++;
    const kind = want(`${section}.1`, isStr);
    const loc = want(`${section}.2`, isStr);
    if (ended) return false;
    const flags = want(`${section}.3`, isU32);
    want(`${section}.4`, isU32);
    const blob = want(`${section}.5`, (r) => r.type === T_BLOB);
    if (h.resources.length < MAX_RESOURCES) h.resources.push({ kind: kind?.text ?? "", location: loc?.text ?? "", ...(flags ? { flags: flags.num } : {}), tracking: blob?.bytes ? tracking(blob.bytes, h.problems) : [] });
    return !ended;
  };

  (() => {
    // Section 1.
    h.threatId = want("1.0", (r) => r.type === T_U64)?.big;
    h.detectionId = want("1.1", (r) => r.type === T_GUID)?.text;
    if (atSep()) h.version = take()!.text;
    h.threatName = want("1.3", isStr)?.text;
    // Section 2.
    const optional = keep("2.0")?.num === 4;
    h.severityId = want("2.1", isU32)?.num;
    h.categoryId = want("2.2", isU32)?.num;
    keep("2.3");
    keep("2.4");
    h.threatStatusId = want("2.5", isU32)?.num;
    const listed = count("2.6", 1);
    if (listed === undefined) return;
    for (let n = 0; n < listed; n++) {
      const v = want(`2.${7 + n}`, isU32);
      if (v) h.list.push(v.num!);
    }
    const resources = count(`2.${7 + listed}`, 5);
    if (resources === undefined) return;
    // Section 3.
    for (let n = 0; n < resources; n++) if (!resource("3")) return;
    // Section 4.
    h.statusChanged = fromFiletime(want("4.0", (r) => r.type === T_TIME)?.num);
    h.statusErrorCode = want("4.1", (r) => r.type === T_I32)?.num;
    keep("4.2");
    const q = want("4.3", (r) => r.type === T_GUID)?.text;
    if (q && /[1-9A-F]/i.test(q)) h.quarantineId = q;
    h.executionStatusId = want("4.4", isU32)?.num;
    // Section 5, when section 2 starts with 4.
    if (optional) for (let n = 0; n < 6; n++) keep(`5.${n}`);
    // Section 6.
    keep("6.0");
    h.user = want("6.1", isStr)?.text;
    h.sourceTypeId = want("6.2", isU32)?.num;
    h.process = want("6.3", isStr)?.text;
    for (let n = 4; n < 7; n++) keep(`6.${n}`);
    h.initialDetection = fromFiletime(want("6.7", (r) => r.type === T_TIME)?.num);
    keep("6.8");
    h.remediation = fromFiletime(want("6.9", (r) => r.type === T_TIME)?.num);
    for (let n = 10; n < 15; n++) keep(`6.${n}`);
    const more = count("6.15", 5);
    if (more === undefined) return;
    // Section 7.
    for (let n = 0; n < more; n++) if (!resource("7")) return;
    // Section 8.
    for (let n = 0; n < 5; n++) keep(`8.${n}`);
  })();
  if (i < vals.length) {
    h.problems.push("values_after_footer");
    for (const r of vals.slice(i, i + 50)) h.unknown.push([`after.${r.at}`, show(r)]);
  }
  return h;
}

/** A tracking value by key, from the last resource that has it. */
export function trackingValue(h: Pick<HistoryRaw, "resources">, key: string): string | undefined {
  for (let i = h.resources.length - 1; i >= 0; i--) {
    const hit = h.resources[i].tracking.find(([k]) => k === key);
    if (hit) return hit[1];
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Writer (the sample and the tests)

const cat = (parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};
const le32 = (n: number) => Uint8Array.of(n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff);
const le64 = (n: number | bigint) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
};
const ticks = (ms: number | null | undefined) => (ms === null || ms === undefined ? BigInt(0) : BigInt(Math.round(ms)) * BigInt(10_000) + BigInt("116444736000000000"));
const w16 = (s: string) => {
  const b = new Uint8Array(s.length * 2 + 2);
  for (let i = 0; i < s.length; i++) {
    b[i * 2] = s.charCodeAt(i) & 0xff;
    b[i * 2 + 1] = s.charCodeAt(i) >> 8;
  }
  return b;
};
const guidBytes = (g: string) => {
  const x = g.replace(/[{}-]/g, "");
  const p = (i: number) => parseInt(x.slice(i * 2, i * 2 + 2), 16);
  return Uint8Array.from([p(3), p(2), p(1), p(0), p(5), p(4), p(7), p(6), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15)]);
};

function value(type: number, data: Uint8Array): Uint8Array {
  const v = new Uint8Array((8 + data.length + 7) & ~7);
  v.set(le32(data.length), 0);
  v.set(le32(type), 4);
  v.set(data, 8);
  return v;
}
const vU32 = (n: number, type = 0x06) => value(type, le32(n));
const vStr = (s: string) => value(T_STR, w16(s));
const vTime = (ms: number | null | undefined) => value(T_TIME, le64(ticks(ms)));

export type TrackingSpec = [string, { u32: number } | { u64: bigint | number } | { time: number } | { bool: boolean } | { str: string } | { ascii: string }];

function trackingBlob(pairs: TrackingSpec[]): Uint8Array {
  const body = cat(
    pairs.map(([k, v]) => {
      const key = w16(k);
      let val: Uint8Array;
      if ("u32" in v) val = cat([le32(3), le32(v.u32)]);
      else if ("u64" in v) val = cat([le32(4), le64(v.u64)]);
      else if ("time" in v) val = cat([le32(4), le64(ticks(v.time))]);
      else if ("bool" in v) val = cat([le32(5), Uint8Array.of(v.bool ? 1 : 0)]);
      else if ("str" in v) {
        const s = w16(v.str);
        val = cat([le32(6), le32(s.length), s]);
      } else {
        const s = new TextEncoder().encode(`${v.ascii}\0`);
        val = cat([le32(7), le32(s.length), s]);
      }
      return cat([le32(key.length), key, val]);
    }),
  );
  return cat([le32(body.length + 4), body]);
}

export interface HistorySpec {
  threatId: bigint | number;
  detectionId: string;
  threatName: string;
  severityId: number;
  categoryId: number;
  threatStatusId: number;
  list?: number[];
  resources: { kind: string; location: string; flags?: number; tracking: TrackingSpec[] }[];
  statusChanged: number;
  statusErrorCode?: number;
  quarantineId?: string;
  executionStatusId: number;
  user: string;
  sourceTypeId: number;
  process: string;
  initialDetection: number;
  remediation?: number | null;
}

/** A DetectionHistory file in the layout above (no section 5, no section 7 resources). */
export function writeHistory(s: HistorySpec): Uint8Array {
  const list = s.list ?? [];
  const parts: Uint8Array[] = [
    value(T_U64, le64(s.threatId)),
    value(T_GUID, guidBytes(s.detectionId)),
    vStr(SEPARATOR),
    vStr(s.threatName),
    vU32(0),
    vU32(s.severityId),
    vU32(s.categoryId),
    vU32(1),
    vU32(1),
    vU32(s.threatStatusId),
    vU32(list.length),
    ...list.map((n) => vU32(n)),
    vU32(s.resources.length),
  ];
  for (const r of s.resources) {
    const blob = trackingBlob(r.tracking);
    parts.push(vStr(SEPARATOR), vStr(r.kind), vStr(r.location), vU32(r.flags ?? 0), vU32(blob.length), value(T_BLOB, blob));
  }
  parts.push(vTime(s.statusChanged), value(T_I32, le32(s.statusErrorCode ?? 0)), vU32(0), value(T_GUID, guidBytes(s.quarantineId ?? "00000000-0000-0000-0000-000000000000")), vU32(s.executionStatusId));
  parts.push(vU32(0), vStr(s.user), vU32(s.sourceTypeId), vStr(s.process), vU32(0), vU32(0), vU32(0), vTime(s.initialDetection), vU32(0), vTime(s.remediation ?? null));
  parts.push(vU32(0), vU32(0, 0x00), vU32(0), vStr(s.user), vU32(0), vU32(0));
  parts.push(vU32(0, 0x00), vU32(0), vU32(0), vU32(0), vU32(0));
  return cat(parts);
}
