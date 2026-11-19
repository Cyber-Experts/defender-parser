// Microsoft Defender's quarantine (ProgramData\Microsoft\Windows Defender\
// Quarantine): Entries\{GUID}, ResourceData\<xx>\<ID>, Resources\<xx>\<ID>.
//
// Sources: Fox-IT / NCC Group, "Reverse, Reveal, Recover: Windows Defender
// Quarantine Forensics" (2023) and their dissect.target plugin
// (plugins/os/windows/defender/quarantine.py): the 60-byte entry header, the
// two sections, the resources and their 4-byte aligned fields, ResourceData
// as RC4-encrypted BackupRead output (WIN32_STREAM_ID streams: security
// descriptor, data, alternate data streams such as Zone.Identifier). The RC4
// key was published by cuckoo-modified's quarantine.py and is used by every
// reader since. The header magic numbers (DB E8 C5 01 / DB E8 C5 02), the
// CRC-32 convention, the Resources record and a registry hive as the content
// of registry resources come from Yamato Security's ys-defender-history-parser
// (src/quarantine.rs); Dissect does not check them, so a header without the
// magic numbers is still read when its section sizes fit the file.
//
// Each part (the header, section 1, section 2; a ResourceData file whole) is
// encrypted on its own: the RC4 key stream restarts for each.
//
// Recovered content is live malware. This module decodes it to describe it
// (streams, sizes, hashes, Zone.Identifier, owner); `recoverFileData` returns
// the file's bytes only for the encrypted-ZIP export (lib/defender/recover.ts).
// Nothing here renders or keeps those bytes in the analysis.

import { crc32, hashes, sha1, type Hashes } from "./hash";
import { guidString, sidString } from "./winbin";

// prettier-ignore
const KEY = Uint8Array.from([
  0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69, 0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86,
  0xA3, 0xF6, 0x23, 0xB7, 0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC, 0x54, 0xFA,
  0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F, 0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18,
  0x27, 0x96, 0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4, 0x8E, 0x23, 0xD0, 0x53,
  0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8, 0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
  0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58, 0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE,
  0x3C, 0x8A, 0x77, 0x52, 0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC, 0x1B, 0xC8,
  0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59, 0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E,
  0x3E, 0x19, 0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D, 0x2C, 0x07, 0xE2, 0x57,
  0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E, 0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
  0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3, 0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A,
  0xEA, 0xCD, 0x62, 0x1D, 0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE, 0xD7, 0xDC,
  0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12, 0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16,
  0x4B, 0x11, 0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6, 0x26, 0x2E, 0x42, 0x9B,
  0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98, 0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
  0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD, 0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53,
]);

const SBOX = (() => {
  const s = Uint8Array.from({ length: 256 }, (_, i) => i);
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + KEY[i]) & 0xff;
    [s[i], s[j]] = [s[j], s[i]];
  }
  return s;
})();

/** RC4 with Defender's quarantine key: decrypts a part, and encrypts it alike. The key stream starts afresh at each call. */
export function rc4(data: Uint8Array): Uint8Array {
  const s = SBOX.slice();
  const out = new Uint8Array(data.length);
  let i = 0;
  let j = 0;
  for (let k = 0; k < data.length; k++) {
    i = (i + 1) & 0xff;
    j = (j + s[i]) & 0xff;
    const t = s[i];
    s[i] = s[j];
    s[j] = t;
    out[k] = data[k] ^ s[(s[i] + s[j]) & 0xff];
  }
  return out;
}

// ---------------------------------------------------------------------------
// Limits

/** An entry or a Resources record is a few KB; anything past this is not one. */
export const MAX_ENTRY_BYTES = 4 * 1024 * 1024;
/** ResourceData files are decrypted, parsed and hashed in memory up to this size. */
export const MAX_RESOURCE_BYTES = 256 * 1024 * 1024;
const MAX_RESOURCES = 10_000;
const MAX_FIELDS = 256;
const MAX_STREAMS = 4096;
const MAX_TEXT = 32 * 1024;

const HEADER = 60;
const MAGIC = [0xdb, 0xe8, 0xc5, 0x01];
const FOOTER = [0xdb, 0xe8, 0xc5, 0x02];
const ENTRY_FIXED = 52;
const RECORD_FIXED = 32;

const u16 = (b: Uint8Array, o: number) => (o + 2 <= b.length ? b[o] | (b[o + 1] << 8) : undefined);
const u32 = (b: Uint8Array, o: number) => (o + 4 <= b.length ? (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0 : undefined);
/** A 64-bit value as a number (exact up to 2^53; larger values lose low bits, which no size or time here reaches). */
const u64 = (b: Uint8Array, o: number) => {
  const lo = u32(b, o);
  const hi = u32(b, o + 4);
  return lo === undefined || hi === undefined ? undefined : hi * 4294967296 + lo;
};
const u64Text = (b: Uint8Array, o: number) => (o + 8 <= b.length ? new DataView(b.buffer, b.byteOffset + o, 8).getBigUint64(0, true).toString() : undefined);
const hexOf = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** FILETIME (100 ns ticks since 1601) → ms since the epoch; null for 0 and for times outside 1601–9999. */
export function fromFiletime(ticks: number | undefined): number | null {
  if (!ticks) return null;
  const ms = ticks / 10_000 - 11_644_473_600_000;
  return Number.isFinite(ms) && ms > -11_644_473_600_000 && ms < 253_402_300_800_000 ? Math.floor(ms) : null;
}

/** Bare upper-case GUID ("800362A7-0000-0000-FB11-12639186E0D6"). */
const guid = (b: Uint8Array, o: number) => guidString(b, o)?.slice(1, -1);

/** UTF-16LE text up to the first NUL. */
function utf16z(b: Uint8Array, o: number, end: number): { text: string; next: number } | null {
  for (let i = o; i + 1 < end; i += 2) {
    if (b[i] === 0 && b[i + 1] === 0) return { text: new TextDecoder("utf-16le").decode(b.subarray(o, Math.min(i, o + MAX_TEXT))), next: i + 2 };
  }
  return null;
}

/** Single-byte text up to the first NUL. */
function asciiz(b: Uint8Array, o: number, end: number): { text: string; next: number } | null {
  for (let i = o; i < end; i++) {
    if (b[i] === 0) return { text: new TextDecoder("windows-1252").decode(b.subarray(o, Math.min(i, o + MAX_TEXT))), next: i + 1 };
  }
  return null;
}

// ---------------------------------------------------------------------------
// The container shared by entries and Resources records

interface Container {
  sections: [Uint8Array, Uint8Array];
  magic: boolean;
  /** Per section: the stored CRC-32 matches its content ("plain" or "inverted" convention), or not. */
  crc: ("ok" | "mismatch" | "cut")[];
  problems: string[];
}

export class QuarantineError extends Error {}

function container(data: Uint8Array, minFirst: number): Container {
  if (data.length < HEADER) throw new QuarantineError("shorter than the 60-byte header");
  if (data.length > MAX_ENTRY_BYTES) throw new QuarantineError(`larger than ${MAX_ENTRY_BYTES} bytes: not a quarantine entry`);
  const head = rc4(data.subarray(0, HEADER));
  const s1 = u32(head, 40)!;
  const s2 = u32(head, 44)!;
  const magic = MAGIC.every((x, i) => head[i] === x) && FOOTER.every((x, i) => head[56 + i] === x);
  const problems: string[] = [];
  if (!magic) {
    // Read anyway when the sizes fit the file exactly: the magic numbers come from one reader only.
    if (!(s1 >= minFirst && s1 <= MAX_ENTRY_BYTES && s2 <= MAX_ENTRY_BYTES && HEADER + s1 + s2 === data.length)) throw new QuarantineError("no quarantine header: neither its magic numbers nor section sizes that fit the file");
    problems.push("magic");
  }
  const crc: Container["crc"] = [];
  const sections: Uint8Array[] = [];
  let at = HEADER;
  for (const [n, size] of [s1, s2].entries()) {
    const end = Math.min(data.length, at + size);
    const plain = rc4(data.subarray(at, end));
    if (end - at < size) {
      crc.push("cut");
      problems.push(`section${n + 1}_cut`);
    } else {
      const c = crc32(plain);
      const stored = u32(head, 48 + 4 * n)!;
      crc.push(stored === c || stored === (~c >>> 0) ? "ok" : "mismatch");
    }
    sections.push(plain);
    at = end;
  }
  if (at < data.length) problems.push("trailing_bytes");
  return { sections: sections as [Uint8Array, Uint8Array], magic, crc, problems };
}

// ---------------------------------------------------------------------------
// Entries\{GUID}

/** A field of a quarantined resource: identifier (12 bits), type (4 bits), value. */
export interface QField {
  id: number;
  type: number;
  /** Name as Dissect names it, when known. */
  name?: string;
  /** Text, a number in decimal, a time in ISO 8601 or bytes in hex. */
  value: string;
}

export interface QResourceRaw {
  /** Its type as written: file, regkey, service, startup, taskscheduler, … */
  kind: string;
  /** The path as written (\\?\C:\…, HKLM\…). */
  path: string;
  physicalPath?: string;
  /** The content's identifier: the ResourceData file's name (40 hex digits, upper case). */
  resourceId?: string;
  attributes?: number;
  size?: number;
  created?: number | null;
  accessed?: number | null;
  written?: number | null;
  fields: QField[];
  problems: string[];
}

export interface QEntryRaw {
  guid?: string;
  scanId?: string;
  time: number | null;
  threatId?: string;
  /** Section 1's DWORD after the threat ID: 1 in every entry Fox-IT examined. */
  one?: number;
  threatName?: string;
  resources: QResourceRaw[];
  magic: boolean;
  crc: ("ok" | "mismatch" | "cut")[];
  problems: string[];
}

const FIELD_NAMES: Record<number, string> = {
  0x02: "ResourceId",
  0x03: "RegistryResourceId",
  0x0a: "Flags",
  0x0c: "PhysicalPath",
  0x0d: "DetectionContext",
  0x0e: "Unknown0E",
  0x0f: "CreationTime",
  0x10: "LastAccessTime",
  0x11: "LastWriteTime",
  0x12: "FileSize",
};

export function readEntry(data: Uint8Array): QEntryRaw {
  const c = container(data, ENTRY_FIXED + 1);
  const [first, second] = c.sections;
  const e: QEntryRaw = { time: null, resources: [], magic: c.magic, crc: c.crc, problems: [...c.problems] };
  if (first.length < ENTRY_FIXED) e.problems.push("section1_short");
  else {
    e.guid = guid(first, 0);
    e.scanId = guid(first, 16);
    e.time = fromFiletime(u64(first, 32));
    e.threatId = u64Text(first, 40);
    e.one = u32(first, 48);
    const name = asciiz(first, ENTRY_FIXED, first.length);
    e.threatName = name?.text ?? new TextDecoder("windows-1252").decode(first.subarray(ENTRY_FIXED, ENTRY_FIXED + MAX_TEXT));
    if (!name) e.problems.push("name_unterminated");
  }
  const count = u32(second, 0);
  if (count === undefined) {
    e.problems.push("section2_short");
    return e;
  }
  const table = 4 + Math.min(count, MAX_RESOURCES) * 4;
  if (count > MAX_RESOURCES || table > second.length) {
    e.problems.push("resource_count");
    return e;
  }
  const offsets = Array.from({ length: count }, (_, i) => u32(second, 4 + i * 4)!);
  for (const start of offsets) {
    if (start < table || start >= second.length) {
      e.problems.push("resource_offset");
      continue;
    }
    const end = offsets.filter((o) => o > start).reduce((m, o) => Math.min(m, o), second.length);
    const r = readResource(second, start, end);
    if (r) e.resources.push(r);
    else e.problems.push("resource_unreadable");
  }
  return e;
}

/** A resource at [start, end) of section 2: path, field count, type, then fields each 4-byte aligned within the section. */
function readResource(s: Uint8Array, start: number, end: number): QResourceRaw | null {
  const path = utf16z(s, start, end);
  if (!path) return null;
  let at = path.next;
  const count = u16(s, at);
  if (count === undefined || at + 2 > end) return null;
  at += 2;
  const kind = asciiz(s, at, end);
  if (!kind) return null;
  at = kind.next;
  const r: QResourceRaw = { kind: kind.text, path: path.text, fields: [], problems: [] };
  for (let n = 0; n < Math.min(count, MAX_FIELDS); n++) {
    at = (at + 3) & ~3;
    if (at + 4 > end) {
      r.problems.push("field_cut");
      break;
    }
    const size = u16(s, at)!;
    const word = u16(s, at + 2)!;
    const id = word & 0x0fff;
    const type = word >> 12;
    if (at + 4 + size > end) {
      r.problems.push("field_cut");
      break;
    }
    const d = s.subarray(at + 4, at + 4 + size);
    let value: string;
    let num: number | undefined;
    if (type === 1) value = new TextDecoder("windows-1252").decode(d.subarray(0, MAX_TEXT)).replace(/\0+$/, "");
    else if (type === 2) value = new TextDecoder("utf-16le").decode(d.subarray(0, MAX_TEXT & ~1)).replace(/\0+$/, "");
    else if (type === 3 && size === 4) value = String((num = u32(d, 0)!));
    else if (type === 6 && size === 8) value = u64Text(d, 0)!;
    else value = hexOf(d.subarray(0, 512));
    const f: QField = { id, type, value, ...(FIELD_NAMES[id] ? { name: FIELD_NAMES[id] } : {}) };
    if (type === 4) {
      f.name = "ResourceId";
      if (size === 20 && !r.resourceId) r.resourceId = hexOf(d).toUpperCase();
    } else if (id === 0x0c && type === 2) r.physicalPath = value;
    else if (id === 0x0a && num !== undefined) r.attributes = num;
    else if (id === 0x12 && type === 6) r.size = u64(d, 0);
    else if ((id === 0x0f || id === 0x10 || id === 0x11) && type === 6) {
      const t = fromFiletime(u64(d, 0));
      f.value = t === null ? value : new Date(t).toISOString();
      if (id === 0x0f) r.created = t;
      else if (id === 0x10) r.accessed = t;
      else r.written = t;
    }
    r.fields.push(f);
    at += 4 + size;
  }
  if (count > MAX_FIELDS) r.problems.push("too_many_fields");
  return r;
}

// ---------------------------------------------------------------------------
// Resources\<xx>\<ID>

export interface QRecordRaw {
  dataSize?: number;
  resourceId?: string;
  entries: string[];
  magic: boolean;
  crc: ("ok" | "mismatch" | "cut")[];
  problems: string[];
}

export function readResourceRecord(data: Uint8Array): QRecordRaw {
  const c = container(data, RECORD_FIXED);
  const [first, second] = c.sections;
  const r: QRecordRaw = { entries: [], magic: c.magic, crc: c.crc, problems: [...c.problems] };
  if (first.length < RECORD_FIXED) r.problems.push("section1_short");
  else {
    r.dataSize = u64(first, 0);
    r.resourceId = hexOf(first.subarray(8, 28)).toUpperCase();
    const n = u32(first, 28)!;
    if (second.length !== n * 16) r.problems.push("entry_count");
  }
  for (let o = 0; o + 16 <= second.length && r.entries.length < MAX_RESOURCES; o += 16) r.entries.push(guid(second, o)!);
  return r;
}

/** Whether `head` (≥ 60 bytes) decrypts to a quarantine header: "entry", "record" (Resources) or null. */
export function sniffQuarantine(head: Uint8Array): "entry" | "record" | null {
  if (head.length < HEADER) return null;
  const h = rc4(head.subarray(0, HEADER));
  if (!(MAGIC.every((x, i) => h[i] === x) && FOOTER.every((x, i) => h[56 + i] === x))) return null;
  return u32(h, 40) === RECORD_FIXED ? "record" : "entry";
}

// ---------------------------------------------------------------------------
// ResourceData\<xx>\<ID>

export const STREAM_KINDS: Record<number, string> = {
  1: "Data",
  2: "EaData",
  3: "SecurityData",
  4: "AlternateData",
  5: "Link",
  6: "PropertyData",
  7: "ObjectId",
  8: "ReparseData",
  9: "SparseBlock",
  10: "TxfsData",
  11: "GhostedFileExtents",
};
const STREAM_SPARSE = 0x08;

export interface StreamInfo {
  kind: number;
  attributes: number;
  /** An alternate data stream's name (":Zone.Identifier:$DATA"). */
  name: string;
  size: number;
  /** Where its data starts in the decrypted content. */
  offset: number;
}

export interface ZoneIdentifier {
  /** The stream's text as written (at most 4 KB). */
  text: string;
  zoneId?: string;
  referrerUrl?: string;
  hostUrl?: string;
  /** Other key=value lines. */
  other: [string, string][];
}

export interface ResourceDataRaw {
  size: number;
  /** SHA-1 of the whole decrypted content, upper case. */
  contentSha1: string;
  /** A registry hive (the content of a registry key or service resource), not a file's streams. */
  hive: boolean;
  streams: StreamInfo[];
  /** The file's data stream: size and hashes. Absent for a hive, a sparse file or no data stream. */
  file?: { size: number } & Hashes;
  sparse: boolean;
  zone?: ZoneIdentifier;
  owner?: string;
  group?: string;
  problems: string[];
}

function streams(content: Uint8Array, problems: string[]): StreamInfo[] {
  const out: StreamInfo[] = [];
  let at = 0;
  while (at < content.length && out.length < MAX_STREAMS) {
    if (at + 20 > content.length) {
      problems.push("stream_header_cut");
      break;
    }
    const kind = u32(content, at)!;
    const attributes = u32(content, at + 4)!;
    const size = u64(content, at + 8)!;
    const nameSize = u32(content, at + 16)!;
    if (kind < 1 || kind > 11) {
      problems.push("stream_kind");
      break;
    }
    const nameAt = at + 20;
    const dataAt = nameAt + nameSize;
    if (nameSize > 65_536 || dataAt > content.length || dataAt + size > content.length) {
      problems.push("stream_cut");
      break;
    }
    const name = new TextDecoder("utf-16le").decode(content.subarray(nameAt, nameAt + (nameSize & ~1)));
    out.push({ kind, attributes, name, size, offset: dataAt });
    at = dataAt + size;
  }
  if (out.length >= MAX_STREAMS && at < content.length) problems.push("too_many_streams");
  return out;
}

/** The Zone.Identifier text: [ZoneTransfer], ZoneId, ReferrerUrl, HostUrl. */
export function readZoneIdentifier(bytes: Uint8Array): ZoneIdentifier {
  const b = bytes.subarray(0, 4096);
  const text = b[0] === 0xff && b[1] === 0xfe ? new TextDecoder("utf-16le").decode(b.subarray(2)) : new TextDecoder("utf-8").decode(b);
  const z: ZoneIdentifier = { text, other: [] };
  for (const line of text.split(/\r?\n/)) {
    const m = /^([^=\[]+)=(.*)$/.exec(line.trim());
    if (!m) continue;
    const k = m[1].trim();
    const v = m[2].trim();
    if (/^zoneid$/i.test(k)) z.zoneId = v;
    else if (/^referrerurl$/i.test(k)) z.referrerUrl = v;
    else if (/^hosturl$/i.test(k)) z.hostUrl = v;
    else if (z.other.length < 20) z.other.push([k, v]);
  }
  return z;
}

/** Owner and group SIDs of a self-relative security descriptor. */
function sdSids(sd: Uint8Array): { owner?: string; group?: string } {
  if (sd.length < 20 || sd[0] !== 1) return {};
  const owner = u32(sd, 4)!;
  const group = u32(sd, 8)!;
  return { owner: owner ? sidString(sd, owner)?.sid : undefined, group: group ? sidString(sd, group)?.sid : undefined };
}

/** The decrypted content of a ResourceData file, described: streams, the data stream's hashes, Zone.Identifier, owner. */
export function readResourceData(encrypted: Uint8Array): ResourceDataRaw {
  if (encrypted.length > MAX_RESOURCE_BYTES) throw new QuarantineError(`larger than ${MAX_RESOURCE_BYTES / 1_048_576} MB: not decrypted`);
  const content = rc4(encrypted);
  const problems: string[] = [];
  const r: ResourceDataRaw = { size: content.length, contentSha1: sha1(content).toUpperCase(), hive: false, streams: [], sparse: false, problems };
  if (content.length >= 4 && content[0] === 0x72 && content[1] === 0x65 && content[2] === 0x67 && content[3] === 0x66) {
    r.hive = true;
    return r;
  }
  r.streams = streams(content, problems);
  const di = r.streams.findIndex((s) => s.kind === 1);
  if (di >= 0) {
    const d = r.streams[di];
    const blocks = r.streams.slice(di + 1).findIndex((s) => s.kind === 1 || s.kind === 4);
    const following = r.streams.slice(di + 1, blocks < 0 ? undefined : di + 1 + blocks);
    r.sparse = (d.attributes & STREAM_SPARSE) !== 0 || following.some((s) => s.kind === 9);
    if (!r.sparse) r.file = { size: d.size, ...hashes(content.subarray(d.offset, d.offset + d.size)) };
  }
  const zone = r.streams.find((s) => s.kind === 4 && /^:?zone\.identifier(?::\$data)?$/i.test(s.name));
  if (zone) r.zone = readZoneIdentifier(content.subarray(zone.offset, zone.offset + zone.size));
  const sd = r.streams.find((s) => s.kind === 3);
  if (sd) Object.assign(r, sdSids(content.subarray(sd.offset, sd.offset + Math.min(sd.size, 65_536))));
  return r;
}

/**
 * The quarantined file's bytes and its alternate data streams, for the
 * encrypted-ZIP export only. Null for a hive, a sparse file, or content
 * without a data stream.
 */
export function recoverFileData(encrypted: Uint8Array): { data: Uint8Array; ads: { name: string; data: Uint8Array }[] } | null {
  const r = readResourceData(encrypted);
  if (r.hive || r.sparse || !r.file) return null;
  const content = rc4(encrypted);
  const d = r.streams.find((s) => s.kind === 1)!;
  return {
    data: content.slice(d.offset, d.offset + d.size),
    ads: r.streams.filter((s) => s.kind === 4).map((s) => ({ name: s.name, data: content.slice(s.offset, s.offset + s.size) })),
  };
}

// ---------------------------------------------------------------------------
// Writers (the sample and the tests)

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
const le16 = (n: number) => Uint8Array.of(n & 0xff, (n >>> 8) & 0xff);
const le64 = (n: number | bigint) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
};
const toTicks = (ms: number) => BigInt(Math.round(ms)) * BigInt(10_000) + BigInt("116444736000000000");
const w16z = (s: string) => {
  const b = new Uint8Array(s.length * 2 + 2);
  for (let i = 0; i < s.length; i++) {
    b[i * 2] = s.charCodeAt(i) & 0xff;
    b[i * 2 + 1] = s.charCodeAt(i) >> 8;
  }
  return b;
};
const az = (s: string) => cat([new TextEncoder().encode(s), Uint8Array.of(0)]);
const fromHex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
/** "{GUID}" or bare → 16 mixed-endian bytes. */
export function guidToBytes(g: string): Uint8Array {
  const h = g.replace(/[{}-]/g, "");
  const x = (i: number) => parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return Uint8Array.from([x(3), x(2), x(1), x(0), x(5), x(4), x(7), x(6), x(8), x(9), x(10), x(11), x(12), x(13), x(14), x(15)]);
}

function writeContainer(first: Uint8Array, second: Uint8Array, unknown = 0): Uint8Array {
  const head = new Uint8Array(HEADER);
  head.set(MAGIC, 0);
  head.set(le32(unknown), 4);
  head.set(le32(first.length), 40);
  head.set(le32(second.length), 44);
  // Stored as Yamato Security's reader checks them: without the CRC's final inversion.
  head.set(le32(~crc32(first) >>> 0), 48);
  head.set(le32(~crc32(second) >>> 0), 52);
  head.set(FOOTER, 56);
  return cat([rc4(head), rc4(first), rc4(second)]);
}

export interface FileResourceSpec {
  kind?: string;
  /** As Defender writes it, \\?\ prefix included. */
  path: string;
  physicalPath?: string;
  resourceId?: string;
  attributes?: number;
  size?: number;
  created?: number;
  accessed?: number;
  written?: number;
}

export interface EntrySpec {
  guid: string;
  scanId: string;
  time: number;
  threatId: bigint | number;
  threatName: string;
  resources: FileResourceSpec[];
}

function field(id: number, type: number, data: Uint8Array): Uint8Array {
  return cat([le16(data.length), le16((type << 12) | id), data]);
}

/** A quarantine entry (Entries\{GUID}), as Dissect and Yamato Security's reader lay it out. */
export function writeEntry(spec: EntrySpec): Uint8Array {
  const first = cat([guidToBytes(spec.guid), guidToBytes(spec.scanId), le64(toTicks(spec.time)), le64(spec.threatId), le32(1), az(spec.threatName)]);
  const bodies = spec.resources.map((r) => {
    const fields: Uint8Array[] = [];
    if (r.resourceId) fields.push(field(0x02, 4, fromHex(r.resourceId)));
    if (r.attributes !== undefined) fields.push(field(0x0a, 3, le32(r.attributes)));
    if (r.physicalPath) fields.push(field(0x0c, 2, w16z(r.physicalPath)));
    if (r.created !== undefined) fields.push(field(0x0f, 6, le64(toTicks(r.created))));
    if (r.accessed !== undefined) fields.push(field(0x10, 6, le64(toTicks(r.accessed))));
    if (r.written !== undefined) fields.push(field(0x11, 6, le64(toTicks(r.written))));
    if (r.size !== undefined) fields.push(field(0x12, 6, le64(r.size)));
    return { head: cat([w16z(r.path), le16(fields.length), az(r.kind ?? "file")]), fields };
  });
  const table = 4 + spec.resources.length * 4;
  const parts: Uint8Array[] = [];
  const offsets: number[] = [];
  let at = table;
  for (const b of bodies) {
    at = (at + 3) & ~3;
    offsets.push(at);
    // Fields are 4-byte aligned within the section.
    const chunk: Uint8Array[] = [b.head];
    let p = at + b.head.length;
    for (const f of b.fields) {
      const aligned = (p + 3) & ~3;
      chunk.push(new Uint8Array(aligned - p), f);
      p = aligned + f.length;
    }
    parts.push(cat(chunk));
    at = p;
  }
  const second = new Uint8Array(at);
  second.set(le32(spec.resources.length), 0);
  offsets.forEach((o, i) => second.set(le32(o), 4 + i * 4));
  parts.forEach((p, i) => second.set(p, offsets[i]));
  return writeContainer(first, second);
}

/** A Resources record: the content's size and ID, the entries holding it. */
export function writeResourceRecord(dataSize: number, resourceId: string, entries: string[]): Uint8Array {
  const first = cat([le64(dataSize), fromHex(resourceId), le32(entries.length)]);
  return writeContainer(first, cat(entries.map(guidToBytes)));
}

export interface StreamSpec {
  kind: number;
  name?: string;
  data: Uint8Array;
  attributes?: number;
}

/** BackupRead-style streams (WIN32_STREAM_ID), decrypted. */
export function backupStreams(list: StreamSpec[]): Uint8Array {
  return cat(
    list.flatMap((s) => {
      const name = s.name ? w16z(s.name).subarray(0, s.name.length * 2) : new Uint8Array();
      return [cat([le32(s.kind), le32(s.attributes ?? 0), le64(s.data.length), le32(name.length), name]), s.data];
    }),
  );
}

/** A ResourceData file: the streams, RC4-encrypted; its name is the SHA-1 of the decrypted content (Yamato Security's reading). */
export function writeResourceData(list: StreamSpec[]): { bytes: Uint8Array; id: string } {
  const plain = backupStreams(list);
  return { bytes: rc4(plain), id: sha1(plain).toUpperCase() };
}

/** A self-relative security descriptor: owner, group, and a DACL granting full control to each SID given. */
export function securityDescriptor(owner: Uint8Array, group: Uint8Array, allow: Uint8Array[]): Uint8Array {
  const aces = allow.map((sid) => cat([Uint8Array.of(0, 0), le16(8 + sid.length), le32(0x001f01ff), sid]));
  const aclSize = 8 + aces.reduce((n, a) => n + a.length, 0);
  const acl = cat([Uint8Array.of(2, 0), le16(aclSize), le16(aces.length), le16(0), ...aces]);
  const ownerAt = 20;
  const groupAt = ownerAt + owner.length;
  const daclAt = groupAt + group.length;
  return cat([Uint8Array.of(1, 0), le16(0x8004), le32(ownerAt), le32(groupAt), le32(0), le32(daclAt), owner, group, acl]);
}
