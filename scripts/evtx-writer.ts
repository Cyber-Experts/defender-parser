/**
 * A minimal EVTX writer: template-free BinXML with inline names, ported from
 * PowerShell Parser's scripts/make-samples.py (whose one chunk the `evtx`
 * crate parses), with several chunks when the records do not fit in one.
 * Used by scripts/make-samples.ts for the sample's Operational log and by the
 * tests; tests/decoders.test.ts checks that the vendored reader parses it.
 */

import { crc32 } from "../lib/defender/hash";

const CHUNK_SIZE = 65_536;
const FILE_HEADER_SIZE = 4096;
const CHUNK_HEADER_SIZE = 512;

export interface EvtxEvent {
  recordId: number;
  /** ms since the epoch, UTC (TimeCreated). */
  time: number;
  provider: string;
  providerGuid?: string;
  eventId: number;
  level: number;
  channel: string;
  computer: string;
  /** Security UserID. */
  user?: string;
  pid?: number;
  tid?: number;
  /** <Data Name="…">value</Data>; an empty value is written as an empty element. */
  data: [string, string][];
}

class BinXml {
  private buf: number[] = [];
  constructor(private readonly base: number) {}
  private get off() {
    return this.base + this.buf.length;
  }
  private u8(n: number) {
    this.buf.push(n & 0xff);
  }
  private u16(n: number) {
    this.buf.push(n & 0xff, (n >> 8) & 0xff);
  }
  private u32(n: number) {
    this.buf.push(n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff);
  }
  private utf16(s: string) {
    for (let i = 0; i < s.length; i++) this.u16(s.charCodeAt(i));
  }
  /** Inline name: the name offset points at the NameLink written right after it. */
  private name(n: string) {
    this.u32(this.off + 4);
    this.u32(0); // next link
    this.u16(0); // hash
    this.u16(n.length);
    this.utf16(n);
    this.u16(0);
  }
  private value(text: string) {
    this.u8(0x05); // value token
    this.u8(0x01); // string type
    this.u16(text.length);
    this.utf16(text);
  }
  fragmentHeader() {
    this.buf.push(0x0f, 0x01, 0x01, 0x00);
  }
  open(n: string, attrs: [string, string][] = []) {
    this.u8(attrs.length ? 0x41 : 0x01);
    this.u16(0); // dependency identifier
    this.u32(0); // data size (unused by the reader)
    this.name(n);
    if (attrs.length) {
      this.u32(0); // attribute list size
      for (const [an, av] of attrs) {
        this.u8(0x06);
        this.name(an);
        this.value(av);
      }
    }
  }
  closeStart() {
    this.u8(0x02);
  }
  closeEmpty() {
    this.u8(0x03);
  }
  close() {
    this.u8(0x04);
  }
  eof() {
    this.u8(0x00);
  }
  leaf(n: string, text?: string, attrs: [string, string][] = []) {
    this.open(n, attrs);
    if (text === undefined || text === "") this.closeEmpty();
    else {
      this.closeStart();
      this.value(text);
      this.close();
    }
  }
  bytes() {
    return Uint8Array.from(this.buf);
  }
}

const iso7 = (ms: number) => new Date(ms).toISOString().replace(/\.(\d{3})Z$/, ".$10000Z");

function buildEvent(offset: number, e: EvtxEvent): Uint8Array {
  const x = new BinXml(offset);
  x.fragmentHeader();
  x.open("Event");
  x.closeStart();
  x.open("System");
  x.closeStart();
  x.open("Provider", e.providerGuid ? [["Name", e.provider], ["Guid", e.providerGuid]] : [["Name", e.provider]]);
  x.closeEmpty();
  x.leaf("EventID", String(e.eventId));
  x.leaf("Version", "0");
  x.leaf("Level", String(e.level));
  x.leaf("Task", "0");
  x.leaf("Opcode", "0");
  x.leaf("Keywords", "0x8000000000000000");
  x.open("TimeCreated", [["SystemTime", iso7(e.time)]]);
  x.closeEmpty();
  x.leaf("EventRecordID", String(e.recordId));
  x.open("Execution", [
    ["ProcessID", String(e.pid ?? 3536)],
    ["ThreadID", String(e.tid ?? 3948)],
  ]);
  x.closeEmpty();
  x.leaf("Channel", e.channel);
  x.leaf("Computer", e.computer);
  x.open("Security", e.user ? [["UserID", e.user]] : []);
  x.closeEmpty();
  x.close(); // </System>
  x.open("EventData");
  x.closeStart();
  for (const [n, v] of e.data) x.leaf("Data", v, [["Name", n]]);
  x.close(); // </EventData>
  x.close(); // </Event>
  x.eof();
  return x.bytes();
}

const toTicks = (ms: number) => BigInt(Math.round(ms)) * BigInt(10_000) + BigInt("116444736000000000");

function record(offset: number, e: EvtxEvent): Uint8Array {
  const bx = buildEvent(offset + 24, e);
  const size = 24 + bx.length + 4;
  const out = new Uint8Array(size);
  const dv = new DataView(out.buffer);
  out.set([0x2a, 0x2a, 0, 0], 0);
  dv.setUint32(4, size, true);
  dv.setBigUint64(8, BigInt(e.recordId), true);
  dv.setBigUint64(16, toTicks(e.time), true);
  out.set(bx, 24);
  dv.setUint32(size - 4, size, true);
  return out;
}

function buildChunk(events: EvtxEvent[]): Uint8Array {
  const chunk = new Uint8Array(CHUNK_SIZE);
  let at = CHUNK_HEADER_SIZE;
  let lastOffset = at;
  for (const e of events) {
    const r = record(at, e);
    lastOffset = at;
    chunk.set(r, at);
    at += r.length;
  }
  const dv = new DataView(chunk.buffer);
  chunk.set(new TextEncoder().encode("ElfChnk\0"), 0);
  dv.setBigUint64(8, BigInt(events[0].recordId), true); // first event record number
  dv.setBigUint64(16, BigInt(events[events.length - 1].recordId), true); // last event record number
  dv.setBigUint64(24, BigInt(events[0].recordId), true); // first event record ID
  dv.setBigUint64(32, BigInt(events[events.length - 1].recordId), true); // last event record ID
  dv.setUint32(40, 128, true); // header size
  dv.setUint32(44, lastOffset, true);
  dv.setUint32(48, at, true); // free space offset
  dv.setUint32(52, crc32(chunk.subarray(CHUNK_HEADER_SIZE, at)), true);
  dv.setUint32(120, 0, true);
  const head = new Uint8Array(120 + 384);
  head.set(chunk.subarray(0, 120), 0);
  head.set(chunk.subarray(128, 512), 120);
  dv.setUint32(124, crc32(head), true);
  return chunk;
}

/** An EVTX file holding the events in order, as many 64 KB chunks as they need. */
export function buildEvtx(events: EvtxEvent[]): Uint8Array {
  const chunks: Uint8Array[] = [];
  let group: EvtxEvent[] = [];
  let used = CHUNK_HEADER_SIZE;
  for (const e of events) {
    const size = record(0, e).length;
    if (group.length && used + size > CHUNK_SIZE) {
      chunks.push(buildChunk(group));
      group = [];
      used = CHUNK_HEADER_SIZE;
    }
    if (CHUNK_HEADER_SIZE + size > CHUNK_SIZE) throw new Error(`event ${e.recordId} does not fit in a chunk`);
    group.push(e);
    used += size;
  }
  if (group.length) chunks.push(buildChunk(group));
  const header = new Uint8Array(FILE_HEADER_SIZE);
  const dv = new DataView(header.buffer);
  header.set(new TextEncoder().encode("ElfFile\0"), 0);
  dv.setBigUint64(8, BigInt(0), true); // first chunk number
  dv.setBigUint64(16, BigInt(Math.max(0, chunks.length - 1)), true); // last chunk number
  dv.setBigUint64(24, BigInt((events[events.length - 1]?.recordId ?? 0) + 1), true); // next record ID
  dv.setUint32(32, 128, true);
  dv.setUint16(36, 1, true); // minor version
  dv.setUint16(38, 3, true); // major version
  dv.setUint16(40, FILE_HEADER_SIZE, true);
  dv.setUint16(42, chunks.length, true);
  dv.setUint32(120, 0, true); // flags: clean
  dv.setUint32(124, crc32(header.subarray(0, 120)), true);
  const out = new Uint8Array(FILE_HEADER_SIZE + chunks.length * CHUNK_SIZE);
  out.set(header, 0);
  chunks.forEach((c, i) => out.set(c, FILE_HEADER_SIZE + i * CHUNK_SIZE));
  return out;
}
