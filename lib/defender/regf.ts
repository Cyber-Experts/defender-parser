// Windows registry hive files ("regf"): SYSTEM, SOFTWARE, SAM, NTUSER.DAT,
// UsrClass.dat. Read-only and bounded: the file comes from a machine under
// investigation, so every offset is checked, list recursion is capped and a
// cycle never loops. Only the primary file is read; transaction logs
// (.LOG1/.LOG2) are not replayed, which `dirty` reports.
//
// Layout: a 4 KiB base block, then hive bins ("hbin") holding cells. A cell
// starts with its size as a signed 32-bit integer (negative: allocated) and
// is addressed by its offset from the first bin. Keys are "nk" cells, values
// "vk", subkey lists "lf" / "lh" / "li" / "ri", big data "db".
//
// `writeHive` builds a hive from a tree, for the sample and the tests.

export const REG_NONE = 0;
export const REG_SZ = 1;
export const REG_EXPAND_SZ = 2;
export const REG_BINARY = 3;
export const REG_DWORD = 4;
export const REG_DWORD_BIG_ENDIAN = 5;
export const REG_LINK = 6;
export const REG_MULTI_SZ = 7;
export const REG_QWORD = 11;

export class HiveError extends Error {}

const BASE = 4096;
const MAX_KEYS = 2_000_000;
const MAX_VALUES_PER_KEY = 100_000;
const MAX_LIST_DEPTH = 8;
const BIG_DATA_MIN_MINOR = 4;
const BIG_SEGMENT = 16344;

/** FILETIME (100 ns since 1601) → ms since the Unix epoch; null for 0 or absurd values. */
export function filetime(lo: number, hi: number): number | null {
  if (lo === 0 && hi === 0) return null;
  const ms = (hi * 4294967296 + lo) / 10000 - 11644473600000;
  return ms > 0 && ms < 4102444800000 ? Math.round(ms) : null;
}

export interface RegValue {
  /** "" for the key's default value. */
  name: string;
  type: number;
  data: Uint8Array;
}

const utf16 = new TextDecoder("utf-16le");
const latin1 = new TextDecoder("latin1");

/** UTF-16LE text up to the first NUL (REG_SZ, REG_EXPAND_SZ). */
export function decodeSz(data: Uint8Array): string {
  const even = data.subarray(0, data.length & ~1);
  const s = utf16.decode(even);
  const nul = s.indexOf("\0");
  return nul === -1 ? s : s.slice(0, nul);
}

/** A value as text: strings as stored, numbers in decimal, binary as hex. */
export function valueText(v: RegValue | undefined): string | undefined {
  if (!v) return undefined;
  switch (v.type) {
    case REG_SZ:
    case REG_EXPAND_SZ:
    case REG_LINK:
      return decodeSz(v.data);
    case REG_MULTI_SZ:
      return valueStrings(v).join(" ");
    case REG_DWORD:
    case REG_DWORD_BIG_ENDIAN:
    case REG_QWORD: {
      const n = valueNumber(v);
      return n === undefined ? undefined : String(n);
    }
    default:
      // Some software writes strings as REG_BINARY / REG_NONE.
      return looksUtf16(v.data) ? decodeSz(v.data) : hex(v.data.subarray(0, 256));
  }
}

/** REG_MULTI_SZ entries (empty ones dropped); a single REG_SZ as one entry. */
export function valueStrings(v: RegValue | undefined): string[] {
  if (!v) return [];
  if (v.type === REG_MULTI_SZ) {
    return utf16
      .decode(v.data.subarray(0, v.data.length & ~1))
      .split("\0")
      .filter((s) => s !== "");
  }
  const s = valueText(v);
  return s ? [s] : [];
}

export function valueNumber(v: RegValue | undefined): number | undefined {
  if (!v) return undefined;
  const d = new DataView(v.data.buffer, v.data.byteOffset, v.data.byteLength);
  if (v.type === REG_DWORD && d.byteLength >= 4) return d.getUint32(0, true);
  if (v.type === REG_DWORD_BIG_ENDIAN && d.byteLength >= 4) return d.getUint32(0, false);
  if (v.type === REG_QWORD && d.byteLength >= 8) return d.getUint32(0, true) + d.getUint32(4, true) * 4294967296;
  // Numbers stored as strings ("Start" = "2" happens in hand-made keys).
  if ((v.type === REG_SZ || v.type === REG_EXPAND_SZ) && /^\s*\d+\s*$/.test(decodeSz(v.data))) return Number(decodeSz(v.data));
  if (v.type === REG_BINARY && d.byteLength === 4) return d.getUint32(0, true);
  return undefined;
}

function looksUtf16(b: Uint8Array): boolean {
  if (b.length < 4 || b.length % 2) return false;
  let zeros = 0;
  for (let i = 1; i < b.length; i += 2) if (b[i] === 0) zeros++;
  return zeros >= (b.length / 2) * 0.9 && b[0] !== 0;
}

export const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

export class Hive {
  readonly bytes: Uint8Array;
  private readonly dv: DataView;
  /** Base block: sequence numbers differ when the hive was not cleanly written back. */
  readonly dirty: boolean;
  /** Base block last-written time. */
  readonly lastWrite: number | null;
  /** The tail of the path the hive was loaded from ("\??\C:\Users\x\ntuser.dat"), as stored. */
  readonly fileName: string;
  readonly minor: number;
  /** Shorter than its base block says: keys past the cut cannot be read. */
  readonly truncated: boolean;
  readonly root: Key;
  /** Keys materialised so far (bounded by MAX_KEYS). */
  keys = 0;
  /** Damaged cells skipped while reading (lists, keys, values), and the first messages. */
  damaged = 0;
  readonly damage: string[] = [];

  /** A damaged cell: skip it, keep reading. Resource limits are not damage: they stop the read. */
  skip(err: unknown) {
    if (!(err instanceof HiveError) || /^too many/.test(err.message)) throw err;
    this.damaged++;
    if (this.damage.length < 10) this.damage.push(err.message);
  }

  constructor(bytes: Uint8Array) {
    if (bytes.length < BASE + 32) throw new HiveError("too small to be a registry hive");
    this.bytes = bytes;
    this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (this.ascii(0, 4) !== "regf") throw new HiveError("not a registry hive (no regf signature)");
    this.dirty = this.u32(4) !== this.u32(8);
    this.lastWrite = filetime(this.u32(12), this.u32(16));
    this.minor = this.u32(24);
    const name = utf16.decode(bytes.subarray(48, 48 + 64));
    this.fileName = name.replace(/\0[\s\S]*$/, "");
    if (this.ascii(BASE, 4) !== "hbin") throw new HiveError("no hive bin after the base block");
    this.truncated = bytes.length < BASE + this.u32(40);
    this.root = this.key(this.u32(36), "", "");
  }

  u16(o: number): number {
    if (o < 0 || o + 2 > this.bytes.length) throw new HiveError(`read past the end of the hive at ${o}`);
    return this.dv.getUint16(o, true);
  }
  u32(o: number): number {
    if (o < 0 || o + 4 > this.bytes.length) throw new HiveError(`read past the end of the hive at ${o}`);
    return this.dv.getUint32(o, true);
  }
  private ascii(o: number, n: number): string {
    return o + n <= this.bytes.length ? latin1.decode(this.bytes.subarray(o, o + n)) : "";
  }

  /** A cell's data as [file offset, length]. */
  cell(off: number): [number, number] {
    const at = BASE + off;
    if (off === 0xffffffff || at + 4 > this.bytes.length || off < 32) throw new HiveError(`cell offset out of range: ${off}`);
    const size = Math.abs(this.dv.getInt32(at, true));
    if (size < 8 || at + size > this.bytes.length) throw new HiveError(`bad cell size at ${off}`);
    return [at + 4, size - 4];
  }

  sig(at: number): string {
    return this.ascii(at, 2);
  }

  key(off: number, parentPath: string, nameOverride?: string): Key {
    if (++this.keys > MAX_KEYS) throw new HiveError("too many keys");
    const [at, len] = this.cell(off);
    if (this.sig(at) !== "nk" || len < 76) throw new HiveError(`expected a key (nk) at ${off}`);
    const flags = this.u16(at + 2);
    const nameLen = Math.min(this.u16(at + 72), len - 76);
    const raw = this.bytes.subarray(at + 76, at + 76 + nameLen);
    const name = nameOverride ?? (flags & 0x20 ? latin1.decode(raw) : utf16.decode(raw.subarray(0, raw.length & ~1)));
    const path = nameOverride !== undefined ? "" : parentPath ? `${parentPath}\\${name}` : name;
    return new Key(this, at, name, path);
  }
}

export class Key {
  readonly lastWrite: number | null;
  private sub?: Key[];
  private vals?: RegValue[];

  constructor(
    readonly hive: Hive,
    private readonly at: number,
    /** The key's own name ("" for the hive root). */
    readonly name: string,
    /** Path from the hive root, backslash-separated ("" for the root). */
    readonly path: string,
  ) {
    this.lastWrite = filetime(hive.u32(at + 4), hive.u32(at + 8));
  }

  get subkeyCount(): number {
    return this.hive.u32(this.at + 20);
  }

  subkeys(): Key[] {
    if (this.sub) return this.sub;
    const out: Key[] = [];
    const n = this.subkeyCount;
    if (n > 0) {
      const offs: number[] = [];
      try {
        this.list(this.hive.u32(this.at + 28), offs, 0, new Set());
      } catch (err) {
        this.hive.skip(err);
      }
      for (const o of offs) {
        try {
          out.push(this.hive.key(o, this.path));
        } catch (err) {
          this.hive.skip(err);
        }
      }
    }
    this.sub = out;
    return out;
  }

  private list(off: number, out: number[], depth: number, seen: Set<number>) {
    if (depth > MAX_LIST_DEPTH || seen.has(off)) throw new HiveError(`subkey list loops or nests too deep at ${off}`);
    seen.add(off);
    const h = this.hive;
    const [at, len] = h.cell(off);
    const sig = h.sig(at);
    const count = h.u16(at + 2);
    if (sig === "lf" || sig === "lh") {
      if (4 + count * 8 > len) throw new HiveError(`subkey list overruns its cell at ${off}`);
      for (let i = 0; i < count; i++) out.push(h.u32(at + 4 + i * 8));
    } else if (sig === "li") {
      if (4 + count * 4 > len) throw new HiveError(`subkey list overruns its cell at ${off}`);
      for (let i = 0; i < count; i++) out.push(h.u32(at + 4 + i * 4));
    } else if (sig === "ri") {
      if (4 + count * 4 > len) throw new HiveError(`subkey index overruns its cell at ${off}`);
      for (let i = 0; i < count; i++) this.list(h.u32(at + 4 + i * 4), out, depth + 1, seen);
    } else throw new HiveError(`unknown subkey list "${sig}" at ${off}`);
    if (out.length > MAX_KEYS) throw new HiveError("too many keys");
  }

  /** A descendant by backslash path, case-insensitive. */
  subkey(path: string): Key | undefined {
    let k: Key | undefined = this as Key;
    for (const part of path.split("\\")) {
      if (!part) continue;
      const lower = part.toLowerCase();
      k = k.subkeys().find((s) => s.name.toLowerCase() === lower);
      if (!k) return undefined;
    }
    return k;
  }

  values(): RegValue[] {
    if (this.vals) return this.vals;
    const h = this.hive;
    const n = h.u32(this.at + 36);
    const out: RegValue[] = [];
    if (n > 0) {
      if (n > MAX_VALUES_PER_KEY) throw new HiveError(`too many values in ${this.path || "the root key"}`);
      try {
        const [lat, llen] = h.cell(h.u32(this.at + 40));
        const count = Math.min(n, Math.floor(llen / 4));
        if (count < n) h.skip(new HiveError(`value list overruns its cell in ${this.path}`));
        for (let i = 0; i < count; i++) {
          try {
            const v = this.readValue(h.u32(lat + i * 4));
            if (v) out.push(v);
          } catch (err) {
            h.skip(err);
          }
        }
      } catch (err) {
        h.skip(err);
      }
    }
    this.vals = out;
    return out;
  }

  private readValue(off: number): RegValue | undefined {
    const h = this.hive;
    const [at, len] = h.cell(off);
    if (h.sig(at) !== "vk" || len < 20) return undefined;
    const nameLen = Math.min(h.u16(at + 2), len - 20);
    const rawSize = h.u32(at + 4);
    const dataOff = h.u32(at + 8);
    const type = h.u32(at + 12);
    const flags = h.u16(at + 16);
    const rawName = h.bytes.subarray(at + 20, at + 20 + nameLen);
    const name = flags & 1 ? latin1.decode(rawName) : utf16.decode(rawName.subarray(0, rawName.length & ~1));
    let data: Uint8Array;
    if (rawSize & 0x80000000) {
      // Up to four bytes kept in the offset field itself.
      data = h.bytes.slice(at + 8, at + 8 + Math.min(rawSize & 0x7fffffff, 4));
    } else if (rawSize === 0) {
      data = new Uint8Array(0);
    } else {
      const [dat, dlen] = h.cell(dataOff);
      if (rawSize > BIG_SEGMENT && h.minor >= BIG_DATA_MIN_MINOR && h.sig(dat) === "db") data = this.bigData(dat, rawSize);
      else data = h.bytes.slice(dat, dat + Math.min(rawSize, dlen));
    }
    return { name, type, data };
  }

  private bigData(at: number, declared: number): Uint8Array {
    let size = declared;
    const h = this.hive;
    const segs = h.u16(at + 2);
    const [lat, llen] = h.cell(h.u32(at + 4));
    if (segs * 4 > llen) throw new HiveError("big data segment list overruns its cell");
    // The declared size is the file's word: never allocate more than the segments can hold.
    const out = new Uint8Array(Math.min(size, segs * BIG_SEGMENT, h.bytes.length));
    size = out.length;
    let pos = 0;
    for (let i = 0; i < segs && pos < size; i++) {
      const [sat, slen] = h.cell(h.u32(lat + i * 4));
      const take = Math.min(slen, BIG_SEGMENT, size - pos);
      out.set(h.bytes.subarray(sat, sat + take), pos);
      pos += take;
    }
    return pos === size ? out : out.slice(0, pos);
  }

  /** A value by name, case-insensitive ("" or "(default)" for the default value). */
  value(name: string): RegValue | undefined {
    const n = name.toLowerCase() === "(default)" ? "" : name.toLowerCase();
    return this.values().find((v) => v.name.toLowerCase() === n);
  }

  text(name: string): string | undefined {
    return valueText(this.value(name));
  }

  num(name: string): number | undefined {
    return valueNumber(this.value(name));
  }
}

export function openHive(bytes: Uint8Array): Hive {
  return new Hive(bytes);
}

/** Every key under (and including) `k`, depth-first, at most `max`. */
export function* walk(k: Key, max = MAX_KEYS): Generator<Key> {
  const stack: Key[] = [k];
  let n = 0;
  while (stack.length) {
    const cur = stack.pop()!;
    yield cur;
    if (++n >= max) return;
    const subs = cur.subkeys();
    for (let i = subs.length - 1; i >= 0; i--) stack.push(subs[i]);
  }
}

// ---------------------------------------------------------------------------
// Writer

export interface WValue {
  name: string;
  type: number;
  data: Uint8Array;
}
export interface WKey {
  name: string;
  /** ms since the epoch. */
  lastWrite?: number;
  values?: WValue[];
  subkeys?: WKey[];
}

const enc16 = (s: string) => {
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    out[i * 2] = s.charCodeAt(i) & 0xff;
    out[i * 2 + 1] = s.charCodeAt(i) >> 8;
  }
  return out;
};
const isLatin1 = (s: string) => /^[\x00-\xff]*$/.test(s);

export const sz = (name: string, s: string, type = REG_SZ): WValue => ({ name, type, data: enc16(`${s}\0`) });
export const expandSz = (name: string, s: string): WValue => sz(name, s, REG_EXPAND_SZ);
export const multiSz = (name: string, list: string[]): WValue => ({ name, type: REG_MULTI_SZ, data: enc16(`${list.map((s) => `${s}\0`).join("")}\0`) });
export const dword = (name: string, n: number): WValue => {
  const d = new Uint8Array(4);
  new DataView(d.buffer).setUint32(0, n >>> 0, true);
  return { name, type: REG_DWORD, data: d };
};
export const qword = (name: string, n: number | bigint): WValue => {
  const d = new Uint8Array(8);
  new DataView(d.buffer).setBigUint64(0, BigInt(n), true);
  return { name, type: REG_QWORD, data: d };
};
export const binary = (name: string, data: Uint8Array, type = REG_BINARY): WValue => ({ name, type, data });

/** ms since the epoch → FILETIME [lo, hi]. */
export function toFiletime(ms: number): [number, number] {
  const ft = BigInt(Math.round(ms)) * BigInt(10000) + BigInt("116444736000000000");
  return [Number(ft & BigInt(0xffffffff)), Number(ft >> BigInt(32))];
}

/** Uppercase-name hash used by "lh" lists. */
export function lhHash(name: string): number {
  let h = 0;
  for (const ch of name.toUpperCase()) h = (Math.imul(h, 37) + ch.charCodeAt(0)) >>> 0;
  return h;
}

interface Cell {
  size: number;
  write: (dv: DataView, at: number, off: (c: Cell) => number) => void;
}

/** A hive file holding `root` (its name becomes the root key's name). */
export function writeHive(root: WKey, opts: { fileName?: string; lastWrite?: number } = {}): Uint8Array {
  const cells: Cell[] = [];
  const add = (dataLen: number, write: Cell["write"]): Cell => {
    const c: Cell = { size: (4 + dataLen + 7) & ~7, write };
    cells.push(c);
    return c;
  };

  // One shared security descriptor: owner Administrators, group SYSTEM, Everyone full control.
  const sd = securityDescriptor();
  let keyCount = 0;
  const sk = add(20 + sd.length, (dv, at, off) => {
    dv.setUint16(at, 0x6b73, true); // "sk"
    dv.setUint32(at + 4, off(sk), true);
    dv.setUint32(at + 8, off(sk), true);
    dv.setUint32(at + 12, keyCount, true);
    dv.setUint32(at + 16, sd.length, true);
    new Uint8Array(dv.buffer).set(sd, at + 20);
  });

  const keyCell = (k: WKey, isRoot: boolean, parent: () => Cell | null): Cell => {
    keyCount++;
    const latin = isLatin1(k.name);
    const nameBytes = latin ? Uint8Array.from(k.name, (c) => c.charCodeAt(0)) : enc16(k.name);
    const subs = [...(k.subkeys ?? [])].sort((a, b) => (a.name.toUpperCase() < b.name.toUpperCase() ? -1 : a.name.toUpperCase() > b.name.toUpperCase() ? 1 : 0));
    const vals = k.values ?? [];
    const [lo, hi] = toFiletime(k.lastWrite ?? opts.lastWrite ?? Date.UTC(2026, 0, 1));
    const subCells: Cell[] = [];
    const nk = add(76 + nameBytes.length, (dv, at, off) => {
      dv.setUint16(at, 0x6b6e, true); // "nk"
      dv.setUint16(at + 2, (latin ? 0x20 : 0) | (isRoot ? 0x0c : 0), true);
      dv.setUint32(at + 4, lo, true);
      dv.setUint32(at + 8, hi, true);
      const p = parent();
      dv.setUint32(at + 16, p ? off(p) : 0, true);
      dv.setUint32(at + 20, subs.length, true);
      dv.setUint32(at + 28, subs.length ? off(subList!) : 0xffffffff, true);
      dv.setUint32(at + 32, 0xffffffff, true);
      dv.setUint32(at + 36, vals.length, true);
      dv.setUint32(at + 40, vals.length ? off(valList!) : 0xffffffff, true);
      dv.setUint32(at + 44, off(sk), true);
      dv.setUint32(at + 48, 0xffffffff, true);
      dv.setUint32(at + 52, Math.max(0, ...subs.map((s) => s.name.length * 2)), true);
      dv.setUint32(at + 60, Math.max(0, ...vals.map((v) => v.name.length * 2)), true);
      dv.setUint32(at + 64, Math.max(0, ...vals.map((v) => v.data.length)), true);
      dv.setUint16(at + 72, nameBytes.length, true);
      new Uint8Array(dv.buffer).set(nameBytes, at + 76);
    });
    let valList: Cell | undefined;
    if (vals.length) {
      const vks = vals.map((v) => valueCells(v));
      valList = add(vals.length * 4, (dv, at, off) => vks.forEach((c, i) => dv.setUint32(at + i * 4, off(c), true)));
    }
    let subList: Cell | undefined;
    for (const s of subs) subCells.push(keyCell(s, false, () => nk));
    if (subs.length) {
      const CHUNK = 1000;
      if (subs.length <= CHUNK) subList = lh(subs, subCells);
      else {
        const parts: Cell[] = [];
        for (let i = 0; i < subs.length; i += CHUNK) parts.push(lh(subs.slice(i, i + CHUNK), subCells.slice(i, i + CHUNK)));
        subList = add(4 + parts.length * 4, (dv, at, off) => {
          dv.setUint16(at, 0x6972, true); // "ri"
          dv.setUint16(at + 2, parts.length, true);
          parts.forEach((c, i) => dv.setUint32(at + 4 + i * 4, off(c), true));
        });
      }
    }
    return nk;
  };

  const lh = (keys: WKey[], kc: Cell[]): Cell =>
    add(4 + keys.length * 8, (dv, at, off) => {
      dv.setUint16(at, 0x686c, true); // "lh"
      dv.setUint16(at + 2, keys.length, true);
      keys.forEach((k, i) => {
        dv.setUint32(at + 4 + i * 8, off(kc[i]), true);
        dv.setUint32(at + 8 + i * 8, lhHash(k.name), true);
      });
    });

  const valueCells = (v: WValue): Cell => {
    const latin = isLatin1(v.name);
    const nameBytes = latin ? Uint8Array.from(v.name, (c) => c.charCodeAt(0)) : enc16(v.name);
    let data: Cell | undefined;
    if (v.data.length > 4 && v.data.length <= BIG_SEGMENT) {
      data = add(v.data.length, (dv, at) => new Uint8Array(dv.buffer).set(v.data, at));
    } else if (v.data.length > BIG_SEGMENT) {
      const segs: Cell[] = [];
      for (let i = 0; i < v.data.length; i += BIG_SEGMENT) {
        const part = v.data.subarray(i, i + BIG_SEGMENT);
        segs.push(add(part.length, (dv, at) => new Uint8Array(dv.buffer).set(part, at)));
      }
      const segList = add(segs.length * 4, (dv, at, off) => segs.forEach((c, i) => dv.setUint32(at + i * 4, off(c), true)));
      data = add(8, (dv, at, off) => {
        dv.setUint16(at, 0x6264, true); // "db"
        dv.setUint16(at + 2, segs.length, true);
        dv.setUint32(at + 4, off(segList), true);
      });
    }
    return add(20 + nameBytes.length, (dv, at, off) => {
      dv.setUint16(at, 0x6b76, true); // "vk"
      dv.setUint16(at + 2, nameBytes.length, true);
      if (data) {
        dv.setUint32(at + 4, v.data.length, true);
        dv.setUint32(at + 8, off(data), true);
      } else {
        dv.setUint32(at + 4, (v.data.length | 0x80000000) >>> 0, true);
        new Uint8Array(dv.buffer).set(v.data, at + 8);
      }
      dv.setUint32(at + 12, v.type, true);
      dv.setUint16(at + 16, latin ? 1 : 0, true);
      new Uint8Array(dv.buffer).set(nameBytes, at + 20);
    });
  };

  const rootCell = keyCell(root, true, () => null);

  // Lay the cells out in 4 KiB bins; a cell never crosses a bin boundary.
  const offsets = new Map<Cell, number>();
  const bins: { start: number; size: number }[] = [];
  let binStart = 0;
  let binSize = 4096;
  let pos = 32;
  for (const c of cells) {
    if (pos + c.size > binSize) {
      bins.push({ start: binStart, size: binSize });
      binStart += binSize;
      binSize = Math.max(4096, Math.ceil((c.size + 32) / 4096) * 4096);
      pos = 32;
    }
    offsets.set(c, binStart + pos);
    pos += c.size;
  }
  bins.push({ start: binStart, size: binSize });
  const total = binStart + binSize;

  const out = new Uint8Array(BASE + total);
  const dv = new DataView(out.buffer);
  const off = (c: Cell) => offsets.get(c)!;
  const [tlo, thi] = toFiletime(opts.lastWrite ?? root.lastWrite ?? Date.UTC(2026, 0, 1));
  for (const b of bins) {
    const at = BASE + b.start;
    out.set([0x68, 0x62, 0x69, 0x6e], at); // "hbin"
    dv.setUint32(at + 4, b.start, true);
    dv.setUint32(at + 8, b.size, true);
    if (b.start === 0) {
      dv.setUint32(at + 20, tlo, true);
      dv.setUint32(at + 24, thi, true);
    }
  }
  for (const c of cells) {
    const o = off(c);
    dv.setInt32(BASE + o, -c.size, true);
    c.write(dv, BASE + o + 4, off);
  }
  // Free space at the end of each bin: one free cell.
  const used = new Map<number, number>();
  for (const c of cells) {
    const o = off(c);
    const b = bins.find((x) => o >= x.start && o < x.start + x.size)!;
    used.set(b.start, Math.max(used.get(b.start) ?? 32, o - b.start + c.size));
  }
  for (const b of bins) {
    const u = used.get(b.start) ?? 32;
    if (b.size - u >= 8) dv.setInt32(BASE + b.start + u, b.size - u, true);
  }

  // Base block.
  out.set([0x72, 0x65, 0x67, 0x66], 0); // "regf"
  dv.setUint32(4, 1, true);
  dv.setUint32(8, 1, true);
  dv.setUint32(12, tlo, true);
  dv.setUint32(16, thi, true);
  dv.setUint32(20, 1, true);
  dv.setUint32(24, 5, true);
  dv.setUint32(28, 0, true);
  dv.setUint32(32, 1, true);
  dv.setUint32(36, off(rootCell), true);
  dv.setUint32(40, total, true);
  dv.setUint32(44, 1, true);
  out.set(enc16((opts.fileName ?? "").slice(-31)), 48);
  let sum = 0;
  for (let i = 0; i < 508; i += 4) sum ^= dv.getUint32(i, true);
  sum >>>= 0;
  dv.setUint32(508, sum === 0xffffffff ? 0xfffffffe : sum === 0 ? 1 : sum, true);
  return out;
}

function securityDescriptor(): Uint8Array {
  const sid = (auth: number, subs: number[]) => {
    const b = new Uint8Array(8 + subs.length * 4);
    const d = new DataView(b.buffer);
    b[0] = 1;
    b[1] = subs.length;
    b[7] = auth;
    subs.forEach((s, i) => d.setUint32(8 + i * 4, s, true));
    return b;
  };
  const owner = sid(5, [32, 544]);
  const group = sid(5, [18]);
  const everyone = sid(1, [0]);
  const ace = new Uint8Array(8 + everyone.length);
  const ad = new DataView(ace.buffer);
  ace[0] = 0; // ACCESS_ALLOWED
  ace[1] = 0x02; // container inherit
  ad.setUint16(2, ace.length, true);
  ad.setUint32(4, 0xf003f, true); // KEY_ALL_ACCESS
  ace.set(everyone, 8);
  const acl = new Uint8Array(8 + ace.length);
  const cd = new DataView(acl.buffer);
  acl[0] = 2;
  cd.setUint16(2, acl.length, true);
  cd.setUint16(4, 1, true);
  acl.set(ace, 8);
  const sd = new Uint8Array(20 + owner.length + group.length + acl.length);
  const d = new DataView(sd.buffer);
  sd[0] = 1;
  d.setUint16(2, 0x8004, true); // self-relative, DACL present
  d.setUint32(4, 20, true);
  d.setUint32(8, 20 + owner.length, true);
  d.setUint32(16, 20 + owner.length + group.length, true);
  sd.set(owner, 20);
  sd.set(group, 20 + owner.length);
  sd.set(acl, 20 + owner.length + group.length);
  return sd;
}
