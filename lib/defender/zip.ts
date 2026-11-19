// A ZIP writer: STORE entries with Info-ZIP UTC times (the sample, as PCA
// Parser and Windows Persistence write theirs) and, for recovered quarantine
// files, traditional PKWARE encryption ("ZipCrypto", APPNOTE.TXT section
// 6.1), the format malware exchanges use with the password "infected" and
// that unzip, 7-Zip and every archive tool open. ZipCrypto is weak: it keeps
// the file from being opened, scanned or run by accident, not from anyone
// who wants it. Written here, no dependency.

import { crc32, crcTable } from "./hash";

export interface ZipItem {
  path: string;
  bytes: Uint8Array;
  /** ms since the epoch. */
  mtime: number;
}

const cat = (parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};

/** The ZipCrypto cipher state (APPNOTE 6.1.5). */
class ZipCrypto {
  private k0 = 0x12345678;
  private k1 = 0x23456789;
  private k2 = 0x34567890;
  constructor(password: string) {
    for (const b of new TextEncoder().encode(password)) this.update(b);
  }
  private update(b: number) {
    this.k0 = (crcTable[(this.k0 ^ b) & 0xff] ^ (this.k0 >>> 8)) >>> 0;
    this.k1 = (Math.imul((this.k1 + (this.k0 & 0xff)) >>> 0, 134775813) + 1) >>> 0;
    this.k2 = (crcTable[(this.k2 ^ (this.k1 >>> 24)) & 0xff] ^ (this.k2 >>> 8)) >>> 0;
  }
  private stream(): number {
    const t = (this.k2 | 2) & 0xffff;
    return (Math.imul(t, t ^ 1) >>> 8) & 0xff;
  }
  encrypt(data: Uint8Array): Uint8Array {
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      out[i] = data[i] ^ this.stream();
      this.update(data[i]);
    }
    return out;
  }
}

/** Random bytes from the platform (crypto.getRandomValues). */
const randomBytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));

/**
 * A ZIP of STORE entries; encrypted with ZipCrypto when a password is given.
 * `random` supplies the 11 random bytes of each encryption header (tests).
 */
export function writeZip(items: ZipItem[], opts: { password?: string; random?: (n: number) => Uint8Array } = {}): Uint8Array {
  const parts: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  const dos = (ms: number) => {
    const d = new Date(Math.max(ms, Date.UTC(1980, 0, 1)));
    return {
      time: (d.getUTCHours() << 11) | (d.getUTCMinutes() << 5) | (d.getUTCSeconds() >> 1),
      date: ((d.getUTCFullYear() - 1980) << 9) | ((d.getUTCMonth() + 1) << 5) | d.getUTCDate(),
    };
  };
  const encrypted = opts.password !== undefined;
  for (const f of items) {
    const name = new TextEncoder().encode(f.path);
    const crc = crc32(f.bytes);
    const { time, date } = dos(f.mtime);
    let body = f.bytes;
    if (encrypted) {
      const zc = new ZipCrypto(opts.password!);
      const head = new Uint8Array(12);
      head.set((opts.random ?? randomBytes)(11).subarray(0, 11), 0);
      // The last header byte is the CRC's high byte: readers check it against the password.
      head[11] = crc >>> 24;
      body = cat([zc.encrypt(head), zc.encrypt(f.bytes)]);
    }
    const flags = 0x0800 | (encrypted ? 0x0001 : 0);
    const ext = new Uint8Array(9);
    const ev = new DataView(ext.buffer);
    ev.setUint16(0, 0x5455, true);
    ev.setUint16(2, 5, true);
    ext[4] = 1;
    ev.setUint32(5, Math.max(0, Math.floor(f.mtime / 1000)), true);
    const local = new Uint8Array(30 + name.length + ext.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, encrypted ? 20 : 10, true);
    lv.setUint16(6, flags, true);
    lv.setUint16(8, 0, true); // STORE
    lv.setUint16(10, time, true);
    lv.setUint16(12, date, true);
    lv.setUint32(14, crc, true);
    lv.setUint32(18, body.length, true);
    lv.setUint32(22, f.bytes.length, true);
    lv.setUint16(26, name.length, true);
    lv.setUint16(28, ext.length, true);
    local.set(name, 30);
    local.set(ext, 30 + name.length);
    const cd = new Uint8Array(46 + name.length + ext.length);
    const cv = new DataView(cd.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 0x031e, true);
    cv.setUint16(6, encrypted ? 20 : 10, true);
    cv.setUint16(8, flags, true);
    cv.setUint16(10, 0, true);
    cv.setUint16(12, time, true);
    cv.setUint16(14, date, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, body.length, true);
    cv.setUint32(24, f.bytes.length, true);
    cv.setUint16(28, name.length, true);
    cv.setUint16(30, ext.length, true);
    cv.setUint32(38, 0o100644 << 16, true);
    cv.setUint32(42, offset, true);
    cd.set(name, 46);
    cd.set(ext, 46 + name.length);
    parts.push(local, body);
    central.push(cd);
    offset += local.length + body.length;
  }
  const cdSize = central.reduce((n, c) => n + c.length, 0);
  const end = new Uint8Array(22);
  const env = new DataView(end.buffer);
  env.setUint32(0, 0x06054b50, true);
  env.setUint16(8, items.length, true);
  env.setUint16(10, items.length, true);
  env.setUint32(12, cdSize, true);
  env.setUint32(16, offset, true);
  return cat([...parts, ...central, end]);
}
