// Small Windows binary helpers shared by the decoders: GUIDs, SIDs,
// FILETIME and SYSTEMTIME, bounded little-endian reads.

import { filetime } from "./regf";

export const u16 = (b: Uint8Array, o: number): number | undefined => (o >= 0 && o + 2 <= b.length ? b[o] | (b[o + 1] << 8) : undefined);
export const u32 = (b: Uint8Array, o: number): number | undefined =>
  o >= 0 && o + 4 <= b.length ? (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0 : undefined;

/** FILETIME at `o` → ms since the epoch. */
export function filetimeAt(b: Uint8Array, o: number): number | null {
  const lo = u32(b, o);
  const hi = u32(b, o + 4);
  return lo === undefined || hi === undefined ? null : filetime(lo, hi);
}

/** SYSTEMTIME (16 bytes) at `o` → ms since the epoch (as UTC; .job files store local time). */
export function systemtimeAt(b: Uint8Array, o: number): number | null {
  const y = u16(b, o);
  if (!y || y < 1601 || y > 2200) return null;
  const mo = u16(b, o + 2)!;
  const d = u16(b, o + 6)!;
  const h = u16(b, o + 8)!;
  const mi = u16(b, o + 10)!;
  const s = u16(b, o + 12)!;
  const ms = u16(b, o + 14)!;
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 59) return null;
  return Date.UTC(y, mo - 1, d, h, mi, s, ms);
}

/** Mixed-endian GUID → "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}". */
export function guidString(b: Uint8Array, o = 0): string | undefined {
  if (o + 16 > b.length) return undefined;
  const h = (i: number) => b[o + i].toString(16).padStart(2, "0");
  const g = `${h(3)}${h(2)}${h(1)}${h(0)}-${h(5)}${h(4)}-${h(7)}${h(6)}-${h(8)}${h(9)}-${h(10)}${h(11)}${h(12)}${h(13)}${h(14)}${h(15)}`;
  return `{${g.toUpperCase()}}`;
}

/** Binary SID → "S-1-5-21-…" and its byte length. */
export function sidString(b: Uint8Array, o = 0): { sid: string; length: number } | undefined {
  if (o + 8 > b.length || b[o] !== 1) return undefined;
  const n = b[o + 1];
  const length = 8 + n * 4;
  if (n > 15 || o + length > b.length) return undefined;
  let auth = 0;
  for (let i = 2; i < 8; i++) auth = auth * 256 + b[o + i];
  const subs: number[] = [];
  for (let i = 0; i < n; i++) subs.push(u32(b, o + 8 + i * 4)!);
  return { sid: `S-1-${auth}${subs.map((s) => `-${s}`).join("")}`, length };
}

/** Binary SID from "S-1-5-…" (for the sample and tests). */
export function sidBytes(sid: string): Uint8Array {
  const parts = sid.split("-").slice(1).map(Number);
  const subs = parts.slice(2);
  const out = new Uint8Array(8 + subs.length * 4);
  const dv = new DataView(out.buffer);
  out[0] = parts[0];
  out[1] = subs.length;
  dv.setUint16(2, 0);
  dv.setUint32(4, parts[1]);
  subs.forEach((s, i) => dv.setUint32(8 + i * 4, s >>> 0, true));
  return out;
}

/** "{GUID}" → 16 mixed-endian bytes (for the sample and tests). */
export function guidBytes(g: string): Uint8Array {
  const h = g.replace(/[{}-]/g, "");
  const x = (i: number) => parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return Uint8Array.from([x(3), x(2), x(1), x(0), x(5), x(4), x(7), x(6), x(8), x(9), x(10), x(11), x(12), x(13), x(14), x(15)]);
}

/** UTF-16LE text up to the first NUL, from `o` for `n` bytes. */
export function utf16At(b: Uint8Array, o: number, n: number): string {
  const len = Math.max(0, Math.min(n, b.length - o)) & ~1;
  const s = new TextDecoder("utf-16le").decode(b.subarray(o, o + len));
  const nul = s.indexOf("\0");
  return nul === -1 ? s : s.slice(0, nul);
}

/** Windows-1252 text up to the first NUL. */
export function ansiz(b: Uint8Array, o: number, max = 4096): string {
  let e = o;
  while (e < b.length && e < o + max && b[e] !== 0) e++;
  return new TextDecoder("windows-1252").decode(b.subarray(o, e));
}
