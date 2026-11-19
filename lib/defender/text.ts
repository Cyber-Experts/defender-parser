// Text files: MPLog, MPDetection and MpCmdRun.log. Encoding detection and
// bounded line splitting (from PCA Parser). Everything here is bounded: the
// files come from machines under investigation and may be damaged or
// crafted.
//
// Defender writes its support logs as UTF-16LE (Dissect and Intrinsec read
// them as UTF-16 first, then UTF-8; Velociraptor's MPLog artifact as
// UTF-16LE) and MpCmdRun.log as UTF-16LE (Dissect). Copies get re-saved, so a
// BOM is honoured, UTF-16 without a BOM is recognised by its zero bytes, and
// 8-bit text is read as UTF-8 when it is valid UTF-8, else as windows-1252.

import type { LineEnding } from "./types";

export type Encoding = "utf-16le" | "utf-16be" | "utf-8" | "windows-1252" | "ascii";

/** MPLog files rotate in the tens of MB; anything past this is not read. */
export const MAX_TEXT_BYTES = 128 * 1024 * 1024;
/** Lines read per file. */
export const MAX_LINES = 2_000_000;
/** A longer line is cut to this many characters (and said so). */
export const MAX_LINE = 8192;
/** Lines not understood kept with their text (the rest are only counted). */
export const MAX_UNPARSED_KEPT = 200;

export interface Decoded {
  text: string;
  encoding: Encoding;
  bom: boolean;
  /** Bytes past MAX_TEXT_BYTES were not read. */
  cut: boolean;
}

const SAMPLE = 8192;

/** Share of 16-bit units whose high (LE: odd) byte is zero, and of those whose low byte is. */
function zeroProfile(b: Uint8Array): { odd: number; even: number } {
  const n = Math.min(b.length, SAMPLE) & ~1;
  if (n < 4) return { odd: 0, even: 0 };
  let odd = 0;
  let even = 0;
  for (let i = 0; i < n; i += 2) {
    if (b[i] === 0) even++;
    if (b[i + 1] === 0) odd++;
  }
  return { odd: odd / (n / 2), even: even / (n / 2) };
}

/** UTF-16 without a BOM: most text in these files is ASCII, so every other byte is zero. */
export function sniffUtf16(b: Uint8Array): "utf-16le" | "utf-16be" | null {
  const z = zeroProfile(b);
  if (z.odd >= 0.4 && z.even < 0.1) return "utf-16le";
  if (z.even >= 0.4 && z.odd < 0.1) return "utf-16be";
  return null;
}

function isAscii(b: Uint8Array): boolean {
  for (let i = 0; i < b.length; i++) if (b[i] >= 0x80) return false;
  return true;
}

const utf8Strict = new TextDecoder("utf-8", { fatal: true });

/** Bytes → text, with the encoding it was read as. Never throws. */
export function decodeText(input: Uint8Array): Decoded {
  const cut = input.length > MAX_TEXT_BYTES;
  const b = cut ? input.subarray(0, MAX_TEXT_BYTES) : input;
  const out = (text: string, encoding: Encoding, bom: boolean): Decoded => ({ text, encoding, bom, cut });
  if (b.length >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) return out(new TextDecoder("utf-8").decode(b.subarray(3)), "utf-8", true);
  if (b.length >= 2 && b[0] === 0xff && b[1] === 0xfe) return out(new TextDecoder("utf-16le").decode(b.subarray(2, b.length - ((b.length - 2) & 1))), "utf-16le", true);
  if (b.length >= 2 && b[0] === 0xfe && b[1] === 0xff) return out(new TextDecoder("utf-16be").decode(b.subarray(2, b.length - ((b.length - 2) & 1))), "utf-16be", true);
  const wide = sniffUtf16(b);
  // An odd byte at the end of UTF-16 is a cut file: dropped, not decoded as half a character.
  if (wide) return out(new TextDecoder(wide).decode(b.subarray(0, b.length & ~1)), wide, false);
  if (isAscii(b)) return out(new TextDecoder("utf-8").decode(b), "ascii", false);
  try {
    return out(utf8Strict.decode(b), "utf-8", false);
  } catch {
    return out(new TextDecoder("windows-1252").decode(b), "windows-1252", false);
  }
}

export interface Lines {
  /** Lines without their end-of-line characters; long ones are cut to MAX_LINE + 1 characters. */
  lines: string[];
  ending: LineEnding;
  /** More than MAX_LINES lines: the rest were not read. */
  more: boolean;
}

/** Split on CRLF, LF or CR, bounded in count; the last line counts only when it holds something. */
export function splitLines(text: string): Lines {
  const lines: string[] = [];
  let crlf = 0;
  let lf = 0;
  let cr = 0;
  let i = 0;
  const n = text.length;
  while (i < n) {
    if (lines.length >= MAX_LINES) return { lines, ending: ending(crlf, lf, cr), more: true };
    let j = i;
    while (j < n) {
      const c = text.charCodeAt(j);
      if (c === 10 || c === 13) break;
      j++;
    }
    lines.push(j - i > MAX_LINE ? text.slice(i, i + MAX_LINE + 1) : text.slice(i, j));
    if (j >= n) break;
    if (text.charCodeAt(j) === 13 && text.charCodeAt(j + 1) === 10) {
      crlf++;
      i = j + 2;
    } else {
      if (text.charCodeAt(j) === 10) lf++;
      else cr++;
      i = j + 1;
    }
  }
  return { lines, ending: ending(crlf, lf, cr), more: false };
}

function ending(crlf: number, lf: number, cr: number): LineEnding {
  const kinds = [crlf, lf, cr].filter((x) => x > 0).length;
  if (kinds === 0) return "none";
  if (kinds > 1) return "mixed";
  return crlf ? "crlf" : lf ? "lf" : "cr";
}

/** A value cut for display. */
export function clip(text: string, max = 300): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}
