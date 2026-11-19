/**
 * Minimal in-browser tar reader, so UAC collections (`uac-<host>-linux-
 * <date>.tar.gz` by default) and hand-made `tar czf` archives of /var/log
 * can be dropped as-is. Handles ustar, GNU long names (`L`), pax headers
 * (`x` / `g`: path, size, mtime, linkpath), GNU long link targets (`K`),
 * base-256 sizes and symlinks, reported with their target and mtime: a
 * systemd `*.wants/` link records when a unit was enabled, `rc?.d/S*` links
 * what starts at boot, `.bash_history → /dev/null` an anti-forensic step.
 * `.tar.gz` / `.tgz` are inflated with the native DecompressionStream.
 */

export interface TarEntry {
  path: string;
  size: number;
  mtime: number | null;
  /** Symlink target (type 2), when the entry is a link. */
  link?: string;
  head(bytes: number): Promise<Uint8Array>;
  file(): Promise<File>;
}

const BLOCK = 512;

function cstr(b: Uint8Array, off: number, len: number): string {
  let end = off;
  while (end < off + len && b[end] !== 0) end++;
  return new TextDecoder("utf-8").decode(b.subarray(off, end));
}

function octal(b: Uint8Array, off: number, len: number): number {
  // Base-256 (GNU) for large values: high bit of the first byte set.
  if (b[off] & 0x80) {
    let v = b[off] & 0x7f;
    for (let i = 1; i < len; i++) v = v * 256 + b[off + i];
    return v;
  }
  const s = cstr(b, off, len).trim();
  return s ? parseInt(s, 8) : 0;
}

/** True if `b` (≥ 512 bytes) is a tar header block (ustar magic, or a valid checksum). */
export function isTarHeader(b: Uint8Array): boolean {
  if (b.length < BLOCK) return false;
  if (cstr(b, 257, 5) === "ustar") return true;
  const stored = octal(b, 148, 8);
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 32 : b[i];
  return stored > 0 && stored === sum && b[0] !== 0;
}

function parsePax(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  let i = 0;
  while (i < text.length) {
    const sp = text.indexOf(" ", i);
    if (sp < 0) break;
    const len = Number(text.slice(i, sp));
    if (!Number.isFinite(len) || len <= 0) break;
    const rec = text.slice(sp + 1, i + len - 1);
    const eq = rec.indexOf("=");
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    i += len;
  }
  return out;
}

export async function gunzipToBlob(blob: Blob): Promise<Blob> {
  const stream = blob.stream().pipeThrough(new DecompressionStream("gzip"));
  return new Response(stream).blob();
}

/** List the regular files (and symlinks) of a tar archive. */
export async function listTar(blob: Blob): Promise<TarEntry[]> {
  const out: TarEntry[] = [];
  let off = 0;
  let longName: string | null = null;
  let longLink: string | null = null;
  let pax: Record<string, string> = {};
  let globalPax: Record<string, string> = {};
  while (off + BLOCK <= blob.size) {
    const h = new Uint8Array(await blob.slice(off, off + BLOCK).arrayBuffer());
    if (h.every((x) => x === 0)) break; // end-of-archive marker
    if (!isTarHeader(h)) throw new Error(`damaged tar header at offset ${off}`);
    const type = String.fromCharCode(h[156] || 48);
    let size = octal(h, 124, 12);
    const data = off + BLOCK;
    if (type === "L" || type === "K" || type === "x" || type === "g") {
      const next = data + Math.ceil(size / BLOCK) * BLOCK;
      const text = new TextDecoder("utf-8").decode(new Uint8Array(await blob.slice(data, data + size).arrayBuffer()));
      if (type === "L") longName = text.replace(/\0+$/, "");
      else if (type === "K") longLink = text.replace(/\0+$/, "");
      else if (type === "x") pax = parsePax(text);
      else globalPax = { ...globalPax, ...parsePax(text) };
      off = next;
      continue;
    }
    const prefix = cstr(h, 345, 155);
    let path = longName ?? pax.path ?? (prefix ? `${prefix}/${cstr(h, 0, 100)}` : cstr(h, 0, 100));
    if (pax.size) size = Number(pax.size);
    const mtimeS = pax.mtime ? Number(pax.mtime) : globalPax.mtime ? Number(globalPax.mtime) : octal(h, 136, 12);
    path = path.replace(/^\.?\/+/, "").replace(/\\/g, "/");
    const start = data;
    const end = data + size;
    const mtime = Number.isFinite(mtimeS) && mtimeS > 0 ? mtimeS * 1000 : null;
    if ((type === "0" || type === "\0" || type === "7") && !path.endsWith("/")) {
      const name = path.slice(path.lastIndexOf("/") + 1);
      out.push({
        path,
        size,
        mtime,
        head: async (n) => new Uint8Array(await blob.slice(start, Math.min(end, start + n)).arrayBuffer()),
        file: async () => new File([blob.slice(start, end)], name, { lastModified: mtime ?? 0 }),
      });
    } else if (type === "2") {
      const link = longLink ?? pax.linkpath ?? cstr(h, 157, 100);
      const name = path.slice(path.lastIndexOf("/") + 1);
      out.push({ path, size: 0, mtime, link, head: async () => new Uint8Array(), file: async () => new File([], name, { lastModified: mtime ?? 0 }) });
    }
    longName = null;
    longLink = null;
    pax = {};
    off = data + Math.ceil(size / BLOCK) * BLOCK;
  }
  return out;
}
