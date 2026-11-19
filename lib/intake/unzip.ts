/**
 * Minimal in-browser ZIP reader, so triage collections (KAPE, Velociraptor,
 * a zipped C:\Windows\System32\config folder, …) can be dropped as-is. Ported from
 * recyclebin-parser (src/lib/unzip.ts).
 *
 * Reads the central directory (ZIP64 aware), then extracts each entry:
 * STORE entries are zero-copy `Blob.slice`s, DEFLATE entries are inflated with
 * the native `DecompressionStream`. Works in browsers and Node 18+.
 */
export interface ZipEntryFile {
  /** Path inside the archive, `/`-separated. */
  path: string;
  file: File;
}

/**
 * A lazily-extracted entry: `head()` inflates only the first bytes (enough
 * to sniff a file header), `file()` extracts the whole entry. A KAPE
 * collection holds thousands of files; only the SYSTEM / SOFTWARE hives get inflated.
 */
export interface ZipEntry {
  path: string;
  /** Uncompressed size. */
  size: number;
  /**
   * The modification time is the DOS field only: the collecting machine's
   * local time, read here in the browser's zone (no UTC extra field).
   */
  mtimeApprox: boolean;
  head(bytes: number): Promise<Uint8Array>;
  file(): Promise<File>;
}

const ZIP_MAGIC = 0x04034b50;
const EOCD_SIG = 0x06054b50;
const ZIP64_LOCATOR_SIG = 0x07064b50;
const ZIP64_EOCD_SIG = 0x06064b50;
const CD_SIG = 0x02014b50;

async function view(blob: Blob, start: number, end: number): Promise<DataView> {
  return new DataView(await blob.slice(start, end).arrayBuffer());
}

function u64(v: DataView, off: number): number {
  return Number(v.getBigUint64(off, true));
}

/** True if the blob starts with a ZIP local-file-header signature. */
export async function isZip(blob: Blob): Promise<boolean> {
  if (blob.size < 22) return false;
  const v = await view(blob, 0, 4);
  return v.getUint32(0, true) === ZIP_MAGIC;
}

/** `undefined` when the archive left the date blank (e.g. FTK Imager exports). */
function dosToUnixMs(time: number, date: number): number | undefined {
  if (date === 0) return undefined;
  return new Date(
    ((date >> 9) & 0x7f) + 1980,
    ((date >> 5) & 0x0f) - 1,
    date & 0x1f,
    (time >> 11) & 0x1f,
    (time >> 5) & 0x3f,
    (time & 0x1f) * 2,
  ).getTime();
}

/**
 * Velociraptor (and some other collectors) percent-encode characters such as
 * `:` in archive paths (`C%3A/$Recycle.Bin/…`). Decode segments that look
 * encoded, leaving anything that isn't valid percent-encoding untouched.
 */
function decodeSegment(seg: string): string {
  if (!/%[0-9A-Fa-f]{2}/.test(seg)) return seg;
  try {
    return decodeURIComponent(seg);
  } catch {
    return seg;
  }
}

/** Turn `\`-separated ZIP entry names (Compress-Archive on PowerShell 5.1) into `/`-separated ones. */
export function normalizeSeparators(name: string): string {
  return name.replace(/\\/g, "/");
}

const METHOD_NAMES: Record<number, string> = {
  9: "Deflate64",
  12: "BZIP2",
  14: "LZMA",
  93: "Zstandard",
  95: "XZ",
  99: "AES encryption",
};

export async function listZip(blob: Blob): Promise<ZipEntry[]> {
  // The End Of Central Directory record sits in the last 22 + (≤ 65 535 comment) bytes.
  const tailStart = Math.max(0, blob.size - 22 - 0xffff);
  const tail = await view(blob, tailStart, blob.size);
  let eocd = -1;
  for (let i = tail.byteLength - 22; i >= 0; i--) {
    if (tail.getUint32(i, true) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("not a valid ZIP archive (end of central directory not found)");

  let count = tail.getUint16(eocd + 10, true);
  let cdSize = tail.getUint32(eocd + 12, true);
  let cdOffset = tail.getUint32(eocd + 16, true);

  if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    const loc = eocd - 20;
    if (loc < 0 || tail.getUint32(loc, true) !== ZIP64_LOCATOR_SIG) {
      throw new Error("ZIP64 archive is missing its locator record");
    }
    const z64Offset = u64(tail, loc + 8);
    const z64 = await view(blob, z64Offset, z64Offset + 56);
    if (z64.getUint32(0, true) !== ZIP64_EOCD_SIG) {
      throw new Error("ZIP64 end of central directory record is corrupt");
    }
    count = u64(z64, 32);
    cdSize = u64(z64, 40);
    cdOffset = u64(z64, 48);
  }

  const cd = await view(blob, cdOffset, cdOffset + cdSize);
  const utf8 = new TextDecoder("utf-8");
  const out: ZipEntry[] = [];
  let p = 0;

  for (let n = 0; n < count; n++) {
    if (cd.getUint32(p, true) !== CD_SIG) throw new Error("ZIP central directory is corrupt");
    const flags = cd.getUint16(p + 8, true);
    const method = cd.getUint16(p + 10, true);
    const time = cd.getUint16(p + 12, true);
    const date = cd.getUint16(p + 14, true);
    let csize = cd.getUint32(p + 20, true);
    let usize = cd.getUint32(p + 24, true);
    const nameLen = cd.getUint16(p + 28, true);
    const extraLen = cd.getUint16(p + 30, true);
    const commentLen = cd.getUint16(p + 32, true);
    let localOffset = cd.getUint32(p + 42, true);
    let name = utf8.decode(new Uint8Array(cd.buffer, p + 46, nameLen));
    let mtime = dosToUnixMs(time, date);
    let approx = mtime !== undefined;

    // Extra fields: ZIP64 sizes/offset, Info-ZIP UTC mtime, Unicode path.
    let e = p + 46 + nameLen;
    const extraEnd = e + extraLen;
    while (e + 4 <= extraEnd) {
      const id = cd.getUint16(e, true);
      const size = cd.getUint16(e + 2, true);
      const d = e + 4;
      if (id === 0x0001) {
        let q = d;
        if (usize === 0xffffffff) {
          usize = u64(cd, q);
          q += 8;
        }
        if (csize === 0xffffffff) {
          csize = u64(cd, q);
          q += 8;
        }
        if (localOffset === 0xffffffff) localOffset = u64(cd, q);
      } else if (id === 0x5455 && size >= 5 && cd.getUint8(d) & 1) {
        mtime = cd.getUint32(d + 1, true) * 1000;
        approx = false;
      } else if (id === 0x7075 && size > 5) {
        name = utf8.decode(new Uint8Array(cd.buffer, d + 5, size - 5));
      }
      e = d + size;
    }
    p = extraEnd + commentLen;

    // Windows PowerShell 5.1's Compress-Archive writes `\` as the separator
    // (`Users\alice\AppData\…`). A backslash is never part of a Windows file
    // name, so treating every `\` as a separator is safe.
    name = normalizeSeparators(name);

    if (name.endsWith("/")) continue; // directory entry

    if (flags & 1) {
      throw new Error(
        "this ZIP is password-protected — extract it first, then drop the folder",
      );
    }
    const path = name.split("/").filter(Boolean).map(decodeSegment).join("/");
    if (method !== 0 && method !== 8) {
      // One exotic entry shouldn't sink the whole collection.
      const err = new Error(
        `uses unsupported ZIP compression (${METHOD_NAMES[method] ?? `method ${method}`}) — extract the ZIP first, then drop the folder`,
      );
      out.push({ path, size: usize, mtimeApprox: false, head: () => Promise.reject(err), file: () => Promise.reject(err) });
      continue;
    }

    const base = path.slice(path.lastIndexOf("/") + 1);
    const entryOffset = localOffset;
    const entryCsize = csize;
    const entryUsize = usize;
    const entryMethod = method;
    // No time at all: 0, which the reader takes as "unknown" (a File would otherwise take the current time).
    const entryMtime = mtime ?? 0;
    const entryApprox = approx;
    let start: Promise<number> | null = null;
    const dataStart = () =>
      (start ??= view(blob, entryOffset, entryOffset + 30).then(
        (lh) => entryOffset + 30 + lh.getUint16(26, true) + lh.getUint16(28, true),
      ));
    const raw = async () => {
      const s0 = await dataStart();
      return blob.slice(s0, s0 + entryCsize);
    };

    out.push({
      path,
      size: entryUsize,
      mtimeApprox: entryApprox,
      async head(bytes: number) {
        const r = await raw();
        if (entryMethod === 0) return new Uint8Array(await r.slice(0, bytes).arrayBuffer());
        const reader = r.stream().pipeThrough(new DecompressionStream("deflate-raw")).getReader();
        const chunks: Uint8Array[] = [];
        let got = 0;
        try {
          while (got < bytes) {
            const { value, done } = await reader.read();
            if (done || !value) break;
            chunks.push(value);
            got += value.length;
          }
        } finally {
          reader.cancel().catch(() => {});
        }
        const outBuf = new Uint8Array(Math.min(got, bytes));
        let p2 = 0;
        for (const c of chunks) {
          const take = Math.min(c.length, outBuf.length - p2);
          outBuf.set(c.subarray(0, take), p2);
          p2 += take;
          if (p2 >= outBuf.length) break;
        }
        return outBuf;
      },
      async file() {
        const r = await raw();
        const data =
          entryMethod === 0
            ? r
            : await new Response(r.stream().pipeThrough(new DecompressionStream("deflate-raw"))).blob();
        if (data.size !== entryUsize) {
          throw new Error(`"${name}" is corrupt (expected ${entryUsize} bytes, got ${data.size})`);
        }
        return new File([data], base, { lastModified: entryMtime });
      },
    });
  }

  return out;
}

/** Extract every entry (small archives / tests). */
export async function readZip(blob: Blob): Promise<ZipEntryFile[]> {
  const entries = await listZip(blob);
  return Promise.all(entries.map(async (e) => ({ path: e.path, file: await e.file() })));
}
