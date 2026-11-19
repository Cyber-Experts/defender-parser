/**
 * Intake for single files, dropped folders and collections (KAPE and
 * Velociraptor zips, a `.zip` or `.tar.gz` of the Defender folders, a mounted
 * image dropped as a folder, files handed over by Disk Image Parser). In a
 * collection only Defender's quarantine, DetectionHistory and support logs,
 * the Defender event logs, MpCmdRun.log and the SOFTWARE hive are opened;
 * everything else is counted, not read (mpenginedb.db is listed as not
 * read). Loose files all go to the engine, which recognises them by name or
 * content. Adapted from PCA Parser's intake.
 */

import { listZip } from "./unzip";
import { gunzipToBlob, isTarHeader, listTar } from "./untar";
import { ENGINEDB_LOCATION, EVTX_LOCATION, HISTORY_LOCATION, MPCMDRUN_LOCATION, QUARANTINE_LOCATION, SOFTWARE_LOCATION, SUPPORT_LOG_LOCATION } from "@/lib/defender/paths";

export interface DroppedFile {
  /** Path as dropped (inside folders / archives), `/`-separated. */
  path: string;
  file: File;
}

/** A file known only by a way to read its bytes (loose file or archive entry). */
interface Candidate {
  path: string;
  size: number;
  head(bytes: number): Promise<Uint8Array>;
  file(): Promise<File>;
  /** The modification time is a ZIP's DOS field (local time, zone unknown). */
  mtimeApprox?: boolean;
}

export type SkipCode = "empty" | "zipError" | "tarError" | "readError" | "tooLarge" | "notRead";

export interface SkipReason {
  path: string;
  code: SkipCode;
  /** Interpolation values for the message. */
  params?: Record<string, string>;
}

/** What the engine is given: a Defender file or the SOFTWARE hive. */
export type ArtifactKind = "defender" | "hive";

export interface Artifact {
  path: string;
  /** File.lastModified carries the mtime when known (0: unknown). */
  file: File;
  kind: ArtifactKind;
  /** The mtime is a ZIP's DOS field: the collecting machine's local time. */
  mtimeApprox?: boolean;
}

export interface Collected {
  artifacts: Artifact[];
  skipped: SkipReason[];
  /** Unrelated files in a collection: counted only. */
  ignored: number;
}

export interface CollectProgress {
  phase: "unpacking" | "scanning";
  done: number;
  total: number;
}

const HEAD = 512;
const MAX_ARCHIVE_DEPTH = 3;
/** SOFTWARE hives reach a few hundred MB on real machines; past 1 GiB it is not one (browser memory). The readers bound each kind further. */
export const MAX_FILE = 1024 * 1024 * 1024;

const baseName = (path: string) => path.slice(path.lastIndexOf("/") + 1);

/** What a path is to the engine, "noted" for a Defender file listed but not read, or null when it is not opened in a collection. */
export function wantedInCollection(path: string): ArtifactKind | "zip" | "tar" | "noted" | null {
  const lower = path.toLowerCase().replace(/\\/g, "/");
  const name = baseName(lower);
  if (name.endsWith(".zip")) return "zip";
  if (/\.(tar|tar\.gz|tgz)$/.test(name)) return "tar";
  if (QUARANTINE_LOCATION.test(lower) || HISTORY_LOCATION.test(lower) || SUPPORT_LOG_LOCATION.test(lower) || EVTX_LOCATION.test(lower) || MPCMDRUN_LOCATION.test(lower)) return "defender";
  if (SOFTWARE_LOCATION.test(lower)) return "hive";
  if (ENGINEDB_LOCATION.test(lower)) return "noted";
  // Defender files collected out of their folders.
  // An exported log named after Defender (wevtutil epl … Defender-Operational.evtx).
  if (/^(?:mplog|mpdetection)-[^/]*\.log$/.test(name) || /^mpcmdrun\.log/.test(name) || /defender[^/]*\.evtx$/.test(name)) return "defender";
  return null;
}

/** ZIP local-file-header signature "PK\x03\x04". */
export function startsWithZipMagic(head: Uint8Array): boolean {
  return head.length >= 4 && head[0] === 0x50 && head[1] === 0x4b && head[2] === 0x03 && head[3] === 0x04;
}

export function startsWithGzip(head: Uint8Array): boolean {
  return head.length >= 3 && head[0] === 0x1f && head[1] === 0x8b && head[2] === 0x08;
}

function looseCandidate(f: DroppedFile): Candidate {
  return {
    path: f.path,
    size: f.file.size,
    head: async (n) => new Uint8Array(await f.file.slice(0, n).arrayBuffer()),
    file: async () => f.file,
  };
}

async function expandArchive(c: Candidate, kind: "zip" | "tar" | "tgz"): Promise<Candidate[]> {
  if (kind === "zip") {
    const entries = await listZip(await c.file());
    return entries.map((e) => ({ path: `${c.path}/${e.path}`, size: e.size, head: e.head, file: e.file, ...(e.mtimeApprox ? { mtimeApprox: true } : {}) }));
  }
  const blob = kind === "tgz" ? await gunzipToBlob(await c.file()) : await c.file();
  // Symlinks carry nothing Defender-related: only regular files are kept.
  const entries = (await listTar(blob)).filter((e) => e.link === undefined);
  return entries.map((e) => ({ path: `${c.path}/${e.path}`, size: e.size, head: e.head, file: e.file }));
}

/**
 * Expand archives and classify everything that was dropped. Loose files go
 * to the engine (it says what it cannot recognise); inside folders and
 * archives, only the locations above are opened.
 */
export async function collect(dropped: DroppedFile[], onProgress?: (p: CollectProgress) => void): Promise<Collected> {
  const skipped: SkipReason[] = [];
  let ignored = 0;
  const inCollection = dropped.length > 12 || dropped.some((f) => f.path.includes("/"));

  // 1. Flatten: loose files + archive entries (recursively, bounded depth).
  const candidates: { c: Candidate; inCollection: boolean }[] = [];
  const pending: { c: Candidate; depth: number; inCollection: boolean }[] = dropped.map((f) => ({ c: looseCandidate(f), depth: 0, inCollection }));
  let unpacked = 0;
  while (pending.length > 0) {
    const { c, depth, inCollection: ic } = pending.shift()!;
    const name = baseName(c.path).toLowerCase();
    let archive: "zip" | "tar" | "tgz" | null = null;
    if (depth < MAX_ARCHIVE_DEPTH && c.size >= 22) {
      const head = await c.head(HEAD);
      const namedArchive = depth === 0 || /\.(zip|tar|tgz|tar\.gz)$/.test(name);
      if (namedArchive && startsWithZipMagic(head)) archive = "zip";
      else if (namedArchive && /\.(tgz|tar\.gz)$/.test(name) && startsWithGzip(head)) archive = "tgz";
      else if (namedArchive && (name.endsWith(".tar") || depth === 0) && isTarHeader(head)) archive = "tar";
    }
    if (!archive) {
      candidates.push({ c, inCollection: ic });
      continue;
    }
    onProgress?.({ phase: "unpacking", done: unpacked++, total: unpacked + pending.length });
    try {
      for (const e of await expandArchive(c, archive)) pending.push({ c: e, depth: depth + 1, inCollection: true });
    } catch (err) {
      skipped.push({ path: c.path, code: archive === "zip" ? "zipError" : "tarError", params: { error: errorText(err) } });
    }
  }

  // 2. Classify: in a collection only the locations above are opened.
  const artifacts: Artifact[] = [];
  let done = 0;
  for (const { c, inCollection: ic } of candidates) {
    onProgress?.({ phase: "scanning", done: done++, total: candidates.length });
    const wanted = wantedInCollection(c.path);
    if (wanted === "noted") {
      skipped.push({ path: c.path, code: "notRead", params: { size: `${Math.round(c.size / 1_048_576)} MB` } });
      continue;
    }
    const kind: ArtifactKind | null = wanted === "zip" || wanted === "tar" ? null : wanted;
    if (ic && kind === null) {
      ignored++;
      continue;
    }
    if (c.size > MAX_FILE) {
      skipped.push({ path: c.path, code: "tooLarge", params: { size: `${Math.round(c.size / 1_048_576)} MB` } });
      continue;
    }
    if (c.size === 0) {
      skipped.push({ path: c.path, code: "empty" });
      continue;
    }
    try {
      artifacts.push({ path: c.path, file: await c.file(), kind: kind ?? "defender", ...(c.mtimeApprox ? { mtimeApprox: true } : {}) });
    } catch (err) {
      skipped.push({ path: c.path, code: "readError", params: { error: errorText(err) } });
    }
  }
  onProgress?.({ phase: "scanning", done: candidates.length, total: candidates.length });
  artifacts.sort((a, b) => a.path.localeCompare(b.path));
  return { artifacts, skipped, ignored };
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// ---------------------------------------------------------------------------
// Reading drops and <input> selections
// ---------------------------------------------------------------------------

function readAllEntries(dir: FileSystemDirectoryEntry): Promise<FileSystemEntry[]> {
  const reader = dir.createReader();
  const all: FileSystemEntry[] = [];
  return new Promise((resolve, reject) => {
    // readEntries returns results in batches (≈100 in Chromium) until empty.
    const next = () =>
      reader.readEntries((batch) => {
        if (batch.length === 0) return resolve(all);
        all.push(...batch);
        next();
      }, reject);
    next();
  });
}

async function walk(entry: FileSystemEntry, out: DroppedFile[]): Promise<void> {
  if (entry.isFile) {
    const file = await new Promise<File>((resolve, reject) => (entry as FileSystemFileEntry).file(resolve, reject));
    out.push({ path: entry.fullPath.replace(/^\/+/, ""), file });
  } else if (entry.isDirectory) {
    for (const child of await readAllEntries(entry as FileSystemDirectoryEntry)) await walk(child, out);
  }
}

/**
 * Every file from a drop, descending into dropped folders. Must be called
 * synchronously from the `drop` handler: DataTransfer items are only
 * readable until the handler returns.
 */
export function filesFromDataTransfer(dt: DataTransfer): Promise<DroppedFile[]> {
  const entries = Array.from(dt.items)
    .filter((item) => item.kind === "file")
    .map((item) => item.webkitGetAsEntry?.() ?? null);
  if (entries.length === 0 || entries.some((e) => e === null)) {
    return Promise.resolve(Array.from(dt.files).map((file) => ({ path: file.name, file })));
  }
  return (async () => {
    const out: DroppedFile[] = [];
    for (const entry of entries) await walk(entry!, out);
    return out;
  })();
}

/** Files from an `<input type="file">`, with or without `webkitdirectory`. */
export function filesFromInput(files: FileList): DroppedFile[] {
  return Array.from(files).map((file) => ({ path: file.webkitRelativePath || file.name, file }));
}
