// The only way a quarantined file leaves the page: a ZIP encrypted with the
// password "infected", built in the browser on an explicit click. It holds
// the file's data stream, each alternate data stream (Zone.Identifier…) and a
// text file describing where it came from. The bytes are never rendered,
// never kept in the analysis, never offered raw.

import { hashes } from "./hash";
import { recoverFileData } from "./quarantine";
import { writeZip, type ZipItem } from "./zip";

export const RECOVERY_PASSWORD = "infected";

export interface RecoveryMeta {
  host: string;
  /** The quarantined file's path as Defender recorded it. */
  path: string;
  threatName?: string;
  /** When it was quarantined, ms UTC. */
  quarantined?: number | null;
  /** Its last write time, ms UTC (the entry's), used as the ZIP entries' time. */
  written?: number | null;
  resourceData: string;
}

/** A file name safe on every system: the original's, with anything odd replaced. */
export function safeName(path: string): string {
  const base = path.replace(/\//g, "\\").split("\\").pop() || "file";
  const s = base.replace(/[\x00-\x1f<>:"|?*‪-‮⁦-⁩]/g, "_").replace(/^\.+/, "_").slice(0, 120);
  return s || "file";
}

export interface Recovery {
  zip: Uint8Array;
  /** Suggested download name. */
  name: string;
  sha256: string;
  size: number;
}

/** The encrypted ZIP for one ResourceData file, or null when it holds no recoverable file (a hive, a sparse file). */
export function buildRecoveryZip(resourceData: Uint8Array, meta: RecoveryMeta, random?: (n: number) => Uint8Array): Recovery | null {
  const r = recoverFileData(resourceData);
  if (!r) return null;
  const h = hashes(r.data);
  const name = safeName(meta.path);
  const mtime = meta.written ?? meta.quarantined ?? Date.UTC(1980, 0, 1);
  const iso = (t: number | null | undefined) => (t === null || t === undefined ? "unknown" : new Date(t).toISOString());
  const info = [
    "LIVE MALWARE. This archive holds a file Microsoft Defender quarantined.",
    "Open it only in an isolated analysis machine. Do not run it.",
    "",
    `Host:            ${meta.host}`,
    `Original path:   ${meta.path}`,
    `Threat:          ${meta.threatName ?? "unknown"}`,
    `Quarantined:     ${iso(meta.quarantined)} (UTC)`,
    `ResourceData:    ${meta.resourceData}`,
    `Size:            ${r.data.length} bytes`,
    `MD5:             ${h.md5}`,
    `SHA-1:           ${h.sha1}`,
    `SHA-256:         ${h.sha256}`,
    `Streams:         data${r.ads.map((a) => `, ${a.name}`).join("")}`,
    "",
    "Recovered by Defender Parser in the browser: RC4 with Defender's quarantine key, then the BackupRead streams.",
    "",
  ].join("\r\n");
  const items: ZipItem[] = [
    { path: name, bytes: r.data, mtime },
    ...r.ads.map((a) => ({ path: `${name}_${a.name.replace(/^:/, "").replace(/:\$DATA$/i, "").replace(/[^\w.-]+/g, "_") || "stream"}.ads`, bytes: a.data, mtime })),
    { path: "README.txt", bytes: new TextEncoder().encode(info), mtime },
  ];
  return { zip: writeZip(items, { password: RECOVERY_PASSWORD, random }), name: `${name}.${h.sha256.slice(0, 12)}.infected.zip`, sha256: h.sha256, size: r.data.length };
}
