// Where a collection file sat on Windows, and what it is. A triage
// collection nests the file system under a prefix (host folder, archive
// name, a drive folder "C/" or Velociraptor's "C%3A/"): the prefix is
// everything before the place a known location matches, and it names the
// host. Adapted from PCA Parser and Windows Persistence (lib/*/paths.ts).

import type { FileRole } from "./types";

const at = (s: string) => new RegExp(`(?:^|/)${s}$`);
const DEFENDER = String.raw`programdata/microsoft/windows defender`;

/** Quarantine\Entries, ResourceData, Resources. */
export const QUARANTINE_LOCATION = at(String.raw`${DEFENDER}/quarantine/(?:entries|resourcedata|resources)/[^/]+(?:/[^/]+)?`);
/** Scans\History\Service\DetectionHistory\<nn>\<GUID>. */
export const HISTORY_LOCATION = at(String.raw`${DEFENDER}/scans/history/service/detectionhistory/(?:[^/]+/)?[^/]+`);
/** Support\MPLog-*.log, MPDetection-*.log. */
export const SUPPORT_LOG_LOCATION = at(String.raw`${DEFENDER}/support/mp(?:log|detection)-[^/]*`);
/** The Defender event logs (Operational, and the other Defender channels). */
export const EVTX_LOCATION = at(String.raw`windows/system32/winevt/logs/microsoft-windows-windows defender%4[^/]+\.evtx`);
/** MpCmdRun.log in C:\Windows\Temp, a profile's Temp folder, or elsewhere. */
export const MPCMDRUN_LOCATION = at(String.raw`(?:windows/temp|(?:users|documents and settings)/[^/]+/appdata/local/temp|windows\.old/windows/temp|windows/serviceprofiles/[^/]+/appdata/local/temp|windows/microsoft antimalware/tmp)/mpcmdrun\.log[^/]*`);
/** The SOFTWARE hive. */
export const SOFTWARE_LOCATION = at(String.raw`windows/system32/config/software`);
/** Defender's SQLite database: noted, not read. */
export const ENGINEDB_LOCATION = at(String.raw`${DEFENDER}/scans/mpenginedb\.db`);

/** Any other file of Defender's folder: placed on its host, listed as not read. */
const DEFENDER_FOLDER = at(String.raw`${DEFENDER}/.+`);

const LOCATIONS = [QUARANTINE_LOCATION, HISTORY_LOCATION, SUPPORT_LOG_LOCATION, EVTX_LOCATION, MPCMDRUN_LOCATION, SOFTWARE_LOCATION, DEFENDER_FOLDER];

/** Profiles that are not one person's. */
export const NOT_A_USER = /^(?:public|default|default user|all users)$/i;

export interface Placed {
  root: string;
  sysPath: string;
  placed: boolean;
  drive?: string;
}

const DRIVE = /^(?:([a-z])(?::|%3a|\$)?|\\\\\.\\([a-z]):|volume\{[0-9a-f-]+\})$/i;

export function place(path: string): Placed {
  const clean = path.replace(/\\/g, "/").replace(/^\/+/, "");
  const lower = clean.toLowerCase();
  let best: number | null = null;
  for (const r of LOCATIONS) {
    const m = r.exec(lower);
    if (!m) continue;
    const start = m[0].startsWith("/") ? m.index + 1 : m.index;
    if (best === null || start < best) best = start;
  }
  if (best === null) return { root: "", sysPath: clean.slice(clean.lastIndexOf("/") + 1), placed: false };
  const prefix = clean.slice(0, best).replace(/\/+$/, "").split("/").filter(Boolean);
  let drive: string | undefined;
  const last = prefix[prefix.length - 1];
  const d = last ? DRIVE.exec(last) : null;
  if (d) {
    prefix.pop();
    if (d[1] || d[2]) drive = `${(d[1] ?? d[2]).toUpperCase()}:`;
  }
  return { root: prefix.join("/"), sysPath: `${drive ?? "C:"}\\${clean.slice(best).replace(/\//g, "\\")}`, placed: true, drive };
}

/** What a placed file is, from where it sat. */
export function roleOf(sysPath: string): FileRole | null {
  const p = sysPath.toLowerCase();
  if (/\\quarantine\\entries\\[^\\]+$/.test(p)) return "entry";
  if (/\\quarantine\\resourcedata\\[^\\]+\\[^\\]+$/.test(p)) return "resourcedata";
  if (/\\quarantine\\resources\\[^\\]+\\[^\\]+$/.test(p)) return "resources";
  if (/\\detectionhistory\\(?:[^\\]+\\)?[^\\]+$/.test(p)) return "history";
  if (/\\support\\mplog-[^\\]*$/.test(p)) return "mplog";
  if (/\\support\\mpdetection-[^\\]*$/.test(p)) return "mpdetection";
  if (/\\winevt\\logs\\microsoft-windows-windows defender%4[^\\]+\.evtx$/.test(p)) return "evtx";
  if (/\\mpcmdrun\.log[^\\]*$/.test(p)) return "mpcmdrun";
  if (/\\windows\\system32\\config\\software$/.test(p)) return "software";
  if (/\\windows defender\\/.test(p)) return "defender-other";
  return null;
}

/** The account a profile path belongs to: C:\Users\<name>\… (Public and Default are nobody's). */
export function userFromPath(sysPath: string): string | undefined {
  const m = /^[a-z]:\\(?:users|documents and settings)\\([^\\]+)\\/i.exec(sysPath);
  return m && !NOT_A_USER.test(m[1]) ? m[1] : undefined;
}

/** "\\?\C:\x" → "C:\x"; trimmed. */
export const plainPath = (p: string) => p.trim().replace(/^\\\\\?\\(?=[a-z]:)/i, "").replace(/^\\\?\?\\(?=[a-z]:)/i, "");

/** Lower-case join key of a path. */
export const pathKey = (p: string) => plainPath(p).replace(/^"(.*)"$/, "$1").toLowerCase();

/** File name of a Windows path. */
export const baseName = (p: string) => p.slice(p.replace(/\//g, "\\").lastIndexOf("\\") + 1);

/** System-wide variables Defender exclusions may hold, relative to the system drive. */
const SYSTEM_VARS: Record<string, string> = {
  programdata: "\\programdata",
  allusersprofile: "\\programdata",
  programfiles: "\\program files",
  "programfiles(x86)": "\\program files (x86)",
  systemroot: "\\windows",
  windir: "\\windows",
  public: "\\users\\public",
  systemdrive: "",
};

/** A path with a leading system variable expanded on the system drive (C:); per-user variables stay as written. */
export function expandSystemVars(p: string, drive = "c:"): string {
  const m = /^%([^%\\]{1,40})%(.*)$/.exec(p.trim());
  if (!m) return p.trim();
  const v = SYSTEM_VARS[m[1].toLowerCase()];
  return v === undefined ? p.trim() : `${drive}${v}${m[2]}`;
}
