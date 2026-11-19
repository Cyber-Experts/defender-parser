// Locations and exclusions that deserve a look. Each rule is named in the
// dictionary with its reason (why_<code>).

import { expandSystemVars, pathKey } from "./paths";
import type { Flag, Severity } from "./types";

export const SEVERITY_RANK: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };

export function worst(flags: Flag[]): Severity | null {
  let w: Severity | null = null;
  for (const f of flags) if (w === null || SEVERITY_RANK[f.severity] < SEVERITY_RANK[w]) w = f.severity;
  return w;
}

/**
 * A staging location for a detected file: temporary folders, C:\Users\Public,
 * the recycle bin, PerfLogs, a first-level ProgramData folder; or Downloads.
 */
export function stagingPlace(path: string): { code: "staging_path" | "downloads"; folder: string } | null {
  const p = pathKey(path);
  let m = /^[a-z]:\\(?:users|documents and settings)\\[^\\]+\\appdata\\local\\temp\\/.exec(p);
  if (m) return { code: "staging_path", folder: "AppData\\Local\\Temp" };
  if (/^[a-z]:\\windows\\temp\\/.test(p)) return { code: "staging_path", folder: "Windows\\Temp" };
  if (/^[a-z]:\\users\\public\\/.test(p)) return { code: "staging_path", folder: "Users\\Public" };
  if (/^[a-z]:\\\$recycle\.bin\\/.test(p)) return { code: "staging_path", folder: "$Recycle.Bin" };
  if (/^[a-z]:\\perflogs\\/.test(p)) return { code: "staging_path", folder: "PerfLogs" };
  if (/^[a-z]:\\temp\\/.test(p)) return { code: "staging_path", folder: "\\Temp" };
  m = /^[a-z]:\\programdata\\([^\\]+)\\[^\\]+$/.exec(p);
  if (m) return { code: "staging_path", folder: `ProgramData\\${path.split("\\")[2] ?? m[1]}` };
  if (/^[a-z]:\\programdata\\[^\\]+$/.test(p)) return { code: "staging_path", folder: "ProgramData" };
  if (/^[a-z]:\\(?:users|documents and settings)\\[^\\]+\\downloads\\/.test(p)) return { code: "downloads", folder: "Downloads" };
  return null;
}

/** Extensions whose exclusion lets most programs and scripts through. */
export const BROAD_EXTENSIONS = new Set(["exe", "dll", "ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "hta", "scr", "com", "msi", "lnk", "sys", "cpl"]);

/** Script hosts and system programs that run other code: excluding them excludes what they open. */
export const SCRIPT_HOSTS = new Set([
  "powershell.exe",
  "pwsh.exe",
  "powershell_ise.exe",
  "cmd.exe",
  "wscript.exe",
  "cscript.exe",
  "mshta.exe",
  "rundll32.exe",
  "regsvr32.exe",
  "msbuild.exe",
  "installutil.exe",
  "wmic.exe",
  "python.exe",
  "pythonw.exe",
  "node.exe",
  "java.exe",
  "javaw.exe",
  "explorer.exe",
  "svchost.exe",
]);

export type ExclusionRisk = "exclusion_drive_root" | "exclusion_writable" | "exclusion_broad_ext" | "exclusion_script_host" | "exclusion_process_name";

/** A folder any user can write to (or a per-user variable pointing at one). */
function writableFolder(p: string): boolean {
  if (/^%(?:temp|tmp|appdata|localappdata|userprofile|public|programdata|allusersprofile)%/i.test(p)) return true;
  const k = pathKey(expandSystemVars(p));
  return (
    /^[a-z]:\\(?:users|documents and settings)(?:\\|$)/.test(k) ||
    /^[a-z]:\\programdata(?:\\|$)/.test(k) ||
    /^[a-z]:\\windows\\temp(?:\\|$)/.test(k) ||
    /^[a-z]:\\(?:temp|tmp|perflogs|\$recycle\.bin)(?:\\|$)/.test(k) ||
    /\\(?:downloads|appdata)(?:\\|$)/.test(k)
  );
}

/** What makes an exclusion risky, worst first. */
export function exclusionRisks(kind: string, value: string): ExclusionRisk[] {
  const v = value.trim();
  const out: ExclusionRisk[] = [];
  if (kind === "Paths" || kind === "TemporaryPaths") {
    const k = pathKey(expandSystemVars(v)).replace(/\\\*(?:\.\*)?$/, "").replace(/\\+$/, "");
    if (/^[a-z]:?$/.test(k) || k === "*" || k === "") out.push("exclusion_drive_root");
    else if (writableFolder(v)) out.push("exclusion_writable");
    if (/^\*\.(\w+)$/.test(v) && BROAD_EXTENSIONS.has(v.slice(2).toLowerCase())) out.push("exclusion_broad_ext");
  } else if (kind === "Extensions") {
    if (BROAD_EXTENSIONS.has(v.replace(/^\*?\./, "").toLowerCase())) out.push("exclusion_broad_ext");
  } else if (kind === "Processes") {
    const name = v.replace(/^"|"$/g, "").split("\\").pop()!.toLowerCase();
    if (SCRIPT_HOSTS.has(name)) out.push("exclusion_script_host");
    if (/[\\/]/.test(v)) {
      if (writableFolder(v)) out.push("exclusion_writable");
    } else out.push("exclusion_process_name");
  }
  return out;
}

const glob = (p: string) => new RegExp(`^${p.toLowerCase().replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`);

/**
 * Whether an exclusion covers a detection, as Windows Persistence matches
 * them: a folder covers what is under it, a file itself, * and ? as
 * wildcards; an extension by the file's; a process exclusion by name matches
 * the process that touched the file or the detected file's own name, by full
 * path that path only.
 */
export function exclusionCovers(kind: string, value: string, file: string, process?: string): boolean {
  const img = pathKey(file);
  if (!img) return false;
  if (kind === "Paths" || kind === "TemporaryPaths") {
    const p = pathKey(expandSystemVars(value)).replace(/\\+$/, "");
    if (!p) return false;
    if (/[*?]/.test(p)) {
      const re = glob(p);
      return re.test(img) || re.test(img.slice(0, img.lastIndexOf("\\")));
    }
    return img === p || img.startsWith(`${p}\\`);
  }
  if (kind === "Extensions") {
    const ext = value.replace(/^\*?\./, "").toLowerCase();
    return !!ext && img.endsWith(`.${ext}`);
  }
  if (kind === "Processes") {
    const v = value.replace(/^"|"$/g, "").toLowerCase();
    const procs = [img, process ? pathKey(process) : ""].filter(Boolean);
    if (/[\\/]/.test(v)) return procs.some((x) => x === pathKey(expandSystemVars(v)));
    return procs.some((x) => x.split("\\").pop() === v);
  }
  return false;
}
