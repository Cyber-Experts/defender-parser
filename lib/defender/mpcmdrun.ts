// MpCmdRun.log (C:\Windows\Temp, and %TEMP% of a user who ran MpCmdRun.exe).
//
// Layout from dissect.target's mpcmdrun reader and its test file: UTF-16LE
// text; each run between lines of dashes, with "MpCmdRun: Command Line: …",
// " Start Time: Mon Nov 03 2025 13:08:19" (left-to-right marks between the
// words) and "MpCmdRun: End Time: …"; the start time is missing from some
// runs. The times carry no zone: Dissect reads them in the machine's time
// zone. They are kept as written and never placed on the UTC timeline.
// Commands and options: Microsoft, "Use the command line to manage Microsoft
// Defender Antivirus" (MpCmdRun.exe), and LOLBAS (-DownloadFile).

import { decodeText, splitLines, type Encoding } from "./text";
import type { LineEnding } from "./types";

export interface MpRunRaw {
  /** 1-based line of the command line. */
  line: number;
  command: string;
  /** The run's start and end as written, and read as if UTC for ordering only. */
  startText?: string;
  start: number | null;
  endText?: string;
  end: number | null;
  kind: CommandKind;
  /** The run's other lines (at most 40). */
  detail: string[];
}

export interface MpCmdRunRaw {
  encoding: Encoding;
  bom: boolean;
  lineEnding: LineEnding;
  lines: number;
  runs: MpRunRaw[];
  cut: boolean;
}

export type CommandKind =
  | "remove_definitions"
  | "remove_dynamic_signature"
  | "add_dynamic_signature"
  | "restore"
  | "reset_platform"
  | "revert_platform"
  | "download_file"
  | "check_exclusion"
  | "signature_update"
  | "scan"
  | "get_files"
  | "other";

const MAX_RUNS = 50_000;
const MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];

/** "Mon Nov 03 2025 13:08:19" (marks removed) → as if UTC; null when not that shape. */
export function cmdTime(text: string): number | null {
  const m = /^(?:[A-Za-z]{3}\s+)?([A-Za-z]{3})\s+(\d{1,2})\s+(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})$/.exec(text.replace(/\u200e/g, "").trim());
  if (!m) return null;
  const mo = MONTHS.indexOf(m[1].toLowerCase());
  const [d, y, h, mi, s] = [+m[2], +m[3], +m[4], +m[5], +m[6]];
  if (mo < 0 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 59 || y < 1980 || y > 9999) return null;
  const t = Date.UTC(y, mo, d, h, mi, s);
  return new Date(t).getUTCDate() === d ? t : null;
}

/** What a command line does, by its first option. */
export function commandKind(command: string): CommandKind {
  const c = command.toLowerCase();
  const has = (opt: string) => new RegExp(`(?:^|\\s)[-/]?${opt}(?:\\s|$)`, "i").test(c);
  if (has("removedefinitions")) return "remove_definitions";
  if (has("removedynamicsignature")) return "remove_dynamic_signature";
  if (has("adddynamicsignature")) return "add_dynamic_signature";
  if (/(?:^|\s)-restore(?:\s|$)/i.test(c)) return "restore";
  if (has("resetplatform")) return "reset_platform";
  if (has("revertplatform")) return "revert_platform";
  if (has("downloadfile")) return "download_file";
  if (has("checkexclusion")) return "check_exclusion";
  if (has("signatureupdate") || has("signaturesupdateservice")) return "signature_update";
  if (has("scan")) return "scan";
  if (has("getfiles")) return "get_files";
  return "other";
}

export function parseMpCmdRun(bytes: Uint8Array): MpCmdRunRaw {
  const dec = decodeText(bytes);
  const split = splitLines(dec.text);
  const out: MpCmdRunRaw = { encoding: dec.encoding, bom: dec.bom, lineEnding: split.ending, lines: split.lines.length, runs: [], cut: dec.cut || split.more };
  let run: MpRunRaw | null = null;
  const close = () => {
    if (run && out.runs.length < MAX_RUNS) out.runs.push(run);
    run = null;
  };
  split.lines.forEach((raw, idx) => {
    const line = raw.replace(/\u200e/g, "").replace(/^\ufeff/, "");
    const t = line.trim();
    if (/^-{20,}$/.test(t)) {
      close();
      return;
    }
    const cmd = /Command Line:\s*(.*)$/.exec(t);
    if (cmd && /^MpCmdRun:/i.test(t)) {
      close();
      run = { line: idx + 1, command: cmd[1].slice(0, 4096), start: null, end: null, kind: commandKind(cmd[1]), detail: [] };
      return;
    }
    if (!run) return;
    const r: MpRunRaw = run;
    const st = /^Start Time:\s*(.*)$/.exec(t);
    if (st && !r.startText) {
      r.startText = st[1].trim();
      r.start = cmdTime(st[1]);
      return;
    }
    const en = /^(?:MpCmdRun:\s*)?End Time:\s*(.*)$/.exec(t);
    if (en) {
      r.endText = en[1].trim();
      r.end = cmdTime(en[1]);
      return;
    }
    if (t && r.detail.length < 40) r.detail.push(t.slice(0, 500));
  });
  close();
  return out;
}

/** Whether text holds MpCmdRun runs (for loose files). */
export const looksLikeMpCmdRun = (text: string) => /MpCmdRun:\s*Command Line:/i.test(text);
