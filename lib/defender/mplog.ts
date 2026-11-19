// Microsoft Protection logs (ProgramData\Microsoft\Windows Defender\Support\
// MPLog-*.log) and the detection logs beside them (MPDetection-*.log).
//
// Line shapes from Intrinsec's mplog_parser (MIT), Fox-IT's dissect.target
// (plugins/os/windows/defender/mplog.py), CrowdStrike's "How to Use MPLogs
// for Forensic Investigations", artefacts.help ("Windows Defender - Support
// logs") and Yamato Security's ys-defender-history-parser (src/mplog.rs, read
// against DFIRArtifactMuseum's MPLogs): estimated impact (ProcessImageName),
// SDN cloud queries with SHA-1 / SHA-256, DETECTION_ADD, DETECTIONEVENT,
// DETECTION_CLEANEVENT, lowfi and threat command lines, EMS scans and
// detections, mini-filter blocked and unscanned files, original file names,
// [Exclusion] / [ProcessExclusion] / [RtpConfig], filter caching, the
// service's start, stop and versions, the service-log header, and the
// multi-line blocks (resource scans, threat actions, BM telemetry, the RTP
// perf log).
//
// Times. A timed line starts "2021-07-22T15:38:04.557Z": the Z (or an
// offset) makes it UTC. Newer logs also write the same form without a zone;
// what zone those are in is not settled (DLEAPP and Yamato Security read them
// as UTC when the service-log header's UTC "Current time" is within a minute
// of the first line; a 2023 sample shows the same event once with Z and once
// in local time without it), so they stay "no zone", shown as written and
// kept off the UTC timeline. Block times ("Start Time:12-15-2022 11:24:33",
// MM-DD-YYYY) and the header's "Started On" carry no zone either.

import { decodeText, splitLines, MAX_LINE, MAX_UNPARSED_KEPT, type Encoding } from "./text";
import { fromFiletime } from "./quarantine";
import type { LineEnding, Unparsed } from "./types";

export type MpKind =
  | "header"
  | "impact"
  | "process_counts"
  | "sdn"
  | "sdn_result"
  | "detection_add"
  | "detection_event"
  | "detection_clean"
  | "lowfi"
  | "threat_cmdline"
  | "ems_scan"
  | "ems_detection"
  | "original_name"
  | "blocked_file"
  | "unsuccessful_scan"
  | "filter_caching"
  | "exclusion"
  | "process_exclusion"
  | "rtp_config"
  | "service_started"
  | "service_stopped"
  | "version"
  | "resource_scan"
  | "threat_actions"
  | "bm_telemetry"
  | "rtp_perf"
  | "other";

/** How a line's time was read: UTC as written (Z or an offset), or no zone. */
export type MpZone = "utc" | "none";

export interface MpEntryRaw {
  /** 1-based line of its first line. */
  line: number;
  /** Lines it spans (blocks). */
  span: number;
  kind: MpKind;
  /** The time as written. */
  stamp: string;
  /** ms since the epoch, UTC; null when the zone is not known or there is no time. */
  time: number | null;
  /** The time as written read as if UTC: for ordering zone-less lines among themselves only. */
  wall: number | null;
  zone: MpZone;
  fields: Record<string, string>;
  raw: string;
}

export interface MpLogRaw {
  encoding: Encoding;
  bom: boolean;
  lineEnding: LineEnding;
  lines: number;
  blank: number;
  cut: boolean;
  entries: MpEntryRaw[];
  /** Timed lines whose message the tool does not recognise (kept as "other"). */
  other: number;
  unparsed: Unparsed[];
  unparsedCount: number;
  /** Entries past the per-file cap: counted, not kept. */
  dropped: number;
}

/** Entries kept per file; the rest are counted. */
export const MAX_ENTRIES = 300_000;
const MAX_BLOCK = 400;
const MAX_FIELD = 4096;

const TIMED = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?)(Z|[+-]\d{2}:\d{2})?\s+(.*)$/;
const DAYS = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

function utcParts(y: number, mo: number, d: number, h: number, mi: number, s: number, frac: string): number | null {
  if (y < 1601 || y > 9999 || mo < 1 || mo > 12 || d < 1 || d > DAYS[mo - 1] || h > 23 || mi > 59 || s > 59) return null;
  if (mo === 2 && d === 29 && !(y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0))) return null;
  const ms = frac ? Number(frac.padEnd(3, "0").slice(0, 3)) : 0;
  const t = Date.UTC(y, mo - 1, d, h, mi, s, ms);
  return Number.isFinite(t) ? t : null;
}

/** "2021-07-22T15:38:04.557" (no zone) read as if UTC. */
function isoWall(text: string): number | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?$/.exec(text);
  return m ? utcParts(+m[1], +m[2], +m[3], +m[4], +m[5], +m[6], m[7] ?? "") : null;
}

/** "12-15-2022 11:24:33" (MM-DD-YYYY) or "2022-12-15 11:24:33", read as if UTC; zone not known. */
export function blockWall(text: string): number | null {
  const t = text.replace(/‎/g, "").trim();
  const us = /^(\d{1,2})[-/](\d{1,2})[-/](\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?$/.exec(t);
  if (us) return utcParts(+us[3], +us[1], +us[2], +us[4], +us[5], +us[6], us[7] ?? "");
  return isoWall(t);
}

/** "05/06/2024 13:20:45.123456789 UTC …" → ms, UTC. */
function headerTime(text: string): number | null {
  const m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?\s+UTC\b/.exec(text.trim());
  return m ? utcParts(+m[3], +m[1], +m[2], +m[4], +m[5], +m[6], m[7] ?? "") : null;
}

const clipField = (s: string) => (s.length > MAX_FIELD ? `${s.slice(0, MAX_FIELD)}…` : s);

/** "Label: value, Label: value…" by the labels expected, in order; a value runs to the next label found (paths may hold ", "). */
function labelled(body: string, labels: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  const at: { label: string; start: number; value: number }[] = [];
  let from = 0;
  for (const label of labels) {
    const re = new RegExp(`(?:^|,\\s*)${label}[: ]\\s*`, "g");
    re.lastIndex = from;
    const m = re.exec(body);
    if (!m) continue;
    at.push({ label, start: m.index, value: m.index + m[0].length });
    from = m.index + m[0].length;
  }
  at.forEach((a, i) => {
    out[a.label] = clipField(body.slice(a.value, i + 1 < at.length ? at[i + 1].start : body.length).trim());
  });
  return out;
}

const IMPACT = ["ProcessImageName", "Pid", "TotalTime", "Count", "MaxTime", "MaxTimeFile", "EstimatedImpact"];
const MINIFILTER = ["Process", "Status", "State", "ScanRequest", "FileId", "Reason", "IoStatusBlockForNewFile", "DesiredAccess", "FileAttributes", "ScanAttributes", "AccessStateFlags", "BackingFileInfo"];

/** A detection target: "file:<path>", "process:pid:<n>,ProcessStart:<FILETIME>", or "<schema>:<location>". */
function target(t: string): Record<string, string> {
  const s = t.split(" PropBag")[0].trim();
  if (!s) return {};
  const m = /^([A-Za-z]+):(.*)$/.exec(s);
  if (!m) return { Target: clipField(s) };
  const out: Record<string, string> = { Target: clipField(s), Schema: m[1].toLowerCase() };
  if (m[1].toLowerCase() === "process") {
    const pid = /pid:(\d+)/i.exec(m[2]);
    if (pid) out.Pid = pid[1];
    const ps = /ProcessStart:(\d+)/i.exec(m[2]);
    const t2 = ps ? fromFiletime(Number(ps[1])) : null;
    if (t2 !== null) out.ProcessStart = new Date(t2).toISOString();
  } else out.Path = clipField(m[2].split(";")[0].trim());
  return out;
}

/** "<path> (<device path>)": the group whose parentheses balance and that starts like a path, taken from the end. */
function pathAndDevice(text: string): { path: string; device?: string } {
  if (!text.endsWith(")")) return { path: text };
  let depth = 0;
  for (let i = text.length - 1; i >= 1; i--) {
    if (text[i] === ")") depth++;
    else if (text[i] === "(") {
      depth--;
      if (depth === 0) {
        const inner = text.slice(i + 1, -1);
        if (text[i - 1] === " " && /^(?:\\|[A-Za-z]:)/.test(inner)) return { path: text.slice(0, i - 1), device: inner };
        return { path: text };
      }
    }
  }
  return { path: text };
}

/** A timed line's message → kind and fields. */
export function classify(rest: string): { kind: MpKind; fields: Record<string, string> } {
  let i: number;
  if (rest.startsWith("ProcessImageName:")) return { kind: "impact", fields: labelled(rest, IMPACT) };
  if ((i = rest.indexOf("[Mini-filter] ")) >= 0) {
    const body = rest.slice(i + 14);
    const kind: MpKind | null = body.startsWith("Blocked file") ? "blocked_file" : body.startsWith("Unsuccessful scan status") ? "unsuccessful_scan" : null;
    if (kind) {
      const after = body.slice(body.indexOf(": ") + 2);
      const p = after.indexOf(" Process: ");
      const fields: Record<string, string> = { Path: clipField((p >= 0 ? after.slice(0, p) : after).replace(/\.$/, "")) };
      if (p >= 0) Object.assign(fields, labelled(after.slice(p + 1), MINIFILTER));
      return { kind, fields };
    }
  }
  if ((i = rest.indexOf("[ProcessExclusion] ")) >= 0) {
    const [path, device] = rest.slice(i + 19).split(" -> ");
    return { kind: "process_exclusion", fields: { Path: clipField(path), ...(device ? { DevicePath: clipField(device) } : {}) } };
  }
  if ((i = rest.indexOf("[RtpConfig] Config change detected, type: ")) >= 0) return { kind: "rtp_config", fields: { Type: rest.slice(i + 42).trim() } };
  if ((i = rest.indexOf("[Exclusion] ")) >= 0) {
    const body = rest.slice(i + 12);
    const [path, device] = body.split(" -> ");
    return { kind: "exclusion", fields: { Path: clipField(path), ...(device ? { DevicePath: clipField(device) } : {}) } };
  }
  let m = /DETECTION_ADD(?:#\d+)?\s+(\S+)\s*(.*)$/.exec(rest);
  if (m) return { kind: "detection_add", fields: { ThreatName: m[1], ...target(m[2]) } };
  m = /DETECTIONEVENT\s+(MPSOURCE_\S+)\s+(\S+)\s*(.*)$/.exec(rest);
  if (m) return { kind: "detection_event", fields: { Source: m[1], ThreatName: m[2], ...target(m[3]) } };
  m = /DETECTION_CLEANEVENT\s+(MPSOURCE_\S+)\s+(\S+)\s+(0x[0-9a-fA-F]+)\s+(\S+)/.exec(rest);
  if (m) return { kind: "detection_clean", fields: { Source: m[1], Action: m[2], Hr: m[3], ThreatName: m[4] } };
  if ((i = rest.indexOf("Filter caching disabled for ")) >= 0) {
    const body = rest.slice(i + 28);
    const r = body.lastIndexOf(" (runtime");
    return { kind: "filter_caching", fields: { Path: clipField(r >= 0 ? body.slice(0, r) : body) } };
  }
  if ((i = rest.indexOf("Issuing SDN query for ")) >= 0) {
    let body = rest.slice(i + 22);
    const fields: Record<string, string> = {};
    const h = body.lastIndexOf(" (sha1=");
    if (h >= 0 && body.endsWith(")")) {
      for (const part of body.slice(h + 2, -1).split(/,\s*/)) {
        const [k, v] = part.split("=");
        if (k === "sha1" && /^[0-9a-f]{40}$/i.test(v ?? "")) fields.Sha1 = v.toLowerCase();
        else if ((k === "sha2" || k === "sha256") && /^[0-9a-f]{64}$/i.test(v ?? "")) fields.Sha256 = v.toLowerCase();
      }
      body = body.slice(0, h);
    }
    const pd = pathAndDevice(body);
    return { kind: "sdn", fields: { Path: clipField(pd.path), ...(pd.device ? { DevicePath: clipField(pd.device) } : {}), ...fields } };
  }
  if ((i = rest.indexOf("SDN query completed: ")) >= 0) return { kind: "sdn_result", fields: { Result: rest.slice(i + 21).trim() } };
  if ((i = rest.indexOf("EMS scan for process: ")) >= 0) {
    const body = rest.slice(i + 22);
    const p = body.indexOf(" pid: ");
    return { kind: "ems_scan", fields: { Process: p >= 0 ? body.slice(0, p) : body, ...(p >= 0 ? labelled(body.slice(p + 1), ["pid", "sigseq", "sendMemoryScanReport", "source"]) : {}) } };
  }
  if ((i = rest.indexOf("EMS detection: ")) >= 0) {
    const parts = rest.slice(i + 15).split(", ");
    const fields: Record<string, string> = { ThreatName: parts[0] };
    for (const p of parts.slice(1)) {
      const [k, v] = p.split("=");
      if (k && v !== undefined) fields[k] = v;
    }
    return { kind: "ems_detection", fields };
  }
  m = /original file name "(.*)" for "(.*)", hr=(\w+)/.exec(rest);
  if (m) return { kind: "original_name", fields: { OriginalFileName: clipField(m[1]), Path: clipField(m[2]), Hr: m[3] } };
  if ((i = rest.indexOf("lowfi: ")) >= 0) return { kind: "lowfi", fields: { CommandLine: clipField(rest.slice(i + 7)) } };
  if ((i = rest.indexOf("threat: ")) >= 0) return { kind: "threat_cmdline", fields: { CommandLine: clipField(rest.slice(i + 8)) } };
  if (rest.startsWith("Service started - ")) {
    const body = rest.slice(18);
    const p = body.lastIndexOf(" (");
    return { kind: "service_started", fields: { Product: p >= 0 ? body.slice(0, p) : body, ...(p >= 0 ? { Id: body.slice(p + 2).replace(/\)$/, "") } : {}) } };
  }
  if (rest.startsWith("Service stopped with exit code ")) return { kind: "service_stopped", fields: { ExitCode: rest.slice(31).trim() } };
  if (rest.startsWith("Version: ")) return { kind: "version", fields: labelled(rest.slice(9), ["Product", "Service", "Engine", "AS", "AV"]) };
  return { kind: "other", fields: {} };
}

const BLOCKS: { kind: MpKind; start: (l: string) => boolean; end: (l: string) => boolean }[] = [
  { kind: "resource_scan", start: (l) => l.startsWith("Begin Resource Scan"), end: (l) => l.startsWith("End Scan") },
  { kind: "threat_actions", start: (l) => l.startsWith("Beginning threat actions"), end: (l) => l.startsWith("Finished threat actions") },
  { kind: "bm_telemetry", start: (l) => l.startsWith("BEGIN BM telemetry"), end: (l) => l.startsWith("END BM telemetry") },
  { kind: "rtp_perf", start: (l) => /RTP Perf Log/.test(l) && !/END RTP Perf Log/.test(l), end: (l) => /END RTP Perf Log/.test(l) },
];

export function parseMpLog(bytes: Uint8Array): MpLogRaw {
  const dec = decodeText(bytes);
  const split = splitLines(dec.text);
  const lines = split.lines;
  const out: MpLogRaw = { encoding: dec.encoding, bom: dec.bom, lineEnding: split.ending, lines: lines.length, blank: 0, cut: dec.cut || split.more, entries: [], other: 0, unparsed: [], unparsedCount: 0, dropped: 0 };
  const push = (e: MpEntryRaw) => {
    if (out.entries.length < MAX_ENTRIES) out.entries.push(e);
    else out.dropped++;
  };
  const notUnderstood = (n: number, text: string, reason: string) => {
    out.unparsedCount++;
    if (out.unparsed.length < MAX_UNPARSED_KEPT) out.unparsed.push({ line: n, text: text.slice(0, 300), reason });
  };
  let i = 0;
  while (i < lines.length) {
    const raw = lines[i];
    const line = raw.replace(/^﻿/, "").replace(/‎/g, "").trimEnd();
    const n = i + 1;
    if (!line.trim()) {
      out.blank++;
      i++;
      continue;
    }
    if (raw.length > MAX_LINE) {
      notUnderstood(n, raw, "too_long");
      i++;
      continue;
    }
    // Service-log header: "<service> (<GUID>) Service Log", then up to 8 lines to "Current time:".
    if (/ Service Log$/.test(line.trim())) {
      const fields: Record<string, string> = {};
      const title = line.trim().replace(/ Service Log$/, "");
      const p = title.lastIndexOf(" (");
      fields.Service = p >= 0 ? title.slice(0, p) : title;
      if (p >= 0) fields.Id = title.slice(p + 2).replace(/\)$/, "");
      let j = i + 1;
      let current: number | null = null;
      for (; j < Math.min(lines.length, i + 9); j++) {
        const l = lines[j].replace(/‎/g, "").trim();
        if (l.startsWith("Started On ")) fields.StartedOn = l.slice(11);
        else if (l.startsWith("OS install time: ")) fields.OsInstallTime = l.slice(17);
        else if (l.startsWith("Current time: ")) {
          fields.CurrentTime = l.slice(14);
          current = headerTime(l.slice(14));
          const ms = /\((\d+) ms since boot\)/.exec(l);
          if (ms) fields.MsSinceBoot = ms[1];
          j++;
          break;
        } else if (TIMED.test(l)) break;
      }
      push({ line: n, span: j - i, kind: "header", stamp: fields.CurrentTime ?? "", time: current, wall: current, zone: current !== null ? "utc" : "none", fields, raw: lines.slice(i, j).join("\n").slice(0, 4000) });
      i = j;
      continue;
    }
    const block = BLOCKS.find((b) => b.start(line.trim()));
    if (block) {
      let j = i + 1;
      let ended = false;
      while (j < lines.length && j - i < MAX_BLOCK) {
        const l = lines[j].trim();
        if (block.end(l)) {
          ended = true;
          j++;
          break;
        }
        if (TIMED.test(l) || BLOCKS.some((b) => b.start(l))) break;
        j++;
      }
      const body = lines.slice(i, j);
      const fields: Record<string, string> = {};
      for (const l of body.slice(1)) {
        const m = /^\s*([\w -]{1,60}?)\s*:(.*)$/.exec(l.replace(/‎/g, ""));
        if (!m) continue;
        const k = m[1].trim();
        const v = m[2].trim();
        if (!v) continue;
        fields[k] = clipField(fields[k] ? `${fields[k]} | ${v}` : v);
      }
      if (!ended) fields._unterminated = "yes";
      let stamp = fields["Start Time"] ?? fields["Start time"] ?? fields["RTP Start"] ?? fields.CreationTime ?? "";
      if (block.kind === "bm_telemetry" && fields.ProcessCreationTime) {
        const t = fromFiletime(Number(fields.ProcessCreationTime));
        if (t !== null) fields.ProcessCreated = new Date(t).toISOString();
      }
      stamp = stamp.replace(/‎/g, "").trim();
      push({ line: n, span: j - i, kind: block.kind, stamp, time: null, wall: stamp ? blockWall(stamp) : null, zone: "none", fields, raw: body.join("\n").slice(0, 8000) });
      i = j;
      continue;
    }
    const m = TIMED.exec(line.trim());
    if (m) {
      const [, clock, zoneText, rest] = m;
      const wall = isoWall(clock);
      let time: number | null = null;
      let zone: MpZone = "none";
      if (zoneText === "Z") {
        time = wall;
        zone = "utc";
      } else if (zoneText && wall !== null) {
        const sign = zoneText[0] === "+" ? 1 : -1;
        const hh = +zoneText.slice(1, 3);
        const mm = +zoneText.slice(4, 6);
        if (hh <= 23 && mm <= 59) {
          time = wall - sign * (hh * 60 + mm) * 60_000;
          zone = "utc";
        }
      }
      if (wall === null) {
        notUnderstood(n, line, "bad_time");
        i++;
        continue;
      }
      const c = classify(rest);
      if (c.kind === "other") out.other++;
      push({ line: n, span: 1, kind: c.kind, stamp: `${clock}${zoneText ?? ""}`, time, wall, zone, fields: c.fields, raw: line.trim().slice(0, 4000) });
      i++;
      continue;
    }
    if (line.trim().startsWith("Per-process counts:")) {
      const prev = out.entries[out.entries.length - 1];
      push({ line: n, span: 1, kind: "process_counts", stamp: prev?.stamp ?? "", time: prev?.time ?? null, wall: prev?.wall ?? null, zone: prev?.zone ?? "none", fields: labelled(line.trim().slice(19).trim(), IMPACT), raw: line.trim().slice(0, 4000) });
      i++;
      continue;
    }
    notUnderstood(n, line, "no_time");
    i++;
  }
  return out;
}

/** Whether text looks like an MPLog or MPDetection log (for loose files). */
export function looksLikeMpLog(lines: string[]): boolean {
  return lines.some((l) => / Service Log$/.test(l.trim()) || /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\s+(?:ProcessImageName:|SDN:|DETECTION|\[RTP\]|\[Mini-filter\]|Engine:|Service started - |Version: )/.test(l.trim()));
}
