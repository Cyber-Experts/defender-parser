// Pure functions behind the tool's views: findings (flags grouped across
// detections and changes), filters, the timeline, and the exports (CSV,
// formula-safe; JSON; Markdown). No React here; unit-tested. Nothing here
// holds or writes recovered file content: the analysis has none.

import { SEVERITY_RANK, worst } from "./heuristics";
import type { MpKind } from "./mplog";
import type { Analysis, Change, Detection, Flag, MpLine, Severity } from "./types";

export type Item = Detection | Change;
export const isDetection = (x: Item): x is Detection => "threatName" in x;

export interface Finding {
  code: string;
  severity: Severity;
  items: Item[];
}

/** Every flag, grouped by what it means, worst first (info last). */
export function computeFindings(items: Item[]): Finding[] {
  const by = new Map<string, Finding>();
  for (const it of items) {
    for (const f of it.flags) {
      const key = `${f.code}|${f.severity}`;
      if (!by.has(key)) by.set(key, { code: f.code, severity: f.severity, items: [] });
      const g = by.get(key)!;
      if (!g.items.includes(it)) g.items.push(it);
    }
  }
  return [...by.values()].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || b.items.length - a.items.length || a.code.localeCompare(b.code));
}

export const itemSeverity = (x: Item): Severity | null => worst(x.flags);

// ---------------------------------------------------------------------------
// Filters

export interface Filters {
  query: string;
  host: string;
  /** A flag code, or "all". */
  flag: string;
  minSeverity: Severity | "all";
}

export const DEFAULT_FILTERS: Filters = { query: "", host: "all", flag: "all", minSeverity: "all" };

function severityOk(flags: Flag[], min: Filters["minSeverity"]): boolean {
  if (min === "all") return true;
  const s = worst(flags);
  return s !== null && SEVERITY_RANK[s] <= SEVERITY_RANK[min];
}

export function detectionText(d: Detection): string {
  return [d.threatName, d.threatId, d.path, ...d.resources.map((r) => r.location), d.user, d.process, d.source.name, d.action.name, d.detectionId, d.hashes.sha256, d.hashes.sha1, d.hashes.md5, d.status]
    .filter(Boolean)
    .join("\n")
    .toLowerCase();
}

export function changeText(c: Change): string {
  return [c.what, ...Object.values(c.params), c.reg?.keyPath, c.cmd?.command, c.event ? String(c.event.eventId) : ""].filter(Boolean).join("\n").toLowerCase();
}

function common(x: Item, f: Filters, text: () => string): boolean {
  if (f.host !== "all" && x.host !== f.host) return false;
  if (f.flag !== "all" && !x.flags.some((g) => g.code === f.flag)) return false;
  if (!severityOk(x.flags, f.minSeverity)) return false;
  const q = f.query.trim().toLowerCase();
  return !q || text().includes(q);
}

export const filterDetections = (items: Detection[], f: Filters) => items.filter((d) => common(d, f, () => detectionText(d)));
export const filterChanges = (items: Change[], f: Filters, source: Change["source"] | "all" = "all") => items.filter((c) => (source === "all" || c.source === source) && common(c, f, () => changeText(c)));

/** MPLog entries by kind and text (the flag and severity filters do not apply to lines). */
export function filterMplog(items: MpLine[], f: Pick<Filters, "query" | "host">, kind: MpKind | "all" | "files" | "processes" = "all"): MpLine[] {
  const q = f.query.trim().toLowerCase();
  return items.filter((m) => {
    if (f.host !== "all" && m.host !== f.host) return false;
    if (kind === "files" && m.kind !== "sdn") return false;
    if (kind === "processes" && m.kind !== "impact" && m.kind !== "process_counts") return false;
    if (kind !== "all" && kind !== "files" && kind !== "processes" && m.kind !== kind) return false;
    return !q || m.raw.toLowerCase().includes(q);
  });
}

export interface SeenFile {
  path: string;
  sha1?: string;
  sha256?: string;
  first: string;
  last: string;
  count: number;
  detected: boolean;
  host: string;
}

/** Files MPLog's cloud queries name (with their hashes), detected or not. */
export function filesSeen(lines: MpLine[]): SeenFile[] {
  const by = new Map<string, SeenFile>();
  for (const m of lines) {
    if (m.kind !== "sdn" || !m.fields.Path) continue;
    const k = `${m.host}|${m.fields.Path.toLowerCase()}|${m.fields.Sha256 ?? ""}`;
    const have = by.get(k);
    if (have) {
      have.count++;
      have.last = m.stamp;
      have.detected ||= !!m.detection;
    } else by.set(k, { path: m.fields.Path, sha1: m.fields.Sha1, sha256: m.fields.Sha256, first: m.stamp, last: m.stamp, count: 1, detected: !!m.detection, host: m.host });
  }
  return [...by.values()].sort((a, b) => a.first.localeCompare(b.first));
}

export interface SeenProcess {
  name: string;
  count: number;
  files: number;
  first: string;
  last: string;
  host: string;
}

/** Processes MPLog's estimated-impact lines name: programs Defender scanned files for. */
export function processesSeen(lines: MpLine[]): SeenProcess[] {
  const by = new Map<string, SeenProcess>();
  for (const m of lines) {
    if (m.kind !== "impact" || !m.fields.ProcessImageName) continue;
    const k = `${m.host}|${m.fields.ProcessImageName.toLowerCase()}`;
    const n = Number(m.fields.Count) || 0;
    const have = by.get(k);
    if (have) {
      have.count++;
      have.files += n;
      have.last = m.stamp;
    } else by.set(k, { name: m.fields.ProcessImageName, count: 1, files: n, first: m.stamp, last: m.stamp, host: m.host });
  }
  return [...by.values()].sort((a, b) => a.first.localeCompare(b.first));
}

// ---------------------------------------------------------------------------
// Timeline

export type TimelineSource = "event" | "history" | "quarantine" | "mplog" | "registry";

export interface TimelineItem {
  id: string;
  time: number;
  host: string;
  source: TimelineSource;
  /** Dictionary key of what happened (ev_1116, tl_history_detected, mp_sdn, tl_key) and its parameters. */
  what: string;
  params: Record<string, string>;
  detail: string;
  detection?: string;
  change?: string;
  file: string;
}

/** Every record with a UTC time. Times without a zone (MpCmdRun.log, some MPLog lines) are not placed. */
export function buildTimeline(a: Analysis): TimelineItem[] {
  const out: TimelineItem[] = [];
  for (const e of a.events) {
    if (e.time === null) continue;
    const d = e.data;
    const get = (n: string) => d.find(([k]) => k === n)?.[1];
    const detail = get("Threat Name") ?? get("New Value") ?? get("Old Value") ?? get("Value") ?? get("Current Signature Version") ?? get("Scan Type") ?? "";
    out.push({ id: e.id, time: e.time, host: e.host, source: "event", what: `ev_${e.eventId}`, params: { id: String(e.eventId ?? "?") }, detail, ...(e.detection ? { detection: e.detection } : {}), ...(e.change ? { change: e.change } : {}), file: e.file });
  }
  for (const h of a.history) {
    const loc = h.resources[0]?.location ?? "";
    if (h.initialDetection !== null) out.push({ id: `${h.id}:i`, time: h.initialDetection, host: h.host, source: "history", what: "tl_history_detected", params: {}, detail: `${h.threatName ?? ""} ${loc}`.trim(), ...(h.detection ? { detection: h.detection } : {}), file: h.file });
    if (h.statusChanged !== null) out.push({ id: `${h.id}:s`, time: h.statusChanged, host: h.host, source: "history", what: "tl_history_status", params: { status: String(h.threatStatusId ?? "?") }, detail: h.threatName ?? "", ...(h.detection ? { detection: h.detection } : {}), file: h.file });
  }
  for (const q of a.quarantine) {
    if (q.time === null) continue;
    out.push({ id: q.id, time: q.time, host: q.host, source: "quarantine", what: "tl_quarantined", params: {}, detail: `${q.threatName ?? ""} ${q.resources.map((r) => r.display).join(", ")}`.trim(), ...(q.detection ? { detection: q.detection } : {}), file: q.file });
  }
  for (const m of a.mplog) {
    if (m.time === null) continue;
    const f = m.fields;
    const detail = [f.ThreatName, f.Path ?? f.ProcessImageName ?? f.CommandLine ?? f.Process, f.Sha256 ? `sha256 ${f.Sha256}` : ""].filter(Boolean).join(" ");
    out.push({ id: m.id, time: m.time, host: m.host, source: "mplog", what: `mp_${m.kind}`, params: { zone: m.zone }, detail: detail || m.raw.slice(0, 200), ...(m.detection ? { detection: m.detection } : {}), file: m.file });
  }
  for (const k of a.keys) {
    if (k.lastWrite === null) continue;
    out.push({ id: `k:${k.file}|${k.keyPath}`, time: k.lastWrite, host: k.host, source: "registry", what: "tl_key", params: { n: String(k.values) }, detail: k.keyPath, file: k.file });
  }
  return out.sort((x, y) => x.time - y.time || x.id.localeCompare(y.id, "en", { numeric: true }));
}

export function filterTimeline(items: TimelineItem[], f: Pick<Filters, "query" | "host">, source: TimelineSource | "all" = "all"): TimelineItem[] {
  const q = f.query.trim().toLowerCase();
  return items.filter((t) => (f.host === "all" || t.host === f.host) && (source === "all" || t.source === source) && (!q || `${t.what}\n${t.detail}`.toLowerCase().includes(q)));
}

/** Records with a time but no zone: not on the timeline. */
export function unzonedCount(a: Analysis): { mplog: number; commands: number } {
  return { mplog: a.mplog.filter((m) => m.time === null && m.stamp).length, commands: a.commands.filter((c) => c.startText).length };
}

// ---------------------------------------------------------------------------
// Exports

export const isoUtc = (ms: number | null | undefined) => (ms === null || ms === undefined || !Number.isFinite(ms) ? "" : new Date(ms).toISOString());

/**
 * A CSV cell that spreadsheets cannot read as a formula: a leading = + - @,
 * tab or carriage return (or their full-width forms), even after spaces, gets
 * a quote in front.
 */
export function csvCell(v: string | number | null | undefined): string {
  let s = v === null || v === undefined ? "" : String(v);
  if (/^[\s　]*[=+\-@\t\r＝＋－＠]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

const csv = (rows: (string | number | null | undefined)[][]) => rows.map((r) => r.map(csvCell).join(",")).join("\r\n") + "\r\n";
const nameOf = (n: { id: number | null; name: string | null }) => n.name ?? (n.id !== null ? String(n.id) : "");
const sources = (d: Detection) => [d.events.length ? `events:${d.events.map((e) => e.eventId).join("+")}` : "", d.history.length ? "detectionhistory" : "", d.quarantine.length ? "quarantine" : "", d.mplog.length ? "mplog" : ""].filter(Boolean).join(" ");

export function detectionsCsv(items: Detection[]): string {
  const head = ["severity", "time_utc", "host", "threat", "threat_id", "defender_severity", "category", "path", "user", "process", "detection_source", "action", "result", "error_code", "quarantined", "sha256", "sha1", "md5", "flags", "sources", "detection_id"];
  const rows = items.map((d) => [
    itemSeverity(d) ?? "",
    isoUtc(d.time),
    d.host,
    d.threatName,
    d.threatId ?? "",
    nameOf(d.severity),
    nameOf(d.category),
    d.path,
    d.user ?? "",
    d.process ?? "",
    nameOf(d.source),
    nameOf(d.action),
    d.result,
    d.errorCode ?? "",
    d.quarantined === null ? "" : d.quarantined ? "yes" : "no",
    d.hashes.sha256 ?? "",
    d.hashes.sha1 ?? "",
    d.hashes.md5 ?? "",
    d.flags.map((f) => `${f.code}:${f.severity}`).join(" "),
    sources(d),
    d.detectionId ?? "",
  ]);
  return csv([head, ...rows]);
}

export function changesCsv(items: Change[]): string {
  const head = ["severity", "time_utc", "local_time_no_zone", "host", "source", "what", "details", "flags"];
  const rows = items.map((c) => [itemSeverity(c) ?? "", isoUtc(c.time), c.localTime ?? "", c.host, c.source, c.what, Object.entries(c.params).map(([k, v]) => `${k}=${v}`).join("; "), c.flags.map((f) => `${f.code}:${f.severity}`).join(" ")]);
  return csv([head, ...rows]);
}

export function timelineCsv(items: TimelineItem[]): string {
  const head = ["time_utc", "host", "source", "what", "detail", "file"];
  return csv([head, ...items.map((t) => [isoUtc(t.time), t.host, t.source, t.what, t.detail, t.file])]);
}

/** Everything read, as JSON: records and their raw sources, never recovered file content (the analysis holds none). */
export function toJson(a: Analysis): string {
  return JSON.stringify(
    { tool: "defender-parser", generated: new Date().toISOString(), timesAre: "UTC (ISO 8601) unless a field says otherwise", ...a },
    (key, value) => (typeof value === "number" && /^(?:time|newest|first|last|initialDetection|remediation|statusChanged|keyLastWrite|lastWrite|created|accessed|written|mtime)$/.test(key) ? isoUtc(value) : value),
    2,
  );
}

export interface MarkdownLabels {
  finding: (f: Finding) => string;
  flag: (f: Flag) => string;
  why: (code: string) => string;
  item: (x: Item) => string;
}

/** Text safe inside Markdown: no code spans, table pipes, line breaks or HTML. */
const md = (s: string) => s.replace(/[`|<>]/g, "'").replace(/[\r\n]+/g, " ").slice(0, 600);

export function toMarkdown(a: Analysis, label: MarkdownLabels): string {
  const items: Item[] = [...a.detections, ...a.changes];
  const findings = computeFindings(items);
  const u = unzonedCount(a);
  const lines = [`# Microsoft Defender: ${a.hosts.map((h) => md(h.name)).join(", ")}`, ""];
  for (const h of a.hosts) {
    lines.push(`- **${md(h.name)}**: newest record ${isoUtc(h.newest) || "unknown"}; files: ${Object.entries(h.files).map(([k, n]) => `${n} ${k}`).join(", ") || "none"}`);
  }
  lines.push(
    "",
    "Times are UTC unless marked otherwise. MpCmdRun.log and some MPLog lines carry no time zone: they are quoted as written.",
    "",
    `- Detections: ${a.detections.length}; protection changes: ${a.changes.length}; Operational events: ${a.events.length}; MPLog entries: ${a.mplog.length}${u.mplog ? ` (${u.mplog} without a zone)` : ""}; MpCmdRun runs: ${a.commands.length}`,
    "",
    "## Detections",
    "",
  );
  if (!a.detections.length) lines.push("None.", "");
  for (const d of a.detections) {
    lines.push(
      `- ${isoUtc(d.time) || "time unknown"} · **${md(d.threatName || "?")}** · \`${md(d.path || "?")}\`${d.user ? ` · ${md(d.user)}` : ""}${d.process ? ` · ${md(d.process)}` : ""} · ${md(nameOf(d.source) || "source ?")} · ${md(nameOf(d.action) || "action ?")} (${d.result})${d.quarantined ? " · quarantined" : ""}${d.hashes.sha256 ? ` · SHA-256 ${d.hashes.sha256}` : ""}`,
    );
  }
  lines.push("", "## Findings", "");
  if (!findings.length) lines.push("None.", "");
  for (const f of findings) {
    const heading = label.finding(f);
    lines.push(`### ${f.severity.toUpperCase()} · ${md(heading)}`, "", md(label.why(f.code)), "");
    for (const x of f.items) {
      const flag = x.flags.find((g) => g.code === f.code && g.severity === f.severity);
      const own = flag ? label.flag(flag) : "";
      lines.push(`- ${isoUtc(x.time) || (!isDetection(x) && x.localTime ? `${md(x.localTime)} (no zone)` : "time unknown")} · ${md(label.item(x))}${own && own !== heading ? ` · ${md(own)}` : ""}${a.hosts.length > 1 ? ` · ${md(x.host)}` : ""}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}
