// The analysis: files of one or more Windows machines in; detections,
// quarantine, protection changes, MPLog entries and file reports out. Pure
// and synchronous (runs in a Web Worker); every reader is bounded and a file
// that cannot be read is reported, never thrown. The Operational log arrives
// already read by the WebAssembly reader (lib/defender/evtx.ts), as records.
//
// Per host:
//  1. read every file by its role;
//  2. tie each ResourceData and Resources file to the quarantine resource
//     that names its content;
//  3. detections: the Operational log's threat events grouped by Detection
//     ID; then each DetectionHistory file (by the same Detection ID, which is
//     its file name); then each quarantine entry (by the GUID the history file
//     names, else by threat name, path and a time within 15 minutes); then
//     MPLog's detection lines (by threat and path within 5 minutes, UTC times
//     only) and the SDN line of the same path just before (hashes). What
//     nothing ties stays a detection of its own;
//  4. protection changes: the Defender events that record a setting, an
//     exclusion, a blocked change, a quarantine or history action; the
//     exclusions and switches of the SOFTWARE hive (at their key's LastWrite
//     time); every MpCmdRun.exe run;
//  5. flags, once every host's newest time is known.

import { ACTION_EVENTS, ACTIONS, CATEGORIES, FAILED_EVENTS, FAILED_STATUS, SEVERITY, SOURCES, THREAT_EVENTS, THREAT_STATUS, field, named, parseIsoUtc, parseRegChange, parseResources, regNumber, textName, type EvtxFileRaw, type NamedId } from "./evtx";
import { exclusionCovers, exclusionRisks, SEVERITY_RANK, stagingPlace, worst } from "./heuristics";
import { readHistory, sniffHistory, trackingValue, MAX_HISTORY_BYTES } from "./history";
import { looksLikeMpCmdRun, parseMpCmdRun } from "./mpcmdrun";
import { looksLikeMpLog, parseMpLog } from "./mplog";
import { baseName, pathKey, place, plainPath, roleOf, userFromPath } from "./paths";
import { readEntry, readResourceData, readResourceRecord, sniffQuarantine, STREAM_KINDS, rc4 } from "./quarantine";
import { HiveError, openHive } from "./regf";
import { readDefenderKeys } from "./registry";
import { decodeText, splitLines } from "./text";
import type { Analysis, Change, Detection, FileReport, FileRole, Flag, HistoryRecord, Host, InputFile, MpCmd, MpLine, OpEvent, QuarantineEntry, QuarantineResource, RegKeyInfo, RegSetting, ResourceDataInfo } from "./types";

const MINUTE = 60_000;
const DAY = 86_400_000;
const RECENT = 7 * DAY;
const QUARANTINE_WINDOW = 15 * MINUTE;
const MPLOG_WINDOW = 5 * MINUTE;
const SDN_WINDOW = 10 * MINUTE;
const EXCLUSION_WINDOW = 60 * MINUTE;

const errText = (err: unknown) => (err instanceof Error ? err.message : String(err));
const iso = (t: number) => new Date(t).toISOString().replace("T", " ").replace(/\.\d{3}Z$/, "");
const norm = (g: string | undefined) => g?.replace(/[{}]/g, "").toUpperCase();
const lower = (s: string | undefined) => (s ?? "").trim().toLowerCase();

type Role = Exclude<FileRole, "unknown">;

/** A loose file (no folder around it): by its name, then by its content. */
export function sniffLoose(input: InputFile): Role | null {
  const name = input.path.replace(/\\/g, "/").split("/").pop()!.toLowerCase();
  const b = input.bytes;
  if (b.length >= 8 && new TextDecoder("latin1").decode(b.subarray(0, 8)) === "ElfFile\0") return "evtx";
  if (b.length > 4096 && b[0] === 0x72 && b[1] === 0x65 && b[2] === 0x67 && b[3] === 0x66) {
    try {
      const h = openHive(b);
      return h.root.subkey("Microsoft\\Windows Defender") || h.root.subkey("Microsoft\\Windows NT\\CurrentVersion") ? "software" : null;
    } catch {
      return null;
    }
  }
  const q = sniffQuarantine(b);
  if (q) return q === "record" ? "resources" : "entry";
  if (sniffHistory(b)) return "history";
  if (/^mpcmdrun\.log/.test(name)) return "mpcmdrun";
  if (/^mpdetection-.*\.log$/.test(name)) return "mpdetection";
  if (/^mplog-.*\.log$/.test(name)) return "mplog";
  if (/^[0-9a-f]{40}$/i.test(name) && b.length >= 20) {
    const head = rc4(b.subarray(0, 24));
    const kind = head[0] | (head[1] << 8) | (head[2] << 16) | (head[3] << 24);
    if ((kind >= 1 && kind <= 11 && head[4] < 0x20) || (head[0] === 0x72 && head[1] === 0x65 && head[2] === 0x67 && head[3] === 0x66)) return "resourcedata";
  }
  const text = decodeText(b.subarray(0, 256 * 1024)).text;
  if (looksLikeMpCmdRun(text)) return "mpcmdrun";
  const lines = splitLines(text).lines.slice(0, 200);
  if (looksLikeMpLog(lines)) return lines.some((l) => /^\S+\s+Version: /.test(l.trim())) && !lines.some((l) => /ProcessImageName:|SDN:/.test(l)) ? "mpdetection" : "mplog";
  return null;
}

interface Placed {
  input: InputFile;
  root: string | null;
  sysPath: string;
  role: Role | null;
}

const LOOSE_SYS: Partial<Record<Role, (name: string) => string>> = {
  evtx: (n) => `C:\\Windows\\System32\\winevt\\Logs\\${/\.evtx$/i.test(n) ? n : "Microsoft-Windows-Windows Defender%4Operational.evtx"}`,
  software: () => "C:\\Windows\\System32\\config\\SOFTWARE",
  entry: (n) => `C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine\\Entries\\${n}`,
  resources: (n) => `C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine\\Resources\\${n.slice(0, 2).toUpperCase()}\\${n}`,
  resourcedata: (n) => `C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine\\ResourceData\\${n.slice(0, 2).toUpperCase()}\\${n}`,
  history: (n) => `C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Service\\DetectionHistory\\${n}`,
  mplog: (n) => `C:\\ProgramData\\Microsoft\\Windows Defender\\Support\\${n}`,
  mpdetection: (n) => `C:\\ProgramData\\Microsoft\\Windows Defender\\Support\\${n}`,
  mpcmdrun: (n) => `C:\\Windows\\Temp\\${n}`,
};

/** A name for an ID: "Severe", or null. */
const nm = (n: NamedId) => n.name ?? (n.id !== null ? `ID ${n.id}` : null);

export function analyze(inputs: InputFile[], evtx: EvtxFileRaw[] = []): Analysis {
  const evtxByPath = new Map(evtx.map((e) => [e.path, e]));
  // 1. Place every file on a host: by where it sat, else by what it is.
  const placed: Placed[] = inputs.map((input) => {
    const p = place(input.path);
    if (p.placed) return { input, root: p.root, sysPath: p.sysPath, role: roleOf(p.sysPath) as Role | null };
    const role = evtxByPath.has(input.path) ? "evtx" : sniffLoose(input);
    const sysPath = role && LOOSE_SYS[role] ? LOOSE_SYS[role]!(p.sysPath) : p.sysPath;
    return { input, root: null, sysPath, role };
  });
  const roots = [...new Set(placed.filter((x) => x.root !== null).map((x) => x.root!))];
  const looseRoot = roots.length === 1 ? roots[0] : "";
  const byRoot = new Map<string, Placed[]>();
  for (const x of placed) {
    const r = x.root ?? looseRoot;
    if (!byRoot.has(r)) byRoot.set(r, []);
    byRoot.get(r)!.push(x);
  }

  const a: Analysis = { hosts: [], detections: [], events: [], history: [], quarantine: [], mplog: [], commands: [], registry: [], keys: [], changes: [], files: [], newest: null };
  let seq = 0;
  const names = new Set<string>();

  for (const [root, list] of byRoot) {
    let name = root ? root.split("/").filter(Boolean).pop()! : "collection";
    if (names.has(name)) name = root || `collection ${names.size + 1}`;
    names.add(name);
    const host: Host = { root, name, users: [], files: {}, newest: null };
    a.hosts.push(host);
    const reports = new Map<Placed, FileReport>();
    for (const x of list) {
      const r: FileReport = {
        path: x.input.path,
        sysPath: x.sysPath,
        host: name,
        role: x.role ?? "unknown",
        status: x.role ? "empty" : "unrecognised",
        size: x.input.bytes.length,
        mtime: x.input.mtime,
        ...(x.input.mtimeApprox ? { mtimeApprox: true } : {}),
        records: 0,
        unparsed: [],
        unparsedCount: 0,
        first: null,
        last: null,
        notes: [],
      };
      reports.set(x, r);
      a.files.push(r);
      if (x.role) host.files[x.role] = (host.files[x.role] ?? 0) + 1;
    }
    const seeRange = (r: FileReport, t: number | null) => {
      if (t === null) return;
      if (r.first === null || t < r.first) r.first = t;
      if (r.last === null || t > r.last) r.last = t;
    };
    const fail = (x: Placed, err: unknown) => {
      const r = reports.get(x)!;
      r.status = "error";
      r.error = errText(err);
    };
    const of = (role: Role) => list.filter((x) => x.role === role);
    const users = new Set<string>();

    // --- Operational log.
    const events: OpEvent[] = [];
    for (const x of of("evtx")) {
      const r = reports.get(x)!;
      const raw = evtxByPath.get(x.input.path);
      if (!raw) {
        r.status = "not-read";
        r.notes.push({ code: "evtx_not_read" });
        continue;
      }
      if (raw.error) {
        fail(x, new Error(raw.error));
        continue;
      }
      let other = 0;
      for (const rec of raw.records) {
        if (!/windows defender/i.test(rec.provider)) other++;
        const ev: OpEvent = {
          id: `e${++seq}`,
          host: name,
          file: x.input.path,
          recordId: rec.recordId,
          time: parseIsoUtc(rec.timestamp),
          eventId: rec.eventId,
          level: rec.level,
          provider: rec.provider,
          computer: rec.computer,
          data: rec.data,
          xml: rec.xml,
        };
        const sid = /<Security\s+UserID="([^"]{1,200})"/.exec(rec.xml)?.[1];
        if (sid) ev.userSid = sid;
        events.push(ev);
        seeRange(r, ev.time);
      }
      r.records = raw.records.length;
      r.status = raw.records.length ? "parsed" : "empty";
      if (raw.total > raw.records.length) r.notes.push({ code: "evtx_capped", params: { n: String(raw.records.length), total: String(raw.total) } });
      if (other) r.notes.push({ code: "evtx_other_provider", params: { n: String(other) } });
    }
    events.sort((p, q) => (p.time ?? 0) - (q.time ?? 0) || p.recordId - q.recordId);

    // --- DetectionHistory.
    const history: HistoryRecord[] = [];
    for (const x of of("history")) {
      const r = reports.get(x)!;
      try {
        if (x.input.bytes.length > MAX_HISTORY_BYTES) throw new Error("larger than 4 MB: not a DetectionHistory file");
        const h = readHistory(x.input.bytes);
        if (h.problems.includes("not_history_start") && !h.threatName) {
          r.status = "unrecognised";
          r.notes.push({ code: "history_not" });
          continue;
        }
        const rec: HistoryRecord = {
          id: `h${++seq}`,
          host: name,
          file: x.input.path,
          ...(h.detectionId ? { detectionId: h.detectionId } : {}),
          threatId: h.threatId,
          threatName: h.threatName,
          severityId: h.severityId,
          categoryId: h.categoryId,
          threatStatusId: h.threatStatusId,
          statusChanged: h.statusChanged,
          statusErrorCode: h.statusErrorCode,
          quarantineId: h.quarantineId,
          executionStatusId: h.executionStatusId,
          user: h.user,
          sourceTypeId: h.sourceTypeId,
          process: h.process,
          initialDetection: h.initialDetection,
          remediation: h.remediation,
          resources: h.resources,
          sha256: trackingValue(h, "ThreatTrackingSha256")?.toLowerCase(),
          sha1: trackingValue(h, "ThreatTrackingSha1")?.toLowerCase(),
          md5: trackingValue(h, "ThreatTrackingMD5")?.toLowerCase(),
          size: trackingValue(h, "ThreatTrackingSize"),
          unknown: h.unknown,
          problems: h.problems,
        };
        for (const k of ["sha256", "sha1", "md5", "size"] as const) if (rec[k] === undefined) delete rec[k];
        const fileGuid = norm(baseName(x.sysPath));
        if (rec.detectionId && fileGuid && /^[0-9A-F-]{36}$/.test(fileGuid) && fileGuid !== norm(rec.detectionId)) r.notes.push({ code: "history_name_differs", params: { id: rec.detectionId } });
        history.push(rec);
        r.records = 1;
        r.status = "parsed";
        seeRange(r, rec.initialDetection);
        seeRange(r, rec.statusChanged);
        if (h.problems.length) r.notes.push({ code: "problems", params: { list: [...new Set(h.problems)].slice(0, 8).join(", ") } });
      } catch (err) {
        fail(x, err);
      }
    }

    // --- Quarantine: entries, then the contents and records they name.
    const entries: QuarantineEntry[] = [];
    for (const x of of("entry")) {
      const r = reports.get(x)!;
      try {
        const e = readEntry(x.input.bytes);
        const entry: QuarantineEntry = {
          id: `q${++seq}`,
          host: name,
          file: x.input.path,
          guid: e.guid,
          scanId: e.scanId,
          time: e.time,
          threatId: e.threatId,
          threatName: e.threatName,
          resources: e.resources.map(
            (res): QuarantineResource => ({
              kind: res.kind,
              path: res.path,
              display: plainPath(res.physicalPath || res.path),
              ...(res.resourceId ? { resourceId: res.resourceId } : {}),
              ...(res.attributes !== undefined ? { attributes: res.attributes } : {}),
              ...(res.size !== undefined ? { size: res.size } : {}),
              created: res.created ?? null,
              accessed: res.accessed ?? null,
              written: res.written ?? null,
              fields: res.fields,
              problems: res.problems,
            }),
          ),
          magic: e.magic,
          crc: e.crc,
          problems: e.problems,
        };
        entries.push(entry);
        r.records = entry.resources.length;
        r.status = "parsed";
        seeRange(r, entry.time);
        if (!e.magic) r.notes.push({ code: "q_no_magic" });
        if (e.crc.includes("mismatch")) r.notes.push({ code: "q_crc" });
        const fileGuid = norm(baseName(x.sysPath));
        if (entry.guid && fileGuid && /^[0-9A-F-]{36}$/.test(fileGuid) && fileGuid !== entry.guid) r.notes.push({ code: "q_name_differs", params: { id: entry.guid } });
        const probs = [...e.problems.filter((p) => p !== "magic"), ...e.resources.flatMap((x2) => x2.problems)];
        if (probs.length) r.notes.push({ code: "problems", params: { list: [...new Set(probs)].slice(0, 8).join(", ") } });
      } catch (err) {
        fail(x, err);
      }
    }
    const resById = new Map<string, QuarantineResource[]>();
    for (const e of entries) for (const res of e.resources) if (res.resourceId) resById.set(res.resourceId, [...(resById.get(res.resourceId) ?? []), res]);
    for (const x of of("resourcedata")) {
      const r = reports.get(x)!;
      const fileName = baseName(x.sysPath).toUpperCase();
      try {
        const d = readResourceData(x.input.bytes);
        const info: ResourceDataInfo = {
          file: x.input.path,
          size: x.input.bytes.length,
          name: fileName,
          contentSha1: d.contentSha1,
          nameMatches: fileName === d.contentSha1 ? "content" : d.file && fileName === d.file.sha1.toUpperCase() ? "file" : "none",
          hive: d.hive,
          sparse: d.sparse,
          streams: d.streams.map((s) => ({ kind: s.kind, attributes: s.attributes, name: s.name, size: s.size, kindName: STREAM_KINDS[s.kind] ?? `kind ${s.kind}` })),
          ...(d.file ? { recovered: { size: d.file.size, md5: d.file.md5, sha1: d.file.sha1, sha256: d.file.sha256 } } : {}),
          ...(d.zone ? { zone: d.zone } : {}),
          ...(d.owner ? { owner: d.owner } : {}),
          ...(d.group ? { group: d.group } : {}),
          problems: d.problems,
        };
        r.records = d.streams.length || (d.hive ? 1 : 0);
        r.status = "parsed";
        r.notes.push({ code: `rd_name_${info.nameMatches}` });
        if (d.hive) r.notes.push({ code: "rd_hive" });
        if (d.sparse) r.notes.push({ code: "rd_sparse" });
        if (d.problems.length) r.notes.push({ code: "problems", params: { list: [...new Set(d.problems)].join(", ") } });
        const owners = resById.get(fileName);
        if (owners) for (const res of owners) res.data = info;
        else r.notes.push({ code: "rd_no_entry" });
      } catch (err) {
        fail(x, err);
        const owners = resById.get(fileName);
        if (owners) for (const res of owners) res.data = { file: x.input.path, size: x.input.bytes.length, name: fileName, contentSha1: "", nameMatches: "none", hive: false, sparse: false, streams: [], problems: [], error: errText(err) };
      }
    }
    for (const x of of("resources")) {
      const r = reports.get(x)!;
      try {
        const rec = readResourceRecord(x.input.bytes);
        r.records = rec.entries.length;
        r.status = "parsed";
        const owners = rec.resourceId ? resById.get(rec.resourceId) : undefined;
        if (owners) for (const res of owners) res.record = { file: x.input.path, ...(rec.dataSize !== undefined ? { dataSize: rec.dataSize } : {}), entries: rec.entries };
        else r.notes.push({ code: "rd_no_entry" });
        if (rec.problems.filter((p) => p !== "magic").length) r.notes.push({ code: "problems", params: { list: rec.problems.join(", ") } });
      } catch (err) {
        fail(x, err);
      }
    }
    for (const e of entries) for (const res of e.resources) if (res.resourceId && !res.data && res.kind === "file") res.problems.push("content_not_collected");

    // --- MPLog and MPDetection.
    const mplog: MpLine[] = [];
    for (const x of [...of("mplog"), ...of("mpdetection")]) {
      const r = reports.get(x)!;
      try {
        const res = parseMpLog(x.input.bytes);
        Object.assign(r, { encoding: res.encoding, bom: res.bom, lineEnding: res.lineEnding, lines: res.lines, unparsed: res.unparsed, unparsedCount: res.unparsedCount });
        const kinds: Record<string, number> = {};
        let noZone = 0;
        for (const e of res.entries) {
          kinds[e.kind] = (kinds[e.kind] ?? 0) + 1;
          if (e.time === null && e.stamp) noZone++;
          const line: MpLine = { id: `m${++seq}`, host: name, file: x.input.path, line: e.line, span: e.span, kind: e.kind, stamp: e.stamp, time: e.time, zone: e.zone, fields: e.fields, raw: e.raw };
          mplog.push(line);
          seeRange(r, e.time);
        }
        r.kinds = kinds;
        r.noZone = noZone;
        r.records = res.entries.length;
        r.status = res.entries.length ? "parsed" : "empty";
        if (res.cut) r.notes.push({ code: "cut" });
        if (res.dropped) r.notes.push({ code: "mplog_dropped", params: { n: String(res.dropped) } });
        if (noZone) r.notes.push({ code: "mplog_no_zone", params: { n: String(noZone) } });
        if (res.other) r.notes.push({ code: "mplog_other", params: { n: String(res.other) } });
        if (res.encoding !== "utf-16le") r.notes.push({ code: "encoding_unexpected", params: { expected: "UTF-16LE" } });
      } catch (err) {
        fail(x, err);
      }
    }

    // --- MpCmdRun.log.
    const commands: MpCmd[] = [];
    for (const x of of("mpcmdrun")) {
      const r = reports.get(x)!;
      try {
        const res = parseMpCmdRun(x.input.bytes);
        Object.assign(r, { encoding: res.encoding, bom: res.bom, lineEnding: res.lineEnding, lines: res.lines });
        const user = userFromPath(x.sysPath);
        if (user) users.add(user);
        for (const run of res.runs) {
          commands.push({ id: `c${++seq}`, host: name, file: x.input.path, line: run.line, ...(user ? { user } : {}), command: run.command, kind: run.kind, ...(run.startText ? { startText: run.startText } : {}), ...(run.endText ? { endText: run.endText } : {}), startWall: run.start, detail: run.detail });
        }
        r.records = res.runs.length;
        r.status = res.runs.length ? "parsed" : "empty";
        if (res.runs.length) r.notes.push({ code: "cmd_local_time" });
        if (res.cut) r.notes.push({ code: "cut" });
      } catch (err) {
        fail(x, err);
      }
    }

    // --- SOFTWARE: the Defender keys only.
    const registry: RegSetting[] = [];
    const keys: RegKeyInfo[] = [];
    for (const x of of("software")) {
      const r = reports.get(x)!;
      try {
        const hive = openHive(x.input.bytes);
        if (hive.dirty) r.notes.push({ code: "hive_dirty" });
        if (hive.truncated) r.notes.push({ code: "hive_truncated" });
        const res = readDefenderKeys(hive);
        if (hive.damaged) r.notes.push({ code: "hive_damaged", params: { n: String(hive.damaged) } });
        for (const k of res.damaged) r.notes.push({ code: "key_damaged", params: { key: k } });
        if (res.absent) r.notes.push({ code: "no_defender_keys" });
        for (const k of res.keys) {
          keys.push({ host: name, file: x.input.path, keyPath: k.keyPath, group: k.group, policy: k.policy, ...(k.exclusionKind ? { exclusionKind: k.exclusionKind } : {}), lastWrite: k.lastWrite, values: k.values.length });
          seeRange(r, k.lastWrite);
          for (const v of k.values) {
            registry.push({ id: `r${++seq}`, host: name, file: x.input.path, keyPath: k.keyPath, keyLastWrite: k.lastWrite, group: k.group, policy: k.policy, ...(k.exclusionKind ? { exclusionKind: k.exclusionKind } : {}), name: v.name, typeName: v.typeName, text: v.text, ...(v.num !== undefined ? { num: v.num } : {}), ...(v.meaning ? { meaning: v.meaning } : {}) });
          }
        }
        r.records = res.keys.reduce((n, k) => n + k.values.length, 0);
        r.status = res.keys.length ? "parsed" : "empty";
      } catch (err) {
        fail(x, err instanceof HiveError ? err : new Error(errText(err)));
      }
    }

    for (const x of list) {
      if (x.role === "defender-other") {
        const r = reports.get(x)!;
        r.status = "not-read";
        r.notes.push({ code: "not_read" });
      }
    }

    // --- 3. Detections.
    const detections: Detection[] = [];
    const empty = (id: number | null = null): NamedId => ({ id, name: null, from: null });
    const newDetection = (): Detection => ({
      id: `d${++seq}`,
      host: name,
      time: null,
      timeFrom: null,
      threatName: "",
      severity: empty(),
      category: empty(),
      path: "",
      resources: [],
      source: empty(),
      origin: empty(),
      action: empty(),
      result: "unknown",
      quarantined: null,
      hashes: { from: [] },
      amsi: false,
      events: [],
      history: [],
      quarantine: [],
      mplog: [],
      joins: [],
      flags: [],
    });
    // 3a. Threat events, by Detection ID.
    const byDetectionId = new Map<string, Detection>();
    for (const ev of events) {
      if (ev.eventId === null || !THREAT_EVENTS.has(ev.eventId)) continue;
      const did = norm(field(ev.data, "Detection ID"));
      let d = did ? byDetectionId.get(did) : undefined;
      if (!d) {
        d = newDetection();
        if (did) {
          d.detectionId = did;
          byDetectionId.set(did, d);
        }
        detections.push(d);
      } else d.joins.push({ source: "event", how: "same_detection_id", params: { event: String(ev.eventId), id: did! } });
      d.events.push(ev);
      ev.detection = d.id;
    }
    // 3b. DetectionHistory, by the same Detection ID.
    for (const h of history) {
      const did = norm(h.detectionId);
      let d = did ? byDetectionId.get(did) : undefined;
      if (d) d.joins.push({ source: "history", how: "history_detection_id", params: { id: did! } });
      else {
        d = newDetection();
        if (did) {
          d.detectionId = did;
          byDetectionId.set(did, d);
        }
        detections.push(d);
      }
      d.history.push(h);
      h.detection = d.id;
    }
    // Fill each detection from what it has so far, so entries and lines can be matched to it.
    for (const d of detections) fill(d);
    // 3c. Quarantine entries.
    for (const e of entries) {
      const viaHistory = detections.find((d) => d.history.some((h) => h.quarantineId && norm(h.quarantineId) === norm(e.guid)));
      let d = viaHistory;
      if (d) d.joins.push({ source: "quarantine", how: "history_quarantine_id", params: { id: e.guid ?? "" } });
      else {
        const paths = e.resources.map((r) => pathKey(r.display));
        let best: { d: Detection; delta: number } | null = null;
        for (const c of detections) {
          if (c.quarantine.length || !e.threatName || lower(c.threatName) !== lower(e.threatName) || c.time === null || e.time === null) continue;
          if (!c.resources.some((r) => paths.includes(pathKey(r.location)))) continue;
          const delta = Math.abs(e.time - c.time);
          if (delta <= QUARANTINE_WINDOW && (!best || delta < best.delta)) best = { d: c, delta };
        }
        if (best) {
          d = best.d;
          d.joins.push({ source: "quarantine", how: "quarantine_threat_path_time", params: { seconds: String(Math.round(best.delta / 1000)) } });
        }
      }
      if (!d) {
        d = newDetection();
        detections.push(d);
      }
      d.quarantine.push(e);
      e.detection = d.id;
      fill(d);
    }
    // 3d. MPLog detection lines, then the SDN line of the same path.
    const detLines = mplog.filter((m) => m.kind === "detection_add" || m.kind === "detection_event" || m.kind === "detection_clean");
    for (const m of detLines) {
      const threat = lower(m.fields.ThreatName);
      const path = m.fields.Path ? pathKey(m.fields.Path) : "";
      let best: { d: Detection; delta: number } | null = null;
      if (m.time !== null) {
        for (const c of detections) {
          if (lower(c.threatName) !== threat || c.time === null) continue;
          if (path && !c.resources.some((r) => pathKey(r.location) === path)) continue;
          const delta = Math.abs(m.time - c.time);
          if (delta <= MPLOG_WINDOW && (!best || delta < best.delta)) best = { d: c, delta };
        }
      }
      let d = best?.d;
      if (d) d.joins.push({ source: "mplog", how: path ? "mplog_threat_path_time" : "mplog_threat_time", params: { line: String(m.line), seconds: String(Math.round(best!.delta / 1000)) } });
      else {
        // A detection only MPLog recorded: lines of the same threat and path within a minute make one.
        d = detections.find((c) => c.events.length === 0 && c.history.length === 0 && c.quarantine.length === 0 && c.mplog.some((o) => lower(o.fields.ThreatName) === threat && (!path || !o.fields.Path || pathKey(o.fields.Path) === path) && o.time !== null && m.time !== null && Math.abs(o.time - m.time) <= MINUTE));
        if (d) d.joins.push({ source: "mplog", how: "mplog_same_detection", params: { line: String(m.line) } });
        else {
          d = newDetection();
          detections.push(d);
        }
      }
      d.mplog.push(m);
      m.detection = d.id;
      fill(d);
    }
    const sdn = mplog.filter((m) => m.kind === "sdn" && m.time !== null && m.fields.Path);
    for (const d of detections) {
      if (d.time === null) continue;
      const paths = new Set(d.resources.map((r) => pathKey(r.location)));
      const hit = sdn.filter((m) => !m.detection && paths.has(pathKey(m.fields.Path)) && m.time! <= d.time! + MINUTE && d.time! - m.time! <= SDN_WINDOW).sort((p, q) => q.time! - p.time!)[0];
      if (hit) {
        d.mplog.push(hit);
        hit.detection = d.id;
        d.joins.push({ source: "mplog", how: "sdn_same_path", params: { line: String(hit.line), seconds: String(Math.round((d.time - hit.time!) / 1000)) } });
        fill(d);
      }
    }
    for (const d of detections) {
      d.mplog.sort((p, q) => p.line - q.line);
      const u = d.user?.split("\\").pop();
      if (u && !/^(?:system|local service|network service)$/i.test(u) && !/\$$/.test(u)) users.add(u);
    }

    // --- 4. Protection changes.
    const changes: Change[] = [];
    const change = (c: Omit<Change, "id" | "host" | "flags">): Change => {
      const ch: Change = { id: `x${++seq}`, host: name, flags: [], ...c };
      changes.push(ch);
      return ch;
    };
    for (const ev of events) {
      const id = ev.eventId;
      if (id === null) continue;
      const d = ev.data;
      const base = { time: ev.time, source: "event" as const, event: ev };
      let ch: Change | null = null;
      if (id === 5007) {
        const oldV = parseRegChange(field(d, "Old Value"));
        const newV = parseRegChange(field(d, "New Value"));
        const r = newV ?? oldV;
        if (r?.exclusionKind) {
          ch = change({ ...base, what: newV && oldV ? "exclusion_changed" : newV ? "exclusion_added" : "exclusion_removed", params: { kind: r.exclusionKind, value: r.name, ...(r.policy ? { policy: "yes" } : {}) } });
        } else if (r) {
          ch = change({ ...base, what: "setting_changed", params: { name: r.name, key: r.key, old: oldV?.value ?? "", new: newV?.value ?? "" } });
        } else ch = change({ ...base, what: "setting_changed", params: { name: "", key: "", old: "", new: "" } });
      } else if (id === 5013) {
        const r = parseRegChange(field(d, "Value"));
        ch = change({ ...base, what: "tamper_blocked", params: { name: r?.name ?? "", key: r?.key ?? "", value: r?.value ?? field(d, "Value") ?? "" } });
      } else if (id === 5001) ch = change({ ...base, what: "rtp_disabled", params: {} });
      else if (id === 5000) ch = change({ ...base, what: "rtp_enabled", params: {} });
      else if (id === 5010) ch = change({ ...base, what: "antispyware_disabled", params: {} });
      else if (id === 5012) ch = change({ ...base, what: "antivirus_disabled", params: {} });
      else if (id === 5009) ch = change({ ...base, what: "antispyware_enabled", params: {} });
      else if (id === 5011) ch = change({ ...base, what: "antivirus_enabled", params: {} });
      else if (id === 5004) ch = change({ ...base, what: "rtp_feature_configured", params: { feature: field(d, "Feature Name", "Feature") ?? "", configuration: field(d, "Configuration") ?? "" } });
      else if (id === 5008) ch = change({ ...base, what: "engine_failure", params: { resource: field(d, "Resource") ?? "", failure: field(d, "Failure Type") ?? "", code: field(d, "Exception Code") ?? "" } });
      else if (id === 3002) ch = change({ ...base, what: "rtp_feature_failure", params: { feature: field(d, "Feature Name", "Feature") ?? "", reason: field(d, "Reason") ?? "", code: field(d, "Error Code") ?? "" } });
      else if (id === 1009 || id === 1010 || id === 1011 || id === 1012) {
        ch = change({
          ...base,
          what: { 1009: "quarantine_restored", 1010: "restore_failed", 1011: "quarantine_deleted", 1012: "delete_failed" }[id]!,
          params: { threat: field(d, "Threat Name") ?? "", path: parseResources(field(d, "Path", "Path Found"))[0]?.location ?? "", user: userOf(d) ?? "" },
        });
      } else if (id === 1013 || id === 1014) ch = change({ ...base, what: id === 1013 ? "history_deleted" : "history_delete_failed", params: { user: userOf(d) ?? "", timestamp: field(d, "Timestamp") ?? "" } });
      if (ch) ev.change = ch.id;
    }
    for (const g of registry) {
      if (g.exclusionKind) {
        change({ time: g.keyLastWrite, source: "registry", reg: g, what: "exclusion_present", params: { kind: g.exclusionKind, value: g.name, ...(g.policy ? { policy: "yes" } : {}) } });
      } else if (g.meaning || /^disable/i.test(g.name)) {
        if (g.group === "defender" && !/^disable/i.test(g.name)) continue;
        change({ time: g.keyLastWrite, source: "registry", reg: g, what: "setting_present", params: { name: g.name, value: g.text, key: g.keyPath, ...(g.meaning ? { meaning: g.meaning } : {}), ...(g.policy ? { policy: "yes" } : {}) } });
      }
    }
    for (const c of commands) {
      const ch = change({ time: null, ...(c.startText ? { localTime: c.startText } : {}), source: "command", cmd: c, what: "command", params: { kind: c.kind, command: c.command } });
      c.change = ch.id;
    }

    a.detections.push(...detections);
    a.events.push(...events);
    a.history.push(...history);
    a.quarantine.push(...entries);
    a.mplog.push(...mplog);
    a.commands.push(...commands);
    a.registry.push(...registry);
    a.keys.push(...keys);
    a.changes.push(...changes);
    host.users = [...users].sort((p, q) => p.localeCompare(q));

    // Newest UTC time of the host.
    let newest: number | null = null;
    const see = (t: number | null | undefined) => {
      if (t !== null && t !== undefined && (newest === null || t > newest)) newest = t;
    };
    for (const e of events) see(e.time);
    for (const h of history) {
      see(h.initialDetection);
      see(h.statusChanged);
    }
    for (const e of entries) see(e.time);
    for (const m of mplog) see(m.time);
    for (const k of keys) see(k.lastWrite);
    host.newest = newest;

    flagHost(host, detections, changes);
  }

  const rank = (flags: Flag[]) => {
    const w = worst(flags.filter((f) => f.severity !== "info"));
    return w === null ? 4 : SEVERITY_RANK[w];
  };
  a.detections.sort((p, q) => rank(p.flags) - rank(q.flags) || (q.time ?? -Infinity) - (p.time ?? -Infinity));
  a.changes.sort((p, q) => (p.time ?? Infinity) - (q.time ?? Infinity) || p.id.localeCompare(q.id, "en", { numeric: true }));
  a.newest = a.hosts.reduce<number | null>((n, h) => (h.newest !== null && (n === null || h.newest > n) ? h.newest : n), null);
  return a;
}

/** "Detection User" (1116+), else "Domain\User" (1006–1013). */
function userOf(d: [string, string][]): string | undefined {
  const u = field(d, "Detection User", "Remediation User");
  if (u) return u;
  const dom = field(d, "Domain");
  const usr = field(d, "User");
  return usr ? (dom ? `${dom}\\${usr}` : usr) : undefined;
}

/** A detection's fields from its sources: events first (1116, then the action events), then DetectionHistory, the quarantine entry, MPLog. */
function fill(d: Detection) {
  const detect = d.events.find((e) => e.eventId === 1116 || e.eventId === 1006 || e.eventId === 1015) ?? d.events[0];
  const actions = d.events.filter((e) => e.eventId !== null && ACTION_EVENTS.has(e.eventId));
  const lastAction = actions[actions.length - 1];
  const h = d.history[0];
  const q = d.quarantine[0];
  const m = d.mplog.find((x) => x.kind === "detection_add") ?? d.mplog.find((x) => x.kind !== "sdn");

  // Time.
  const evTime = detect ? (parseIsoUtc(field(detect.data, "Detection Time") ?? "") ?? detect.time) : null;
  if (evTime !== null) [d.time, d.timeFrom] = [evTime, "event"];
  else if (h?.initialDetection) [d.time, d.timeFrom] = [h.initialDetection, "history"];
  else if (q?.time) [d.time, d.timeFrom] = [q.time, "quarantine"];
  else if (m?.time) [d.time, d.timeFrom] = [m.time, "mplog"];

  // Threat.
  const evData = detect?.data ?? [];
  d.threatName = field(evData, "Threat Name") ?? h?.threatName ?? q?.threatName ?? m?.fields.ThreatName ?? "";
  d.threatId = field(evData, "Threat ID") ?? h?.threatId ?? q?.threatId;
  if (d.threatId === undefined) delete d.threatId;
  d.severity = named(field(evData, "Severity ID") ?? (h?.severityId !== undefined ? String(h.severityId) : undefined), field(evData, "Severity Name"), SEVERITY);
  d.category = named(field(evData, "Category ID") ?? (h?.categoryId !== undefined ? String(h.categoryId) : undefined), field(evData, "Category Name"), CATEGORIES);

  // Where.
  const evRes = parseResources(field(evData, "Path", "Path Found"));
  const hRes = (h?.resources ?? []).map((r) => ({ schema: r.kind.toLowerCase(), location: r.location }));
  const qRes = (q?.resources ?? []).map((r) => ({ schema: r.kind.toLowerCase(), location: r.display }));
  const mRes = d.mplog.filter((x) => x.fields.Path && x.kind !== "sdn").map((x) => ({ schema: x.fields.Schema ?? "file", location: x.fields.Path }));
  const all = [...evRes, ...hRes, ...qRes, ...mRes];
  const seen = new Set<string>();
  d.resources = all.filter((r) => {
    const k = `${r.schema}|${pathKey(r.location)}`;
    if (seen.has(k) || !r.location) return false;
    seen.add(k);
    return true;
  });
  const fileLike = d.resources.find((r) => /^(?:file|containerfile|webfile)$/.test(r.schema));
  d.path = plainPath((fileLike ?? d.resources[0])?.location.split("|")[0] ?? "");

  // Who, what, how.
  const user = userOf(evData) ?? h?.user;
  if (user) d.user = user;
  const proc = field(evData, "Process Name") ?? h?.process;
  if (proc) d.process = proc;
  d.source = named(field(evData, "Source ID", "Detection Source Index") ?? (h?.sourceTypeId !== undefined ? String(h.sourceTypeId) : undefined), field(evData, "Source Name", "Detection Source"), SOURCES);
  d.origin = named(field(evData, "Origin ID"), field(evData, "Origin Name"), {});
  if (lastAction) {
    d.action = named(field(lastAction.data, "Action ID", "Cleaning Action Index"), field(lastAction.data, "Action Name", "Cleaning Action"), ACTIONS);
    const code = field(lastAction.data, "Error Code");
    if (code) d.errorCode = code;
    const text = field(lastAction.data, "Error Description");
    if (text) d.errorText = text.trim();
  }
  if (h?.threatStatusId !== undefined) d.status = THREAT_STATUS[h.threatStatusId] ?? `status ${h.threatStatusId}`;

  // Result.
  const failedEv = d.events.some((e) => e.eventId !== null && FAILED_EVENTS.has(e.eventId));
  const errorBad = d.errorCode !== undefined && regNumber(d.errorCode) !== undefined && regNumber(d.errorCode) !== 0;
  const actionName = lower(nm(d.action) ?? "");
  if (failedEv || (h?.threatStatusId !== undefined && FAILED_STATUS.has(h.threatStatusId)) || (lastAction?.eventId === 1117 && errorBad)) d.result = "failed";
  else if (lastAction && (actionName === "allow" || actionName === "no action" || d.action.id === 6 || d.action.id === 9)) d.result = "allowed";
  else if (h?.threatStatusId === 5) d.result = "allowed";
  else if (lastAction || (h?.threatStatusId !== undefined && [2, 3, 4, 6].includes(h.threatStatusId)) || q) d.result = "done";
  else if (h?.threatStatusId === 1 || d.events.length) d.result = "none";
  else d.result = "unknown";
  const quarantinedAction = actionName === "quarantine" || d.action.id === 2;
  d.quarantined = q ? true : h?.threatStatusId === 3 || (quarantinedAction && d.result === "done") ? true : d.result === "done" || d.result === "allowed" ? false : null;

  // Hashes: from the quarantined content when there is one (the bytes themselves), else DetectionHistory's
  // tracking data, else MPLog's cloud query. Other sources are named when they agree, and listed when they differ.
  const sets: { src: string; sha256?: string; sha1?: string; md5?: string }[] = [];
  for (const qq of d.quarantine) for (const r of qq.resources) if (r.data?.recovered) sets.push({ src: "quarantine", ...r.data.recovered });
  for (const hh of d.history) if (hh.sha256 || hh.sha1 || hh.md5) sets.push({ src: "history", sha256: hh.sha256, sha1: hh.sha1, md5: hh.md5 });
  for (const x of d.mplog) if (x.fields.Sha256 || x.fields.Sha1) sets.push({ src: "mplog", sha256: x.fields.Sha256, sha1: x.fields.Sha1 });
  const hs: Detection["hashes"] = { from: [] };
  const low = (v?: string) => v?.toLowerCase();
  const agrees = (a: (typeof sets)[0], b: (typeof sets)[0]) =>
    (["sha256", "sha1", "md5"] as const).some((k) => a[k] && b[k] && low(a[k]) === low(b[k])) && !(["sha256", "sha1", "md5"] as const).some((k) => a[k] && b[k] && low(a[k]) !== low(b[k]));
  const first = sets[0];
  if (first) {
    for (const s of sets) {
      if (s !== first && !agrees(first, s)) {
        if (!(hs.differs ?? []).includes(s.src)) hs.differs = [...(hs.differs ?? []), s.src];
        continue;
      }
      for (const k of ["sha256", "sha1", "md5"] as const) if (!hs[k] && s[k]) hs[k] = low(s[k]);
      if (!hs.from.includes(s.src)) hs.from.push(s.src);
    }
  }
  d.hashes = hs;

  // AMSI: the event's own source name, a resource of type amsi, or source 10 (inferred).
  d.amsi = lower(textName(field(evData, "Source Name", "Detection Source"))) === "amsi" || d.resources.some((r) => r.schema === "amsi") || d.source.id === 10;
}

// ---------------------------------------------------------------------------
// 5. Flags

function flagHost(host: Host, detections: Detection[], changes: Change[]) {
  const add = (flags: Flag[], f: Flag) => {
    if (!flags.some((x) => x.code === f.code && x.severity === f.severity)) flags.push(f);
  };
  const recent = (t: number | null) => t !== null && host.newest !== null && t <= host.newest && host.newest - t <= RECENT;

  // Detections.
  const byHash = new Map<string, Set<string>>();
  for (const d of detections) {
    const h = d.hashes.sha256 ?? d.hashes.sha1;
    if (h && d.path) byHash.set(h, new Set([...(byHash.get(h) ?? []), pathKey(d.path)]));
  }
  for (const d of detections) {
    const f = d.flags;
    if (d.path) {
      const p = stagingPlace(d.path);
      if (p) add(f, { code: p.code, severity: p.code === "staging_path" ? "medium" : "low", params: { folder: p.folder } });
    }
    if (d.result === "failed") add(f, { code: "action_failed", severity: "high", params: { action: nm(d.action) ?? d.status ?? "?", error: d.errorCode ?? (d.history[0]?.statusErrorCode !== undefined ? String(d.history[0].statusErrorCode) : "") } });
    if (d.result === "allowed") add(f, { code: "action_allowed", severity: "high", params: { action: nm(d.action) ?? d.status ?? "?" } });
    if (d.amsi) add(f, { code: "amsi", severity: "medium", params: { process: d.process ?? "?" } });
    const hash = d.hashes.sha256 ?? d.hashes.sha1;
    const paths = hash ? byHash.get(hash) : undefined;
    if (hash && paths && paths.size > 1) add(f, { code: "same_hash", severity: "medium", params: { n: String(paths.size), hash: hash.slice(0, 16) } });
    if (recent(d.time)) add(f, { code: "recent", severity: "low", params: { date: new Date(d.time!).toISOString().slice(0, 10) } });
  }

  // Changes.
  for (const c of changes) {
    const f = c.flags;
    const p = c.params;
    if (c.what === "exclusion_added" || c.what === "exclusion_changed" || c.what === "exclusion_present") {
      const risks = exclusionRisks(p.kind, p.value);
      for (const r of risks) add(f, { code: r, severity: r === "exclusion_process_name" ? "medium" : "high", params: { kind: p.kind, value: p.value } });
      if (!risks.length) add(f, { code: "exclusion_other", severity: "low", params: { kind: p.kind, value: p.value } });
      if (c.time !== null) {
        for (const d of detections) {
          if (d.time === null || !d.path || Math.abs(d.time - c.time) > EXCLUSION_WINDOW) continue;
          if (!exclusionCovers(p.kind, p.value, d.path, d.process)) continue;
          const delta = Math.round((c.time - d.time) / 1000);
          const params = { kind: p.kind, value: p.value, threat: d.threatName, path: d.path, when: delta >= 0 ? "after" : "before", minutes: String(Math.max(1, Math.round(Math.abs(delta) / 60))), seconds: String(Math.abs(delta)), at: iso(c.time) };
          add(f, { code: "exclusion_near_detection", severity: "high", params });
          add(d.flags, { code: "exclusion_nearby", severity: "high", params });
        }
      }
    }
    if (c.what === "rtp_disabled") add(f, { code: "rtp_off", severity: "high" });
    if (c.what === "antispyware_disabled" || c.what === "antivirus_disabled") add(f, { code: "scanning_off", severity: "high" });
    if (c.what === "setting_changed" && /^disable/i.test(p.name) && regNumber(p.new) === 1) add(f, { code: "setting_off", severity: "high", params: { name: p.name } });
    if (c.what === "setting_present") {
      if (/^disable/i.test(p.name) && c.reg?.num === 1) add(f, { code: "setting_off", severity: "high", params: { name: p.name } });
      if (p.meaning === "tamper_off") add(f, { code: "tamper_off", severity: "medium", params: { value: p.value } });
      if (p.meaning === "maps_off") add(f, { code: "maps_off", severity: "low" });
    }
    if (c.what === "tamper_blocked") add(f, { code: "tamper_blocked", severity: "medium", params: { name: p.name || p.value } });
    if (c.what === "quarantine_restored") add(f, { code: "quarantine_restored", severity: "high", params: { threat: p.threat } });
    if (c.what === "quarantine_deleted") add(f, { code: "quarantine_deleted", severity: "medium", params: { threat: p.threat } });
    if (c.what === "history_deleted") add(f, { code: "history_deleted", severity: "medium", params: { user: p.user } });
    if (c.what === "command") {
      if (p.kind === "remove_definitions") add(f, { code: "remove_definitions", severity: "high" });
      else if (p.kind === "restore") add(f, { code: "quarantine_restored", severity: "high", params: { threat: "" } });
      else if (["remove_dynamic_signature", "add_dynamic_signature", "reset_platform", "revert_platform", "download_file"].includes(p.kind)) add(f, { code: "mpcmdrun_tamper", severity: "medium", params: { kind: p.kind } });
    }
    const flagged = f.some((x) => x.severity !== "info" && x.code !== "exclusion_other");
    if (flagged && recent(c.time)) add(f, { code: "recent", severity: "low", params: { date: new Date(c.time!).toISOString().slice(0, 10) } });
  }
  for (const x of [...detections, ...changes]) x.flags.sort((p, q) => SEVERITY_RANK[p.severity] - SEVERITY_RANK[q.severity]);
}
