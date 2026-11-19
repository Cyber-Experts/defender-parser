// The data model. The readers turn each source into records: Operational
// events, DetectionHistory files, quarantine entries and their content,
// MPLog lines, MpCmdRun runs and the SOFTWARE hive's Defender keys. The
// engine joins them into detections (one per threat found) and protection
// changes (settings, exclusions, commands), adds flags (why a row deserves a
// look) and reports each file. The UI, exports and findings only read these
// types. No recovered file content is ever part of them.

import type { CommandKind } from "./mpcmdrun";
import type { MpKind, MpZone } from "./mplog";
import type { NamedId } from "./evtx";
import type { ExclusionKind, RegGroup } from "./registry";
import type { QField, StreamInfo, ZoneIdentifier } from "./quarantine";
import type { HistoryResource } from "./history";

export type Severity = "high" | "medium" | "low" | "info";

/** Why a row deserves a look. `code` keys the explanation in the dictionary. */
export interface Flag {
  code: string;
  severity: Severity;
  params?: Record<string, string>;
}

export interface Note {
  code: string;
  params?: Record<string, string>;
}

export type LineEnding = "crlf" | "lf" | "cr" | "mixed" | "none";

export interface Unparsed {
  line: number;
  text: string;
  reason: string;
}

// ---------------------------------------------------------------------------
// Sources

/** One record of the Operational log. */
export interface OpEvent {
  id: string;
  host: string;
  file: string;
  recordId: number;
  /** TimeCreated, UTC. */
  time: number | null;
  eventId: number | null;
  level: number | null;
  provider: string;
  computer: string;
  /** Security UserID of the record (Defender writes as S-1-5-18). */
  userSid?: string;
  /** Event data pairs, as written. */
  data: [string, string][];
  /** The record's XML, as the reader rendered it (at most 16 KB). */
  xml: string;
  /** The detection it belongs to, if any. */
  detection?: string;
  /** The protection change it is, if any. */
  change?: string;
}

/** A DetectionHistory file. */
export interface HistoryRecord {
  id: string;
  host: string;
  file: string;
  detectionId?: string;
  threatId?: string;
  threatName?: string;
  severityId?: number;
  categoryId?: number;
  threatStatusId?: number;
  statusChanged: number | null;
  statusErrorCode?: number;
  quarantineId?: string;
  executionStatusId?: number;
  user?: string;
  sourceTypeId?: number;
  process?: string;
  initialDetection: number | null;
  remediation: number | null;
  resources: HistoryResource[];
  sha256?: string;
  sha1?: string;
  md5?: string;
  size?: string;
  unknown: [string, string][];
  problems: string[];
  detection?: string;
}

/** A quarantined resource's content (ResourceData), described. Its bytes are never kept. */
export interface ResourceDataInfo {
  /** Collection path of the ResourceData file. */
  file: string;
  /** The file's size on disk (encrypted). */
  size: number;
  /** Its name: 40 hex digits, upper case (when it is one). */
  name: string;
  /** SHA-1 of the whole decrypted content, upper case. */
  contentSha1: string;
  /** Which SHA-1 the file name equals: the decrypted content's, the recovered file's, or neither. */
  nameMatches: "content" | "file" | "none";
  hive: boolean;
  sparse: boolean;
  streams: (Pick<StreamInfo, "kind" | "attributes" | "name" | "size"> & { kindName: string })[];
  /** The recovered file: size and hashes. */
  recovered?: { size: number; md5: string; sha1: string; sha256: string };
  zone?: ZoneIdentifier;
  owner?: string;
  group?: string;
  problems: string[];
  error?: string;
}

export interface QuarantineResource {
  kind: string;
  /** As written (\\?\C:\…). */
  path: string;
  /** The path to show: the physical path field, else the path without \\?\. */
  display: string;
  resourceId?: string;
  attributes?: number;
  size?: number;
  created?: number | null;
  accessed?: number | null;
  written?: number | null;
  fields: QField[];
  problems: string[];
  /** The content, when its ResourceData file was collected. */
  data?: ResourceDataInfo;
  /** The Resources record of the content, when collected. */
  record?: { file: string; dataSize?: number; entries: string[] };
}

/** A quarantine entry (Entries\{GUID}). */
export interface QuarantineEntry {
  id: string;
  host: string;
  file: string;
  guid?: string;
  scanId?: string;
  /** When the threat was quarantined, UTC. */
  time: number | null;
  threatId?: string;
  threatName?: string;
  resources: QuarantineResource[];
  /** The header's magic numbers were found. */
  magic: boolean;
  crc: ("ok" | "mismatch" | "cut")[];
  problems: string[];
  detection?: string;
}

/** An MPLog or MPDetection entry (a line, or a block of lines). */
export interface MpLine {
  id: string;
  host: string;
  file: string;
  line: number;
  span: number;
  kind: MpKind;
  stamp: string;
  /** UTC when the line says so (Z or an offset); null for a time without a zone. */
  time: number | null;
  zone: MpZone;
  fields: Record<string, string>;
  raw: string;
  detection?: string;
}

/** One MpCmdRun.exe run from MpCmdRun.log. */
export interface MpCmd {
  id: string;
  host: string;
  file: string;
  line: number;
  /** The account whose %TEMP% held the log; undefined for C:\Windows\Temp. */
  user?: string;
  command: string;
  kind: CommandKind;
  /** As written: local time of the machine, zone not recorded. */
  startText?: string;
  endText?: string;
  /** The start read as if UTC, for ordering runs only. */
  startWall: number | null;
  detail: string[];
  change?: string;
}

/** A value of a Defender key of the SOFTWARE hive. */
export interface RegSetting {
  id: string;
  host: string;
  file: string;
  keyPath: string;
  keyLastWrite: number | null;
  group: RegGroup;
  policy: boolean;
  exclusionKind?: ExclusionKind;
  name: string;
  typeName: string;
  text: string;
  num?: number;
  meaning?: string;
}

/** A Defender key read (values or not), with its LastWrite time. */
export interface RegKeyInfo {
  host: string;
  file: string;
  keyPath: string;
  group: RegGroup;
  policy: boolean;
  exclusionKind?: ExclusionKind;
  lastWrite: number | null;
  values: number;
}

// ---------------------------------------------------------------------------
// Joined rows

/** How a source was tied to a detection. */
export interface JoinEvidence {
  source: "event" | "history" | "quarantine" | "mplog";
  /** Code (dictionary: join_<code>) and parameters. */
  how: string;
  params?: Record<string, string>;
}

export type ActionResult = "done" | "failed" | "allowed" | "none" | "unknown";

/** One detection: every source joined. */
export interface Detection {
  id: string;
  host: string;
  /** Detection ID (GUID) when a source gives one. */
  detectionId?: string;
  /** Detection time, UTC: the event's Detection Time, else DetectionHistory's, the quarantine's, MPLog's. */
  time: number | null;
  timeFrom: "event" | "history" | "quarantine" | "mplog" | null;
  threatName: string;
  threatId?: string;
  severity: NamedId;
  category: NamedId;
  /** Where it was found: the first file-like resource, else the first resource. */
  path: string;
  resources: { schema: string; location: string }[];
  user?: string;
  process?: string;
  source: NamedId;
  origin: NamedId;
  action: NamedId;
  result: ActionResult;
  errorCode?: string;
  errorText?: string;
  /** DetectionHistory's threat status. */
  status?: string;
  quarantined: boolean | null;
  /** From the quarantined content, else DetectionHistory, else MPLog; `from` names the sources that agree, `differs` those that give other hashes. */
  hashes: { sha256?: string; sha1?: string; md5?: string; from: string[]; differs?: string[] };
  amsi: boolean;
  events: OpEvent[];
  history: HistoryRecord[];
  quarantine: QuarantineEntry[];
  mplog: MpLine[];
  joins: JoinEvidence[];
  flags: Flag[];
}

export type ChangeSource = "event" | "registry" | "command";

/** A protection change: a setting, an exclusion, a blocked attempt, a command, a quarantine or history action. */
export interface Change {
  id: string;
  host: string;
  /** UTC when known. */
  time: number | null;
  /** For a command: its start as written (zone not recorded). */
  localTime?: string;
  source: ChangeSource;
  /** What happened (dictionary: change_<what>). */
  what: string;
  params: Record<string, string>;
  event?: OpEvent;
  reg?: RegSetting;
  cmd?: MpCmd;
  flags: Flag[];
}

export type FileRole = "evtx" | "entry" | "resourcedata" | "resources" | "history" | "mplog" | "mpdetection" | "mpcmdrun" | "software" | "defender-other" | "unknown";
export type FileStatus = "parsed" | "empty" | "unrecognised" | "not-read" | "error";

export interface FileReport {
  path: string;
  /** Where the file sat on Windows; for an unplaced file, its name. */
  sysPath: string;
  host: string;
  role: FileRole;
  status: FileStatus;
  size: number;
  mtime: number | null;
  mtimeApprox?: boolean;
  encoding?: string;
  bom?: boolean;
  lineEnding?: LineEnding;
  lines?: number;
  records: number;
  unparsed: Unparsed[];
  unparsedCount: number;
  first: number | null;
  last: number | null;
  /** MPLog: entries by kind. */
  kinds?: Record<string, number>;
  /** MPLog: entries whose time has no zone. */
  noZone?: number;
  notes: Note[];
  error?: string;
}

export interface Host {
  root: string;
  name: string;
  users: string[];
  files: Record<string, number>;
  /** Newest UTC time of the host's records (recency is judged against it). */
  newest: number | null;
}

export interface Analysis {
  hosts: Host[];
  detections: Detection[];
  events: OpEvent[];
  history: HistoryRecord[];
  quarantine: QuarantineEntry[];
  mplog: MpLine[];
  commands: MpCmd[];
  registry: RegSetting[];
  keys: RegKeyInfo[];
  changes: Change[];
  files: FileReport[];
  newest: number | null;
}

/** One input file as the engine receives it. */
export interface InputFile {
  path: string;
  bytes: Uint8Array;
  mtime: number | null;
  mtimeApprox?: boolean;
}
