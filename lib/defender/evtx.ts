// The Defender Operational log (Microsoft-Windows-Windows Defender%4
// Operational.evtx), read by EVTX Parser's WebAssembly reader
// (vendor/evtx, SOURCES.md): every record, its event data and its XML.
//
// Event IDs and their fields: Microsoft, "Microsoft Defender Antivirus event
// IDs and error codes"; the data field names as the raw XML holds them come
// from the example events of EvtxECmd's Defender maps (Eric Zimmerman's evtx
// repository) and dissect.target's Defender record fields. In the raw XML
// several "… Name" fields hold message-table references (%%818, %%887) that
// only the provider's message file turns into words; the tool then names the
// ID from documented tables, says so, and never guesses an undocumented one.

/** One record as the reader returns it. */
export interface EvtxRecordRaw {
  recordId: number;
  /** TimeCreated, ISO 8601 as the reader writes it. */
  timestamp: string;
  eventId: number | null;
  level: number | null;
  provider: string;
  channel: string;
  computer: string;
  data: [string, string][];
  xml: string;
}

export interface EvtxFileRaw {
  /** Collection path of the file. */
  path: string;
  records: EvtxRecordRaw[];
  /** Records in the file (more than `records` when capped). */
  total: number;
  error?: string;
}

/** Records read per file; the rest are counted. */
export const MAX_EVTX_RECORDS = 300_000;
/** EVTX files read up to this size. */
export const MAX_EVTX_BYTES = 256 * 1024 * 1024;
const MAX_XML = 16 * 1024;
const MAX_VALUE = 8 * 1024;

/** The part of EVTX Parser's EvtxHandle this site uses. */
export interface EvtxHandleLike {
  count(): bigint;
  get_chunk(start: bigint, len: bigint): unknown;
  get_event_data_batch(indices: Uint32Array): unknown;
  get_xml(index: bigint): string;
  free(): void;
}

const num = (v: unknown): number | null => (v === null || v === undefined ? null : Number.isFinite(Number(v)) ? Number(v) : null);
const str = (v: unknown): string => (typeof v === "string" ? v : v === null || v === undefined ? "" : String(v));

/** Read a file with the WebAssembly reader (`make` builds an EvtxHandle). Never throws. */
export function readEvtx(path: string, bytes: Uint8Array, make: (b: Uint8Array) => EvtxHandleLike): EvtxFileRaw {
  if (bytes.length > MAX_EVTX_BYTES) return { path, records: [], total: 0, error: `larger than ${MAX_EVTX_BYTES / 1_048_576} MB: not read` };
  let h: EvtxHandleLike | null = null;
  try {
    h = make(bytes);
    const total = Number(h.count());
    const take = Math.min(total, MAX_EVTX_RECORDS);
    const rows = (h.get_chunk(BigInt(0), BigInt(take)) as Record<string, unknown>[]) ?? [];
    const records: EvtxRecordRaw[] = [];
    for (let start = 0; start < rows.length; start += 2000) {
      const idx = Uint32Array.from({ length: Math.min(2000, rows.length - start) }, (_, i) => start + i);
      const data = (h.get_event_data_batch(idx) as [unknown, unknown][][]) ?? [];
      idx.forEach((i, k) => {
        const r = rows[i] ?? {};
        let xml = "";
        try {
          xml = h!.get_xml(BigInt(i));
        } catch {
          xml = "";
        }
        records.push({
          recordId: num(r.record_id) ?? 0,
          timestamp: str(r.timestamp),
          eventId: num(r.event_id),
          level: num(r.level),
          provider: str(r.provider),
          channel: str(r.channel),
          computer: str(r.computer),
          data: (data[k] ?? []).slice(0, 200).map(([a, b]) => [str(a).slice(0, 200), str(b).slice(0, MAX_VALUE)] as [string, string]),
          xml: xml.length > MAX_XML ? `${xml.slice(0, MAX_XML)}…` : xml,
        });
      });
    }
    return { path, records, total };
  } catch (err) {
    return { path, records: [], total: 0, error: err instanceof Error ? err.message : String(err) };
  } finally {
    try {
      h?.free();
    } catch {
      /* already freed or poisoned */
    }
  }
}

/** "2019-07-13T13:14:44.410427800Z" or "+00:00" → ms, UTC. */
export function parseIsoUtc(text: string): number | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:?\d{2})?$/.exec(text.trim());
  if (!m) return null;
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number);
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60) return null;
  let t = Date.UTC(y, mo - 1, d, h, mi, s, m[7] ? Number(m[7].padEnd(3, "0").slice(0, 3)) : 0);
  const z = m[8];
  if (z && z !== "Z") {
    const sign = z[0] === "+" ? 1 : -1;
    const digits = z.slice(1).replace(":", "");
    t -= sign * (Number(digits.slice(0, 2)) * 60 + Number(digits.slice(2, 4))) * 60_000;
  }
  return Number.isFinite(t) ? t : null;
}

// ---------------------------------------------------------------------------
// The events that matter (Microsoft's event ID reference)

/** Event IDs named by the tool; the label is in the dictionary (ev_<id>). */
export const NAMED_EVENTS = [
  1000, 1001, 1002, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015, 1116, 1117, 1118, 1119, 1120, 1121, 1122, 1127, 1150, 1151, 2000, 2001, 2002, 2003, 3002, 3007, 5000, 5001, 5004, 5007, 5008, 5009,
  5010, 5011, 5012, 5013,
] as const;

/** Detection and action events: one detection each, joined by Detection ID. */
export const THREAT_EVENTS = new Set([1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119]);
/** Events that record an action and its result. */
export const ACTION_EVENTS = new Set([1007, 1008, 1117, 1118, 1119]);
export const FAILED_EVENTS = new Set([1008, 1118, 1119]);

/** MSFT_MpThreat SeverityID (also the events' Severity ID). */
export const SEVERITY: Record<number, string> = { 0: "Unknown", 1: "Low", 2: "Moderate", 4: "High", 5: "Severe" };

/**
 * Detection sources: MSFT_MpThreatDetection's DetectionSourceTypeID documents
 * 0–5 and 7–9. 6, 10 and 11 follow the order of the detection sources in
 * Microsoft's event reference (IEPROTECT, AMSI, UAC): marked as inferred.
 */
export const SOURCES: Record<number, { name: string; inferred?: true }> = {
  0: { name: "Unknown" },
  1: { name: "User" },
  2: { name: "System" },
  3: { name: "Real-time" },
  4: { name: "IOAV" },
  5: { name: "NRI" },
  6: { name: "IEPROTECT", inferred: true },
  7: { name: "ELAM" },
  8: { name: "Local attestation" },
  9: { name: "Remote attestation" },
  10: { name: "AMSI", inferred: true },
  11: { name: "UAC", inferred: true },
};

/** Defender's threat actions (ThreatSeverityDefaultAction / Set-MpPreference): Action ID of 1117, 1007, 1008, 1118, 1119. */
export const ACTIONS: Record<number, string> = { 1: "Clean", 2: "Quarantine", 3: "Remove", 6: "Allow", 8: "User defined", 9: "No action", 10: "Block" };

/** Threat categories (Get-MpThreatCatalog numbering, as libyal and Yamato Security list it). */
export const CATEGORIES: Record<number, string> = {
  0: "Invalid", 1: "Adware", 2: "Spyware", 3: "Password stealer", 4: "Trojan downloader", 5: "Worm", 6: "Backdoor", 7: "Remote access trojan", 8: "Trojan", 9: "Email flooder", 10: "Keylogger", 11: "Dialer",
  12: "Monitoring software", 13: "Browser modifier", 14: "Cookie", 15: "Browser plugin", 16: "AOL exploit", 17: "Nuker", 18: "Security disabler", 19: "Joke program", 20: "Hostile ActiveX control",
  21: "Software bundler", 22: "Stealth notifier", 23: "Settings modifier", 24: "Toolbar", 25: "Remote control software", 26: "Trojan FTP", 27: "Potentially unwanted software", 28: "ICQ exploit",
  29: "Trojan telnet", 30: "Exploit", 31: "File-sharing program", 32: "Malware creation tool", 33: "Remote control software", 34: "Tool", 36: "Trojan denial of service", 37: "Trojan dropper",
  38: "Trojan mass mailer", 39: "Trojan monitoring software", 40: "Trojan proxy server", 42: "Virus", 43: "Known", 44: "Unknown", 45: "SPP", 46: "Behavior", 47: "Vulnerability", 48: "Policy", 49: "EUS",
  50: "Ransom", 51: "ASR",
};

/** MSFT_MpThreatDetection ThreatStatusID (DetectionHistory's status). */
export const THREAT_STATUS: Record<number, string> = {
  0: "Unknown", 1: "Detected", 2: "Cleaned", 3: "Quarantined", 4: "Removed", 5: "Allowed", 6: "Blocked", 102: "Quarantine failed", 103: "Remove failed", 104: "Allow failed", 105: "Abandoned", 107: "Block failed",
};
export const FAILED_STATUS = new Set([102, 103, 104, 107]);

/** MSFT_MpThreatDetection CurrentThreatExecutionStatusID. */
export const EXECUTION_STATUS: Record<number, string> = { 0: "Unknown", 1: "Blocked", 2: "Allowed", 3: "Executing", 4: "Not executing" };

// ---------------------------------------------------------------------------
// Field helpers

/** First value of any of the names given (case-insensitive). */
export function field(data: [string, string][], ...names: string[]): string | undefined {
  for (const n of names) {
    const hit = data.find(([k]) => k.toLowerCase() === n.toLowerCase());
    if (hit && hit[1] !== "") return hit[1];
  }
  return undefined;
}

/** A "… Name" field's text, unless it is a message-table reference (%%818). */
export const textName = (v: string | undefined) => (v && !/^%%\d+$/.test(v.trim()) ? v.trim() : undefined);

export interface NamedId {
  id: number | null;
  /** The name: the event's own text, else from a documented table. */
  name: string | null;
  /** "event": written in the log; "table": from documentation; "inferred": from documentation order only. */
  from: "event" | "table" | "inferred" | null;
  /** The event's message-table reference, when that is what it holds. */
  ref?: string;
}

export function named(idText: string | undefined, nameText: string | undefined, table: Record<number, string | { name: string; inferred?: true }>): NamedId {
  const id = idText !== undefined && /^\s*-?\d+\s*$/.test(idText) ? Number(idText) : null;
  const own = textName(nameText);
  const ref = nameText && /^%%\d+$/.test(nameText.trim()) ? nameText.trim() : undefined;
  if (own) return { id, name: own, from: "event" };
  const t = id !== null ? table[id] : undefined;
  if (t === undefined) return { id, name: null, from: null, ...(ref ? { ref } : {}) };
  const entry = typeof t === "string" ? { name: t } : t;
  return { id, name: entry.name, from: entry.inferred ? "inferred" : "table", ...(ref ? { ref } : {}) };
}

/** A threat event's Path: "file:_C:\x.exe; webfile:_C:\x.exe|https://…|pid:1" → resources. */
export function parseResources(path: string | undefined): { schema: string; location: string }[] {
  if (!path) return [];
  const parts = path.split(/;\s*(?=[A-Za-z]+:_)/);
  return parts
    .map((p) => p.trim())
    .filter(Boolean)
    .slice(0, 100)
    .map((p) => {
      const m = /^([A-Za-z]+):_(.*)$/.exec(p);
      return m ? { schema: m[1].toLowerCase(), location: m[2] } : { schema: "", location: p };
    });
}

/** A Defender registry change as 5007 and 5013 write it: "HKLM\SOFTWARE\Microsoft\Windows Defender\…\Name = 0x0". */
export interface RegChange {
  /** The whole text. */
  text: string;
  /** Registry path up to the value. */
  key: string;
  /** The value's name (for an exclusion: the excluded item). */
  name: string;
  /** The value as written after " = ". */
  value: string;
  policy: boolean;
  exclusionKind?: string;
}

export function parseRegChange(text: string | undefined): RegChange | null {
  if (!text) return null;
  const t = text.trim();
  const eq = t.lastIndexOf(" = ");
  const path = eq >= 0 ? t.slice(0, eq) : t;
  const value = eq >= 0 ? t.slice(eq + 3).trim() : "";
  const m = /^(?:HKLM|HKEY_LOCAL_MACHINE)\\SOFTWARE\\(Policies\\)?Microsoft\\Windows Defender\\(.*)$/i.exec(path);
  if (!m) {
    const s = path.lastIndexOf("\\");
    return { text: t, key: s >= 0 ? path.slice(0, s) : "", name: s >= 0 ? path.slice(s + 1) : path, value, policy: false };
  }
  const rest = m[2];
  const ex = /^Exclusions\\(Paths|Extensions|Processes|IpAddresses|TemporaryPaths)\\(.+)$/i.exec(rest);
  const base = path.slice(0, path.length - rest.length);
  if (ex) return { text: t, key: `${base}Exclusions\\${ex[1]}`, name: ex[2], value, policy: !!m[1], exclusionKind: ex[1] };
  const s = rest.lastIndexOf("\\");
  return { text: t, key: s >= 0 ? `${base}${rest.slice(0, s)}` : base.replace(/\\$/, ""), name: s >= 0 ? rest.slice(s + 1) : rest, value, policy: !!m[1] };
}

/** "0x1" or "1" → 1. */
export function regNumber(v: string): number | undefined {
  const t = v.trim().replace(/\(.*\)$/, "").trim();
  if (/^0x[0-9a-f]+$/i.test(t)) return parseInt(t, 16);
  if (/^\d+$/.test(t)) return Number(t);
  return undefined;
}
