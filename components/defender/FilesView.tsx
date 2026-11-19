"use client";

import { formatUtc } from "@/components/defender/bits";
import { pick, t, type ToolDict } from "@/lib/defender/dict";
import type { SkipReason } from "@/lib/intake/collect";
import type { Analysis, FileReport, FileStatus } from "@/lib/defender/types";
import { cn } from "@/lib/utils";

const STATUS_ORDER: Record<FileStatus, number> = { error: 0, unrecognised: 1, "not-read": 2, parsed: 3, empty: 4 };
const ROLE_ORDER: Record<FileReport["role"], number> = { evtx: 0, history: 1, entry: 2, resourcedata: 3, resources: 4, mplog: 5, mpdetection: 6, mpcmdrun: 7, software: 8, "defender-other": 9, unknown: 10 };

function encodingText(f: FileReport, dict: ToolDict): string {
  if (!f.encoding) return "";
  return [pick(dict, `enc_${f.encoding}`, f.encoding), f.bom ? dict.enc_bom : "", f.lineEnding ? pick(dict, `eol_${f.lineEnding}`, f.lineEnding) : ""].filter(Boolean).join(", ");
}

function FileCard({ f, dict }: { f: FileReport; dict: ToolDict }) {
  const facts = [
    pick(dict, `role_${f.role}`, f.role),
    pick(dict, `status_${f.status}`, f.status),
    encodingText(f, dict),
    f.lines !== undefined ? t(dict.files_lines, { n: f.lines.toLocaleString("en") }) : "",
    t(pick(dict, `files_records_${f.role}`, dict.files_records), { n: f.records.toLocaleString("en") }),
    t(dict.bytes, { n: f.size.toLocaleString("en") }),
  ].filter(Boolean);
  return (
    <section className="space-y-1.5 rounded-xl border bg-card px-3 py-2.5 sm:px-4">
      <p className="font-mono text-xs font-semibold break-all">{f.path}</p>
      {f.sysPath !== f.path && <p className="font-mono text-[0.7rem] break-all text-muted-foreground">{f.sysPath}</p>}
      <p className="text-xs text-muted-foreground">{facts.join(" · ")}</p>
      <p className="text-xs text-muted-foreground">
        {dict.files_modified}: <span className="font-mono">{formatUtc(f.mtime) || "—"}</span>
        {f.mtimeApprox && <span> ({dict.files_approx})</span>}
        {f.first !== null && (
          <>
            {" · "}
            {dict.files_range}: <span className="font-mono">{formatUtc(f.first)}</span> → <span className="font-mono">{formatUtc(f.last)}</span>
          </>
        )}
      </p>
      {f.kinds && Object.keys(f.kinds).length > 0 && (
        <p className="text-xs text-muted-foreground">
          {Object.entries(f.kinds)
            .sort((a, b) => b[1] - a[1])
            .map(([k, n]) => `${pick(dict, `mp_${k}`, k)} ${n.toLocaleString("en")}`)
            .join(" · ")}
        </p>
      )}
      {f.error && <p className="text-xs font-medium text-sev-high">{f.error}</p>}
      {f.notes.length > 0 && (
        <ul className="list-disc space-y-0.5 pl-5 text-xs">
          {f.notes.map((n, i) => (
            <li key={`${n.code}-${i}`}>{t(pick(dict, `note_${n.code}`, n.code), n.params ?? {})}</li>
          ))}
        </ul>
      )}
      {f.unparsedCount > 0 && (
        <div>
          <p className="eyebrow mb-1 text-sev-medium">{t(dict.files_unparsed, { n: f.unparsedCount.toLocaleString("en") })}</p>
          <p className="mb-1 text-xs text-muted-foreground">{dict.files_unparsedNote}</p>
          <ul className="max-h-48 space-y-0.5 overflow-auto rounded-md bg-muted/40 px-2 py-1 font-mono text-xs">
            {f.unparsed.map((u, i) => (
              <li key={`${u.line}-${i}`} className="break-all">
                <span className="text-muted-foreground">
                  {u.line} ({pick(dict, `reason_${u.reason}`, u.reason)}):{" "}
                </span>
                {u.text}
              </li>
            ))}
            {f.unparsedCount > f.unparsed.length && <li className="text-muted-foreground">{t(dict.more, { n: (f.unparsedCount - f.unparsed.length).toLocaleString("en") })}</li>}
          </ul>
        </div>
      )}
    </section>
  );
}

/** Each input: what it was read as, its encoding, records, lines not understood, time range and notes. */
export function FilesView({ analysis, skipped, ignored, dict }: { analysis: Analysis; skipped: SkipReason[]; ignored: number; dict: ToolDict }) {
  const files = [...analysis.files].sort((a, b) => a.host.localeCompare(b.host) || ROLE_ORDER[a.role] - ROLE_ORDER[b.role] || STATUS_ORDER[a.status] - STATUS_ORDER[b.status] || a.path.localeCompare(b.path));
  return (
    <div className="space-y-2 p-3 sm:p-4">
      <p className="max-w-3xl text-xs leading-relaxed text-muted-foreground">{dict.files_intro}</p>
      {files.map((f) => (
        <div key={f.path} className={cn(f.status === "unrecognised" && "opacity-80")}>
          <FileCard f={f} dict={dict} />
        </div>
      ))}
      {skipped.length > 0 && (
        <section className="pt-2">
          <h3 className="eyebrow mb-2">{dict.files_skipped}</h3>
          <ul className="space-y-1 text-xs">
            {skipped.map((s, i) => (
              <li key={`${s.path}-${i}`} className="flex flex-wrap gap-x-2">
                <span className="font-mono break-all">{s.path}</span>
                <span className="text-muted-foreground">{t(pick(dict, `skip_${s.code}`, s.code), s.params ?? {})}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
      {ignored > 0 && <p className="text-xs text-muted-foreground">{t(dict.files_ignored, { n: ignored.toLocaleString("en") })}</p>}
    </div>
  );
}
