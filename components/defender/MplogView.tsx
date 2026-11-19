"use client";

import { useMemo, useState } from "react";
import { Paged } from "@/components/defender/bits";
import { pick, t, type ToolDict } from "@/lib/defender/dict";
import type { MpKind } from "@/lib/defender/mplog";
import type { Detection, MpLine } from "@/lib/defender/types";
import { filesSeen, filterMplog, processesSeen } from "@/lib/defender/view";
import { cn } from "@/lib/utils";

type Mode = "lines" | "files" | "processes";
const base = (p: string) => p.slice(p.replace(/\\/g, "/").lastIndexOf("/") + 1);

/** MPLog and MPDetection entries by type, with search; the files and processes Defender saw, detected or not. */
export function MplogView({ lines, query, host, dict, detections, onSelect }: { lines: MpLine[]; query: string; host: string; dict: ToolDict; detections: Map<string, Detection>; onSelect: (d: Detection) => void }) {
  const [mode, setMode] = useState<Mode>("lines");
  const [kind, setKind] = useState<MpKind | "all">("all");
  const kinds = useMemo(() => [...new Set(lines.map((l) => l.kind))].sort(), [lines]);
  const shown = useMemo(() => filterMplog(lines, { query, host }, kind), [lines, query, host, kind]);
  const files = useMemo(() => filesSeen(filterMplog(lines, { query, host }, "files")), [lines, query, host]);
  const procs = useMemo(() => processesSeen(filterMplog(lines, { query, host }, "processes")), [lines, query, host]);
  const tab = (m: Mode, label: string, n: number) => (
    <button key={m} type="button" aria-pressed={mode === m} onClick={() => setMode(m)} className={cn("rounded-md border px-2.5 py-0.5 text-xs", mode === m ? "border-primary bg-accent font-semibold" : "text-muted-foreground hover:bg-muted")}>
      {label} <span className="font-mono">({n.toLocaleString("en")})</span>
    </button>
  );
  return (
    <div className="space-y-3 p-3 sm:p-4">
      <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">{dict.mp_intro}</p>
      <div className="flex flex-wrap items-center gap-1.5">
        {tab("lines", dict.mp_lines, shown.length)}
        {tab("files", dict.mp_files, files.length)}
        {tab("processes", dict.mp_processes, procs.length)}
        {mode === "lines" && kinds.length > 1 && (
          <select value={kind} onChange={(e) => setKind(e.target.value as MpKind | "all")} aria-label={dict.mp_kind} className="ml-auto h-7 rounded-md border border-input bg-card px-2 text-xs">
            <option value="all">{dict.mp_allKinds}</option>
            {kinds.map((k) => (
              <option key={k} value={k}>
                {pick(dict, `mp_${k}`, k)}
              </option>
            ))}
          </select>
        )}
      </div>
      {lines.length === 0 && <p className="text-sm text-muted-foreground">{dict.mp_noLogs}</p>}
      {mode === "lines" && lines.length > 0 && (
        <Paged items={shown} dict={dict}>
          {(list) => (
            <ol className="divide-y overflow-hidden rounded-xl border bg-card">
              {list.map((m) => {
                const d = m.detection ? detections.get(m.detection) : undefined;
                return (
                  <li key={m.id} className="px-3 py-1.5">
                    <div className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 text-xs">
                      <span className="font-mono tabular-nums">{m.stamp || "—"}</span>
                      <span className={cn("rounded px-1 text-[0.68rem]", m.zone === "utc" ? "bg-muted" : "bg-sev-medium-bg text-sev-medium")}>{m.zone === "utc" ? "UTC" : dict.mp_noZone}</span>
                      <span className="font-medium">{pick(dict, `mp_${m.kind}`, m.kind)}</span>
                      <span className="text-muted-foreground">
                        {base(m.file)}:{m.line}
                      </span>
                      {d && (
                        <button type="button" onClick={() => onSelect(d)} className="text-link underline-offset-4 hover:underline">
                          {t(dict.mp_inDetection, { threat: d.threatName })}
                        </button>
                      )}
                    </div>
                    <pre className="mt-0.5 font-mono text-[0.7rem] leading-relaxed whitespace-pre-wrap break-all text-muted-foreground">{m.raw}</pre>
                  </li>
                );
              })}
            </ol>
          )}
        </Paged>
      )}
      {mode === "files" && (
        <>
          <p className="text-xs text-muted-foreground">{dict.mp_filesNote}</p>
          <Paged items={files} dict={dict}>
            {(list) => (
              <ul className="divide-y overflow-hidden rounded-xl border bg-card">
                {list.map((f) => (
                  <li key={`${f.host}|${f.path}|${f.sha256}`} className="px-3 py-1.5 text-xs">
                    <span className="font-mono font-medium break-all">{f.path}</span>
                    {f.detected && <span className="ml-2 rounded bg-sev-high-bg px-1 text-[0.68rem] text-sev-high">{dict.mp_detected}</span>}
                    <span className="block font-mono text-[0.7rem] break-all text-muted-foreground">
                      {f.sha256 ? `SHA-256 ${f.sha256}` : dict.mp_noHash}
                      {f.sha1 ? ` · SHA-1 ${f.sha1}` : ""}
                    </span>
                    <span className="block text-[0.7rem] text-muted-foreground">{t(dict.mp_seen, { first: f.first, last: f.last, n: f.count })}</span>
                  </li>
                ))}
              </ul>
            )}
          </Paged>
        </>
      )}
      {mode === "processes" && (
        <>
          <p className="text-xs text-muted-foreground">{dict.mp_processesNote}</p>
          <Paged items={procs} dict={dict}>
            {(list) => (
              <ul className="divide-y overflow-hidden rounded-xl border bg-card">
                {list.map((p) => (
                  <li key={`${p.host}|${p.name}`} className="flex flex-wrap items-baseline gap-x-3 px-3 py-1.5 text-xs">
                    <span className="font-mono font-medium">{p.name}</span>
                    <span className="text-muted-foreground">{t(dict.mp_procSeen, { first: p.first, last: p.last, n: p.count, files: p.files.toLocaleString("en") })}</span>
                  </li>
                ))}
              </ul>
            )}
          </Paged>
        </>
      )}
    </div>
  );
}
