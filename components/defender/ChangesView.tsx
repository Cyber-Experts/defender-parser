"use client";

import { useState } from "react";
import { Database, KeyRound, ScrollText, Terminal } from "lucide-react";
import { Paged, SevBadge, formatUtc } from "@/components/defender/bits";
import { changeTitle, pick, plural, t, type ToolDict } from "@/lib/defender/dict";
import type { Analysis, Change } from "@/lib/defender/types";
import { itemSeverity } from "@/lib/defender/view";
import { cn } from "@/lib/utils";

const ICON = { event: ScrollText, registry: KeyRound, command: Terminal } as const;

/** Protection changes: Defender's own events, the hive's exclusions and switches at their key time, MpCmdRun runs. */
export function ChangesView({ analysis, items, dict, multiHost, onSelect }: { analysis: Analysis; items: Change[]; dict: ToolDict; multiHost: boolean; onSelect: (c: Change) => void }) {
  const [source, setSource] = useState<Change["source"] | "all">("all");
  const shown = source === "all" ? items : items.filter((c) => c.source === source);
  const keys = analysis.keys.filter((k) => multiHost || k.host === analysis.hosts[0]?.name);
  return (
    <div className="space-y-3 p-3 sm:p-4">
      <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">{dict.ch_intro}</p>
      <div className="flex flex-wrap gap-1.5" role="group" aria-label={dict.ch_sources}>
        {(["all", "event", "registry", "command"] as const).map((s) => (
          <button
            key={s}
            type="button"
            aria-pressed={source === s}
            onClick={() => setSource(s)}
            className={cn("rounded-md border px-2.5 py-0.5 text-xs", source === s ? "border-primary bg-accent font-semibold" : "text-muted-foreground hover:bg-muted")}
          >
            {pick(dict, `ch_source_${s}`, s)} <span className="font-mono">({(s === "all" ? items : items.filter((c) => c.source === s)).length})</span>
          </button>
        ))}
      </div>
      {shown.length === 0 ? (
        <p className="text-sm text-muted-foreground">{dict.ch_none}</p>
      ) : (
        <Paged items={shown} dict={dict}>
          {(list) => (
            <ol className="divide-y overflow-hidden rounded-xl border bg-card">
              {list.map((c) => {
                const sev = itemSeverity(c);
                const Icon = ICON[c.source];
                return (
                  <li key={c.id}>
                    <button type="button" onClick={() => onSelect(c)} className="flex w-full min-w-0 flex-wrap items-baseline gap-x-3 gap-y-0.5 px-3 py-1.5 text-left hover:bg-muted/50">
                      <span className="w-40 shrink-0 font-mono text-[0.72rem] tabular-nums">{c.time !== null ? formatUtc(c.time, true) : c.localTime ? <span className="text-muted-foreground">{t(dict.local_time, { time: c.localTime })}</span> : "—"}</span>
                      <span className="inline-flex w-36 shrink-0 items-center gap-1.5 text-xs text-muted-foreground">
                        <Icon className="size-3.5 shrink-0" aria-hidden />
                        {c.event ? `${dict.ch_event} ${c.event.eventId}` : pick(dict, `ch_source_${c.source}`, c.source)}
                      </span>
                      <span className="w-16 shrink-0">{sev && sev !== "info" ? <SevBadge severity={sev} dict={dict} /> : null}</span>
                      {multiHost && <span className="text-xs text-muted-foreground">{c.host}</span>}
                      <span className="min-w-0 flex-1 font-mono text-xs break-all">{changeTitle(dict, c)}</span>
                    </button>
                  </li>
                );
              })}
            </ol>
          )}
        </Paged>
      )}

      <section className="pt-2">
        <h3 className="eyebrow mb-2 flex items-center gap-1.5">
          <Database className="size-3.5" aria-hidden /> {dict.reg_title}
        </h3>
        <p className="mb-2 max-w-3xl text-xs leading-relaxed text-muted-foreground">{dict.reg_intro}</p>
        {keys.length === 0 ? (
          <p className="text-sm text-muted-foreground">{analysis.files.some((f) => f.role === "software") ? dict.reg_none : dict.reg_noHive}</p>
        ) : (
          <div className="overflow-hidden rounded-xl border bg-card">
            {keys.map((k) => {
              const values = analysis.registry.filter((g) => g.file === k.file && g.keyPath === k.keyPath);
              return (
                <div key={`${k.file}|${k.keyPath}`} className="border-b px-3 py-2 last:border-b-0">
                  <div className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5">
                    <span className="font-mono text-xs font-semibold break-all">{k.keyPath}</span>
                    <span className="text-xs text-muted-foreground">
                      {dict.field_keyTime}: <span className="font-mono">{formatUtc(k.lastWrite) || "—"}</span>
                    </span>
                    <span className="ml-auto font-mono text-xs text-muted-foreground">{plural(dict, "reg_values", k.values)}</span>
                  </div>
                  {values.length > 0 && (
                    <ul className="mt-1 space-y-0.5 pl-3">
                      {values.map((v) => (
                        <li key={v.id} className="font-mono text-xs break-all">
                          {v.name || "(default)"} <span className="text-muted-foreground">= {v.typeName} {v.text}</span>
                          {v.meaning && <span className="ml-1 rounded bg-muted px-1 font-sans text-[0.7rem]">{pick(dict, `meaning_${v.meaning}`, v.meaning)}</span>}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
