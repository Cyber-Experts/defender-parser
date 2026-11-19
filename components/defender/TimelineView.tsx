"use client";

import { useState } from "react";
import { Paged, formatUtc } from "@/components/defender/bits";
import { pick, t, type ToolDict } from "@/lib/defender/dict";
import type { Change, Detection } from "@/lib/defender/types";
import type { TimelineItem, TimelineSource } from "@/lib/defender/view";
import { cn } from "@/lib/utils";

const SOURCES: (TimelineSource | "all")[] = ["all", "event", "history", "quarantine", "mplog", "registry"];

/** Every record with a UTC time, labelled with its source. */
export function TimelineView({ items, unzoned, dict, multiHost, detections, changes, onSelect }: { items: TimelineItem[]; unzoned: { mplog: number; commands: number }; dict: ToolDict; multiHost: boolean; detections: Map<string, Detection>; changes: Map<string, Change>; onSelect: (x: Detection | Change) => void }) {
  const [source, setSource] = useState<TimelineSource | "all">("all");
  const shown = source === "all" ? items : items.filter((i) => i.source === source);
  const label = (it: TimelineItem) => {
    if (it.what.startsWith("ev_")) return `${it.params.id} · ${pick(dict, it.what, dict.ev_unnamed)}`;
    if (it.what === "tl_history_status") return t(dict.tl_history_status, { status: pick(dict, `status_${it.params.status}`, it.params.status) });
    if (it.what === "tl_key") return t(pick(dict, it.params.n === "1" ? "tl_key_one" : "tl_key"), it.params);
    if (it.what.startsWith("mp_")) return `MPLog · ${pick(dict, it.what, it.what.slice(3))}`;
    return pick(dict, it.what, it.what);
  };
  return (
    <div className="space-y-2 p-3 sm:p-4">
      <p className="max-w-3xl text-xs leading-relaxed text-muted-foreground">
        {dict.tl_note}
        {unzoned.mplog + unzoned.commands > 0 && <> {t(dict.tl_unzoned, { mplog: unzoned.mplog, commands: unzoned.commands })}</>}
      </p>
      <div className="flex flex-wrap gap-1.5">
        {SOURCES.map((s) => (
          <button key={s} type="button" aria-pressed={source === s} onClick={() => setSource(s)} className={cn("rounded-md border px-2.5 py-0.5 text-xs", source === s ? "border-primary bg-accent font-semibold" : "text-muted-foreground hover:bg-muted")}>
            {pick(dict, `tl_source_${s}`, s)}
          </button>
        ))}
      </div>
      {shown.length === 0 ? (
        <p className="text-sm text-muted-foreground">{dict.tl_none}</p>
      ) : (
        <Paged items={shown} dict={dict}>
          {(list) => (
            <ol className="divide-y overflow-hidden rounded-xl border bg-card">
              {list.map((it) => {
                const target = (it.detection && detections.get(it.detection)) || (it.change && changes.get(it.change)) || undefined;
                const body = (
                  <>
                    <span className="w-44 shrink-0 font-mono text-[0.72rem] tabular-nums">{formatUtc(it.time, true)}</span>
                    <span className="w-64 shrink-0 truncate text-xs text-muted-foreground" title={label(it)}>
                      {label(it)}
                    </span>
                    {multiHost && <span className="text-xs text-muted-foreground">{it.host}</span>}
                    <span className="min-w-0 flex-1 font-mono text-xs break-all">{it.detail}</span>
                  </>
                );
                return (
                  <li key={it.id}>
                    {target ? (
                      <button type="button" onClick={() => onSelect(target)} className="flex w-full min-w-0 flex-wrap items-baseline gap-x-3 gap-y-0.5 px-3 py-1.5 text-left hover:bg-muted/50">
                        {body}
                      </button>
                    ) : (
                      <div className="flex min-w-0 flex-wrap items-baseline gap-x-3 gap-y-0.5 bg-surface/60 px-3 py-1.5">{body}</div>
                    )}
                  </li>
                );
              })}
            </ol>
          )}
        </Paged>
      )}
    </div>
  );
}
