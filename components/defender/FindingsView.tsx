"use client";

import { useState } from "react";
import { FileQuestion, ShieldQuestion } from "lucide-react";
import { SevBadge, formatUtc } from "@/components/defender/bits";
import { findingHeading, flagTitle, flagWhy, itemLabel, plural, t, type ToolDict } from "@/lib/defender/dict";
import { isDetection, type Finding, type Item } from "@/lib/defender/view";

const SHOWN = 8;

function FindingCard({ f, dict, onSelect, multiHost }: { f: Finding; dict: ToolDict; onSelect: (x: Item) => void; multiHost: boolean }) {
  const [open, setOpen] = useState(false);
  const title = findingHeading(dict, f);
  const list = open ? f.items : f.items.slice(0, SHOWN);
  return (
    <section data-sev={f.severity} aria-label={title} className="finding rounded-xl border bg-card py-3 pr-3 pl-4 shadow-[var(--shadow-soft)] sm:pr-4 sm:pl-5">
      <div className="flex flex-wrap items-start gap-2.5">
        <SevBadge severity={f.severity} dict={dict} className="mt-0.5" />
        <div className="min-w-0 flex-1">
          <h3 className="text-base leading-snug font-bold">
            {title}
            <span className="ml-2 align-middle font-mono text-xs font-normal text-muted-foreground">{plural(dict, "find_items", f.items.length)}</span>
          </h3>
          <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{flagWhy(dict, f.code)}</p>
          <ul className="mt-2 space-y-0.5">
            {list.map((x) => {
              const flag = x.flags.find((y) => y.code === f.code)!;
              const own = flagTitle(dict, flag);
              const when = x.time !== null ? formatUtc(x.time) : !isDetection(x) && x.localTime ? t(dict.local_time, { time: x.localTime }) : "";
              return (
                <li key={x.id}>
                  <button type="button" onClick={() => onSelect(x)} className="flex w-full min-w-0 flex-wrap items-baseline gap-x-2 gap-y-0.5 rounded-md px-1.5 py-1 text-left text-xs hover:bg-muted/60">
                    {when && <span className="font-mono text-muted-foreground tabular-nums">{when}</span>}
                    {multiHost && <span className="text-muted-foreground">{x.host}</span>}
                    <span className="min-w-0 font-mono font-medium break-all">{itemLabel(dict, x)}</span>
                    {own !== title && <span className="text-muted-foreground">· {own}</span>}
                  </button>
                </li>
              );
            })}
          </ul>
          {f.items.length > SHOWN && (
            <button type="button" onClick={() => setOpen((o) => !o)} aria-expanded={open} className="mt-1 px-1.5 text-sm font-medium text-link underline-offset-4 hover:underline">
              {open ? dict.less : t(dict.more, { n: f.items.length - SHOWN })}
            </button>
          )}
        </div>
      </div>
    </section>
  );
}

export function FindingsView({ findings, dict, missing, multiHost, onSelect }: { findings: Finding[]; dict: ToolDict; missing: string[]; multiHost: boolean; onSelect: (x: Item) => void }) {
  return (
    <div className="space-y-3 p-3 sm:p-4">
      <p className="flex items-start gap-2 rounded-xl border border-dashed bg-card px-3 py-2.5 text-sm leading-relaxed">
        <ShieldQuestion className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
        {dict.find_scope}
      </p>
      {missing.length > 0 && (
        <p className="flex items-start gap-2 rounded-xl border border-dashed px-3 py-2.5 text-sm text-muted-foreground">
          <FileQuestion className="mt-0.5 size-4 shrink-0" aria-hidden />
          {t(dict.find_missing, { list: missing.join(", ") })}
        </p>
      )}
      {findings.length === 0 && <p className="rounded-xl border bg-muted/30 p-4 text-sm text-muted-foreground">{dict.find_none}</p>}
      {findings.map((f) => (
        <FindingCard key={`${f.code}|${f.severity}`} f={f} dict={dict} onSelect={onSelect} multiHost={multiHost} />
      ))}
      <p className="text-xs leading-relaxed text-muted-foreground">{dict.find_note}</p>
    </div>
  );
}
