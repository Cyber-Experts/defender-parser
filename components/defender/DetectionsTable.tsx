"use client";

import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import { Paged, SevBadge, formatUtc } from "@/components/defender/bits";
import { pick, t, type ToolDict } from "@/lib/defender/dict";
import { SEVERITY_RANK } from "@/lib/defender/heuristics";
import type { Detection } from "@/lib/defender/types";
import { itemSeverity } from "@/lib/defender/view";
import { cn } from "@/lib/utils";

type Col = "severity" | "time" | "threat" | "path";

const short = (h?: string) => (h ? `${h.slice(0, 12)}…` : "");

/** One row per detection, every source joined; rows open the detail sheet. */
export function DetectionsTable({ items, dict, multiHost, onSelect, empty }: { items: Detection[]; dict: ToolDict; multiHost: boolean; onSelect: (d: Detection) => void; empty: string }) {
  const [sort, setSort] = useState<{ col: Col; dir: 1 | -1 }>({ col: "severity", dir: 1 });
  const rows = useMemo(() => {
    const sev = (d: Detection) => {
      const s = itemSeverity(d);
      return s === null ? 4 : SEVERITY_RANK[s];
    };
    const byTime = (a: Detection, b: Detection) => (b.time ?? -Infinity) - (a.time ?? -Infinity);
    const cmp: Record<Col, (a: Detection, b: Detection) => number> = {
      severity: (a, b) => sev(a) - sev(b),
      time: (a, b) => -byTime(a, b),
      threat: (a, b) => a.threatName.localeCompare(b.threatName),
      path: (a, b) => a.path.localeCompare(b.path),
    };
    return [...items].sort((a, b) => cmp[sort.col](a, b) * sort.dir || byTime(a, b));
  }, [items, sort]);
  if (items.length === 0) return <p className="p-4 text-sm text-muted-foreground">{empty}</p>;
  const head = (col: Col, label: string, className?: string) => {
    const active = sort.col === col;
    const Icon = !active ? ArrowUpDown : sort.dir === 1 ? ArrowUp : ArrowDown;
    return (
      <th className={className} aria-sort={active ? (sort.dir === 1 ? "ascending" : "descending") : "none"}>
        <button type="button" onClick={() => setSort({ col, dir: active ? (sort.dir === 1 ? -1 : 1) : col === "time" ? -1 : 1 })} className="inline-flex items-center gap-1 uppercase hover:text-foreground" title={t(dict.sortBy, { col: label })}>
          {label}
          <Icon className={cn("size-3", !active && "opacity-40")} aria-hidden />
        </button>
      </th>
    );
  };
  return (
    <div className="min-w-0">
      <Paged items={rows} dict={dict}>
        {(shown) => (
          <table className="data-table w-full min-w-[78rem] border-separate border-spacing-0 text-sm">
            <thead className="sticky top-0 z-10 bg-card">
              <tr className="[&>th]:border-b [&>th]:px-3 [&>th]:py-2 [&>th]:text-left">
                {head("severity", dict.col_severity, "w-24")}
                {head("time", dict.col_time, "w-40")}
                {head("threat", dict.col_threat)}
                {head("path", dict.col_path)}
                <th className="w-36">{dict.col_user}</th>
                <th className="w-32">{dict.col_source}</th>
                <th className="w-36">{dict.col_action}</th>
                <th className="w-24">{dict.col_quarantined}</th>
                <th className="w-32">{dict.col_sha256}</th>
                {multiHost && <th className="w-28">{dict.col_host}</th>}
              </tr>
            </thead>
            <tbody>
              {shown.map((d) => {
                const sev = itemSeverity(d);
                return (
                  <tr
                    key={d.id}
                    tabIndex={0}
                    onClick={() => onSelect(d)}
                    onKeyDown={(k) => {
                      if (k.key === "Enter" || k.key === " ") {
                        k.preventDefault();
                        onSelect(d);
                      }
                    }}
                    className="cursor-pointer align-top transition-colors hover:bg-muted/50 focus-visible:bg-muted/60 [&>td]:border-b [&>td]:px-3 [&>td]:py-1.5"
                  >
                    <td>{sev ? <SevBadge severity={sev} dict={dict} /> : <span className="text-xs text-muted-foreground">—</span>}</td>
                    <td className="font-mono text-xs whitespace-nowrap tabular-nums">{d.time !== null ? formatUtc(d.time) : <span className="text-muted-foreground">—</span>}</td>
                    <td className="max-w-[18rem]">
                      <span className="block font-mono text-xs font-medium break-all">{d.threatName || "—"}</span>
                      <span className="block truncate text-[0.7rem] text-muted-foreground">{[d.severity.name, d.category.name].filter(Boolean).join(" · ")}</span>
                    </td>
                    <td className="max-w-[24rem]">
                      <span className="line-clamp-2 font-mono text-xs break-all" title={d.path}>
                        {d.path || "—"}
                      </span>
                      {d.process && <span className="block truncate font-mono text-[0.7rem] text-muted-foreground" title={d.process}>{t(dict.via_process, { process: d.process.split("\\").pop() ?? d.process })}</span>}
                    </td>
                    <td className="max-w-36">
                      <span className="block truncate text-xs" title={d.user}>
                        {d.user ?? <span className="text-muted-foreground">—</span>}
                      </span>
                    </td>
                    <td className="text-xs">{d.source.name ?? (d.source.id !== null ? `ID ${d.source.id}` : "—")}</td>
                    <td className="text-xs">
                      <span className="block">{d.action.name ?? (d.action.id !== null ? `ID ${d.action.id}` : d.status ?? "—")}</span>
                      <span className={cn("block text-[0.7rem]", d.result === "failed" || d.result === "allowed" ? "font-semibold text-sev-high" : "text-muted-foreground")}>{pick(dict, `result_${d.result}`, d.result)}</span>
                    </td>
                    <td className="text-xs">{d.quarantined === null ? "—" : d.quarantined ? dict.yes : dict.no}</td>
                    <td className="font-mono text-[0.7rem] text-muted-foreground" title={d.hashes.sha256 ?? d.hashes.sha1}>
                      {short(d.hashes.sha256 ?? d.hashes.sha1) || "—"}
                    </td>
                    {multiHost && <td className="font-mono text-xs">{d.host}</td>}
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Paged>
    </div>
  );
}
