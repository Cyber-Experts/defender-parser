"use client";

import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState, type DragEvent } from "react";
import { track } from "@vercel/analytics";
import { ChevronDown, FileDown, FolderOpen, Lock, Maximize2, Minimize2, Sparkles, TriangleAlert, Upload, X } from "lucide-react";
import { LogoMark } from "@/components/brand/logo";
import { ChangesView } from "@/components/defender/ChangesView";
import { CollectGuide } from "@/components/defender/CollectGuide";
import { DetectionsTable } from "@/components/defender/DetectionsTable";
import { FilesView } from "@/components/defender/FilesView";
import { FindingsView } from "@/components/defender/FindingsView";
import { ItemDetail } from "@/components/defender/ItemDetail";
import { MplogView } from "@/components/defender/MplogView";
import { QuarantineView } from "@/components/defender/QuarantineView";
import { TimelineView } from "@/components/defender/TimelineView";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Sheet, SheetContent } from "@/components/ui/sheet";
import { collect, filesFromDataTransfer, filesFromInput, type Artifact, type DroppedFile, type SkipReason } from "@/lib/intake/collect";
import { receiveHandoff } from "@/lib/intake/handoff";
import { analyzeInWorker } from "@/lib/defender/client";
import { findingHeading, flagGroup, flagTitle, flagWhy, itemLabel, plural, t, type ToolDict } from "@/lib/defender/dict";
import { buildRecoveryZip } from "@/lib/defender/recover";
import type { Analysis, Change, Detection, QuarantineEntry, QuarantineResource, Severity } from "@/lib/defender/types";
import {
  DEFAULT_FILTERS,
  buildTimeline,
  changesCsv,
  computeFindings,
  detectionsCsv,
  filterChanges,
  filterDetections,
  filterMplog,
  filterTimeline,
  itemSeverity,
  timelineCsv,
  toJson,
  toMarkdown,
  unzonedCount,
  type Filters,
  type Item,
} from "@/lib/defender/view";
import { cn } from "@/lib/utils";

type Tab = "findings" | "detections" | "quarantine" | "changes" | "mplog" | "timeline" | "files";
const TABS: Tab[] = ["findings", "detections", "quarantine", "changes", "mplog", "timeline", "files"];
const MIN_SEVERITIES: (Severity | "all")[] = ["all", "high", "medium", "low", "info"];
const SAMPLE = "/samples/FIN-WKS-07.zip";

function download(name: string, type: string, body: BlobPart) {
  const url = URL.createObjectURL(new Blob([body], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.rel = "noopener";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function DefenderTool({ dict }: { dict: ToolDict }) {
  const [inputs, setInputs] = useState<Artifact[]>([]);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [skipped, setSkipped] = useState<SkipReason[]>([]);
  const [ignored, setIgnored] = useState(0);
  const [errors, setErrors] = useState<string[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [tab, setTab] = useState<Tab>("findings");
  const [selected, setSelected] = useState<Item | null>(null);
  const filesInput = useRef<HTMLInputElement>(null);
  const folderInput = useRef<HTMLInputElement>(null);
  const workspace = useRef<HTMLElement>(null);

  // Results take over the viewport as soon as they appear; the landing page
  // comes back when they are cleared.
  const hasResults = analysis !== null;
  const [fullscreen, setFullscreen] = useState(false);
  const [hadResults, setHadResults] = useState(false);
  if (hadResults !== hasResults) {
    setHadResults(hasResults);
    setFullscreen(hasResults);
  }

  useEffect(() => {
    if (!fullscreen) return;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || e.defaultPrevented || selected) return;
      const el = e.target as HTMLElement | null;
      if (el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable)) return;
      setFullscreen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = prevOverflow;
      window.removeEventListener("keydown", onKey);
    };
  }, [fullscreen, selected]);

  useEffect(() => {
    const el = workspace.current;
    if (!el) return;
    if (fullscreen) {
      if (!el.contains(document.activeElement)) el.focus({ preventScroll: true });
    } else {
      el.scrollIntoView({ block: "nearest" });
    }
  }, [fullscreen]);

  const ingest = useCallback(
    async (dropped: DroppedFile[], source: "upload" | "sample" | "handoff" = "upload") => {
      if (dropped.length === 0) return;
      setBusy(dict.unpacking);
      try {
        const found = await collect(dropped, (p) => setBusy(p.phase === "unpacking" ? dict.unpacking : t(dict.scanning, { done: p.done, total: p.total })));
        setSkipped((s) => [...s, ...found.skipped]);
        setIgnored((n) => n + found.ignored);
        if (found.artifacts.length === 0) {
          if (!analysis) setErrors((e) => [...e, dict.nothingFound]);
          return;
        }
        // Sources are joined across files: re-run over everything so far.
        const known = new Set(inputs.map((a) => a.path));
        const all = [...inputs, ...found.artifacts.filter((a) => !known.has(a.path))];
        setInputs(all);
        setBusy(dict.analysing);
        const result = await analyzeInWorker(all, (done, total) => setBusy(t(dict.reading, { done, total })));
        if (result.files.every((f) => f.status === "unrecognised") && !analysis) setErrors((e) => [...e, dict.nothingFound]);
        setAnalysis(result);
        track("parse_file", { artifact: "defender", source });
      } catch (err) {
        setErrors((e) => [...e, t(dict.parseError, { error: err instanceof Error ? err.message : String(err) })]);
      } finally {
        setBusy(null);
      }
    },
    [dict, inputs, analysis],
  );

  const loadSample = useCallback(async () => {
    setBusy(dict.unpacking);
    try {
      const res = await fetch(SAMPLE);
      if (!res.ok) throw new Error(`${SAMPLE}: HTTP ${res.status}`);
      const name = SAMPLE.slice(SAMPLE.lastIndexOf("/") + 1);
      track("load_sample", { artifact: "defender", sample: "FIN-WKS-07" });
      // No modification time on the zip itself: its entries carry their own.
      await ingest([{ path: name, file: new File([await res.blob()], name, { lastModified: 0 }) }], "sample");
    } catch (err) {
      setErrors((e) => [...e, err instanceof Error ? err.message : String(err)]);
      setBusy(null);
    }
  }, [dict, ingest]);

  // Files handed over by a sister tool (Disk Image Parser): browser to
  // browser, never through a server (lib/intake/handoff.ts).
  useEffect(
    () =>
      receiveHandoff({
        onWait: (tool) => setBusy(t(dict.handoffWaiting, { tool })),
        onFiles: (files) => void ingest(files, "handoff"),
        onTimeout: (tool) => {
          setBusy(null);
          setErrors((e) => [...e, t(dict.handoffFailed, { tool })]);
        },
      }),
    [dict, ingest],
  );

  /** A quarantined file, out only as a ZIP encrypted with "infected", on the user's click. */
  const recover = useCallback(
    async (res: QuarantineResource, entry: QuarantineEntry) => {
      const art = res.data ? inputs.find((a) => a.path === res.data!.file) : undefined;
      if (!art) throw new Error(dict.q_recoverMissing);
      const r = buildRecoveryZip(new Uint8Array(await art.file.arrayBuffer()), { host: entry.host, path: res.display, threatName: entry.threatName, quarantined: entry.time, written: res.written ?? null, resourceData: res.data!.file });
      if (!r) throw new Error(dict.q_recoverNone);
      track("recover_quarantine", { format: "zip_infected" });
      download(r.name, "application/zip", r.zip as BlobPart);
    },
    [inputs, dict],
  );

  const clear = () => {
    setInputs([]);
    setAnalysis(null);
    setSkipped([]);
    setIgnored(0);
    setErrors([]);
    setFilters(DEFAULT_FILTERS);
    setSelected(null);
    setTab("findings");
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    void filesFromDataTransfer(e.dataTransfer).then((f) => ingest(f));
  };

  const detections = useMemo(() => analysis?.detections ?? [], [analysis]);
  const changes = useMemo(() => analysis?.changes ?? [], [analysis]);
  const detById = useMemo(() => new Map(detections.map((d) => [d.id, d])), [detections]);
  const chById = useMemo(() => new Map(changes.map((c) => [c.id, c])), [changes]);
  const timeline = useMemo(() => (analysis ? buildTimeline(analysis) : []), [analysis]);
  const unzoned = useMemo(() => (analysis ? unzonedCount(analysis) : { mplog: 0, commands: 0 }), [analysis]);
  // Typing stays responsive on large collections: filtering follows behind.
  const deferred = useDeferredValue(filters);
  const shownDetections = useMemo(() => filterDetections(detections, deferred), [detections, deferred]);
  const shownChanges = useMemo(() => filterChanges(changes, deferred), [changes, deferred]);
  const shownTimeline = useMemo(() => filterTimeline(timeline, deferred), [timeline, deferred]);
  const shownMplog = useMemo(() => filterMplog(analysis?.mplog ?? [], deferred), [analysis, deferred]);
  const shownQuarantine = useMemo(() => {
    const q = deferred.query.trim().toLowerCase();
    return (analysis?.quarantine ?? [])
      .filter((e) => (deferred.host === "all" || e.host === deferred.host) && (!q || `${e.threatName}\n${e.resources.map((r) => `${r.display}\n${r.data?.recovered?.sha256 ?? ""}\n${r.data?.zone?.hostUrl ?? ""}`).join("\n")}`.toLowerCase().includes(q)))
      .sort((x, y) => (y.time ?? -Infinity) - (x.time ?? -Infinity));
  }, [analysis, deferred]);
  // Findings follow the host and search filters, not the flag or severity ones.
  const findings = useMemo(() => computeFindings([...filterDetections(detections, { ...deferred, flag: "all", minSeverity: "all" }), ...filterChanges(changes, { ...deferred, flag: "all", minSeverity: "all" })]), [detections, changes, deferred]);
  const flagCodes = useMemo(() => [...new Set([...detections, ...changes].flatMap((x) => x.flags.map((f) => f.code)))].sort((a, b) => flagGroup(dict, a).localeCompare(flagGroup(dict, b))), [detections, changes, dict]);

  const hosts = analysis?.hosts ?? [];
  const multiHost = hosts.length > 1;
  const hostLabel = hosts.map((h) => h.name).join(", ") || "collection";
  const exportStem = `${(hosts[0]?.name ?? "collection").replace(/[^\w.-]+/g, "_")}_defender`;
  const flagged = [...detections, ...changes].filter((x) => {
    const s = itemSeverity(x);
    return s !== null && s !== "info";
  }).length;
  const high = [...detections, ...changes].filter((x) => itemSeverity(x) === "high").length;
  const quarantinedFiles = (analysis?.quarantine ?? []).reduce((n, e) => n + e.resources.length, 0);
  const missing = useMemo(() => {
    if (!analysis) return [];
    const has = (r: string) => analysis.files.some((f) => f.role === r && f.status === "parsed");
    return [
      ["evtx", dict.missing_evtx],
      ["history", dict.missing_history],
      ["entry", dict.missing_quarantine],
      ["mplog", dict.missing_mplog],
      ["software", dict.missing_software],
    ]
      .filter(([r]) => !has(r))
      .map(([, label]) => label);
  }, [analysis, dict]);

  const pickers = (
    <div className="flex flex-wrap items-center justify-center gap-2">
      <Button onClick={() => filesInput.current?.click()} disabled={!!busy}>
        <Upload /> {dict.browseFiles}
      </Button>
      <Button variant="outline" onClick={() => folderInput.current?.click()} disabled={!!busy}>
        <FolderOpen /> {dict.browseFolder}
      </Button>
      <Button variant="secondary" onClick={() => void loadSample()} disabled={!!busy}>
        <Sparkles /> {dict.trySample}
      </Button>
    </div>
  );

  const notices = (
    <>
      {busy && (
        <p role="status" className="flex items-center gap-2 font-mono text-xs text-muted-foreground">
          <span aria-hidden className="size-2 animate-pulse rounded-full bg-primary motion-reduce:animate-none" />
          {busy}
        </p>
      )}
      {errors.map((e) => (
        <p key={e} className="flex items-start gap-2 rounded-lg border border-sev-high/30 bg-sev-high-bg px-3 py-2 text-sm text-sev-high">
          <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
          {e}
        </p>
      ))}
    </>
  );

  const selectCls = "h-8 min-w-0 flex-1 basis-32 sm:flex-none sm:basis-auto rounded-lg border border-input bg-card px-2.5 text-sm shadow-[var(--shadow-soft)] transition-colors focus-visible:border-ring";
  const count = (tb: Tab) =>
    ({
      findings: findings.length,
      detections: shownDetections.length,
      quarantine: shownQuarantine.length,
      changes: shownChanges.length,
      mplog: shownMplog.length,
      timeline: shownTimeline.length,
      files: analysis?.files.length ?? 0,
    })[tb];

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={(e) => {
        if (e.currentTarget === e.target) setDragOver(false);
      }}
      onDrop={onDrop}
      className="space-y-4"
    >
      <input
        ref={filesInput}
        type="file"
        multiple
        className="hidden"
        onChange={(e) => {
          if (e.target.files) void ingest(filesFromInput(e.target.files));
          e.target.value = "";
        }}
      />
      <input
        ref={folderInput}
        type="file"
        className="hidden"
        // @ts-expect-error — non-standard but supported by every current browser.
        webkitdirectory=""
        onChange={(e) => {
          if (e.target.files) void ingest(filesFromInput(e.target.files));
          e.target.value = "";
        }}
      />

      {!analysis ? (
        <div className="mx-auto max-w-4xl space-y-4">
          <div className="rounded-[1.35rem] border bg-card/70 p-1.5 shadow-[var(--shadow-lift)] backdrop-blur">
            <div
              className={cn(
                "relative isolate overflow-hidden rounded-2xl border-[1.5px] border-dashed bg-card px-4 py-10 text-center transition-colors sm:px-10 sm:py-12",
                dragOver ? "border-primary bg-accent/70" : "border-input",
              )}
            >
              <div aria-hidden className={cn("relative mx-auto mb-5 grid size-12 place-items-center rounded-xl bg-brand-50 text-brand-600 ring-1 ring-brand-200 transition-transform motion-reduce:transition-none dark:bg-brand-900/40 dark:text-brand-400 dark:ring-brand-800", dragOver && "scale-105")}>
                <Upload className="size-5" />
              </div>
              <p className="font-heading text-lg font-bold tracking-[-0.02em] text-balance sm:text-xl">{dict.dropTitle}</p>
              <p className="mx-auto mt-2 max-w-xl text-sm leading-relaxed text-muted-foreground">{dict.dropHint}</p>
              <p className="mt-2 font-mono text-[0.7rem] tracking-wide text-muted-foreground uppercase">{dict.dropFormats}</p>
              <div className="mt-6">{pickers}</div>
              <p className="mx-auto mt-4 max-w-xl text-xs leading-relaxed text-muted-foreground">{dict.sampleNote}</p>
              <p className="mt-5 inline-flex max-w-full items-center gap-1.5 rounded-full border bg-surface px-3 py-1 text-left text-xs text-muted-foreground">
                <Lock className="size-3.5 shrink-0 text-success" aria-hidden /> {dict.privacy}
              </p>
            </div>
          </div>
          {notices}
        </div>
      ) : (
        <section
          ref={workspace}
          tabIndex={-1}
          aria-label={dict.workspaceLabel}
          className={cn(
            "flex min-w-0 flex-col overflow-hidden outline-none",
            fullscreen ? "fixed inset-0 z-[45] m-0 bg-background" : "h-[82vh] min-h-[560px] rounded-2xl border bg-card shadow-[var(--shadow-lift)]",
            dragOver && "ring-2 ring-primary ring-inset",
          )}
        >
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b bg-card px-3 py-2 sm:px-4">
            <div className="flex min-w-40 flex-1 items-center gap-2.5">
              <LogoMark />
              <div className="min-w-0">
                <p className="truncate font-mono text-xs font-medium">{hostLabel}</p>
                <p className="truncate text-[0.7rem] text-muted-foreground">
                  {plural(dict, "filesLoaded", analysis.files.length)} · {plural(dict, "detectionsLoaded", detections.length)}
                </p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              <Button variant="outline" size="sm" onClick={() => filesInput.current?.click()} disabled={!!busy} title={dict.addMore}>
                <Upload /> <span className="sr-only md:not-sr-only">{dict.addMore}</span>
              </Button>
              <Button variant="outline" size="icon-sm" onClick={() => folderInput.current?.click()} disabled={!!busy} title={dict.browseFolder} aria-label={dict.browseFolder}>
                <FolderOpen />
              </Button>
              <DropdownMenu>
                <DropdownMenuTrigger render={<Button variant="outline" size="sm" />}>
                  <FileDown /> {dict.exportLabel} <ChevronDown className="size-3" />
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-64">
                  <DropdownMenuItem
                    onClick={() => {
                      track("export", { format: "csv" });
                      download(`${exportStem}_detections.csv`, "text/csv", detectionsCsv(shownDetections));
                    }}
                  >
                    {dict.exportCsv}
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    onClick={() => {
                      track("export", { format: "changes_csv" });
                      download(`${exportStem}_changes.csv`, "text/csv", changesCsv(shownChanges));
                    }}
                  >
                    {dict.exportChangesCsv}
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    onClick={() => {
                      track("export", { format: "timeline_csv" });
                      download(`${exportStem}_timeline.csv`, "text/csv", timelineCsv(shownTimeline));
                    }}
                  >
                    {dict.exportTimelineCsv}
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    onClick={() => {
                      track("export", { format: "json" });
                      download(`${exportStem}.json`, "application/json", toJson(analysis));
                    }}
                  >
                    {dict.exportJson}
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    onClick={() => {
                      track("export", { format: "md" });
                      download(`${exportStem}.md`, "text/markdown", toMarkdown(analysis, { finding: (f) => findingHeading(dict, f), flag: (f) => flagTitle(dict, f), why: (c) => flagWhy(dict, c), item: (x) => itemLabel(dict, x) }));
                    }}
                  >
                    {dict.exportMarkdown}
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
              <Button variant="ghost" size="sm" onClick={clear} disabled={!!busy} title={dict.newAnalysis}>
                <X /> <span className="sr-only md:not-sr-only">{dict.newAnalysis}</span>
              </Button>
              <Button
                variant="outline"
                size="icon-sm"
                onClick={() => setFullscreen((f) => !f)}
                aria-pressed={fullscreen}
                aria-label={fullscreen ? dict.exitFullscreen : dict.enterFullscreen}
                title={fullscreen ? `${dict.exitFullscreen} (Esc)` : dict.enterFullscreen}
              >
                {fullscreen ? <Minimize2 /> : <Maximize2 />}
              </Button>
            </div>
          </div>

          {(busy || errors.length > 0) && <div className="max-h-32 shrink-0 space-y-1.5 overflow-y-auto border-b px-3 py-2 sm:px-4">{notices}</div>}

          <dl className="grid shrink-0 grid-cols-3 border-b bg-surface lg:grid-cols-6">
            {(
              [
                [dict.stat_detections, detections.length.toLocaleString("en"), ""],
                [dict.stat_flagged, flagged.toLocaleString("en"), "bg-sev-medium"],
                [dict.stat_high, high.toLocaleString("en"), "bg-sev-high"],
                [dict.stat_quarantined, quarantinedFiles.toLocaleString("en"), ""],
                [dict.stat_changes, changes.length.toLocaleString("en"), ""],
                [dict.stat_events, analysis.events.length.toLocaleString("en"), ""],
              ] as const
            ).map(([k, v, dot]) => (
              <div key={k} className="-mr-px -mb-px min-w-0 border-r border-b px-3 py-2 sm:px-4">
                <dt className="flex items-start gap-1.5 font-mono text-[0.64rem] leading-tight font-bold tracking-[0.06em] text-muted-foreground uppercase sm:items-center sm:truncate">
                  {dot && <span aria-hidden className={cn("mt-[0.2rem] size-1.5 shrink-0 rounded-full sm:mt-0", dot)} />}
                  {k}
                </dt>
                <dd className="mt-0.5 truncate font-heading text-base font-bold tabular-nums tracking-[-0.02em] sm:text-xl">{v}</dd>
              </div>
            ))}
          </dl>

          <div className="flex shrink-0 flex-wrap items-center gap-2 border-b px-3 py-2 sm:px-4">
            <input
              type="search"
              value={filters.query}
              onChange={(e) => setFilters({ ...filters, query: e.target.value })}
              placeholder={dict.search}
              aria-label={dict.search}
              className="h-8 min-w-0 flex-1 basis-56 rounded-lg border border-input bg-card px-2.5 text-sm shadow-[var(--shadow-soft)] transition-colors placeholder:text-muted-foreground focus-visible:border-ring"
            />
            {flagCodes.length > 0 && (
              <select value={filters.flag} onChange={(e) => setFilters({ ...filters, flag: e.target.value })} aria-label={dict.allFlags} className={cn(selectCls, "max-w-56")}>
                <option value="all">{dict.allFlags}</option>
                {flagCodes.map((c) => (
                  <option key={c} value={c}>
                    {flagGroup(dict, c)}
                  </option>
                ))}
              </select>
            )}
            <select value={filters.minSeverity} onChange={(e) => setFilters({ ...filters, minSeverity: e.target.value as Severity | "all" })} aria-label={dict.minSeverityLabel} className={selectCls}>
              {MIN_SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {dict[`minSeverity_${s}`]}
                </option>
              ))}
            </select>
            {multiHost && (
              <select value={filters.host} onChange={(e) => setFilters({ ...filters, host: e.target.value })} aria-label={dict.col_host} className={cn(selectCls, "max-w-48")}>
                <option value="all">{dict.allHosts}</option>
                {hosts.map((h) => (
                  <option key={h.name} value={h.name}>
                    {h.name}
                  </option>
                ))}
              </select>
            )}
          </div>

          <div role="tablist" aria-label={dict.tabsLabel} className="flex shrink-0 gap-1 overflow-x-auto border-b bg-surface px-2 py-1.5 sm:px-3">
            {TABS.map((tb) => (
              <button
                key={tb}
                type="button"
                role="tab"
                id={`tab-${tb}`}
                aria-selected={tab === tb}
                aria-controls={`panel-${tb}`}
                onClick={() => setTab(tb)}
                className={cn(
                  "inline-flex shrink-0 items-center gap-1.5 rounded-md px-3 py-1 text-sm font-medium whitespace-nowrap transition-colors",
                  tab === tb ? "bg-card text-foreground shadow-[var(--shadow-soft)] ring-1 ring-border" : "text-muted-foreground hover:bg-card/60 hover:text-foreground",
                )}
              >
                {dict[`tab_${tb}`]}
                <span className={cn("rounded-full px-1.5 font-mono text-[0.68rem]", tab === tb ? "bg-accent text-accent-foreground" : "bg-muted text-muted-foreground")}>{count(tb).toLocaleString("en")}</span>
              </button>
            ))}
          </div>

          <div key={tab} role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} className="min-h-0 flex-1 overflow-auto bg-background/40">
            {tab === "findings" && <FindingsView findings={findings} dict={dict} missing={missing} multiHost={multiHost} onSelect={setSelected} />}
            {tab === "detections" && <DetectionsTable items={shownDetections} dict={dict} multiHost={multiHost} onSelect={setSelected} empty={detections.length === 0 ? dict.noDetections : dict.noRows} />}
            {tab === "quarantine" && <QuarantineView entries={shownQuarantine} detections={detById} dict={dict} multiHost={multiHost} onSelect={setSelected} onRecover={recover} />}
            {tab === "changes" && <ChangesView analysis={analysis} items={shownChanges} dict={dict} multiHost={multiHost} onSelect={(c: Change) => setSelected(c)} />}
            {tab === "mplog" && <MplogView lines={analysis.mplog} query={deferred.query} host={deferred.host} dict={dict} detections={detById} onSelect={(d: Detection) => setSelected(d)} />}
            {tab === "timeline" && <TimelineView items={shownTimeline} unzoned={unzoned} dict={dict} multiHost={multiHost} detections={detById} changes={chById} onSelect={setSelected} />}
            {tab === "files" && <FilesView analysis={analysis} skipped={skipped} ignored={ignored} dict={dict} />}
          </div>

          <div className="flex shrink-0 items-center justify-between gap-4 border-t bg-surface px-3 py-1.5 font-mono text-[0.7rem] text-muted-foreground sm:px-4">
            <span className="min-w-0 truncate">
              {t(dict.rows, { detections: shownDetections.length.toLocaleString("en"), changes: shownChanges.length.toLocaleString("en") })}
              <span className="hidden md:inline"> · {dict.footNote}</span>
            </span>
            {fullscreen && (
              <span className="hidden shrink-0 items-center gap-1.5 lg:inline-flex">
                <kbd className="rounded border bg-muted px-1 py-px">Esc</kbd> · {dict.exitFullscreen}
              </span>
            )}
          </div>
        </section>
      )}

      {/* Always on the page: other pages link to #collect, results or not. */}
      <div className="mx-auto max-w-4xl">
        <CollectGuide id="collect" dict={dict.collect} />
      </div>

      <Sheet open={selected !== null} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-xl">
          {selected && <ItemDetail item={selected} dict={dict} />}
        </SheetContent>
      </Sheet>
    </div>
  );
}
