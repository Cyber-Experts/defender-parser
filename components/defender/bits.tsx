"use client";

import { useState, type ReactNode } from "react";
import { Check, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { t, type ToolDict } from "@/lib/defender/dict";
import type { Severity } from "@/lib/defender/types";
import { cn } from "@/lib/utils";

export const SEV_CLASS: Record<Severity, string> = { high: "sev-high", medium: "sev-medium", low: "sev-low", info: "sev-info" };

/** "2026-09-14 10:06:12" (UTC, as recorded; no conversion). */
export function formatUtc(ms: number | null | undefined, withMs = false): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms) || Math.abs(ms) > 8.64e15) return "";
  const iso = new Date(ms).toISOString().replace("T", " ");
  return withMs ? iso.replace(/Z$/, "") : iso.replace(/\.\d{3}Z$/, "");
}

export function SevBadge({ severity, dict, className }: { severity: Severity; dict: ToolDict; className?: string }) {
  return <span className={cn("sev", SEV_CLASS[severity], className)}>{dict[`sev_${severity}`]}</span>;
}

export function CopyButton({ text, label, done, className }: { text: string; label: string; done: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard?.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
      className={cn("inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs text-muted-foreground transition-colors hover:bg-muted hover:text-foreground", className)}
    >
      {copied ? <Check className="size-3.5" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
      {copied ? done : label}
    </button>
  );
}

/** A list rendered a page at a time, with a "more" button. */
export function Paged<T>({ items, page = 300, dict, children }: { items: T[]; page?: number; dict: ToolDict; children: (shown: T[]) => ReactNode }) {
  const [limit, setLimit] = useState(page);
  return (
    <>
      {children(items.slice(0, limit))}
      {items.length > limit && (
        <div className="p-3 text-center">
          <Button variant="outline" size="sm" onClick={() => setLimit((l) => l + page)}>
            {t(dict.more, { n: (items.length - limit).toLocaleString("en") })}
          </Button>
        </div>
      )}
    </>
  );
}

export const mono = (v: ReactNode) => <span className="font-mono text-xs break-all">{v}</span>;

/** A label and its value in a two-column list (detail sheets). */
export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[9.5rem_1fr] gap-3 border-b py-1.5 text-sm last:border-b-0">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  );
}

/** Raw source text (an event's XML, a log line), shown as text only. */
export function Raw({ text, label }: { text: string; label: string }) {
  return (
    <div className="mt-1">
      <p className="eyebrow mb-0.5">{label}</p>
      <pre className="max-h-72 overflow-auto rounded-md bg-[var(--code-bg)] px-2.5 py-1.5 font-mono text-[0.7rem] leading-relaxed whitespace-pre-wrap break-all text-[var(--code-fg)]">{text}</pre>
    </div>
  );
}
