"use client";

import { useState, type ReactNode } from "react";
import { FileArchive, Lock, TriangleAlert } from "lucide-react";
import { CopyButton, Field, formatUtc, mono } from "@/components/defender/bits";
import { pick, t, type ToolDict } from "@/lib/defender/dict";
import { RECOVERY_PASSWORD } from "@/lib/defender/recover";
import type { Detection, QuarantineEntry, QuarantineResource } from "@/lib/defender/types";
import { Button } from "@/components/ui/button";

/** Hash with a copy button. */
function HashLine({ label, value, dict }: { label: string; value: string; dict: ToolDict }) {
  return (
    <Field label={label}>
      <span className="font-mono text-xs break-all">{value}</span> <CopyButton text={value} label={dict.detail_copy} done={dict.detail_copied} />
    </Field>
  );
}

/** The recovery box: a warning, a confirmation, then the encrypted ZIP on an explicit click. */
function Recovery({ res, entry, dict, onRecover }: { res: QuarantineResource; entry: QuarantineEntry; dict: ToolDict; onRecover: (res: QuarantineResource, entry: QuarantineEntry) => Promise<void> }) {
  const [ack, setAck] = useState(false);
  const [state, setState] = useState<"idle" | "busy" | "done" | "error">("idle");
  const [error, setError] = useState("");
  const d = res.data;
  if (!d || d.error || !d.recovered) return null;
  return (
    <div className="mt-2 rounded-lg border border-sev-high/40 bg-sev-high-bg/60 px-3 py-2.5 text-sm">
      <p className="flex items-start gap-2 font-semibold text-sev-high">
        <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
        {dict.q_live}
      </p>
      <p className="mt-1 text-xs leading-relaxed">{t(dict.q_zipNote, { password: RECOVERY_PASSWORD })}</p>
      <label className="mt-2 flex items-start gap-2 text-xs">
        <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} className="mt-0.5" />
        <span>{dict.q_ack}</span>
      </label>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <Button
          size="sm"
          variant="destructive"
          disabled={!ack || state === "busy"}
          onClick={async () => {
            setState("busy");
            try {
              await onRecover(res, entry);
              setState("done");
            } catch (err) {
              setError(err instanceof Error ? err.message : String(err));
              setState("error");
            }
          }}
        >
          <FileArchive /> {dict.q_download}
        </Button>
        <span className="inline-flex items-center gap-1 rounded-md border bg-card px-2 py-0.5 font-mono text-xs">
          <Lock className="size-3" aria-hidden /> {t(dict.q_password, { password: RECOVERY_PASSWORD })}
        </span>
        {state === "done" && <span className="text-xs text-muted-foreground">{dict.q_downloaded}</span>}
        {state === "error" && <span className="text-xs text-sev-high">{error}</span>}
      </div>
    </div>
  );
}

/** A compact fact: label above value (the resource's facts grid). */
function Fact({ label, children, text = false }: { label: string; children: ReactNode; text?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-[0.7rem] text-muted-foreground">{label}</dt>
      <dd className={text ? "min-w-0 text-xs break-words" : "min-w-0 font-mono text-xs break-all"}>{children}</dd>
    </div>
  );
}

function ResourceCard({ res, entry, dict, onRecover }: { res: QuarantineResource; entry: QuarantineEntry; dict: ToolDict; onRecover: (res: QuarantineResource, entry: QuarantineEntry) => Promise<void> }) {
  const d = res.data;
  return (
    <div className="rounded-lg border bg-background/60 px-3 py-2.5">
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <span className="chip">{res.kind}</span>
        <span className="min-w-0 font-mono text-sm font-semibold break-all">{res.display || "—"}</span>
        {res.size !== undefined && <span className="text-xs text-muted-foreground">{t(dict.bytes, { n: res.size.toLocaleString("en") })}</span>}
      </div>
      <dl className="mt-2 grid grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-3">
        {res.created ? <Fact label={dict.q_created}>{formatUtc(res.created, true)}</Fact> : null}
        {res.written ? <Fact label={dict.q_written}>{formatUtc(res.written, true)}</Fact> : null}
        {res.accessed ? <Fact label={dict.q_accessed}>{formatUtc(res.accessed, true)}</Fact> : null}
        {res.attributes !== undefined && <Fact label={dict.q_attributes}>{`0x${res.attributes.toString(16)}`}</Fact>}
        {res.resourceId && <Fact label={dict.q_resourceId}>{res.resourceId}</Fact>}
        {res.path !== res.display && <Fact label={dict.q_pathWritten}>{res.path}</Fact>}
      </dl>
      {!d ? (
        res.resourceId && <p className="mt-2 text-xs text-muted-foreground">{dict.q_noContent}</p>
      ) : d.error ? (
        <p className="mt-2 text-xs text-sev-high">{t(dict.q_contentError, { error: d.error })}</p>
      ) : (
        <div className="mt-3 border-t pt-2">
          <p className="eyebrow mb-1">{dict.q_content}</p>
          <dl>
            {d.recovered && (
              <>
                <Field label={dict.q_recoveredSize}>{t(dict.bytes, { n: d.recovered.size.toLocaleString("en") })}</Field>
                <HashLine label="SHA-256" value={d.recovered.sha256} dict={dict} />
                <HashLine label="SHA-1" value={d.recovered.sha1} dict={dict} />
                <HashLine label="MD5" value={d.recovered.md5} dict={dict} />
              </>
            )}
            <Field label={dict.q_nameCheck}>
              <span className="text-xs">{pick(dict, `q_name_${d.nameMatches}`, d.nameMatches)}</span>
            </Field>
            {d.zone && (
              <Field label="Zone.Identifier">
                <span className="block text-xs">
                  ZoneId {mono(d.zone.zoneId ?? "—")} {d.zone.zoneId && <span className="text-muted-foreground">({pick(dict, `zone_${d.zone.zoneId}`, "?")})</span>}
                </span>
                {d.zone.hostUrl && <span className="block text-xs">HostUrl {mono(d.zone.hostUrl)}</span>}
                {d.zone.referrerUrl && <span className="block text-xs">ReferrerUrl {mono(d.zone.referrerUrl)}</span>}
                {d.zone.other.map(([k, v]) => (
                  <span key={k} className="block text-xs">
                    {k} {mono(v)}
                  </span>
                ))}
              </Field>
            )}
            {!d.zone && !d.hive && <Field label="Zone.Identifier">{dict.q_noZone}</Field>}
            {d.hive && <Field label={dict.q_hive}>{dict.q_hiveNote}</Field>}
            {d.sparse && <Field label={dict.q_sparse}>{dict.q_sparseNote}</Field>}
            {d.owner && <Field label={dict.q_owner}>{mono(d.owner)}</Field>}
            <Field label={dict.q_streams}>
              <span className="text-xs">{d.streams.map((s) => `${s.kindName}${s.name ? ` ${s.name}` : ""} (${s.size.toLocaleString("en")} B)`).join(", ") || "—"}</span>
            </Field>
            {d.problems.length > 0 && <Field label={dict.field_problems}>{d.problems.join(", ")}</Field>}
          </dl>
          <Recovery res={res} entry={entry} dict={dict} onRecover={onRecover} />
        </div>
      )}
      {res.problems.length > 0 && <p className="mt-1 text-xs text-sev-medium">{res.problems.map((p) => pick(dict, `qp_${p}`, p)).join(", ")}</p>}
    </div>
  );
}

/** Every quarantine entry, its resources and what their content holds; recovery as an encrypted ZIP only. */
export function QuarantineView({ entries, detections, dict, multiHost, onSelect, onRecover }: { entries: QuarantineEntry[]; detections: Map<string, Detection>; dict: ToolDict; multiHost: boolean; onSelect: (d: Detection) => void; onRecover: (res: QuarantineResource, entry: QuarantineEntry) => Promise<void> }) {
  return (
    <div className="space-y-3 p-3 sm:p-4">
      <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">{dict.q_intro}</p>
      {entries.length === 0 && <p className="text-sm text-muted-foreground">{dict.q_none}</p>}
      {entries.map((e) => {
        const d = e.detection ? detections.get(e.detection) : undefined;
        return (
          <section key={e.id} className="overflow-hidden rounded-xl border bg-card shadow-[var(--shadow-soft)]">
            <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 border-b bg-surface px-3 py-2 sm:px-4">
              <h3 className="font-mono text-sm font-semibold break-all">{e.threatName ?? "?"}</h3>
              <span className="text-xs text-muted-foreground">
                {dict.q_time}: <span className="font-mono">{formatUtc(e.time, true) || "—"}</span>
              </span>
              {multiHost && <span className="text-xs text-muted-foreground">{e.host}</span>}
              {d && (
                <button type="button" onClick={() => onSelect(d)} className="ml-auto text-xs font-medium text-link underline-offset-4 hover:underline">
                  {dict.q_openDetection}
                </button>
              )}
            </div>
            <div className="space-y-2 px-3 py-2.5 sm:px-4">
              <dl className="grid grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-4">
                <Fact label={dict.q_entry}>{e.guid ? `{${e.guid}}` : "—"}</Fact>
                {e.threatId && <Fact label={dict.field_threatId}>{e.threatId}</Fact>}
                {e.scanId && <Fact label={dict.q_scan}>{`{${e.scanId}}`}</Fact>}
                <Fact label={dict.q_check} text>
                  {e.magic ? dict.q_magicOk : dict.q_magicMissing} · {e.crc.map((c, i) => t(pick(dict, `q_crc_${c}`, c), { n: i + 1 })).join(", ")}
                </Fact>
              </dl>
              {e.resources.map((r, i) => (
                <ResourceCard key={`${e.id}-${i}`} res={r} entry={e} dict={dict} onRecover={onRecover} />
              ))}
            </div>
          </section>
        );
      })}
    </div>
  );
}
