"use client";

import { SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { CopyButton, Field, Raw, SevBadge, formatUtc, mono } from "@/components/defender/bits";
import { changeTitle, eventName, flagTitle, flagWhy, namedText, pick, t, type ToolDict } from "@/lib/defender/dict";
import { CATEGORIES, EXECUTION_STATUS, SOURCES, THREAT_STATUS } from "@/lib/defender/evtx";
import type { Change, Detection, Flag, OpEvent } from "@/lib/defender/types";
import { isDetection, type Item } from "@/lib/defender/view";

const base = (p: string) => p.slice(p.replace(/\\/g, "/").lastIndexOf("/") + 1);

function Flags({ flags, dict }: { flags: Flag[]; dict: ToolDict }) {
  return (
    <section>
      <h3 className="eyebrow mb-2">{dict.detail_flags}</h3>
      {flags.length === 0 ? (
        <p className="text-sm text-muted-foreground">{dict.detail_noFlags}</p>
      ) : (
        <ul className="space-y-2">
          {flags.map((f, i) => (
            <li key={`${f.code}-${i}`} data-sev={f.severity} className="finding rounded-lg border bg-card py-2 pr-3 pl-4">
              <div className="flex flex-wrap items-center gap-2">
                <SevBadge severity={f.severity} dict={dict} />
                <span className="text-sm font-semibold">{flagTitle(dict, f)}</span>
              </div>
              <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{flagWhy(dict, f.code)}</p>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function EventCard({ ev, dict }: { ev: OpEvent; dict: ToolDict }) {
  return (
    <div className="mb-2 rounded-lg border bg-muted/20 px-3 py-1.5">
      <dl>
        <Field label={dict.field_event}>{eventName(dict, ev.eventId)}</Field>
        <Field label={dict.field_timeCreated}>{mono(formatUtc(ev.time, true) || "—")}</Field>
        <Field label={dict.field_record}>
          {mono(`${base(ev.file)} #${ev.recordId}`)}
          {ev.userSid && <span className="text-xs text-muted-foreground"> · {ev.userSid}</span>}
        </Field>
        {ev.data
          .filter(([, v]) => v !== "")
          .map(([k, v], i) => (
            <Field key={`${k}-${i}`} label={k}>
              {mono(v)}
            </Field>
          ))}
      </dl>
      <details className="mt-1">
        <summary className="cursor-pointer text-xs text-muted-foreground">{dict.detail_xml}</summary>
        <Raw text={ev.xml} label={dict.detail_raw} />
      </details>
    </div>
  );
}

function DetectionDetail({ d, dict }: { d: Detection; dict: ToolDict }) {
  const h = d.hashes;
  return (
    <>
      <SheetHeader className="p-0 pr-8">
        <p className="eyebrow">
          {dict.detail_detection} · {d.host}
        </p>
        <SheetTitle className="font-mono text-base leading-snug break-all">{d.threatName || "?"}</SheetTitle>
        <SheetDescription className="font-mono text-xs break-all">{d.path || "—"}</SheetDescription>
        {d.path && (
          <div>
            <CopyButton text={d.path} label={dict.detail_copy} done={dict.detail_copied} className="-ml-1.5" />
          </div>
        )}
      </SheetHeader>
      <Flags flags={d.flags} dict={dict} />
      <section>
        <h3 className="eyebrow mb-1">{dict.detail_summary}</h3>
        <dl>
          <Field label={dict.col_time}>
            {mono(formatUtc(d.time, true) || "—")}
            {d.timeFrom && <span className="block text-xs text-muted-foreground">{pick(dict, `timeFrom_${d.timeFrom}`, d.timeFrom)}</span>}
          </Field>
          {d.threatId && <Field label={dict.field_threatId}>{mono(d.threatId)}</Field>}
          <Field label={dict.field_severity}>{namedText(dict, d.severity)}</Field>
          <Field label={dict.field_category}>{namedText(dict, d.category)}</Field>
          <Field label={dict.field_resources}>
            <ul className="space-y-0.5">
              {d.resources.map((r, i) => (
                <li key={i}>
                  <span className="chip">{r.schema || "?"}</span> {mono(r.location)}
                </li>
              ))}
            </ul>
          </Field>
          <Field label={dict.col_user}>
            {d.user ?? "—"}
            <span className="block text-xs text-muted-foreground">{dict.detail_userNote}</span>
          </Field>
          <Field label={dict.field_process}>{mono(d.process ?? "—")}</Field>
          <Field label={dict.col_source}>{namedText(dict, d.source)}</Field>
          {(d.origin.id !== null || d.origin.name) && <Field label={dict.field_origin}>{namedText(dict, d.origin)}</Field>}
          <Field label={dict.col_action}>
            {namedText(dict, d.action)} · {pick(dict, `result_${d.result}`, d.result)}
            {d.errorCode && <span className="block font-mono text-xs">{`${d.errorCode}${d.errorText ? ` ${d.errorText}` : ""}`}</span>}
          </Field>
          {d.status && <Field label={dict.field_status}>{d.status}</Field>}
          <Field label={dict.col_quarantined}>{d.quarantined === null ? dict.unknown : d.quarantined ? dict.yes : dict.no}</Field>
          {(h.sha256 || h.sha1 || h.md5) && (
            <Field label={dict.field_hashes}>
              {h.sha256 && <span className="block font-mono text-xs break-all">SHA-256 {h.sha256}</span>}
              {h.sha1 && <span className="block font-mono text-xs break-all">SHA-1 {h.sha1}</span>}
              {h.md5 && <span className="block font-mono text-xs break-all">MD5 {h.md5}</span>}
              <span className="block text-xs text-muted-foreground">{t(dict.detail_hashFrom, { from: h.from.map((f) => pick(dict, `src_${f}`, f)).join(", ") })}</span>
            </Field>
          )}
          {d.detectionId && <Field label={dict.field_detectionId}>{mono(`{${d.detectionId}}`)}</Field>}
        </dl>
      </section>
      <section>
        <h3 className="eyebrow mb-1">{dict.detail_joins}</h3>
        {d.joins.length === 0 ? (
          <p className="text-sm text-muted-foreground">{dict.detail_noJoins}</p>
        ) : (
          <ul className="list-disc space-y-0.5 pl-5 text-sm">
            {d.joins.map((j, i) => (
              <li key={i}>{t(pick(dict, `join_${j.how}`, j.how), j.params ?? {})}</li>
            ))}
          </ul>
        )}
      </section>
      <section>
        <h3 className="eyebrow mb-1">{dict.detail_events}</h3>
        {d.events.length === 0 ? <p className="text-sm text-muted-foreground">{dict.detail_noEvents}</p> : d.events.map((ev) => <EventCard key={ev.id} ev={ev} dict={dict} />)}
      </section>
      <section>
        <h3 className="eyebrow mb-1">{dict.detail_history}</h3>
        {d.history.length === 0 ? (
          <p className="text-sm text-muted-foreground">{dict.detail_noHistory}</p>
        ) : (
          d.history.map((hh) => (
            <div key={hh.id} className="mb-2 rounded-lg border bg-muted/20 px-3 py-1.5">
              <dl>
                <Field label={dict.field_file}>{mono(base(hh.file))}</Field>
                <Field label={dict.field_threat}>{mono(hh.threatName ?? "—")}</Field>
                {hh.threatId && <Field label={dict.field_threatId}>{mono(hh.threatId)}</Field>}
                {hh.categoryId !== undefined && <Field label={dict.field_category}>{`${CATEGORIES[hh.categoryId] ?? "?"} (${hh.categoryId})`}</Field>}
                {hh.threatStatusId !== undefined && <Field label={dict.field_status}>{`${THREAT_STATUS[hh.threatStatusId] ?? "?"} (${hh.threatStatusId})`}</Field>}
                {hh.executionStatusId !== undefined && <Field label={dict.field_execution}>{`${EXECUTION_STATUS[hh.executionStatusId] ?? "?"} (${hh.executionStatusId})`}</Field>}
                {hh.sourceTypeId !== undefined && <Field label={dict.col_source}>{`${SOURCES[hh.sourceTypeId]?.name ?? "?"} (${hh.sourceTypeId}${SOURCES[hh.sourceTypeId]?.inferred ? `, ${dict.from_inferred}` : ""})`}</Field>}
                <Field label={dict.col_user}>{hh.user ?? "—"}</Field>
                <Field label={dict.field_process}>{mono(hh.process ?? "—")}</Field>
                <Field label={dict.field_initial}>{mono(formatUtc(hh.initialDetection, true) || "—")}</Field>
                <Field label={dict.field_statusChanged}>{mono(formatUtc(hh.statusChanged, true) || "—")}</Field>
                <Field label={dict.field_remediation}>{mono(formatUtc(hh.remediation, true) || "—")}</Field>
                {hh.statusErrorCode !== undefined && <Field label={dict.field_errorCode}>{mono(String(hh.statusErrorCode))}</Field>}
                {hh.quarantineId && <Field label={dict.field_quarantineId}>{mono(`{${hh.quarantineId}}`)}</Field>}
                {hh.resources.map((r, i) => (
                  <Field key={i} label={`${dict.field_resource} ${i + 1}`}>
                    <span className="chip">{r.kind}</span> {mono(r.location)}
                    {r.tracking.length > 0 && (
                      <ul className="mt-0.5 space-y-0.5">
                        {r.tracking.map(([k, v], j) => (
                          <li key={j} className="font-mono text-[0.7rem] break-all">
                            <span className="text-muted-foreground">{k}</span> {v}
                          </li>
                        ))}
                      </ul>
                    )}
                  </Field>
                ))}
                {hh.unknown.length > 0 && (
                  <Field label={dict.field_unknown}>
                    <span className="font-mono text-[0.7rem] break-all">{hh.unknown.map(([k, v]) => `${k}=${v}`).join(" · ")}</span>
                  </Field>
                )}
                {hh.problems.length > 0 && <Field label={dict.field_problems}>{hh.problems.join(", ")}</Field>}
              </dl>
            </div>
          ))
        )}
      </section>
      <section>
        <h3 className="eyebrow mb-1">{dict.detail_quarantine}</h3>
        {d.quarantine.length === 0 ? (
          <p className="text-sm text-muted-foreground">{dict.detail_noQuarantine}</p>
        ) : (
          d.quarantine.map((q) => (
            <div key={q.id} className="mb-2 rounded-lg border bg-muted/20 px-3 py-1.5">
              <dl>
                <Field label={dict.q_entry}>{mono(q.guid ? `{${q.guid}}` : base(q.file))}</Field>
                <Field label={dict.q_time}>{mono(formatUtc(q.time, true) || "—")}</Field>
                {q.resources.map((r, i) => (
                  <Field key={i} label={`${dict.field_resource} ${i + 1}`}>
                    <span className="chip">{r.kind}</span> {mono(r.display)}
                    {r.data?.recovered && <span className="block font-mono text-[0.7rem] break-all text-muted-foreground">SHA-256 {r.data.recovered.sha256}</span>}
                    {r.data?.zone?.hostUrl && <span className="block font-mono text-[0.7rem] break-all text-muted-foreground">HostUrl {r.data.zone.hostUrl}</span>}
                  </Field>
                ))}
              </dl>
              <p className="text-xs text-muted-foreground">{dict.detail_quarantineNote}</p>
            </div>
          ))
        )}
      </section>
      <section>
        <h3 className="eyebrow mb-1">{dict.detail_mplog}</h3>
        {d.mplog.length === 0 ? <p className="text-sm text-muted-foreground">{dict.detail_noMplog}</p> : d.mplog.map((m) => <Raw key={m.id} text={m.raw} label={`${base(m.file)}:${m.line} · ${m.zone === "utc" ? "UTC" : dict.mp_noZone}`} />)}
      </section>
    </>
  );
}

function ChangeDetail({ c, dict }: { c: Change; dict: ToolDict }) {
  return (
    <>
      <SheetHeader className="p-0 pr-8">
        <p className="eyebrow">
          {dict.detail_change} · {c.host}
        </p>
        <SheetTitle className="font-mono text-base leading-snug break-all">{changeTitle(dict, c)}</SheetTitle>
        <SheetDescription className="text-xs">{c.time !== null ? `${formatUtc(c.time, true)} UTC` : c.localTime ? t(dict.local_time, { time: c.localTime }) : "—"}</SheetDescription>
      </SheetHeader>
      <Flags flags={c.flags} dict={dict} />
      <section>
        <h3 className="eyebrow mb-1">{dict.detail_summary}</h3>
        <dl>
          <Field label={dict.field_source}>{pick(dict, `ch_source_${c.source}`, c.source)}</Field>
          {Object.entries(c.params).map(([k, v]) => (
            <Field key={k} label={pick(dict, `param_${k}`, k)}>
              {mono(k === "meaning" ? pick(dict, `meaning_${v}`, v) : k === "kind" && c.what === "command" ? pick(dict, `cmdkind_${v}`, v) : v || "—")}
            </Field>
          ))}
          {c.source === "registry" && c.reg && (
            <>
              <Field label={dict.field_key}>{mono(c.reg.keyPath)}</Field>
              <Field label={dict.field_keyTime}>
                {mono(formatUtc(c.reg.keyLastWrite) || "—")} <span className="text-xs text-muted-foreground">({dict.field_keyTimeNote})</span>
              </Field>
              <Field label={dict.field_value}>{mono(`${c.reg.name} = ${c.reg.typeName} ${c.reg.text}`)}</Field>
              <Field label={dict.field_file}>{mono(c.reg.file)}</Field>
            </>
          )}
          {c.source === "command" && c.cmd && (
            <>
              <Field label={dict.field_start}>{mono(c.cmd.startText ?? "—")}</Field>
              <Field label={dict.field_end}>{mono(c.cmd.endText ?? "—")}</Field>
              <Field label={dict.field_file}>{mono(`${c.cmd.file}:${c.cmd.line}`)}</Field>
              {c.cmd.user && <Field label={dict.col_user}>{c.cmd.user}</Field>}
            </>
          )}
        </dl>
        {c.source === "command" && <p className="mt-1 text-xs text-muted-foreground">{dict.detail_cmdNote}</p>}
      </section>
      {c.event && (
        <section>
          <h3 className="eyebrow mb-1">{dict.detail_events}</h3>
          <EventCard ev={c.event} dict={dict} />
        </section>
      )}
      {c.cmd && c.cmd.detail.length > 0 && <Raw text={c.cmd.detail.join("\n")} label={dict.detail_raw} />}
    </>
  );
}

/** Everything about one detection or change: why it stands out, every source with its raw text. */
export function ItemDetail({ item, dict }: { item: Item; dict: ToolDict }) {
  return <div className="flex flex-col gap-5 p-4 pt-2">{isDetection(item) ? <DetectionDetail d={item} dict={dict} /> : <ChangeDetail c={item} dict={dict} />}</div>;
}
