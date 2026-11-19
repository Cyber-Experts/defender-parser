import type en from "@/app/[lang]/dictionaries/en.json";
import type { Change, Flag } from "./types";
import type { NamedId } from "./evtx";
import { isDetection, type Finding, type Item } from "./view";

/** UI strings for the Defender workspace (en.json's `tool`). */
export type ToolDict = (typeof en)["tool"];

/** `"{n} files"` + `{ n: 3 }` → `"3 files"`. */
export function t(template: string, params: Record<string, string | number> = {}): string {
  return template.replace(/\{(\w+)\}/g, (m, k: string) => (k in params ? String(params[k]) : m));
}

/** Look up a dynamic key (`flag_recent`, `ev_1116`…), falling back to `fallback`. */
export function pick(dict: ToolDict, key: string, fallback = key): string {
  const v = (dict as unknown as Record<string, unknown>)[key];
  return typeof v === "string" ? v : fallback;
}

/** `"{n} items"`, or the `_one` variant when there is one. */
export function plural(dict: ToolDict, key: string, n: number, params: Record<string, string | number> = {}): string {
  return t(n === 1 ? pick(dict, `${key}_one`, pick(dict, key)) : pick(dict, key), { n: n.toLocaleString("en"), ...params });
}

/** Parameters in words: an exclusion's kind (the registry key's name, "Processes") as "Process". */
function words(dict: ToolDict, params: Record<string, string> = {}): Record<string, string> {
  return params.kind ? { ...params, kind: pick(dict, `exkind_${params.kind}`, params.kind) } : { ...params };
}

/** A flag's title, with its parameters filled in. */
export function flagTitle(dict: ToolDict, f: Pick<Flag, "code" | "params">): string {
  return t(pick(dict, `flag_${f.code}`, f.code), words(dict, f.params));
}

export const flagWhy = (dict: ToolDict, code: string) => pick(dict, `why_${code}`, "");

/** A flag's name without its parameters (filters, groups). */
export function flagGroup(dict: ToolDict, code: string): string {
  return pick(dict, `group_${code}`, pick(dict, `flag_${code}`, code).replace(/\s*\(?\{\w+\}\)?/g, "").replace(/[:\s]+$/, ""));
}

/** A finding's heading: the flag's own title when every item says the same, else its group label. */
export function findingHeading(dict: ToolDict, f: Finding): string {
  const titles = new Set(f.items.map((it) => flagTitle(dict, it.flags.find((x) => x.code === f.code && x.severity === f.severity) ?? { code: f.code })));
  if (titles.size === 1) return [...titles][0];
  return flagGroup(dict, f.code);
}

/** An event ID with its name: "1116 · Malware detected". */
export function eventName(dict: ToolDict, id: number | null): string {
  if (id === null) return "?";
  const name = pick(dict, `ev_${id}`, "");
  return name ? `${id} · ${name}` : String(id);
}

/** A name for an ID, saying where it comes from: the log's own text, the documentation, or the documentation's order only. */
export function namedText(dict: ToolDict, n: NamedId): string {
  if (n.name === null) return n.id === null ? "—" : t(dict.id_only, { id: n.id, ref: n.ref ? ` (${n.ref})` : "" });
  if (n.from === "event") return n.id !== null ? `${n.name} (${n.id})` : n.name;
  return `${n.name} (${n.id}, ${n.from === "inferred" ? dict.from_inferred : dict.from_table})`;
}

/** A protection change in words: "Path exclusion added: C:\ProgramData\Intel". */
export function changeTitle(dict: ToolDict, c: Change): string {
  if (c.what === "command") return t(pick(dict, `cmd_${c.params.kind}`, dict.cmd_other), c.params);
  const p = words(dict, c.params);
  if (c.what === "setting_present" && p.meaning) p.meaning = ` (${pick(dict, `meaning_${p.meaning}`, p.meaning)})`;
  else if (c.what === "setting_present") p.meaning = "";
  if (p.policy === "yes") p.policy = dict.policy_suffix;
  else p.policy = "";
  return t(pick(dict, `change_${c.what}`, c.what), p);
}

/** One line for a detection or a change (findings, report). */
export function itemLabel(dict: ToolDict, x: Item): string {
  if (isDetection(x)) return `${x.threatName || "?"} · ${x.path || "?"}`;
  return changeTitle(dict, x);
}
