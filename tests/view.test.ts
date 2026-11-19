// The views and exports: findings, filters, the timeline, CSV formula
// safety, JSON and Markdown, and that no export carries quarantined content.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import en from "@/app/[lang]/dictionaries/en.json";
import { changeTitle, eventName, findingHeading, flagGroup, flagTitle, flagWhy, itemLabel, namedText, type ToolDict } from "@/lib/defender/dict";
import { NAMED_EVENTS } from "@/lib/defender/evtx";
import type { Analysis } from "@/lib/defender/types";
import { buildTimeline, changesCsv, computeFindings, csvCell, DEFAULT_FILTERS, detectionsCsv, filesSeen, filterChanges, filterDetections, filterMplog, filterTimeline, processesSeen, timelineCsv, toJson, toMarkdown, unzonedCount } from "@/lib/defender/view";
import { M64, PUA } from "@/scripts/make-samples";
import { analyzeAll, input, oplog, threat } from "./helpers";

const dict = en.tool as ToolDict;
const DIR = join(process.cwd(), "public/samples");
let a: Analysis;
beforeAll(async () => {
  const manifest = JSON.parse(readFileSync(join(DIR, "manifest.json"), "utf8")) as { file: string; mtime: number }[];
  a = await analyzeAll(manifest.map((m) => ({ path: m.file, bytes: new Uint8Array(readFileSync(join(DIR, m.file))), mtime: m.mtime })));
});
const labels = () => ({ finding: (f: Parameters<typeof findingHeading>[1]) => findingHeading(dict, f), flag: (f: Parameters<typeof flagTitle>[1]) => flagTitle(dict, f), why: (c: string) => flagWhy(dict, c), item: (x: Parameters<typeof itemLabel>[1]) => itemLabel(dict, x) });

describe("dictionary", () => {
  it("has a title, a group and a why for every flag the engine sets", () => {
    const engine = readFileSync("lib/defender/engine.ts", "utf8");
    const used = new Set([...engine.matchAll(/code: "([a-z_]+)", severity/g)].map((m) => m[1]));
    for (const m of engine.matchAll(/code: (p\.code|r)/g)) void m;
    for (const c of ["staging_path", "downloads", "exclusion_drive_root", "exclusion_writable", "exclusion_broad_ext", "exclusion_script_host", "exclusion_process_name"]) used.add(c);
    expect(used.size).toBeGreaterThan(20);
    for (const c of used) {
      expect(dict, c).toHaveProperty(`flag_${c}`);
      expect(flagWhy(dict, c).length, c).toBeGreaterThan(40);
      expect(flagGroup(dict, c), c).not.toMatch(/\{/);
    }
  });

  it("names every event the tool names, and every change and command", () => {
    for (const id of NAMED_EVENTS) expect(eventName(dict, id)).toMatch(new RegExp(`^${id} · \\w`));
    for (const c of a.changes) expect(changeTitle(dict, c)).not.toMatch(/\{\w+\}/);
    expect(namedText(dict, { id: 4, name: null, from: null, ref: "%%845" })).toBe("ID 4 (%%845): name not recorded");
    expect(namedText(dict, { id: 10, name: "AMSI", from: "inferred" })).toBe("AMSI (10, name inferred from the documentation's order)");
  });
});

describe("findings and filters", () => {
  it("groups flags worst first across detections and changes", () => {
    const f = computeFindings([...a.detections, ...a.changes]);
    expect(f.map((x) => `${x.code}:${x.severity}:${x.items.length}`)).toEqual([
      "exclusion_near_detection:high:2",
      "exclusion_writable:high:2",
      "exclusion_nearby:high:1",
      "exclusion_process_name:medium:2",
      "amsi:medium:1",
      "tamper_blocked:medium:1",
      "recent:low:7",
      "downloads:low:2",
    ]);
    expect(findingHeading(dict, f[0])).toBe("Process exclusion m64.exe, 1 min after a detection of Backdoor:Win64/Gfxhelp.A");
  });

  it("filters by text, flag and severity", () => {
    expect(filterDetections(a.detections, { ...DEFAULT_FILTERS, query: "7zfm" }).map((d) => d.threatName)).toEqual(["Backdoor:Win64/Gfxhelp.A"]);
    expect(filterDetections(a.detections, { ...DEFAULT_FILTERS, flag: "amsi" })).toHaveLength(1);
    expect(filterDetections(a.detections, { ...DEFAULT_FILTERS, minSeverity: "high" })).toHaveLength(1);
    expect(filterChanges(a.changes, DEFAULT_FILTERS, "command")).toHaveLength(3);
    expect(filterChanges(a.changes, { ...DEFAULT_FILTERS, query: "programdata\\intel" })).toHaveLength(2);
    expect(filterMplog(a.mplog, { query: "", host: "all" }, "files").map((m) => m.fields.Path)).toEqual(["C:\\Users\\alice\\Downloads\\Invoice_2026-0914.pdf.exe", "C:\\Users\\svc_backup\\Downloads\\tools\\m64.exe"]);
    expect(filesSeen(a.mplog).map((f) => [f.path.split("\\").pop(), f.detected])).toEqual([
      ["Invoice_2026-0914.pdf.exe", false],
      ["m64.exe", true],
    ]);
    expect(processesSeen(a.mplog).map((p) => p.name)).toEqual(["MsMpEng.exe", "OUTLOOK.EXE", "msedge.exe", "Invoice_2026-0914.pdf.exe", "powershell.exe", "7zFM.exe"]);
  });
});

describe("timeline", () => {
  it("places only UTC records, sorted, and counts the rest", () => {
    const tl = buildTimeline(a);
    expect(tl.every((t, i) => i === 0 || tl[i - 1].time <= t.time)).toBe(true);
    expect(new Set(tl.map((t) => t.source))).toEqual(new Set(["event", "history", "quarantine", "mplog", "registry"]));
    expect(unzonedCount(a)).toEqual({ mplog: 1, commands: 3 });
    expect(tl.some((t) => t.what === "mp_threat_actions")).toBe(false);
    const day = filterTimeline(tl, { query: "gfxhelp", host: "all" });
    expect(day.length).toBeGreaterThan(4);
    expect(filterTimeline(tl, { query: "", host: "all" }, "registry").map((t) => t.detail)).toEqual([
      "Microsoft\\Windows Defender\\Features",
      "Microsoft\\Windows Defender\\Exclusions\\Extensions",
      "Microsoft\\Windows Defender",
      "Microsoft\\Windows Defender\\Exclusions",
      "Microsoft\\Windows Defender\\Exclusions\\Paths",
      "Microsoft\\Windows Defender\\Exclusions\\Processes",
    ]);
  });
});

describe("exports", () => {
  it("makes CSV cells that spreadsheets cannot read as formulas", () => {
    expect(csvCell("=HYPERLINK(1)")).toBe("'=HYPERLINK(1)");
    expect(csvCell("  +1")).toBe("'  +1");
    expect(csvCell("-2")).toBe("'-2");
    expect(csvCell("@x")).toBe("'@x");
    expect(csvCell("\tx")).toBe("'\tx");
    expect(csvCell("＝1")).toBe("'＝1");
    expect(csvCell('a,"b"')).toBe('"a,""b"""');
    expect(csvCell(null)).toBe("");
  });

  it("keeps hostile names inert in every export", async () => {
    const evil = await analyzeAll([input("H/C/Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx", oplog([[Date.UTC(2026, 0, 1), 1116, threat({ time: Date.UTC(2026, 0, 1), name: '=HYPERLINK("http://x.example")', path: "file:_C:\\a`b|<img src=x>.exe", user: "@evil" })]]))]);
    const csv = detectionsCsv(evil.detections);
    expect(csv).toContain(`'=HYPERLINK(""http://x.example"")`);
    expect(csv).toContain("'@evil");
    const md = toMarkdown(evil, labels());
    expect(md).not.toMatch(/<img|`b\|/);
  });

  it("never writes quarantined content: not in CSV, JSON or Markdown", () => {
    const outputs = [detectionsCsv(a.detections), changesCsv(a.changes), timelineCsv(buildTimeline(a)), toJson(a), toMarkdown(a, labels())];
    for (const content of [M64, PUA]) {
      const marker = new TextDecoder().decode(content.subarray(0, 60));
      const padding = new TextDecoder().decode(content.subarray(200, 260));
      for (const o of outputs) {
        expect(o).not.toContain(marker.slice(0, 40));
        expect(o).not.toContain(padding);
      }
    }
    // The analysis itself holds no recovered bytes: only sizes and hashes.
    expect(JSON.stringify(a)).not.toContain("placeholder padding");
  });

  it("writes JSON with ISO times and the Markdown report", () => {
    const j = JSON.parse(toJson(a));
    expect(j.tool).toBe("defender-parser");
    expect(j.detections[0].time).toBe("2026-09-14T10:06:51.388Z");
    expect(j.registry[0].keyLastWrite).toMatch(/^2026-/);
    const md = toMarkdown(a, labels());
    expect(md).toMatch(/^# Microsoft Defender: FIN-WKS-07/);
    expect(md).toContain("### HIGH · Process exclusion m64.exe, 1 min after a detection of Backdoor:Win64/Gfxhelp.A");
    expect(md).toContain("- 2026-09-14T10:08:12.771Z · Process exclusion added: m64.exe");
    expect(md).toContain("MPLog entries: 17 (1 without a zone)");
    const csv = detectionsCsv(a.detections).split("\r\n");
    expect(csv[0]).toBe("severity,time_utc,host,threat,threat_id,defender_severity,category,path,user,process,detection_source,action,result,error_code,quarantined,sha256,sha1,md5,flags,sources,detection_id");
    expect(csv[1]).toContain("Backdoor:Win64/Gfxhelp.A");
  });
});
