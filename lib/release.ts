// Sitemap schedule: a new site should not hand Google every page on day one.
// Every page is online and linked from the start; a page whose frontmatter
// has `sitemapFrom: "YYYY-MM-DD"` in the future is only left out of
// sitemap.xml until that day. The sitemap revalidates hourly
// (app/sitemap.ts), so pages join it on their date without a redeploy.
// The file reads are kept out of Turbopack's tracing (it would otherwise ship
// the whole project with the sitemap function); next.config.ts's
// outputFileTracingIncludes ships ./content instead.

import fs from "node:fs";
import path from "node:path";

/** "2026-11-26" counts from 2026-11-26T00:00:00Z; a full timestamp from that instant. */
export function releaseTime(date: string): number {
  return Date.parse(/^\d{4}-\d{2}-\d{2}$/.test(date) ? `${date}T00:00:00Z` : date);
}

/** No date, an unreadable one or a past one: in the sitemap. */
export function isReleased(date: string | undefined, now = Date.now()): boolean {
  if (!date) return true;
  const t = releaseTime(date);
  return Number.isNaN(t) || t <= now;
}

/** A top-level frontmatter value of a markdown file, without a YAML parser. */
export function frontmatterValue(raw: string, key: string): string | undefined {
  const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(raw.slice(0, 8000))?.[1];
  return fm ? new RegExp(`^${key}:\\s*["']?([^"'\\r\\n#]+?)["']?\\s*$`, "m").exec(fm)?.[1] : undefined;
}

const COLLECTIONS = ["blog"];

/** "/techniques/screensaver"-style paths (no locale) kept out of the sitemap at `now`. */
export function sitemapHiddenPaths(now = Date.now(), contentDir = path.join(process.cwd(), "content")): Set<string> {
  const out = new Set<string>();
  for (const collection of COLLECTIONS) {
    const dir = path.join(/*turbopackIgnore: true*/ contentDir, collection);
    if (!fs.existsSync(/*turbopackIgnore: true*/ dir)) continue;
    for (const locale of fs.readdirSync(/*turbopackIgnore: true*/ dir)) {
      const ldir = path.join(/*turbopackIgnore: true*/ dir, locale);
      if (!fs.statSync(/*turbopackIgnore: true*/ ldir).isDirectory()) continue;
      for (const file of fs.readdirSync(/*turbopackIgnore: true*/ ldir)) {
        if (!/\.mdx?$/.test(file)) continue;
        const from = frontmatterValue(fs.readFileSync(/*turbopackIgnore: true*/ path.join(/*turbopackIgnore: true*/ ldir, file), "utf8"), "sitemapFrom");
        if (!isReleased(from, now)) out.add(`/${collection}/${file.replace(/\.mdx?$/, "")}`);
      }
    }
  }
  return out;
}

/** Whether a sitemap URL ("https://…/en/techniques/x") is one of the held-back pages. */
export function heldBack(url: string, hidden: Set<string>): boolean {
  if (!hidden.size) return false;
  const p = new URL(url).pathname.replace(/\/+$/, "").replace(/^\/[a-z]{2}(?=\/)/, "");
  return hidden.has(p);
}
