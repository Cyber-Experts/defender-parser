// Sitemap schedule (lib/release.ts): every page is online; pages with a
// future `sitemapFrom` stay out of sitemap.xml until that date. Checked on
// a content folder made here, so the test does not depend on the articles.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { frontmatterValue, heldBack, isReleased, releaseTime, sitemapHiddenPaths } from "@/lib/release";

const dir = mkdtempSync(join(tmpdir(), "defender-release-"));
const write = (p: string, fm: string) => {
  mkdirSync(join(dir, p, ".."), { recursive: true });
  writeFileSync(join(dir, p), `---\n${fm}\n---\n\nBody.\n`);
};
write("blog/en/what-is-defender-quarantine.md", 'title: "Quarantine"\ndate: "2026-11-19"');
write("blog/en/mplog-lines.md", 'title: "MPLog"\ndate: "2026-11-19"\nsitemapFrom: "2026-11-26"');
write("blog/en/detectionhistory.md", 'title: "History"\nsitemapFrom: "2026-12-03"');
// Not a collection of this site (no glossary): never read.
write("glossary/en/msmpeng.md", 'title: "MsMpEng"\nsitemapFrom: "2026-12-03"');
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("sitemap schedule", () => {
  it("reads sitemapFrom and counts from midnight UTC of that day", () => {
    expect(frontmatterValue('---\ntitle: "x"\ndate: "2026-11-19"\nsitemapFrom: "2026-11-26"\n---\nsitemapFrom: "1999-01-01"', "sitemapFrom")).toBe("2026-11-26");
    expect(frontmatterValue("---\ndate: 2026-12-03\n---\n", "sitemapFrom")).toBeUndefined();
    expect(releaseTime("2026-11-26")).toBe(Date.UTC(2026, 10, 26));
    expect(isReleased("2026-11-26", Date.UTC(2026, 10, 25, 23, 59))).toBe(false);
    expect(isReleased("2026-11-26", Date.UTC(2026, 10, 26))).toBe(true);
    expect(isReleased(undefined)).toBe(true);
    expect(isReleased("not a date")).toBe(true);
  });

  it("holds back the later batches only, and only blog pages", () => {
    const hidden = sitemapHiddenPaths(Date.UTC(2026, 10, 19, 12), dir);
    expect([...hidden].sort()).toEqual(["/blog/detectionhistory", "/blog/mplog-lines"]);
    expect(heldBack("https://www.defenderparser.com/en/blog/mplog-lines", hidden)).toBe(true);
    expect(heldBack("https://www.defenderparser.com/en/blog/detectionhistory/", hidden)).toBe(true);
    expect(heldBack("https://www.defenderparser.com/en/blog/what-is-defender-quarantine", hidden)).toBe(false);
    expect(heldBack("https://www.defenderparser.com/en/blog", hidden)).toBe(false);
    expect([...sitemapHiddenPaths(Date.UTC(2026, 10, 27), dir)]).toEqual(["/blog/detectionhistory"]);
    expect(sitemapHiddenPaths(Date.UTC(2026, 11, 3), dir).size).toBe(0);
  });

  it("reads the site's own content folder without failing", () => {
    expect(sitemapHiddenPaths(Date.UTC(2026, 10, 19))).toBeInstanceOf(Set);
  });
});
