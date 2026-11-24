import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { ImageResponse } from "next/og";
import { brand, logoMarkDataUri } from "@/lib/brand";
import { siteConfig } from "@/site.config";
import { ogSize } from "@/lib/og-size";

export { ogSize };

/**
 * Branded Open Graph / Twitter card renderer shared by every
 * `opengraph-image.tsx`: a dark graphite card, an emerald glow and a fine
 * grid, the records-and-magnifier mark, the title in Archivo ExtraBold, and the scan line
 * with the site's promise at the foot. Colors come from `lib/brand.ts`; the
 * font is Archivo from `assets/fonts` (Satori can't use next/font).
 */

const fontsPromise = Promise.all([
  readFile(join(process.cwd(), "assets/fonts/Archivo-Regular.woff")),
  readFile(join(process.cwd(), "assets/fonts/Archivo-SemiBold.woff")),
  readFile(join(process.cwd(), "assets/fonts/Archivo-ExtraBold.woff")),
]);

type OgCardProps = {
  title: string;
  description?: string;
  /** Small label top-right, e.g. "Blog" or a tag. */
  eyebrow?: string;
};

function palette() {
  const c = brand.colors;
  return brand.og.theme === "dark"
    ? {
        background: c.base950,
        foreground: "#f3f7f5",
        muted: c.base400,
        subtle: c.base500,
        line: "rgba(255,255,255,0.045)",
        pillBorder: "rgba(255,255,255,0.14)",
        glow: `${c.brand600}73`,
        accent: c.brand400,
      }
    : {
        background: c.white,
        foreground: c.base950,
        muted: c.base500,
        subtle: c.base400,
        line: "rgba(8,12,10,0.05)",
        pillBorder: c.base200,
        glow: `${c.brand500}33`,
        accent: c.brand600,
      };
}

function titleSize(title: string) {
  if (title.length > 90) return 50;
  if (title.length > 55) return 58;
  return 70;
}

export function OgCard({ title, description, eyebrow }: OgCardProps) {
  const p = palette();
  const host = new URL(siteConfig.url).host.replace(/^www\./, "");
  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
        padding: "64px 72px",
        background: p.background,
        backgroundImage: `radial-gradient(circle at 0% 0%, ${p.glow} 0%, transparent 52%), linear-gradient(${p.line} 1px, transparent 1px), linear-gradient(90deg, ${p.line} 1px, transparent 1px)`,
        backgroundSize: "100% 100%, 48px 48px, 48px 48px",
        color: p.foreground,
        fontFamily: "Archivo",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src={logoMarkDataUri({ size: 52 })} width={52} height={52} alt="" />
          <span style={{ fontSize: 30, fontWeight: 800, letterSpacing: -0.6 }}>{siteConfig.name}</span>
        </div>
        {eyebrow && (
          <span
            style={{
              display: "flex",
              fontSize: 20,
              fontWeight: 600,
              letterSpacing: 2,
              textTransform: "uppercase",
              color: p.accent,
              border: `1px solid ${p.pillBorder}`,
              borderRadius: 999,
              padding: "8px 20px",
            }}
          >
            {eyebrow}
          </span>
        )}
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 22, maxWidth: 1020 }}>
        <div style={{ display: "block", fontSize: titleSize(title), fontWeight: 800, lineHeight: 1.06, letterSpacing: -2.2, lineClamp: 3 }}>{title}</div>
        {description && <div style={{ display: "block", fontSize: 27, lineHeight: 1.4, color: p.muted, lineClamp: 2 }}>{description}</div>}
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
        <div style={{ display: "flex", height: 1, background: `linear-gradient(90deg, ${p.accent}, transparent 70%)` }} />
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: 22, color: p.subtle }}>
          <span style={{ display: "flex", alignItems: "center", gap: 12, color: p.muted }}>
            <span style={{ display: "flex", width: 10, height: 10, borderRadius: 999, background: p.accent }} />
            Runs in your browser · nothing is uploaded
          </span>
          <span style={{ display: "flex", fontWeight: 600, color: p.muted }}>{host}</span>
        </div>
      </div>
    </div>
  );
}

/** Render an `OgCard` as a cached PNG response. */
export async function renderOgImage(props: OgCardProps) {
  const [regular, semibold, extrabold] = await fontsPromise;
  return new ImageResponse(<OgCard {...props} />, {
    ...ogSize,
    fonts: [
      { name: "Archivo", data: regular, weight: 400, style: "normal" },
      { name: "Archivo", data: semibold, weight: 600, style: "normal" },
      { name: "Archivo", data: extrabold, weight: 800, style: "normal" },
    ],
    headers: {
      // OG images are content-addressed by URL; safe to cache forever.
      "Cache-Control": "public, max-age=31536000, immutable",
    },
  });
}
