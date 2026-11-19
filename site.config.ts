function resolveSiteUrl(): string {
  // 1. Explicit override always wins.
  if (process.env.NEXT_PUBLIC_SITE_URL) {
    return process.env.NEXT_PUBLIC_SITE_URL.replace(/\/$/, "");
  }
  // 2. On Vercel production, use the project's stable production URL.
  if (
    process.env.VERCEL_ENV === "production" &&
    process.env.VERCEL_PROJECT_PRODUCTION_URL
  ) {
    return `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`;
  }
  // 3. On any other Vercel deployment (preview, branch), use the per-deploy URL
  //    so OG / canonical / sitemap point to the preview itself.
  if (process.env.VERCEL_URL) {
    return `https://${process.env.VERCEL_URL}`;
  }
  // 4. Local builds: the production origin (canonical, sitemap, OG).
  return "https://www.defenderparser.com";
}

export const siteConfig = {
  name: "Defender Parser",
  shortName: "Defender Parser",
  description:
    "Read Microsoft Defender's quarantine, DetectionHistory, MPLog, Operational event log, MpCmdRun.log and exclusions in your browser: one detection and tampering timeline, quarantined files described and recoverable as an encrypted ZIP. Nothing is uploaded.",
  url: resolveSiteUrl(),
  twitter: undefined as string | undefined,
  defaultAuthor: "Florian Amette",
  authors: [
    {
      name: "Florian Amette",
      url: "https://www.f4k.fr",
      // Square photo (local path under /public or absolute URL). Without one,
      // initials on a brand tint are shown.
      avatar: undefined as string | undefined,
      // E-E-A-T signals (Person JSON-LD). All optional but high-value for
      // authority: who the author is, what they're expert in, and verifiable
      // profiles. `sameAs` is merged with url/twitter/github automatically.
      bio: "DFIR engineer. Author of Defender Parser, PCA Parser, Windows Persistence and the in-browser forensic parser series.",
      jobTitle: "DFIR engineer",
      knowsAbout: ["Digital forensics", "Incident response", "Windows forensics", "Microsoft Defender", "Malware triage"],
      sameAs: [] as string[],
    },
  ],
  defaultOgImage: "/opengraph-image",
  organization: {
    // Same publisher as the sister parser sites (linuxlog-parser, evtx-parser…).
    legalName: "Cyber Experts",
    // Raster (PNG) logo — Google requires a bitmap ≥112px for Organization.
    logo: "/apple-icon",
    foundingDate: "2025-01-01",
    founder: "Florian Amette" as string | undefined,
    // Optional but high-impact: populate this once you have a Wikidata entity.
    wikidata: undefined as string | undefined,
    sameAs: ["https://github.com/Cyber-Experts"] as string[],
    address: {
      streetAddress: undefined as string | undefined,
      addressLocality: undefined as string | undefined,
      addressRegion: undefined as string | undefined,
      postalCode: undefined as string | undefined,
      addressCountry: undefined as string | undefined,
    },
    contactPoint: {
      email: "contact@defenderparser.com",
      telephone: undefined as string | undefined,
      contactType: "customer support",
      areaServed: [] as string[],
      availableLanguage: ["en"],
    },
  },
  oembed: {
    /** Consume oEmbed: turn bare URLs in posts into rich embeds. */
    enabled: true,
    /** Max width hint sent to providers (px). */
    maxWidth: 800,
    /**
     * Best-effort discovery for hosts not in the curated provider registry
     * (fetches the page and parses its oEmbed <link>). Off by default — it adds
     * a network round-trip per unknown bare URL at build time.
     */
    discovery: false,
    /** Provide oEmbed: expose /oembed and discovery <link> tags for our pages. */
    provide: true,
  },
  verification: {
    google: process.env.NEXT_PUBLIC_GOOGLE_SITE_VERIFICATION,
    bing: process.env.NEXT_PUBLIC_BING_SITE_VERIFICATION,
  },
  analytics: {
    provider: process.env.NEXT_PUBLIC_ANALYTICS_PROVIDER as
      | "plausible"
      | "umami"
      | "ga4"
      | undefined,
    domain: process.env.NEXT_PUBLIC_ANALYTICS_DOMAIN,
    id: process.env.NEXT_PUBLIC_ANALYTICS_ID,
  },
} as const;

export type SiteConfig = typeof siteConfig;
