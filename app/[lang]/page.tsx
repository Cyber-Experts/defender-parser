import Link from "next/link";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { ArrowRight } from "lucide-react";
import { PostCard } from "@/components/post-card";
import { DefenderTool } from "@/components/defender/DefenderTool";
import { FaqJsonLd } from "@/components/seo/faq-jsonld";
import { blog } from "@/next-md-blog.config";
import { siteConfig } from "@/site.config";
import { LOCALES, hreflangFor } from "@/lib/i18n";
import { feedDiscoveryTypes, pageTitle, socialMetadata } from "@/lib/metadata";
import { getDictionary, hasLocale } from "./dictionaries";

type Params = { lang: string };

export async function generateStaticParams() {
  return LOCALES.map((lang) => ({ lang }));
}

export async function generateMetadata({ params }: { params: Promise<Params> }): Promise<Metadata> {
  const { lang } = await params;
  if (!hasLocale(lang)) return {};
  const dict = await getDictionary(lang);
  return {
    metadataBase: new URL(siteConfig.url),
    // The layout's `%s | Site` template doesn't apply to the page in its own
    // segment, so build the full title here.
    title: pageTitle(dict.metadata.homeTitle),
    description: dict.metadata.homeDescription,
    alternates: {
      canonical: `${siteConfig.url}/${lang}`,
      languages: hreflangFor(siteConfig.url, "/"),
      types: feedDiscoveryTypes(lang),
    },
    ...socialMetadata({
      lang,
      url: `${siteConfig.url}/${lang}`,
      title: siteConfig.name,
      description: dict.metadata.homeDescription,
    }),
  };
}

/** What the tool reads, as the hero's decorative chips (file names are language-neutral). */
const CHIPS = ["Quarantine\\Entries", "ResourceData", "DetectionHistory", "MPLog-*.log", "Defender%4Operational.evtx", "MpCmdRun.log", "Exclusions", "SOFTWARE"];

export default async function HomePage({ params }: { params: Promise<Params> }) {
  const { lang } = await params;
  if (!hasLocale(lang)) notFound();
  const locale = lang;
  const dict = await getDictionary(locale);
  const posts = await blog.getAll({ locale });
  const featured = posts.slice(0, 3);
  const ref = dict.reference;
  const sections: [string, string[], "p" | "ul"][] = [
    [ref.whatTitle, ref.what, "p"],
    [ref.filesTitle, ref.files, "ul"],
    [ref.provesTitle, ref.proves, "ul"],
    [ref.howTitle, ref.how, "ul"],
    [ref.limitsTitle, ref.limits, "ul"],
  ];
  return (
    <main id="main-content">
      <FaqJsonLd items={ref.faq.map((f) => ({ question: f.q, answer: f.a }))} />
      <div className="relative isolate">
        <div aria-hidden className="bg-grid absolute inset-0 -z-10" />
        <div aria-hidden className="bg-glow absolute inset-0 -z-10" />
        <section className="container mx-auto max-w-4xl px-4 pt-10 pb-8 text-center md:pt-12 md:pb-9">
          {/* The main promise first: nothing leaves the browser. */}
          <p className="status-pill">
            <span aria-hidden className="status-dot" />
            {dict.home.eyebrow}
          </p>
          <h1 className="mx-auto mt-5 max-w-[21ch] font-heading text-[2.25rem] leading-[1.04] font-extrabold tracking-[-0.035em] text-balance sm:text-5xl md:text-[3.6rem]">{dict.home.heading}</h1>
          <p className="mx-auto mt-5 max-w-2xl text-base leading-relaxed text-pretty text-muted-foreground sm:text-lg">{dict.home.subheading}</p>
          <ul aria-label={dict.home.readsLabel} className="mt-6 hidden flex-wrap justify-center gap-1.5 sm:flex">
            {CHIPS.map((c) => (
              <li key={c} className="chip">
                {c}
              </li>
            ))}
          </ul>
        </section>
      </div>

      <section id="tool" aria-label={dict.tool.workspaceLabel} className="container mx-auto scroll-mt-20 px-4">
        <DefenderTool dict={dict.tool} />
      </section>

      <div className="container mx-auto px-4">
        <article className="prose mx-auto mt-24 max-w-3xl dark:prose-invert">
          {sections.map(([title, items, kind], i) => (
            <section key={title}>
              <p aria-hidden className="section-index not-prose mt-14 mb-0">{String(i + 1).padStart(2, "0")}</p>
              <h2 className="mt-3">{title}</h2>
              {kind === "p" ? (
                items.map((p) => <p key={p}>{p}</p>)
              ) : (
                <ul>
                  {items.map((li) => (
                    <li key={li}>{li}</li>
                  ))}
                </ul>
              )}
            </section>
          ))}
          <section>
            <h2>{ref.faqTitle}</h2>
            <div className="not-prose divide-y overflow-hidden rounded-xl border bg-card shadow-[var(--shadow-soft)]">
              {ref.faq.map((f) => (
                <details key={f.q} className="group px-4 py-3.5 open:bg-surface [&_summary::-webkit-details-marker]:hidden">
                  <summary className="flex cursor-pointer list-none items-start justify-between gap-4 text-base font-semibold">
                    <h3 className="text-base font-semibold">{f.q}</h3>
                    <span aria-hidden className="mt-0.5 grid size-5 shrink-0 place-items-center rounded-md border bg-background font-mono text-xs text-muted-foreground transition-transform group-open:rotate-45 group-open:text-primary">
                      +
                    </span>
                  </summary>
                  <p className="mt-2 leading-relaxed text-muted-foreground">{f.a}</p>
                </details>
              ))}
            </div>
          </section>
        </article>

        {featured.length > 0 && (
          <section className="mx-auto mt-24 max-w-6xl">
            <div className="mb-6 flex items-end justify-between gap-4 border-b pb-3">
              <p className="eyebrow">{dict.nav.blog}</p>
              <Link href={`/${locale}/blog`} className="inline-flex items-center gap-1 text-sm font-medium underline-offset-4 hover:underline">
                {dict.home.readBlog} <ArrowRight className="size-3.5" aria-hidden />
              </Link>
            </div>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {featured.map((p) => (
                <PostCard key={p.slug} post={p} locale={locale} />
              ))}
            </div>
          </section>
        )}
      </div>
    </main>
  );
}
