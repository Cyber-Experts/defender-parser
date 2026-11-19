import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { Breadcrumbs } from "@/components/breadcrumbs";
import { JsonLd } from "@/components/seo/json-ld";
import { siteConfig } from "@/site.config";
import { LOCALES } from "@/lib/i18n";
import { staticPageMetadata } from "@/lib/metadata";
import { homeCrumb } from "@/lib/breadcrumbs";
import { LegalBody } from "@/components/legal-page";
import { getDictionary, hasLocale } from "../dictionaries";
import { OptOut } from "@borromic/analytics/opt-out";

type Params = { lang: string };

export async function generateStaticParams() {
  return LOCALES.map((lang) => ({ lang }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<Params>;
}): Promise<Metadata> {
  const { lang } = await params;
  if (!hasLocale(lang)) return {};
  const { privacyPage: pp } = await getDictionary(lang);
  return staticPageMetadata({ lang, path: "/privacy", title: pp.title, description: pp.description });
}

// The text describes what the site really does (Vercel hosting, Vercel Web
// Analytics + Speed Insights, no cookies, files never uploaded, the usage
// events sent by components/defender/DefenderTool.tsx and
// components/auto-events.tsx); update it if those events change or if an
// analytics provider is set through NEXT_PUBLIC_ANALYTICS_PROVIDER
// (see components/analytics.tsx).

export default async function PrivacyPage({
  params,
}: {
  params: Promise<Params>;
}) {
  const { lang } = await params;
  if (!hasLocale(lang)) notFound();
  const locale = lang;
  const dict = await getDictionary(locale);
  const pp = dict.privacyPage;
  const url = `${siteConfig.url}/${lang}/privacy`;
  return (
    <>
      <JsonLd
        data={{
          "@context": "https://schema.org",
          "@type": "WebPage",
          "@id": url,
          url,
          name: pp.title,
          description: pp.description,
          inLanguage: locale,
          isPartOf: { "@id": `${siteConfig.url}/#website` },
          about: { "@id": `${siteConfig.url}/#organization` },
          datePublished: "2026-11-20",
          dateModified: "2026-11-20",
        }}
      />
      <main id="main-content" className="container mx-auto max-w-3xl px-4 py-12 prose dark:prose-invert">
        <Breadcrumbs items={[homeCrumb(locale, dict), { name: pp.title }]} />
        <LegalBody text={pp} />
        <p>
          Pages visited and a few actions on them, with the country, are also measured by Borromic web analytics, with no cookies and no identification of visitors.{" "}
          <OptOut stop="Stop measuring my visits" resume="Measure my visits again" />
        </p>
      </main>
    </>
  );
}
