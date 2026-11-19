import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { Breadcrumbs } from "@/components/breadcrumbs";
import { JsonLd } from "@/components/seo/json-ld";
import { siteConfig } from "@/site.config";
import { LOCALES } from "@/lib/i18n";
import { LegalBody } from "@/components/legal-page";
import { staticPageMetadata } from "@/lib/metadata";
import { homeCrumb } from "@/lib/breadcrumbs";
import { getDictionary, hasLocale } from "../dictionaries";

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
  const { termsPage: tp } = await getDictionary(lang);
  return staticPageMetadata({ lang, path: "/terms", title: tp.title, description: tp.description });
}

export default async function TermsPage({
  params,
}: {
  params: Promise<Params>;
}) {
  const { lang } = await params;
  if (!hasLocale(lang)) notFound();
  const locale = lang;
  const dict = await getDictionary(locale);
  const tp = dict.termsPage;
  const url = `${siteConfig.url}/${lang}/terms`;
  // "…described in the privacy policy".
  const pt = dict.privacyPage.title;
  const privacyLabel = pt.charAt(0).toLowerCase() + pt.slice(1);
  return (
    <>
      <JsonLd
        data={{
          "@context": "https://schema.org",
          "@type": "WebPage",
          "@id": url,
          url,
          name: tp.title,
          description: tp.description,
          inLanguage: locale,
          isPartOf: { "@id": `${siteConfig.url}/#website` },
          about: { "@id": `${siteConfig.url}/#organization` },
          datePublished: "2026-11-20",
          dateModified: "2026-11-20",
        }}
      />
      <main id="main-content" className="container mx-auto max-w-3xl px-4 py-12 prose dark:prose-invert">
        <Breadcrumbs items={[homeCrumb(locale, dict), { name: tp.title }]} />
        <LegalBody text={tp} links={{ privacy: { href: `/${locale}/privacy`, label: privacyLabel } }} />
      </main>
    </>
  );
}
