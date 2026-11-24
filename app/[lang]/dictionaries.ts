import "server-only";
import { type Locale } from "@/lib/i18n";
import type en from "./dictionaries/en.json";
import type { LegalText } from "@/components/legal-page";

// Single source of truth lives in lib/i18n; re-exported here for the pages that
// already import locale helpers from this module.
export { hasLocale } from "@/lib/i18n";

export type Dictionary = {
  metadata: {
    homeTitle: string;
    homeDescription: string;
    blogTitle: string;
    blogDescription: string;
    searchTitle: string;
    searchDescription: string;
    sitemapTitle: string;
    sitemapDescription: string;
  };
  /** Site-wide strip above the header: no affiliation with Microsoft. */
  disclaimer: string;
  nav: {
    home: string;
    blog: string;
    search: string;
    contact: string;
    menu: string;
  };
  authors: {
    title: string;
    description: string;
    latestArticles: string;
    article: string;
    articles: string;
    expertise: string;
    website: string;
    viewProfile: string;
  };
  toggleTheme: string;
  footer: { rights: string; sitemap: string; rss: string };
  blog: {
    tableOfContents: string;
    relatedArticles: string;
    readMore: string;
    readingTime: string;
    publishedOn: string;
    updatedOn: string;
    byAuthor: string;
    writtenBy: string;
    estReadingTime: string;
    tags: string;
    share: string;
    noPosts: string;
    previous: string;
    next: string;
    page: string;
    faq: string;
    tools: string;
    supplies: string;
    totalTime: string;
    result: string;
  };
  tag: { title: string; back: string };
  search: { placeholder: string; noResults: string };
  notFound: { title: string; cta: string };
  home: {
    heading: string;
    subheading: string;
    readBlog: string;
    /** The promise in the hero's status pill. */
    eyebrow: string;
    /** Accessible name of the list of artifacts the tool reads. */
    readsLabel: string;
    /** The home page's share card: a one-line description and its label. */
    ogDescription: string;
    ogEyebrow: string;
  };
  /** The Defender tool's strings (lib/defender/dict.ts). */
  tool: (typeof en)["tool"];
  /** Reference copy and FAQ under the tool on the home page. */
  reference: (typeof en)["reference"];
  privacyPage: LegalText;
  termsPage: LegalText;
};

const loaders: Record<Locale, () => Promise<Dictionary>> = {
  en: () =>
    import("./dictionaries/en.json").then((m) => m.default as Dictionary),
};

export async function getDictionary(locale: Locale): Promise<Dictionary> {
  return loaders[locale]();
}
