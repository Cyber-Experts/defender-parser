import Link from "next/link";
import type { ReactNode } from "react";
import { siteConfig } from "@/site.config";

export type LegalText = {
  title: string;
  description: string;
  updated: string;
  summary: string[];
  /** `{site}`, `{org}`, `{email}`, `{vercel}` and `{privacy}` are filled in when rendering. */
  sections: { h: string; p?: string[]; list?: string[] }[];
};

const VERCEL_PRIVACY = "https://vercel.com/legal/privacy-policy";

type Links = { privacy?: { href: string; label: string } };

function fill(text: string, links: Links): ReactNode[] {
  const { email } = siteConfig.organization.contactPoint;
  return text.split(/(\{site\}|\{org\}|\{email\}|\{vercel\}|\{privacy\})/).map((part, i) => {
    if (part === "{privacy}" && links.privacy)
      return (
        <Link key={i} href={links.privacy.href}>
          {links.privacy.label}
        </Link>
      );
    if (part === "{site}") return siteConfig.name;
    if (part === "{org}") return siteConfig.organization.legalName;
    if (part === "{email}")
      return (
        <a key={i} href={`mailto:${email}`}>
          {email}
        </a>
      );
    if (part === "{vercel}")
      return (
        <a key={i} href={VERCEL_PRIVACY} rel="noopener noreferrer" target="_blank">
          vercel.com/legal/privacy-policy
        </a>
      );
    return part;
  });
}

/** Body of the privacy and terms pages: date, summary card, sections. */
export function LegalBody({ text, links = {} }: { text: LegalText; links?: Links }) {
  return (
    <>
      <h1 className="hyphens-auto [overflow-wrap:anywhere]">{text.title}</h1>
      <p>
        <em>{text.updated}</em>
      </p>
      <ul className="not-prose my-6 space-y-2 rounded-xl border bg-card px-5 py-4 text-sm leading-relaxed shadow-[var(--shadow-soft)]">
        {text.summary.map((s) => (
          <li key={s} className="flex gap-2.5">
            <span aria-hidden className="mt-2 size-1.5 shrink-0 rounded-full bg-foreground" />
            {s}
          </li>
        ))}
      </ul>
      {text.sections.map((sec) => (
        <section key={sec.h}>
          <h2>{sec.h}</h2>
          {sec.list && (
            <ul>
              {sec.list.map((li) => (
                <li key={li}>{fill(li, links)}</li>
              ))}
            </ul>
          )}
          {sec.p?.map((para) => (
            <p key={para}>{fill(para, links)}</p>
          ))}
        </section>
      ))}
    </>
  );
}
