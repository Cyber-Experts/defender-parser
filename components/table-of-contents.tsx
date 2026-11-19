"use client";

import { useEffect, useState } from "react";
import type { TocItem } from "@/lib/toc";
import { cn } from "@/lib/utils";

/** The post's headings, with the section being read marked (aria-current) as the page scrolls. */
export function TableOfContents({
  items,
  title,
}: {
  items: TocItem[];
  title: string;
}) {
  const [active, setActive] = useState<string | null>(null);

  useEffect(() => {
    const headings = items
      .map((it) => document.getElementById(it.slug))
      .filter((el): el is HTMLElement => el !== null);
    if (!headings.length) return;
    let frame = 0;
    const update = () => {
      frame = 0;
      let current: string | null = null;
      for (const el of headings) {
        if (el.getBoundingClientRect().top > 120) break;
        current = el.id;
      }
      setActive(current);
    };
    const onScroll = () => {
      if (!frame) frame = requestAnimationFrame(update);
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      window.removeEventListener("scroll", onScroll);
      if (frame) cancelAnimationFrame(frame);
    };
  }, [items]);

  if (!items.length) return null;
  return (
    <nav aria-label={title} className="text-sm">
      <h2 className="font-semibold mb-3">{title}</h2>
      <ol className="space-y-2 border-l">
        {items.map((it) => {
          const current = active === it.slug;
          return (
            <li
              key={it.slug}
              className={cn(
                "-ml-px border-l-2 border-transparent pl-3 transition-colors",
                it.depth === 3 && "pl-6 text-muted-foreground",
                current && "border-primary text-foreground",
              )}
            >
              <a
                href={`#${it.slug}`}
                aria-current={current ? "location" : undefined}
                className={cn("hover:text-foreground hover:underline underline-offset-4", current && "font-medium")}
              >
                {it.text}
              </a>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
