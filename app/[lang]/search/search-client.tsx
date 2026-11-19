"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { Input } from "@/components/ui/input";

type Item = {
  slug: string;
  /** Page URL. */
  href: string;
  title: string;
  description: string;
  tags: string[];
  date: string;
};

export function SearchClient({
  items,
  placeholder,
  noResults,
}: {
  items: Item[];
  placeholder: string;
  noResults: string;
}) {
  const [q, setQ] = useState("");
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return items;
    return items.filter((i) =>
      [i.title, i.description, ...i.tags].some((s) =>
        s.toLowerCase().includes(needle),
      ),
    );
  }, [items, q]);
  return (
    <div className="mt-8 space-y-6">
      <Input
        type="search"
        autoFocus
        placeholder={placeholder}
        value={q}
        onChange={(e) => setQ(e.target.value)}
        aria-label={placeholder}
      />
      {filtered.length === 0 ? (
        <p className="text-muted-foreground">{noResults}</p>
      ) : (
        <ul className="space-y-4" role="list">
          {filtered.map((i) => (
            <li key={i.href}>
              <Link
                href={i.href}
                className="block group"
              >
                <h2 className="font-semibold group-hover:underline">{i.title}</h2>
                {i.description && (
                  <p className="text-sm text-muted-foreground">{i.description}</p>
                )}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
