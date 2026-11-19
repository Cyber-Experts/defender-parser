/**
 * Brand constants for places CSS variables can't reach: generated images
 * (favicon, apple-icon, Open Graph cards via Satori), the web manifest and
 * the browser `theme-color`.
 *
 * The site UI itself is themed by `app/theme.css`. When you rebrand, change
 * the palette in both files — the hex values below mirror the Tailwind v4
 * palette steps referenced there (`emerald` brand, darkened one step from
 * 600 up, on the green-tinted graphite base).
 */
export const brand = {
  colors: {
    /** --brand-500 / --brand-600 / --brand-700 in theme.css (emerald-500, -700, -800) */
    brand500: "#00bc7d",
    brand600: "#007a55",
    brand700: "#006045",
    /** --brand-400 (emerald-400), for marks on dark grounds */
    brand400: "#00d492",
    /** --base-* in theme.css (green-tinted graphite) */
    base50: "#f8fbf9",
    base200: "#e1e7e4",
    base400: "#9aa39f",
    base500: "#66706b",
    base800: "#232926",
    base900: "#131916",
    base950: "#080c0a",
    white: "#ffffff",
  },
  /** Open Graph / social card appearance. */
  og: {
    /** "dark" stands out in social feeds; "light" matches a light site. */
    theme: "dark" as "dark" | "light",
  },
} as const;

const c = brand.colors;

/** Browser UI color (address bar, PWA title bar) per color scheme. */
export const themeColor = { light: c.white, dark: c.base950 } as const;

/**
 * The logo mark, as raw SVG geometry on a 32×32 grid. Shared by the React
 * `<LogoMark>`, the favicon, the apple-icon and OG images so the mark is
 * defined exactly once. Replace these paths (or the whole mark) to rebrand.
 */
export const logoMark = {
  viewBox: "0 0 32 32",
  radius: 8,
  /** Filled shape (top layer): the scan line, a parsed record read across the shield. */
  fill: "M10.75 15.25h10.5a.75.75 0 0 1 0 1.5h-10.5a.75.75 0 0 1 0-1.5Z",
  /** Stroked shape (bottom layer): a shield. */
  stroke: "M16 6.25l7.25 2.9v6.1c0 4.55-3.05 8.05-7.25 9.75c-4.2-1.7-7.25-5.2-7.25-9.75v-6.1Z",
  strokeWidth: 2.25,
} as const;

/** Standalone SVG markup of the mark, for image routes. */
export function logoMarkSvg({
  background = c.brand600,
  foreground = c.white,
  size = 32,
  radius = logoMark.radius,
}: {
  background?: string;
  foreground?: string;
  size?: number;
  /** Corner radius on the 32-unit grid; 0 for platforms that mask icons (iOS). */
  radius?: number;
} = {}) {
  const m = logoMark;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="${m.viewBox}"><rect width="32" height="32" rx="${radius}" fill="${background}"/><path d="${m.fill}" fill="${foreground}" stroke="${foreground}" stroke-width="1.5" stroke-linejoin="round"/><path d="${m.stroke}" fill="none" stroke="${foreground}" stroke-width="${m.strokeWidth}" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
}

/** The mark as a data URI, for `<img>` inside ImageResponse (Satori). */
export function logoMarkDataUri(options?: Parameters<typeof logoMarkSvg>[0]) {
  return `data:image/svg+xml;base64,${Buffer.from(logoMarkSvg(options)).toString("base64")}`;
}
