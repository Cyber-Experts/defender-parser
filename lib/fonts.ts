import { Archivo, Red_Hat_Mono } from "next/font/google";

/**
 * Typefaces: Archivo, a grotesque with a width axis, for everything; headings
 * set it semi-expanded (`font-stretch` in globals.css) for the confident,
 * engineered voice of a security tool. Red Hat Mono for paths, hashes, times
 * and code: compact, calm, unambiguous 0/O and 1/l. Both are self-hosted by
 * next/font at build time (no runtime font requests).
 *
 * OG images can't use next/font: they read `assets/fonts/Archivo-*.woff`.
 */
const sans = Archivo({
  variable: "--font-brand-sans",
  subsets: ["latin"],
  axes: ["wdth"],
  display: "swap",
});

const mono = Red_Hat_Mono({
  variable: "--font-brand-mono",
  subsets: ["latin"],
  display: "swap",
});

/** Class names that define the font CSS variables; put on `<html>`. */
export const fontVariables = [sans.variable, mono.variable].join(" ");
