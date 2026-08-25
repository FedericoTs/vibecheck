import type { Metadata } from "next";
import { Space_Grotesk, JetBrains_Mono } from "next/font/google";
import { Analytics } from "@vercel/analytics/next";
import { headers } from "next/headers";
import { siteBaseUrl } from "@/lib/site-url";
import "./globals.css";

const display = Space_Grotesk({
  variable: "--font-space-grotesk",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
});

const mono = JetBrains_Mono({
  variable: "--font-jetbrains-mono",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

// Canonical base-URL resolution (headers-first, so OG links point at the real
// custom domain rather than Vercel's protected per-deploy URL) lives in
// @/lib/site-url, shared with robots.ts and sitemap.ts.

const description =
  "A free, open-source security report card for AI-built apps. See exactly what a stranger can read from your Supabase project and how your app is configured — runs in your browser, we store nothing.";

const TITLE = "vibecheck — is your app leaking?";

export async function generateMetadata(): Promise<Metadata> {
  return {
    metadataBase: await siteBaseUrl(),
    title: TITLE,
    description,
    // "./" resolves against the CURRENT route, so every page gets its own
    // canonical rather than all of them claiming to be the homepage. We flag a
    // missing canonical on other people's apps; ours was missing because the
    // homepage is a client component and cannot export metadata itself.
    alternates: { canonical: "./" },
    openGraph: {
      title: TITLE,
      description,
      siteName: "vibecheck",
      images: [{ url: "/api/og", width: 1200, height: 630, type: "image/png", alt: "vibecheck — a security report card for AI-built apps" }],
      type: "website",
    },
    twitter: {
      card: "summary_large_image",
      site: "@federico_sciuca",
      creator: "@federico_sciuca",
      title: TITLE,
      description,
      images: [{ url: "/api/og", alt: "vibecheck — a security report card for AI-built apps" }],
    },
  };
}

/**
 * Structured data so assistants don't have to infer what this page is — the
 * same check we run on other people's apps. Every claim here is literally true:
 * no aggregateRating, no review counts, no invented awards. It is a free
 * (price 0) open-source web tool, and that is all this says.
 */
function structuredData(base: string): string {
  const json = {
    "@context": "https://schema.org",
    "@type": "WebApplication",
    name: "vibecheck",
    alternateName: "is my app leaking?",
    url: base,
    description,
    applicationCategory: "SecurityApplication",
    operatingSystem: "Any (runs in the browser)",
    isAccessibleForFree: true,
    offers: { "@type": "Offer", price: "0", priceCurrency: "EUR" },
    license: "https://opensource.org/licenses/MIT",
    codeRepository: "https://github.com/FedericoTs/vibecheck",
    creator: { "@type": "Person", name: "Federico Sciuca" },
  };
  // Escape "<" so the payload can never terminate the script element early.
  return JSON.stringify(json).replace(/</g, "\\u003c");
}

export default async function RootLayout({ children }: LayoutProps<"/">) {
  const base = (await siteBaseUrl()).origin;
  // Next nonces the scripts it emits itself, but not ours. A JSON-LD data block
  // is not executable and the spec does not require it, yet browsers have
  // differed on this — carrying the nonce costs nothing and removes the doubt.
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  return (
    <html lang="en" className={`${display.variable} ${mono.variable} h-full antialiased`}>
      <body className="min-h-full">
        {children}
        <script nonce={nonce} type="application/ld+json" dangerouslySetInnerHTML={{ __html: structuredData(base) }} />
        <Analytics />
      </body>
    </html>
  );
}
