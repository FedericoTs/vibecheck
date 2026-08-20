import type { Metadata } from "next";
import { Space_Grotesk, JetBrains_Mono } from "next/font/google";
import { Analytics } from "@vercel/analytics/next";
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
  "A free, open-source security report card for AI-built apps. See exactly what a stranger can read from your Supabase project and how your app is configured — runs in your browser, we see nothing.";

const TITLE = "vibecheck — is your app leaking?";

export async function generateMetadata(): Promise<Metadata> {
  return {
    metadataBase: await siteBaseUrl(),
    title: TITLE,
    description,
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

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${display.variable} ${mono.variable} h-full antialiased`}>
      <body className="min-h-full">
        {children}
        <Analytics />
      </body>
    </html>
  );
}
