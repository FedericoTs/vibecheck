import type { Metadata } from "next";
import { Space_Grotesk, JetBrains_Mono } from "next/font/google";
import { headers } from "next/headers";
import { Analytics } from "@vercel/analytics/next";
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

// Resolve the canonical base URL for absolute OG links, tolerating an unset OR
// empty env var (an empty NEXT_PUBLIC_SITE_URL must fall through, which `??`
// does not do), and never throwing at build time on a malformed value.
function resolveBaseUrl(): URL {
  const explicit = process.env.NEXT_PUBLIC_SITE_URL?.trim();
  const vercel = process.env.VERCEL_URL?.trim();
  const candidate = explicit || (vercel ? `https://${vercel}` : "http://localhost:3000");
  try {
    return new URL(candidate);
  } catch {
    return new URL("http://localhost:3000");
  }
}

// Prefer the PUBLIC host the request actually came in on (the production alias
// or a custom domain), so OG images never point at Vercel's protected per-deploy
// URL. Falls back to the env/VERCEL_URL resolver.
async function baseUrl(): Promise<URL> {
  try {
    const h = await headers();
    const host = h.get("x-forwarded-host") ?? h.get("host");
    if (host) return new URL(`${h.get("x-forwarded-proto") ?? "https"}://${host}`);
  } catch {
    /* headers() unavailable (e.g. static) — fall through */
  }
  return resolveBaseUrl();
}

const description =
  "A free, open-source security report card for AI-built apps. See exactly what a stranger can read from your Supabase project and how your app is configured — runs in your browser, we see nothing.";

const TITLE = "vibecheck — is your app leaking?";

export async function generateMetadata(): Promise<Metadata> {
  return {
    metadataBase: await baseUrl(),
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
