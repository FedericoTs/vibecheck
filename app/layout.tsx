import type { Metadata } from "next";
import { Space_Grotesk, JetBrains_Mono } from "next/font/google";
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

const description =
  "A free, open-source security report card for AI-built apps. See exactly what a stranger can read from your Supabase project and how your app is configured — runs in your browser, we see nothing.";

export const metadata: Metadata = {
  metadataBase: resolveBaseUrl(),
  title: "vibecheck — is your app leaking?",
  description,
  openGraph: {
    title: "vibecheck — is your app leaking?",
    description,
    images: [{ url: "/api/og", width: 1200, height: 630 }],
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "vibecheck — is your app leaking?",
    description,
    images: ["/api/og"],
  },
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${display.variable} ${mono.variable} h-full antialiased`}>
      <body className="min-h-full">{children}</body>
    </html>
  );
}
