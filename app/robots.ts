import type { MetadataRoute } from 'next';
import { siteBaseUrl } from '@/lib/site-url';

// Dynamic so the sitemap link + host reflect the real request host (the custom
// domain), not Vercel's protected per-deploy URL, even with no env configured.
export const dynamic = 'force-dynamic';

export default async function robots(): Promise<MetadataRoute.Robots> {
  const base = (await siteBaseUrl()).origin;
  return {
    rules: [
      {
        userAgent: '*',
        allow: '/',
        // Not indexable content: the scan API, the deliberately-vulnerable demo
        // fixture, and the dynamic SVG badge route. `/r` stays crawlable on
        // purpose so social unfurlers can read its OG card — it carries its own
        // noindex instead.
        disallow: ['/api/', '/demo/', '/badge'],
      },
    ],
    sitemap: `${base}/sitemap.xml`,
    host: base,
  };
}
