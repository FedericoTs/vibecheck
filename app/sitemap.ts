import type { MetadataRoute } from 'next';
import { siteBaseUrl } from '@/lib/site-url';

// Dynamic so entry URLs resolve to the real request host (the custom domain),
// not Vercel's protected per-deploy URL, even with no env configured.
export const dynamic = 'force-dynamic';

// Bumped when the indexable content changes; kept stable per build so crawlers
// don't see a churning lastmod on every fetch. (Date.now()/new Date() with no
// arg would make it move every request.)
const LAST_MODIFIED = new Date('2026-08-20');

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const base = await siteBaseUrl();
  return [
    {
      url: new URL('/', base).toString(),
      lastModified: LAST_MODIFIED,
      changeFrequency: 'weekly',
      priority: 1,
    },
    {
      url: new URL('/legal', base).toString(),
      lastModified: LAST_MODIFIED,
      changeFrequency: 'yearly',
      priority: 0.3,
    },
  ];
  // Intentionally excluded: /demo/leaky (noindex fixture), /r (thin per-query
  // share pages, noindex), /badge + /api/* (functional routes).
}
