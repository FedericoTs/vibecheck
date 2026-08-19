import { NextResponse } from 'next/server';
import { assertPublicUrl } from '@/lib/scan/ssrf';
import { parsePsi } from '@/lib/scan/lighthouse';

export const runtime = 'nodejs';
export const maxDuration = 60; // PageSpeed Insights can take 20-40s

const PSI = 'https://www.googleapis.com/pagespeedonline/v5/runPagespeed';
const CATEGORIES = ['PERFORMANCE', 'ACCESSIBILITY', 'BEST_PRACTICES', 'SEO'];
// Cache each URL's Lighthouse result at Vercel's edge for an hour so repeat
// scans of the same URL reuse ONE Google call — protecting the PSI quota. GET
// (not POST) so the CDN can key the cache on the URL.
const CACHE = 'public, s-maxage=3600, stale-while-revalidate=86400';

export async function GET(request: Request): Promise<Response> {
  const rawUrl = new URL(request.url).searchParams.get('url') ?? '';

  let target: URL;
  try {
    target = await assertPublicUrl(rawUrl);
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 400 });
  }

  // Google fetches the target from its side, so there's no SSRF from PSI itself.
  const params = new URLSearchParams({ url: target.toString(), strategy: 'mobile' });
  for (const c of CATEGORIES) params.append('category', c);
  const key = process.env.PAGESPEED_API_KEY;
  if (key) params.set('key', key);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 45000);
  try {
    const res = await fetch(`${PSI}?${params.toString()}`, { signal: controller.signal });
    const json = (await res.json()) as { error?: { message?: string } };
    if (!res.ok || json?.error) {
      // Don't cache failures (e.g. a transient quota error) — no Cache-Control.
      return NextResponse.json({ error: json?.error?.message ?? 'Lighthouse is unavailable right now' }, { status: 502 });
    }
    return NextResponse.json(parsePsi(json, target.host), { headers: { 'Cache-Control': CACHE } });
  } catch {
    return NextResponse.json({ error: 'Lighthouse timed out' }, { status: 504 });
  } finally {
    clearTimeout(timer);
  }
}
