import { NextResponse } from 'next/server';
import { rateLimitResponse } from '@/lib/rate-limit';
import { assertPublicUrl } from '@/lib/scan/ssrf';
import { safeFetch, UA } from '@/lib/scan/fetch';
import { analyzeVisibility, isJsOnlyShell } from '@/lib/scan/visibility';
import { findSmuggledText } from '@/lib/scan/smuggling';
import { probeCrawlers } from '@/lib/scan/crawler-probe';

export const runtime = 'nodejs';
// The synthetic crawler probe adds a few outbound fetches to a possibly-slow
// origin. Match the ceiling the other multi-fetch routes declare.
export const maxDuration = 60;

const MAX_BYTES = 2_000_000;
const TIMEOUT_MS = 6000;

/**
 * Fetch a well-known file; returns '' when it isn't really there.
 *
 * Redirects are FOLLOWED (via safeFetch, which revalidates every hop): a
 * sitemap served behind a 301 is still a sitemap, and treating it as missing
 * was a false negative found live on vercel.com. A permissive Accept header
 * avoids servers refusing the request outright.
 */
async function fetchIfPresent(url: string): Promise<string> {
  try {
    const target = await assertPublicUrl(url);
    const { response } = await safeFetch(target, {
      headers: { 'user-agent': UA, accept: 'text/plain, application/xml, text/xml, */*' },
      timeoutMs: TIMEOUT_MS,
    });
    if (!response.ok) return '';
    const type = response.headers.get('content-type') ?? '';
    const body = (await response.text()).slice(0, 200_000);
    // An SPA catch-all serving HTML for /robots.txt does not mean it exists.
    if (/text\/html/i.test(type) || /^\s*<(!doctype|html)/i.test(body)) return '';
    return body;
  } catch {
    return '';
  }
}

export async function POST(request: Request): Promise<Response> {
  const limited = rateLimitResponse(request.headers);
  if (limited) return limited;

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }
  const rawUrl = typeof (body as { url?: unknown })?.url === 'string' ? (body as { url: string }).url : '';

  let target: URL;
  try {
    target = await assertPublicUrl(rawUrl);
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 400 });
  }

  let html = '';
  let finalUrl = target;
  try {
    const { response, url } = await safeFetch(target);
    finalUrl = url;
    html = (await response.text()).slice(0, MAX_BYTES);
  } catch {
    return NextResponse.json({ error: 'Could not reach that URL' }, { status: 502 });
  }

  const [robotsTxt, sitemap, llms] = await Promise.all([
    fetchIfPresent(new URL('/robots.txt', finalUrl).toString()),
    fetchIfPresent(new URL('/sitemap.xml', finalUrl).toString()),
    fetchIfPresent(new URL('/llms.txt', finalUrl).toString()),
  ]);

  const result = analyzeVisibility(
    { html, robotsTxt, hasRobots: robotsTxt.length > 0, hasSitemap: sitemap.length > 0, hasLlmsTxt: llms.length > 0 },
    finalUrl.host,
  );

  // Fetch the page AS the AI crawlers and measure what they actually receive.
  // Every request revalidates the URL through assertPublicUrl + safeFetch, so a
  // crawler probe can never become an SSRF or redirect-to-private hop.
  const crawlerProbe = await probeCrawlers(
    finalUrl.toString(),
    html,
    async (u, init) => {
      // safeFetch enforces its own timeout, so the probe's AbortSignal is a
      // belt-and-braces backstop rather than the primary bound.
      const safe = await assertPublicUrl(u);
      const { response } = await safeFetch(safe, { headers: init?.headers, timeoutMs: TIMEOUT_MS });
      return response;
    },
    { timeoutMs: TIMEOUT_MS },
  ).catch(() => null);

  return NextResponse.json({
    ...result,
    crawlerProbe,
    // The hidden-instruction scan rides along here because this route already
    // holds the served HTML AND the JS-only-shell verdict. That verdict is
    // passed through as limitedCoverage so the report can refuse to show a
    // clean pass for a page whose content we never actually saw.
    smuggling: findSmuggledText(html, isJsOnlyShell(html)),
  });
}
