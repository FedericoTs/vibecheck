import { NextResponse } from 'next/server';
import { rateLimitResponse } from '@/lib/rate-limit';
import { assertPublicUrl } from '@/lib/scan/ssrf';
import { safeFetch, UA } from '@/lib/scan/fetch';
import { ROUTE_PROBES, classifyRoute, gradeRoutes, type RouteProbe, type RouteFinding } from '@/lib/scan/routes';
import { extractRoutes } from '@/lib/scan/bundle-routes';
import { scriptUrls, fetchScript } from '@/lib/scan/bundle';

export const runtime = 'nodejs';

const TIMEOUT_MS = 7000;
const MAX_BYTES = 200_000;
const CONCURRENCY = 5;

/** GET one path, read-only. Never posts, never attempts a login. */
async function probeOne(origin: string, probe: RouteProbe, baseline: string): Promise<RouteFinding> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(origin + probe.path, {
      method: 'GET',
      redirect: 'manual', // a redirect is itself the signal (usually to a login)
      signal: controller.signal,
      headers: { 'user-agent': UA, accept: 'text/html,application/json;q=0.9,*/*;q=0.8' },
    });
    const body = (await res.text()).slice(0, MAX_BYTES);
    return classifyRoute(
      probe,
      {
        status: res.status,
        contentType: res.headers.get('content-type') ?? '',
        body,
        redirected: res.status >= 300 && res.status < 400,
      },
      baseline,
    );
  } catch {
    // Never 'absent' — we did not learn that it is not there, we learned nothing.
    return { path: probe.path, label: probe.label, kind: probe.kind, verdict: 'unreachable' };
  } finally {
    clearTimeout(timer);
  }
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (i < items.length) {
        const idx = i++;
        out[idx] = await fn(items[idx]);
      }
    }),
  );
  return out;
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

  // Baseline: the site's own homepage. Single-page apps serve this same shell
  // for every path, so without it we would accuse every SPA of exposing /admin.
  // Passed explicitly (never module state) so concurrent scans can't cross-talk.
  let origin = target.origin;
  let baseline = '';
  try {
    const { response, url } = await safeFetch(target);
    origin = url.origin;
    baseline = (await response.text()).slice(0, MAX_BYTES);
  } catch {
    return NextResponse.json({ error: 'Could not reach that URL' }, { status: 502 });
  }

  // The app's own bundle names its real routes. Probing those is the same
  // legality as probing /admin — a public GET — with a far higher hit rate and
  // a finding that is self-evidently about them rather than about our guess list.
  let discovered: RouteProbe[] = [];
  let refused: RouteProbe[] = [];
  try {
    const scripts = scriptUrls(baseline, target, 6);
    const code = (await Promise.all(scripts.map(fetchScript))).join('\n');
    const extracted = extractRoutes(code, scripts, 12);
    // Never probe a path the fixed list already covers.
    const known = new Set(ROUTE_PROBES.map((p) => p.path));
    discovered = extracted.probes.filter((p) => !known.has(p.path));
    refused = extracted.refused;
  } catch {
    /* bundle unreadable — fall back to the fixed list, which still runs */
  }

  const findings = await mapLimit([...ROUTE_PROBES, ...discovered], CONCURRENCY, (p) =>
    probeOne(origin, p, baseline),
  );
  return NextResponse.json({
    ...gradeRoutes(findings, target.host),
    routesFromBundle: discovered.length,
    // Reported, never requested. See lib/scan/bundle-routes.ts.
    refused: refused.map((r) => r.path),
  });
}
