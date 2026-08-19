import { NextResponse } from 'next/server';
import { assertPublicUrl } from '@/lib/scan/ssrf';
import { safeFetch, UA } from '@/lib/scan/fetch';
import { findSecrets, gradeSecrets, isSourceMap, type SecretFinding } from '@/lib/scan/secrets';
import { discoverSupabase } from '@/lib/scan/discover';

export const runtime = 'nodejs';

const MAX_BYTES = 2_000_000;
const MAX_SCRIPTS = 20;
const BUNDLE_TIMEOUT_MS = 8000;

// Bundles most likely to carry the app's config/credentials get fetched first,
// so a page with dozens of chunks still gets its main bundle scanned.
const PRIORITY = /(main|index|app|entry|client|bundle|vendor|runtime|chunk|_app|layout|page)/i;

/** Same-origin <script src> URLs from the page HTML, most-likely-relevant first. */
export function sameOriginScripts(html: string, pageUrl: URL): string[] {
  const urls = new Set<string>();
  for (const m of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
    try {
      const u = new URL(m[1], pageUrl);
      if (u.origin === pageUrl.origin && (u.pathname.endsWith('.js') || u.pathname.endsWith('.mjs'))) {
        urls.add(u.toString());
      }
    } catch {
      /* skip unparseable src */
    }
  }
  const all = [...urls];
  const ranked = [...all.filter((u) => PRIORITY.test(u)), ...all.filter((u) => !PRIORITY.test(u))];
  return ranked.slice(0, MAX_SCRIPTS);
}

async function fetchText(url: string): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), BUNDLE_TIMEOUT_MS);
  try {
    const res = await fetch(url, { redirect: 'manual', signal: controller.signal, headers: { 'user-agent': UA } });
    if (!res.ok) return ''; // skip redirects / errors
    return (await res.text()).slice(0, MAX_BYTES);
  } catch {
    return '';
  } finally {
    clearTimeout(timer);
  }
}

export async function POST(request: Request): Promise<Response> {
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

  // Scan the HTML (inline scripts + window.__ENV blobs live here) and the bundles.
  const all: SecretFinding[] = [...findSecrets(html)];
  const scripts = sameOriginScripts(html, finalUrl);
  const bundles = await Promise.all(scripts.map(fetchText));
  for (const b of bundles) all.push(...findSecrets(b));

  // Locate the Supabase project the app already exposes publicly, so the browser
  // can run the database check without the user pasting anything. We only find
  // it here — the table probes still run client-side.
  const discovered = discoverSupabase([html, ...bundles].join('\n'));

  // Are the source maps published? A .js.map republishes the original source —
  // comments, unminified logic, sometimes keys that minification hid.
  const mapTargets = scripts.slice(0, 4).map((s) => `${s}.map`);
  const maps = await Promise.all(
    mapTargets.map(async (m) => {
      const body = await fetchText(m);
      return isSourceMap(body ? 200 : 0, body) ? m.split('/').pop() ?? m : null;
    }),
  );
  const exposedMaps = maps.filter((m): m is string => !!m);

  // Dedupe across HTML + every bundle.
  const seen = new Set<string>();
  const findings = all.filter((f) => {
    const k = f.id + ':' + f.redacted;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  return NextResponse.json({
    ...gradeSecrets(findings, finalUrl.host),
    sourceMaps: { exposed: exposedMaps, checked: mapTargets.length > 0 },
    discovered,
  });
}
