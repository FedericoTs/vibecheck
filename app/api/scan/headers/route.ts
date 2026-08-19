import { NextResponse } from 'next/server';
import { assertPublicUrl } from '@/lib/scan/ssrf';
import { gradeHeaders } from '@/lib/scan/headers';

// Node runtime: the SSRF guard resolves DNS to reject private addresses.
export const runtime = 'nodejs';

const TIMEOUT_MS = 8000;
const MAX_REDIRECTS = 4;

async function fetchOnce(url: string): Promise<Response> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    return await fetch(url, {
      method: 'GET',
      redirect: 'manual', // we follow hops ourselves so each is SSRF-validated
      signal: controller.signal,
      headers: { 'user-agent': 'vibecheck/0.1 (+https://github.com/FedericoTs/vibecheck)' },
    });
  } finally {
    clearTimeout(t);
  }
}

/** Follow redirects manually, re-validating every hop so a redirect can't smuggle us to a private host. */
async function safeFetch(start: URL): Promise<Response> {
  let url = start;
  for (let i = 0; i < MAX_REDIRECTS; i++) {
    const res = await fetchOnce(url.toString());
    const loc = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && loc) {
      const next = new URL(loc, url);
      await assertPublicUrl(next.toString()); // throws on a private/loopback hop
      url = next;
      continue;
    }
    return res;
  }
  throw new Error('Too many redirects');
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

  let res: Response;
  try {
    res = await safeFetch(target);
  } catch (e) {
    const msg = (e as Error).message;
    return NextResponse.json(
      { error: /private|resolve|redirect/i.test(msg) ? msg : 'Could not reach that URL' },
      { status: 502 },
    );
  }

  const headers: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    headers[k] = v;
  });

  return NextResponse.json(gradeHeaders(headers, target.host));
}
