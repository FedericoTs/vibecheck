import { NextResponse } from 'next/server';
import { rateLimitResponse } from '@/lib/rate-limit';
import { assertPublicUrl } from '@/lib/scan/ssrf';
import { safeFetch, UA } from '@/lib/scan/fetch';
import { scanDevServer, type Probe } from '@/lib/scan/devserver';

export const runtime = 'nodejs';

const MAX_BYTES = 2_000_000;
const PROBE_BYTES = 200_000;
const TIMEOUT_MS = 6000;

/**
 * Fetch one corroboration URL, keeping the STATUS intact.
 *
 * The check distinguishes a 400 (dev-only endpoint) from 200/403/404 (various
 * production hosts), so this must not collapse failures into a single value —
 * safeFetch returns non-2xx responses rather than throwing, which is exactly
 * what is needed. A genuine network failure throws, and the caller turns that
 * into "unknown" rather than a pass.
 */
const probe: Probe = async (url) => {
  const safe = await assertPublicUrl(url);
  const { response } = await safeFetch(safe, { headers: { 'user-agent': UA }, timeoutMs: TIMEOUT_MS });
  return {
    status: response.status,
    contentType: response.headers.get('content-type') ?? '',
    body: (await response.text()).slice(0, PROBE_BYTES),
  };
};

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

  try {
    const { response, url } = await safeFetch(target);
    const html = (await response.text()).slice(0, MAX_BYTES);
    const result = await scanDevServer(
      {
        html,
        status: response.status,
        contentType: response.headers.get('content-type') ?? '',
        url,
      },
      probe,
    );
    return NextResponse.json(result);
  } catch {
    return NextResponse.json({ error: 'Could not reach that URL' }, { status: 502 });
  }
}
