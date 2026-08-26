import { NextResponse } from 'next/server';
import { rateLimitResponse } from '@/lib/rate-limit';
import { assertPublicUrl } from '@/lib/scan/ssrf';
import { safeFetch } from '@/lib/scan/fetch';
import { analyzeFundamentals } from '@/lib/scan/fundamentals';
import { analyzeAccessibility } from '@/lib/scan/accessibility';

export const runtime = 'nodejs';

const MAX_BYTES = 2_000_000;

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
    // Accessibility rides along on the SAME html — a second pillar for zero
    // extra requests, and it must never see different bytes than fundamentals.
    return NextResponse.json({
      ...analyzeFundamentals(html, url),
      accessibility: analyzeAccessibility(html, url.host),
    });
  } catch {
    return NextResponse.json({ error: 'Could not reach that URL' }, { status: 502 });
  }
}
