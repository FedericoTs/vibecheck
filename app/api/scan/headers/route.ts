import { NextResponse } from 'next/server';
import { rateLimitResponse } from '@/lib/rate-limit';
import { assertPublicUrl } from '@/lib/scan/ssrf';
import { safeFetch } from '@/lib/scan/fetch';
import { gradeHeaders } from '@/lib/scan/headers';

export const runtime = 'nodejs';

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

  let response: Response;
  let finalUrl: URL;
  try {
    ({ response, url: finalUrl } = await safeFetch(target));
  } catch (e) {
    const msg = (e as Error).message;
    return NextResponse.json(
      { error: /private|resolve|redirect/i.test(msg) ? msg : 'Could not reach that URL' },
      { status: 502 },
    );
  }

  const headers: Record<string, string> = {};
  response.headers.forEach((v, k) => {
    headers[k] = v;
  });

  // The FINAL host, not the requested one. safeFetch follows redirects, so on a
  // site whose apex redirects (google.com -> www.google.com) the headers we
  // graded came from somewhere else entirely — and printing the requested URL as
  // the reproduction meant the command returned the redirect's headers, not the
  // ones the finding was about. A proof that does not reproduce is worse than no
  // proof, because it invites the reader to conclude the tool is wrong.
  const measured = gradeHeaders(headers, finalUrl.host);
  return NextResponse.json({
    ...measured,
    requestedHost: target.host,
    redirected: finalUrl.host !== target.host ? finalUrl.origin : undefined,
  });
}
