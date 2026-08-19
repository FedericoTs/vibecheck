import { NextResponse } from 'next/server';
import { assertPublicUrl } from '@/lib/scan/ssrf';
import { safeFetch } from '@/lib/scan/fetch';
import { gradeHeaders } from '@/lib/scan/headers';

export const runtime = 'nodejs';

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

  let response: Response;
  try {
    ({ response } = await safeFetch(target));
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

  return NextResponse.json(gradeHeaders(headers, target.host));
}
