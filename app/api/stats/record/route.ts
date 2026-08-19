import { NextResponse } from 'next/server';
import { recordScan, clampSecrets } from '@/lib/stats';

export const runtime = 'nodejs';

// Opt-in: the client only calls this when the user clicks "add to the tally".
// The payload is anonymous — a leaking flag + a secret count, never a URL or key.
export async function POST(request: Request): Promise<Response> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ ok: false }, { status: 400 });
  }
  const b = body as { leaking?: unknown; secrets?: unknown };
  const ok = await recordScan({ leaking: !!b.leaking, secrets: clampSecrets(b.secrets) });
  return NextResponse.json({ ok });
}
