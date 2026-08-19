import { NextResponse } from 'next/server';
import { rateLimitResponse } from '@/lib/rate-limit';

export const runtime = 'nodejs';

/**
 * Opt-in monitoring waitlist.
 *
 * The ONLY thing vibecheck ever stores, and it stores exactly one field: an
 * email address the person typed on purpose. No scanned URL, no grade, no
 * findings — the scan stays anonymous, which is the whole promise. Keeping the
 * scan and the email strictly separate is what makes "we never see your app"
 * still true for everyone who does not opt in.
 *
 * Backed by a Resend segment: no database to run, unsubscribe handling comes
 * with it, and the list stays entirely separate from any other project.
 */

const SEGMENT_ID = process.env.RESEND_WAITLIST_SEGMENT_ID;
const API_KEY = process.env.RESEND_API_KEY;

/** Deliberately permissive: rejecting valid-but-unusual addresses is worse than accepting a typo. */
export function isPlausibleEmail(value: string): boolean {
  const v = value.trim();
  if (v.length < 6 || v.length > 254) return false;
  if (/\s/.test(v)) return false;
  const at = v.indexOf('@');
  if (at < 1 || at !== v.lastIndexOf('@')) return false;
  const domain = v.slice(at + 1);
  return domain.includes('.') && !domain.startsWith('.') && !domain.endsWith('.');
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
  const email = typeof (body as { email?: unknown })?.email === 'string' ? (body as { email: string }).email.trim() : '';

  if (!isPlausibleEmail(email)) {
    return NextResponse.json({ error: "That does not look like an email address." }, { status: 400 });
  }
  if (!API_KEY || !SEGMENT_ID) {
    // Not configured yet — say so honestly rather than pretending it worked.
    return NextResponse.json({ error: 'The waitlist is not switched on yet. Try again soon.' }, { status: 503 });
  }

  try {
    const res = await fetch('https://api.resend.com/contacts', {
      method: 'POST',
      headers: { Authorization: `Bearer ${API_KEY}`, 'content-type': 'application/json' },
      body: JSON.stringify({ email, segment_ids: [SEGMENT_ID], unsubscribed: false }),
      signal: AbortSignal.timeout(8000),
    });
    // A duplicate is a success from the person's point of view.
    if (res.ok || res.status === 409) return NextResponse.json({ ok: true });
    return NextResponse.json({ error: 'Could not add you just now — try again in a minute.' }, { status: 502 });
  } catch {
    return NextResponse.json({ error: 'Could not add you just now — try again in a minute.' }, { status: 502 });
  }
}
