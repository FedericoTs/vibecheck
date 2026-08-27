import { NextResponse } from 'next/server';
import { randomBytes } from 'node:crypto';
import { rateLimitResponse } from '@/lib/rate-limit';
import { buildSaved, newSlug, saveReport, savingEnabled } from '@/lib/report-store';
import type { Report } from '@/lib/scan/report';

export const runtime = 'nodejs';

/**
 * Read-only health check, so "saving is off" can be diagnosed without guessing.
 *
 * Reports whether a token was found and the NAME of the variable it came from —
 * never the value, and never anything else from the environment.
 */
export function GET(): Response {
  const name = Object.keys(process.env).find((k) => k.endsWith('_READ_WRITE_TOKEN'));
  return NextResponse.json({ saving: savingEnabled(), tokenVar: name ?? null });
}

/** A saved report is a document, not a payload — cap it so nobody stores a novel. */
const MAX_BODY = 512_000;

/**
 * Save a report and hand back its private link.
 *
 * Two gates, both deliberate:
 *
 *   - `authorized` must be sent explicitly. The client only sends it when
 *     someone has ticked the box saying they own or are allowed to test the
 *     site. It is not proof of anything, and it is not meant to be; it is the
 *     moment the person takes responsibility for publishing findings about a
 *     domain, which is the difference between a tool and an accomplice.
 *   - Nothing is stored unless a Blob token is configured, so a fork or a local
 *     run keeps the original "we store nothing" behaviour with no code change.
 */
export async function POST(request: Request): Promise<Response> {
  const limited = rateLimitResponse(request.headers);
  if (limited) return limited;

  if (!savingEnabled()) {
    return NextResponse.json({ error: 'Saving is not enabled on this deployment' }, { status: 503 });
  }

  const raw = await request.text();
  if (raw.length > MAX_BODY) {
    return NextResponse.json({ error: 'That report is too large to save' }, { status: 413 });
  }

  let body: { report?: Report; host?: string; skipped?: string[]; authorized?: boolean };
  try {
    body = JSON.parse(raw);
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }

  if (body.authorized !== true) {
    return NextResponse.json(
      { error: 'You must confirm you own or are authorized to test this site' },
      { status: 403 },
    );
  }

  const report = body.report;
  if (!report || typeof report !== 'object' || !Array.isArray(report.categories)) {
    return NextResponse.json({ error: 'No report to save' }, { status: 400 });
  }

  // Host is used as the title and the outbound link, so it must be a hostname
  // and nothing else — never a full URL, never a path, never a redirect.
  const host = String(body.host ?? '').toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
  if (!/^[a-z0-9.-]{3,253}$/.test(host) || !host.includes('.')) {
    return NextResponse.json({ error: 'Invalid host' }, { status: 400 });
  }

  const skipped = Array.isArray(body.skipped) ? body.skipped.slice(0, 40).map((s) => String(s).slice(0, 40)) : [];

  try {
    const slug = newSlug(() => new Uint8Array(randomBytes(32)));
    const saved = buildSaved({ slug, host, report, skipped, now: new Date() });
    await saveReport(saved);
    return NextResponse.json({ slug, expiresAt: saved.expiresAt });
  } catch (e) {
    // The message comes from the storage SDK, not from user input, and it is the
    // difference between "the token is wrong" and "the store is full". Truncated,
    // never a stack.
    const reason = e instanceof Error ? e.message.slice(0, 200) : '';
    console.error('[report:save]', reason);
    return NextResponse.json(
      { error: 'Could not save that report', reason: reason || undefined },
      { status: 502 },
    );
  }
}
