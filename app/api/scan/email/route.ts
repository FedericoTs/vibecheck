import { NextResponse } from 'next/server';
import { Resolver } from 'node:dns/promises';
import { rateLimitResponse } from '@/lib/rate-limit';
import { assertPublicUrl } from '@/lib/scan/ssrf';
import { analyzeEmailAuth, type DnsFacts } from '@/lib/scan/email-auth';

export const runtime = 'nodejs';

const DNS_TIMEOUT_MS = 5000;

/** Strip a leading www. so we check the domain people actually send mail from. */
export function apexDomain(host: string): string {
  return host.replace(/^www\./i, '');
}

async function withTimeout<T>(p: Promise<T>, fallback: T): Promise<T> {
  return Promise.race([
    p.catch(() => fallback),
    new Promise<T>((resolve) => setTimeout(() => resolve(fallback), DNS_TIMEOUT_MS)),
  ]);
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

  const domain = apexDomain(target.hostname);
  // Public resolvers: the host's own DNS may be split-horizon or cached oddly.
  const resolver = new Resolver({ timeout: DNS_TIMEOUT_MS, tries: 1 });
  resolver.setServers(['1.1.1.1', '8.8.8.8']);

  const [txtRaw, dmarcRaw, mx] = await Promise.all([
    withTimeout(resolver.resolveTxt(domain), [] as string[][]),
    withTimeout(resolver.resolveTxt(`_dmarc.${domain}`), [] as string[][]),
    withTimeout(resolver.resolveMx(domain), [] as Array<{ exchange: string }>),
  ]);

  // TXT records arrive as arrays of chunks that must be joined, not separate records.
  const facts: DnsFacts = {
    txt: txtRaw.map((chunks) => chunks.join('')),
    dmarcTxt: dmarcRaw.map((chunks) => chunks.join('')),
    hasMx: mx.length > 0,
  };

  return NextResponse.json(analyzeEmailAuth(facts, domain));
}
