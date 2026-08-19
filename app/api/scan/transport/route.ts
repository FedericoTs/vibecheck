import { NextResponse } from 'next/server';
import tls from 'node:tls';
import { rateLimitResponse } from '@/lib/rate-limit';
import { assertPublicUrl } from '@/lib/scan/ssrf';
import { UA } from '@/lib/scan/fetch';
import { analyzeTransport, isOpenRedirect, type CertFacts } from '@/lib/scan/transport';

export const runtime = 'nodejs';

const TIMEOUT_MS = 7000;
/** IANA-reserved and inert — a harmless canary to redirect at. */
const CANARY_HOST = 'example.com';
const CANARY = `https://${CANARY_HOST}/vibecheck-open-redirect-probe`;
const REDIRECT_PARAMS = ['redirect', 'next', 'url', 'returnUrl', 'return_to', 'continue'];

/** Node types these cert fields as string | string[]; flatten to plain strings. */
function asStrings(v: string | string[] | undefined): string[] {
  if (!v) return [];
  return Array.isArray(v) ? v.filter(Boolean) : [v];
}

/** Read the peer certificate without trusting it — we want to SEE a bad cert. */
function inspectCert(host: string): Promise<CertFacts> {
  return new Promise((resolve) => {
    const done = (f: CertFacts) => {
      resolve(f);
      try {
        socket.destroy();
      } catch {
        /* already closed */
      }
    };
    const socket = tls.connect(
      { host, port: 443, servername: host, rejectUnauthorized: false, timeout: TIMEOUT_MS },
      () => {
        const c = socket.getPeerCertificate();
        if (!c || Object.keys(c).length === 0) return done({ checked: false });
        const names = [
          ...asStrings(c.subject?.CN),
          ...String(c.subjectaltname ?? '')
            .split(',')
            .map((s) => s.trim().replace(/^DNS:/i, ''))
            .filter(Boolean),
        ];
        done({
          checked: true,
          validTo: c.valid_to,
          issuer: asStrings(c.issuer?.O)[0] ?? asStrings(c.issuer?.CN)[0],
          names: [...new Set(names)],
        });
      },
    );
    socket.on('error', () => done({ checked: false }));
    socket.on('timeout', () => done({ checked: false }));
  });
}

async function probeRedirect(origin: string, param: string): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const url = `${origin}/?${param}=${encodeURIComponent(CANARY)}`;
    const res = await fetch(url, {
      method: 'GET',
      redirect: 'manual', // observe the Location header; never follow it
      signal: controller.signal,
      headers: { 'user-agent': UA },
    });
    return isOpenRedirect(res.status, res.headers.get('location'), CANARY_HOST);
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

async function httpsEnforced(host: string): Promise<boolean | undefined> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`http://${host}/`, {
      method: 'HEAD',
      redirect: 'manual',
      signal: controller.signal,
      headers: { 'user-agent': UA },
    });
    if (res.status >= 300 && res.status < 400) {
      return (res.headers.get('location') ?? '').toLowerCase().startsWith('https://');
    }
    return res.status < 400 ? false : undefined; // served over plain http, or unclear
  } catch {
    return undefined; // http not reachable at all — nothing to report
  } finally {
    clearTimeout(timer);
  }
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

  const [cert, enforced, redirects] = await Promise.all([
    inspectCert(target.hostname),
    httpsEnforced(target.hostname),
    Promise.all(REDIRECT_PARAMS.map(async (p) => ((await probeRedirect(target.origin, p)) ? p : null))),
  ]);

  return NextResponse.json(
    analyzeTransport(
      {
        cert,
        httpsEnforced: enforced,
        openRedirectParams: redirects.filter((p): p is string => !!p),
        redirectChecked: true,
      },
      target.hostname,
    ),
  );
}
