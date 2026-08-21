import { NextResponse } from 'next/server';
import { rateLimitResponse } from '@/lib/rate-limit';
import { assertPublicUrl } from '@/lib/scan/ssrf';
import { SENSITIVE_PATHS, classifyPath, unreachablePath, gradePaths, type PathProbe, type PathFinding } from '@/lib/scan/paths';

export const runtime = 'nodejs';

const TIMEOUT_MS = 6000;

async function probeOne(base: string, probe: PathProbe): Promise<PathFinding> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(base + probe.path, {
      method: 'GET',
      redirect: 'manual', // a redirect means the file isn't directly served
      signal: controller.signal,
      headers: { 'user-agent': 'vibecheck/0.1 (+https://github.com/FedericoTs/vibecheck)' },
    });
    const ct = res.headers.get('content-type') ?? '';
    const body = (await res.text()).slice(0, 8192);
    return classifyPath(probe, res.status, ct, body);
  } catch {
    // Unreachable or aborted. NOT the same as "not exposed" - we never found out.
    return unreachablePath(probe);
  } finally {
    clearTimeout(t);
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

  const findings = await Promise.all(SENSITIVE_PATHS.map((p) => probeOne(target.origin, p)));
  return NextResponse.json(gradePaths(findings, target.host));
}
