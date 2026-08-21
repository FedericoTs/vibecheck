import { NextResponse } from 'next/server';
import { rateLimitResponse } from '@/lib/rate-limit';
import { assertPublicUrl } from '@/lib/scan/ssrf';
import { UA } from '@/lib/scan/fetch';
import { AI_PROBES, classifyAiProbe, gradeAiSurface, type AiSurfaceProbe, type AiFinding } from '@/lib/scan/ai-surface';

export const runtime = 'nodejs';

const TIMEOUT_MS = 8000;
const MAX_BYTES = 100_000;
const CONCURRENCY = 4;

/**
 * The smallest request that reveals whether the endpoint is open.
 *
 * For an LLM proxy we send an EMPTY body — never a real prompt — so we can
 * never cause a completion to run and spend the owner's money. For MCP we send
 * the read-only `tools/list` JSON-RPC method and never invoke a tool.
 */
function probeBody(probe: AiSurfaceProbe): string {
  return probe.kind === 'mcp'
    ? JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
    : JSON.stringify({});
}

async function probeOne(origin: string, probe: AiSurfaceProbe): Promise<AiFinding> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(origin + probe.path, {
      method: 'POST',
      redirect: 'manual',
      signal: controller.signal,
      headers: {
        'user-agent': UA,
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream;q=0.9, */*;q=0.8',
      },
      body: probeBody(probe),
    });
    const body = (await res.text()).slice(0, MAX_BYTES);
    return classifyAiProbe(probe, {
      status: res.status,
      contentType: res.headers.get('content-type') ?? '',
      body,
    });
  } catch {
    // Never 'absent' — we did not learn that it is not there, we learned nothing.
    return { path: probe.path, label: probe.label, kind: probe.kind, verdict: 'unreachable' };
  } finally {
    clearTimeout(timer);
  }
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (i < items.length) {
        const idx = i++;
        out[idx] = await fn(items[idx]);
      }
    }),
  );
  return out;
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

  const findings = await mapLimit(AI_PROBES, CONCURRENCY, (p) => probeOne(target.origin, p));
  return NextResponse.json(gradeAiSurface(findings, target.host));
}
