import { describe, expect, it } from 'vitest';
import { classifyProbe, contentParity, probeCrawlers, PROBE_AGENTS } from './crawler-probe';

const words = (html: string) => {
  const out = new Set<string>();
  for (const w of html.replace(/<[^>]+>/g, ' ').toLowerCase().split(/\s+/)) if (w.length >= 2) out.add(w);
  return out;
};

describe('contentParity', () => {
  it('is 100 when the crawler got everything the browser saw', () => {
    const base = words('the quick brown fox jumps');
    expect(contentParity(base, words('the quick brown fox jumps over the lazy dog'))).toBe(100);
  });

  it('measures the share of BASELINE words present, not identity', () => {
    const base = words('alpha beta gamma delta');
    expect(contentParity(base, words('alpha beta'))).toBe(50);
  });

  it('is 0 when the crawler got a shell with none of the content', () => {
    expect(contentParity(words('real page content here'), words('<div id=root></div>'))).toBe(0);
  });

  it('does not divide by zero on an empty baseline', () => {
    expect(contentParity(new Set(), new Set())).toBe(100);
    expect(contentParity(new Set(), words('anything'))).toBe(0);
  });
});

describe('classifyProbe', () => {
  it('reads a bot wall (403/429/503) as blocked, not as an error', () => {
    for (const s of [401, 403, 429, 503]) expect(classifyProbe(s, null).verdict).toBe('blocked');
  });

  it('bands parity into full / reduced / blocked', () => {
    expect(classifyProbe(200, 95).verdict).toBe('full');
    expect(classifyProbe(200, 55).verdict).toBe('reduced');
    expect(classifyProbe(200, 5).verdict).toBe('blocked');
  });

  it('a network failure is an error, distinct from a block', () => {
    expect(classifyProbe(null, null).verdict).toBe('error');
  });
});

describe('probeCrawlers', () => {
  const html = '<html><body><h1>Real Content</h1><p>lots of actual words on this landing page</p></body></html>';

  it('sends each crawler its real User-Agent and compares to the baseline', async () => {
    const seen: string[] = [];
    const fetchy = (async (_u: string, init?: { headers?: Record<string, string> }) => {
      seen.push(init?.headers?.['user-agent'] ?? '');
      return { status: 200, ok: true, text: async () => html } as unknown as Response;
    }) as never;

    const r = await probeCrawlers('https://x.com', html, fetchy);
    expect(r.checked).toBe(true);
    expect(r.probes).toHaveLength(PROBE_AGENTS.length);
    // Every configured agent's UA actually went out.
    for (const a of PROBE_AGENTS) expect(seen.some((ua) => ua.includes(a.name))).toBe(true);
    // Same content back => full parity.
    expect(r.probes.every((p) => p.verdict === 'full')).toBe(true);
  });

  it('flags the allowed-but-empty-shell case a robots check would miss', async () => {
    const shell = '<html><body><div id="root"></div></body></html>';
    const fetchy = (async () => ({ status: 200, ok: true, text: async () => shell }) as unknown as Response) as never;
    const r = await probeCrawlers('https://x.com', html, fetchy);
    expect(r.probes.every((p) => p.parityPercent === 0 && p.verdict === 'blocked')).toBe(true);
  });

  it('records a bot wall without throwing', async () => {
    const fetchy = (async () => ({ status: 403, ok: false, text: async () => '' }) as unknown as Response) as never;
    const r = await probeCrawlers('https://x.com', html, fetchy);
    expect(r.probes.every((p) => p.verdict === 'blocked' && p.status === 403)).toBe(true);
  });

  it('survives a network failure per crawler', async () => {
    const fetchy = (async () => {
      throw new Error('ECONNREFUSED');
    }) as never;
    const r = await probeCrawlers('https://x.com', html, fetchy);
    expect(r.probes.every((p) => p.verdict === 'error' && p.status === null)).toBe(true);
  });
});
