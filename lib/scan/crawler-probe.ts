import { visibleText } from './visibility';

/**
 * Synthetic AI-crawler probe.
 *
 * The crawler matrix answers a question by INFERENCE: does robots.txt allow
 * GPTBot? This answers the same question by PROOF: fetch the page AS GPTBot and
 * see what actually comes back. The two disagree more often than you would
 * think — a site can `allow` every AI crawler in robots and still serve them an
 * empty JavaScript shell, a Cloudflare challenge, or a geo-block, so ChatGPT and
 * Claude get nothing while robots.txt looks perfect.
 *
 * Proof-shaped, in this codebase's sense: it executes a request and reports the
 * observed result, rather than reading a policy and concluding.
 *
 * REPORTED, NOT GRADED. A site serving less to a crawler has legitimate
 * explanations we cannot rule out from outside — bot protection, rate limiting,
 * a paywall, a deliberate block. So this measures and shows; it never moves the
 * grade. Same rule the rest of the crawler matrix already follows.
 *
 * NOTE ON THE USER AGENT. We send a real crawler's User-Agent string against a
 * URL the user gave us about their own app. That is what a crawler audit is; it
 * touches only the user's own public page, over a plain GET, and nothing else.
 */

export type Fetchy = (url: string, init?: { headers?: Record<string, string>; signal?: AbortSignal }) => Promise<Response>;

/** The crawlers worth actually impersonating — the ones a site most wants to reach it. */
export const PROBE_AGENTS: Array<{ name: string; purpose: string; ua: string }> = [
  {
    name: 'GPTBot',
    purpose: 'OpenAI · ChatGPT',
    ua: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot',
  },
  {
    name: 'ClaudeBot',
    purpose: 'Anthropic · Claude',
    ua: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ClaudeBot/1.0; +claudebot@anthropic.com',
  },
  {
    name: 'PerplexityBot',
    purpose: 'Perplexity',
    ua: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot',
  },
];

export type ProbeVerdict = 'full' | 'reduced' | 'blocked' | 'error';

export interface CrawlerProbe {
  name: string;
  purpose: string;
  /** HTTP status the crawler UA received, or null on a network failure. */
  status: number | null;
  /**
   * Of the words a normal browser sees, the share this crawler also received.
   * null when we could not compute it (no baseline, or the fetch failed).
   */
  parityPercent: number | null;
  verdict: ProbeVerdict;
  detail: string;
}

export interface CrawlerProbeResult {
  /** True only when a baseline existed and at least one probe completed. */
  checked: boolean;
  baselineWords: number;
  probes: CrawlerProbe[];
}

/** The set of content words on a page, lowercased, deduped. Cheap and order-free. */
function wordSet(html: string): Set<string> {
  const out = new Set<string>();
  for (const w of visibleText(html).toLowerCase().split(/\s+/)) {
    if (w.length >= 2) out.add(w);
  }
  return out;
}

/**
 * Of the baseline's words, what fraction the crawler also received.
 *
 * Directional, not symmetric: we ask "did the crawler get YOUR content", not
 * "are the two identical". A crawler page with extra boilerplate still scores
 * 100 if it contains everything the browser showed.
 */
export function contentParity(baseline: Set<string>, crawler: Set<string>): number {
  if (baseline.size === 0) return crawler.size === 0 ? 100 : 0;
  let hit = 0;
  for (const w of baseline) if (crawler.has(w)) hit += 1;
  return Math.round((hit / baseline.size) * 100);
}

export function classifyProbe(status: number | null, parity: number | null): { verdict: ProbeVerdict; detail: string } {
  if (status === null) return { verdict: 'error', detail: 'the request did not complete — timed out or was refused' };
  if (status === 403 || status === 401 || status === 429 || status === 503) {
    return { verdict: 'blocked', detail: `the crawler got HTTP ${status} — blocked before it could read anything` };
  }
  if (status >= 400) return { verdict: 'error', detail: `the crawler got HTTP ${status}` };
  if (parity === null) return { verdict: 'error', detail: 'could not compare the content' };
  if (parity >= 80) return { verdict: 'full', detail: `received ${parity}% of your content` };
  if (parity >= 30) return { verdict: 'reduced', detail: `received only ${parity}% of your content` };
  return { verdict: 'blocked', detail: `received almost none of your content (${parity}%)` };
}

/**
 * Fetch the page as each crawler and measure content parity against a baseline
 * fetched with a normal browser UA.
 *
 * `baselineHtml` is the HTML the ordinary scan already fetched, so this adds one
 * request per crawler, not two — keeping the outbound fan-out small, which the
 * launch-readiness audit cared about.
 */
export async function probeCrawlers(
  url: string,
  baselineHtml: string,
  fetchy: Fetchy,
  opts: { timeoutMs?: number } = {},
): Promise<CrawlerProbeResult> {
  const baseline = wordSet(baselineHtml);
  const timeoutMs = opts.timeoutMs ?? 6000;

  const probes = await Promise.all(
    PROBE_AGENTS.map(async ({ name, purpose, ua }): Promise<CrawlerProbe> => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetchy(url, { headers: { 'user-agent': ua, accept: 'text/html,*/*;q=0.8' }, signal: controller.signal });
        const status = res.status;
        let parity: number | null = null;
        if (res.ok) {
          const body = (await res.text()).slice(0, 2_000_000);
          parity = contentParity(baseline, wordSet(body));
        }
        const { verdict, detail } = classifyProbe(status, parity);
        return { name, purpose, status, parityPercent: parity, verdict, detail };
      } catch {
        const { verdict, detail } = classifyProbe(null, null);
        return { name, purpose, status: null, parityPercent: null, verdict, detail };
      } finally {
        clearTimeout(timer);
      }
    }),
  );

  return { checked: baseline.size > 0, baselineWords: baseline.size, probes };
}
