import type { Grade } from './types';
import { scoreToGrade } from './grade';
import type { CrawlerProbeResult } from './crawler-probe';
import { analyzeSchema, describeSchema } from './schema';

/**
 * AI visibility — can an LLM or a search crawler actually read this app?
 *
 * Increasingly the traffic that matters arrives via an assistant rather than a
 * search box, and AI-built apps are unusually bad at this: the generators
 * produce client-rendered SPAs, so the HTML a crawler receives is an empty
 * <div id="root"> while the real content only appears after JavaScript runs.
 * Most crawlers never run it, so the page is invisible.
 *
 * Two honesty rules shape this file:
 *
 *  - Blocking AI crawlers is a legitimate choice, not a mistake. Publishers do
 *    it deliberately. So the crawler policy is REPORTED, never graded.
 *  - llms.txt is an emerging convention, not a requirement, so its absence is
 *    advisory rather than a failure. Inventing failures to inflate a check count
 *    is exactly what makes the 150-check scanners noisy.
 */

export interface VisibilityCheck {
  key: string;
  label: string;
  pass: boolean;
  severity: 'high' | 'medium' | 'low';
  detail?: string;
}

export interface VisibilityResult {
  host: string;
  checks: VisibilityCheck[];
  failed: VisibilityCheck[];
  crawlers: CrawlerAccess[];
  /**
   * What AI crawlers ACTUALLY received when we fetched the page as them —
   * added by the API route after the fact (this pure function has no network),
   * so it is optional here. Proof to sit beside the robots-policy inference.
   */
  crawlerProbe?: CrawlerProbeResult;
  /** The opening words a non-JS reader receives, quoted verbatim as evidence. */
  excerpt: { excerpt: string; words: number };
  grade: Grade;
  score: number;
  summary: string;
}

/** The AI crawlers worth naming when we report a site's policy. */
const AI_AGENTS = ['GPTBot', 'ClaudeBot', 'anthropic-ai', 'PerplexityBot', 'Google-Extended', 'CCBot', 'Bytespider'];

/** Visible text once markup, scripts and styles are stripped. */
export function visibleText(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&[a-z]+;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function visibleTextLength(html: string): number {
  return visibleText(html).length;
}

/**
 * The opening words a reader that does not execute JavaScript actually
 * receives, quoted verbatim.
 *
 * This is evidence, not a metric. "Your page is a JS-only shell" is an
 * abstraction people argue with; showing them the fourteen words a crawler got
 * is not arguable. Fully deterministic — the served bytes with markup removed,
 * no rendering, no inference, no model in the loop.
 *
 * It reports what WE fetched. It is a statement about this response, not a
 * claim about what any particular crawler chooses to do with it.
 */
export function crawlerExcerpt(html: string, maxWords = 40): { excerpt: string; words: number } {
  const words = visibleText(html).split(/\s+/).filter(Boolean);
  const head = words.slice(0, maxWords).join(' ');
  return { excerpt: words.length > maxWords ? `${head}…` : head, words: words.length };
}

// ── content quality: readability, headings, alt text ─────────────────

/** Rough syllable count — enough for a Flesch estimate, not linguistics. */
export function countSyllables(word: string): number {
  const w = word.toLowerCase().replace(/[^a-z]/g, '');
  if (w.length === 0) return 0;
  if (w.length <= 3) return 1;
  const trimmed = w.replace(/(?:[^laeiouy]es|[^laeiouy]ed|[^laeiouy]e)$/, '').replace(/^y/, '');
  const groups = trimmed.match(/[aeiouy]{1,2}/g);
  return groups ? groups.length : 1;
}

/**
 * Flesch Reading Ease (0-100; higher = easier). Below ~30 is college-graduate
 * dense, which both readers and the models summarising your page struggle with.
 * Returns null when there is too little prose to score meaningfully.
 */
export function fleschReadingEase(text: string): number | null {
  const words = text.split(/\s+/).filter((w) => /[a-z]/i.test(w));
  const sentences = (text.match(/[.!?]+(\s|$)/g) || []).length || 1;
  if (words.length < 60) return null; // not enough content to score
  const syllables = words.reduce((n, w) => n + countSyllables(w), 0);
  const score = 206.835 - 1.015 * (words.length / sentences) - 84.6 * (syllables / words.length);
  return Math.max(0, Math.min(100, Math.round(score)));
}

/** One H1, no skipped levels, some headings at all. */
export function headingStructure(html: string): { h1Count: number; hasHeadings: boolean; skips: boolean } {
  const levels = [...html.matchAll(/<h([1-6])[\s>]/gi)].map((m) => parseInt(m[1], 10));
  const present = new Set(levels);
  const max = levels.length ? Math.max(...levels) : 0;
  let skips = false;
  for (let lvl = 2; lvl <= max; lvl++) {
    if (present.has(lvl) && !present.has(lvl - 1)) {
      skips = true;
      break;
    }
  }
  return { h1Count: levels.filter((l) => l === 1).length, hasHeadings: levels.length > 0, skips };
}

/** How many CONTENT images carry alt text (decorative/hidden ones are excluded). */
export function altTextCoverage(html: string): { total: number; withAlt: number } {
  const imgs = [...html.matchAll(/<img\b[^>]*>/gi)]
    .map((m) => m[0])
    .filter((t) => !/role=["']presentation["']|aria-hidden=["']true["']/i.test(t));
  const withAlt = imgs.filter((t) => /\balt\s*=\s*["'][^"']+["']/i.test(t)).length;
  return { total: imgs.length, withAlt };
}

/**
 * Does the served HTML carry the content, or is it an empty shell that only
 * fills in once JavaScript runs? The latter is invisible to most crawlers.
 */
export function isJsOnlyShell(html: string): boolean {
  const text = visibleTextLength(html);
  const hasScripts = /<script[^>]+src=/i.test(html);
  return hasScripts && text < 300;
}

export function hasStructuredData(html: string): boolean {
  return /<script[^>]+type=["']application\/ld\+json["']/i.test(html);
}

export function hasCanonical(html: string): boolean {
  return /<link[^>]+rel=["']canonical["']/i.test(html);
}

/** Which AI crawlers a robots.txt explicitly disallows. Reported, not graded. */
export function blockedAiAgents(robotsTxt: string): string[] {
  if (!robotsTxt) return [];
  const out: string[] = [];
  // Split into per-user-agent blocks and look for a blanket disallow.
  const blocks = robotsTxt.split(/(?=^\s*user-agent:)/gim);
  for (const block of blocks) {
    const agent = block.match(/^\s*user-agent:\s*(.+)$/im)?.[1]?.trim();
    if (!agent) continue;
    const disallowsRoot = /^\s*disallow:\s*\/\s*$/im.test(block);
    if (!disallowsRoot) continue;
    const match = AI_AGENTS.find((a) => a.toLowerCase() === agent.toLowerCase());
    if (match) out.push(match);
  }
  return out;
}

export interface CrawlerAccess {
  name: string;
  group: 'search' | 'ai';
  purpose: string;
  allowed: boolean;
}

// The crawlers worth showing a site owner: the search engines you WANT, and the
// AI answer-engines whose access decides whether ChatGPT / Claude / Perplexity /
// Gemini can ever cite you. Blocking any of these is a legitimate choice, so the
// matrix is REPORTED, never graded.
export const CRAWLERS: Array<{ name: string; token: string; group: 'search' | 'ai'; purpose: string }> = [
  { name: 'Googlebot', token: 'googlebot', group: 'search', purpose: 'Google Search' },
  { name: 'Bingbot', token: 'bingbot', group: 'search', purpose: 'Bing · Copilot' },
  { name: 'GPTBot', token: 'gptbot', group: 'ai', purpose: 'OpenAI · training' },
  { name: 'OAI-SearchBot', token: 'oai-searchbot', group: 'ai', purpose: 'ChatGPT Search' },
  { name: 'ClaudeBot', token: 'claudebot', group: 'ai', purpose: 'Claude' },
  { name: 'PerplexityBot', token: 'perplexitybot', group: 'ai', purpose: 'Perplexity' },
  { name: 'Google-Extended', token: 'google-extended', group: 'ai', purpose: 'Gemini · training' },
  { name: 'CCBot', token: 'ccbot', group: 'ai', purpose: 'Common Crawl' },
  { name: 'Applebot-Extended', token: 'applebot-extended', group: 'ai', purpose: 'Apple Intelligence' },
  { name: 'Bytespider', token: 'bytespider', group: 'ai', purpose: 'ByteDance · TikTok' },
];

/** The robots.txt rule lines that apply to a user-agent: exact match wins over `*`. */
function rulesFor(robots: string, token: string): string[] | null {
  const lines = robots.split(/\r?\n/).map((l) => l.replace(/#.*$/, '').trim()).filter(Boolean);
  const groups: Array<{ agents: string[]; rules: string[] }> = [];
  let cur: { agents: string[]; rules: string[] } | null = null;
  let prevWasAgent = false;
  for (const line of lines) {
    const ua = line.match(/^user-agent:\s*(.+)$/i);
    if (ua) {
      // consecutive User-agent lines share the following rules (robots.txt spec)
      if (!cur || !prevWasAgent) {
        cur = { agents: [], rules: [] };
        groups.push(cur);
      }
      cur.agents.push(ua[1].trim().toLowerCase());
      prevWasAgent = true;
    } else {
      if (cur) cur.rules.push(line);
      prevWasAgent = false;
    }
  }
  const exact = groups.find((g) => g.agents.includes(token));
  if (exact) return exact.rules;
  const star = groups.find((g) => g.agents.includes('*'));
  return star ? star.rules : null;
}

/** Can this crawler reach the site root? No robots / no matching group = yes. */
export function robotsAllows(robots: string, token: string): boolean {
  if (!robots.trim()) return true;
  const rules = rulesFor(robots, token.toLowerCase());
  if (!rules) return true;
  if (rules.some((r) => /^allow:\s*\/\s*$/i.test(r))) return true; // explicit root Allow wins
  return !rules.some((r) => /^disallow:\s*\/\s*$/i.test(r));
}

/** Allow/block status for every crawler we track. Reported, never graded. */
export function crawlerMatrix(robots: string): CrawlerAccess[] {
  return CRAWLERS.map(({ name, token, group, purpose }) => ({ name, group, purpose, allowed: robotsAllows(robots, token) }));
}

export interface VisibilityFacts {
  html: string;
  robotsTxt: string;
  hasRobots: boolean;
  hasSitemap: boolean;
  hasLlmsTxt: boolean;
}

const PENALTY = { high: 35, medium: 15, low: 7 } as const;

export function analyzeVisibility(facts: VisibilityFacts, host = ''): VisibilityResult {
  const { html } = facts;
  const jsOnly = isJsOnlyShell(html);
  const blocked = blockedAiAgents(facts.robotsTxt);
  // Quoted verbatim in the check below — evidence beats an abstraction.
  const excerpt = crawlerExcerpt(html);
  const schema = analyzeSchema(html);

  const checks: VisibilityCheck[] = [
    {
      key: 'content-in-html',
      label: 'Content readable without JavaScript',
      pass: !jsOnly,
      severity: 'high',
      detail: jsOnly
        ? `the served HTML holds only ${excerpt.words} word(s) of text — crawlers and most AI assistants never run your JavaScript, so this is all they get: "${excerpt.excerpt}"`
        : `${excerpt.words} words are in the HTML itself. A crawler's first sight of this page: "${excerpt.excerpt}"`,
    },
    {
      key: 'structured-data',
      label: 'Structured data (JSON-LD)',
      // Present AND parses. A malformed block is worse than none — search and AI
      // engines skip it silently — so a broken block fails the check even though
      // markup exists. The "no markup" case stays a pass: it is a missed
      // opportunity, not a defect, and grading it would punish plain pages.
      pass: schema.broken === 0,
      severity: 'low',
      detail:
        schema.blocks === 0
          ? 'none found — assistants have to infer what this page is'
          : describeSchema(schema),
    },
    {
      key: 'canonical',
      label: 'Canonical URL set',
      pass: hasCanonical(html),
      severity: 'low',
      detail: hasCanonical(html) ? 'declared' : 'not declared — duplicate URLs may compete with each other',
    },
    {
      key: 'sitemap',
      label: 'Sitemap published',
      pass: facts.hasSitemap,
      severity: 'low',
      detail: facts.hasSitemap ? '/sitemap.xml is served' : 'no /sitemap.xml — crawlers must guess your URLs',
    },
    // ── content quality (SEO + how well an assistant can summarise you) ─
    (() => {
      const flesch = fleschReadingEase(visibleText(html));
      return {
        key: 'readability',
        label: 'Readable prose (Flesch)',
        pass: flesch === null ? true : flesch >= 30,
        severity: 'low' as const,
        detail:
          flesch === null
            ? 'too little text to score'
            : flesch >= 30
              ? `Flesch ${flesch} — reasonably readable`
              : `Flesch ${flesch} — very dense (college-graduate level); hard for readers and for models summarising the page`,
      };
    })(),
    (() => {
      const h = headingStructure(html);
      const ok = h.hasHeadings && h.h1Count === 1 && !h.skips;
      return {
        key: 'headings',
        label: 'Clear heading structure (one H1)',
        pass: ok,
        severity: 'low' as const,
        detail: !h.hasHeadings
          ? 'no headings found — assistants and search use them to understand the page'
          : h.h1Count === 0
            ? 'no H1 — every page should have exactly one'
            : h.h1Count > 1
              ? `${h.h1Count} H1s — a page should have exactly one`
              : h.skips
                ? 'heading levels skip (e.g. H1 → H3), which confuses document structure'
                : 'one H1, levels in order',
      };
    })(),
    (() => {
      const a = altTextCoverage(html);
      const pct = a.total === 0 ? 100 : Math.round((a.withAlt / a.total) * 100);
      return {
        key: 'alt-text',
        label: 'Images have alt text',
        pass: a.total === 0 || pct >= 80,
        severity: 'low' as const,
        detail:
          a.total === 0
            ? 'no content images to describe'
            : `${a.withAlt}/${a.total} images have alt text (${pct}%)${pct < 80 ? ' — add alt for accessibility and image search' : ''}`,
      };
    })(),
    // ── reported, never graded ────────────────────────────────────────
    {
      key: 'ai-crawler-policy',
      label: 'AI crawler policy',
      pass: true,
      severity: 'low',
      detail: !facts.hasRobots
        ? 'no robots.txt — every crawler, AI included, is allowed by default'
        : blocked.length > 0
          ? `robots.txt blocks ${blocked.join(', ')} — fine if deliberate, worth knowing if not`
          : 'robots.txt allows AI crawlers',
    },
    {
      key: 'llms-txt',
      label: 'llms.txt',
      pass: true, // emerging convention, not a requirement
      severity: 'low',
      detail: facts.hasLlmsTxt
        ? 'published — assistants get a curated summary of your site'
        : 'not published (optional) — an emerging convention for telling assistants what your site is',
    },
  ];

  const failed = checks.filter((c) => !c.pass);
  const score = Math.max(0, 100 - failed.reduce((n, c) => n + PENALTY[c.severity], 0));
  return {
    host,
    checks,
    failed,
    crawlers: crawlerMatrix(facts.robotsTxt),
    excerpt,
    grade: scoreToGrade(score),
    score,
    summary: jsOnly
      ? 'AI assistants and crawlers see an empty page ⚠️'
      : failed.length === 0
        ? 'Your content is readable by assistants and crawlers ✅'
        : `${failed.length} thing(s) limiting how well assistants can read this ⚠️`,
  };
}
