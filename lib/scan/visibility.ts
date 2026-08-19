import type { Grade } from './types';
import { scoreToGrade } from './grade';

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
  grade: Grade;
  score: number;
  summary: string;
}

/** The AI crawlers worth naming when we report a site's policy. */
const AI_AGENTS = ['GPTBot', 'ClaudeBot', 'anthropic-ai', 'PerplexityBot', 'Google-Extended', 'CCBot', 'Bytespider'];

/** Visible text once markup, scripts and styles are stripped. */
export function visibleTextLength(html: string): number {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&[a-z]+;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim().length;
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

  const checks: VisibilityCheck[] = [
    {
      key: 'content-in-html',
      label: 'Content readable without JavaScript',
      pass: !jsOnly,
      severity: 'high',
      detail: jsOnly
        ? `the served HTML holds ~${visibleTextLength(html)} characters of text — crawlers and most AI assistants never run your JavaScript, so they see an empty page`
        : `~${visibleTextLength(html)} characters of text are in the HTML itself`,
    },
    {
      key: 'structured-data',
      label: 'Structured data (JSON-LD)',
      pass: hasStructuredData(html),
      severity: 'low',
      detail: hasStructuredData(html)
        ? 'schema.org markup found'
        : 'none found — assistants have to infer what this page is',
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
    grade: scoreToGrade(score),
    score,
    summary: jsOnly
      ? 'AI assistants and crawlers see an empty page ⚠️'
      : failed.length === 0
        ? 'Your content is readable by assistants and crawlers ✅'
        : `${failed.length} thing(s) limiting how well assistants can read this ⚠️`,
  };
}
