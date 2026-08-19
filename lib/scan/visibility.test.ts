import { describe, it, expect } from 'vitest';
import {
  visibleTextLength,
  isJsOnlyShell,
  hasStructuredData,
  hasCanonical,
  blockedAiAgents,
  analyzeVisibility,
  type VisibilityFacts,
} from './visibility';

const facts = (over: Partial<VisibilityFacts> = {}): VisibilityFacts => ({
  html: '<html><body>' + 'Real content about the product. '.repeat(20) + '</body></html>',
  robotsTxt: '',
  hasRobots: false,
  hasSitemap: true,
  hasLlmsTxt: false,
  ...over,
});
const get = (r: ReturnType<typeof analyzeVisibility>, k: string) => r.checks.find((c) => c.key === k)!;

const SPA_SHELL = '<!doctype html><html><head><title>App</title></head><body><div id="root"></div><script src="/app.js"></script></body></html>';

describe('text extraction', () => {
  it('ignores markup, scripts and styles', () => {
    expect(visibleTextLength('<p>hello world</p>')).toBe(11);
    expect(visibleTextLength('<script>const x = "a very long string indeed";</script>')).toBe(0);
    expect(visibleTextLength('<style>.a{color:red}</style>')).toBe(0);
  });
});

describe('isJsOnlyShell — the invisible-to-AI case', () => {
  it('flags an empty SPA shell that only fills in via JS', () => {
    expect(isJsOnlyShell(SPA_SHELL)).toBe(true);
  });
  it('does NOT flag a server-rendered page that also ships scripts', () => {
    const ssr = '<html><body>' + 'Substantial rendered copy here. '.repeat(30) + '<script src="/app.js"></script></body></html>';
    expect(isJsOnlyShell(ssr)).toBe(false);
  });
  it('does not flag a static page with no scripts at all', () => {
    expect(isJsOnlyShell('<html><body><p>short</p></body></html>')).toBe(false);
  });
});

describe('markup detectors', () => {
  it('finds JSON-LD and canonical', () => {
    expect(hasStructuredData('<script type="application/ld+json">{}</script>')).toBe(true);
    expect(hasStructuredData('<script src="/a.js"></script>')).toBe(false);
    expect(hasCanonical('<link rel="canonical" href="https://x.com/">')).toBe(true);
    expect(hasCanonical('<link rel="stylesheet" href="/a.css">')).toBe(false);
  });
});

describe('blockedAiAgents', () => {
  it('lists AI crawlers blocked by a blanket disallow', () => {
    const robots = 'User-agent: GPTBot\nDisallow: /\n\nUser-agent: ClaudeBot\nDisallow: /\n\nUser-agent: *\nAllow: /';
    expect(blockedAiAgents(robots).sort()).toEqual(['ClaudeBot', 'GPTBot']);
  });
  it('does not count a partial disallow or an allowed agent', () => {
    expect(blockedAiAgents('User-agent: GPTBot\nDisallow: /admin')).toEqual([]);
    expect(blockedAiAgents('User-agent: GPTBot\nAllow: /')).toEqual([]);
    expect(blockedAiAgents('')).toEqual([]);
  });
  it('ignores a blanket block of non-AI agents', () => {
    expect(blockedAiAgents('User-agent: *\nDisallow: /')).toEqual([]);
  });
});

describe('analyzeVisibility', () => {
  it('a JS-only shell is the headline failure', () => {
    const r = analyzeVisibility(facts({ html: SPA_SHELL }), 'app.com');
    expect(get(r, 'content-in-html').pass).toBe(false);
    expect(get(r, 'content-in-html').detail).toMatch(/never run your JavaScript/);
    expect(r.summary).toMatch(/see an empty page/);
    expect(r.grade).not.toBe('A');
  });

  it('REPORTS the AI crawler policy without grading it — blocking is a valid choice', () => {
    const r = analyzeVisibility(facts({ hasRobots: true, robotsTxt: 'User-agent: GPTBot\nDisallow: /' }), 'app.com');
    const c = get(r, 'ai-crawler-policy');
    expect(c.pass).toBe(true); // never a failure
    expect(c.detail).toMatch(/blocks GPTBot/);
    expect(c.detail).toMatch(/fine if deliberate/);
  });

  it('treats llms.txt as optional, never a failure', () => {
    const r = analyzeVisibility(facts({ hasLlmsTxt: false }), 'app.com');
    expect(get(r, 'llms-txt').pass).toBe(true);
    expect(get(r, 'llms-txt').detail).toMatch(/optional/);
  });

  it('a well-built page passes everything', () => {
    const r = analyzeVisibility(
      facts({
        html: '<html><head><link rel="canonical" href="https://x.com/"><script type="application/ld+json">{}</script></head><body>' +
          'Plenty of real server-rendered content. '.repeat(20) + '</body></html>',
        hasSitemap: true,
      }),
      'app.com',
    );
    expect(r.failed).toHaveLength(0);
    expect(r.grade).toBe('A');
  });
});
