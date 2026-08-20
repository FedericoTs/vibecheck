import { describe, it, expect } from 'vitest';
import {
  visibleTextLength,
  isJsOnlyShell,
  hasStructuredData,
  hasCanonical,
  blockedAiAgents,
  analyzeVisibility,
  type VisibilityFacts,
  fleschReadingEase,
  headingStructure,
  altTextCoverage,
  robotsAllows,
  crawlerMatrix,
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
        html: '<html><head><link rel="canonical" href="https://x.com/"><script type="application/ld+json">{}</script></head><body><h1>Welcome</h1>' +
          'The team ships fast and keeps things simple. Users love how clear it feels. '.repeat(12) + '</body></html>',
        hasSitemap: true,
      }),
      'app.com',
    );
    expect(r.failed).toHaveLength(0);
    expect(r.grade).toBe('A');
  });
});

describe('content quality — readability, headings, alt text', () => {
  it('Flesch: easy prose scores high, dense prose low, thin content is null', () => {
    const easy = 'The cat sat on the mat. It was a warm day. The sun was up. We ran to the park. It was fun. '.repeat(3);
    const dense = 'Notwithstanding the aforementioned considerations, the multifaceted implementation necessitates comprehensive evaluation of the interdependent architectural methodologies. '.repeat(4);
    expect(fleschReadingEase(easy)!).toBeGreaterThan(70);
    expect(fleschReadingEase(dense)!).toBeLessThan(40);
    expect(fleschReadingEase('too short')).toBe(null);
  });

  it('headings: flags none, multiple H1, and skipped levels', () => {
    expect(headingStructure('<h1>Title</h1><h2>Sub</h2>')).toEqual({ h1Count: 1, hasHeadings: true, skips: false });
    expect(headingStructure('<h1>A</h1><h1>B</h1>').h1Count).toBe(2);
    expect(headingStructure('<h1>A</h1><h3>skip</h3>').skips).toBe(true);
    expect(headingStructure('<p>no headings</p>').hasHeadings).toBe(false);
  });

  it('alt text: counts content images with alt, ignores decorative', () => {
    const html = '<img src="a.jpg" alt="a cat"><img src="b.jpg"><img src="c.jpg" alt="" role="presentation">';
    const a = altTextCoverage(html);
    expect(a.total).toBe(2); // decorative one excluded
    expect(a.withAlt).toBe(1);
  });

  it('surfaces the three as low-severity checks in the report', () => {
    const html = '<html><body><h1>A</h1><h1>B</h1>' + 'Some real content here. '.repeat(20) + '<img src="x.jpg"></body></html>';
    const r = analyzeVisibility({ html, robotsTxt: '', hasRobots: false, hasSitemap: true, hasLlmsTxt: false }, 'app.com');
    const keys = r.checks.map((c) => c.key);
    expect(keys).toContain('readability');
    expect(keys).toContain('headings');
    expect(keys).toContain('alt-text');
    expect(r.checks.find((c) => c.key === 'headings')!.pass).toBe(false); // two H1s
  });
});

describe('crawler access matrix (robots.txt)', () => {
  it('no robots.txt = everyone allowed', () => {
    expect(robotsAllows('', 'gptbot')).toBe(true);
    expect(crawlerMatrix('').every((c) => c.allowed)).toBe(true);
  });

  it('a bot-specific Disallow: / blocks that bot only', () => {
    const robots = 'User-agent: GPTBot\nDisallow: /\n\nUser-agent: *\nDisallow:';
    expect(robotsAllows(robots, 'gptbot')).toBe(false);
    expect(robotsAllows(robots, 'googlebot')).toBe(true); // uses * group (empty disallow)
  });

  it('a blanket Disallow: / under * blocks bots without their own group', () => {
    expect(robotsAllows('User-agent: *\nDisallow: /', 'ccbot')).toBe(false);
  });

  it('a bot with its own group ignores the * group', () => {
    const robots = 'User-agent: *\nDisallow: /\n\nUser-agent: Googlebot\nDisallow:';
    expect(robotsAllows(robots, 'googlebot')).toBe(true); // own group allows
    expect(robotsAllows(robots, 'bingbot')).toBe(false); // falls to * (blocked)
  });

  it('shared rules across consecutive User-agent lines', () => {
    const robots = 'User-agent: GPTBot\nUser-agent: CCBot\nDisallow: /';
    expect(robotsAllows(robots, 'gptbot')).toBe(false);
    expect(robotsAllows(robots, 'ccbot')).toBe(false);
    expect(robotsAllows(robots, 'googlebot')).toBe(true);
  });

  it('a sub-path Disallow does not block root; Allow:/ overrides Disallow:/', () => {
    expect(robotsAllows('User-agent: *\nDisallow: /admin', 'googlebot')).toBe(true);
    expect(robotsAllows('User-agent: *\nDisallow: /\nAllow: /', 'googlebot')).toBe(true);
  });

  it('the matrix reports both search and AI crawlers', () => {
    const m = crawlerMatrix('User-agent: GPTBot\nDisallow: /');
    expect(m.find((c) => c.name === 'GPTBot')?.allowed).toBe(false);
    expect(m.find((c) => c.name === 'Googlebot')?.allowed).toBe(true);
    expect(m.some((c) => c.group === 'search')).toBe(true);
    expect(m.some((c) => c.group === 'ai')).toBe(true);
  });
});
