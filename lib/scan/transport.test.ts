import { describe, it, expect } from 'vitest';
import { daysUntilExpiry, certCoversHost, isOpenRedirect, analyzeTransport, type TransportFacts } from './transport';

const NOW = Date.parse('2026-08-19T00:00:00Z');
const inDays = (n: number) => new Date(NOW + n * 86_400_000).toISOString();
const facts = (over: Partial<TransportFacts> = {}): TransportFacts => ({
  cert: { checked: true, validTo: inDays(90), issuer: "Let's Encrypt", names: ['myapp.com'] },
  httpsEnforced: true,
  openRedirectParams: [],
  redirectChecked: true,
  ...over,
});
const get = (r: ReturnType<typeof analyzeTransport>, k: string) => r.checks.find((c) => c.key === k);

describe('daysUntilExpiry', () => {
  it('counts forward and backward, tolerates junk', () => {
    expect(daysUntilExpiry(inDays(30), NOW)).toBe(30);
    expect(daysUntilExpiry(inDays(-3), NOW)).toBe(-3);
    expect(daysUntilExpiry('not a date', NOW)).toBe(null);
    expect(daysUntilExpiry(undefined, NOW)).toBe(null);
  });
});

describe('certCoversHost', () => {
  it('matches exact names and single-label wildcards', () => {
    expect(certCoversHost(['myapp.com'], 'myapp.com')).toBe(true);
    expect(certCoversHost(['*.myapp.com'], 'www.myapp.com')).toBe(true);
    expect(certCoversHost(['*.myapp.com'], 'myapp.com')).toBe(false);
    // a wildcard covers ONE label only
    expect(certCoversHost(['*.myapp.com'], 'a.b.myapp.com')).toBe(false);
    expect(certCoversHost(['other.com'], 'myapp.com')).toBe(false);
  });
  it('never accuses when the names are unknown', () => {
    expect(certCoversHost(undefined, 'myapp.com')).toBe(true);
    expect(certCoversHost([], 'myapp.com')).toBe(true);
  });
});

describe('isOpenRedirect', () => {
  it('fires only on a real redirect to the planted foreign host', () => {
    expect(isOpenRedirect(302, 'https://example.com/canary', 'example.com')).toBe(true);
    expect(isOpenRedirect(301, '//example.com/canary', 'example.com')).toBe(true); // protocol-relative
  });
  it('does NOT fire on same-site redirects, non-redirects, or junk', () => {
    expect(isOpenRedirect(302, '/dashboard', 'example.com')).toBe(false);
    expect(isOpenRedirect(302, 'https://myapp.com/next', 'example.com')).toBe(false);
    expect(isOpenRedirect(200, 'https://example.com/', 'example.com')).toBe(false); // no redirect
    expect(isOpenRedirect(302, null, 'example.com')).toBe(false);
    expect(isOpenRedirect(302, ':::::', 'example.com')).toBe(false);
  });
});

describe('analyzeTransport', () => {
  it('a healthy site passes everything', () => {
    const r = analyzeTransport(facts(), 'myapp.com', NOW);
    expect(r.failed).toHaveLength(0);
    expect(r.grade).toBe('A');
  });

  it('an expired certificate is a hard failure with plain-language impact', () => {
    const r = analyzeTransport(facts({ cert: { checked: true, validTo: inDays(-2), names: ['myapp.com'] } }), 'myapp.com', NOW);
    expect(get(r, 'cert-expiry')!.pass).toBe(false);
    expect(get(r, 'cert-expiry')!.detail).toMatch(/expired 2 day\(s\) ago/);
    expect(get(r, 'cert-expiry')!.detail).toMatch(/browser warning/);
  });

  it('warns separately when renewal is imminent but the cert is still valid', () => {
    const r = analyzeTransport(facts({ cert: { checked: true, validTo: inDays(5), names: ['myapp.com'] } }), 'myapp.com', NOW);
    expect(get(r, 'cert-expiry')!.pass).toBe(true); // still valid
    expect(get(r, 'cert-renewal')!.pass).toBe(false); // but flagged
  });

  it('flags an open redirect and names the parameter', () => {
    const r = analyzeTransport(facts({ openRedirectParams: ['next', 'redirect'] }), 'myapp.com', NOW);
    const c = get(r, 'open-redirect')!;
    expect(c.pass).toBe(false);
    expect(c.detail).toMatch(/next\/\?redirect/);
    expect(c.detail).toMatch(/phishing link that looks like yours/);
  });

  it('flags http served without a redirect to https', () => {
    const r = analyzeTransport(facts({ httpsEnforced: false }), 'myapp.com', NOW);
    expect(get(r, 'https-enforced')!.pass).toBe(false);
  });

  it('reports nothing it could not test', () => {
    const r = analyzeTransport({ cert: { checked: false }, openRedirectParams: [], redirectChecked: false }, 'myapp.com', NOW);
    expect(r.checks).toHaveLength(0);
    expect(r.grade).toBe('A');
  });
});

/**
 * Reported against google.com, where http 301s to another http URL. The old
 * copy called that "served without redirecting", which was simply not what
 * happened — and a report that misdescribes its own observation is worth less
 * than one that stays quiet.
 */
describe('http behaviour is described accurately', () => {
  const detail = (over: Partial<TransportFacts>) =>
    analyzeTransport(facts(over), 'myapp.com', NOW).checks.find((c) => c.key === 'https-enforced')?.detail ?? '';

  it('does not claim "no redirect" when there was a redirect', () => {
    const d = detail({ httpsEnforced: false, httpBehaviour: 'http-redirect' });
    expect(d).not.toMatch(/without redirecting/i);
    expect(d).toMatch(/redirects, but to another http address/i);
  });

  it('names preload as the thing it cannot see, rather than ignoring it', () => {
    expect(detail({ httpsEnforced: false, httpBehaviour: 'http-redirect' })).toMatch(/preload/i);
  });

  it('still says plainly when the page really is served over http', () => {
    expect(detail({ httpsEnforced: false, httpBehaviour: 'plain' })).toMatch(/served over plain http/i);
  });

  it('is unchanged when http correctly upgrades', () => {
    expect(detail({ httpsEnforced: true, httpBehaviour: 'https' })).toMatch(/redirected to https/i);
  });

  it('falls back safely when the route reports no behaviour', () => {
    expect(detail({ httpsEnforced: false })).toMatch(/plain http/i);
  });
});

/**
 * "Certificate is current ✓ — expiry could not be read" asserted the one thing
 * the same sentence said was unavailable. In a security report a false assurance
 * is the worse direction to err, and a red cross would have been an unearned
 * accusation, so it takes the third state.
 */
describe('an unreadable certificate expiry is not a pass', () => {
  const certCheck = (validTo: string | undefined) =>
    analyzeTransport(facts({ cert: { ...facts({}).cert, checked: true, validTo } }), 'myapp.com', NOW).checks.find(
      (c) => c.key === 'cert-expiry',
    )!;

  it('is shown but not graded when expiry cannot be read', () => {
    const c = certCheck(undefined);
    expect(c.pass).toBe(false);
    expect(c.graded).toBe(false);
    expect(c.detail).toMatch(/could not be read/i);
  });

  it('does not drag the score down either', () => {
    const unknown = analyzeTransport(
      facts({ cert: { ...facts({}).cert, checked: true, validTo: undefined } }),
      'myapp.com',
      NOW,
    );
    const valid = analyzeTransport(facts({}), 'myapp.com', NOW);
    expect(unknown.score).toBe(valid.score);
  });

  it('still fails plainly on a genuinely expired certificate', () => {
    const c = certCheck(new Date(NOW - 5 * 86_400_000).toISOString());
    expect(c.pass).toBe(false);
    expect(c.graded).toBeUndefined(); // a real accusation, and counted
  });
});
