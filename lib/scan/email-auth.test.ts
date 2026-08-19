import { describe, it, expect } from 'vitest';
import { findSpf, findDmarc, dmarcPolicy, spfIsEnforcing, analyzeEmailAuth, type DnsFacts } from './email-auth';

const facts = (over: Partial<DnsFacts> = {}): DnsFacts => ({ txt: [], dmarcTxt: [], hasMx: false, ...over });
const get = (r: ReturnType<typeof analyzeEmailAuth>, k: string) => r.checks.find((c) => c.key === k)!;

describe('record parsing', () => {
  it('finds SPF and DMARC among unrelated TXT records', () => {
    expect(findSpf(['google-site-verification=x', 'v=spf1 include:_spf.google.com -all'])).toMatch(/^v=spf1/);
    expect(findSpf(['some-other-record'])).toBe(null);
    expect(findDmarc(['v=DMARC1; p=reject; rua=mailto:a@b.c'])).toMatch(/^v=DMARC1/);
    expect(findDmarc([])).toBe(null);
  });

  it('reads the DMARC enforcement policy', () => {
    expect(dmarcPolicy('v=DMARC1; p=reject')).toBe('reject');
    expect(dmarcPolicy('v=DMARC1; p=quarantine; pct=100')).toBe('quarantine');
    expect(dmarcPolicy('v=DMARC1; p=none')).toBe('none');
    expect(dmarcPolicy(null)).toBe(null);
  });

  it('knows an SPF that does not actually enforce', () => {
    expect(spfIsEnforcing('v=spf1 include:x -all')).toBe(true);
    expect(spfIsEnforcing('v=spf1 include:x ~all')).toBe(true);
    expect(spfIsEnforcing('v=spf1 include:x ?all')).toBe(false);
    expect(spfIsEnforcing('v=spf1 +all')).toBe(false);
  });
});

describe('analyzeEmailAuth', () => {
  it('a domain with nothing published is wide open to spoofing', () => {
    const r = analyzeEmailAuth(facts());
    expect(get(r, 'spf').pass).toBe(false);
    expect(get(r, 'dmarc').pass).toBe(false);
    expect(get(r, 'spf').detail).toMatch(/anyone can send email/);
    expect(r.grade).not.toBe('A');
    expect(r.summary).toMatch(/send mail as you/);
  });

  it('does not demand enforcement before a DMARC record even exists', () => {
    const r = analyzeEmailAuth(facts());
    // spf + dmarc fail, but "enforced" must not pile on a third failure
    expect(get(r, 'dmarc-enforced').pass).toBe(true);
    expect(r.failed).toHaveLength(2);
  });

  it('flags monitor-only DMARC (p=none) as published but not enforced', () => {
    const r = analyzeEmailAuth(facts({ txt: ['v=spf1 -all'], dmarcTxt: ['v=DMARC1; p=none'] }));
    expect(get(r, 'dmarc').pass).toBe(true);
    expect(get(r, 'dmarc-enforced').pass).toBe(false);
    expect(get(r, 'dmarc-enforced').detail).toMatch(/still delivered/);
  });

  it('notes a non-enforcing SPF even though the record exists', () => {
    const r = analyzeEmailAuth(facts({ txt: ['v=spf1 include:x ?all'], dmarcTxt: ['v=DMARC1; p=reject'] }));
    expect(get(r, 'spf').pass).toBe(true);
    expect(get(r, 'spf').detail).toMatch(/does not actually reject/);
  });

  it('a properly protected domain passes everything', () => {
    const r = analyzeEmailAuth(facts({ txt: ['v=spf1 include:_spf.google.com -all'], dmarcTxt: ['v=DMARC1; p=reject'], hasMx: true }));
    expect(r.failed).toHaveLength(0);
    expect(r.grade).toBe('A');
    expect(r.summary).toMatch(/protected against email spoofing/);
  });
});

describe('platform subdomains', () => {
  it('does not demand DNS records the user cannot publish', () => {
    for (const h of ['myapp.vercel.app', 'thing.netlify.app', 'x.pages.dev', 'demo.lovable.app', 'p.supabase.co']) {
      const r = analyzeEmailAuth(facts(), h);
      expect(r.failed).toHaveLength(0);
      expect(r.grade).toBe('A');
      expect(r.checks[0].detail).toMatch(/isn't yours to configure/);
    }
  });

  it('still checks a real custom domain', () => {
    const r = analyzeEmailAuth(facts(), 'myapp.com');
    expect(r.failed.length).toBeGreaterThan(0);
  });

  it('does not exempt a lookalike that merely contains a platform name', () => {
    expect(analyzeEmailAuth(facts(), 'vercel.app.evil.com').failed.length).toBeGreaterThan(0);
  });
});
