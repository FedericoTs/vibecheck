import { describe, it, expect } from 'vitest';
import { combineReport } from './report';
import type { SupabaseScanResult } from './types';
import type { HeadersScanResult } from './headers';
import type { FundamentalsResult } from './fundamentals';

const sb = (over: Partial<SupabaseScanResult> = {}): SupabaseScanResult => ({
  ok: true,
  host: 'abc.supabase.co',
  tablesFound: 3,
  findings: [
    { table: 'users', exposed: true, rowsVisible: 1200 },
    { table: 'posts', exposed: false, rowsVisible: 0 },
  ],
  exposedCount: 1,
  grade: 'D',
  summary: '1 of 3 readable',
  ...over,
});

const hdr = (over: Partial<HeadersScanResult> = {}): HeadersScanResult => ({
  host: 'my.app',
  checks: [
    { key: 'content-security-policy', label: 'Content-Security-Policy', present: false, severity: 'high', note: '', fix: 'Add a CSP' },
    { key: 'x-content-type-options', label: 'X-Content-Type-Options', present: true, severity: 'medium', note: '', fix: '' },
  ],
  missing: [{ key: 'content-security-policy', label: 'Content-Security-Policy', present: false, severity: 'high', note: '', fix: 'Add a CSP' }],
  grade: 'B',
  score: 88,
  summary: '1 missing',
  ...over,
});

const fundamentals = (grade: FundamentalsResult['grade']): FundamentalsResult => ({
  host: 'my.app',
  checks: [
    { key: 'https', label: 'Served over HTTPS', pass: true, severity: 'medium', fix: '' },
    { key: 'title', label: 'Page title', pass: false, severity: 'low', fix: 'add a title' },
  ],
  failed: [{ key: 'title', label: 'Page title', pass: false, severity: 'low', fix: 'add a title' }],
  grade,
  score: 50,
  summary: 'basics missing',
});

describe('combineReport', () => {
  it('overall = worst of the SECURITY categories; issues sum across them', () => {
    const r = combineReport({
      supabase: sb({ grade: 'F', exposedCount: 2, findings: [
        { table: 'users', exposed: true, rowsVisible: 10 },
        { table: 'orders', exposed: true, rowsVisible: 5 },
      ] }),
      headers: hdr(),
    });
    expect(r.overallGrade).toBe('F');
    expect(r.issueCount).toBe(3); // 2 tables + 1 missing header
    expect(r.verdict).toMatch(/Wide open/);
  });

  it('a single security scan works (headers only)', () => {
    const r = combineReport({ headers: hdr({ grade: 'C' }) });
    expect(r.overallGrade).toBe('C');
    expect(r.categories.map((c) => c.key)).toEqual(['headers']);
  });

  it('an errored supabase scan shows but does not count toward the grade', () => {
    const r = combineReport({ supabase: sb({ ok: false, error: 'anon key rejected' }), headers: hdr({ grade: 'A', missing: [] }) });
    expect(r.overallGrade).toBe('A');
    expect(r.categories.find((c) => c.key === 'supabase')?.grade).toBeNull();
  });

  it('BASICS never drag the security headline grade', () => {
    const r = combineReport({ headers: hdr({ grade: 'A', missing: [] }), fundamentals: fundamentals('F') });
    expect(r.overallGrade).toBe('A'); // security is A even though fundamentals is F
    const f = r.categories.find((c) => c.key === 'fundamentals');
    expect(f?.group).toBe('basics');
    expect(f?.grade).toBe('F');
    expect(r.issueCount).toBe(0); // fundamentals failures are not security issues
  });

  it('builds a ✓/✗ checklist per category and counts passed/total across everything', () => {
    const r = combineReport({ headers: hdr(), fundamentals: fundamentals('C') });
    const h = r.categories.find((c) => c.key === 'headers')!;
    expect(h.checks.find((c) => c.label === 'Content-Security-Policy')?.pass).toBe(false);
    expect(h.checks.find((c) => c.label === 'X-Content-Type-Options')?.pass).toBe(true);
    expect(r.total).toBe(4); // 2 headers + 2 fundamentals
    expect(r.passed).toBe(2); // XCTO + HTTPS pass
  });

  it('a clean scan still lists what it checked (green ticks, not an empty card)', () => {
    const r = combineReport({
      secrets: { host: 'my.app', findings: [], grade: 'A', score: 100, summary: 'clean' },
      paths: { host: 'my.app', findings: [{ path: '/.env', label: '.env', severity: 'high', exposed: false }], exposed: [], grade: 'A', score: 100, summary: 'clean' },
    });
    const secrets = r.categories.find((c) => c.key === 'secrets')!;
    expect(secrets.checks[0].pass).toBe(true); // shows a green "no secrets" line
    expect(secrets.checks[0].detail).toMatch(/service_role/);
    const paths = r.categories.find((c) => c.key === 'paths')!;
    expect(paths.checks[0].pass).toBe(true); // the .env probe shows as passed
    expect(r.passed).toBe(2);
  });
});
