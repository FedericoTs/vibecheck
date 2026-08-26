import { describe, it, expect } from 'vitest';
import { combineReport, severityCounts, type ReportInputs } from './report';
import type { Report, ReportCategory, CheckItem } from './report';
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

// local builders so these tests don't depend on the scanners' shapes
const cat = (over: Partial<ReportCategory>): ReportCategory => ({
  key: 'headers',
  group: 'security',
  label: 'Security headers',
  grade: 'F',
  summary: '',
  checks: [],
  ...over,
});
const report = (categories: ReportCategory[]): Report => {
  const all: CheckItem[] = categories.flatMap((c) => c.checks);
  return {
    overallGrade: 'F',
    verdict: '',
    issueCount: all.filter((c) => !c.pass).length,
    passed: all.filter((c) => c.pass).length,
    total: all.length,
    categories,
  };
};

describe('severityCounts', () => {
  const withChecks = (checks: Array<{ pass: boolean; severity?: 'critical' | 'high' | 'medium' | 'low' }>) =>
    report([cat({ checks: checks.map((c, i) => ({ label: 'c' + i, pass: c.pass, severity: c.severity })) })]);

  it('counts only FAILING security checks, grouped by severity', () => {
    const r = withChecks([
      { pass: false, severity: 'critical' },
      { pass: false, severity: 'critical' },
      { pass: false, severity: 'high' },
      { pass: false, severity: 'low' },
      { pass: true, severity: 'critical' }, // passing -> ignored
    ]);
    expect(severityCounts(r)).toEqual({ critical: 2, high: 1, medium: 0, low: 1 });
  });

  it('defaults an unlabelled failure to medium rather than dropping it', () => {
    expect(severityCounts(withChecks([{ pass: false }]))).toEqual({ critical: 0, high: 0, medium: 1, low: 0 });
  });

  it('ignores non-security groups — privacy and SEO are not security issues', () => {
    const r = report([
      cat({ checks: [{ label: 'a', pass: false, severity: 'critical' }] }),
      cat({ key: 'privacy', group: 'privacy', label: 'EU privacy', checks: [{ label: 'b', pass: false, severity: 'critical' }] }),
    ]);
    expect(severityCounts(r).critical).toBe(1);
  });

  it('a clean report has nothing to weight', () => {
    expect(severityCounts(withChecks([{ pass: true }]))).toEqual({ critical: 0, high: 0, medium: 0, low: 0 });
  });
});

describe('an unreachable probe is not a pass', () => {
  it('renders a path we could not reach as ungraded, not a green tick', () => {
    const r = combineReport({
      paths: {
        host: 'x.com',
        grade: 'A',
        score: 100,
        summary: 'Nothing exposed in the 1 of 2 paths we could reach',
        exposed: [],
        findings: [
          { path: '/.env', label: '.env', severity: 'high', exposed: false, checked: false },
          { path: '/.git/config', label: '.git/config', severity: 'high', exposed: false },
        ],
      },
    } as unknown as ReportInputs);
    const paths = r.categories.find((c) => c.key === 'paths')!;
    const unreachable = paths.checks.find((c) => c.label === '.env')!;
    const checked = paths.checks.find((c) => c.label === '.git/config')!;

    expect(unreachable.pass).toBe(false); // not a tick
    expect(unreachable.graded).toBe(false); // but not an accusation either
    expect(checked.pass).toBe(true);
    // It must not inflate the issue count or drag the grade.
    expect(r.issueCount).toBe(0);
    expect(severityCounts(r).high).toBe(0);
  });

  it('renders an unreachable ROUTE the same way', () => {
    const r = combineReport({
      routes: {
        host: 'x.com',
        grade: 'A',
        score: 100,
        summary: 'ok',
        exposed: [],
        findings: [{ path: '/admin', label: '/admin', kind: 'admin', verdict: 'unreachable' }],
      },
    } as unknown as ReportInputs);
    const check = r.categories.find((c) => c.key === 'routes')!.checks[0];
    expect(check.pass).toBe(false);
    expect(check.graded).toBe(false);
    expect(r.issueCount).toBe(0);
  });
});

/**
 * The engine computes a 0-100 for most categories and used to drop it on the
 * floor at ReportCategory, leaving the UI five buckets where there were a
 * hundred. These pin the pass-through, because a silently-missing number just
 * looks like a category that chose not to score itself.
 */
describe('category score + severity pass-through', () => {
  it('carries the scanner 0-100 onto the category, not just the letter', () => {
    const r = combineReport({
      headers: hdr({ grade: 'C', score: 63 }),
    } as unknown as ReportInputs);
    const cat = r.categories.find((c) => c.key === 'headers')!;
    expect(cat.grade).toBe('C');
    expect(cat.score).toBe(63);
  });

  it('keeps two same-letter categories distinguishable by score', () => {
    const low = combineReport({ headers: hdr({ grade: 'C', score: 61 }) } as unknown as ReportInputs);
    const high = combineReport({ headers: hdr({ grade: 'C', score: 74 }) } as unknown as ReportInputs);
    const a = low.categories.find((c) => c.key === 'headers')!;
    const b = high.categories.find((c) => c.key === 'headers')!;
    expect(a.grade).toBe(b.grade);
    expect(a.score).not.toBe(b.score);
  });

  it('keeps severity on a NON-security check, so it can be ranked', () => {
    const r = combineReport({
      fundamentals: {
        host: 'my.app',
        grade: 'C',
        score: 70,
        summary: 'some gaps',
        checks: [{ key: 'title', label: 'Page title', pass: false, severity: 'medium' }],
      },
    } as unknown as ReportInputs);
    const cat = r.categories.find((c) => c.key === 'fundamentals')!;
    expect(cat.checks[0].severity).toBe('medium');
  });

  it('still refuses to let a non-security severity touch the security counts', () => {
    const r = combineReport({
      fundamentals: {
        host: 'my.app',
        grade: 'F',
        score: 10,
        summary: 'bad',
        checks: [{ key: 'title', label: 'Page title', pass: false, severity: 'high' }],
      },
    } as unknown as ReportInputs);
    // basics is not a security group: it must not move issueCount or severityCounts.
    expect(r.issueCount).toBe(0);
    expect(severityCounts(r).high).toBe(0);
  });
});
