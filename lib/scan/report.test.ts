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
  checks: [],
  missing: [{ key: 'content-security-policy', label: 'Content-Security-Policy', present: false, severity: 'high', note: '', fix: 'Add a CSP' }],
  grade: 'B',
  score: 88,
  summary: '1 missing',
  ...over,
});

const fundamentals = (grade: FundamentalsResult['grade']): FundamentalsResult => ({
  host: 'my.app',
  checks: [],
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
    expect(r.issueCount).toBe(3); // 2 tables + 1 header
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
});
