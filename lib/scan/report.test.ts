import { describe, it, expect } from 'vitest';
import { combineReport } from './report';
import type { SupabaseScanResult } from './types';
import type { HeadersScanResult } from './headers';

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

describe('combineReport', () => {
  it('overall = worst of the graded categories; issues sum across scans', () => {
    const r = combineReport(sb({ grade: 'F', exposedCount: 2, findings: [
      { table: 'users', exposed: true, rowsVisible: 10 },
      { table: 'orders', exposed: true, rowsVisible: 5 },
    ] }), hdr());
    expect(r.overallGrade).toBe('F'); // F (db) is worse than B (headers)
    expect(r.categories).toHaveLength(2);
    expect(r.issueCount).toBe(3); // 2 exposed tables + 1 missing header
    expect(r.verdict).toMatch(/Wide open/);
  });

  it('a single scan works (headers only)', () => {
    const r = combineReport(null, hdr({ grade: 'C' }));
    expect(r.overallGrade).toBe('C');
    expect(r.categories.map((c) => c.key)).toEqual(['headers']);
  });

  it('an errored supabase scan is shown but not counted toward the grade', () => {
    const r = combineReport(sb({ ok: false, error: 'anon key rejected' }), hdr({ grade: 'A', missing: [] }));
    expect(r.overallGrade).toBe('A'); // only headers counts
    const dbCat = r.categories.find((c) => c.key === 'supabase');
    expect(dbCat?.grade).toBeNull();
    expect(dbCat?.summary).toMatch(/rejected/);
  });

  it('all clean -> A, zero issues', () => {
    const r = combineReport(
      sb({ grade: 'A', exposedCount: 0, findings: [{ table: 'users', exposed: false, rowsVisible: 0 }] }),
      hdr({ grade: 'A', missing: [] }),
    );
    expect(r.overallGrade).toBe('A');
    expect(r.issueCount).toBe(0);
  });
});
