import { describe, it, expect } from 'vitest';
import { pillars, ranked, unknowns, verdict, cleared, PILLAR_ORDER } from './insights';
import type { Report, ReportCategory, CheckItem } from './report';

const chk = (over: Partial<CheckItem> = {}): CheckItem => ({ label: 'a check', pass: true, ...over });

const cat = (over: Partial<ReportCategory> = {}): ReportCategory => ({
  key: 'headers',
  group: 'security',
  label: 'Security headers',
  grade: 'A',
  summary: 'ok',
  checks: [chk()],
  ...over,
});

const rep = (over: Partial<Report> = {}): Report => ({
  overallGrade: 'A',
  verdict: 'Locked down. Nothing a stranger can reach.',
  issueCount: 0,
  passed: 1,
  total: 1,
  categories: [cat()],
  ...over,
});

describe('pillars', () => {
  it('groups categories and counts pass / fail / unknown separately', () => {
    const r = rep({
      categories: [
        cat({
          checks: [
            chk({ pass: true }),
            chk({ pass: false, severity: 'high' }),
            chk({ pass: false, graded: false }),
          ],
        }),
      ],
    });
    const [security] = pillars(r);
    expect(security.passing).toBe(1);
    expect(security.failing).toBe(1);
    expect(security.unknown).toBe(1);
  });

  it('takes the WORST grade in a pillar, matching the headline rule', () => {
    const r = rep({
      categories: [
        cat({ key: 'headers', grade: 'A' }),
        cat({ key: 'paths', grade: 'F' }),
        cat({ key: 'email', grade: 'B' }),
      ],
    });
    expect(pillars(r)[0].grade).toBe('F');
  });

  it('drops pillars that ran nothing rather than showing an empty shell', () => {
    const names = pillars(rep()).map((p) => p.group);
    expect(names).toEqual(['security']);
    expect(names.length).toBeLessThan(PILLAR_ORDER.length);
  });

  it('reports a null grade when a pillar ran but every category errored', () => {
    const r = rep({ categories: [cat({ grade: null })] });
    expect(pillars(r)[0].grade).toBeNull();
  });
});

describe('ranked', () => {
  it('orders by severity, worst first, and numbers from 1', () => {
    const r = rep({
      categories: [
        cat({
          checks: [
            chk({ label: 'low one', pass: false, severity: 'low' }),
            chk({ label: 'critical one', pass: false, severity: 'critical' }),
            chk({ label: 'medium one', pass: false, severity: 'medium' }),
          ],
        }),
      ],
    });
    const q = ranked(r);
    expect(q.map((f) => f.check.label)).toEqual(['critical one', 'medium one', 'low one']);
    expect(q.map((f) => f.rank)).toEqual([1, 2, 3]);
  });

  it('puts security ahead of another pillar at equal severity', () => {
    const r = rep({
      categories: [
        cat({ key: 'fundamentals', group: 'basics', checks: [chk({ label: 'basics one', pass: false, severity: 'high' })] }),
        cat({ key: 'paths', group: 'security', checks: [chk({ label: 'security one', pass: false, severity: 'high' })] }),
      ],
    });
    expect(ranked(r)[0].check.label).toBe('security one');
  });

  it('never lists an unknown as something to fix', () => {
    const r = rep({
      categories: [cat({ checks: [chk({ pass: false, graded: false, severity: 'critical' })] })],
    });
    expect(ranked(r)).toHaveLength(0);
  });

  it('treats a failing check with no severity as medium rather than dropping it', () => {
    const r = rep({ categories: [cat({ checks: [chk({ pass: false })] })] });
    expect(ranked(r)[0].severity).toBe('medium');
  });

  it('carries a plain-English action for every finding', () => {
    const r = rep({ categories: [cat({ checks: [chk({ pass: false, severity: 'critical' })] })] });
    expect(ranked(r)[0].action).toMatch(/before anyone else/);
  });
});

describe('unknowns', () => {
  it('collects only the shown-but-not-graded checks', () => {
    const r = rep({
      categories: [
        cat({
          checks: [chk({ pass: true }), chk({ pass: false, severity: 'high' }), chk({ label: 'timed out', pass: false, graded: false })],
        }),
      ],
    });
    const u = unknowns(r);
    expect(u).toHaveLength(1);
    expect(u[0].check.label).toBe('timed out');
  });
});

describe('verdict', () => {
  it('states counts and names the weakest pillar to start from', () => {
    const r = rep({
      passed: 62,
      issueCount: 3,
      categories: [
        cat({ key: 'headers', group: 'security', grade: 'D', checks: [chk({ pass: false, severity: 'high' })] }),
        cat({ key: 'fundamentals', group: 'basics', grade: 'A', checks: [chk()] }),
      ],
    });
    const v = verdict(r);
    expect(v.counts).toContain('62 checks passed');
    expect(v.counts).toContain('3 to fix');
    expect(v.weakest).toBe('Security');
    expect(v.strongest).toBe('Fundamentals');
  });

  it('mentions undetermined checks only when there are some', () => {
    const clean = verdict(rep());
    expect(clean.counts).not.toContain('could not determine');

    const withUnknown = verdict(rep({ categories: [cat({ checks: [chk({ pass: false, graded: false })] })] }));
    expect(withUnknown.counts).toContain('1 we could not determine');
  });

  it('refuses to name a strongest and weakest when every pillar graded the same', () => {
    const r = rep({
      categories: [
        cat({ key: 'headers', group: 'security', grade: 'A' }),
        cat({ key: 'fundamentals', group: 'basics', grade: 'A' }),
      ],
    });
    const v = verdict(r);
    expect(v.strongest).toBeNull();
    expect(v.weakest).toBeNull();
  });

  it('says "1 check passed", not "1 checks passed"', () => {
    expect(verdict(rep({ passed: 1 })).counts).toContain('1 check passed');
  });
});

describe('cleared', () => {
  it('gives a plain line for a category that came back fully clean', () => {
    const lines = cleared(rep({ categories: [cat({ key: 'paths', grade: 'A', checks: [chk(), chk()] })] }));
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/\.env/);
  });

  it('stays silent about a category that has any failing check', () => {
    const r = rep({ categories: [cat({ key: 'paths', grade: 'A', checks: [chk(), chk({ pass: false })] })] });
    expect(cleared(r)).toHaveLength(0);
  });

  it('does not claim anything for a category that never ran', () => {
    expect(cleared(rep({ categories: [cat({ key: 'paths', grade: 'A', checks: [] })] }))).toHaveLength(0);
  });
});
