import { describe, it, expect } from 'vitest';
import { parsePsi } from './lighthouse';

const psi = (scores: Record<string, number>) => ({
  lighthouseResult: {
    categories: Object.fromEntries(Object.entries(scores).map(([k, v]) => [k, { score: v }])),
  },
});

describe('parsePsi', () => {
  it('extracts 0-100 scores, grades by the worst, lists the sub-90 ones', () => {
    const r = parsePsi(psi({ performance: 0.45, accessibility: 0.92, 'best-practices': 1, seo: 0.88 }), 'my.app');
    expect(r.scores).toEqual({ performance: 45, accessibility: 92, bestPractices: 100, seo: 88 });
    expect(r.grade).toBe('D'); // worst = 45
    expect(r.low.map((x) => x.label)).toEqual(['Performance', 'SEO']); // 45 and 88 are < 90
    expect(r.summary).toMatch(/Performance 45/);
  });

  it('all green -> A, nothing low', () => {
    const r = parsePsi(psi({ performance: 0.98, accessibility: 1, 'best-practices': 0.95, seo: 1 }));
    expect(r.grade).toBe('A');
    expect(r.low).toHaveLength(0);
  });

  it('missing / malformed response -> no data, grade C, never throws', () => {
    expect(parsePsi({}).summary).toMatch(/No Lighthouse data/);
    expect(parsePsi(null).grade).toBe('C');
    expect(parsePsi({ lighthouseResult: { categories: {} } }).scores.performance).toBe(null);
  });
});
