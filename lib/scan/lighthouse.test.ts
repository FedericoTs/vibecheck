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

describe('parseCwv (Core Web Vitals field data)', () => {
  it('parses LCP/INP/CLS with ratings and human formatting', () => {
    const r = parsePsi({
      loadingExperience: {
        overall_category: 'AVERAGE',
        metrics: {
          LARGEST_CONTENTFUL_PAINT_MS: { percentile: 2500, category: 'AVERAGE' },
          INTERACTION_TO_NEXT_PAINT: { percentile: 180, category: 'GOOD' },
          CUMULATIVE_LAYOUT_SHIFT_SCORE: { percentile: 5, category: 'GOOD' },
        },
      },
    });
    expect(r.cwv?.overall).toBe('needs-improvement');
    expect(r.cwv?.origin).toBe(false);
    expect(r.cwv?.metrics).toEqual([
      { label: 'LCP', display: '2.5 s', rating: 'needs-improvement' },
      { label: 'INP', display: '180 ms', rating: 'good' },
      { label: 'CLS', display: '0.05', rating: 'good' },
    ]);
  });

  it('falls back to FID and to origin-level data', () => {
    const r = parsePsi({
      originLoadingExperience: {
        overall_category: 'SLOW',
        metrics: {
          LARGEST_CONTENTFUL_PAINT_MS: { percentile: 4200, category: 'SLOW' },
          FIRST_INPUT_DELAY_MS: { percentile: 20, category: 'GOOD' },
        },
      },
    });
    expect(r.cwv?.origin).toBe(true);
    expect(r.cwv?.metrics.map((m) => m.label)).toEqual(['LCP', 'FID']);
    expect(r.cwv?.metrics[0].rating).toBe('poor');
  });

  it('no field data -> cwv is null (never invents lab numbers)', () => {
    expect(parsePsi({}).cwv).toBe(null);
    expect(parsePsi({ loadingExperience: { metrics: {} } }).cwv).toBe(null);
  });
});
