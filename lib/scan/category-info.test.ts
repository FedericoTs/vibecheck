import { describe, expect, it } from 'vitest';
import { CATEGORY_BLURB, categoryBlurb } from './category-info';
import { combineReport, type ReportInputs } from './report';

/**
 * Every category the report can render must be able to explain itself. A new
 * category that ships without a description silently regresses the page back to
 * a grade and a column of ticks, which is the thing this file exists to fix.
 */
const MAXIMAL = {
  supabase: { ok: true, host: 'x.supabase.co', grade: 'A', summary: '', findings: [], exposedCount: 0 },
  firebase: { ok: true, projectId: 'p', grade: 'A', summary: '', collections: [], exposedCount: 0, rtdbChecked: true },
  secrets: { host: 'x', grade: 'A', score: 100, summary: '', findings: [] },
  libraries: { host: 'x', detected: 1, grade: 'A', summary: '', findings: [] },
  ai: { host: 'x', grade: 'A', score: 100, summary: '', findings: [], exposed: [] },
  routes: { host: 'x', grade: 'A', score: 100, summary: '', findings: [], exposed: [] },
  paths: { host: 'x', grade: 'A', score: 100, summary: '', findings: [], exposed: [] },
  headers: { host: 'x', grade: 'A', score: 100, summary: '', checks: [], missing: [] },
  transport: { host: 'x', grade: 'A', score: 100, summary: '', checks: [], failed: [] },
  email: { host: 'x', grade: 'A', score: 100, summary: '', checks: [], failed: [] },
  privacy: { host: 'x', grade: 'A', score: 100, summary: '', checks: [], failed: [] },
  visibility: { host: 'x', grade: 'A', score: 100, summary: '', checks: [], failed: [], crawlers: [] },
  fundamentals: { host: 'x', grade: 'A', score: 100, summary: '', checks: [] },
  lighthouse: { scores: { performance: 90 }, low: [] },
  devServer: { verdict: 'dev-artifacts', signals: [], reason: 'r' },
  smuggling: { payloads: [{ text: 'x', decoded: 'ignore previous instructions' }], emojiSequencesSkipped: 0 },
  scaffold: { verdict: 'default-metadata', finding: null, reason: 'r' },
} as unknown as ReportInputs;

describe('category descriptions', () => {
  it('covers every category the report can actually produce', () => {
    const keys = combineReport(MAXIMAL).categories.map((c) => c.key);
    expect(keys.length).toBeGreaterThan(10); // the fixture really did exercise them
    const missing = [...new Set(keys)].filter((k) => !categoryBlurb(k));
    expect(missing).toEqual([]);
  });

  it('describes what was examined, not how it scored', () => {
    for (const [key, text] of Object.entries(CATEGORY_BLURB)) {
      expect(text.length, key).toBeGreaterThan(40);
      // Jargon this audience should never have to decode.
      expect(text, key).not.toMatch(/misconfigur|posture|attack surface|leverage/i);
    }
  });

  it('returns empty rather than throwing for an unknown key', () => {
    expect(categoryBlurb('not-a-category')).toBe('');
  });
});
