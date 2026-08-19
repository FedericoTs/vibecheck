import type { Grade } from './types';
import { scoreToGrade } from './grade';

/**
 * Performance & quality via Google PageSpeed Insights (real Lighthouse scores).
 * We don't compute these ourselves — Google runs Lighthouse against the URL and
 * we parse the category scores. Reliable, and it renders in the SECONDARY
 * section so it never touches the security headline grade.
 */

export interface LighthouseScores {
  performance: number | null;
  accessibility: number | null;
  bestPractices: number | null;
  seo: number | null;
}

export interface LighthouseResult {
  host: string;
  scores: LighthouseScores;
  grade: Grade;
  summary: string;
  low: { label: string; score: number }[]; // categories below 90, worth improving
}

const LABELS: Array<[keyof LighthouseScores, string]> = [
  ['performance', 'Performance'],
  ['accessibility', 'Accessibility'],
  ['bestPractices', 'Best practices'],
  ['seo', 'SEO'],
];

/** Parse a PageSpeed Insights v5 response into category scores (0-100). */
export function parsePsi(json: unknown, host = ''): LighthouseResult {
  const cats = (json as { lighthouseResult?: { categories?: Record<string, { score?: number }> } })?.lighthouseResult
    ?.categories;
  const to100 = (v: number | undefined | null) => (typeof v === 'number' ? Math.round(v * 100) : null);
  const scores: LighthouseScores = {
    performance: to100(cats?.performance?.score),
    accessibility: to100(cats?.accessibility?.score),
    bestPractices: to100(cats?.['best-practices']?.score),
    seo: to100(cats?.seo?.score),
  };

  const present = LABELS.map(([k, label]) => ({ label, score: scores[k] })).filter(
    (x): x is { label: string; score: number } => x.score != null,
  );
  const grade: Grade = present.length ? scoreToGrade(Math.min(...present.map((x) => x.score))) : 'C';
  const low = present.filter((x) => x.score < 90);

  return {
    host,
    scores,
    grade,
    summary: present.length ? present.map((x) => `${x.label} ${x.score}`).join(' · ') : 'No Lighthouse data',
    low,
  };
}
