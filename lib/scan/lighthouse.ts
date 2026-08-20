import type { Grade } from './types';
import { scoreToGrade } from './grade';

/**
 * Performance & quality via Google PageSpeed Insights (real Lighthouse scores).
 * We don't compute these ourselves — Google runs Lighthouse against the URL and
 * we parse the category scores. Reliable, and it renders in the SECONDARY
 * section so it never touches the security headline grade.
 *
 * The same PSI response also carries Chrome UX Report FIELD data (real users,
 * trailing 28 days) — Core Web Vitals — so we surface those too, for free, with
 * no extra call. Field data only exists for sites with enough real traffic; when
 * it's absent we say so rather than inventing lab numbers.
 */

export interface LighthouseScores {
  performance: number | null;
  accessibility: number | null;
  bestPractices: number | null;
  seo: number | null;
}

export type CwvRating = 'good' | 'needs-improvement' | 'poor';
export interface CwvMetric {
  label: string; // 'LCP' | 'INP' | 'FID' | 'CLS'
  display: string; // '2.5 s' | '180 ms' | '0.05'
  rating: CwvRating;
}
export interface CoreWebVitals {
  overall: CwvRating | null;
  metrics: CwvMetric[];
  origin: boolean; // true = origin-level fallback (no page-level field data)
}

export interface LighthouseResult {
  host: string;
  scores: LighthouseScores;
  cwv: CoreWebVitals | null;
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

function ratingOf(category: unknown): CwvRating | null {
  if (category === 'FAST' || category === 'GOOD') return 'good';
  if (category === 'AVERAGE' || category === 'NEEDS_IMPROVEMENT') return 'needs-improvement';
  if (category === 'SLOW' || category === 'POOR') return 'poor';
  return null;
}

type Metrics = Record<string, { percentile?: number; category?: string } | undefined>;
function metric(label: string, raw: Metrics[string], fmt: (p: number) => string): CwvMetric | null {
  const rating = ratingOf(raw?.category);
  if (!raw || typeof raw.percentile !== 'number' || !rating) return null;
  return { label, display: fmt(raw.percentile), rating };
}

/** Pull Core Web Vitals from the PSI field data (page-level, else origin-level). */
export function parseCwv(json: unknown): CoreWebVitals | null {
  const j = json as { loadingExperience?: { metrics?: Metrics; overall_category?: string }; originLoadingExperience?: { metrics?: Metrics; overall_category?: string } };
  const page = j?.loadingExperience;
  const hasPage = !!page?.metrics && Object.keys(page.metrics).length > 0;
  const src = hasPage ? page : j?.originLoadingExperience;
  const m = src?.metrics;
  if (!m) return null;
  const metrics = [
    metric('LCP', m.LARGEST_CONTENTFUL_PAINT_MS, (p) => `${(p / 1000).toFixed(1)} s`),
    metric('INP', m.INTERACTION_TO_NEXT_PAINT, (p) => `${p} ms`) ?? metric('FID', m.FIRST_INPUT_DELAY_MS, (p) => `${p} ms`),
    metric('CLS', m.CUMULATIVE_LAYOUT_SHIFT_SCORE, (p) => (p / 100).toFixed(2)),
  ].filter((x): x is CwvMetric => x != null);
  if (metrics.length === 0) return null;
  return { overall: ratingOf(src?.overall_category), metrics, origin: !hasPage };
}

/** Parse a PageSpeed Insights v5 response into category scores (0-100) + field CWV. */
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
    cwv: parseCwv(json),
    grade,
    summary: present.length ? present.map((x) => `${x.label} ${x.score}`).join(' · ') : 'No Lighthouse data',
    low,
  };
}
