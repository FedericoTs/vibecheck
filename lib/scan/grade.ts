import type { Grade, GradeResult } from './types';

/**
 * Grade the Supabase public-read result. A publicly-readable table with data is
 * a real breach, so the scale is deliberately harsh: any exposure fails.
 */
export function gradeExposure(exposedCount: number, tablesFound: number): GradeResult {
  if (tablesFound === 0) {
    return { grade: 'C', score: 60, label: 'No tables were reachable to test' };
  }
  if (exposedCount === 0) {
    return { grade: 'A', score: 100, label: 'No tables are readable by anonymous visitors' };
  }
  if (exposedCount === 1) {
    return { grade: 'D', score: 45, label: '1 table is readable by anyone' };
  }
  if (exposedCount <= 3) {
    return { grade: 'F', score: 25, label: `${exposedCount} tables are readable by anyone` };
  }
  return { grade: 'F', score: 10, label: `${exposedCount} tables are readable by anyone` };
}

/** Map a 0-100 score to a letter grade. */
export function scoreToGrade(score: number): Grade {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

const ORDER: Grade[] = ['A', 'B', 'C', 'D', 'F'];

/** Worst (lowest) grade across categories — an overall report card is only as good as its weakest scan. */
/**
 * ⚠️ An empty list means NOTHING WAS MEASURED, not 'average'. It returns 'C'.
 * Accepted pre-launch because every path that reaches here also renders the
 * partial-scan banner and the provisional grade label. Trigger to fix: any
 * report observed in the wild with total === 0.
 */
export function worstGrade(grades: Grade[]): Grade {
  if (grades.length === 0) return 'C';
  return grades.reduce((worst, g) => (ORDER.indexOf(g) > ORDER.indexOf(worst) ? g : worst), 'A' as Grade);
}
