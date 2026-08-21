/**
 * The anonymous outcome counter.
 *
 * WHY THIS EXISTS
 * ---------------
 * Nobody can currently answer a basic question about the software the world is
 * now shipping: of the apps built with AI assistance, what fraction expose at
 * least one database table to an anonymous key? The scanner is in a position to
 * measure that — but only if it counts outcomes as they happen. There is no
 * second chance: we promise not to store scans, so the number cannot be
 * recovered later by mining anything. It is counted now or it is never known.
 *
 * WHAT MAKES THAT COMPATIBLE WITH THE PROMISE
 * -------------------------------------------
 * The promise on /legal is that we never see your URL, your keys, or your
 * findings. A counter that records "a database was probed; at least one table
 * was readable" keeps every one of those true: it is a fact ABOUT THE SHAPE OF
 * THE RESULT, carrying nothing that identifies the app it came from.
 *
 * The line is drawn structurally rather than by good intentions:
 *
 *   - every value must be a boolean or a finite number, EXCEPT
 *   - a handful of keys with CLOSED vocabularies (mode, grade), which can only
 *     ever hold one of a few fixed words.
 *
 * A hostname, a table name, a column name, a URL, a key, or a redacted secret
 * is a free-form string, so none of them can satisfy that rule. This is not a
 * convention — `anonymityViolations()` enforces it at the emit site at runtime,
 * and telemetry.test.ts proves the builders satisfy it for adversarial inputs.
 * A future edit that tries to add `{ table: finding.table }` gets dropped in
 * production and fails the suite in CI.
 *
 * WHAT IS DELIBERATELY NOT COUNTED
 * --------------------------------
 * Row counts. "1,247 rows readable" is a plausible fingerprint of a specific
 * app, and the research claim only needs the boolean. Nothing here is worth
 * weakening the promise for.
 */

import { severityCounts, type Report, type ReportInputs } from './report';
import type { RepoScanResult } from './repo';

export const OUTCOME_MODES = ['url', 'backend', 'mobile', 'repo'] as const;
export type OutcomeMode = (typeof OUTCOME_MODES)[number];

export const OUTCOME_GRADES = ['A', 'B', 'C', 'D', 'F', 'unknown'] as const;

/**
 * The ONLY keys allowed to carry a string, and the complete set of words each
 * may hold. Anything not listed here must be a boolean or a number.
 */
export const CLOSED_VOCABULARIES: Record<string, readonly string[]> = {
  mode: OUTCOME_MODES,
  grade: OUTCOME_GRADES,
};

export type OutcomeValue = string | number | boolean;
export type Outcome = Record<string, OutcomeValue>;

/**
 * Keys whose value could identify the scanned app. Returns [] for a clean
 * outcome. Callers drop the offending keys rather than the whole event — a
 * single bad field should not cost us the measurement.
 */
export function anonymityViolations(outcome: Outcome): string[] {
  const bad: string[] = [];
  for (const [key, value] of Object.entries(outcome)) {
    if (typeof value === 'boolean') continue;
    if (typeof value === 'number') {
      // NaN/Infinity survive JSON as null and suggest a broken derivation.
      if (!Number.isFinite(value)) bad.push(key);
      continue;
    }
    if (typeof value !== 'string') {
      bad.push(key);
      continue;
    }
    const vocabulary = CLOSED_VOCABULARIES[key];
    if (!vocabulary || !vocabulary.includes(value)) bad.push(key);
  }
  return bad;
}

/** Strip anything that could identify the app. The last line of defence before `track()`. */
export function sanitizeOutcome(outcome: Outcome): Outcome {
  const bad = new Set(anonymityViolations(outcome));
  if (bad.size === 0) return outcome;
  return Object.fromEntries(Object.entries(outcome).filter(([key]) => !bad.has(key)));
}

/**
 * The outcome of a public-URL scan, as counts and booleans.
 *
 * `dbProbed` is the denominator that makes the headline claim honest: an app
 * whose database we never reached is not evidence of a safe database, and must
 * not be averaged in with the ones we did reach.
 */
export function buildScanOutcome(mode: OutcomeMode, report: Report, inputs?: ReportInputs | null): Outcome {
  const severity = severityCounts(report);
  const supabase = inputs?.supabase ?? null;
  const firebase = inputs?.firebase ?? null;
  const secrets = inputs?.secrets ?? null;

  // A probe happened if either backend actually answered us.
  const supabaseProbed = Boolean(supabase?.ok);
  const firebaseProbed = Boolean(firebase?.ok);

  const outcome: Outcome = {
    mode,
    grade: report.overallGrade,
    issues: report.issueCount,
    passed: report.passed,
    total: report.total,
    critical: severity.critical,
    high: severity.high,
    medium: severity.medium,
    low: severity.low,

    // The research claim. Counts only — never which tables, never how many rows.
    dbProbed: supabaseProbed || firebaseProbed,
    dbExposed: (supabase?.exposedCount ?? 0) > 0 || (firebase?.exposedCount ?? 0) > 0,
    exposedTables: (supabase?.exposedCount ?? 0) + (firebase?.exposedCount ?? 0),
    storagePublic: (supabase?.buckets?.publicBuckets?.length ?? 0) > 0,
    authAutoConfirm: Boolean(supabase?.auth?.autoConfirm),
    rtdbOpen: Boolean(firebase?.rtdbOpen),

    // The newer checks, so we can report how common each pathology actually is.
    secretsExposed: (secrets?.findings ?? []).some((f) => !f.local && !f.commented),
    sourceMapsExposed: (secrets?.sourceMaps?.exposed?.length ?? 0) > 0,
    devArtifacts: inputs?.devServer?.verdict === 'dev-artifacts',
    smuggledText: (inputs?.smuggling?.payloads?.length ?? 0) > 0,
    scaffoldDefault: inputs?.scaffold?.verdict === 'default-metadata',
    vulnerableLibs: (inputs?.libraries?.findings?.length ?? 0) > 0,
  };

  return sanitizeOutcome(outcome);
}

/**
 * The outcome of a repository scan. `graded === false` findings are excluded
 * from the counts for the same reason they are excluded from the grade: we
 * report them, but we have not earned the right to call them problems.
 */
export function buildRepoOutcome(result: RepoScanResult): Outcome {
  const graded = result.findings.filter((f) => f.graded !== false);
  const has = (kind: string): boolean => graded.some((f) => f.kind === kind);

  const outcome: Outcome = {
    mode: 'repo',
    grade: result.grade,
    issues: result.findings.length,
    gradedIssues: graded.length,
    critical: graded.filter((f) => f.severity === 'critical').length,
    high: graded.filter((f) => f.severity === 'high').length,
    filesScanned: result.filesScanned,
    // Coverage, so a thin scan is never mistaken for a clean repo in the aggregate.
    partialScan: (result.unreadableFiles ?? 0) > 0,
    authenticated: Boolean(result.rateLimit?.authenticated),

    secretCommitted: has('secret'),
    crossTenant: has('cross-tenant'),
    vulnerableDeps: has('dependency'),
    dockerfileIssue: has('dockerfile'),
  };

  return sanitizeOutcome(outcome);
}
