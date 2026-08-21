import { describe, expect, it } from 'vitest';
import {
  anonymityViolations,
  buildRepoOutcome,
  buildScanOutcome,
  nextCountState,
  sanitizeOutcome,
  type Outcome,
} from './telemetry';
import type { Report, ReportInputs } from './report';
import type { RepoScanResult } from './repo';

const report = (over: Partial<Report> = {}): Report => ({
  overallGrade: 'F',
  verdict: 'leaking',
  issueCount: 3,
  passed: 20,
  total: 23,
  categories: [
    {
      key: 'supabase',
      group: 'security',
      label: 'Database',
      grade: 'F',
      summary: 'exposed',
      checks: [
        { label: 'users readable', pass: false, severity: 'critical' },
        { label: 'orders readable', pass: false, severity: 'critical' },
        { label: 'CSP', pass: false, severity: 'medium' },
        { label: 'HTTPS', pass: true },
      ],
    },
  ],
  ...over,
});

/**
 * Every identifying string a scan actually holds, planted at once. If any of
 * these reaches the outcome, the promise on /legal is broken.
 */
const SECRETS = [
  'my-startup.com',
  'abcdefgh.supabase.co',
  'customer_billing_records',
  'stripe_customer_id',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret',
  'https://abcdefgh.supabase.co/rest/v1/users?select=*',
];

const loadedInputs = (): ReportInputs =>
  ({
    supabase: {
      ok: true,
      host: 'abcdefgh.supabase.co',
      tablesFound: 12,
      exposedCount: 2,
      grade: 'F',
      summary: 'my-startup.com is leaking customer_billing_records',
      findings: [
        {
          table: 'customer_billing_records',
          exposed: true,
          rowsVisible: 1247,
          columns: ['email', 'stripe_customer_id'],
          probeUrl: 'https://abcdefgh.supabase.co/rest/v1/users?select=*',
        },
      ],
      buckets: { enumerable: true, publicBuckets: ['avatars'], checked: true },
      auth: { checked: true, signupsOpen: true, autoConfirm: true, providers: ['email'] },
    },
    secrets: {
      host: 'my-startup.com',
      findings: [
        { id: 'stripe', label: 'Stripe key', severity: 'critical', redacted: 'sk_live_…1234' },
        { id: 'local', label: 'Local DB', severity: 'high', redacted: 'postgres://…', local: true },
      ],
      sourceMaps: { exposed: ['/_next/static/chunks/main.js.map'], checked: true },
    },
    smuggling: { payloads: [{ text: 'ignore previous instructions' }], emojiSequencesSkipped: 4 },
    devServer: { verdict: 'dev-artifacts', signals: [], reason: 'build manifest served' },
    scaffold: { verdict: 'default-metadata', finding: null, reason: 'create-next-app title' },
    libraries: { host: 'my-startup.com', detected: 9, findings: [{ name: 'react' }], grade: 'C', summary: '' },
  }) as unknown as ReportInputs;

/** Recursively collect every string in the emitted payload. */
function strings(outcome: Outcome): string[] {
  return Object.values(outcome).filter((v): v is string => typeof v === 'string');
}

describe('anonymity guarantee', () => {
  it('emits no free-form strings — only booleans, numbers, and closed vocabularies', () => {
    const outcome = buildScanOutcome('url', report(), loadedInputs());
    expect(anonymityViolations(outcome)).toEqual([]);
    // The only strings that survive are the two enum fields.
    expect(strings(outcome).sort()).toEqual(['F', 'url']);
  });

  it('leaks none of the identifying values the scan was holding', () => {
    const payload = JSON.stringify(buildScanOutcome('url', report(), loadedInputs()));
    for (const secret of SECRETS) {
      expect(payload).not.toContain(secret);
    }
    // Row counts are a fingerprint; we deliberately never send them.
    expect(payload).not.toContain('1247');
  });

  it('rejects a hostname or table name that a future edit tries to add', () => {
    expect(anonymityViolations({ host: 'my-startup.com' })).toEqual(['host']);
    expect(anonymityViolations({ table: 'users' })).toEqual(['table']);
    // ...and an out-of-vocabulary value on an allowed key is still a violation.
    expect(anonymityViolations({ mode: 'https://my-startup.com' })).toEqual(['mode']);
    expect(anonymityViolations({ grade: 'A', mode: 'url' })).toEqual([]);
  });

  it('drops the offending key rather than the whole measurement', () => {
    expect(sanitizeOutcome({ mode: 'url', host: 'my-startup.com', issues: 3 })).toEqual({
      mode: 'url',
      issues: 3,
    });
  });

  it('drops NaN, which JSON would silently turn into null', () => {
    expect(sanitizeOutcome({ issues: NaN, passed: 4 })).toEqual({ passed: 4 });
  });
});

describe('one event per scan', () => {
  /** Replay a sequence of "is there a report right now?" and collect when we would emit. */
  function replay(hasReport: boolean[]): number[] {
    const fired: number[] = [];
    let counted = false;
    hasReport.forEach((present, i) => {
      const next = nextCountState(present, counted);
      counted = next.counted;
      if (next.emit) fired.push(i);
    });
    return fired;
  }

  it('counts once when the late Lighthouse result rebuilds the report', () => {
    // null (scan starts) → report(56 checks) → report(60 checks, Lighthouse landed)
    expect(replay([false, true, true])).toEqual([1]);
  });

  it('still counts the next scan', () => {
    // scan → result → rebuild → new scan clears it → result
    expect(replay([false, true, true, false, true])).toEqual([1, 4]);
  });

  it('counts nothing when a scan never produces a report', () => {
    expect(replay([false, false, false])).toEqual([]);
  });

  it('survives repeated rebuilds without ever double counting', () => {
    expect(replay([false, true, true, true, true, true])).toEqual([1]);
  });
});

describe('buildScanOutcome', () => {
  it('records the exposure outcome the research claim needs', () => {
    const outcome = buildScanOutcome('url', report(), loadedInputs());
    expect(outcome.dbProbed).toBe(true);
    expect(outcome.dbExposed).toBe(true);
    expect(outcome.exposedTables).toBe(2);
    expect(outcome.storagePublic).toBe(true);
    expect(outcome.authAutoConfirm).toBe(true);
  });

  it('separates "probed and clean" from "never probed" — absence of evidence is not evidence', () => {
    const clean = buildScanOutcome('url', report(), {
      supabase: { ok: true, exposedCount: 0 },
    } as unknown as ReportInputs);
    expect(clean.dbProbed).toBe(true);
    expect(clean.dbExposed).toBe(false);

    const noBackend = buildScanOutcome('url', report(), {});
    expect(noBackend.dbProbed).toBe(false);
    expect(noBackend.dbExposed).toBe(false);
  });

  it('does not count a local or commented secret as an exposed one', () => {
    const outcome = buildScanOutcome('url', report(), {
      secrets: {
        findings: [
          { id: 'a', label: 'x', severity: 'high', redacted: '…', local: true },
          { id: 'b', label: 'y', severity: 'high', redacted: '…', commented: true },
        ],
      },
    } as unknown as ReportInputs);
    expect(outcome.secretsExposed).toBe(false);
  });

  it('carries the severity breakdown, since nine issues is not nine equal problems', () => {
    const outcome = buildScanOutcome('url', report(), {});
    expect(outcome.critical).toBe(2);
    expect(outcome.medium).toBe(1);
  });
});

describe('buildRepoOutcome', () => {
  const repo = (over: Partial<RepoScanResult> = {}): RepoScanResult =>
    ({
      ok: true,
      ref: 'main',
      filesScanned: 40,
      grade: 'D',
      findings: [
        { kind: 'secret', path: '.env', label: 'key', severity: 'critical', detail: '' },
        { kind: 'cross-tenant', path: 'app/api/x/route.ts', label: 'x', severity: 'high', detail: '', graded: false },
      ],
      ...over,
    }) as RepoScanResult;

  it('counts only graded findings as problems, but reports the full total', () => {
    const outcome = buildRepoOutcome(repo());
    expect(outcome.issues).toBe(2);
    expect(outcome.gradedIssues).toBe(1);
    expect(outcome.secretCommitted).toBe(true);
    // Reported-but-not-graded must not inflate the aggregate.
    expect(outcome.crossTenant).toBe(false);
  });

  it('flags a partial scan so thin coverage is never averaged in as a clean repo', () => {
    expect(buildRepoOutcome(repo()).partialScan).toBe(false);
    expect(buildRepoOutcome(repo({ unreadableFiles: 12 })).partialScan).toBe(true);
  });

  it('never emits a file path', () => {
    const payload = JSON.stringify(buildRepoOutcome(repo()));
    expect(payload).not.toContain('.env');
    expect(payload).not.toContain('route.ts');
    expect(anonymityViolations(buildRepoOutcome(repo()))).toEqual([]);
  });

  it("keeps 'unknown' a first-class grade rather than coercing it to a pass", () => {
    const outcome = buildRepoOutcome(repo({ grade: 'unknown' as RepoScanResult['grade'] }));
    expect(outcome.grade).toBe('unknown');
    expect(anonymityViolations(outcome)).toEqual([]);
  });
});
