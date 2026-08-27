import { describe, it, expect } from 'vitest';
import { buildSaved, newSlug, sanitize, blobToken, SAVED_VERSION, RETENTION_DAYS } from './report-store';
import type { Report } from './scan/report';

const report = (over: Partial<Report> = {}): Report => ({
  overallGrade: 'D',
  verdict: 'Leaky.',
  issueCount: 2,
  passed: 40,
  total: 50,
  categories: [
    {
      key: 'secrets',
      group: 'security',
      label: 'Exposed secrets',
      grade: 'F',
      score: 8,
      summary: '1 key',
      checks: [
        { label: 'Stripe secret key', pass: false, severity: 'critical', detail: 'sk_live…AAAA' },
        { label: 'No AWS key', pass: true },
      ],
    },
  ],
  ...over,
});

describe('newSlug', () => {
  it('is long enough that guessing is not a threat model', () => {
    const slug = newSlug(() => new Uint8Array(32).fill(7));
    expect(slug.length).toBe(32);
  });

  it('avoids characters that are misread when spoken or pasted', () => {
    const slug = newSlug(() => Uint8Array.from(Array.from({ length: 32 }, (_, i) => i)));
    expect(slug).not.toMatch(/[l01]/);
    expect(slug).toMatch(/^[a-z2-9]+$/);
  });

  it('varies with the random source', () => {
    const a = newSlug(() => new Uint8Array(32).fill(1));
    const b = newSlug(() => new Uint8Array(32).fill(2));
    expect(a).not.toBe(b);
  });
});

describe('sanitize', () => {
  it('keeps the findings and their proof commands', () => {
    const cats = sanitize(
      report({
        categories: [
          {
            key: 'paths',
            group: 'security',
            label: 'Exposed files',
            grade: 'F',
            summary: 'x',
            checks: [
              {
                label: '.env',
                pass: false,
                severity: 'critical',
                evidence: { label: 'proves it', command: "curl -s 'https://x.com/.env'" },
              },
            ],
          },
        ],
      }),
    );
    expect(cats[0].checks[0].evidence?.command).toContain('curl');
  });

  /**
   * The point of the sanitiser: whatever a future caller passes, only the known
   * fields are written. A refactor that starts posting raw scan inputs should
   * lose them here rather than quietly persist someone's project URL or key.
   */
  it('drops any field it does not explicitly know about', () => {
    const dirty = report();
    // Simulate a caller that attached extra state to the report it posted.
    (dirty.categories[0] as unknown as Record<string, unknown>).anonKey = 'eyJhbGciOi.SECRET';
    (dirty.categories[0].checks[0] as unknown as Record<string, unknown>).probeUrl =
      'https://abc.supabase.co/rest/v1/users';

    const clean = sanitize(dirty);
    const serialised = JSON.stringify(clean);
    expect(serialised).not.toContain('anonKey');
    expect(serialised).not.toContain('SECRET');
    expect(serialised).not.toContain('probeUrl');
    expect(serialised).not.toContain('supabase.co');
  });
});

describe('buildSaved', () => {
  const now = new Date('2026-08-27T10:00:00.000Z');

  it('records what was scanned and when', () => {
    const saved = buildSaved({ slug: 'abc', host: 'my.app', report: report(), skipped: [], now });
    expect(saved.v).toBe(SAVED_VERSION);
    expect(saved.host).toBe('my.app');
    expect(saved.grade).toBe('D');
    expect(saved.passed).toBe(40);
    expect(saved.savedAt).toBe('2026-08-27T10:00:00.000Z');
  });

  it('expires so a stale report cannot describe an app that has moved on', () => {
    const saved = buildSaved({ slug: 'abc', host: 'my.app', report: report(), skipped: [], now });
    const days = (new Date(saved.expiresAt).getTime() - now.getTime()) / 86_400_000;
    expect(days).toBe(RETENTION_DAYS);
  });

  it('carries the skipped list, so a partial scan cannot read as a clean one', () => {
    const saved = buildSaved({ slug: 'abc', host: 'my.app', report: report(), skipped: ['headers', 'paths'], now });
    expect(saved.skipped).toEqual(['headers', 'paths']);
  });
});

/**
 * Connecting a Blob store lets you set an env-var PREFIX, so the token is not
 * always called BLOB_READ_WRITE_TOKEN. Hardcoding the default name made a
 * correctly-configured store read as "saving is off" with nothing to say why.
 */
describe('blobToken', () => {
  it('prefers the default name', () => {
    expect(blobToken({ BLOB_READ_WRITE_TOKEN: 'a', OTHER_READ_WRITE_TOKEN: 'b' } as unknown as NodeJS.ProcessEnv)).toBe('a');
  });

  it('accepts a prefixed token when the default is absent', () => {
    expect(blobToken({ VIBECHECK_READ_WRITE_TOKEN: 'b' } as unknown as NodeJS.ProcessEnv)).toBe('b');
  });

  it('ignores empty values rather than treating them as configured', () => {
    expect(blobToken({ BLOB_READ_WRITE_TOKEN: '' } as unknown as NodeJS.ProcessEnv)).toBeUndefined();
  });

  it('is undefined when nothing is set, so saving stays off', () => {
    expect(blobToken({} as unknown as NodeJS.ProcessEnv)).toBeUndefined();
  });
});

/**
 * A token pasted with the quotes from a KEY="value" snippet still looks set and
 * passes every "is it configured" check, then fails at the API with an opaque
 * error. Cheaper to strip it than to make someone debug invisible quotes.
 */
describe('token cleaning', () => {
  const t = (v: string) => blobToken({ BLOB_READ_WRITE_TOKEN: v } as unknown as NodeJS.ProcessEnv);

  it('strips wrapping double quotes', () => {
    expect(t('"vercel_blob_rw_abc"')).toBe('vercel_blob_rw_abc');
  });

  it('strips wrapping single quotes', () => {
    expect(t("'vercel_blob_rw_abc'")).toBe('vercel_blob_rw_abc');
  });

  it('strips stray whitespace and newlines', () => {
    expect(t('  vercel_blob_rw_abc\n')).toBe('vercel_blob_rw_abc');
  });

  it('leaves a clean token untouched', () => {
    expect(t('vercel_blob_rw_abc')).toBe('vercel_blob_rw_abc');
  });

  it('does not strip an unmatched leading quote, which is not a wrapper', () => {
    expect(t('"vercel_blob_rw_abc')).toBe('"vercel_blob_rw_abc');
  });
});
