import { describe, it, expect } from 'vitest';
import { fixFor, failingChecks, buildFixPrompt } from './fixes';
import type { Report, ReportCategory } from './report';

const cat = (over: Partial<ReportCategory>): ReportCategory => ({
  key: 'headers',
  group: 'security',
  label: 'Security headers',
  grade: 'F',
  summary: '',
  checks: [],
  ...over,
});

const report = (categories: ReportCategory[]): Report => ({
  overallGrade: 'F',
  verdict: 'Wide open.',
  issueCount: categories.flatMap((c) => c.checks).filter((c) => !c.pass).length,
  passed: categories.flatMap((c) => c.checks).filter((c) => c.pass).length,
  total: categories.flatMap((c) => c.checks).length,
  categories,
});

describe('fixFor', () => {
  it('prefers specific label guidance over the category default', () => {
    expect(fixFor('headers', { label: 'Content-Security-Policy', pass: false })).toMatch(/default-src/);
    expect(fixFor('headers', { label: 'Some other header', pass: false })).toMatch(/next.config.js/);
  });

  it('gives real, actionable SQL for a database exposure', () => {
    const f = fixFor('supabase', { label: 'users', pass: false });
    expect(f).toMatch(/row level security/i);
    expect(f).toMatch(/create policy/i);
    expect(f).toMatch(/insert\/update\/delete/i); // the per-command trap
  });

  it('tells the user to rotate, not just relocate, an exposed key', () => {
    expect(fixFor('secrets', { label: 'Stripe secret key', pass: false })).toMatch(/rotate|revoke/i);
    expect(fixFor('secrets', { label: 'Stripe secret key', pass: false })).toMatch(/NEXT_PUBLIC_/);
  });

  it('falls back to something sane for an unknown category', () => {
    expect(fixFor('mystery', { label: 'unknown thing', pass: false })).toMatch(/remediate/i);
  });
});

describe('failingChecks', () => {
  it('collects only failures, and only from security categories', () => {
    const r = report([
      cat({ checks: [{ label: 'Content-Security-Policy', pass: false }, { label: 'X-Content-Type-Options', pass: true }] }),
      cat({ key: 'fundamentals', group: 'basics', label: 'Fundamentals', checks: [{ label: 'Page title', pass: false }] }),
    ]);
    const f = failingChecks(r);
    expect(f).toHaveLength(1);
    expect(f[0].check.label).toBe('Content-Security-Policy');
  });
});

describe('buildFixPrompt', () => {
  it('produces a numbered, pasteable prompt with what was seen and how to fix it', () => {
    const r = report([
      cat({
        key: 'supabase',
        label: 'Database exposure',
        checks: [{ label: 'users', pass: false, detail: '1,200 rows readable by anyone' }],
      }),
    ]);
    const p = buildFixPrompt(r, 'https://myapp.com');
    expect(p).toMatch(/found 1 issue/);
    expect(p).toMatch(/https:\/\/myapp\.com/);
    expect(p).toMatch(/1\. \[Database exposure\] users/);
    expect(p).toMatch(/What the scan saw: 1,200 rows/);
    expect(p).toMatch(/How to fix: .*row level security/i);
    expect(p).toMatch(/has to hold on the server/);
  });

  it('adds the rotation warning ONLY when a key was actually exposed', () => {
    const withKey = report([cat({ key: 'secrets', label: 'Exposed secrets', checks: [{ label: 'AWS access key id', pass: false }] })]);
    expect(buildFixPrompt(withKey)).toMatch(/must be ROTATED/);

    const noKey = report([cat({ checks: [{ label: 'Referrer-Policy', pass: false }] })]);
    expect(buildFixPrompt(noKey)).not.toMatch(/must be ROTATED/);
  });

  it('says nothing to do when the scan is clean', () => {
    expect(buildFixPrompt(report([cat({ checks: [{ label: 'CSP', pass: true }] })]))).toMatch(/came back clean/);
  });

  it('numbers multiple issues across categories', () => {
    const r = report([
      cat({ key: 'secrets', label: 'Exposed secrets', checks: [{ label: 'Stripe secret key', pass: false }] }),
      cat({ checks: [{ label: 'Content-Security-Policy', pass: false }] }),
    ]);
    const p = buildFixPrompt(r);
    expect(p).toMatch(/found 2 issues/);
    expect(p).toMatch(/1\. \[Exposed secrets\]/);
    expect(p).toMatch(/2\. \[Security headers\]/);
  });
});
