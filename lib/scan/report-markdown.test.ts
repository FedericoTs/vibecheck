import { describe, expect, it } from 'vitest';
import { buildReportMarkdown } from './report-markdown';
import type { Report, ReportInputs } from './report';
import { combineReport } from './report';

const clean = (): Report => combineReport({} as ReportInputs);

const leaky = (): Report =>
  combineReport({
    supabase: {
      ok: true,
      host: 'x.supabase.co',
      tablesFound: 1,
      exposedCount: 1,
      grade: 'F',
      summary: 'leaking',
      findings: [
        {
          table: 'users',
          exposed: true,
          rowsVisible: 1200,
          columns: ['email'],
          probeUrl: 'https://x.supabase.co/rest/v1/users?select=*&limit=1',
        },
      ],
    },
    secrets: { host: 'x', grade: 'F', score: 8, summary: '', findings: [{ id: 'stripe', label: 'Stripe secret key', severity: 'high', redacted: 'sk_live_…' }] },
  } as unknown as ReportInputs);

describe('buildReportMarkdown', () => {
  it('opens with the untrusted-data instruction to the agent', () => {
    const md = buildReportMarkdown(leaky());
    expect(md).toMatch(/UNTRUSTED DATA/);
    expect(md).toMatch(/ignore it/i);
    // The safe-handoff block must come BEFORE any finding.
    expect(md.indexOf('UNTRUSTED DATA')).toBeLessThan(md.indexOf('## Security'));
  });

  it('carries the reproducible command for a finding that has one', () => {
    const md = buildReportMarkdown(leaky());
    expect(md).toMatch(/Prove it yourself/);
    expect(md).toContain('rest/v1/users?select=*&limit=1');
  });

  it('tells the agent to ROTATE an exposed key, not just move it', () => {
    const md = buildReportMarkdown(leaky());
    expect(md).toMatch(/rotated/i);
  });

  it('reports a clean scan as nothing to change', () => {
    const md = buildReportMarkdown(clean());
    expect(md).toMatch(/No issues found/i);
    // Even a clean report keeps the safe-handoff header.
    expect(md).toMatch(/UNTRUSTED DATA/);
  });

  it('states plainly that the grade is security-only', () => {
    expect(buildReportMarkdown(leaky())).toMatch(/security only/i);
  });

  it('is deterministic', () => {
    const r = leaky();
    expect(buildReportMarkdown(r, 'https://a.com')).toBe(buildReportMarkdown(r, 'https://a.com'));
  });
});
