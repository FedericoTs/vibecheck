import { describe, it, expect } from 'vitest';
import { gradeHeaders, lowerHeaders } from './headers';

const FULL = {
  'Content-Security-Policy': "default-src 'self'",
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
};

describe('gradeHeaders', () => {
  it('lowerHeaders normalises keys', () => {
    expect(lowerHeaders({ 'X-Foo': 'bar' })).toEqual({ 'x-foo': 'bar' });
  });

  it('a fully-hardened response grades A with nothing missing', () => {
    const r = gradeHeaders(FULL, 'safe.app');
    expect(r.grade).toBe('A');
    expect(r.missing).toHaveLength(0);
    expect(r.score).toBe(100);
  });

  it('a bare response (no security headers) grades F', () => {
    const r = gradeHeaders({}, 'naked.app');
    expect(r.grade).toBe('F');
    expect(r.missing.length).toBeGreaterThanOrEqual(4);
    expect(r.summary).toMatch(/missing or weak/);
  });

  it('CSP frame-ancestors satisfies the clickjacking check without X-Frame-Options', () => {
    const r = gradeHeaders({ 'content-security-policy': "default-src 'self'; frame-ancestors 'none'" });
    expect(r.checks.find((c) => c.key === 'x-frame-options')?.present).toBe(true);
  });

  it('X-Powered-By is treated as an info leak (check fails, note names the stack)', () => {
    const r = gradeHeaders({ ...FULL, 'X-Powered-By': 'Express' });
    const check = r.checks.find((c) => c.key === 'x-powered-by');
    expect(check?.present).toBe(false);
    expect(check?.note).toMatch(/Express/);
    expect(r.score).toBe(95); // lone low-severity info leak: docked 5, still an A but flagged
  });

  it('missing only X-Content-Type-Options (medium) stays a solid grade', () => {
    const { ['X-Content-Type-Options']: _omit, ...rest } = FULL;
    const r = gradeHeaders(rest);
    expect(r.score).toBe(88); // 100 - 12
    expect(r.grade).toBe('B');
  });
});
