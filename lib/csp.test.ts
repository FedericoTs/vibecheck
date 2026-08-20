import { describe, it, expect } from 'vitest';
import { buildCsp } from './csp';
import { cspIsMeaningful } from './scan/headers';

const csp = buildCsp({ nonce: 'dGVzdC1ub25jZS0xMjM0' });

describe('our own Content-Security-Policy', () => {
  it('passes the very check we run on other people', () => {
    // If this ever fails, the site would be scored down by its own scanner —
    // which is the whole reason the policy lives in a tested module.
    expect(cspIsMeaningful(csp)).toBe(true);
  });

  it('carries the per-request nonce on script-src and nothing unsafe', () => {
    const scriptSrc = csp.match(/script-src ([^;]*)/)![1];
    expect(scriptSrc).toContain("'nonce-dGVzdC1ub25jZS0xMjM0'");
    expect(scriptSrc).not.toContain('unsafe-inline');
    expect(scriptSrc).not.toContain('unsafe-eval');
    // A bare scheme or wildcard in script-src would defeat the policy — and our
    // own cspIsMeaningful rejects both.
    expect(scriptSrc).not.toMatch(/(^|\s)\*(\s|$)/);
    expect(scriptSrc).not.toMatch(/(^|\s)https?:(\s|$)/);
  });

  it("keeps 'unsafe-inline' confined to styles, never scripts", () => {
    // The report draws computed widths as inline style attributes, which a nonce
    // cannot cover. Documented tradeoff — but it must not leak into script-src.
    expect(csp.match(/style-src ([^;]*)/)![1]).toContain("'unsafe-inline'");
  });

  it('allows cross-origin connect, or the client-side database probe dies', () => {
    // The probe runs in the visitor's browser against the visitor's own backend,
    // whose origin is unknowable at build time. This is load-bearing, not slack.
    const connect = csp.match(/connect-src ([^;]*)/)![1];
    expect(connect).toContain('https:');
    expect(connect).not.toContain('http:'); // no cleartext downgrade
  });

  it('locks down the classic injection pivots', () => {
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'self'");
    expect(csp).toContain("form-action 'self'");
  });

  it('emits a fresh nonce per call', () => {
    expect(buildCsp({ nonce: 'a' })).not.toBe(buildCsp({ nonce: 'b' }));
  });
});
