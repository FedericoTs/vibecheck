import { describe, it, expect, beforeEach } from 'vitest';
import { checkRateLimit, resetRateLimit, clientKey } from './rate-limit';

beforeEach(() => resetRateLimit());

describe('clientKey', () => {
  it('takes the first x-forwarded-for hop, falls back sensibly', () => {
    expect(clientKey(new Headers({ 'x-forwarded-for': '1.2.3.4, 5.6.7.8' }))).toBe('1.2.3.4');
    expect(clientKey(new Headers({ 'x-real-ip': '9.9.9.9' }))).toBe('9.9.9.9');
    expect(clientKey(new Headers())).toBe('unknown');
  });
});

describe('checkRateLimit', () => {
  it('allows ~10 full reports per minute, then blocks with a retry hint', () => {
    const now = 1_000_000;
    let last = checkRateLimit('ip', now);
    for (let i = 0; i < 59; i++) last = checkRateLimit('ip', now);
    expect(last.allowed).toBe(true);
    expect(last.remaining).toBe(0);

    const blocked = checkRateLimit('ip', now);
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('the window resets', () => {
    const now = 2_000_000;
    for (let i = 0; i < 60; i++) checkRateLimit('ip2', now);
    expect(checkRateLimit('ip2', now).allowed).toBe(false);
    expect(checkRateLimit('ip2', now + 61_000).allowed).toBe(true);
  });

  it('limits are per client, so one abuser cannot block everyone else', () => {
    const now = 3_000_000;
    for (let i = 0; i < 60; i++) checkRateLimit('noisy', now);
    expect(checkRateLimit('noisy', now).allowed).toBe(false);
    expect(checkRateLimit('quiet', now).allowed).toBe(true);
  });
});
