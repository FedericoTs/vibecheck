import { describe, it, expect } from 'vitest';
import { computeStats, clampSecrets } from './stats';

describe('clampSecrets', () => {
  it('coerces to a non-negative integer capped at 50 (anti-abuse)', () => {
    expect(clampSecrets(3)).toBe(3);
    expect(clampSecrets('7')).toBe(7);
    expect(clampSecrets(-5)).toBe(0);
    expect(clampSecrets(9999)).toBe(50);
    expect(clampSecrets('nonsense')).toBe(0);
    expect(clampSecrets(null)).toBe(0);
    expect(clampSecrets(2.9)).toBe(2);
  });
});

describe('computeStats', () => {
  it('parses Redis string values, floors negatives/garbage to 0', () => {
    expect(computeStats({ total: '1420', leaking: '867', secrets: '43' })).toEqual({ total: 1420, leaking: 867, secrets: 43 });
    expect(computeStats({ total: null, leaking: undefined, secrets: 'x' })).toEqual({ total: 0, leaking: 0, secrets: 0 });
    expect(computeStats({})).toEqual({ total: 0, leaking: 0, secrets: 0 });
  });
});
