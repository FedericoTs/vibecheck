import { describe, it, expect } from 'vitest';
import { analyzeFundamentals } from './fundamentals';

const https = new URL('https://my.app');
const http = new URL('http://my.app');

const FULL = `<!doctype html><html lang="en"><head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>My App</title>
<meta name="description" content="the best app">
<meta property="og:title" content="My App"><meta property="og:image" content="/og.png">
<link rel="canonical" href="https://my.app">
</head><body><script src="https://my.app/a.js"></script></body></html>`;

describe('analyzeFundamentals', () => {
  it('a fully-set-up https page passes everything (A)', () => {
    const r = analyzeFundamentals(FULL, https);
    expect(r.grade).toBe('A');
    expect(r.failed).toHaveLength(0);
  });

  it('an http + bare page fails https, title, viewport…', () => {
    const r = analyzeFundamentals('<html><head></head><body></body></html>', http);
    const failed = r.failed.map((c) => c.key);
    expect(failed).toContain('https');
    expect(failed).toContain('title');
    expect(failed).toContain('viewport');
    expect(r.grade).not.toBe('A');
  });

  it('detects mixed content on an https page', () => {
    const r = analyzeFundamentals('<html><head><title>x</title></head><body><img src="http://cdn/x.png"></body></html>', https);
    expect(r.checks.find((c) => c.key === 'mixed-content')?.pass).toBe(false);
  });

  it('an http page is not dinged for mixed content (only checked on https)', () => {
    const r = analyzeFundamentals('<img src="http://cdn/x.png">', http);
    expect(r.checks.find((c) => c.key === 'mixed-content')?.pass).toBe(true);
  });
});
