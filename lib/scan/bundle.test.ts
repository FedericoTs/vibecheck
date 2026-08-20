import { describe, it, expect } from 'vitest';
import { scriptUrls } from './bundle';

const page = new URL('https://myapp.com/');

describe('scriptUrls — the shared bundle corpus', () => {
  it('INCLUDES chunks served from a separate asset host (the assetPrefix/CDN case)', () => {
    // The regression this locks: supabase.com serves all of its scripts from
    // frontend-assets.supabase.com. A same-origin-only filter found ZERO
    // scripts and the scan reported "no secrets found" having read no
    // JavaScript at all — a silent false pass, the worst failure mode here.
    const html = `
      <script src="https://frontend-assets.supabase.com/_next/static/chunks/main-abc.js"></script>
      <script src="https://frontend-assets.supabase.com/_next/static/chunks/page-def.js"></script>`;
    const urls = scriptUrls(html, new URL('https://supabase.com/'));
    expect(urls).toHaveLength(2);
    expect(urls[0]).toContain('frontend-assets.supabase.com');
  });

  it('resolves relative srcs against the page URL', () => {
    const urls = scriptUrls('<script src="/_next/static/main.js"></script>', page);
    expect(urls).toEqual(['https://myapp.com/_next/static/main.js']);
  });

  it('ranks same-origin first, then the same site, then third parties', () => {
    const html = `
      <script src="https://www.googletagmanager.com/gtag/js.js"></script>
      <script src="https://cdn.myapp.com/assets/vendor.js"></script>
      <script src="/_next/static/main.js"></script>`;
    const urls = scriptUrls(html, page);
    expect(urls[0]).toBe('https://myapp.com/_next/static/main.js');
    expect(urls[1]).toContain('cdn.myapp.com');
    expect(urls[2]).toContain('googletagmanager.com');
  });

  it('keeps only http(s) .js/.mjs and ignores junk', () => {
    const html = `
      <script src="/a.css"></script>
      <script src="javascript:alert(1)"></script>
      <script src="data:text/javascript,alert(1)"></script>
      <script>inline()</script>
      <script src="/real.mjs"></script>`;
    expect(scriptUrls(html, page)).toEqual(['https://myapp.com/real.mjs']);
  });

  it('deduplicates and honours the cap', () => {
    const dup = '<script src="/a.js"></script><script src="/a.js"></script>';
    expect(scriptUrls(dup, page)).toHaveLength(1);
    const many = Array.from({ length: 30 }, (_, i) => `<script src="/c${i}.js"></script>`).join('');
    expect(scriptUrls(many, page, 5)).toHaveLength(5);
  });

  it('prefers likely-entry chunks within a tier so they win the cap', () => {
    const html = `
      <script src="/static/zzz-polyfill-9.js"></script>
      <script src="/static/main-entry.js"></script>`;
    expect(scriptUrls(html, page, 1)).toEqual(['https://myapp.com/static/main-entry.js']);
  });
});
