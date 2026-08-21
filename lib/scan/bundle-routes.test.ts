import { describe, expect, it } from 'vitest';
import { extractRoutes, routeFromChunkUrl } from './bundle-routes';

const paths = (r: { probes: { path: string }[] }) => r.probes.map((p) => p.path);
const refusedPaths = (r: { refused: { path: string }[] }) => r.refused.map((p) => p.path);

describe('extractRoutes', () => {
  it('finds the routes the app actually ships, not the ones we guessed', () => {
    const bundle = `
      await fetch("/api/orders");
      const admin = "/console/settings";
      router.push("/api/reports/monthly");
    `;
    expect(paths(extractRoutes(bundle))).toEqual(['/api/orders', '/api/reports/monthly', '/console/settings']);
  });

  /**
   * The rule that keeps this defensible. We cannot verify ownership, a GET
   * handler that deletes is a real pattern in AI-generated code, and requesting
   * one would make us the attacker.
   */
  it('REFUSES to request anything whose name implies a write', () => {
    const bundle = `
      "/api/admin/purge-all"
      "/api/users/delete"
      "/api/invoices/refund"
      "/api/session/logout"
      "/api/orders"
    `;
    const r = extractRoutes(bundle);
    expect(paths(r)).toEqual(['/api/orders']);
    expect(refusedPaths(r).sort()).toEqual([
      '/api/admin/purge-all',
      '/api/invoices/refund',
      '/api/session/logout',
      '/api/users/delete',
    ]);
  });

  it('drops anything that is not literally requestable', () => {
    const bundle = `
      "/api/users/\${id}"
      "/api/posts/[slug]"
      "/api/search?q=x"
      "/api/a b"
      "/api/app.js"
      "/api/styles.css"
      "/api/a/b/c/d/e/f/g"
      "/api"
    `;
    expect(paths(extractRoutes(bundle))).toEqual([]);
  });

  it('ignores paths outside the prefixes worth probing', () => {
    const bundle = '"/about" "/blog/hello" "/pricing"';
    expect(paths(extractRoutes(bundle))).toEqual([]);
  });

  it('caps how many requests it will make, stably', () => {
    const bundle = Array.from({ length: 40 }, (_, i) => `"/api/thing${String(i).padStart(2, '0')}"`).join(' ');
    const r = extractRoutes(bundle, [], 5);
    expect(r.probes).toHaveLength(5);
    // Sorted, so a truncated list is deterministic rather than Set-order dependent.
    expect(paths(r)).toEqual(['/api/thing00', '/api/thing01', '/api/thing02', '/api/thing03', '/api/thing04']);
  });

  it('classifies by what the route is, not just where it sits', () => {
    const r = extractRoutes('"/api/orders" "/admin/users" "/debug/state"');
    const kind = (p: string) => r.probes.find((x) => x.path === p)?.kind;
    expect(kind('/api/orders')).toBe('data');
    expect(kind('/admin/users')).toBe('admin');
    expect(kind('/debug/state')).toBe('debug');
  });
});

describe('routeFromChunkUrl', () => {
  it('reads the route tree out of Next.js page-chunk names', () => {
    expect(routeFromChunkUrl('https://x.com/_next/static/chunks/app/admin/page-a1b2c3.js')).toBe('/admin');
    expect(routeFromChunkUrl('/_next/static/chunks/app/dashboard/settings/page-9f8e.js')).toBe('/dashboard/settings');
    expect(routeFromChunkUrl('/_next/static/chunks/app/admin/layout-77aa.js')).toBe('/admin');
  });

  it('strips route groups, which are not part of the URL', () => {
    expect(routeFromChunkUrl('/_next/static/chunks/app/(marketing)/pricing/page-11.js')).toBe('/pricing');
  });

  it('skips dynamic segments, which cannot be requested literally', () => {
    expect(routeFromChunkUrl('/_next/static/chunks/app/blog/[slug]/page-22.js')).toBe(null);
  });

  it('ignores anything that is not an app page chunk', () => {
    expect(routeFromChunkUrl('/_next/static/chunks/main-abc.js')).toBe(null);
    expect(routeFromChunkUrl('/static/app.js')).toBe(null);
  });

  it('feeds chunk-derived routes into the probe list', () => {
    const r = extractRoutes('', ['/_next/static/chunks/app/admin/page-a1.js'], 12);
    expect(paths(r)).toEqual(['/admin']);
  });
});
