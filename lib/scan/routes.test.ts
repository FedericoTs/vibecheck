import { describe, it, expect } from 'vitest';
import {
  isSameShell,
  looksLikeAuthGate,
  looksLikeAdminUi,
  looksLikeData,
  classifyRoute,
  gradeRoutes,
  ROUTE_PROBES,
  type ProbeResponse,
  type RouteFinding,
} from './routes';

const probe = (path: string) => ROUTE_PROBES.find((p) => p.path === path)!;
const html = (body: string, status = 200): ProbeResponse => ({ status, contentType: 'text/html', body, redirected: false });
const json = (body: unknown, status = 200): ProbeResponse => ({
  status,
  contentType: 'application/json',
  body: JSON.stringify(body),
  redirected: false,
});

const SHELL = '<!doctype html><html><head><title>My App</title></head><body><div id="root"></div><script src="/app.js"></script></body></html>';

describe('isSameShell — the SPA false-positive guard', () => {
  it('recognises the identical app shell', () => {
    expect(isSameShell(SHELL, SHELL)).toBe(true);
    expect(isSameShell(SHELL.replace('My App', 'My App — Admin'), SHELL)).toBe(true);
  });
  it('distinguishes genuinely different content', () => {
    expect(isSameShell('<html><body><h1>Admin Dashboard</h1><table>' + 'x'.repeat(2000) + '</table></body></html>', SHELL)).toBe(false);
  });
});

describe('content heuristics', () => {
  it('looksLikeAuthGate: password field or sign-in wording', () => {
    expect(looksLikeAuthGate('<input type="password" name="p">')).toBe(true);
    expect(looksLikeAuthGate('<h1>Please Log in</h1>')).toBe(true);
    expect(looksLikeAuthGate('<h1>Welcome to our marketing site</h1>')).toBe(false);
  });

  it('looksLikeAdminUi: real admin markers, not a marketing page', () => {
    expect(looksLikeAdminUi('<h1>Admin Dashboard</h1>')).toBe(true);
    expect(looksLikeAdminUi('<table><tr><th>Email</th><th>Role</th></tr></table>')).toBe(true);
    expect(looksLikeAdminUi('<h1>Our pricing</h1><p>we are admin friendly</p>')).toBe(false);
  });

  it('looksLikeData: records only — not errors or empty lists', () => {
    expect(looksLikeData('application/json', '[{"id":1,"email":"a@b.c"}]')).toBe(true);
    expect(looksLikeData('application/json', '{"users":[{"id":1}]}')).toBe(true);
    expect(looksLikeData('application/json', '[]')).toBe(false);
    expect(looksLikeData('application/json', '{"error":"Unauthorized"}')).toBe(false);
    expect(looksLikeData('text/html', '[{"id":1}]')).toBe(false);
  });
});

describe('classifyRoute', () => {
  it('404 / 401 / redirect are not findings', () => {
    expect(classifyRoute(probe('/admin'), html('nope', 404), SHELL).verdict).toBe('absent');
    expect(classifyRoute(probe('/admin'), html('denied', 401), SHELL).verdict).toBe('protected');
    expect(classifyRoute(probe('/admin'), { ...html(''), status: 302, redirected: true }, SHELL).verdict).toBe('protected');
  });

  it('a login page at /admin is PROTECTED, not exposed', () => {
    const login = '<html><body><form><input type="password"></form></body></html>';
    expect(classifyRoute(probe('/admin'), html(login), SHELL).verdict).toBe('protected');
  });

  it('an SPA shell at /admin is INCONCLUSIVE, never a false accusation', () => {
    const f = classifyRoute(probe('/admin'), html(SHELL), SHELL);
    expect(f.verdict).toBe('inconclusive');
    expect(f.detail).toMatch(/app shell/);
  });

  it('a real admin UI with no auth gate is EXPOSED', () => {
    const admin = '<html><body><h1>Admin Dashboard</h1><table><tr><th>Email</th><th>Role</th></tr></table>' + 'x'.repeat(1500) + '</body></html>';
    const f = classifyRoute(probe('/admin'), html(admin), SHELL);
    expect(f.verdict).toBe('exposed');
    expect(f.detail).toMatch(/without authentication/);
  });

  it('an API returning real user records is EXPOSED; an empty/error one is not', () => {
    expect(classifyRoute(probe('/api/users'), json([{ id: 1, email: 'a@b.c' }]), SHELL).verdict).toBe('exposed');
    expect(classifyRoute(probe('/api/users'), json([]), SHELL).verdict).toBe('absent');
    // an API that answers "Unauthorized" is genuinely protected, not absent
    expect(classifyRoute(probe('/api/users'), json({ error: 'Unauthorized' }, 200), SHELL).verdict).toBe('protected');
    expect(classifyRoute(probe('/api/users'), json({ error: 'Not found' }, 200), SHELL).verdict).toBe('absent');
  });

  it('a publicly served debug page with real debug output is EXPOSED', () => {
    const dbg = '<html><body><h1>PHP Version 8.2</h1>phpinfo() ' + 'y'.repeat(2000) + '</body></html>';
    expect(classifyRoute(probe('/phpinfo.php'), html(dbg), SHELL).verdict).toBe('exposed');
  });

  it('REGRESSION: a soft 404 (200 + "not found" page) is NOT an exposed debug route', () => {
    // Found live: vercel.com returned 200 + a custom 404 page for /phpinfo.php
    // and the old rule reported it as EXPOSED. Vercel does not run PHP.
    const soft404 = '<html><body><h1>404</h1><p>This page could not be found.</p>' + 'z'.repeat(1500) + '</body></html>';
    expect(classifyRoute(probe('/phpinfo.php'), html(soft404), SHELL).verdict).toBe('absent');
  });

  it('a debug path that exists but shows no debug output is only INCONCLUSIVE', () => {
    const page = '<html><body><h1>Our developer blog</h1>' + 'q'.repeat(2000) + '</body></html>';
    expect(classifyRoute(probe('/debug'), html(page), SHELL).verdict).toBe('inconclusive');
  });
});

describe('gradeRoutes', () => {
  const mk = (verdict: RouteFinding['verdict']): RouteFinding => ({ path: '/admin', label: 'a', kind: 'admin', verdict });
  it('clean scan is an A; one exposed route is a serious drop', () => {
    expect(gradeRoutes([mk('absent'), mk('protected')]).grade).toBe('A');
    expect(gradeRoutes([mk('exposed')]).grade).toBe('D');
    expect(gradeRoutes([mk('exposed'), mk('exposed')]).grade).toBe('F');
  });
  it('inconclusive results never count against you', () => {
    expect(gradeRoutes([mk('inconclusive'), mk('inconclusive')]).grade).toBe('A');
  });
});

describe('schema disclosure (OpenAPI / Swagger)', () => {
  const schemaProbe = ROUTE_PROBES.find((p) => p.path === '/openapi.json')!;
  const docsProbe = ROUTE_PROBES.find((p) => p.path === '/api-docs')!;

  it('EXPOSED when a real OpenAPI document is served', () => {
    const spec = JSON.stringify({ openapi: '3.0.0', paths: { '/users': {} } });
    const f = classifyRoute(schemaProbe, { status: 200, contentType: 'application/json', body: spec, redirected: false }, SHELL);
    expect(f.verdict).toBe('exposed');
    expect(f.detail).toMatch(/full API surface/);
  });

  it('EXPOSED for a rendered Swagger UI page', () => {
    const html = '<html><head><title>API Docs</title></head><body><div id="swagger-ui"></div>' + 'x'.repeat(1200) + '</body></html>';
    expect(classifyRoute(docsProbe, { status: 200, contentType: 'text/html', body: html, redirected: false }, SHELL).verdict).toBe('exposed');
  });

  it('ordinary JSON or an SPA shell at those paths is NOT a schema finding', () => {
    expect(classifyRoute(schemaProbe, { status: 200, contentType: 'application/json', body: '{"ok":true}', redirected: false }, SHELL).verdict).toBe('absent');
    expect(classifyRoute(docsProbe, { status: 200, contentType: 'text/html', body: SHELL, redirected: false }, SHELL).verdict).toBe('inconclusive');
  });
});
