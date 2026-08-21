import { describe, it, expect } from 'vitest';
import { normalizeSupabaseUrl, parseTablesFromOpenApi, parseCountHeader, isExposed, parseRpcFromOpenApi, classifyBuckets, classifyAuthConfig, scanSupabase, looksLikeApiSpec } from './supabase';
import type { Fetchy } from './types';

// ── pure helpers ─────────────────────────────────────────────────────
describe('pure helpers', () => {
  it('normalizeSupabaseUrl accepts host or url, strips path, keeps origin', () => {
    expect(normalizeSupabaseUrl('abc.supabase.co').base).toBe('https://abc.supabase.co');
    expect(normalizeSupabaseUrl('https://abc.supabase.co/rest/v1/').host).toBe('abc.supabase.co');
    expect(() => normalizeSupabaseUrl('')).toThrow();
    expect(() => normalizeSupabaseUrl('   ')).toThrow();
  });

  it('parseTablesFromOpenApi extracts table paths, drops "/" and rpc', () => {
    const doc = { paths: { '/': {}, '/users': {}, '/posts': {}, '/rpc/do_thing': {} } };
    expect(parseTablesFromOpenApi(doc)).toEqual(['posts', 'users']);
    expect(parseTablesFromOpenApi({})).toEqual([]);
    expect(parseTablesFromOpenApi(null)).toEqual([]);
  });

  it('parseCountHeader reads N from content-range', () => {
    expect(parseCountHeader('0-0/42')).toBe(42);
    expect(parseCountHeader('*/0')).toBe(0);
    expect(parseCountHeader(null)).toBe(null);
  });

  it('isExposed only when 200 + a real row came back', () => {
    expect(isExposed(200, [{ id: 1 }])).toBe(true);
    expect(isExposed(200, [])).toBe(false); // empty or RLS-filtered
    expect(isExposed(401, [{ id: 1 }])).toBe(false); // blocked
  });

  it('parseRpcFromOpenApi lists public database functions (never calls them)', () => {
    const doc = { paths: { '/': {}, '/users': {}, '/rpc/wipe_org': {}, '/rpc/get_stats': {} } };
    expect(parseRpcFromOpenApi(doc)).toEqual(['get_stats', 'wipe_org']);
    expect(parseRpcFromOpenApi({})).toEqual([]);
  });

  it('classifyAuthConfig reads the public auth settings; only the risky COMBINATION matters', () => {
    const risky = classifyAuthConfig(200, { disable_signup: false, mailer_autoconfirm: true, external: { google: true, github: false } });
    expect(risky.checked).toBe(true);
    expect(risky.signupsOpen).toBe(true);
    expect(risky.autoConfirm).toBe(true);
    expect(risky.providers).toEqual(['google']); // only enabled providers

    const safe = classifyAuthConfig(200, { disable_signup: false, mailer_autoconfirm: false });
    expect(safe.autoConfirm).toBe(false);

    // phone autoconfirm counts too
    expect(classifyAuthConfig(200, { phone_autoconfirm: true }).autoConfirm).toBe(true);

    // unreachable / non-JSON must not fabricate a finding
    expect(classifyAuthConfig(401, null).checked).toBe(false);
    expect(classifyAuthConfig(200, 'nope').checked).toBe(false);
  });

  it('classifyBuckets flags enumeration + public buckets, tolerates a blocked response', () => {
    const open = classifyBuckets(200, [{ name: 'avatars', public: true }, { name: 'private', public: false }]);
    expect(open.enumerable).toBe(true);
    expect(open.publicBuckets).toEqual(['avatars']);

    const blocked = classifyBuckets(401, { message: 'denied' });
    expect(blocked.enumerable).toBe(false);
    expect(blocked.publicBuckets).toEqual([]);
  });
});

// ── full scan against a mocked Supabase ──────────────────────────────
function res(body: unknown, init: ResponseInit = {}): Response {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...init,
  });
}

/** Route mock fetch by URL substring; each entry is a fresh Response factory. */
function mockFetch(routes: Array<[string, () => Response]>): Fetchy {
  return async (url) => {
    for (const [needle, make] of routes) if (url.includes(needle)) return make();
    return res('not found', { status: 404 });
  };
}

// Shaped like a real PostgREST response, which always carries the Swagger
// version. A fixture that omits it cannot catch a guard that requires it.
const SWAGGER = { swagger: '2.0', paths: { '/': {}, '/users': {}, '/posts': {}, '/secrets': {}, '/rpc/x': {} } };

describe('scanSupabase', () => {
  it('flags the tables the anon key can actually read, grades F', async () => {
    const fetchy = mockFetch([
      ['/rest/v1/users', () => res([{ id: 1 }], { headers: { 'content-range': '0-0/1200' } })], // EXPOSED
      ['/rest/v1/posts', () => res([{ id: 9 }], { headers: { 'content-range': '0-0/3' } })], // EXPOSED
      ['/rest/v1/secrets', () => res({ message: 'permission denied' }, { status: 401 })], // safe (blocked)
      ['/rest/v1/', () => res(SWAGGER)], // discovery (must be last: matches broadly)
    ]);
    const r = await scanSupabase({ url: 'https://abc.supabase.co', anonKey: 'anon.jwt', fetch: fetchy });
    expect(r.ok).toBe(true);
    expect(r.tablesFound).toBe(3);
    expect(r.exposedCount).toBe(2);
    expect(r.grade).toBe('F');
    expect(r.findings.find((f) => f.table === 'users')?.rowsVisible).toBe(1200);
    expect(r.findings.find((f) => f.table === 'secrets')?.exposed).toBe(false);
    expect(r.summary).toMatch(/2 of 3/);
  });

  it('a fully locked-down project grades A', async () => {
    const fetchy = mockFetch([
      ['/rest/v1/users', () => res([])], // RLS filters all rows -> safe
      ['/rest/v1/posts', () => res([])],
      ['/rest/v1/secrets', () => res([])],
      ['/rest/v1/', () => res(SWAGGER)],
    ]);
    const r = await scanSupabase({ url: 'abc.supabase.co', anonKey: 'anon.jwt', fetch: fetchy });
    expect(r.exposedCount).toBe(0);
    expect(r.grade).toBe('A');
    expect(r.summary).toMatch(/none readable/);
  });

  it('a rejected anon key fails cleanly, never throws', async () => {
    const fetchy = mockFetch([['/rest/v1/', () => res({ message: 'invalid' }, { status: 401 })]]);
    const r = await scanSupabase({ url: 'abc.supabase.co', anonKey: 'bad', fetch: fetchy });
    expect(r.ok).toBe(false);
    // The key is usually auto-detected, so the message must not tell the user to
    // re-check something they never typed, and must not read as a finding.
    expect(r.error).toMatch(/rejected its public key/i);
    expect(r.error).toMatch(/nothing here is a finding/i);
  });

  it('missing inputs fail with guidance, not a crash', async () => {
    expect((await scanSupabase({ url: '', anonKey: 'x' })).error).toMatch(/URL/);
    expect((await scanSupabase({ url: 'abc.supabase.co', anonKey: '' })).error).toMatch(/anon/i);
  });
});

describe('looksLikeApiSpec — checking nothing must not look like checking', () => {
  it('accepts a real PostgREST description', () => {
    expect(looksLikeApiSpec({ swagger: '2.0', paths: { '/': {}, '/users': {} } })).toBe(true);
    expect(looksLikeApiSpec({ openapi: '3.0.0', paths: {} })).toBe(true);
  });

  it('rejects unrelated JSON that merely returned 200', () => {
    expect(looksLikeApiSpec({ message: 'hello' })).toBe(false);
    expect(looksLikeApiSpec({ paths: { '/users': {} } })).toBe(false); // no version
    expect(looksLikeApiSpec({ swagger: '2.0' })).toBe(false); // no paths
    expect(looksLikeApiSpec(null)).toBe(false);
    expect(looksLikeApiSpec('<!doctype html>')).toBe(false);
  });

  it('reports unknown rather than a clean pass when the origin is not PostgREST', async () => {
    const fetchy = (async () =>
      ({ ok: true, status: 200, json: async () => ({ message: 'hello' }) }) as unknown as Response) as never;
    const r = await scanSupabase({ url: 'https://db.mycompany.com', anonKey: 'sb_publishable_abcdefghijklmnop', fetch: fetchy });
    expect(r.ok).toBe(false);
    expect(r.findings).toEqual([]);
    expect(r.summary).toMatch(/not checked/i);
    // The dangerous rendering would be "no tables reachable" — i.e. a pass.
    expect(r.summary).not.toMatch(/no tables/i);
  });
});
