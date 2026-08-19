import { describe, it, expect } from 'vitest';
import { findSupabaseUrls, findAnonKeys, discoverSupabase } from './discover';

const b64url = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (payload: object) => `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url(payload)}.sigsigsig`;

const ANON = jwt({ role: 'anon', iss: 'supabase' });
const SERVICE = jwt({ role: 'service_role', iss: 'supabase' });

const BUNDLE = `
  const SUPABASE_URL="https://abcdefghijkl.supabase.co";
  const SUPABASE_ANON_KEY="${ANON}";
  createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
`;

describe('findSupabaseUrls', () => {
  it('finds the project URL and normalises it', () => {
    expect(findSupabaseUrls(BUNDLE)).toEqual(['https://abcdefghijkl.supabase.co']);
  });
  it('dedupes repeats and ignores unrelated hosts', () => {
    const t = 'https://abcdefghijkl.supabase.co x https://abcdefghijkl.supabase.co y https://example.com';
    expect(findSupabaseUrls(t)).toHaveLength(1);
    expect(findSupabaseUrls('https://example.com')).toEqual([]);
  });
});

describe('findAnonKeys', () => {
  it('returns anon keys only — NEVER a service_role key', () => {
    expect(findAnonKeys(BUNDLE)).toEqual([ANON]);
    expect(findAnonKeys(`key="${SERVICE}"`)).toEqual([]);
  });
  it('ignores non-JWT junk', () => {
    expect(findAnonKeys('const x = "not.a.jwt";')).toEqual([]);
  });
});

describe('discoverSupabase', () => {
  it('pairs the URL + anon key from a real-looking bundle', () => {
    expect(discoverSupabase(BUNDLE)).toEqual({
      url: 'https://abcdefghijkl.supabase.co',
      anonKey: ANON,
    });
  });

  it('returns null when either half is missing', () => {
    expect(discoverSupabase('https://abcdefghijkl.supabase.co only')).toBe(null);
    expect(discoverSupabase(`key ${ANON} only`)).toBe(null);
    expect(discoverSupabase('nothing here')).toBe(null);
  });

  it('does not hand back a service_role key even when one is present', () => {
    const d = discoverSupabase(`https://abcdefghijkl.supabase.co ${SERVICE}`);
    expect(d).toBe(null); // no anon key -> nothing to probe with
  });
});
