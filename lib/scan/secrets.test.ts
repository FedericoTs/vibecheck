import { describe, it, expect } from 'vitest';
import { findSecrets, jwtRole, redact, gradeSecrets, isSourceMap, sourcesFromMap, countPublicGoogleKeys, type SecretFinding } from './secrets';

const b64url = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (payload: object) => `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url(payload)}.abcdefghij`;

describe('jwtRole', () => {
  it('reads the role claim, tolerates junk', () => {
    expect(jwtRole(jwt({ role: 'service_role' }))).toBe('service_role');
    expect(jwtRole(jwt({ role: 'anon' }))).toBe('anon');
    expect(jwtRole('not.a.jwt')).toBe(null);
  });
});

describe('redact', () => {
  it('masks the middle, keeps a hint', () => {
    expect(redact('sk_live_1234567890abcdef')).toBe('sk_live…cdef');
    expect(redact('short')).toBe('sho…');
  });
});

describe('findSecrets — precision (false positives are unacceptable)', () => {
  it('flags a Supabase service_role key, NEVER the public anon key', () => {
    expect(findSecrets(jwt({ role: 'service_role', iss: 'supabase' })).map((f) => f.id)).toContain('supabase-service-role');
    expect(findSecrets(jwt({ role: 'anon', iss: 'supabase' })).map((f) => f.id)).not.toContain('supabase-service-role');
  });

  it("flags Supabase's CURRENT secret key format, never the publishable one", () => {
    const secret = 'sb_secret_' + 'A'.repeat(30);
    const publishable = 'sb_publishable_' + 'B'.repeat(30);
    const ids = findSecrets(`${secret} ${publishable}`).map((f) => f.id);
    expect(ids).toEqual(['supabase-secret']); // publishable is public by design
  });

  it('flags a Stripe SECRET key, not the publishable key', () => {
    const secret = 'sk_live_51H0' + 'a'.repeat(24);
    const publishable = 'pk_live_51H0' + 'b'.repeat(24);
    const ids = findSecrets(`${secret} ${publishable}`).map((f) => f.id);
    expect(ids).toEqual(['stripe-secret']);
  });

  it('flags AWS / GitHub / private keys / Anthropic', () => {
    expect(findSecrets('AKIAIOSFODNN7EXAMPLE').map((f) => f.id)).toContain('aws-key');
    expect(findSecrets('ghp_' + 'a'.repeat(36)).map((f) => f.id)).toContain('github-token');
    expect(findSecrets('-----BEGIN RSA PRIVATE KEY-----').map((f) => f.id)).toContain('private-key');
    expect(findSecrets('sk-ant-' + 'a'.repeat(30)).map((f) => f.id)).toContain('anthropic');
  });

  it('dedupes repeated matches', () => {
    const k = 'sk_live_' + 'a'.repeat(24);
    expect(findSecrets(`${k} then again ${k} and ${k}`)).toHaveLength(1);
  });

  it('clean client code produces nothing', () => {
    expect(findSecrets('const x=1; fetch("/api/user"); const pk="pk_live_ok";')).toEqual([]);
  });

  it('catches the newer patterns: Slack, SendGrid, npm, and DB connection strings', () => {
    // NOTE: these fixtures are assembled at runtime rather than written as literals.
    // Spelled out in full they trip GitHub's own secret-scanning push protection —
    // which is a decent independent signal that the patterns look like the real thing.
    const slackWebhook = 'https://hooks.slack.com/' + 'services/T00000000/B00000000/' + 'X'.repeat(24);
    expect(findSecrets('xox' + 'b-1234567890-abcdef').map((f) => f.id)).toContain('slack-token');
    expect(findSecrets(slackWebhook).map((f) => f.id)).toContain('slack-webhook');
    expect(findSecrets('SG' + '.abcdefghijklmnop.qrstuvwxyz012345').map((f) => f.id)).toContain('sendgrid');
    expect(findSecrets('npm_' + 'a'.repeat(36)).map((f) => f.id)).toContain('npm-token');
    expect(findSecrets('postgresql://admin:' + 'hunter2' + '@db.example.com:5432/app').map((f) => f.id)).toContain('db-url');
  });

  it('does not flag a harmless postgres URL with no credentials', () => {
    expect(findSecrets('postgres://localhost:5432/dev').map((f) => f.id)).not.toContain('db-url');
  });

  it('REGRESSION: browser Google/Firebase AIza keys are never reported as leaked secrets', () => {
    // Found live on firebase.google.com: 9 AIza keys were flagged as "secrets".
    // They are public by design (referrer-restricted), so flagging them would
    // give every Firebase/Maps app a false alarm and a wrong grade.
    const keys = 'AIzaSyA1234567890abcdefghijklmnopqrstuv AIzaSyB1234567890abcdefghijklmnopqrstuv';
    expect(findSecrets(keys)).toEqual([]);
    expect(countPublicGoogleKeys(keys)).toBe(2); // still counted, as advisory info
    expect(countPublicGoogleKeys('no keys here')).toBe(0);
  });
});

describe('isSourceMap', () => {
  it('detects a real source map, rejects the SPA HTML fallback and 404s', () => {
    const map = JSON.stringify({ version: 3, sources: ['src/App.tsx'], mappings: 'AAAA' });
    expect(isSourceMap(200, map)).toBe(true);
    expect(isSourceMap(200, '<!doctype html><html>app</html>')).toBe(false);
    expect(isSourceMap(404, map)).toBe(false);
    expect(isSourceMap(200, 'console.log(1)')).toBe(false);
  });
});

describe('gradeSecrets', () => {
  const f = (severity: SecretFinding['severity'], id = 'x'): SecretFinding => ({ id, label: id, severity, redacted: 'x…' });
  it('any exposed secret key -> F', () => {
    const r = gradeSecrets([f('high', 'stripe-secret')]);
    expect(r.grade).toBe('F');
    expect(r.summary).toMatch(/exposed/);
  });
  it('only a medium (e.g. Google key) -> C; nothing -> A', () => {
    expect(gradeSecrets([f('medium', 'google-api')]).grade).toBe('C');
    expect(gradeSecrets([]).grade).toBe('A');
  });
});

describe('sourcesFromMap — reading the source a map republishes', () => {
  it('extracts sourcesContent so a secret hidden by minification becomes findable', () => {
    const secret = 'sk' + '_live_' + 'A'.repeat(24);
    const map = JSON.stringify({
      version: 3,
      sources: ['src/config.ts'],
      sourcesContent: ['export const STRIPE = "' + secret + '";'],
      mappings: 'AAAA',
    });
    const source = sourcesFromMap(map);
    expect(source).toContain(secret);
    // and the end-to-end intent: the secret scanner finds it in the restored source
    expect(findSecrets(source).map((f) => f.id)).toContain('stripe-secret');
  });

  it('returns empty for a map with no sourcesContent, and for junk', () => {
    expect(sourcesFromMap(JSON.stringify({ version: 3, sources: ['a.ts'] }))).toBe('');
    expect(sourcesFromMap('not json at all')).toBe('');
    expect(sourcesFromMap(JSON.stringify({ sourcesContent: [null, 42] }))).toBe('');
  });
});
