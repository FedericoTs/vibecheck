import { describe, it, expect } from 'vitest';
import { findSecrets, jwtRole, redact, gradeSecrets, type SecretFinding } from './secrets';

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
