import { describe, it, expect } from 'vitest';
import {
  parseRepoUrl,
  selectFiles,
  isApiRouteFile,
  detectCrossTenant,
  analyzeRepoFiles,
  gradeRepo,
  isFixture,
  type TreeEntry,
} from './repo';

describe('parseRepoUrl', () => {
  it('accepts the common github URL shapes and shorthand', () => {
    expect(parseRepoUrl('https://github.com/FedericoTs/vibecheck')).toEqual({ owner: 'FedericoTs', repo: 'vibecheck' });
    expect(parseRepoUrl('github.com/acme/app.git')).toEqual({ owner: 'acme', repo: 'app' });
    expect(parseRepoUrl('https://github.com/acme/app/tree/main/src')).toEqual({ owner: 'acme', repo: 'app' });
    expect(parseRepoUrl('acme/app')).toEqual({ owner: 'acme', repo: 'app' });
  });
  it('rejects non-repos', () => {
    expect(parseRepoUrl('https://github.com/acme')).toBe(null);
    expect(parseRepoUrl('https://example.com/x/y')).toBe(null);
    expect(parseRepoUrl('')).toBe(null);
  });
});

describe('selectFiles', () => {
  const tree = (paths: string[]): TreeEntry[] => paths.map((p) => ({ path: p, type: 'blob' }));

  it('keeps source, drops node_modules / lockfiles / build output', () => {
    const files = selectFiles(
      tree(['src/app/api/users/route.ts', 'node_modules/x/index.js', 'package-lock.json', 'dist/bundle.min.js', '.env', 'README.md']),
    );
    expect(files).toContain('src/app/api/users/route.ts');
    expect(files).toContain('.env');
    expect(files).not.toContain('node_modules/x/index.js');
    expect(files).not.toContain('package-lock.json');
    expect(files).not.toContain('dist/bundle.min.js');
    expect(files).not.toContain('README.md'); // not a scannable extension
  });

  it('prioritises .env and API routes, and caps the count', () => {
    const many = Array.from({ length: 200 }, (_, i) => `src/util${i}.ts`);
    const files = selectFiles(tree(['.env.production', 'app/api/orders/route.ts', ...many]), 10);
    expect(files[0]).toBe('.env.production');
    expect(files[1]).toBe('app/api/orders/route.ts');
    expect(files).toHaveLength(10);
  });
});

describe('isApiRouteFile', () => {
  it('recognises App Router, Pages Router, and bare api dirs', () => {
    expect(isApiRouteFile('app/api/users/route.ts')).toBe(true);
    expect(isApiRouteFile('src/pages/api/orders.ts')).toBe(true);
    expect(isApiRouteFile('server/api/vendors.js')).toBe(true);
    expect(isApiRouteFile('src/components/Button.tsx')).toBe(false);
    expect(isApiRouteFile('src/lib/db.ts')).toBe(false);
  });
});

describe('detectCrossTenant — the tenant-guard shape (a CONJUNCTION)', () => {
  const P = 'app/api/orders/[id]/route.ts';

  it('flags authenticated + bare-id filter + NO tenant column', () => {
    const code = `
      export async function GET(req) {
        const { user } = await withApiAuth(req);
        const order = await supabase.from('orders').select('*').eq('id', params.id).single();
        return Response.json(order);
      }`;
    expect(detectCrossTenant(P, code)?.detail).toMatch(/another tenant/);
  });

  it('does NOT flag when the query IS scoped to the tenant', () => {
    const code = `
      const { user } = await withApiAuth(req);
      supabase.from('orders').select('*').eq('id', id).eq('organization_id', user.organization_id);`;
    expect(detectCrossTenant(P, code)).toBe(null);
  });

  it('does NOT flag an unauthenticated public route (no auth signal)', () => {
    expect(detectCrossTenant(P, `supabase.from('posts').select('*').eq('id', id)`)).toBe(null);
  });

  it('does NOT flag auth without a bare-id filter (e.g. a list endpoint)', () => {
    expect(detectCrossTenant(P, `const {user}=await withApiAuth(req); supabase.from('orders').select('*')`)).toBe(null);
  });

  it('never fires outside an API route file', () => {
    expect(detectCrossTenant('src/lib/helpers.ts', `withApiAuth(); .eq('id', id)`)).toBe(null);
  });

  it('catches Prisma and Drizzle shapes too', () => {
    const prisma = `await requireAuth(); prisma.order.findUnique({ where: { id } })`;
    const drizzle = `getSession(); db.select().from(orders).where(eq(orders.id, id))`;
    expect(detectCrossTenant(P, prisma)).not.toBe(null);
    expect(detectCrossTenant(P, drizzle)).not.toBe(null);
  });
});

describe('analyzeRepoFiles + gradeRepo', () => {
  it('finds a committed secret and grades F', () => {
    const stripe = 'sk' + '_live_' + 'A'.repeat(24);
    const findings = analyzeRepoFiles([{ path: '.env', content: `STRIPE_SECRET_KEY=${stripe}` }]);
    expect(findings[0].kind).toBe('secret');
    expect(findings[0].label).toMatch(/committed in \.env/);
    expect(gradeRepo(findings)).toBe('F');
  });

  it('a clean repo grades A', () => {
    const findings = analyzeRepoFiles([{ path: 'src/app/page.tsx', content: 'export default function Page(){return null}' }]);
    expect(findings).toHaveLength(0);
    expect(gradeRepo(findings)).toBe('A');
  });

  it('one cross-tenant route is a serious drop, two is F', () => {
    const bad = `const {user}=await withApiAuth(req); supabase.from('x').select('*').eq('id', id)`;
    expect(gradeRepo(analyzeRepoFiles([{ path: 'app/api/a/route.ts', content: bad }]))).toBe('D');
    expect(
      gradeRepo(
        analyzeRepoFiles([
          { path: 'app/api/a/route.ts', content: bad },
          { path: 'app/api/b/route.ts', content: bad },
        ]),
      ),
    ).toBe('F');
  });
});

describe('fixture exclusion — the false positive E2E caught', () => {
  it('drops test files, fixtures, examples, demos and templates', () => {
    const kept = selectFiles(
      [
        'lib/scan/secrets.test.ts',
        'src/__tests__/auth.ts',
        'examples/leaky-demo/src/app/api/orders/route.ts',
        'e2e/checkout.spec.ts',
        '.env.example',
        'src/mocks/handlers.ts',
        // the ones that SHOULD survive:
        'src/app/api/orders/route.ts',
        '.env',
      ].map((p) => ({ path: p, type: 'blob' })),
    );
    expect(kept).toEqual(['.env', 'src/app/api/orders/route.ts']);
  });

  it('isFixture recognises the deliberate-fixture paths', () => {
    expect(isFixture('lib/scan/secrets.test.ts')).toBe(true);
    expect(isFixture('examples/leaky-demo/x.ts')).toBe(true);
    expect(isFixture('.env.example')).toBe(true);
    expect(isFixture('src/app/api/route.ts')).toBe(false);
    expect(isFixture('.env')).toBe(false);
  });
});
