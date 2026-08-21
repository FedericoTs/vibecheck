import { describe, it, expect } from 'vitest';
import { parseNpmLock, cleanVersion, parsePackageJson, parseRequirementsTxt, osvBatchBody, parseOsvBatch, cvssScore, isMalware, classifyVuln, type Dep, parsePnpmLock, parseYarnLock } from './deps';

describe('parseNpmLock', () => {
  it('reads exact versions from a v3 lockfile (packages), skips the root', () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'my-app', version: '1.0.0' },
        'node_modules/axios': { version: '1.2.3' },
        'node_modules/left-pad': { version: '1.3.0' },
      },
    });
    const deps = parseNpmLock(lock);
    expect(deps).toContainEqual({ name: 'axios', version: '1.2.3', ecosystem: 'npm' });
    expect(deps).toContainEqual({ name: 'left-pad', version: '1.3.0', ecosystem: 'npm' });
    expect(deps.find((d) => d.name === 'my-app')).toBeUndefined();
  });

  it('falls back to a v1 lockfile (nested dependencies)', () => {
    const lock = JSON.stringify({ lockfileVersion: 1, dependencies: { axios: { version: '0.21.0', dependencies: { follow: { version: '1.0.0' } } } } });
    const deps = parseNpmLock(lock);
    expect(deps).toContainEqual({ name: 'axios', version: '0.21.0', ecosystem: 'npm' });
    expect(deps).toContainEqual({ name: 'follow', version: '1.0.0', ecosystem: 'npm' });
  });

  it('tolerates junk', () => {
    expect(parseNpmLock('not json')).toEqual([]);
    expect(parseNpmLock('{}')).toEqual([]);
  });
});

describe('cleanVersion / parsePackageJson', () => {
  it('pulls a concrete version out of a range', () => {
    expect(cleanVersion('^1.2.3')).toBe('1.2.3');
    expect(cleanVersion('~4.5.6')).toBe('4.5.6');
    expect(cleanVersion('>=2.0.0')).toBe('2.0.0');
    expect(cleanVersion('*')).toBe(null);
    expect(cleanVersion('latest')).toBe(null);
    expect(cleanVersion('workspace:*')).toBe(null);
  });

  it('reads dependencies + devDependencies, skips un-pinnable ranges', () => {
    const pkg = JSON.stringify({ dependencies: { axios: '^1.2.3', foo: '*' }, devDependencies: { vitest: '~2.0.0' } });
    const deps = parsePackageJson(pkg);
    expect(deps).toContainEqual({ name: 'axios', version: '1.2.3', ecosystem: 'npm' });
    expect(deps).toContainEqual({ name: 'vitest', version: '2.0.0', ecosystem: 'npm' });
    expect(deps.find((d) => d.name === 'foo')).toBeUndefined();
  });
});

describe('parseRequirementsTxt', () => {
  it('takes only pinned == deps', () => {
    const req = '# comment\nrequests==2.28.0\ndjango>=4.0\n-r other.txt\nflask == 2.3.2';
    const deps = parseRequirementsTxt(req);
    expect(deps).toContainEqual({ name: 'requests', version: '2.28.0', ecosystem: 'PyPI' });
    expect(deps).toContainEqual({ name: 'flask', version: '2.3.2', ecosystem: 'PyPI' });
    expect(deps.find((d) => d.name === 'django')).toBeUndefined(); // not pinned
  });
});

describe('OSV query shaping', () => {
  const deps: Dep[] = [
    { name: 'axios', version: '1.2.3', ecosystem: 'npm' },
    { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
  ];

  it('builds a batch body OSV understands', () => {
    expect(osvBatchBody(deps)).toEqual({
      queries: [
        { package: { name: 'axios', ecosystem: 'npm' }, version: '1.2.3' },
        { package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.20' },
      ],
    });
  });

  it('maps a batch response back to the vulnerable deps only', () => {
    const results = [{ vulns: [{ id: 'GHSA-aaaa' }, { id: 'GHSA-aaaa' }] }, {}];
    const out = parseOsvBatch(deps, results);
    expect(out).toHaveLength(1);
    expect(out[0].dep.name).toBe('axios');
    expect(out[0].ids).toEqual(['GHSA-aaaa']); // deduped
  });
});

describe('vuln classification', () => {
  it('reads the highest CVSS score', () => {
    // Was written against a fake vector with a number glued on the end, which
    // only parsed because the old regex looked for a trailing number. Real OSV
    // vectors carry no score at all — they have to be read from the metrics.
    expect(
      cvssScore([
        { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
        { score: '7.5' },
      ]),
    ).toBe(9.8);
    expect(cvssScore(undefined)).toBe(null);
  });

  it('detects malicious-package advisories', () => {
    expect(isMalware({ id: 'MAL-2026-1234' })).toBe(true);
    expect(isMalware({ id: 'GHSA-x', summary: 'Package contains malicious code that exfiltrates env vars' })).toBe(true);
    expect(isMalware({ id: 'GHSA-y', summary: 'Prototype pollution in lodash' })).toBe(false);
  });

  it('grades malware and CVSS 9+ as critical, 7+ as high', () => {
    expect(classifyVuln({ id: 'MAL-1' }).severity).toBe('critical');
    expect(classifyVuln({ id: 'G', severity: [{ score: '9.8' }] }).severity).toBe('critical');
    expect(classifyVuln({ id: 'G', severity: [{ score: '7.5' }] }).severity).toBe('high');
    expect(classifyVuln({ id: 'G', database_specific: { severity: 'HIGH' } }).severity).toBe('high');
    // An advisory nothing rated is 'unknown', never 'medium' — inventing a
    // rating and then grading the user on it is the thing to avoid.
    expect(classifyVuln({ id: 'G', summary: 'minor' }).severity).toBe('unknown');
    expect(classifyVuln({ id: 'G', database_specific: { severity: 'MODERATE' } }).severity).toBe('medium');
  });
});

describe('isMalware — "MALICIOUS" is the most damaging word we can print', () => {
  it('does NOT brand a healthy package because its prose says "malicious user"', () => {
    // The previous test searched `details` too, so an ordinary XSS advisory
    // branded postcss as malicious.
    expect(isMalware({
      id: 'GHSA-7fh5-64p2-3v2j',
      summary: 'PostCSS line return parsing error',
      details: 'An attacker may craft input so that a malicious user could inject CSS.',
    })).toBe(false);
    expect(isMalware({
      id: 'GHSA-566m-qj78-rww5',
      summary: 'Regular Expression Denial of Service in postcss',
      details: 'A malicious actor could exploit this ReDoS with a crafted stylesheet.',
    })).toBe(false);
  });

  it('still flags the real supply-chain compromises, which predate MAL- ids', () => {
    expect(isMalware({ id: 'MAL-2025-1234', summary: 'anything' })).toBe(true);
    expect(isMalware({ id: 'GHSA-xxxx', aliases: ['MAL-2025-9'], summary: 'x' })).toBe(true);
    expect(isMalware({ id: 'GHSA-x', summary: 'x', database_specific: { malicious: true } })).toBe(true);
    // eslint-scope and ua-parser-js are titled this way and carry no MAL- id.
    expect(isMalware({ id: 'GHSA-hxxf-q3w9-4xgw', summary: 'Malicious code in eslint-scope' })).toBe(true);
    expect(isMalware({ id: 'GHSA-pjwm-rvh2-c87w', summary: 'Embedded malware in ua-parser-js' })).toBe(true);
    expect(isMalware({ id: 'GHSA-y', summary: 'Backdoored release of foo' })).toBe(true);
  });
});

describe('lockfile parsers — a range floor is not an installed version', () => {
  it('reads pnpm v9 keys and strips the peer suffix', () => {
    const lock = `lockfileVersion: '9.0'
packages:
  react-dom@18.2.0:
    resolution: {integrity: sha512-x}
  '@types/node@20.11.5':
    resolution: {integrity: sha512-y}
snapshots:
  react-dom@18.2.0(react@18.2.0):
    dependencies:
      react: 18.2.0`;
    const deps = parsePnpmLock(lock);
    // The peer suffix must be stripped or OSV gets an unresolvable version.
    expect(deps).toContainEqual({ name: 'react-dom', version: '18.2.0', ecosystem: 'npm' });
    expect(deps).toContainEqual({ name: '@types/node', version: '20.11.5', ecosystem: 'npm' });
    expect(deps.some((d) => d.version.includes('('))).toBe(false);
  });

  it('reads the older pnpm /name/version form', () => {
    expect(parsePnpmLock("packages:\n  /postcss/8.4.31:\n    resolution: {}")).toContainEqual({
      name: 'postcss', version: '8.4.31', ecosystem: 'npm',
    });
  });

  it('reads yarn v1 and Berry, taking the RESOLVED version not the range', () => {
    const v1 = `"react-dom@^18.2.0":\n  version "18.2.0"\n  resolved "https://..."`;
    expect(parseYarnLock(v1)).toContainEqual({ name: 'react-dom', version: '18.2.0', ecosystem: 'npm' });
    const berry = `"lodash@npm:^4.17.20":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"`;
    expect(parseYarnLock(berry)).toContainEqual({ name: 'lodash', version: '4.17.21', ecosystem: 'npm' });
  });

  it('keeps the scope on a scoped yarn package', () => {
    expect(parseYarnLock(`"@babel/core@^7.0.0":\n  version "7.24.0"`)).toContainEqual({
      name: '@babel/core', version: '7.24.0', ecosystem: 'npm',
    });
  });
});

describe('cvssScore — OSV stores a VECTOR, not a number', () => {
  it('reads a v3 vector instead of silently returning null', () => {
    // The old numeric regex matched nothing, so every non-GitHub advisory had
    // no severity and was defaulted to medium.
    expect(cvssScore([{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }])).toBe(9.8);
  });

  it('reads a v4 vector, which uses VC/VI/VA', () => {
    expect(cvssScore([{ type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H' }])).toBe(9.8);
  });

  it('returns null for a vector it cannot read — never a guessed number', () => {
    expect(cvssScore([{ type: 'X', score: 'not-a-vector' }])).toBe(null);
    expect(cvssScore(undefined)).toBe(null);
  });

  it('classifies as unknown when nothing established a rating', () => {
    const c = classifyVuln({ id: 'GHSA-x', summary: 'Something' });
    expect(c.severity).toBe('unknown');
  });
});
