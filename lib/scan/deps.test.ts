import { describe, it, expect } from 'vitest';
import {
  parseNpmLock,
  cleanVersion,
  parsePackageJson,
  parseRequirementsTxt,
  osvBatchBody,
  parseOsvBatch,
  cvssScore,
  isMalware,
  classifyVuln,
  type Dep,
  type OsvVuln,
} from './deps';

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
    expect(cvssScore([{ score: 'CVSS:3.1/AV:N/.../ 9.8' }, { score: '7.5' }])).toBe(9.8);
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
    expect(classifyVuln({ id: 'G', summary: 'minor' }).severity).toBe('medium');
  });
});
