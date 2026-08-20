import { describe, it, expect } from 'vitest';
import { purl, toCycloneDX } from './sbom';
import type { Dep } from './deps';

describe('purl', () => {
  it('builds package URLs, encoding scoped npm names', () => {
    expect(purl({ name: 'axios', version: '1.2.3', ecosystem: 'npm' })).toBe('pkg:npm/axios@1.2.3');
    expect(purl({ name: '@babel/core', version: '7.0.0', ecosystem: 'npm' })).toBe('pkg:npm/%40babel/core@7.0.0');
    expect(purl({ name: 'requests', version: '2.28.0', ecosystem: 'PyPI' })).toBe('pkg:pypi/requests@2.28.0');
  });
});

describe('toCycloneDX', () => {
  const deps: Dep[] = [
    { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
    { name: 'axios', version: '1.2.3', ecosystem: 'npm' },
    { name: 'axios', version: '1.2.3', ecosystem: 'npm' }, // dup
  ];

  it('produces a valid CycloneDX 1.5 document', () => {
    const bom = toCycloneDX(deps, 'acme/app', '2026-08-19T00:00:00Z');
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.5');
    expect(bom.metadata.component.name).toBe('acme/app');
    expect(bom.metadata.tools[0].vendor).toBe('vibecheck');
  });

  it('dedupes and sorts deterministically', () => {
    const bom = toCycloneDX(deps, 'x', 't');
    expect(bom.components).toHaveLength(2); // axios dedup
    expect(bom.components.map((c) => c.name)).toEqual(['axios', 'lodash']); // sorted by purl
    expect(bom.components[0].purl).toBe('pkg:npm/axios@1.2.3');
    expect(bom.components[0]['bom-ref']).toBe('pkg:npm/axios@1.2.3');
  });

  it('is serialisable to the file people actually download', () => {
    const bom = toCycloneDX(deps, 'x', 't');
    const json = JSON.parse(JSON.stringify(bom));
    expect(json.components[0].type).toBe('library');
  });
});
